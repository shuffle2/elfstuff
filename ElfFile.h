#pragma once

#include "ElfFileTypes.h"
#include "VirtualMemory.h"

/*
version 1:
    0x40 bytes
    params:
        sceProcessName
        sceUserMainThreadName
        sceUserMainThreadPriority
        sceUserMainThreadStackSize
version 2:
    0x48 bytes
    possibly null params?
*/
struct SceElfProcparam {
    u64 size;
    u32 magic;
    u32 version;
    u64 sdk_version;
    //u64 params[0];
};

namespace Simulator { struct Executor; }

#define DW_EH_PE_absptr         0x00
#define DW_EH_PE_omit           0xff

#define DW_EH_PE_uleb128        0x01
#define DW_EH_PE_udata2         0x02
#define DW_EH_PE_udata4         0x03
#define DW_EH_PE_udata8         0x04
#define DW_EH_PE_sleb128        0x09
#define DW_EH_PE_sdata2         0x0A
#define DW_EH_PE_sdata4         0x0B
#define DW_EH_PE_sdata8         0x0C
#define DW_EH_PE_signed         0x08

#define DW_EH_PE_pcrel          0x10
#define DW_EH_PE_textrel        0x20
#define DW_EH_PE_datarel        0x30
#define DW_EH_PE_funcrel        0x40
#define DW_EH_PE_aligned        0x50

#define DW_EH_PE_indirect       0x80

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0, /* info == register number */
    UWOP_ALLOC_LARGE,     /* no info, alloc size in next 2 slots */
    UWOP_ALLOC_SMALL,     /* info == size of allocation / 8 - 1 */
    UWOP_SET_FPREG,       /* no info, FP = RSP + UNWIND_INFO.FPRegOffset*16 */
    UWOP_SAVE_NONVOL,     /* info == register number, offset in next slot */
    UWOP_SAVE_NONVOL_FAR, /* info == register number, offset in next 2 slots */
    UWOP_SAVE_XMM128,     /* info == XMM reg number, offset in next slot */
    UWOP_SAVE_XMM128_FAR, /* info == XMM reg number, offset in next 2 slots */
    UWOP_PUSH_MACHFRAME   /* info == 0: no error-code, 1: error-code */
} UNWIND_CODE_OPS;

enum UNWIND_REGISTER : u8 {
    RAX,
    RCX,
    RDX,
    RBX,
    RSP,
    RBP,
    RSI,
    RDI,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
};

typedef union _UNWIND_CODE {
    struct {
        u8 CodeOffset;
        u8 UnwindOp : 4;
        u8 OpInfo : 4;
    };
    u16 FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

typedef struct _UNWIND_INFO {
    u8 Version : 3;
    u8 Flags : 5;
    u8 SizeOfProlog;
    u8 CountOfCodes;
    u8 FrameRegister : 4;
    u8 FrameOffset : 4;
    UNWIND_CODE UnwindCode[1];
    /*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
    *   union {
    *       OPTIONAL ULONG ExceptionHandler;
    *       OPTIONAL ULONG FunctionEntry;
    *   };
    *   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

struct eh_frame_hdr {
    u8 version;
    u8 eh_frame_ptr_enc;
    u8 fde_count_enc;
    u8 table_enc;
};
struct eh_cie {
    uintptr_t caf;
    intptr_t daf;
    u8 fde_enc;
    const u8 *insns;
    size_t insns_len;
};
struct eh_fde {
    eh_cie cie;
    uintptr_t start;
    uintptr_t end;
    const u8 *insns;
    size_t insns_len;
};
struct eh_fde_rel {
    u32 start;
    u32 end;
    uintptr_t caf;
    intptr_t daf;
    u32 init_insns;
    u32 init_insns_len;
    u32 insns;
    u32 insns_len;
};
struct ElfEHInfo {
    std::vector<eh_fde_rel> fdes;
    bool Init(const u8 *base, const eh_frame_hdr *hdr);
    bool TranslateCFI(PUNWIND_INFO ui, const eh_fde_rel &fde, uintptr_t base);
    bool Install(const void *code_base, void *eh_base);
    size_t GetNativeSize();
};

struct ElfFile {
    std::unique_ptr<VirtualMemory::MappedObject> object;

    u8 *file;
    Elf64_Ehdr *header;
    std::vector<Elf64_Phdr *> pheaders;
    u8 *dynlibdata;
    Elf64_Dyn *dynamic;
    u64 procparam_rva;
    std::unique_ptr<ElfEHInfo> eh_info;

    u32 plt_offset;
    template<typename T>
    struct DynList {
        T *ptr;
        size_t num;
    };
    DynList<const char> dynstr;
    DynList<Elf64_Sym> dynsym;
    DynList<Elf64_Rela> rela;
    DynList<Elf64_Rela> jmprel;

    // XXX Currently not tracking attributes of modules or libraries...
    struct ModuleInfo {
        u16 id;
        u8 ver_major;
        u8 ver_minor;
        const char *name;
    };
    std::vector<ModuleInfo> modules;
    struct LibraryInfo {
        u16 id;
        u16 version;
        const char *name;
    };
    std::vector<LibraryInfo> libraries;

    u64 load_mem_offset;
    u64 load_mem_size;
    VirtualMemory::Allocation relocbase;

    std::map<std::string, uintptr_t> symbol_map;

    struct PltRecord {
        uintptr_t slot_offset;
        u16 mid;
        u64 nid;
    };
    std::vector<PltRecord> plt_slots;

    bool Load(const std::string path);
    bool ParseHeaders();
    bool ParseDynamic();
    bool CheckSegments();
    VirtualMemory::Protection GetSegProt(const Elf64_Phdr &phdr);
    bool Map();
    void ProcessRelocations(Simulator::Executor *exec, const DynList<Elf64_Rela> &relocs);

    bool FriendlySymbolName(const char *name, std::string *friendly);

    void AllocatePltSlot(const char *name, const Elf64_Rela &reloc);
    void SetupPltResolver(Simulator::Executor *exec);
    bool SetSegmentProtections();
};
