#pragma once

#include "stdafx.h"

struct ElfIdent {
    u32 magic;
#define ELF_MAGIC 0x464C457F // litte endian \x7FELF
    u8 elf_class;
#define   ELFCLASSNONE  0    // Invalid class
#define   ELFCLASS32    1    // 32bit object
#define   ELFCLASS64    2    // 64bit object
    u8 bytesex;
#define   ELFDATANONE    0   // Invalid data encoding
#define   ELFDATA2LSB    1   // low byte first
#define   ELFDATA2MSB    2   // high byte first
    u8 version;              // file version
    u8 osabi;                // Operating System/ABI indication
#define   ELFOSABI_NONE          0 // UNIX System V ABI
#define   ELFOSABI_FREEBSD       9 // FreeBSD
    u8 abiversion;           // ABI version
    u8 pad[7];

    bool is_valid() const { return magic == ELF_MAGIC; }
    bool is_msb()   const { return bytesex == ELFDATA2MSB; }
    bool is_64()    const { return elf_class == ELFCLASS64; }
};

enum ElfHeaderType : u32 {
    ET_EXEC = 2,
    ET_LOOS = 0xfe00,
    ET_SCE_EXEC         = ET_LOOS + 0x00,
    ET_SCE_REPLAY_EXEC  = ET_LOOS + 0x01,
    ET_SCE_RELEXEC      = ET_LOOS + 0x04,
    ET_SCE_STUBLIB      = ET_LOOS + 0x0c,
    ET_SCE_DYNEXEC      = ET_LOOS + 0x10,
    ET_SCE_DYNAMIC      = ET_LOOS + 0x18,
};

enum ElfMachine : u16 {
    EM_X86_64       = 62,  // Advanced Micro Devices X86-64 processor
};

struct Elf64_Ehdr {
    ElfIdent e_ident;
    u16      e_type;
    u16      e_machine;
    u32      e_version;
    u64      e_entry;
    u64      e_phoff;
    u64      e_shoff;
    u32      e_flags;
    u16      e_ehsize;
    u16      e_phentsize;
    u16      e_phnum;
    u16      e_shentsize;
    u16      e_shnum;
    u16      e_shstrndx;
};

enum ElfPHeaderType : u32 {
    PT_NULL    = 0,               //ignore entries in program table
    PT_LOAD    = 1,               //loadable segmen described in _filesz & _memsz
    PT_DYNAMIC = 2,               //dynamic linking information
    PT_INTERP  = 3,               //path name to interpreter (loadable)
    PT_NOTE    = 4,               //auxilarry information
    PT_SHLIB   = 5,               //reserved. Has no specified semantics
    PT_PHDR    = 6,               //location & size program header table
    PT_TLS     = 7,               //Thread local storage segment
    PT_LOOS    = 0x60000000ul,    // OS-
    PT_HIOS    = 0x6ffffffful,    //    specific
    PT_LOPROC  = 0x70000000ul,    // processor-
    PT_HIPROC  = 0x7ffffffful,    //           specific
    PT_GNU_EH_FRAME = (PT_LOOS + 0x474e550ul),
    PT_GNU_STACK    = (PT_LOOS + 0x474e551ul),
    PT_GNU_RELRO    = (PT_LOOS + 0x474e552), // Read-only after relocation

    PT_SCE_RELA       = 0x60000000,
    
    // .sce_special
    //   .sce_debug_fingerprint
    //   .dynstr
    //   .dynsym
    //   .dyn.rela.plt
    //   .dyn.rela.dyn
    //   .hash
    //   .dynamic (but it has it's own program header, too)
    PT_SCE_DYNLIBDATA   = 0x61000000,
    // .sce_process_param
    PT_SCE_PROCPARAM    = 0x61000001,
    PT_SCE_MODULEPARAM  = 0x61000002,
    // Globbed stuff like rtti info and .got.plt
    PT_SCE_RELRO        = 0x61000010,
    
    // .prodg_meta_data
    // env variables
    PT_SCE_COMMENT    = 0x6fffff00,
    // .sceversion
    // stub lib versions
    PT_SCE_VERSION    = 0x6fffff01,
};

enum ElfSegmentFlags
{
    PF_X          = (1 << 0),       // Segment is executable
    PF_W          = (1 << 1),       // Segment is writable
    PF_R          = (1 << 2),       // Segment is readable
    PF_MASKOS     = 0x0FF00000,     // OS-specific reserved bits
    PF_MASKPROC   = 0xF0000000,     // Processor-specific reserved bits
};

struct Elf64_Phdr {
    u32 p_type;
    u32 p_flags;
    u64 p_offset;
    u64 p_vaddr;
    u64 p_paddr;
    u64 p_filesz;
    u64 p_memsz;
    u64 p_align;
};

enum ElfSHeaderType : u32 {
    SHT_SCE_RELA    = 0x60000000,

    SHT_SCENID      = 0x61000001,
};

struct Elf64_Shdr {
    u32 sh_name;      // Section name, index in string tbl
    u32 sh_type;      // Type of section
    u64 sh_flags;     // Miscellaneous section attributes
    u64 sh_addr;      // Section virtual addr at execution
    u64 sh_offset;    // Section file offset
    u64 sh_size;      // Size of section in bytes
    u32 sh_link;      // Index of another section
    u32 sh_info;      // Additional section information
    u64 sh_addralign; // Section alignment
    u64 sh_entsize;   // Entry size if section holds table
};

struct Elf64_Sym {
    u32 st_name;
    u8  st_info;
    u8  st_other;
    u16 st_shndx;
    u64 st_value;
    u64 st_size;
};

#define ELF64_ST_BIND(i)   ((i)>>4)
#define ELF64_ST_TYPE(i)   ((i)&0xf)

#define ELF64_ST_VISIBILITY(o) ((o)&0x3)

enum elf_ST_BIND
{
  STB_LOCAL   = 0,
  STB_GLOBAL  = 1,
  STB_WEAK    = 2,
  STB_LOOS    = 10,              //OS-specific
  STB_GNU_UNIQUE = 10,           // Symbol is unique in namespace
  STB_HIOS    = 12,
  STB_LOPROC  = 13,              //processor-
  STB_HIPROC  = 15,               //          specific
  STB_INVALID = 254
};

enum elf_ST_TYPE
{
  STT_NOTYPE    = 0,
  STT_OBJECT  = 1,              // associated with data object
  STT_FUNC    = 2,              // associated with function or execut. code
  STT_SECTION = 3,
  STT_FILE    = 4,              // name of source file
  STT_COMMON  = 5,              // Uninitialized common section
  STT_TLS     = 6,              // TLS-data object
  STT_LOOS   = 10,              //OS-
  STT_HIOS   = 12,              //   specific
  STT_LOPROC = 13,              //processor-
  STT_HIPROC = 15,              //          specific
  STT_GNU_IFUNC = 10,           // Symbol is an indirect code object
};

enum elf_ST_VISIBILITY
{
  STV_DEFAULT    = 0,               /* Visibility is specified by binding type */
  STV_INTERNAL   = 1,               /* OS specific version of STV_HIDDEN */
  STV_HIDDEN     = 2,               /* Can only be seen inside currect component */
  STV_PROTECTED  = 3,               /* Treat as STB_LOCAL inside current component */
};

enum elf_x86_64_relocation_type : u32 {
    R_X86_64_NONE = 0,          /* none */
    R_X86_64_64 = 1,            /* word64, S + A */
    R_X86_64_PC32 = 2,          /* word32, S + A - P */
    R_X86_64_GOT32 = 3,         /* word32, G + A */
    R_X86_64_PLT32 = 4,         /* word32, L + A - P */
    R_X86_64_COPY = 5,          /* none */
    R_X86_64_GLOB_DAT = 6,      /* word64, S, set GOT entry to data address */
    R_X86_64_JMP_SLOT = 7,      /* word64, S, set GOT entry to code address */
    R_X86_64_RELATIVE = 8,      /* word64, B + A */
    R_X86_64_GOTPCREL = 9,      /* word32, G + GOT + A - P */
    R_X86_64_32 = 10,           /* word32 (zero extend), S + A */
    R_X86_64_32S = 11,          /* word32 (sign extend), S + A */
    R_X86_64_16 = 12,           /* word16, S + A */
    R_X86_64_PC16 = 13,         /* word16, S + A - P */
    R_X86_64_8 = 14,            /* word8, S + A */
    R_X86_64_PC8 = 15,          /* word8, S + A - P */
    R_X86_64_DPTMOD64 = 16,     /* word64, ID of module containing symbol */
    R_X86_64_DTPOFF64 = 17,     /* word64, offset in TLS block */
    R_X86_64_TPOFF64 = 18,      /* word64, offset in initial TLS block */
    R_X86_64_TLSGD = 19,        /* word32, PC-rel offset to GD GOT block */
    R_X86_64_TLSLD = 20,        /* word32, PC-rel offset to LD GOT block */
    R_X86_64_DTPOFF32 = 21,     /* word32, offset to TLS block */
    R_X86_64_GOTTPOFF = 22,     /* word32, PC-rel offset to IE GOT entry */
    R_X86_64_TPOFF32 = 23,      /* word32, offset in initial TLS block */
    R_X86_64_PC64 = 24,         /* word64, PC relative */
    R_X86_64_GOTOFF64 = 25,     /* word64, offset to GOT */
    R_X86_64_GOTPC32 = 26,      /* word32, signed pc relative to GOT */
    R_X86_64_GOT64 = 27,        /* word64, GOT entry offset */
    R_X86_64_GOTPCREL64 = 28,   /* word64, signed pc relative to GOT entry */
    R_X86_64_GOTPC64 = 29,      /* word64, signed pc relative to GOT */
    R_X86_64_GOTPLT64 = 30,     /* like GOT64, but indicates PLT entry needed */
    R_X86_64_PLTOFF64 = 31,     /* word64, GOT relative offset to PLT entry */
    R_X86_64_GOTPC32_TLSDESC = 34, /* GOT offset for TLS descriptor */
    R_X86_64_TLSDESC_CALL = 35, /* Marker for call through TLS descriptor */
    R_X86_64_TLSDESC = 36       /* TLS descriptor */
};

struct Elf64_Rela {
    u64 r_offset;
    u64 r_info;
    s64 r_addend;
};

#define ELF64_R_SYM(i)     u32((i) >> 32)
#define ELF64_R_TYPE(i)    u32(i)

enum ElfDynamicTagType : u64 {
    DT_NULL     = 0,              //(-) end ofd _DYNAMIC array
    DT_NEEDED   = 1,              //(v) str-table offset name to needed library
    DT_PLTRELSZ = 2,              //(v) tot.size in bytes of relocation entries
    DT_PLTGOT   = 3,              //(p) see below
    DT_HASH     = 4,              //(p) addr. of symbol hash teble
    DT_STRTAB   = 5,              //(p) addr of string table
    DT_SYMTAB   = 6,              //(p) addr of symbol table
    DT_RELA     = 7,              //(p) addr of relocation table
    DT_RELASZ   = 8,              //(v) size in bytes of DT_RELA table
    DT_RELAENT  = 9,              //(v) size in bytes of DT_RELA entry
    DT_STRSZ    = 10,             //(v) size in bytes of string table
    DT_SYMENT   = 11,             //(v) size in byte of symbol table entry
    DT_INIT     = 12,             //(p) addr. of initialization function
    DT_FINI     = 13,             //(p) addr. of termination function
    DT_SONAME   = 14,             //(v) offs in str.-table - name of shared object
    DT_RPATH    = 15,             //(v) offs in str-table - search patch
    DT_SYMBOLIC = 16,             //(-) start search of shared object
    DT_REL      = 17,             //(p) similar to DT_RELA
    DT_RELSZ    = 18,             //(v) tot.size in bytes of DT_REL
    DT_RELENT   = 19,             //(v) size in bytes of DT_REL entry
    DT_PLTREL   = 20,             //(v) type of relocation (DT_REL or DT_RELA)
    DT_DEBUG    = 21,             //(p) not specified
    DT_TEXTREL  = 22,             //(-) segment permisson
    DT_JMPREL   = 23,             //(p) addr of dlt procedure (if present)
    DT_BIND_NOW         = 24,
    DT_INIT_ARRAY       = 25,
    DT_FINI_ARRAY       = 26,
    DT_INIT_ARRAYSZ     = 27,
    DT_FINI_ARRAYSZ     = 28,
    DT_RUNPATH          = 29,
    DT_FLAGS            = 30,
    #define DF_ORIGIN         0x01
    #define DF_SYMBOLIC       0x02
    #define DF_TEXTREL        0x04
    #define DF_BIND_NOW       0x08
    #define DF_STATIC_TLS     0x10
    DT_ENCODING         = 31,
    DT_PREINIT_ARRAY    = 32,
    DT_PREINIT_ARRAYSZ  = 33,
    DT_LOOS       = 0x60000000ul,  // OS-specific
    DT_HIOS       = 0x6ffffffful,  //
    DT_SCE_IDTABENTSZ           = 0x61000005,
    DT_SCE_FINGERPRINT          = 0x61000007,
    DT_SCE_ORIGINAL_FILENAME    = 0x61000009,
    DT_SCE_MODULE_INFO          = 0x6100000d,
    DT_SCE_NEEDED_MODULE        = 0x6100000f,
    DT_SCE_MODULE_ATTR          = 0x61000011,
    DT_SCE_EXPORT_LIB           = 0x61000013,
    DT_SCE_IMPORT_LIB           = 0x61000015,
    DT_SCE_EXPORT_LIB_ATTR      = 0x61000017,
    DT_SCE_IMPORT_LIB_ATTR      = 0x61000019,
    DT_SCE_STUB_MODULE_NAME     = 0x6100001d,
    DT_SCE_STUB_MODULE_VERSION  = 0x6100001f,
    DT_SCE_STUB_LIBRARY_NAME    = 0x61000021,
    DT_SCE_STUB_LIBRARY_VERSION = 0x61000023,
    DT_SCE_HASH                 = 0x61000025,
    DT_SCE_PLTGOT               = 0x61000027,
    DT_SCE_JMPREL               = 0x61000029,
    DT_SCE_PLTREL               = 0x6100002b,
    DT_SCE_PLTRELSZ             = 0x6100002d,
    DT_SCE_RELA                 = 0x6100002f,
    DT_SCE_RELASZ               = 0x61000031,
    DT_SCE_RELAENT              = 0x61000033,
    DT_SCE_STRTAB               = 0x61000035,
    DT_SCE_STRSZ                = 0x61000037,
    DT_SCE_SYMTAB               = 0x61000039,
    DT_SCE_SYMENT               = 0x6100003b,
    DT_SCE_HASHSZ               = 0x6100003d,
    DT_SCE_SYMTABSZ             = 0x6100003f,
};

struct Elf64_Dyn {
    u64 d_tag;
    u64 d_un;
};
