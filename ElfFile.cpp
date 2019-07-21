#include "ElfFile.h"
#include "Utils.h"

typedef u64 sce_nid_t;
typedef u16 sce_obj_id_t;
// lcm(6, 8) = 24 = 24 / 8 = 3 bytes per 4 b64 symbols
// so 8bytes needs 11 symbols + null char
typedef std::array<char, 12> sce_mangled_nid_t;

struct symbol_info_t {
    sce_nid_t nid;
    sce_obj_id_t lid;
    sce_obj_id_t mid;
};

static const u8 b64_value[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0x3F, 0xFF, 0xFF,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B,
    0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
    0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30,
    0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static bool sce_base64_decode_nid(const char *b64, sce_nid_t *nid) {
    *nid = 0;
    size_t b64_len = strlen(b64);
    if (b64_len != 11) {
        return false;
    }
    for (size_t i = 0; i < b64_len; i++) {
        u8 idx = b64[i];
        if (idx >= sizeof(b64_value)) {
            return false;
        }
        u8 v = b64_value[idx];
        if (v == 0xff) {
            *nid = 0;
            return false;
        }
        if (i == (b64_len - 1)) {
            *nid <<= 4;
            *nid |= v >> 2;
        }
        else {
            *nid <<= 6;
            *nid |= v;
        }
    }
    return true;
}

static bool sce_base64_decode_obj_id(const char *b64, sce_obj_id_t *id) {
    *id = 0;
    size_t b64_len = strlen(b64);
    if (b64_len > 4) {
        return false;
    }
    for (size_t i = 0; i < b64_len; i++) {
        u8 idx = b64[i];
        if (idx >= sizeof(b64_value)) {
            return false;
        }
        u8 v = b64_value[idx];
        if (v == 0xff) {
            *id = 0;
            return false;
        }
        *id <<= 6;
        *id |= v;
    }
    return true;
}

static bool sce_unmangle_symbol(const std::string &triplet, symbol_info_t *symbol) {
    auto lid_pos = triplet.find('#');
    if (lid_pos == triplet.npos) {
        return false;
    }
    auto mid_pos = triplet.find('#', lid_pos + 1);
    if (mid_pos == triplet.npos) {
        return false;
    }
    auto lid_b64 = triplet.substr(lid_pos + 1, mid_pos - (lid_pos + 1));
    if (!sce_base64_decode_obj_id(lid_b64.c_str(), &symbol->lid)) {
        return false;
    }
    auto mid_b64 = triplet.substr(mid_pos + 1);
    if (!sce_base64_decode_obj_id(mid_b64.c_str(), &symbol->mid)) {
        return false;
    }
    auto nid_b64 = triplet.substr(0, lid_pos);
    if (!sce_base64_decode_nid(nid_b64.c_str(), &symbol->nid)) {
        return false;
    }
    return true;
}

static const u8 nid_suffix[] = {
    0x51, 0x8D, 0x64, 0xA6, 0x35, 0xDE, 0xD8, 0xC1, 0xE6, 0xB0,
    0x39, 0xB1, 0xC3, 0xE5, 0x52, 0x30
};

static void string_to_sce_nid(const char *s, sce_nid_t *nid) {
    mbedtls_sha1_context ctx;
    u8 digest[0x14];
    mbedtls_sha1_init(&ctx);
    mbedtls_sha1_starts(&ctx);
    mbedtls_sha1_update(&ctx, (const u8 *)s, strlen(s));
    mbedtls_sha1_update(&ctx, nid_suffix, sizeof(nid_suffix));
    mbedtls_sha1_finish(&ctx, digest);
    *nid = 0;
    for (size_t i = 0; i < sizeof(*nid); i++) {
        *nid |= (sce_nid_t)digest[i] << (i * 8);
    }
}

static void sce_base64_encode_nid(const sce_nid_t nid, sce_mangled_nid_t *mangled) {
    const char *sce_b64_lut = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-";
    size_t i = 0;
    (*mangled)[i++] = sce_b64_lut[(nid >> 58) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 52) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 46) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 40) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 34) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 28) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 22) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 16) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 10) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[(nid >> 4) & 0x3f];
    (*mangled)[i++] = sce_b64_lut[((nid & 0xf) << 2) & 0x3f];
    (*mangled)[i++] = '\0';
}

static void sce_mangle_name(const char *name, sce_mangled_nid_t *mangled) {
    sce_nid_t nid;
    string_to_sce_nid(name, &nid);
    sce_base64_encode_nid(nid, mangled);
}

std::string mangled_name(const char *name) {
    sce_mangled_nid_t mangled;
    sce_mangle_name(name, &mangled);
    return mangled.data();
}

bool ElfFile::ParseDynamic() {
    if (!dynamic || !dynlibdata) {
        return false;
    }
#define ASSIGN_DYNPTR(x) \
    do { x.ptr = reinterpret_cast<decltype(x.ptr)>(dynlibdata + dyn->d_un); } while (0)
#define ASSIGN_DYNNUM(x) \
    do { x.num = dyn->d_un / sizeof(*x.ptr); } while (0)
    size_t mod_max_id = 0;
    size_t lib_max_id = 0;
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_SCE_STRTAB:
            ASSIGN_DYNPTR(dynstr);
            break;
        case DT_SCE_STRSZ:
            ASSIGN_DYNNUM(dynstr);
            break;
        case DT_SCE_SYMTAB:
            ASSIGN_DYNPTR(dynsym);
            break;
        case DT_SCE_SYMTABSZ:
            ASSIGN_DYNNUM(dynsym);
            break;
        case DT_SCE_RELA:
            ASSIGN_DYNPTR(rela);
            break;
        case DT_SCE_RELASZ:
            ASSIGN_DYNNUM(rela);
            break;
        case DT_SCE_JMPREL:
            ASSIGN_DYNPTR(jmprel);
            break;
        case DT_SCE_PLTRELSZ:
            ASSIGN_DYNNUM(jmprel);
            break;
        case DT_SCE_PLTGOT:
            plt_offset = static_cast<u32>(dyn->d_un);
            break;
        case DT_SCE_MODULE_INFO:
        case DT_SCE_NEEDED_MODULE:
            mod_max_id = std::max(mod_max_id, dyn->d_un >> 48);
            break;
        case DT_SCE_EXPORT_LIB:
        case DT_SCE_IMPORT_LIB:
            lib_max_id = std::max(lib_max_id, dyn->d_un >> 48);
            break;
        }
    }
#undef ASSIGN_DYNPTR
#undef ASSIGN_DYNNUM

    modules.resize(mod_max_id + 1);
    libraries.resize(lib_max_id + 1);
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        switch (dyn->d_tag) {
        case DT_SCE_NEEDED_MODULE:
        case DT_SCE_MODULE_INFO:
        {
            u16 mid = (u16)(dyn->d_un >> 48);
            auto &mi = modules[mid];
            mi.id = mid;
            mi.ver_major = (u8)(dyn->d_un >> 32);
            mi.ver_minor = (u8)(dyn->d_un >> 40);
            mi.name = dynstr.ptr + (u32)dyn->d_un;
            break;
        }
        case DT_SCE_EXPORT_LIB:
        case DT_SCE_IMPORT_LIB:
        {
            u16 lid = (u16)(dyn->d_un >> 48);
            auto &li = libraries[lid];
            li.id = lid;
            li.version = (u16)(dyn->d_un >> 32);
            li.name = dynstr.ptr + (u32)dyn->d_un;
            break;
        }
        }
    }

    // logging to see if rtld needs to take care of init/fini funcs
    // order is defined by spec as:
    // build image -> reloc -> preinit_array -> init -> init_array -> entry -> fini_array -> fini
    // however, it seems orbis crt will call these init funcs (for current
    // module) from _start (entrypoint). so, maybe we don't need to care?
    /*
    orbis rtld behavior:
    * when starting new process, kernel:
    * creates VM space
    * loads main binary
    * preloads libkernel and libSceLibcInternal
    * also inits complete dependency graph (but doesn't load things)
    * initializes all JMPREL to libkernel!sceKernelReportUnpatchedFunctionCall
    * somehow execution starts at libkernel!_start
    * see self_orbis_sysvec { exec_copyout_strings, self_orbis_fixup, exec_setregs }
    * libkernel!_start -> sys_dynlib_process_needed_and_relocate
    * loads needed objects
    * allocates tls entries and performs relocs
    * returns to libkernel!_orbis_rtld_entry
    * afterwards kernel just has to respond to requests made by usermode - it's running!
    */
    /*
    for (Elf64_Dyn *dyn = dynamic; dyn->d_tag != DT_NULL; dyn++) {
        const char *modname = modules[0].name;
#define LOG_THING(thing) \
case thing: printf("%-20s: %-20s = %16llx\n", modname, #thing, dyn->d_un); break;
        switch (dyn->d_tag) {
            LOG_THING(DT_PREINIT_ARRAY);
            LOG_THING(DT_PREINIT_ARRAYSZ);
            LOG_THING(DT_INIT);
            LOG_THING(DT_INIT_ARRAY);
            LOG_THING(DT_INIT_ARRAYSZ);
            LOG_THING(DT_FINI_ARRAY);
            LOG_THING(DT_FINI_ARRAYSZ);
            LOG_THING(DT_FINI);
        }
#undef LOG_THING
    }
    */
    return true;
}

bool ElfFile::ParseHeaders() {
    header = reinterpret_cast<Elf64_Ehdr *>(file);
    if (!header->e_ident.is_valid() ||
        !header->e_ident.is_64() ||
        header->e_ident.is_msb() ||
        !(header->e_type == ET_SCE_EXEC ||
            header->e_type == ET_SCE_REPLAY_EXEC ||
            header->e_type == ET_SCE_RELEXEC ||
            header->e_type == ET_SCE_DYNEXEC ||
            header->e_type == ET_SCE_DYNAMIC)) {
        return false;
    }
    if (header->e_ident.osabi != ELFOSABI_FREEBSD ||
        header->e_machine != EM_X86_64) {
        return false;
    }
    if (header->e_phentsize != sizeof(Elf64_Phdr)) {
        return false;
    }

    Elf64_Phdr *phdr = reinterpret_cast<Elf64_Phdr *>(file + header->e_phoff);
    pheaders.clear();
    for (size_t i = 0; i < header->e_phnum; i++) {
        if (phdr->p_type == PT_DYNAMIC) {
            dynamic = reinterpret_cast<Elf64_Dyn *>(file + phdr->p_offset);
        }
        else if (phdr->p_type == PT_SCE_DYNLIBDATA) {
            dynlibdata = reinterpret_cast<u8 *>(file + phdr->p_offset);
        }
        else if (phdr->p_type == PT_SCE_PROCPARAM) {
            procparam_rva = phdr->p_vaddr;
        }
        else if (phdr->p_type == PT_TLS) {
            u64 tls_size_total = phdr->p_memsz;
            if (tls_size_total) {
                puts("NEEDS TLS");
            }
        }
        pheaders.push_back(phdr++);
    }

    if (!ParseDynamic()) {
        return false;
    }
    return true;
}

/*
Assert some assumptions are true:
  * Any non-LOAD segment with nonzero memsize is covered by a LOAD segment
  * LOAD segments are at least host page size aligned (really they should
    be target aligned).
  * LOAD segments are in-order and contiguous
If these hold, then it is sane to map the raw elf file directly into flat
memory.
Note that the file offset from the elf header to the first LOAD seg needs
to be taken into account for runtime mapping / relocs.
*/
bool ElfFile::CheckSegments() {
    std::vector<Elf64_Phdr *> load_segs;
    std::vector<Elf64_Phdr *> data_segs;
    size_t va_pos = 0;
    for (const auto &p : pheaders) {
        if (p->p_type == PT_LOAD || p->p_type == PT_SCE_RELRO) {
            load_segs.push_back(p);
            if (p->p_align % TARGET_PAGE_SIZE) {
                return false;
            }
            if (p->p_vaddr != va_pos) {
                return false;
            }
            if (p->p_vaddr == 0) {
                load_mem_offset = p->p_offset;
            }
            va_pos = ALIGN_UP(p->p_vaddr + p->p_memsz, p->p_align);
        }
        else if (p->p_memsz > 0) {
            data_segs.push_back(p);
        }
    }
    for (const auto &d : data_segs) {
        bool found = false;
        for (const auto &l : load_segs) {
            if (d->p_vaddr >= l->p_vaddr &&
                (d->p_vaddr + d->p_memsz) <= (l->p_vaddr + l->p_memsz)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
    }
    load_mem_size = va_pos;
    return true;
}

bool ElfFile::Load(const std::string path) {
    object = std::make_unique<VirtualMemory::MappedObject>(path);
    if (!object->is_ok()) {
        return false;
    }
    file = reinterpret_cast<u8 *>(object->Map());
    if (!file) {
        return false;
    }
    printf("Loading %s\n", path.c_str());
    if (!ParseHeaders()) {
        return false;
    }
    /*
    for (auto const p : pheaders) {
        printf("%8x %8x %16llx %16llx %16llx %16llx %16llx %16llx\n", p->p_type,
            p->p_flags, p->p_offset, p->p_vaddr, p->p_paddr, p->p_filesz,
            p->p_memsz, p->p_align);
    }
    */
    if (!CheckSegments()) {
        return false;
    }
    return true;
}

VirtualMemory::Protection ElfFile::GetSegProt(const Elf64_Phdr &phdr) {
    VirtualMemory::Protection prot = VirtualMemory::kNoAccess;
    switch (phdr.p_flags) {
    case ElfSegmentFlags::PF_R:
        prot = VirtualMemory::kReadOnly;
        break;
    case ElfSegmentFlags::PF_R | ElfSegmentFlags::PF_W:
        prot = VirtualMemory::kReadWrite;
        break;
    case ElfSegmentFlags::PF_R | ElfSegmentFlags::PF_X:
        prot = VirtualMemory::kReadExecute;
        break;
    case ElfSegmentFlags::PF_R | ElfSegmentFlags::PF_W | ElfSegmentFlags::PF_X:
        prot = VirtualMemory::kReadWriteExecute;
        break;
    }
    return prot;
}


typedef uintptr_t _Unwind_Word;
typedef intptr_t _Unwind_Sword;
typedef uintptr_t _Unwind_Ptr;
typedef uintptr_t _Unwind_Internal_Ptr;
typedef uint64_t _Unwind_Exception_Class;

typedef intptr_t _sleb128_t;
typedef uintptr_t _uleb128_t;


/* Read an unsigned leb128 value from P, store the value in VAL, return
   P incremented past the value.  We assume that a word is large enough to
   hold any value so encoded; if it is smaller than a pointer on some target,
   pointers should not be leb128 encoded on that target.  */
static const unsigned char *
read_uleb128(const unsigned char *p, _Unwind_Word *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    _Unwind_Word result;

    result = 0;
    do
    {
        byte = *p++;
        result |= ((_Unwind_Word)byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);

    *val = result;
    return p;
}

/* Similar, but read a signed leb128 value.  */
static const unsigned char *
read_sleb128(const unsigned char *p, _Unwind_Sword *val)
{
    unsigned int shift = 0;
    unsigned char byte;
    _Unwind_Word result;

    result = 0;
    do
    {
        byte = *p++;
        result |= ((_Unwind_Word)byte & 0x7f) << shift;
        shift += 7;
    } while (byte & 0x80);

    /* Sign-extend a negative value.  */
    if (shift < 8 * sizeof(result) && (byte & 0x40) != 0)
        result |= -(((_Unwind_Word)1L) << shift);

    *val = (_Unwind_Sword)result;
    return p;
}

size_t ElfEHInfo::GetNativeSize() {
    size_t total_size = fdes.size() * sizeof(RUNTIME_FUNCTION);
    // TODO convert instructions and add resulting size
    total_size += (1 + fdes.size()) * sizeof(UNWIND_INFO);
    total_size += fdes.size() * sizeof(UNWIND_CODE) * 10;
    return total_size;
}

bool ElfEHInfo::Init(const u8 *base, const eh_frame_hdr *hdr) {
    if (hdr->version != 1) {
        return false;
    }
#define READ_RAW(type, ptr) *(type *)ptr; ptr += sizeof(type);
    auto dw_decode = [&hdr](u8 enc, const u8 *&buf, uintptr_t base = 0) {
        uintptr_t val = 0;
        if (base == 0) {
            base = (uintptr_t)buf;
        }
        switch (enc & 0x70) {
        case DW_EH_PE_absptr:
            break;
        case DW_EH_PE_pcrel:
            val += base;
            break;
        case DW_EH_PE_datarel:
            val += (uintptr_t)hdr;
            break;
        default:
            printf("unexpected enc base %02x\n", enc);
            __debugbreak();
            break;
        }
        switch (enc & 0x0f) {
        case DW_EH_PE_udata2:
            val += READ_RAW(u16, buf);
            break;
        case DW_EH_PE_udata4:
            val += READ_RAW(u32, buf);
            break;
        case DW_EH_PE_sdata4:
            val += READ_RAW(s32, buf);
            break;
        default:
            printf("unexpected enc type %02x\n", enc);
            __debugbreak();
            break;
        }
        if (enc & DW_EH_PE_indirect) {
            val = *(uintptr_t *)val;
        }
        return val;
    };
    auto dw_read_cie = [&dw_decode](eh_cie *cie, const u8 *buf) {
        u32 len = READ_RAW(u32, buf);
        if (len == 0xffffffff) {
            return false;
        }
        auto buf_start = buf;
        u32 id = READ_RAW(u32, buf);
        if (id != 0) {
            return false;
        }
        u8 version = READ_RAW(u8, buf);
        if (version != 1 && version != 3) {
            return false;
        }
        auto aug = (const char *)buf;
        buf += strlen(aug) + 1;
        if (strcmp(aug, "zR") &&
            strcmp(aug, "zPLR")) {
            return false;
        }
        buf = read_uleb128(buf, &cie->caf);
        buf = read_sleb128(buf, &cie->daf);
        // In DWARF Version 2, this field is a ubyte.
        // Practically, i dont think it matters
        _uleb128_t rr;
        buf = read_uleb128(buf, &rr);
        _uleb128_t adl = 0;
        u8 lsda_enc = DW_EH_PE_omit;
        cie->fde_enc = DW_EH_PE_omit;
        const char *c = aug;
        while (*c) {
            switch (*c) {
            case 'z':
                buf = read_uleb128(buf, &adl);
                break;
            case 'P': {
                u8 personality_enc = READ_RAW(u8, buf);
                uintptr_t personality_ptr = dw_decode(personality_enc, buf);
                break;
            }
            case 'L':
                lsda_enc = READ_RAW(u8, buf);
                break;
            case 'R':
                cie->fde_enc = READ_RAW(u8, buf);
                break;
            }
            c++;
        }
        cie->insns = buf;
        cie->insns_len = len - (cie->insns - buf_start);
        return true;
    };
    auto dw_read_fde = [&dw_decode, &dw_read_cie](eh_fde *fde, const u8 *buf) {
        u32 len = READ_RAW(u32, buf);
        if (len == 0xffffffff) {
            return false;
        }
        auto buf_start = buf;
        u32 id = READ_RAW(u32, buf);
        if (id == 0) {
            return false;
        }
        auto eh_cie_ptr = buf_start - id;
        if (!dw_read_cie(&fde->cie, eh_cie_ptr)) {
            return false;
        }
        fde->start = dw_decode(fde->cie.fde_enc, buf);
        fde->end = dw_decode(fde->cie.fde_enc, buf, fde->start);
        u8 adl = READ_RAW(u8, buf);
        // skip over e.g. LSDA ptr
        buf += adl;
        fde->insns = buf;
        fde->insns_len = len - (fde->insns - buf_start);
        return true;
    };
#undef READ_RAW

    const u8 *ptr = (const u8 *)&hdr[1];
    uintptr_t eh_frame_ptr = dw_decode(hdr->eh_frame_ptr_enc, ptr);
    size_t fde_count = dw_decode(hdr->fde_count_enc, ptr);
    fdes.reserve(fde_count);
    for (size_t i = 0; i < fde_count; i++) {
        auto func = dw_decode(hdr->table_enc, ptr);
        auto desc = dw_decode(hdr->table_enc, ptr);
        eh_fde fde;
        if (!dw_read_fde(&fde, (const u8 *)desc)) {
            printf("reading fde %zi failed\n", i);
            continue;
        }
        if (func != fde.start) {
            puts("unexpected range in fde");
        }
        eh_fde_rel fde_rel;
        fde_rel.start = (u32)(fde.start - (uintptr_t)base);
        fde_rel.end = (u32)(fde.end - (uintptr_t)base);
        fde_rel.caf = fde.cie.caf;
        fde_rel.daf = fde.cie.daf;
        fde_rel.init_insns_len = (u32)fde.cie.insns_len;
        fde_rel.init_insns = (u32)(fde.cie.insns - base);
        fde_rel.insns_len = (u32)fde.insns_len;
        fde_rel.insns = (u32)(fde.insns - base);
        fdes.push_back(fde_rel);
    }

    return true;
}

enum CfiOp : u8 {
    DW_CFA_advance_loc        = 0x40,
    DW_CFA_offset             = 0x80,
    DW_CFA_restore            = 0xc0,
    DW_CFA_nop                = 0x00,
    DW_CFA_set_loc            = 0x01,
    DW_CFA_advance_loc1       = 0x02,
    DW_CFA_advance_loc2       = 0x03,
    DW_CFA_advance_loc4       = 0x04,
    DW_CFA_offset_extended    = 0x05,
    DW_CFA_restore_extended   = 0x06,
    DW_CFA_undefined          = 0x07,
    DW_CFA_same_value         = 0x08,
    DW_CFA_register           = 0x09,
    DW_CFA_remember_state     = 0x0a,
    DW_CFA_restore_state      = 0x0b,
    DW_CFA_def_cfa            = 0x0c,
    DW_CFA_def_cfa_register   = 0x0d,
    DW_CFA_def_cfa_offset     = 0x0e,
    DW_CFA_def_cfa_expression = 0x0f,
    DW_CFA_expression         = 0x10,
    DW_CFA_offset_extended_sf = 0x11,
    DW_CFA_def_cfa_sf         = 0x12,
    DW_CFA_def_cfa_offset_sf  = 0x13,
    DW_CFA_val_offset         = 0x14,
    DW_CFA_val_offset_sf      = 0x15,
    DW_CFA_val_expression     = 0x16,
};

enum DwarfCfiReg {
    kRax,
    kRdx,
    kRcx,
    kRbx,
    kRsi,
    kRdi,
    kRbp,
    kRsp,
    kR8,
    kR9,
    kR10,
    kR11,
    kR12,
    kR13,
    kR14,
    kR15,
    // [rsp+0] from call
    kReturnAddress,
    kXmm0,
    kXmm1,
    kXmm2,
    kXmm3,
    kXmm4,
    kXmm5,
    kXmm6,
    kXmm7,
    kXmm8,
    kXmm9,
    kXmm10,
    kXmm11,
    kXmm12,
    kXmm13,
    kXmm14,
    kXmm15,
    kSt0,
    kSt1,
    kSt2,
    kSt3,
    kSt4,
    kSt5,
    kSt6,
    kSt7,
    kMm0,
    kMm1,
    kMm2,
    kMm3,
    kMm4,
    kMm5,
    kMm6,
    kMm7,
    kRflags,
    kEs,
    kCs,
    kSs,
    kDs,
    kFs,
    kGs,
    kReserved_56,
    kReserved_57,
    kFsBase,
    kGsBase,
    kReserved_60,
    kReserved_61,
    kTr,
    kLdt,
    kMxcsr,
    kFcw,
    kFsw
};

struct DwarfCfi {
    CfiOp op;
    uintptr_t operand[2];
    size_t insn_len;
};

static int CFIOpNumOperands(CfiOp op) {
    switch (op) {
    case DW_CFA_nop: return 0;
    case DW_CFA_advance_loc:
    case DW_CFA_advance_loc1:
    case DW_CFA_advance_loc2:
    case DW_CFA_advance_loc4:
    case DW_CFA_def_cfa_register:
    case DW_CFA_def_cfa_offset:
        return 1;
    case DW_CFA_def_cfa:
    case DW_CFA_offset:
        return 2;
    default:
        __debugbreak();
        return 0;
    }
}

static const char *CfiGetOpName(CfiOp op) {
#define RET_STR(x) case DW_CFA_##x: return #x;
    switch (op) {
    RET_STR(nop);
    RET_STR(set_loc);
    RET_STR(advance_loc1);
    RET_STR(advance_loc2);
    RET_STR(advance_loc4);
    RET_STR(offset_extended);
    RET_STR(restore_extended);
    RET_STR(undefined);
    RET_STR(same_value);
    RET_STR(register);
    RET_STR(remember_state);
    RET_STR(restore_state);
    RET_STR(def_cfa);
    RET_STR(def_cfa_register);
    RET_STR(def_cfa_offset);
    RET_STR(def_cfa_expression);
    RET_STR(expression);
    RET_STR(offset_extended_sf);
    RET_STR(def_cfa_sf);
    RET_STR(def_cfa_offset_sf);
    RET_STR(val_offset);
    RET_STR(val_offset_sf);
    RET_STR(val_expression);
    RET_STR(advance_loc);
    RET_STR(offset);
    RET_STR(restore);
    default:
        __debugbreak();
        return "unknown";
    }
#undef RET_STR
}

static const char *CfiGetRegName(DwarfCfiReg reg) {
#define RET_STR(x) case k##x: return #x;
    switch (reg) {
    RET_STR(Rax);
    RET_STR(Rdx);
    RET_STR(Rcx);
    RET_STR(Rbx);
    RET_STR(Rsi);
    RET_STR(Rdi);
    RET_STR(Rbp);
    RET_STR(Rsp);
    RET_STR(R8);
    RET_STR(R9);
    RET_STR(R10);
    RET_STR(R11);
    RET_STR(R12);
    RET_STR(R13);
    RET_STR(R14);
    RET_STR(R15);
    RET_STR(ReturnAddress);
    RET_STR(Xmm0);
    RET_STR(Xmm1);
    RET_STR(Xmm2);
    RET_STR(Xmm3);
    RET_STR(Xmm4);
    RET_STR(Xmm5);
    RET_STR(Xmm6);
    RET_STR(Xmm7);
    RET_STR(Xmm8);
    RET_STR(Xmm9);
    RET_STR(Xmm10);
    RET_STR(Xmm11);
    RET_STR(Xmm12);
    RET_STR(Xmm13);
    RET_STR(Xmm14);
    RET_STR(Xmm15);
    RET_STR(St0);
    RET_STR(St1);
    RET_STR(St2);
    RET_STR(St3);
    RET_STR(St4);
    RET_STR(St5);
    RET_STR(St6);
    RET_STR(St7);
    RET_STR(Mm0);
    RET_STR(Mm1);
    RET_STR(Mm2);
    RET_STR(Mm3);
    RET_STR(Mm4);
    RET_STR(Mm5);
    RET_STR(Mm6);
    RET_STR(Mm7);
    RET_STR(Rflags);
    RET_STR(Es);
    RET_STR(Cs);
    RET_STR(Ss);
    RET_STR(Ds);
    RET_STR(Fs);
    RET_STR(Gs);
    RET_STR(Reserved_56);
    RET_STR(Reserved_57);
    RET_STR(FsBase);
    RET_STR(GsBase);
    RET_STR(Reserved_60);
    RET_STR(Reserved_61);
    RET_STR(Tr);
    RET_STR(Ldt);
    RET_STR(Mxcsr);
    RET_STR(Fcw);
    RET_STR(Fsw);
    default:
        __debugbreak();
        return "unknown";
    }
#undef RET_STR
}

static void CFIDump(const DwarfCfi &insn) {
    if (insn.op == DW_CFA_nop) {
        return;
    }
    int num_operands = CFIOpNumOperands(insn.op);
    auto op_name = CfiGetOpName(insn.op);
    switch (insn.op) {
    case DW_CFA_advance_loc:
    case DW_CFA_advance_loc1:
    case DW_CFA_advance_loc2:
    case DW_CFA_advance_loc4:
        printf("  %s(%lli)\n", op_name, insn.operand[0]);
        break;
    case DW_CFA_def_cfa:
        printf("  %s(%s,%lli)\n", op_name,
            CfiGetRegName((DwarfCfiReg)insn.operand[0]), insn.operand[1]);
        break;
    case DW_CFA_def_cfa_register:
        printf("  %s(%s)\n", op_name,
            CfiGetRegName((DwarfCfiReg)insn.operand[0]));
        break;
    case DW_CFA_def_cfa_offset:
        printf("  %s(%lli)\n", op_name, insn.operand[0]);
        break;
    case DW_CFA_offset:
        printf("  %s(%s,%lli)\n", op_name,
            CfiGetRegName((DwarfCfiReg)insn.operand[0]),
            insn.operand[1]);
        break;
    default:
        __debugbreak();
    }
}

static bool DecodeCFI(DwarfCfi *cfi, const eh_fde_rel &fde, uintptr_t src) {
    const u8 *ptr = (u8 *)src;
    memset(cfi, 0, sizeof(*cfi));

#define READ_RAW(type, ptr) *(type *)ptr; ptr += sizeof(type);

    cfi->op = READ_RAW(CfiOp, ptr);
    switch (cfi->op) {
    case DW_CFA_nop:
        break;
    case DW_CFA_advance_loc1:
        cfi->operand[0] = READ_RAW(u8, ptr);
        break;
    case DW_CFA_advance_loc2:
        cfi->operand[0] = READ_RAW(u16, ptr);
        break;
    case DW_CFA_advance_loc4:
        cfi->operand[0] = READ_RAW(u32, ptr);
        break;
    case DW_CFA_def_cfa:
        ptr = read_uleb128(ptr, &cfi->operand[0]);
        ptr = read_uleb128(ptr, &cfi->operand[1]);
        break;
    case DW_CFA_def_cfa_register:
        ptr = read_uleb128(ptr, &cfi->operand[0]);
        break;
    case DW_CFA_def_cfa_offset:
        ptr = read_uleb128(ptr, &cfi->operand[0]);
        break;
    default:
        switch (cfi->op & 0xc0) {
        case DW_CFA_advance_loc:
            cfi->operand[0] = cfi->op & 0x3f;
            cfi->op = DW_CFA_advance_loc;
            break;
        case DW_CFA_offset:
            cfi->operand[0] = cfi->op & 0x3f;
            cfi->op = DW_CFA_offset;
            ptr = read_uleb128(ptr, &cfi->operand[1]);
            break;
        default:
            printf("unknown cfi op %02x\n", cfi->op);
            __debugbreak();
            return false;
        }
    }

#undef READ_RAW

    switch (cfi->op) {
    case DW_CFA_advance_loc:
    case DW_CFA_advance_loc1:
    case DW_CFA_advance_loc2:
    case DW_CFA_advance_loc4:
        cfi->operand[0] *= fde.caf;
        break;
    case DW_CFA_offset:
        cfi->operand[1] *= fde.daf;
        break;
    }

    cfi->insn_len = (uintptr_t)ptr - src;
    return true;
}

static u8 DwRegToUwReg(DwarfCfiReg reg) {
    switch (reg) {
    case kRax: return UNWIND_REGISTER::RAX;
    case kRdx: return UNWIND_REGISTER::RDX;
    case kRcx: return UNWIND_REGISTER::RCX;
    case kRbx: return UNWIND_REGISTER::RBX;
    case kRsi: return UNWIND_REGISTER::RSI;
    case kRdi: return UNWIND_REGISTER::RDI;
    case kRbp: return UNWIND_REGISTER::RBP;
    case kRsp: return UNWIND_REGISTER::RSP;
    case kR8 : return UNWIND_REGISTER::R8;
    case kR9 : return UNWIND_REGISTER::R9;
    case kR10: return UNWIND_REGISTER::R10;
    case kR11: return UNWIND_REGISTER::R11;
    case kR12: return UNWIND_REGISTER::R12;
    case kR13: return UNWIND_REGISTER::R13;
    case kR14: return UNWIND_REGISTER::R14;
    case kR15: return UNWIND_REGISTER::R15;
    default:
        __debugbreak();
        return 0;
    }
}

// TODO DONT USE STL IN HERE. ITS SOOO SLOOWWWWW!!
bool ElfEHInfo::TranslateCFI(PUNWIND_INFO ui, const eh_fde_rel &fde, uintptr_t base) {
    //printf("fde %llx+%x\n", base, fde.start);

    DwarfCfi cfi;
    std::vector<DwarfCfi> insns;
    for (size_t i = 0; i < fde.init_insns_len;) {
        DecodeCFI(&cfi, fde, base + fde.init_insns + i);
        //CFIDump(cfi);
        i += cfi.insn_len;
        insns.emplace_back(cfi);
    }
    // It seems there are always the same init instructions
    // (to adhere to x64 ABI). MSVC optimizes this away (assumes the
    // behavior is implicit), so it can be ignored. Just make sure that is
    // in fact always the case.
    if (insns.size() < 2) {
        __debugbreak();
        return false;
    }
    if (!(insns[0].op == DW_CFA_def_cfa &&
        insns[0].operand[0] == kRsp &&
        insns[0].operand[1] == 8)) {
        __debugbreak();
        return false;
    }
    if (!(insns[1].op == DW_CFA_offset &&
        insns[1].operand[0] == kReturnAddress &&
        insns[1].operand[1] == -8)) {
        __debugbreak();
        return false;
    }
    for (size_t i = 2; i < insns.size(); i++) {
        if (insns[i].op != DW_CFA_nop) {
            __debugbreak();
            return false;
        }
    }
    insns.clear();
    //printf("  ---\n");
    for (uintptr_t i = 0; i < fde.insns_len;) {
        DecodeCFI(&cfi, fde, base + fde.insns + i);
        //CFIDump(cfi);
        i += cfi.insn_len;
        insns.emplace_back(cfi);
    }

    memset(ui, 0, sizeof(*ui));
    ui->Version = 1;

    u8 prolog_end = 0;
    bool sets_fpreg = false;
    DwarfCfiReg fpreg;
    typedef std::map<intptr_t, DwarfCfiReg> push_map_t;
    std::map<u8, push_map_t> push_levels;
    for (const auto &insn : insns) {
        if (insn.op == DW_CFA_advance_loc ||
            insn.op == DW_CFA_advance_loc1 ||
            insn.op == DW_CFA_advance_loc2 ||
            insn.op == DW_CFA_advance_loc4) {
            prolog_end += insn.operand[0];
        }
        else if (insn.op == DW_CFA_def_cfa_register) {
            if (sets_fpreg) {
                // die on multiple assignments
                __debugbreak();
                return false;
            }
            sets_fpreg = true;
            fpreg = (DwarfCfiReg)insn.operand[0];
        }
        else if (insn.op == DW_CFA_offset) {
            push_levels[prolog_end][insn.operand[1]] = (DwarfCfiReg)insn.operand[0];
        }
    }
    if (sets_fpreg) {
        // Dwarf sets FP relative to CFA, but windows is relative to *current* SP
        // (i.e. SP value midway through prolog).
        // Since the target code is using `mov rbp, rsp` all over the place, just
        // set to 0.
        ui->FrameOffset = 0;
        ui->FrameRegister = DwRegToUwReg(fpreg);
    }
    ui->SizeOfProlog = prolog_end;

    /*
    000001ac`1a8252e0 55              push    rbp
    000001ac`1a8252e1 4889e5          mov     rbp,rsp
    000001ac`1a8252e4 4157            push    r15
    000001ac`1a8252e6 4156            push    r14
    000001ac`1a8252e8 4154            push    r12
    000001ac`1a8252ea 53              push    rbx
    000001ac`1a8252eb 4883e4e0        and     rsp,0FFFFFFFFFFFFFFE0h
    000001ac`1a8252ef 4881ec80010000  sub     rsp,180h

    advance_loc(1)
    def_cfa_offset(16)
    offset(Rbp,-16)
    advance_loc(3)
    def_cfa_register(Rbp)
    advance_loc(18)
    offset(Rbx,-48)
    offset(R12,-40)
    offset(R14,-32)
    offset(R15,-24)

    [end of prolog]
    -48 rbx
    -40 r12
    -32 r14
    -24 r15
    -16 rbp         <- fp
    - 8 saved rip
    [caller frame]
    */

    PUNWIND_CODE uc = ui->UnwindCode;
    for (auto &level_it = push_levels.rbegin(); level_it != push_levels.rend();
        level_it++) {
        for (const auto &push : level_it->second) {
            if (sets_fpreg && fpreg == push.second) {
                // this should have it's own location, but it doesn't seem to matter
                uc->CodeOffset = ui->SizeOfProlog;
                uc->UnwindOp = UWOP_SET_FPREG;
                uc->OpInfo = ui->FrameRegister;
                uc++;
            }
            uc->CodeOffset = level_it->first;
            uc->UnwindOp = UWOP_PUSH_NONVOL;
            uc->OpInfo = DwRegToUwReg(push.second);
            uc++;
        }
    }
    ui->CountOfCodes = uc - ui->UnwindCode;

    return true;
}

bool ElfEHInfo::Install(const void *code_base, void *eh_base) {
    uintptr_t base = (uintptr_t)code_base;
    
    PRUNTIME_FUNCTION rfs = reinterpret_cast<PRUNTIME_FUNCTION>(eh_base);
    PUNWIND_INFO uis = reinterpret_cast<PUNWIND_INFO>((uintptr_t)eh_base +
        fdes.size() * sizeof(RUNTIME_FUNCTION));
    
    PRUNTIME_FUNCTION rf = rfs;
    PUNWIND_INFO ui = uis;
    
    PUNWIND_INFO dummy_unwind = ui++;
    memset(dummy_unwind, 0, sizeof(*dummy_unwind));
    dummy_unwind->Version = 1;

    for (const auto &fde : fdes) {
        rf->BeginAddress = fde.start;
        rf->EndAddress = fde.end;
        if (TranslateCFI(ui, fde, base)) {
            rf->UnwindInfoAddress = (u32)((uintptr_t)ui - base);
            ui = (PUNWIND_INFO)((uintptr_t)ui + sizeof(UNWIND_INFO) - sizeof(UNWIND_CODE) +
                ui->CountOfCodes * sizeof(UNWIND_CODE));
        }
        else {
            // TODO could also use this to dedupe funcs without instructions
            rf->UnwindInfoAddress = (u32)((uintptr_t)dummy_unwind - base);
        }
        rf++;
    }

    if (!RtlAddFunctionTable(rfs, (DWORD)fdes.size(), base)) {
        return false;
    }
    return VirtualMemory::SetProtection(eh_base, GetNativeSize(),
        VirtualMemory::kReadOnly);
}

#include <DbgEng.h>
#pragma comment(lib, "dbgeng")

bool ElfFile::Map() {
    // TODO perhaps allocate some pages directly before the loaded file, to
    // place simulator thunks?

    size_t native_eh_size = 0;
    for (const auto &p : pheaders) {
        if (p->p_type == PT_GNU_EH_FRAME) {
            auto eh = std::make_unique<ElfEHInfo>();
            auto hdr = reinterpret_cast<eh_frame_hdr *>(file + p->p_offset);
            if (!eh->Init(file + load_mem_offset, hdr)) {
                break;
            }
            eh_info = std::move(eh);
            native_eh_size = eh_info->GetNativeSize();
            native_eh_size = ALIGN_UP(native_eh_size, TARGET_PAGE_SIZE);
            break;
        }
    }

    // Create a contiguous allocation for the loadable range of the file
    relocbase = VirtualMemory::MakeAllocation(load_mem_size + native_eh_size,
        VirtualMemory::kReadWriteExecute);
    typedef ULONG (*DbgPrint_t)(_In_ PCHAR Format, ...);
    auto DbgPrint = (DbgPrint_t)GetProcAddress(GetModuleHandleA("ntdll"), "DbgPrint");
    DbgPrint("%p %8llx bytes %s\n", relocbase.get(), load_mem_size, modules[0].name);
    if (!relocbase) {
        return false;
    }
    
    // Copy only loadable sub-ranges into the allocated region
    //  * This assumes allocation is initialized to zero!
    for (const auto &p : pheaders) {
        if (p->p_type == PT_LOAD || p->p_type == PT_SCE_RELRO) {
            void *seg = relocbase.get() + p->p_vaddr;
            std::memcpy(seg, file + p->p_offset, p->p_filesz);
        }
    }

    if (eh_info) {
        eh_info->Install(relocbase.get(), relocbase.get() + load_mem_size);
    }

    // TODO should initialize JMPREL to sceKernelReportUnpatchedFunctionCall

    // Create list of visible symbols to speedup symbol resolving
    for (auto s = dynsym.ptr; s < &dynsym.ptr[dynsym.num]; s++) {
        const int st_bind = ELF64_ST_BIND(s->st_info);
        const int st_type = ELF64_ST_TYPE(s->st_info);
        const int st_visibility = ELF64_ST_VISIBILITY(s->st_other);
        const char *sym_name = &dynstr.ptr[s->st_name];
        if (st_visibility == STV_HIDDEN) {
            continue;
        }
        if (st_type != STT_FUNC && st_type != STT_OBJECT) {
            continue;
        }
        const auto first_delimeter = strchr(sym_name, '#');
        std::string global_name;
        if (first_delimeter) {
            global_name.assign(sym_name, first_delimeter);
        }
        else {
            global_name = sym_name;
        }
        symbol_map[global_name] = (uintptr_t)(relocbase.get() + s->st_value);
    }

    return SetSegmentProtections();
}

bool ElfFile::SetSegmentProtections() {
    // Apply sub-range runtime memory protection
    for (const auto &p : pheaders) {
        if (p->p_type == PT_LOAD || p->p_type == PT_SCE_RELRO) {
            void *seg = relocbase.get() + p->p_vaddr;
            if (!VirtualMemory::SetProtection(seg,
                ALIGN_UP(p->p_memsz, p->p_align), GetSegProt(*p))) {
                return false;
            }
        }
    }
    return true;
}

const char *reloc_type_name(const u32 r_type) {
#define RET_STR(x) case x: return #x;
    switch (r_type) {
        RET_STR(R_X86_64_64);
        RET_STR(R_X86_64_GLOB_DAT);
        RET_STR(R_X86_64_JMP_SLOT);
        RET_STR(R_X86_64_RELATIVE);
        RET_STR(R_X86_64_DPTMOD64);
    default: return "UNKNOWN";
    }
#undef RET_STR
}

const char *st_bind_name(const int st_bind) {
#define RET_STR(x) case x: return #x;
    switch (st_bind) {
        RET_STR(STB_LOCAL);
        RET_STR(STB_GLOBAL);
        RET_STR(STB_WEAK);
    default: return "UNKNOWN";
    }
#undef RET_STR
}

const char *st_type_name(const int st_type) {
#define RET_STR(x) case x: return #x;
    switch (st_type) {
        RET_STR(STT_NOTYPE);
        RET_STR(STT_OBJECT);
        RET_STR(STT_FUNC);
        RET_STR(STT_SECTION);
        RET_STR(STT_FILE);
        RET_STR(STT_COMMON);
        RET_STR(STT_TLS);
    default: return "UNKNOWN";
    }
#undef RET_STR
}

const char *st_visibility_name(const int st_visibility) {
#define RET_STR(x) case x: return #x;
    switch (st_visibility) {
        RET_STR(STV_DEFAULT);
        RET_STR(STV_INTERNAL);
        RET_STR(STV_HIDDEN);
        RET_STR(STV_PROTECTED);
    default: return "UNKNOWN";
    }
#undef RET_STR
}

bool ElfFile::FriendlySymbolName(const char *name, std::string *friendly) {
    // TODO Don't really need to lookup NID -> real name, but it would be nice
    // For now, just return formatted triplet
    symbol_info_t si;
    if (!sce_unmangle_symbol(name, &si)) {
        // most likely failed because it's already unmangled
        // weak symbols like module_start/module_stop hit this...
        *friendly = name;
        return false;
    }
    auto modname = modules[si.mid].name;
    auto libname = libraries[si.lid].name;
    if (!strcmp(modname, libname)) {
        // simplify if modulename == libraryname
        return string_vsprintf(friendly, "%16llx#%s", si.nid, modname);
    }
    else {
        return string_vsprintf(friendly, "%16llx#%s#%s", si.nid, libname, modname);
    }
}

void ElfFile::AllocatePltSlot(const char *name, const Elf64_Rela &reloc) {
    // plt_slots just acts as a cache of jmprel -> sym mapping
    // it wouldn't need to be done like this (could be looked up at dyld time)
    symbol_info_t si;
    if (!sce_unmangle_symbol(name, &si)) {
        // XXX for now, allocate slot which will blow up when used.
        // should be able to handle this, though...
        si.mid = ~0;
        si.nid = ~0ull;
    }
    PltRecord record;
    record.slot_offset = reloc.r_offset;
    record.mid = si.mid;
    record.nid = si.nid;
    plt_slots.push_back(record);
}
#include "Executor.h"
void ElfFile::ProcessRelocations(Simulator::Executor *exec, const DynList<Elf64_Rela> &relocs) {
    // could be further cached by having executor maintain the requestor->available module list
    std::vector<ElfFile *> import_modules;
    for (const auto &m : modules) {
        import_modules.push_back(exec->GetLoadedModule(m.name));
    }
    for (auto r = relocs.ptr; r < &relocs.ptr[relocs.num]; r++) {
        u32 r_sym = ELF64_R_SYM(r->r_info);
        u32 r_type = ELF64_R_TYPE(r->r_info);
        const auto &sym = dynsym.ptr[r_sym];
        const int st_bind = ELF64_ST_BIND(sym.st_info);
        const int st_type = ELF64_ST_TYPE(sym.st_info);
        const int st_visibility = ELF64_ST_VISIBILITY(sym.st_other);
        const char *sym_name = &dynstr.ptr[sym.st_name];
        const uintptr_t A = r->r_addend;
        uintptr_t S = sym.st_value;
        const uintptr_t B = reinterpret_cast<uintptr_t>(relocbase.get());
        // All supported relocs are 64bit
        u64 *const EA = reinterpret_cast<u64 *>(relocbase.get() + r->r_offset);
        uintptr_t value = 0;

        // Is it an unresolved import?
        if (S == 0 && strlen(sym_name)) {
            /*
            std::string friendly_name;
            FriendlySymbolName(sym_name, &friendly_name);
            printf("import %-20s @ +%16llx : %16llx %-10s %-10s %-10s %s\n",
                reloc_type_name(r_type), r->r_offset, value,
                st_bind_name(st_bind), st_type_name(st_type),
                st_visibility_name(st_visibility), friendly_name.c_str());
            //*/
            
            // TODO figure out how to handle non-mangled symbols

            symbol_info_t si;
            if (!sce_unmangle_symbol(sym_name, &si)) {
                //printf("failed to unmangle JMP_SLOT symbol: %s\n", sym_name);
                goto do_reloc;
            }
            ElfFile *dep = import_modules[si.mid];
            if (!dep) {
                goto do_reloc;
            }
            const auto first_delimeter = strchr(sym_name, '#'); 
            std::string global_name;
            if (first_delimeter) {
                global_name.assign(sym_name, first_delimeter);
            }
            else {
                global_name = sym_name;
            }
            const auto &dep_sym = dep->symbol_map.find(global_name);
            if (dep_sym != dep->symbol_map.end()) {
                S = dep_sym->second;
            }
        }
        else {
            S += B;
        }

    do_reloc:
        switch (r_type) {
        case R_X86_64_64:
            value = S + A;
            break;
        case R_X86_64_GLOB_DAT:
            value = S; 
            break;
        case R_X86_64_JMP_SLOT:
            if (S != 0) {
                value = S + A;
            }
            else {
                // Assume the slot is not yet resolved, and existing value is rva
                // to dyld handler thunk.
                value = B + *EA;
            }
            AllocatePltSlot(sym_name, *r);
            break;
        case R_X86_64_RELATIVE:
            value = B + A;
            break;
        case R_X86_64_DPTMOD64:
        {
            // XXX real dynlib loader only makes the patch if symbol was successfully resolved
            // TODO allocate TLS stuff as needed
            u32 tls_index = 0; // find_available_tls_index()
            value = *EA + tls_index;
            break;
        }
        default:
            printf("unsupported reloc type(%i)!\n", r_type);
            return;
        }

        //printf("%llx <- %llx %i S %llx A %llx\n", r->r_offset, value, r_type, S, A);

        // Make the patch
        *EA = value;
    }
}
