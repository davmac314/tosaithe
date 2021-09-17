#ifndef INCLUDE_ELF_H_
#define INCLUDE_ELF_H_

#include <cstdint>

typedef uint16_t Elf64_Half;

typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;

typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

typedef uint64_t Elf64_Addr;

typedef uint64_t Elf64_Off;

static const unsigned EI_NIDENT = 16;

struct Elf64_Ehdr
{
    unsigned char e_ident[EI_NIDENT];
    Elf64_Half e_type;
    Elf64_Half e_machine;
    Elf64_Word e_version;
    Elf64_Addr e_entry;
    Elf64_Off e_phoff;
    Elf64_Off e_shoff;
    Elf64_Word e_flags;
    Elf64_Half e_ehsize;
    Elf64_Half e_phentsize;
    Elf64_Half e_phnum;  /* if PH_XNUM (0xFFFF), the real value is in section 0 sh_info field */
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;  /* if 0, the real value is in section 0 sh_size field */
                         /* (there is always at least one section!) */
    Elf64_Half e_shstrndx; /* index of section containing section header string table */
};

const uint16_t PH_XNUM = 0xFFFF;

// first four bytes of e_ident:
const char ELFMAGIC[4] = { 0x7F, 'E', 'L', 'F' };  // "\177ELF";

const unsigned EI_CLASS = 4;  // index of file class
const unsigned ELFCLASSNONE = 0;
const unsigned ELFCLASS32 = 1;
const unsigned ELFCLASS64 = 2;
const unsigned ELFCLASSNUM = 3; // (number of options)

const unsigned EI_DATA = 5; // index of data encoding
const unsigned ELFDATANONE = 0;
const unsigned ELFDATA2LSB = 1; // 2's complement LSB-first
const unsigned ELFDATA2MSB = 2; // 2's complement MSB-first
const unsigned ELFDATANUM = 3;

const unsigned EI_VERSION = 6; // ELF version
const unsigned EV_NONE = 0;
const unsigned EV_CURRENT = 1; // sure, it makes perfect sense to call it "current"
const unsigned EV_NUM = 2;

const unsigned EI_OSABI = 7;

const unsigned EI_ABIVERSION = 8;

// remaining bytes in e_ident are padding

// values for e_type:
const unsigned ET_NONE = 0;
const unsigned ET_REL = 1;   // relocatable file
const unsigned ET_EXEC = 2;  // executable (including position-independent)
const unsigned ET_DYN = 3;   // dynamic (shared object)
const unsigned ET_CORE = 4;  // core dump
const unsigned ET_NUM = 5;

// values for e_machine:
const unsigned EM_NONE = 0;
const unsigned EM_386 = 3;
const unsigned EM_X86_64 = 62;

// Program header (segment header)
struct Elf64_Phdr
{
    Elf64_Word p_type;
    Elf64_Word p_flags;
    Elf64_Off p_offset;
    Elf64_Addr p_vaddr;
    Elf64_Addr p_paddr;
    Elf64_Xword p_filesz;
    Elf64_Xword p_memsz;
    Elf64_Xword p_align;
};

// segment types
const Elf64_Word PT_NULL = 0;
const Elf64_Word PT_LOAD = 1; // loadable
const Elf64_Word PT_DYNAMIC = 2;
const Elf64_Word PT_INTERP = 3;
const Elf64_Word PT_NOTE = 4;
const Elf64_Word PT_SHLIB = 5; // not actually used
const Elf64_Word PT_PHDR = 6; // program header table itself; not necessarily present in table
const Elf64_Word PT_TLS = 7; // thread-local storage template

const Elf64_Word PT_GNU_EH_FRAME = 0x6474e550; // exception handling

// Section header
struct Elf64_Shdr
{
    Elf64_Word sh_name;  // section name; string table index
    Elf64_Word sh_type;
    Elf64_Xword sh_flags;
    Elf64_Addr sh_addr;  // virtual address
    Elf64_Off sh_offset; // file offset
    Elf64_Xword sh_size;
    Elf64_Word sh_link; // "link to another section"
    Elf64_Word sh_info;
    Elf64_Xword sh_addaralign;
    Elf64_Xword sh_entsize;  // If this section holds a table, the size of its entries
};

const Elf64_Half SHN_UNDEF = 0;  // section index 0 corresponds to undefined section

#endif /* INCLUDE_ELF_H_ */
