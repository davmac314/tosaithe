#ifndef INCLUDE_ELF_H_
#define INCLUDE_ELF_H_

#include <stdint.h>

typedef uint16_t Elf64_Half;

typedef uint32_t Elf64_Word;
typedef uint32_t Elf64_Sword;

typedef uint64_t Elf64_Addr;

typedef uint64_t Elf64_Off;

static const unsigned EI_NIDENT = 16;

typedef struct {
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
    Elf64_Half e_phnum;
    Elf64_Half e_shentsize;
    Elf64_Half e_shnum;
    Elf64_Half e_shstrndx;
} Elf64_Ehdr;

#endif /* INCLUDE_ELF_H_ */
