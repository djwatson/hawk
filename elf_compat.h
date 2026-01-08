// Copyright 2024 Dave Watson

#pragma once

#if __has_include(<elf.h>)
#include <elf.h>
#else
#include <stdint.h>

typedef struct {
  unsigned char e_ident[16];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint64_t e_entry;
  uint64_t e_phoff;
  uint64_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
  uint32_t sh_name;
  uint32_t sh_type;
  uint64_t sh_flags;
  uint64_t sh_addr;
  uint64_t sh_offset;
  uint64_t sh_size;
  uint32_t sh_link;
  uint32_t sh_info;
  uint64_t sh_addralign;
  uint64_t sh_entsize;
} Elf64_Shdr;

typedef struct {
  uint32_t st_name;
  unsigned char st_info;
  unsigned char st_other;
  uint16_t st_shndx;
  uint64_t st_value;
  uint64_t st_size;
} Elf64_Sym;

#define ELFMAG0 0x7f
#define ELFMAG1 'E'
#define ELFMAG2 'L'
#define ELFMAG3 'F'
#define ELFCLASS64 2
#define ELFDATA2LSB 1
#define ELFOSABI_SYSV 0
#define ET_REL 1
#define EM_X86_64 62
#define EM_AARCH64 183
#define EV_CURRENT 1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHT_NOBITS 8
#define SHT_STRTAB 3
#define SHT_SYMTAB 2
#define SHN_ABS 0xfff1
#define STB_GLOBAL 1
#define STT_FILE 4
#define STT_FUNC 2
#define ELF64_ST_INFO(bind, type) (((bind) << 4) + ((type)&0xf))
#endif
