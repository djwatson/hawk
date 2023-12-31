// Copyright 2023 Dave Watson

#define _GNU_SOURCE

#include "jitdump.h"

#include <assert.h>   // for assert
#include <elf.h>      // for (anonymous), Elf64_Shdr, Elf64...
#include <fcntl.h>    // for open, O_CLOEXEC, O_CREAT, O_RDWR
#include <stddef.h>   // for offsetof
#include <stdint.h>   // for uint32_t, uint8_t, uint64_t
#include <stdio.h>    // for sprintf, printf, fprintf, fclose
#include <stdlib.h>   // for exit
#include <string.h>   // for strlen, memcpy, memset
#include <sys/mman.h> // for mmap, munmap, MAP_PRIVATE, PRO...
#include <sys/stat.h> // for S_IRUSR, S_IWUSR
#include <time.h>     // for clock_gettime, timespec, CLOCK...
#include <unistd.h>   // for getpid, write, close, fsync

#include "defs.h"

static int jit_cnt = 0;

/* Earlier perf_map tmp support - supplies names to jit regions */
void perf_map(uint64_t fn, uint64_t len, const char *name) {
  char buf[256];
  snprintf(buf, sizeof(buf) - 1, "/tmp/perf-%i.map", getpid());
  __auto_type file = fopen(buf, "a");
  if (strlen(name)) {
    fprintf(file, "%lx %lx jit function %s %i\n", (uint64_t)fn, len, name,
            jit_cnt);
  } else {
    fprintf(file, "%lx %lx jit anon function %i\n", (uint64_t)fn, len, jit_cnt);
  }
  fclose(file);
}

static void *mapaddr = NULL;
static int fd;

static void jit_dump_error() {
  printf("Jitdump: Could not write\n");
  exit(-1);
}

/* Newer jit dump support.  Requires perf record -k 1, and then perf
   inject, before perf report, but gives full asm listing */
void jit_dump(int len, uint64_t fn, const char *name) {
  struct {
    uint32_t id;
    uint32_t total_size;
    uint64_t timestamp;

    // JIT_CODE_LOAD
    uint32_t pid;
    uint32_t tid;
    uint64_t vma;
    uint64_t code_addr;
    uint64_t code_size;
    uint64_t code_index;
  } record;
  char funcname[256];
  snprintf(funcname, sizeof(funcname) - 1, "Function_%s_%i", name, jit_cnt);

  // clock
  struct timespec ts;
  int result = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (result) {
    printf("Error: clock_gettime: %i\n", result);
    exit(-1);
  }
  record.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

  record.id = 0; // JIT_CODE_LOAD
  record.total_size = sizeof(record) + len + strlen(funcname) + 1;

  record.pid = getpid();
  record.tid = gettid();
  record.vma = (uint64_t)fn;
  record.code_addr = (uint64_t)fn;
  record.code_size = len;
  record.code_index = jit_cnt;

  if (write(fd, &record, sizeof(record)) != sizeof(record)) {
    jit_dump_error();
  }
  if (write(fd, funcname, strlen(funcname) + 1) != strlen(funcname) + 1) {
    jit_dump_error();
  }
  if (write(fd, (void *)fn, len) != len) {
    jit_dump_error();
  }
}

struct {
  uint32_t magic;
  uint32_t version;
  uint32_t total_size;
  uint32_t elf_mach;
  uint32_t pad1;
  uint32_t pid;
  uint64_t timestamp;
  uint64_t flags;
} header;

EXPORT void jit_dump_init() {
  char buf[256];

  snprintf(buf, sizeof(buf) - 1, "jit-%i.dump", getpid());
  fd = open(buf, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
  if (fd < 0) {
    printf("Error opening %s\n", buf);
    exit(-1);
  }
  struct timespec ts;
  int result = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (result) {
    printf("Error: clock_gettime: %i\n", result);
    exit(-1);
  }
  header.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

  header.magic = 0x4A695444;
  header.version = 1;
  header.total_size = sizeof(header);
  header.elf_mach = EM_X86_64;
  header.pad1 = 0;
  header.pid = getpid();
  header.flags = 0;
  if (write(fd, &header, sizeof(header)) != sizeof(header)) {
    printf("Could not init jit dump\n");
    exit(-1);
  }
  fsync(fd);

  mapaddr =
      mmap(NULL, sizeof(header), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (!mapaddr) {
    printf("Failed to map file\n");
    exit(-1);
  }
}

EXPORT void jit_dump_close() {
  if (mapaddr) {
    munmap(mapaddr, sizeof(header));
    close(fd);
  }
}

/// GDB jit-reader interface
#define JIT_REGISTER 1
struct jit_code_entry {
  struct jit_code_entry *next;
  struct jit_code_entry *prev;
  const void *addr;
  uint64_t size;
};
struct jit_descriptor {
  uint32_t version;
  uint32_t action;
  struct jit_code_entry *relevant_entry;
  struct jit_code_entry *first_entry;
};
struct jit_descriptor __jit_debug_descriptor = {1, 0, 0, 0};
void NOINLINE __jit_debug_register_code() {
  /* GDB sets a breakpoint at this function. */
  __asm__ __volatile__("");
}

struct jit_code_entry *last_entry = NULL;
struct jit_code_entry *first_entry = NULL;

typedef struct GDBElfImage {
  Elf64_Ehdr hdr;
  Elf64_Shdr hdrs[6];
  Elf64_Sym syms[3];
  uint8_t data[4096];
} GDBElfImage;

static void build_elf(uint64_t code, int code_sz, GDBElfImage *image, int num);
void jit_reader_add(int len, uint64_t fn) {
  struct jit_code_entry *jitcode = malloc(sizeof(struct jit_code_entry));
  GDBElfImage *image = malloc(sizeof(GDBElfImage));
  if (!image || !jitcode) {
    printf("jit_reader_add: malloc failure\n");
    exit(-1);
  }
  build_elf(fn, len, image, jit_cnt);

  jitcode->addr = image;
  jitcode->size = sizeof(GDBElfImage);
  jitcode->next = NULL;
  if (first_entry) {
    jitcode->prev = last_entry;
    last_entry->next = jitcode;
    last_entry = jitcode;
  } else {
    first_entry = jitcode;
    last_entry = jitcode;
    jitcode->prev = NULL;
  }

  __jit_debug_descriptor.first_entry = first_entry;
  __jit_debug_descriptor.relevant_entry = jitcode;
  __jit_debug_descriptor.action = JIT_REGISTER;
  __jit_debug_descriptor.version = 1;
  __jit_debug_register_code();
  jit_cnt++;
}

////////////// GDB elf entry ///////////////

// Sections text, strtab, symtab, debug info, debug_abbrev, debug_line,
// debug_str (only nash), shstrtab, eh_frame (only lj) symbols file, func

static int64_t write_buf(int64_t *offset, uint8_t *data, void *obj,
                         int64_t len) {
  __auto_type start_offset = *offset;
  assert(*offset + len < 4096);
  memcpy(&data[*offset], obj, len);
  *offset += len;
  return start_offset;
}

static int64_t write_strz(int64_t *offset, uint8_t *data, const char *obj) {
  __auto_type len = strlen(obj) + 1; // null terminated
  return write_buf(offset, data, (void *)obj, (int64_t)len);
}

#define DW_CIE_VERSION 1
enum {
  /* Yes, the order is strange, but correct. */
  DW_REG_AX,
  DW_REG_DX,
  DW_REG_CX,
  DW_REG_BX,
  DW_REG_SI,
  DW_REG_DI,
  DW_REG_BP,
  DW_REG_SP,
  DW_REG_8,
  DW_REG_9,
  DW_REG_10,
  DW_REG_11,
  DW_REG_12,
  DW_REG_13,
  DW_REG_14,
  DW_REG_15,
  DW_REG_RA,
};
enum { DW_EH_PE_udata4 = 3, DW_EH_PE_textrel = 0x20 };
enum {
  DW_CFA_nop = 0x0,
  DW_CFA_offset_extended = 0x5,
  DW_CFA_def_cfa = 0xc,
  DW_CFA_def_cfa_register = 0xd,
  DW_CFA_def_cfa_offset = 0xe,
  DW_CFA_offset_extended_sf = 0x11,
  DW_CFA_advance_loc = 0x40,
  DW_CFA_offset = 0x80
};

static void build_elf(uint64_t code, int code_sz, GDBElfImage *image,
                      int32_t num) {
  memset(image, 0, sizeof(GDBElfImage));

  int64_t offset = 0;

  Elf64_Ehdr hdr = {
      .e_ident = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB,
                  1 /*version */, ELFOSABI_SYSV, 0 /* ABI VERSION */, 0, 0, 0,
                  0, 0, 0, 0},
      .e_type = ET_REL,
      .e_machine = EM_X86_64,
      .e_version = EV_CURRENT,
      .e_entry = 0,
      .e_phoff = 0,
      .e_shoff = sizeof(Elf64_Ehdr),
      .e_flags = 0,
      .e_ehsize = sizeof(Elf64_Ehdr),
      .e_phentsize = 0,
      .e_phnum = 0,
      .e_shentsize = sizeof(Elf64_Shdr),
      .e_shnum = 6,
      .e_shstrndx = 1,
  };
  image->hdr = hdr;
  offset += sizeof(image->hdr);

  __auto_type shstrtab_hdr = &image->hdrs[1];
  offset += sizeof(image->hdrs) + sizeof(image->syms);

  write_strz(&offset, image->data, "");

  shstrtab_hdr->sh_name = write_strz(&offset, image->data, ".shstrtab");
  shstrtab_hdr->sh_type = SHT_STRTAB;
  shstrtab_hdr->sh_addralign = 1;
  shstrtab_hdr->sh_offset = offsetof(GDBElfImage, data);

  __auto_type text_hdr = &image->hdrs[2];
  text_hdr->sh_name = write_strz(&offset, image->data, ".text");
  text_hdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  text_hdr->sh_addr = code;
  text_hdr->sh_size = code_sz;
  text_hdr->sh_offset = 0;
  text_hdr->sh_type = SHT_NOBITS;
  text_hdr->sh_addralign = 16;

  __auto_type str_hdr = &image->hdrs[3];
  str_hdr->sh_name = write_strz(&offset, image->data, ".strtab");
  str_hdr->sh_type = SHT_STRTAB;
  str_hdr->sh_addralign = 1;

  __auto_type sym_hdr = &image->hdrs[4];
  sym_hdr->sh_name = write_strz(&offset, image->data, ".symtab");
  sym_hdr->sh_type = SHT_SYMTAB;
  sym_hdr->sh_addralign = sizeof(void *);
  sym_hdr->sh_offset = offsetof(GDBElfImage, syms);
  sym_hdr->sh_size = sizeof(Elf64_Sym) * 3;
  sym_hdr->sh_link = 3; // link to strtab
  sym_hdr->sh_entsize = sizeof(Elf64_Sym);
  sym_hdr->sh_info = 2; // sym_func

  shstrtab_hdr->sh_size = offset;

  // Write symbols
  __auto_type start_offset = offset;
  str_hdr->sh_offset = offsetof(GDBElfImage, data) + start_offset;
  __auto_type st = offset;
  write_strz(&offset, image->data, "");
  // Emit the symbols
  __auto_type filesym = &image->syms[1];
  filesym->st_name = write_strz(&offset, image->data, "JIT") - st;
  filesym->st_shndx = SHN_ABS;
  filesym->st_info = STT_FILE;
  __auto_type funcsym = &image->syms[2];
  char tmp[244];
  snprintf(tmp, sizeof(tmp) - 1, "TRACE_%i", num);
  funcsym->st_name = write_strz(&offset, image->data, tmp) - st;
  funcsym->st_shndx = 2; // text
  funcsym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  funcsym->st_value = 0;
  funcsym->st_size = code_sz;

  str_hdr->sh_size = offset - start_offset;
}
