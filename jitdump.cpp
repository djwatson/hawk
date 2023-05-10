#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <unistd.h>
#include <stddef.h>
#include <assert.h>

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "jitdump.h"

int cnt = 0;

/* Earlier perf_map tmp support - supplies names to jit regions */
void perf_map(uint64_t fn, uint64_t len, std::string name) {
  char buf[256];
  sprintf(buf, "/tmp/perf-%i.map", getpid());
  auto file = fopen(buf, "a");
  if (name != "") {
    fprintf(file, "%lx %lx jit function %s\n", uint64_t(fn), len, name.c_str());
  } else {
    fprintf(file, "%lx %lx jit anon function %i\n", uint64_t(fn), len, cnt);
  }
  fclose(file);
}

void *mapaddr{nullptr};
int fd;
/* Newer jit dump support.  Requires perf record -k 1, and then perf
   inject, before perf report, but gives full asm listing */
void jit_dump(int len, uint64_t fn, std::string name) {
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
  sprintf(funcname, "Function_%s_%i", name.c_str(), cnt);

  // clock
  struct timespec ts;
  int result = clock_gettime(CLOCK_MONOTONIC, &ts);
  record.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

  record.id = 0; // JIT_CODE_LOAD
  record.total_size = sizeof(record) + len + strlen(funcname) + 1;

  record.pid = getpid();
  record.tid = gettid();
  record.vma = (uint64_t)fn;
  record.code_addr = (uint64_t)fn;
  record.code_size = len;
  record.code_index = cnt;

  write(fd, &record, sizeof(record));
  write(fd, funcname, strlen(funcname) + 1);
  write(fd, (void *)fn, len);
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

void jit_dump_init() {
  char buf[256];
  sprintf(buf, "jit-%i.dump", getpid());
  fd = open(buf, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
  struct timespec ts;
  int result = clock_gettime(CLOCK_MONOTONIC, &ts);
  header.timestamp = ts.tv_sec * 1000000000ULL + ts.tv_nsec;

  header.magic = 0x4A695444;
  header.version = 1;
  header.total_size = sizeof(header);
  header.elf_mach = EM_X86_64;
  header.pad1 = 0;
  header.pid = getpid();
  header.flags = 0;
  write(fd, &header, sizeof(header));
  fsync(fd);

  mapaddr =
      mmap(nullptr, sizeof(header), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
  if (!mapaddr) {
    printf("Failed to map file\n");
    exit(-1);
  }
}

void jit_dump_close() {
  munmap(mapaddr, sizeof(header));
  close(fd);
}

/// GDB jit-reader interface

#include "third-party/jit-protocol.h"

struct jit_code_entry *last_entry{nullptr};
struct jit_code_entry *first_entry{nullptr};

struct GDBElfImage {
  Elf64_Ehdr hdr;
  Elf64_Shdr hdrs[6];
  Elf64_Sym syms[3];
  uint8_t data[4096];
};

void build_elf(uint64_t code, int code_sz, GDBElfImage* image, int num);
void jit_reader_add(int len, uint64_t fn, int i, uint64_t p, std::string name) {
  auto jitcode = new struct jit_code_entry();
  auto image = new GDBElfImage;
  build_elf(fn, len, image, cnt);
  

  //auto entry = new gdb_code_entry;
  // entry->fn = fn;
  // entry->len = len;
  //sprintf(entry->funcname, "Function_%s_%i_%i_%lx", name.c_str(), cnt, i, p);
  jitcode->symfile_addr = image;
  jitcode->symfile_size = sizeof(GDBElfImage);
  jitcode->next_entry = nullptr;
  if (!first_entry) {
    first_entry = jitcode;
    last_entry = jitcode;
    jitcode->prev_entry = nullptr;
  } else {
    jitcode->prev_entry = last_entry;
    last_entry->next_entry = jitcode;
    last_entry = jitcode;
  }

  __jit_debug_descriptor.first_entry = first_entry;
  __jit_debug_descriptor.relevant_entry = jitcode;
  __jit_debug_descriptor.action_flag = JIT_REGISTER;
  __jit_debug_descriptor.version = 1;
  __jit_debug_register_code();
  cnt++;
}

////////////// GDB elf entry ///////////////

#include <elf.h>
#include <vector>


// Sections text, strtab, symtab, debug info, debug_abbrev, debug_line, debug_str (only nash), shstrtab, eh_frame (only lj)
// symbols file, func

long write_buf(long& offset, uint8_t* data, void* obj, long len) {
  auto start_offset = offset;
  assert(offset + len < 4096);
  memcpy(&data[offset], obj, len);
  offset += len;
  return start_offset;
}

long write_strz(long& offset, uint8_t* data, const char* obj) {
  auto len = strlen(obj) + 1; // null terminated
  return write_buf(offset, data, (void*)obj, len);
}

#define DW_CIE_VERSION	1
enum {
  /* Yes, the order is strange, but correct. */
  DW_REG_AX, DW_REG_DX, DW_REG_CX, DW_REG_BX,
  DW_REG_SI, DW_REG_DI, DW_REG_BP, DW_REG_SP,
  DW_REG_8, DW_REG_9, DW_REG_10, DW_REG_11,
  DW_REG_12, DW_REG_13, DW_REG_14, DW_REG_15,
  DW_REG_RA,
};
enum {
  DW_EH_PE_udata4 = 3,
  DW_EH_PE_textrel = 0x20
};
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

void uleb128(long& offset, uint8_t* buffer, uint32_t v)
{
  for (; v >= 0x80; v >>= 7) {
    buffer[offset++] = (uint8_t)((v & 0x7f) | 0x80);
  }
  buffer[offset++] = (uint8_t)v;
}

void sleb128(long& offset, uint8_t* buffer, uint32_t v)
{
  for (; (uint32_t)(v+0x40) >= 0x80; v >>= 7) {
    buffer[offset++] = (uint8_t)((v & 0x7f) | 0x80);
  }
  buffer[offset++] = (uint8_t)(v&0x7f);
}

void build_elf(uint64_t code, int code_sz, GDBElfImage* image, int num) {
  memset(image, 0, sizeof(GDBElfImage));

  long offset = 0;
  
  image->hdr = {
    .e_ident= {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS64, ELFDATA2LSB, 1 /*version */, ELFOSABI_SYSV,
      0 /* ABI VERSION */, 0, 0, 0, 0, 0, 0, 0},
    .e_type = ET_REL,
    .e_machine =EM_X86_64,
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
  offset += sizeof(image->hdr);

  auto shstrtab_hdr = &image->hdrs[1];
  offset += sizeof(image->hdrs) + sizeof(image->syms);

  write_strz(offset, image->data, "");

  shstrtab_hdr->sh_name = write_strz(offset, image->data, ".shstrtab");
  shstrtab_hdr->sh_type = SHT_STRTAB;
  shstrtab_hdr->sh_addralign = 1;
  shstrtab_hdr->sh_offset = offsetof(GDBElfImage, data);

  auto text_hdr = &image->hdrs[2];
  text_hdr->sh_name = write_strz(offset, image->data, ".text");
  text_hdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  text_hdr->sh_addr = code;
  text_hdr->sh_size = code_sz;
  text_hdr->sh_offset = 0;
  text_hdr->sh_type = SHT_NOBITS;
  text_hdr->sh_addralign=16;
  
  auto str_hdr = &image->hdrs[3];
  str_hdr->sh_name = write_strz(offset, image->data, ".strtab");
  str_hdr->sh_type = SHT_STRTAB;
  str_hdr->sh_addralign=1;

  auto sym_hdr = &image->hdrs[4];
  sym_hdr->sh_name = write_strz(offset, image->data, ".symtab");
  sym_hdr->sh_type = SHT_SYMTAB;
  sym_hdr->sh_addralign=sizeof(void*);
  sym_hdr->sh_offset = offsetof(GDBElfImage, syms);
  sym_hdr->sh_size = sizeof(Elf64_Sym)*3;
  sym_hdr->sh_link = 3; // link to strtab
  sym_hdr->sh_entsize = sizeof(Elf64_Sym);
  sym_hdr->sh_info = 2; // sym_func

  auto ehframe_hdr = &image->hdrs[5];
  ehframe_hdr->sh_name = write_strz(offset, image->data, ".eh_frame");
  ehframe_hdr->sh_type = SHT_PROGBITS;
  ehframe_hdr->sh_addralign=1;
  ehframe_hdr->sh_flags = SHF_ALLOC;

  shstrtab_hdr->sh_size = offset;

  // Write symbols
  auto start_offset = offset;
  str_hdr->sh_offset = offsetof(GDBElfImage, data) + start_offset;
  auto st = offset;
  write_strz(offset, image->data, "");
  // Emit the symbols
  auto filesym = &image->syms[1];
  filesym->st_name = write_strz(offset, image->data, "JIT") - st;
  filesym->st_shndx = SHN_ABS;
  filesym->st_info = STT_FILE;
  auto funcsym = &image->syms[2];
  char tmp[244];
  sprintf(tmp, "TRACE_%i", num);
  funcsym->st_name = write_strz(offset, image->data, tmp) - st;
  funcsym->st_shndx = 2; // text
  funcsym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  funcsym->st_value = 0;
  funcsym->st_size = code_sz;
  
  str_hdr->sh_size = offset - start_offset;

  // write ehframe
  start_offset = offset;
  // TODO align 8
  auto buffer = &image->data[0];
  ehframe_hdr->sh_offset = offsetof(GDBElfImage, data) + start_offset;
//   //////////////////////
#define DB(x)		(buffer[offset] = (x), offset++)
#define DU16(x)		(*(uint16_t *)&buffer[offset] = (x), offset += 2)
#define DU32(x)		(*(uint32_t *)&buffer[offset] = (x), offset += 4)
#define DUV(x)		(uleb128(offset, buffer, (x)))
#define DSV(x)		(sleb128(offset, buffer, (x)))
#define DSTR(str)	(write_strz(offset, (uint8_t*)buffer, (str)))
 #define DALIGNNOP(s)	while ((uintptr_t)offset & ((s)-1)) buffer[offset++] = DW_CFA_nop
#define DSECT(name, stmt) \
   { uint32_t *szp_##name = (uint32_t *)&buffer[offset]; offset += 4; stmt \
     *szp_##name = (uint32_t)((&buffer[offset]-(uint8_t *)szp_##name)-4); } 

//   /* Emit DWARF EH CIE. */
  long cie_offset = offset;
  DSECT(CIE,
    DU32(0);			/* Offset to CIE itself. */
    DB(DW_CIE_VERSION);
    DSTR("zR");			/* Augmentation. */
    DUV(1);			/* Code alignment factor. */
    DSV(-(int32_t)sizeof(uintptr_t));  /* Data alignment factor. */
    DB(DW_REG_RA);		/* Return address register. */
    DB(1); DB(DW_EH_PE_textrel|DW_EH_PE_udata4);  /* Augmentation data. */
    DB(DW_CFA_def_cfa); DUV(DW_REG_SP); DUV(sizeof(uintptr_t));
    DB(DW_CFA_offset|DW_REG_RA); DUV(1);
    DALIGNNOP(sizeof(uintptr_t));
  )

//   /* Emit DWARF EH FDE. */
  DSECT(FDE,
    DU32((uint32_t)(offset - cie_offset));	/* Offset to CIE. */
    DU32(0);			/* Machine code offset relative to .text. */
    DU32(code);		/* Machine code length. */
    DB(0);			/* Augmentation data. */
    /* Registers saved in CFRAME. */

    DB(DW_CFA_def_cfa_offset); DUV(16);
    DB(DW_CFA_offset|DW_REG_BP); DUV(2);
    DB(DW_CFA_def_cfa_register); DUV(DW_REG_BP);
    DALIGNNOP(sizeof(uintptr_t));
  )
  ///////////
  ehframe_hdr->sh_size = offset - start_offset;

  // Note this breaks perf record inject for some reason?
  // fd = open("elfout", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
  // write(fd, image, sizeof(GDBElfImage));
  // close(fd);
}
