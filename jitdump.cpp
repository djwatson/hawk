#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <unistd.h>

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
  Elf64_Shdr hdrs[5];
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

long write_buf(std::vector<uint8_t>& buffer, void* obj, long len) {
  auto old_end = buffer.size();
  buffer.resize(buffer.size() + len);
  memcpy(&buffer[old_end], obj, len);
  return old_end;
}

long write_strz(std::vector<uint8_t>& buffer, const char* obj) {
  auto len = strlen(obj) + 1; // null terminated
  return write_buf(buffer, (void*)obj, len);
}

// TODO construct in image directly.
void build_elf(uint64_t code, int code_sz, GDBElfImage* image, int num) {
  long offset = 0;
  std::vector<uint8_t> buffer;
  Elf64_Ehdr hdr = {
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
    .e_shnum = 5,
    .e_shstrndx = 1,
  };
  offset += sizeof(hdr);

  Elf64_Shdr hdrs[5];
  memset(&hdrs, 0, sizeof(hdrs));
  Elf64_Sym syms[3];
  memset(&syms, 0, sizeof(syms));
  
  auto shstrtab_hdr = &hdrs[1];
  offset += sizeof(hdrs) + sizeof(syms);

  write_strz(buffer, "");

  shstrtab_hdr->sh_name = write_strz(buffer, ".shstrtab");
  shstrtab_hdr->sh_type = SHT_STRTAB;
  shstrtab_hdr->sh_addralign = 1;
  shstrtab_hdr->sh_offset = offset;

  auto text_hdr = &hdrs[2];
  text_hdr->sh_name = write_strz(buffer, ".text");
  text_hdr->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
  text_hdr->sh_addr = code;
  text_hdr->sh_size = code_sz;
  text_hdr->sh_offset = 0;
  text_hdr->sh_type = SHT_NOBITS;
  text_hdr->sh_addralign=16;
  
  auto str_hdr = &hdrs[3];
  str_hdr->sh_name = write_strz(buffer, ".strtab");
  str_hdr->sh_type = SHT_STRTAB;
  str_hdr->sh_addralign=1;

  auto sym_hdr = &hdrs[4];
  sym_hdr->sh_name = write_strz(buffer, ".symtab");
  sym_hdr->sh_type = SHT_SYMTAB;
  sym_hdr->sh_addralign=sizeof(void*);
  sym_hdr->sh_offset = offset - sizeof(syms);
  sym_hdr->sh_size = sizeof(Elf64_Sym)*3;
  sym_hdr->sh_link = 3; // link to strtab
  sym_hdr->sh_entsize = sizeof(Elf64_Sym);
  sym_hdr->sh_info = 2; // sym_func

  shstrtab_hdr->sh_size = buffer.size() + offset - shstrtab_hdr->sh_offset;

  str_hdr->sh_offset = offset + buffer.size();
  auto st = buffer.size();
  write_strz(buffer, "");
  // Emit the symbols
  auto filesym = &syms[1];
  filesym->st_name = write_strz(buffer, "JIT") - st;
  filesym->st_shndx = SHN_ABS;
  filesym->st_info = STT_FILE;
  auto funcsym = &syms[2];
  char tmp[244];
  sprintf(tmp, "TRACE_%i", num);
  funcsym->st_name = write_strz(buffer, tmp) - st;
  funcsym->st_shndx = 2; // text
  funcsym->st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  funcsym->st_value = 0;
  funcsym->st_size = code_sz;
  
  str_hdr->sh_size = buffer.size() + offset - str_hdr->sh_offset;

  memcpy(&image->hdr, &hdr, sizeof(hdr));
  memcpy(image->hdrs, hdrs, sizeof(hdrs));
  memcpy(image->syms, syms, sizeof(syms));
  memcpy(image->data, &buffer[0], buffer.size());
  // fd = open("elfout", O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
  // write(fd, image, sizeof(GDBElfImage));
  // close(fd);
}
