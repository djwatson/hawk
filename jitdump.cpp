#include <stdint.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sys/types.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <elf.h>
#include <stdlib.h>

#include "jitdump.h"

int cnt = 0;

/* Earlier perf_map tmp support - supplies names to jit regions */
void perf_map(uint64_t fn, uint64_t len, std::string name) {
  char buf[256];
  sprintf(buf, "/tmp/perf-%i.map", getpid());
  auto file = fopen(buf, "a");
  cnt++;
  if (name != "") {
    fprintf(file, "%lx %lx jit function %s\n", uint64_t(fn), len, name.c_str());
  } else {
    fprintf(file, "%lx %lx jit anon function %i\n", uint64_t(fn), len, cnt);
  }
  fclose(file);
}


void* mapaddr{nullptr};
int fd;
/* Newer jit dump support.  Requires perf record -k 1, and then perf
   inject, before perf report, but gives full asm listing */
void jit_dump(int len, uint64_t fn, std::string name) {
  cnt++;
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
  fd =
      open(buf, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC, S_IRUSR | S_IWUSR);
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

struct jit_code_entry* last_entry{nullptr};
struct jit_code_entry* first_entry{nullptr};

void jit_reader_add(int len, uint64_t fn, int i, uint64_t p, std::string name) {
  auto jitcode = new struct jit_code_entry();

  auto entry = new gdb_code_entry;
  entry->fn = fn;
  entry->len = len;
  sprintf(entry->funcname, "Function_%s_%i_%i_%lx", name.c_str(), cnt, i, p);
  jitcode->symfile_addr = entry;
  jitcode->symfile_size = sizeof(gdb_code_entry);
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
  __jit_debug_register_code ();
}
