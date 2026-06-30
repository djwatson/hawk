#ifdef HAVE_CAPSTONE
#define _GNU_SOURCE
#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include <dlfcn.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "array.h"
#include "disassemble.h"
#include "hashtable.h"

typedef struct {
  uint64_t key;
} label_entry;

static bool is_control_flow(const cs_insn *i) {
  for (int g = 0; g < i->detail->groups_count; g++) {
    uint8_t group = i->detail->groups[g];
    if (group == CS_GRP_JUMP || group == CS_GRP_CALL) {
      return true;
    }
  }
  return false;
}

static bool addr_in_range(uint64_t addr, uint64_t start, uint64_t end) {
  return addr >= start && addr < end;
}

static char *heap_vsprintf(const char *fmt, va_list args) {
  va_list measure;
  va_copy(measure, args);
  int needed = vsnprintf(nullptr, 0, fmt, measure);
  va_end(measure);
  if (needed < 0) {
    abort();
  }

  size_t bytes = (size_t)needed + 1;
  char *buf = malloc(bytes);
  if (!buf) {
    abort();
  }

  va_list write_args;
  va_copy(write_args, args);
  int written = vsnprintf(buf, bytes, fmt, write_args);
  va_end(write_args);
  if (written < 0 || written >= (int)bytes) {
    abort();
  }
  return buf;
}

void comment_append(int64_t offset, comment_entry **comments, const char *fmt,
                    ...) {
  va_list args;
  va_start(args, fmt);
  char *msg = heap_vsprintf(fmt, args);
  va_end(args);
  comment_entry entry = {.offset = offset, .text = msg};
  arrput(*comments, entry);
}

static void maybe_label_insert(label_entry **labels, uint64_t target,
                               uint64_t start, uint64_t end) {
  if (addr_in_range(target, start, end)) {
    hm_insert(*labels, target);
  }
}

static ptrdiff_t maybe_label_lookup(label_entry *labels, uint64_t target,
                                    uint64_t start, uint64_t end) {
  if (!labels) {
    return -1;
  }
  if (!addr_in_range(target, start, end)) {
    return -1;
  }
  return hm_geti(labels, target);
}

static const char *resolve_address(void *addr) {
  Dl_info info;
  auto res = dladdr(addr, &info);
  if (!res) {
    return nullptr;
  }
  return info.dli_sname;
}

void disassemble(const uint8_t *code, size_t len,
                 const comment_entry *comments) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (len == 0) {
    return;
  }

#ifdef __x86_64__
  auto arch = CS_ARCH_X86;
  auto mode = CS_MODE_64;
#elifdef __aarch64__
  auto arch = CS_ARCH_ARM64;
  auto mode = CS_MODE_ARM;
#elifdef __riscv
  auto arch = CS_ARCH_RISCV;
  auto mode = CS_MODE_RISCV64;
#endif

  if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
    printf("BAD open\n");
    return;
  }

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // Needed for operand info
  cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);

  uint64_t start_addr = (uint64_t)code;
  uint64_t end_addr = start_addr + len;

  count = cs_disasm(handle, code, len, start_addr, 0, &insn);
  if (count == 0) {
    printf("ERROR: Failed to disassemble given code!\n");
    cs_close(&handle);
    return;
  }

  label_entry *label_targets = nullptr;
  // First pass: collect all jump target addresses
  for (size_t i = 0; i < count; i++) {
    cs_detail *detail = insn[i].detail;
    if (!detail) {
      continue;
    }

    // Handle conditional/unconditional jumps
    if (is_control_flow(&insn[i])) {
#ifdef __x86_64__
      for (size_t j = 0; j < detail->x86.op_count; j++) {
        if (detail->x86.operands[j].type == X86_OP_IMM) {
          uint64_t target = detail->x86.operands[j].imm;
          maybe_label_insert(&label_targets, target, start_addr, end_addr);
        }
      }
#elifdef __aarch64__
      for (size_t j = 0; j < detail->arm64.op_count; j++) {
        if (detail->arm64.operands[j].type == ARM64_OP_IMM) {
          uint64_t target = detail->arm64.operands[j].imm;
          maybe_label_insert(&label_targets, target, start_addr, end_addr);
        }
      }
#elifdef __riscv
      for (size_t j = 0; j < detail->riscv.op_count; j++) {
        if (detail->riscv.operands[j].type == RISCV_OP_IMM) {
          uint64_t target = detail->riscv.operands[j].imm + insn[i].address;
          maybe_label_insert(&label_targets, target, start_addr, end_addr);
        }
      }
#else
#error Unknown host
#endif
    }
  }

  size_t comment_idx = 0;
  size_t comment_cnt = arrlen(comments);

  // Second pass: print disassembly with labels and comments
  for (size_t i = 0; i < count; i++) {
    uint64_t addr = insn[i].address;

    while (comment_idx < comment_cnt &&
           (uint64_t)comments[comment_idx].offset == addr) {
      printf("// %s\n", comments[comment_idx].text);
      comment_idx++;
    }

    auto idx = hm_geti(label_targets, addr);
    if (idx >= 0) {
      printf(".L%td:\n", idx);
    }

    idx = -1;
    cs_detail *detail = insn[i].detail;

    if (detail && is_control_flow(&insn[i])) {
#ifdef __x86_64__
      for (size_t j = 0; j < detail->x86.op_count; j++) {
        if (detail->x86.operands[j].type == X86_OP_IMM) {
          uint64_t target = detail->x86.operands[j].imm;
          auto target_idx =
              maybe_label_lookup(label_targets, target, start_addr, end_addr);
          if (target_idx >= 0) {
            idx = target_idx;
          }
        }
      }
#elifdef __aarch64__
      for (size_t j = 0; j < detail->arm64.op_count; j++) {
        if (detail->arm64.operands[j].type == ARM64_OP_IMM) {
          uint64_t target = detail->arm64.operands[j].imm;
          auto target_idx =
              maybe_label_lookup(label_targets, target, start_addr, end_addr);
          if (target_idx >= 0) {
            idx = target_idx;
          }
        }
      }
#elifdef __riscv
      for (size_t j = 0; j < detail->riscv.op_count; j++) {
        if (detail->riscv.operands[j].type == RISCV_OP_IMM) {
          uint64_t target = detail->riscv.operands[j].imm + insn[i].address;
          auto target_idx =
              maybe_label_lookup(label_targets, target, start_addr, end_addr);
          if (target_idx >= 0) {
            idx = target_idx;
          }
        }
      }
#endif
    }
    printf("%" PRIx64, addr);
    if (idx >= 0) {
      auto resolved = resolve_address((void *)label_targets[idx].key);
      if (resolved) {
        printf("\t%s\t%s\n", insn[i].mnemonic, resolved);
      } else {
        printf("\t%s\t.L%td\n", insn[i].mnemonic, idx);
      }
    } else {
      printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }
  }

  hm_free(label_targets);
  cs_free(insn, count);
  cs_close(&handle);
}
#endif
