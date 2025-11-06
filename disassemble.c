#define _GNU_SOURCE
#include <capstone/capstone.h> // for cs_insn, cs_close, cs_disasm, cs_free

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>

#include "disassemble.h"
#include "array.h"
#include "hashtable.h"
#include "zone_alloc.h"

static bool is_control_flow(const cs_insn *i) {
  for (int g = 0; g < i->detail->groups_count; g++) {
    uint8_t group = i->detail->groups[g];
    if (group == CS_GRP_JUMP || group == CS_GRP_CALL) {
      return true;
    }
  }
  return false;
}

static const char *resolve_address(void *addr) {
  Dl_info info;
  auto res = dladdr(addr, &info);
  if (!res) {
    return nullptr;
  }
  return info.dli_sname;
}

void disassemble(const uint8_t *code, size_t len, const comment_entry *comments) {
  csh handle;
  cs_insn *insn;
  size_t count;

  if (len == 0) {
    return;
  }

#if defined(__x86_64__)
  auto arch = CS_ARCH_X86;
  auto mode = CS_MODE_64;
#elif defined(__aarch64__)
  auto arch = CS_ARCH_ARM64;
  auto mode = CS_MODE_ARM;
#elif defined(__riscv)
  auto arch = CS_ARCH_RISCV;
  auto mode = CS_MODE_RISCV64;
#endif

  if (cs_open(arch, mode, &handle) != CS_ERR_OK) {
    printf("BAD open\n");
    return;
  }

  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON); // Needed for operand info

  count = cs_disasm(handle, code, len, (uint64_t)code, 0, &insn);
  if (count == 0) {
    printf("ERROR: Failed to disassemble given code!\n");
    cs_close(&handle);
    return;
  }

  struct {
    uint64_t key;
  } *label_targets = nullptr;
  zone z = {};

  // First pass: collect all jump target addresses
  for (size_t i = 0; i < count; i++) {
    cs_detail *detail = insn[i].detail;
    if (!detail) {
      continue;
    }

    // Handle conditional/unconditional jumps
    if (is_control_flow(&insn[i])) {
#if defined(__x86_64__)
      for (size_t j = 0; j < detail->x86.op_count; j++) {
        if (detail->x86.operands[j].type == X86_OP_IMM) {
          hm_insert(&z, label_targets, detail->x86.operands[j].imm);
        }
      }
#elif defined(__aarch64__)
      for (size_t j = 0; j < detail->arm64.op_count; j++) {
        if (detail->arm64.operands[j].type == ARM64_OP_IMM) {
          hm_insert(&z, label_targets, detail->arm64.operands[j].imm);
        }
      }
#elif defined(__riscv)
      for (size_t j = 0; j < detail->riscv.op_count; j++) {
        if (detail->riscv.operands[j].type == RISCV_OP_IMM) {
          hm_insert(&z, label_targets,
                    detail->riscv.operands[j].imm + insn[i].address);
        }
      }
#else
#error Unknown host
#endif
    }
  }

  // Second pass: print disassembly with labels and comments
  ssize_t cur_comment = (ssize_t)arrlen(comments) - 1;
  for (size_t i = 0; i < count; i++) {
    uint64_t addr = insn[i].address;

    while (cur_comment >= 0 &&
           (uint64_t)comments[cur_comment].offset == addr) {
      printf("// %s\n", comments[cur_comment].text);
      cur_comment--;
    }

    auto idx = hm_geti(label_targets, addr);
    if (idx >= 0) {
      printf(".L%li:\n", idx);
    }

    idx = -1;
    cs_detail *detail = insn[i].detail;

    if (detail && is_control_flow(&insn[i])) {
#if defined(__x86_64__)
      for (size_t j = 0; j < detail->x86.op_count; j++) {
        if (detail->x86.operands[j].type == X86_OP_IMM) {
          idx = hm_geti(label_targets, detail->x86.operands[j].imm);
        }
      }
#elif defined(__aarch64__)
      for (size_t j = 0; j < detail->arm64.op_count; j++) {
        if (detail->arm64.operands[j].type == ARM64_OP_IMM) {
          idx = hm_geti(label_targets, detail->arm64.operands[j].imm);
        }
      }
#elif defined(__riscv)
      for (size_t j = 0; j < detail->riscv.op_count; j++) {
        if (detail->riscv.operands[j].type == RISCV_OP_IMM) {
          idx = hm_geti(label_targets,
                        detail->riscv.operands[j].imm + insn[i].address);
        }
      }
#endif
    }
    if (idx >= 0) {
      auto resolved = resolve_address((void *)label_targets[idx].key);
      if (resolved) {
        printf("\t%s\t%s\n", insn[i].mnemonic, resolved);
      } else {
        printf("\t%s\t.L%li\n", insn[i].mnemonic, idx);
      }
    } else {
      printf("\t%s\t%s\n", insn[i].mnemonic, insn[i].op_str);
    }
  }

  cs_free(insn, count);
  cs_close(&handle);
}
