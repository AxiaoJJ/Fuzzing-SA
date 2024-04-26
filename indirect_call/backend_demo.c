#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
// Include this header to use the built-in backend functions
#include <builtin_backend.h>

typedef enum arch_t {
    arm,
    x86_64,
    mips,
    mipsel,
} arch_t;

static arch_t arch = arm;

extern bool arch_supported(const char *arch_name) {
    if (!strcmp(arch_name, "arm")) {
        arch = arm;
        return true;
    }
    if (!strcmp(arch_name, "x86_64")) {
        arch = x86_64;
        return true;
    }
    if (!strcmp(arch_name, "mips")) {
        arch = mips;
        return true;
    }
    if (!strcmp(arch_name, "mipsel")) {
        arch = mipsel;
        return true;
    }
    return false;
}

extern bool is_indirect_branch(uint8_t *insn_data, size_t insn_size) {
    if (arch == arm) {
        // Handles blx rn
        const uint32_t blx_variable_bits = 0xf000000f;
        const uint32_t blx_constant_bits = 0x012fff30;
        // Arbitrarily set all variable bits in the blx instruction before comparing with the input instruction
        const uint32_t blx = blx_constant_bits | blx_variable_bits;
        if (insn_size == 4) {
            uint32_t b0 = insn_data[0];
            uint32_t b1 = insn_data[1];
            uint32_t b2 = insn_data[2];
            uint32_t b3 = insn_data[3];
            uint32_t word = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
            // Set all variable bits in the instruction
            word |= blx_variable_bits;
            if (word == blx) {
                printf("Found a `blx` instruction\n");
                return true;
            }
        }
    } else if (arch == x86_64) {
        // Handles callq rax, rcx, rdx, etc.
        if (insn_size == 2) {
            uint8_t b0 = insn_data[0];
            uint8_t b1 = insn_data[1];
            if ((b0 == 0xff) && (0xd0 <= b1) && (b1 <= 0xd6)) {
                printf("Found a `callq` instruction\n");
                return true;
            }
        }
        // Handles callq r8, r9, r10, etc.
        if (insn_size == 3) {
            uint8_t b0 = insn_data[0];
            uint8_t b1 = insn_data[1];
            uint8_t b2 = insn_data[2];
            if ((b0 == 0x41) && (b1 == 0xff) && (0xd0 <= b2) && (b2 <= 0xd6)) {
                printf("Found a `callq` instruction\n");
                return true;
            }
        }
    }else if (arch == mipsel) {
    // Handles jr and jalr instructions
        if (insn_size == 4) {
            uint32_t instruction = (insn_data[0] << 24) | (insn_data[1] << 16) | (insn_data[2] << 8) | insn_data[3];

            if (instruction == 0x0320f809) {
                printf("Found a `jalr $t9` instruction\n");
                return true;
            }

            if (instruction == 0x03020008) {
                printf("Found a `jr $t9` instruction\n");
                return true;
            }
        }
    }else if (arch == mips) {
    // Handles jr and jalr instructions
        if (insn_size == 4) {
            uint32_t instruction = (insn_data[0] << 24) | (insn_data[1] << 16) | (insn_data[2] << 8) | insn_data[3];

            if (instruction == 0x09f82003) {
                printf("Found a `jalr $t9` instruction\n");
                return true;
            }

            if (instruction == 0x08002003) {
                printf("Found a `jr $t9` instruction\n");
                return true;
            }
        }
    }

    // If we can't tell if the instruction is an indirect branch, let's use the
    // built-in backend as a fallback
    return is_indirect_branch_default_impl(insn_data, insn_size);
}
