/*
 *  AArch64 translation
 *
 *  Copyright (c) 2013 Alexander Graf <agraf@suse.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "cpu.h"
#include "tcg-op.h"
#include "qemu/log.h"
#include "translate.h"
#include "qemu/host-utils.h"

#include "exec/gen-icount.h"

#include "helper.h"
#define GEN_HELPER 1
#include "helper.h"

static TCGv_i64 cpu_X[32];
static TCGv_i64 cpu_pc;
static TCGv_i32 pstate;

static const char *regnames[] = {
    "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
    "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
    "x24", "x25", "x26", "x27", "x28", "x29", "lr", "sp"
};

/* initialize TCG globals.  */
void a64_translate_init(void)
{
    int i;

    cpu_pc = tcg_global_mem_new_i64(TCG_AREG0,
                                    offsetof(CPUARMState, pc),
                                    "pc");
    for (i = 0; i < 32; i++) {
        cpu_X[i] = tcg_global_mem_new_i64(TCG_AREG0,
                                          offsetof(CPUARMState, xregs[i]),
                                          regnames[i]);
    }

    pstate = tcg_global_mem_new_i32(TCG_AREG0,
                                    offsetof(CPUARMState, pstate),
                                    "pstate");
}

void aarch64_cpu_dump_state(CPUState *cs, FILE *f,
                            fprintf_function cpu_fprintf, int flags)
{
    ARMCPU *cpu = ARM_CPU(cs);
    CPUARMState *env = &cpu->env;
    uint32_t psr = pstate_read(env);
    int i;

    cpu_fprintf(f, "PC=%016"PRIx64"  SP=%016"PRIx64"\n",
            env->pc, env->xregs[31]);
    for (i = 0; i < 31; i++) {
        cpu_fprintf(f, "X%02d=%016"PRIx64, i, env->xregs[i]);
        if ((i % 4) == 3) {
            cpu_fprintf(f, "\n");
        } else {
            cpu_fprintf(f, " ");
        }
    }
    cpu_fprintf(f, "PSTATE=%08x (flags %c%c%c%c)\n",
                psr,
                psr & PSTATE_N ? 'N' : '-',
                psr & PSTATE_Z ? 'Z' : '-',
                psr & PSTATE_C ? 'C' : '-',
                psr & PSTATE_V ? 'V' : '-');
    cpu_fprintf(f, "\n");
}

void gen_a64_set_pc_im(uint64_t val)
{
    tcg_gen_movi_i64(cpu_pc, val);
}

static void gen_exception(int excp)
{
    TCGv_i32 tmp = tcg_temp_new_i32();
    tcg_gen_movi_i32(tmp, excp);
    gen_helper_exception(cpu_env, tmp);
    tcg_temp_free_i32(tmp);
}

static void gen_exception_insn(DisasContext *s, int offset, int excp)
{
    gen_a64_set_pc_im(s->pc - offset);
    gen_exception(excp);
    s->is_jmp = DISAS_EXC;
}

static inline bool use_goto_tb(DisasContext *s, int n, uint64_t dest)
{
    /* No direct tb linking with singlestep or deterministic io */
    if (s->singlestep_enabled || (s->tb->cflags & CF_LAST_IO)) {
        return false;
    }

    /* Only link tbs from inside the same guest page */
    if ((s->tb->pc & TARGET_PAGE_MASK) != (dest & TARGET_PAGE_MASK)) {
        return false;
    }

    return true;
}

static inline void gen_goto_tb(DisasContext *s, int n, uint64_t dest)
{
    TranslationBlock *tb;

    tb = s->tb;
    if (use_goto_tb(s, n, dest)) {
        tcg_gen_goto_tb(n);
        gen_a64_set_pc_im(dest);
        tcg_gen_exit_tb((tcg_target_long)tb + n);
        s->is_jmp = DISAS_TB_JUMP;
    } else {
        gen_a64_set_pc_im(dest);
        if (s->singlestep_enabled) {
            gen_exception(EXCP_DEBUG);
        }
        tcg_gen_exit_tb(0);
        s->is_jmp = DISAS_JUMP;
    }
}

static void unallocated_encoding(DisasContext *s)
{
    gen_exception_insn(s, 4, EXCP_UDEF);
}

#define unsupported_encoding(s, insn)                                    \
    do {                                                                 \
        qemu_log_mask(LOG_UNIMP,                                         \
                      "%s:%d: unsupported instruction encoding 0x%08x "  \
                      "at pc=%016" PRIx64 "\n",                          \
                      __FILE__, __LINE__, insn, s->pc - 4);              \
        unallocated_encoding(s);                                         \
    } while (0);

/*
 * the instruction disassembly implemented here matches
 * the instruction encoding classifications in chapter 3 (C3)
 * of the ARM Architecture Reference Manual (DDI0487A_a)
 */

/* Unconditional branch (immediate) */
static void disas_uncond_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Compare & branch (immediate) */
static void disas_comp_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Test & branch (immediate) */
static void disas_test_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional branch (immediate) */
static void disas_cond_b_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C5.6.68 HINT */
static void handle_hint(DisasContext *s, uint32_t insn,
                        unsigned int op1, unsigned int op2, unsigned int crm)
{
    unsigned int selector = crm << 3 | op2;

    if (op1 != 3) {
        unallocated_encoding(s);
        return;
    }

    switch (selector) {
    case 0: /* NOP */
        return;
    case 1: /* YIELD */
    case 2: /* WFE */
    case 3: /* WFI */
    case 4: /* SEV */
    case 5: /* SEVL */
        /* we treat all as NOP at least for now */
        return;
    default:
        /* default specified as NOP equivalent */
        return;
    }
}

/* CLREX, DSB, DMB, ISB */
static void handle_sync(DisasContext *s, uint32_t insn,
                        unsigned int op1, unsigned int op2, unsigned int crm)
{
    if (op1 != 3) {
        unallocated_encoding(s);
        return;
    }

    switch (op2) {
    case 2: /* CLREX */
        unsupported_encoding(s, insn);
        return;
    case 4: /* DSB */
    case 5: /* DMB */
    case 6: /* ISB */
        /* We don't emulate caches so barriers are no-ops */
        return;
    default:
        unallocated_encoding(s);
        return;
    }
}

/* C5.6.130 MSR (immediate) - move immediate to processor state field */
static void handle_msr_i(DisasContext *s, uint32_t insn,
                         unsigned int op1, unsigned int op2, unsigned int crm)
{
    unsupported_encoding(s, insn);
}

/* C5.6.204 SYS */
static void handle_sys(DisasContext *s, uint32_t insn, unsigned int l,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    unsupported_encoding(s, insn);
}

/* C5.6.129 MRS - move from system register */
static void handle_mrs(DisasContext *s, uint32_t insn, unsigned int op0,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    unsupported_encoding(s, insn);
}

/* C5.6.131 MSR (register) - move to system register */
static void handle_msr(DisasContext *s, uint32_t insn, unsigned int op0,
                       unsigned int op1, unsigned int op2,
                       unsigned int crn, unsigned int crm, unsigned int rt)
{
    unsupported_encoding(s, insn);
}

/* C3.2.4 System
 *  31                 22 21  20 19 18 16 15   12 11    8 7   5 4    0
 * +---------------------+---+-----+-----+-------+-------+-----+------+
 * | 1 1 0 1 0 1 0 1 0 0 | L | op0 | op1 |  CRn  |  CRm  | op2 |  Rt  |
 * +---------------------+---+-----+-----+-------+-------+-----+------+
 */
static void disas_system(DisasContext *s, uint32_t insn)
{
    unsigned int l, op0, op1, crn, crm, op2, rt;
    l = extract32(insn, 21, 1);
    op0 = extract32(insn, 19, 2);
    op1 = extract32(insn, 16, 3);
    crn = extract32(insn, 12, 4);
    crm = extract32(insn, 8, 4);
    op2 = extract32(insn, 5, 3);
    rt = extract32(insn, 0, 5);

    if (op0 == 0) {
        if (l || rt != 31) {
            unallocated_encoding(s);
            return;
        }
        switch (crn) {
        case 2: /* C5.6.68 HINT */
            handle_hint(s, insn, op1, op2, crm);
            break;
        case 3: /* CLREX, DSB, DMB, ISB */
            handle_sync(s, insn, op1, op2, crm);
            break;
        case 4: /* C5.6.130 MSR (immediate) */
            handle_msr_i(s, insn, op1, op2, crm);
            break;
        default:
            unallocated_encoding(s);
            break;
        }
        return;
    }

    if (op0 == 1) {
        /* C5.6.204 SYS */
        handle_sys(s, insn, l, op1, op2, crn, crm, rt);
    } else if (l) { /* op0 > 1 */
        /* C5.6.129 MRS - move from system register */
        handle_mrs(s, insn, op0, op1, op2, crn, crm, rt);
    } else {
        /* C5.6.131 MSR (register) - move to system register */
        handle_msr(s, insn, op0, op1, op2, crn, crm, rt);
    }
}

/* Exception generation */
static void disas_exc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Unconditional branch (register) */
static void disas_uncond_b_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.2 Branches, exception generating and system instructions */
static void disas_b_exc_sys(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 25, 7)) {
    case 0x0a: case 0x0b:
    case 0x4a: case 0x4b: /* Unconditional branch (immediate) */
        disas_uncond_b_imm(s, insn);
        break;
    case 0x1a: case 0x5a: /* Compare & branch (immediate) */
        disas_comp_b_imm(s, insn);
        break;
    case 0x1b: case 0x5b: /* Test & branch (immediate) */
        disas_test_b_imm(s, insn);
        break;
    case 0x2a: /* Conditional branch (immediate) */
        disas_cond_b_imm(s, insn);
        break;
    case 0x6a: /* Exception generation / System */
        if (insn & (1 << 24)) {
            disas_system(s, insn);
        } else {
            disas_exc(s, insn);
        }
        break;
    case 0x6b: /* Unconditional branch (register) */
        disas_uncond_b_reg(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* Load/store exclusive */
static void disas_ldst_excl(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load register (literal) */
static void disas_ld_lit(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store pair (all forms) */
static void disas_ldst_pair(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Load/store register (all forms) */
static void disas_ldst_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store multiple structures */
static void disas_ldst_multiple_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* AdvSIMD load/store single structure */
static void disas_ldst_single_struct(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.3 Loads and stores */
static void disas_ldst(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 6)) {
    case 0x08: /* Load/store exclusive */
        disas_ldst_excl(s, insn);
        break;
    case 0x18: case 0x1c: /* Load register (literal) */
        disas_ld_lit(s, insn);
        break;
    case 0x28: case 0x29:
    case 0x2c: case 0x2d: /* Load/store pair (all forms) */
        disas_ldst_pair(s, insn);
        break;
    case 0x38: case 0x39:
    case 0x3c: case 0x3d: /* Load/store register (all forms) */
        disas_ldst_reg(s, insn);
        break;
    case 0x0c: /* AdvSIMD load/store multiple structures */
        disas_ldst_multiple_struct(s, insn);
        break;
    case 0x0d: /* AdvSIMD load/store single structure */
        disas_ldst_single_struct(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* PC-rel. addressing */
static void disas_pc_rel_adr(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (immediate) */
static void disas_add_sub_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Logical (immediate) */
static void disas_logic_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Move wide (immediate) */
static void disas_movw_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Bitfield */
static void disas_bitfield(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Extract */
static void disas_extract(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.4 Data processing - immediate */
static void disas_data_proc_imm(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 23, 6)) {
    case 0x20: case 0x21: /* PC-rel. addressing */
        disas_pc_rel_adr(s, insn);
        break;
    case 0x22: case 0x23: /* Add/subtract (immediate) */
        disas_add_sub_imm(s, insn);
        break;
    case 0x24: /* Logical (immediate) */
        disas_logic_imm(s, insn);
        break;
    case 0x25: /* Move wide (immediate) */
        disas_movw_imm(s, insn);
        break;
    case 0x26: /* Bitfield */
        disas_bitfield(s, insn);
        break;
    case 0x27: /* Extract */
        disas_extract(s, insn);
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* Logical (shifted register) */
static void disas_logic_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (extended register) */
static void disas_add_sub_ext_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (shifted register) */
static void disas_add_sub_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (3 source) */
static void disas_data_proc_3src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Add/subtract (with carry) */
static void disas_adc_sbc(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (immediate) */
static void disas_cc_imm(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional compare (register) */
static void disas_cc_reg(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Conditional select */
static void disas_cond_select(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (1 source) */
static void disas_data_proc_1src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* Data-processing (2 source) */
static void disas_data_proc_2src(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.5 Data processing - register */
static void disas_data_proc_reg(DisasContext *s, uint32_t insn)
{
    switch (extract32(insn, 24, 5)) {
    case 0x0a: /* Logical (shifted register) */
        disas_logic_reg(s, insn);
        break;
    case 0x0b: /* Add/subtract */
        if (insn & (1 << 21)) { /* (extended register) */
            disas_add_sub_ext_reg(s, insn);
        } else {
            disas_add_sub_reg(s, insn);
        }
        break;
    case 0x1b: /* Data-processing (3 source) */
        disas_data_proc_3src(s, insn);
        break;
    case 0x1a:
        switch (extract32(insn, 21, 3)) {
        case 0x0: /* Add/subtract (with carry) */
            disas_adc_sbc(s, insn);
            break;
        case 0x2: /* Conditional compare */
            if (insn & (1 << 11)) { /* (immediate) */
                disas_cc_imm(s, insn);
            } else {            /* (register) */
                disas_cc_reg(s, insn);
            }
            break;
        case 0x4: /* Conditional select */
            disas_cond_select(s, insn);
            break;
        case 0x6: /* Data-processing */
            if (insn & (1 << 30)) { /* (1 source) */
                disas_data_proc_1src(s, insn);
            } else {            /* (2 source) */
                disas_data_proc_2src(s, insn);
            }
            break;
        default:
            unallocated_encoding(s);
            break;
        }
        break;
    default:
        unallocated_encoding(s);
        break;
    }
}

/* C3.6 Data processing - SIMD and floating point */
static void disas_data_proc_simd_fp(DisasContext *s, uint32_t insn)
{
    unsupported_encoding(s, insn);
}

/* C3.1 A64 instruction index by encoding */
static void disas_a64_insn(CPUARMState *env, DisasContext *s)
{
    uint32_t insn;

    insn = arm_ldl_code(env, s->pc, s->bswap_code);
    s->insn = insn;
    s->pc += 4;

    switch (extract32(insn, 25, 4)) {
    case 0x0: case 0x1: case 0x2: case 0x3: /* UNALLOCATED */
        unallocated_encoding(s);
        break;
    case 0x8: case 0x9: /* Data processing - immediate */
        disas_data_proc_imm(s, insn);
        break;
    case 0xa: case 0xb: /* Branch, exception generation and system insns */
        disas_b_exc_sys(s, insn);
        break;
    case 0x4:
    case 0x6:
    case 0xc:
    case 0xe:      /* Loads and stores */
        disas_ldst(s, insn);
        break;
    case 0x5:
    case 0xd:      /* Data processing - register */
        disas_data_proc_reg(s, insn);
        break;
    case 0x7:
    case 0xf:      /* Data processing - SIMD and floating point */
        disas_data_proc_simd_fp(s, insn);
        break;
    default:
        assert(FALSE); /* all 15 cases should be handled above */
        break;
    }
}

void gen_intermediate_code_internal_a64(ARMCPU *cpu,
                                        TranslationBlock *tb,
                                        bool search_pc)
{
    CPUState *cs = CPU(cpu);
    CPUARMState *env = &cpu->env;
    DisasContext dc1, *dc = &dc1;
    CPUBreakpoint *bp;
    uint16_t *gen_opc_end;
    int j, lj;
    target_ulong pc_start;
    target_ulong next_page_start;
    int num_insns;
    int max_insns;

    pc_start = tb->pc;

    dc->tb = tb;

    gen_opc_end = tcg_ctx.gen_opc_buf + OPC_MAX_SIZE;

    dc->is_jmp = DISAS_NEXT;
    dc->pc = pc_start;
    dc->singlestep_enabled = cs->singlestep_enabled;
    dc->condjmp = 0;

    dc->aarch64 = 1;
    dc->thumb = 0;
    dc->bswap_code = 0;
    dc->condexec_mask = 0;
    dc->condexec_cond = 0;
#if !defined(CONFIG_USER_ONLY)
    dc->user = 0;
#endif
    dc->vfp_enabled = 0;
    dc->vec_len = 0;
    dc->vec_stride = 0;

    next_page_start = (pc_start & TARGET_PAGE_MASK) + TARGET_PAGE_SIZE;
    lj = -1;
    num_insns = 0;
    max_insns = tb->cflags & CF_COUNT_MASK;
    if (max_insns == 0) {
        max_insns = CF_COUNT_MASK;
    }

    gen_tb_start();

    tcg_clear_temp_count();

    do {
        if (unlikely(!QTAILQ_EMPTY(&env->breakpoints))) {
            QTAILQ_FOREACH(bp, &env->breakpoints, entry) {
                if (bp->pc == dc->pc) {
                    gen_exception_insn(dc, 0, EXCP_DEBUG);
                    /* Advance PC so that clearing the breakpoint will
                       invalidate this TB.  */
                    dc->pc += 2;
                    goto done_generating;
                }
            }
        }

        if (search_pc) {
            j = tcg_ctx.gen_opc_ptr - tcg_ctx.gen_opc_buf;
            if (lj < j) {
                lj++;
                while (lj < j) {
                    tcg_ctx.gen_opc_instr_start[lj++] = 0;
                }
            }
            tcg_ctx.gen_opc_pc[lj] = dc->pc;
            tcg_ctx.gen_opc_instr_start[lj] = 1;
            tcg_ctx.gen_opc_icount[lj] = num_insns;
        }

        if (num_insns + 1 == max_insns && (tb->cflags & CF_LAST_IO)) {
            gen_io_start();
        }

        if (unlikely(qemu_loglevel_mask(CPU_LOG_TB_OP | CPU_LOG_TB_OP_OPT))) {
            tcg_gen_debug_insn_start(dc->pc);
        }

        disas_a64_insn(env, dc);

        if (tcg_check_temp_count()) {
            fprintf(stderr, "TCG temporary leak before "TARGET_FMT_lx"\n",
                    dc->pc);
        }

        /* Translation stops when a conditional branch is encountered.
         * Otherwise the subsequent code could get translated several times.
         * Also stop translation when a page boundary is reached.  This
         * ensures prefetch aborts occur at the right place.
         */
        num_insns++;
    } while (!dc->is_jmp && tcg_ctx.gen_opc_ptr < gen_opc_end &&
             !cs->singlestep_enabled &&
             !singlestep &&
             dc->pc < next_page_start &&
             num_insns < max_insns);

    if (tb->cflags & CF_LAST_IO) {
        gen_io_end();
    }

    if (unlikely(cs->singlestep_enabled) && dc->is_jmp != DISAS_EXC) {
        /* Note that this means single stepping WFI doesn't halt the CPU.
         * For conditional branch insns this is harmless unreachable code as
         * gen_goto_tb() has already handled emitting the debug exception
         * (and thus a tb-jump is not possible when singlestepping).
         */
        assert(dc->is_jmp != DISAS_TB_JUMP);
        if (dc->is_jmp != DISAS_JUMP) {
            gen_a64_set_pc_im(dc->pc);
        }
        gen_exception(EXCP_DEBUG);
    } else {
        switch (dc->is_jmp) {
        case DISAS_NEXT:
            gen_goto_tb(dc, 1, dc->pc);
            break;
        default:
        case DISAS_JUMP:
        case DISAS_UPDATE:
            /* indicate that the hash table must be used to find the next TB */
            tcg_gen_exit_tb(0);
            break;
        case DISAS_TB_JUMP:
        case DISAS_EXC:
        case DISAS_SWI:
            break;
        case DISAS_WFI:
            /* This is a special case because we don't want to just halt the CPU
             * if trying to debug across a WFI.
             */
            gen_helper_wfi(cpu_env);
            break;
        }
    }

done_generating:
    gen_tb_end(tb, num_insns);
    *tcg_ctx.gen_opc_ptr = INDEX_op_end;

#ifdef DEBUG_DISAS
    if (qemu_loglevel_mask(CPU_LOG_TB_IN_ASM)) {
        qemu_log("----------------\n");
        qemu_log("IN: %s\n", lookup_symbol(pc_start));
        log_target_disas(env, pc_start, dc->pc - pc_start,
                         dc->thumb | (dc->bswap_code << 1));
        qemu_log("\n");
    }
#endif
    if (search_pc) {
        j = tcg_ctx.gen_opc_ptr - tcg_ctx.gen_opc_buf;
        lj++;
        while (lj <= j) {
            tcg_ctx.gen_opc_instr_start[lj++] = 0;
        }
    } else {
        tb->size = dc->pc - pc_start;
        tb->icount = num_insns;
    }
}
