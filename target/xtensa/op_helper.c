/*
 * Copyright (c) 2011, Max Filippov, Open Source and Linux Lab.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the Open Source and Linux Lab nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "qemu/osdep.h"
#include "qemu/main-loop.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "qemu/host-utils.h"
#include "exec/exec-all.h"
#include "exec/cpu_ldst.h"
#include "exec/address-spaces.h"
#include "qemu/timer.h"

#ifndef CONFIG_USER_ONLY

void xtensa_cpu_do_unaligned_access(CPUState *cs,
        vaddr addr, MMUAccessType access_type,
        int mmu_idx, uintptr_t retaddr)
{
    XtensaCPU *cpu = XTENSA_CPU(cs);
    CPUXtensaState *env = &cpu->env;

    if (xtensa_option_enabled(env->config, XTENSA_OPTION_UNALIGNED_EXCEPTION) &&
            !xtensa_option_enabled(env->config, XTENSA_OPTION_HW_ALIGNMENT)) {
        cpu_restore_state(CPU(cpu), retaddr, true);
        HELPER(exception_cause_vaddr)(env,
                env->pc, LOAD_STORE_ALIGNMENT_CAUSE, addr);
    }
}

void tlb_fill(CPUState *cs, target_ulong vaddr, int size,
              MMUAccessType access_type, int mmu_idx, uintptr_t retaddr)
{
    XtensaCPU *cpu = XTENSA_CPU(cs);
    CPUXtensaState *env = &cpu->env;
    uint32_t paddr;
    uint32_t page_size;
    unsigned access;
    int ret = xtensa_get_physical_addr(env, true, vaddr, access_type, mmu_idx,
            &paddr, &page_size, &access);

    qemu_log_mask(CPU_LOG_MMU, "%s(%08x, %d, %d) -> %08x, ret = %d\n",
                  __func__, vaddr, access_type, mmu_idx, paddr, ret);

    if (ret == 0) {
        tlb_set_page(cs,
                     vaddr & TARGET_PAGE_MASK,
                     paddr & TARGET_PAGE_MASK,
                     access, mmu_idx, page_size);
    } else {
        cpu_restore_state(cs, retaddr, true);
        HELPER(exception_cause_vaddr)(env, env->pc, ret, vaddr);
    }
}

void xtensa_cpu_do_transaction_failed(CPUState *cs, hwaddr physaddr, vaddr addr,
                                      unsigned size, MMUAccessType access_type,
                                      int mmu_idx, MemTxAttrs attrs,
                                      MemTxResult response, uintptr_t retaddr)
{
    XtensaCPU *cpu = XTENSA_CPU(cs);
    CPUXtensaState *env = &cpu->env;

    cpu_restore_state(cs, retaddr, true);
    HELPER(exception_cause_vaddr)(env, env->pc,
                                  access_type == MMU_INST_FETCH ?
                                  INSTR_PIF_ADDR_ERROR_CAUSE :
                                  LOAD_STORE_PIF_ADDR_ERROR_CAUSE,
                                  addr);
}

static void tb_invalidate_virtual_addr(CPUXtensaState *env, uint32_t vaddr)
{
    uint32_t paddr;
    uint32_t page_size;
    unsigned access;
    int ret = xtensa_get_physical_addr(env, false, vaddr, 2, 0,
            &paddr, &page_size, &access);
    if (ret == 0) {
        tb_invalidate_phys_addr(&address_space_memory, paddr,
                                MEMTXATTRS_UNSPECIFIED);
    }
}

#endif

void HELPER(exception)(CPUXtensaState *env, uint32_t excp)
{
    CPUState *cs = CPU(xtensa_env_get_cpu(env));

    cs->exception_index = excp;
    if (excp == EXCP_YIELD) {
        env->yield_needed = 0;
    }
    if (excp == EXCP_DEBUG) {
        env->exception_taken = 0;
    }
    cpu_loop_exit(cs);
}

void HELPER(exception_cause)(CPUXtensaState *env, uint32_t pc, uint32_t cause)
{
    uint32_t vector;

    env->pc = pc;
    if (env->sregs[PS] & PS_EXCM) {
        if (env->config->ndepc) {
            env->sregs[DEPC] = pc;
        } else {
            env->sregs[EPC1] = pc;
        }
        vector = EXC_DOUBLE;
    } else {
        env->sregs[EPC1] = pc;
        vector = (env->sregs[PS] & PS_UM) ? EXC_USER : EXC_KERNEL;
    }

    env->sregs[EXCCAUSE] = cause;
    env->sregs[PS] |= PS_EXCM;

    HELPER(exception)(env, vector);
}

void HELPER(exception_cause_vaddr)(CPUXtensaState *env,
        uint32_t pc, uint32_t cause, uint32_t vaddr)
{
    env->sregs[EXCVADDR] = vaddr;
    HELPER(exception_cause)(env, pc, cause);
}

void debug_exception_env(CPUXtensaState *env, uint32_t cause)
{
    if (xtensa_get_cintlevel(env) < env->config->debug_level) {
        HELPER(debug_exception)(env, env->pc, cause);
    }
}

void HELPER(debug_exception)(CPUXtensaState *env, uint32_t pc, uint32_t cause)
{
    unsigned level = env->config->debug_level;

    env->pc = pc;
    env->sregs[DEBUGCAUSE] = cause;
    env->sregs[EPC1 + level - 1] = pc;
    env->sregs[EPS2 + level - 2] = env->sregs[PS];
    env->sregs[PS] = (env->sregs[PS] & ~PS_INTLEVEL) | PS_EXCM |
        (level << PS_INTLEVEL_SHIFT);
    HELPER(exception)(env, EXC_DEBUG);
}

void HELPER(dump_state)(CPUXtensaState *env)
{
    XtensaCPU *cpu = xtensa_env_get_cpu(env);

    cpu_dump_state(CPU(cpu), stderr, fprintf, 0);
}

#ifndef CONFIG_USER_ONLY

void HELPER(waiti)(CPUXtensaState *env, uint32_t pc, uint32_t intlevel)
{
    CPUState *cpu;

    env->pc = pc;
    env->sregs[PS] = (env->sregs[PS] & ~PS_INTLEVEL) |
        (intlevel << PS_INTLEVEL_SHIFT);

    qemu_mutex_lock_iothread();
    check_interrupts(env);
    qemu_mutex_unlock_iothread();

    if (env->pending_irq_level) {
        cpu_loop_exit(CPU(xtensa_env_get_cpu(env)));
        return;
    }

    cpu = CPU(xtensa_env_get_cpu(env));
    cpu->halted = 1;
    HELPER(exception)(env, EXCP_HLT);
}

void HELPER(update_ccount)(CPUXtensaState *env)
{
    uint64_t now = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);

    env->ccount_time = now;
    env->sregs[CCOUNT] = env->ccount_base +
        (uint32_t)((now - env->time_base) *
                   env->config->clock_freq_khz / 1000000);
}

void HELPER(wsr_ccount)(CPUXtensaState *env, uint32_t v)
{
    int i;

    HELPER(update_ccount)(env);
    env->ccount_base += v - env->sregs[CCOUNT];
    for (i = 0; i < env->config->nccompare; ++i) {
        HELPER(update_ccompare)(env, i);
    }
}

void HELPER(update_ccompare)(CPUXtensaState *env, uint32_t i)
{
    uint64_t dcc;

    HELPER(update_ccount)(env);
    dcc = (uint64_t)(env->sregs[CCOMPARE + i] - env->sregs[CCOUNT] - 1) + 1;
    timer_mod(env->ccompare[i].timer,
              env->ccount_time + (dcc * 1000000) / env->config->clock_freq_khz);
    env->yield_needed = 1;
}

void HELPER(check_interrupts)(CPUXtensaState *env)
{
    qemu_mutex_lock_iothread();
    check_interrupts(env);
    qemu_mutex_unlock_iothread();
}

void HELPER(itlb_hit_test)(CPUXtensaState *env, uint32_t vaddr)
{
    /*
     * Attempt the memory load; we don't care about the result but
     * only the side-effects (ie any MMU or other exception)
     */
    cpu_ldub_code_ra(env, vaddr, GETPC());
}

/*!
 * Check vaddr accessibility/cache attributes and raise an exception if
 * specified by the ATOMCTL SR.
 *
 * Note: local memory exclusion is not implemented
 */
void HELPER(check_atomctl)(CPUXtensaState *env, uint32_t pc, uint32_t vaddr)
{
    uint32_t paddr, page_size, access;
    uint32_t atomctl = env->sregs[ATOMCTL];
    int rc = xtensa_get_physical_addr(env, true, vaddr, 1,
            xtensa_get_cring(env), &paddr, &page_size, &access);

    /*
     * s32c1i never causes LOAD_PROHIBITED_CAUSE exceptions,
     * see opcode description in the ISA
     */
    if (rc == 0 &&
            (access & (PAGE_READ | PAGE_WRITE)) != (PAGE_READ | PAGE_WRITE)) {
        rc = STORE_PROHIBITED_CAUSE;
    }

    if (rc) {
        HELPER(exception_cause_vaddr)(env, pc, rc, vaddr);
    }

    /*
     * When data cache is not configured use ATOMCTL bypass field.
     * See ISA, 4.3.12.4 The Atomic Operation Control Register (ATOMCTL)
     * under the Conditional Store Option.
     */
    if (!xtensa_option_enabled(env->config, XTENSA_OPTION_DCACHE)) {
        access = PAGE_CACHE_BYPASS;
    }

    switch (access & PAGE_CACHE_MASK) {
    case PAGE_CACHE_WB:
        atomctl >>= 2;
        /* fall through */
    case PAGE_CACHE_WT:
        atomctl >>= 2;
        /* fall through */
    case PAGE_CACHE_BYPASS:
        if ((atomctl & 0x3) == 0) {
            HELPER(exception_cause_vaddr)(env, pc,
                    LOAD_STORE_ERROR_CAUSE, vaddr);
        }
        break;

    case PAGE_CACHE_ISOLATE:
        HELPER(exception_cause_vaddr)(env, pc,
                LOAD_STORE_ERROR_CAUSE, vaddr);
        break;

    default:
        break;
    }
}

void HELPER(wsr_memctl)(CPUXtensaState *env, uint32_t v)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_ICACHE)) {
        if (extract32(v, MEMCTL_IUSEWAYS_SHIFT, MEMCTL_IUSEWAYS_LEN) >
            env->config->icache_ways) {
            deposit32(v, MEMCTL_IUSEWAYS_SHIFT, MEMCTL_IUSEWAYS_LEN,
                      env->config->icache_ways);
        }
    }
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_DCACHE)) {
        if (extract32(v, MEMCTL_DUSEWAYS_SHIFT, MEMCTL_DUSEWAYS_LEN) >
            env->config->dcache_ways) {
            deposit32(v, MEMCTL_DUSEWAYS_SHIFT, MEMCTL_DUSEWAYS_LEN,
                      env->config->dcache_ways);
        }
        if (extract32(v, MEMCTL_DALLOCWAYS_SHIFT, MEMCTL_DALLOCWAYS_LEN) >
            env->config->dcache_ways) {
            deposit32(v, MEMCTL_DALLOCWAYS_SHIFT, MEMCTL_DALLOCWAYS_LEN,
                      env->config->dcache_ways);
        }
    }
    env->sregs[MEMCTL] = v & env->config->memctl_mask;
}

void HELPER(wsr_rasid)(CPUXtensaState *env, uint32_t v)
{
    XtensaCPU *cpu = xtensa_env_get_cpu(env);

    v = (v & 0xffffff00) | 0x1;
    if (v != env->sregs[RASID]) {
        env->sregs[RASID] = v;
        tlb_flush(CPU(cpu));
    }
}

static uint32_t get_page_size(const CPUXtensaState *env, bool dtlb, uint32_t way)
{
    uint32_t tlbcfg = env->sregs[dtlb ? DTLBCFG : ITLBCFG];

    switch (way) {
    case 4:
        return (tlbcfg >> 16) & 0x3;

    case 5:
        return (tlbcfg >> 20) & 0x1;

    case 6:
        return (tlbcfg >> 24) & 0x1;

    default:
        return 0;
    }
}

/*!
 * Get bit mask for the virtual address bits translated by the TLB way
 */
uint32_t xtensa_tlb_get_addr_mask(const CPUXtensaState *env, bool dtlb, uint32_t way)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        bool varway56 = dtlb ?
            env->config->dtlb.varway56 :
            env->config->itlb.varway56;

        switch (way) {
        case 4:
            return 0xfff00000 << get_page_size(env, dtlb, way) * 2;

        case 5:
            if (varway56) {
                return 0xf8000000 << get_page_size(env, dtlb, way);
            } else {
                return 0xf8000000;
            }

        case 6:
            if (varway56) {
                return 0xf0000000 << (1 - get_page_size(env, dtlb, way));
            } else {
                return 0xf0000000;
            }

        default:
            return 0xfffff000;
        }
    } else {
        return REGION_PAGE_MASK;
    }
}

/*!
 * Get bit mask for the 'VPN without index' field.
 * See ISA, 4.6.5.6, data format for RxTLB0
 */
static uint32_t get_vpn_mask(const CPUXtensaState *env, bool dtlb, uint32_t way)
{
    if (way < 4) {
        bool is32 = (dtlb ?
                env->config->dtlb.nrefillentries :
                env->config->itlb.nrefillentries) == 32;
        return is32 ? 0xffff8000 : 0xffffc000;
    } else if (way == 4) {
        return xtensa_tlb_get_addr_mask(env, dtlb, way) << 2;
    } else if (way <= 6) {
        uint32_t mask = xtensa_tlb_get_addr_mask(env, dtlb, way);
        bool varway56 = dtlb ?
            env->config->dtlb.varway56 :
            env->config->itlb.varway56;

        if (varway56) {
            return mask << (way == 5 ? 2 : 3);
        } else {
            return mask << 1;
        }
    } else {
        return 0xfffff000;
    }
}

/*!
 * Split virtual address into VPN (with index) and entry index
 * for the given TLB way
 */
void split_tlb_entry_spec_way(const CPUXtensaState *env, uint32_t v, bool dtlb,
        uint32_t *vpn, uint32_t wi, uint32_t *ei)
{
    bool varway56 = dtlb ?
        env->config->dtlb.varway56 :
        env->config->itlb.varway56;

    if (!dtlb) {
        wi &= 7;
    }

    if (wi < 4) {
        bool is32 = (dtlb ?
                env->config->dtlb.nrefillentries :
                env->config->itlb.nrefillentries) == 32;
        *ei = (v >> 12) & (is32 ? 0x7 : 0x3);
    } else {
        switch (wi) {
        case 4:
            {
                uint32_t eibase = 20 + get_page_size(env, dtlb, wi) * 2;
                *ei = (v >> eibase) & 0x3;
            }
            break;

        case 5:
            if (varway56) {
                uint32_t eibase = 27 + get_page_size(env, dtlb, wi);
                *ei = (v >> eibase) & 0x3;
            } else {
                *ei = (v >> 27) & 0x1;
            }
            break;

        case 6:
            if (varway56) {
                uint32_t eibase = 29 - get_page_size(env, dtlb, wi);
                *ei = (v >> eibase) & 0x7;
            } else {
                *ei = (v >> 28) & 0x1;
            }
            break;

        default:
            *ei = 0;
            break;
        }
    }
    *vpn = v & xtensa_tlb_get_addr_mask(env, dtlb, wi);
}

/*!
 * Split TLB address into TLB way, entry index and VPN (with index).
 * See ISA, 4.6.5.5 - 4.6.5.8 for the TLB addressing format
 */
static void split_tlb_entry_spec(CPUXtensaState *env, uint32_t v, bool dtlb,
        uint32_t *vpn, uint32_t *wi, uint32_t *ei)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        *wi = v & (dtlb ? 0xf : 0x7);
        split_tlb_entry_spec_way(env, v, dtlb, vpn, *wi, ei);
    } else {
        *vpn = v & REGION_PAGE_MASK;
        *wi = 0;
        *ei = (v >> 29) & 0x7;
    }
}

static xtensa_tlb_entry *get_tlb_entry(CPUXtensaState *env,
        uint32_t v, bool dtlb, uint32_t *pwi)
{
    uint32_t vpn;
    uint32_t wi;
    uint32_t ei;

    split_tlb_entry_spec(env, v, dtlb, &vpn, &wi, &ei);
    if (pwi) {
        *pwi = wi;
    }
    return xtensa_tlb_get_entry(env, dtlb, wi, ei);
}

uint32_t HELPER(rtlb0)(CPUXtensaState *env, uint32_t v, uint32_t dtlb)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        uint32_t wi;
        const xtensa_tlb_entry *entry = get_tlb_entry(env, v, dtlb, &wi);
        return (entry->vaddr & get_vpn_mask(env, dtlb, wi)) | entry->asid;
    } else {
        return v & REGION_PAGE_MASK;
    }
}

uint32_t HELPER(rtlb1)(CPUXtensaState *env, uint32_t v, uint32_t dtlb)
{
    const xtensa_tlb_entry *entry = get_tlb_entry(env, v, dtlb, NULL);
    return entry->paddr | entry->attr;
}

void HELPER(itlb)(CPUXtensaState *env, uint32_t v, uint32_t dtlb)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        uint32_t wi;
        xtensa_tlb_entry *entry = get_tlb_entry(env, v, dtlb, &wi);
        if (entry->variable && entry->asid) {
            tlb_flush_page(CPU(xtensa_env_get_cpu(env)), entry->vaddr);
            entry->asid = 0;
        }
    }
}

uint32_t HELPER(ptlb)(CPUXtensaState *env, uint32_t v, uint32_t dtlb)
{
    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        uint32_t wi;
        uint32_t ei;
        uint8_t ring;
        int res = xtensa_tlb_lookup(env, v, dtlb, &wi, &ei, &ring);

        switch (res) {
        case 0:
            if (ring >= xtensa_get_ring(env)) {
                return (v & 0xfffff000) | wi | (dtlb ? 0x10 : 0x8);
            }
            break;

        case INST_TLB_MULTI_HIT_CAUSE:
        case LOAD_STORE_TLB_MULTI_HIT_CAUSE:
            HELPER(exception_cause_vaddr)(env, env->pc, res, v);
            break;
        }
        return 0;
    } else {
        return (v & REGION_PAGE_MASK) | 0x1;
    }
}

void xtensa_tlb_set_entry_mmu(const CPUXtensaState *env,
        xtensa_tlb_entry *entry, bool dtlb,
        unsigned wi, unsigned ei, uint32_t vpn, uint32_t pte)
{
    entry->vaddr = vpn;
    entry->paddr = pte & xtensa_tlb_get_addr_mask(env, dtlb, wi);
    entry->asid = (env->sregs[RASID] >> ((pte >> 1) & 0x18)) & 0xff;
    entry->attr = pte & 0xf;
}

void xtensa_tlb_set_entry(CPUXtensaState *env, bool dtlb,
        unsigned wi, unsigned ei, uint32_t vpn, uint32_t pte)
{
    XtensaCPU *cpu = xtensa_env_get_cpu(env);
    CPUState *cs = CPU(cpu);
    xtensa_tlb_entry *entry = xtensa_tlb_get_entry(env, dtlb, wi, ei);

    if (xtensa_option_enabled(env->config, XTENSA_OPTION_MMU)) {
        if (entry->variable) {
            if (entry->asid) {
                tlb_flush_page(cs, entry->vaddr);
            }
            xtensa_tlb_set_entry_mmu(env, entry, dtlb, wi, ei, vpn, pte);
            tlb_flush_page(cs, entry->vaddr);
        } else {
            qemu_log_mask(LOG_GUEST_ERROR, "%s %d, %d, %d trying to set immutable entry\n",
                          __func__, dtlb, wi, ei);
        }
    } else {
        tlb_flush_page(cs, entry->vaddr);
        if (xtensa_option_enabled(env->config,
                    XTENSA_OPTION_REGION_TRANSLATION)) {
            entry->paddr = pte & REGION_PAGE_MASK;
        }
        entry->attr = pte & 0xf;
    }
}

void HELPER(wtlb)(CPUXtensaState *env, uint32_t p, uint32_t v, uint32_t dtlb)
{
    uint32_t vpn;
    uint32_t wi;
    uint32_t ei;
    split_tlb_entry_spec(env, v, dtlb, &vpn, &wi, &ei);
    xtensa_tlb_set_entry(env, dtlb, wi, ei, vpn, p);
}


void HELPER(wsr_ibreakenable)(CPUXtensaState *env, uint32_t v)
{
    uint32_t change = v ^ env->sregs[IBREAKENABLE];
    unsigned i;

    for (i = 0; i < env->config->nibreak; ++i) {
        if (change & (1 << i)) {
            tb_invalidate_virtual_addr(env, env->sregs[IBREAKA + i]);
        }
    }
    env->sregs[IBREAKENABLE] = v & ((1 << env->config->nibreak) - 1);
}

void HELPER(wsr_ibreaka)(CPUXtensaState *env, uint32_t i, uint32_t v)
{
    if (env->sregs[IBREAKENABLE] & (1 << i) && env->sregs[IBREAKA + i] != v) {
        tb_invalidate_virtual_addr(env, env->sregs[IBREAKA + i]);
        tb_invalidate_virtual_addr(env, v);
    }
    env->sregs[IBREAKA + i] = v;
}

static void set_dbreak(CPUXtensaState *env, unsigned i, uint32_t dbreaka,
        uint32_t dbreakc)
{
    CPUState *cs = CPU(xtensa_env_get_cpu(env));
    int flags = BP_CPU | BP_STOP_BEFORE_ACCESS;
    uint32_t mask = dbreakc | ~DBREAKC_MASK;

    if (env->cpu_watchpoint[i]) {
        cpu_watchpoint_remove_by_ref(cs, env->cpu_watchpoint[i]);
    }
    if (dbreakc & DBREAKC_SB) {
        flags |= BP_MEM_WRITE;
    }
    if (dbreakc & DBREAKC_LB) {
        flags |= BP_MEM_READ;
    }
    /* contiguous mask after inversion is one less than some power of 2 */
    if ((~mask + 1) & ~mask) {
        qemu_log_mask(LOG_GUEST_ERROR, "DBREAKC mask is not contiguous: 0x%08x\n", dbreakc);
        /* cut mask after the first zero bit */
        mask = 0xffffffff << (32 - clo32(mask));
    }
    if (cpu_watchpoint_insert(cs, dbreaka & mask, ~mask + 1,
            flags, &env->cpu_watchpoint[i])) {
        env->cpu_watchpoint[i] = NULL;
        qemu_log_mask(LOG_GUEST_ERROR, "Failed to set data breakpoint at 0x%08x/%d\n",
                      dbreaka & mask, ~mask + 1);
    }
}

void HELPER(wsr_dbreaka)(CPUXtensaState *env, uint32_t i, uint32_t v)
{
    uint32_t dbreakc = env->sregs[DBREAKC + i];

    if ((dbreakc & DBREAKC_SB_LB) &&
            env->sregs[DBREAKA + i] != v) {
        set_dbreak(env, i, v, dbreakc);
    }
    env->sregs[DBREAKA + i] = v;
}

void HELPER(wsr_dbreakc)(CPUXtensaState *env, uint32_t i, uint32_t v)
{
    if ((env->sregs[DBREAKC + i] ^ v) & (DBREAKC_SB_LB | DBREAKC_MASK)) {
        if (v & DBREAKC_SB_LB) {
            set_dbreak(env, i, env->sregs[DBREAKA + i], v);
        } else {
            if (env->cpu_watchpoint[i]) {
                CPUState *cs = CPU(xtensa_env_get_cpu(env));

                cpu_watchpoint_remove_by_ref(cs, env->cpu_watchpoint[i]);
                env->cpu_watchpoint[i] = NULL;
            }
        }
    }
    env->sregs[DBREAKC + i] = v;
}
#endif

uint32_t HELPER(rer)(CPUXtensaState *env, uint32_t addr)
{
#ifndef CONFIG_USER_ONLY
    return address_space_ldl(env->address_space_er, addr,
                             MEMTXATTRS_UNSPECIFIED, NULL);
#else
    return 0;
#endif
}

void HELPER(wer)(CPUXtensaState *env, uint32_t data, uint32_t addr)
{
#ifndef CONFIG_USER_ONLY
    address_space_stl(env->address_space_er, addr, data,
                      MEMTXATTRS_UNSPECIFIED, NULL);
#endif
}
