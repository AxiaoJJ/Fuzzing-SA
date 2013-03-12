/*
 *  PowerPC MMU, TLB, SLB and BAT emulation helpers for QEMU.
 *
 *  Copyright (c) 2003-2007 Jocelyn Mayer
 *  Copyright (c) 2013 David Gibson, IBM Corporation
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
#include "cpu.h"
#include "helper.h"
#include "sysemu/kvm.h"
#include "kvm_ppc.h"
#include "mmu-hash64.h"

//#define DEBUG_MMU
//#define DEBUG_SLB

#ifdef DEBUG_MMU
#  define LOG_MMU(...) qemu_log(__VA_ARGS__)
#  define LOG_MMU_STATE(env) log_cpu_state((env), 0)
#else
#  define LOG_MMU(...) do { } while (0)
#  define LOG_MMU_STATE(...) do { } while (0)
#endif

#ifdef DEBUG_SLB
#  define LOG_SLB(...) qemu_log(__VA_ARGS__)
#else
#  define LOG_SLB(...) do { } while (0)
#endif

struct mmu_ctx_hash64 {
    hwaddr raddr;      /* Real address              */
    int prot;                      /* Protection bits           */
};

/*
 * SLB handling
 */

static ppc_slb_t *slb_lookup(CPUPPCState *env, target_ulong eaddr)
{
    uint64_t esid_256M, esid_1T;
    int n;

    LOG_SLB("%s: eaddr " TARGET_FMT_lx "\n", __func__, eaddr);

    esid_256M = (eaddr & SEGMENT_MASK_256M) | SLB_ESID_V;
    esid_1T = (eaddr & SEGMENT_MASK_1T) | SLB_ESID_V;

    for (n = 0; n < env->slb_nr; n++) {
        ppc_slb_t *slb = &env->slb[n];

        LOG_SLB("%s: slot %d %016" PRIx64 " %016"
                    PRIx64 "\n", __func__, n, slb->esid, slb->vsid);
        /* We check for 1T matches on all MMUs here - if the MMU
         * doesn't have 1T segment support, we will have prevented 1T
         * entries from being inserted in the slbmte code. */
        if (((slb->esid == esid_256M) &&
             ((slb->vsid & SLB_VSID_B) == SLB_VSID_B_256M))
            || ((slb->esid == esid_1T) &&
                ((slb->vsid & SLB_VSID_B) == SLB_VSID_B_1T))) {
            return slb;
        }
    }

    return NULL;
}

void dump_slb(FILE *f, fprintf_function cpu_fprintf, CPUPPCState *env)
{
    int i;
    uint64_t slbe, slbv;

    cpu_synchronize_state(env);

    cpu_fprintf(f, "SLB\tESID\t\t\tVSID\n");
    for (i = 0; i < env->slb_nr; i++) {
        slbe = env->slb[i].esid;
        slbv = env->slb[i].vsid;
        if (slbe == 0 && slbv == 0) {
            continue;
        }
        cpu_fprintf(f, "%d\t0x%016" PRIx64 "\t0x%016" PRIx64 "\n",
                    i, slbe, slbv);
    }
}

void helper_slbia(CPUPPCState *env)
{
    int n, do_invalidate;

    do_invalidate = 0;
    /* XXX: Warning: slbia never invalidates the first segment */
    for (n = 1; n < env->slb_nr; n++) {
        ppc_slb_t *slb = &env->slb[n];

        if (slb->esid & SLB_ESID_V) {
            slb->esid &= ~SLB_ESID_V;
            /* XXX: given the fact that segment size is 256 MB or 1TB,
             *      and we still don't have a tlb_flush_mask(env, n, mask)
             *      in QEMU, we just invalidate all TLBs
             */
            do_invalidate = 1;
        }
    }
    if (do_invalidate) {
        tlb_flush(env, 1);
    }
}

void helper_slbie(CPUPPCState *env, target_ulong addr)
{
    ppc_slb_t *slb;

    slb = slb_lookup(env, addr);
    if (!slb) {
        return;
    }

    if (slb->esid & SLB_ESID_V) {
        slb->esid &= ~SLB_ESID_V;

        /* XXX: given the fact that segment size is 256 MB or 1TB,
         *      and we still don't have a tlb_flush_mask(env, n, mask)
         *      in QEMU, we just invalidate all TLBs
         */
        tlb_flush(env, 1);
    }
}

int ppc_store_slb(CPUPPCState *env, target_ulong rb, target_ulong rs)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (rb & (0x1000 - env->slb_nr)) {
        return -1; /* Reserved bits set or slot too high */
    }
    if (rs & (SLB_VSID_B & ~SLB_VSID_B_1T)) {
        return -1; /* Bad segment size */
    }
    if ((rs & SLB_VSID_B) && !(env->mmu_model & POWERPC_MMU_1TSEG)) {
        return -1; /* 1T segment on MMU that doesn't support it */
    }

    /* Mask out the slot number as we store the entry */
    slb->esid = rb & (SLB_ESID_ESID | SLB_ESID_V);
    slb->vsid = rs;

    LOG_SLB("%s: %d " TARGET_FMT_lx " - " TARGET_FMT_lx " => %016" PRIx64
            " %016" PRIx64 "\n", __func__, slot, rb, rs,
            slb->esid, slb->vsid);

    return 0;
}

static int ppc_load_slb_esid(CPUPPCState *env, target_ulong rb,
                             target_ulong *rt)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (slot >= env->slb_nr) {
        return -1;
    }

    *rt = slb->esid;
    return 0;
}

static int ppc_load_slb_vsid(CPUPPCState *env, target_ulong rb,
                             target_ulong *rt)
{
    int slot = rb & 0xfff;
    ppc_slb_t *slb = &env->slb[slot];

    if (slot >= env->slb_nr) {
        return -1;
    }

    *rt = slb->vsid;
    return 0;
}

void helper_store_slb(CPUPPCState *env, target_ulong rb, target_ulong rs)
{
    if (ppc_store_slb(env, rb, rs) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
}

target_ulong helper_load_slb_esid(CPUPPCState *env, target_ulong rb)
{
    target_ulong rt = 0;

    if (ppc_load_slb_esid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

target_ulong helper_load_slb_vsid(CPUPPCState *env, target_ulong rb)
{
    target_ulong rt = 0;

    if (ppc_load_slb_vsid(env, rb, &rt) < 0) {
        helper_raise_exception_err(env, POWERPC_EXCP_PROGRAM,
                                   POWERPC_EXCP_INVAL);
    }
    return rt;
}

/*
 * 64-bit hash table MMU handling
 */

static int ppc_hash64_pte_prot(CPUPPCState *env,
                               ppc_slb_t *slb, ppc_hash_pte64_t pte)
{
    unsigned pp, key;
    /* Some pp bit combinations have undefined behaviour, so default
     * to no access in those cases */
    int prot = 0;

    key = !!(msr_pr ? (slb->vsid & SLB_VSID_KP)
             : (slb->vsid & SLB_VSID_KS));
    pp = (pte.pte1 & HPTE64_R_PP) | ((pte.pte1 & HPTE64_R_PP0) >> 61);

    if (key == 0) {
        switch (pp) {
        case 0x0:
        case 0x1:
        case 0x2:
            prot = PAGE_READ | PAGE_WRITE;
            break;

        case 0x3:
        case 0x6:
            prot = PAGE_READ;
            break;
        }
    } else {
        switch (pp) {
        case 0x0:
        case 0x6:
            prot = 0;
            break;

        case 0x1:
        case 0x3:
            prot = PAGE_READ;
            break;

        case 0x2:
            prot = PAGE_READ | PAGE_WRITE;
            break;
        }
    }

    /* No execute if either noexec or guarded bits set */
    if (!(pte.pte1 & HPTE64_R_N) || (pte.pte1 & HPTE64_R_G)) {
        prot |= PAGE_EXEC;
    }

    return prot;
}

static int ppc_hash64_pte_update_flags(struct mmu_ctx_hash64 *ctx,
                                       uint64_t *pte1p, int ret, int rw)
{
    int store = 0;

    /* Update page flags */
    if (!(*pte1p & HPTE64_R_R)) {
        /* Update accessed flag */
        *pte1p |= HPTE64_R_R;
        store = 1;
    }
    if (!(*pte1p & HPTE64_R_C)) {
        if (rw == 1 && ret == 0) {
            /* Update changed flag */
            *pte1p |= HPTE64_R_C;
            store = 1;
        } else {
            /* Force page fault for first write access */
            ctx->prot &= ~PAGE_WRITE;
        }
    }

    return store;
}

static hwaddr ppc_hash64_pteg_search(CPUPPCState *env, hwaddr pteg_off,
                                     bool secondary, target_ulong ptem,
                                     ppc_hash_pte64_t *pte)
{
    hwaddr pte_offset = pteg_off;
    target_ulong pte0, pte1;
    int i;

    for (i = 0; i < HPTES_PER_GROUP; i++) {
        pte0 = ppc_hash64_load_hpte0(env, pte_offset);
        pte1 = ppc_hash64_load_hpte1(env, pte_offset);

        if ((pte0 & HPTE64_V_VALID)
            && (secondary == !!(pte0 & HPTE64_V_SECONDARY))
            && HPTE64_V_COMPARE(pte0, ptem)) {
            pte->pte0 = pte0;
            pte->pte1 = pte1;
            return pte_offset;
        }

        pte_offset += HASH_PTE_SIZE_64;
    }

    return -1;
}

static hwaddr ppc_hash64_htab_lookup(CPUPPCState *env,
                                     ppc_slb_t *slb, target_ulong eaddr,
                                     ppc_hash_pte64_t *pte)
{
    hwaddr pteg_off, pte_offset;
    hwaddr hash;
    uint64_t vsid, epnshift, epnmask, epn, ptem;

    /* Page size according to the SLB, which we use to generate the
     * EPN for hash table lookup..  When we implement more recent MMU
     * extensions this might be different from the actual page size
     * encoded in the PTE */
    epnshift = (slb->vsid & SLB_VSID_L)
        ? TARGET_PAGE_BITS_16M : TARGET_PAGE_BITS;
    epnmask = ~((1ULL << epnshift) - 1);

    if (slb->vsid & SLB_VSID_B) {
        /* 1TB segment */
        vsid = (slb->vsid & SLB_VSID_VSID) >> SLB_VSID_SHIFT_1T;
        epn = (eaddr & ~SEGMENT_MASK_1T) & epnmask;
        hash = vsid ^ (vsid << 25) ^ (epn >> epnshift);
    } else {
        /* 256M segment */
        vsid = (slb->vsid & SLB_VSID_VSID) >> SLB_VSID_SHIFT;
        epn = (eaddr & ~SEGMENT_MASK_256M) & epnmask;
        hash = vsid ^ (epn >> epnshift);
    }
    ptem = (slb->vsid & SLB_VSID_PTEM) | ((epn >> 16) & HPTE64_V_AVPN);

    /* Page address translation */
    LOG_MMU("htab_base " TARGET_FMT_plx " htab_mask " TARGET_FMT_plx
            " hash " TARGET_FMT_plx "\n",
            env->htab_base, env->htab_mask, hash);

    /* Primary PTEG lookup */
    LOG_MMU("0 htab=" TARGET_FMT_plx "/" TARGET_FMT_plx
            " vsid=" TARGET_FMT_lx " ptem=" TARGET_FMT_lx
            " hash=" TARGET_FMT_plx "\n",
            env->htab_base, env->htab_mask, vsid, ptem,  hash);
    pteg_off = (hash * HASH_PTEG_SIZE_64) & env->htab_mask;
    pte_offset = ppc_hash64_pteg_search(env, pteg_off, 0, ptem, pte);

    if (pte_offset == -1) {
        /* Secondary PTEG lookup */
        LOG_MMU("1 htab=" TARGET_FMT_plx "/" TARGET_FMT_plx
                " vsid=" TARGET_FMT_lx " api=" TARGET_FMT_lx
                " hash=" TARGET_FMT_plx "\n", env->htab_base,
                env->htab_mask, vsid, ptem, ~hash);

        pteg_off = (~hash * HASH_PTEG_SIZE_64) & env->htab_mask;
        pte_offset = ppc_hash64_pteg_search(env, pteg_off, 1, ptem, pte);
    }

    return pte_offset;
}

static int ppc_hash64_translate(CPUPPCState *env, struct mmu_ctx_hash64 *ctx,
                                target_ulong eaddr, int rwx)
{
    ppc_slb_t *slb;
    hwaddr pte_offset;
    ppc_hash_pte64_t pte;
    int target_page_bits;
    const int need_prot[] = {PAGE_READ, PAGE_WRITE, PAGE_EXEC};

    assert((rwx == 0) || (rwx == 1) || (rwx == 2));

    /* 1. Handle real mode accesses */
    if (((rwx == 2) && (msr_ir == 0)) || ((rwx != 2) && (msr_dr == 0))) {
        /* Translation is off */
        /* In real mode the top 4 effective address bits are ignored */
        ctx->raddr = eaddr & 0x0FFFFFFFFFFFFFFFULL;
        ctx->prot = PAGE_READ | PAGE_EXEC | PAGE_WRITE;
        return 0;
    }

    /* 2. Translation is on, so look up the SLB */
    slb = slb_lookup(env, eaddr);

    if (!slb) {
        return -5;
    }

    /* 3. Check for segment level no-execute violation */
    if ((rwx == 2) && (slb->vsid & SLB_VSID_N)) {
        return -3;
    }

    /* 4. Locate the PTE in the hash table */
    pte_offset = ppc_hash64_htab_lookup(env, slb, eaddr, &pte);
    if (pte_offset == -1) {
        return -1;
    }
    LOG_MMU("found PTE at offset %08" HWADDR_PRIx "\n", pte_offset);

    /* 5. Check access permissions */

    ctx->prot = ppc_hash64_pte_prot(env, slb, pte);

    if ((need_prot[rwx] & ~ctx->prot) != 0) {
        /* Access right violation */
        LOG_MMU("PTE access rejected\n");
        return -2;
    }

    LOG_MMU("PTE access granted !\n");

    /* 6. Update PTE referenced and changed bits if necessary */

    if (ppc_hash64_pte_update_flags(ctx, &pte.pte1, 0, rwx) == 1) {
        ppc_hash64_store_hpte1(env, pte_offset, pte.pte1);
    }

    /* Keep the matching PTE informations */
    ctx->raddr = pte.pte1;

    /* We have a TLB that saves 4K pages, so let's
     * split a huge page to 4k chunks */
    target_page_bits = (slb->vsid & SLB_VSID_L)
        ? TARGET_PAGE_BITS_16M : TARGET_PAGE_BITS;
    if (target_page_bits != TARGET_PAGE_BITS) {
        ctx->raddr |= (eaddr & ((1 << target_page_bits) - 1))
                      & TARGET_PAGE_MASK;
    }
    return 0;
}

hwaddr ppc_hash64_get_phys_page_debug(CPUPPCState *env, target_ulong addr)
{
    struct mmu_ctx_hash64 ctx;

    if (unlikely(ppc_hash64_translate(env, &ctx, addr, 0) != 0)) {
        return -1;
    }

    return ctx.raddr & TARGET_PAGE_MASK;
}

int ppc_hash64_handle_mmu_fault(CPUPPCState *env, target_ulong address, int rwx,
                                int mmu_idx)
{
    struct mmu_ctx_hash64 ctx;
    int ret = 0;

    ret = ppc_hash64_translate(env, &ctx, address, rwx);
    if (ret == 0) {
        tlb_set_page(env, address & TARGET_PAGE_MASK,
                     ctx.raddr & TARGET_PAGE_MASK, ctx.prot,
                     mmu_idx, TARGET_PAGE_SIZE);
        ret = 0;
    } else if (ret < 0) {
        LOG_MMU_STATE(env);
        if (rwx == 2) {
            switch (ret) {
            case -1:
                env->exception_index = POWERPC_EXCP_ISI;
                env->error_code = 0x40000000;
                break;
            case -2:
                /* Access rights violation */
                env->exception_index = POWERPC_EXCP_ISI;
                env->error_code = 0x08000000;
                break;
            case -3:
                /* No execute protection violation */
                env->exception_index = POWERPC_EXCP_ISI;
                env->error_code = 0x10000000;
                break;
            case -5:
                /* No match in segment table */
                env->exception_index = POWERPC_EXCP_ISEG;
                env->error_code = 0;
                break;
            }
        } else {
            switch (ret) {
            case -1:
                /* No matches in page tables or TLB */
                env->exception_index = POWERPC_EXCP_DSI;
                env->error_code = 0;
                env->spr[SPR_DAR] = address;
                if (rwx == 1) {
                    env->spr[SPR_DSISR] = 0x42000000;
                } else {
                    env->spr[SPR_DSISR] = 0x40000000;
                }
                break;
            case -2:
                /* Access rights violation */
                env->exception_index = POWERPC_EXCP_DSI;
                env->error_code = 0;
                env->spr[SPR_DAR] = address;
                if (rwx == 1) {
                    env->spr[SPR_DSISR] = 0x0A000000;
                } else {
                    env->spr[SPR_DSISR] = 0x08000000;
                }
                break;
            case -5:
                /* No match in segment table */
                env->exception_index = POWERPC_EXCP_DSEG;
                env->error_code = 0;
                env->spr[SPR_DAR] = address;
                break;
            }
        }
#if 0
        printf("%s: set exception to %d %02x\n", __func__,
               env->exception, env->error_code);
#endif
        ret = 1;
    }

    return ret;
}
