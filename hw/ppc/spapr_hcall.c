#include "qemu/osdep.h"
#include "qapi/error.h"
#include "sysemu/hw_accel.h"
#include "sysemu/sysemu.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "exec/exec-all.h"
#include "helper_regs.h"
#include "hw/ppc/spapr.h"
#include "mmu-hash64.h"
#include "cpu-models.h"
#include "trace.h"
#include "kvm_ppc.h"
#include "hw/ppc/spapr_ovec.h"
#include "qemu/error-report.h"
#include "mmu-book3s-v3.h"

struct SPRSyncState {
    int spr;
    target_ulong value;
    target_ulong mask;
};

static void do_spr_sync(CPUState *cs, run_on_cpu_data arg)
{
    struct SPRSyncState *s = arg.host_ptr;
    PowerPCCPU *cpu = POWERPC_CPU(cs);
    CPUPPCState *env = &cpu->env;

    cpu_synchronize_state(cs);
    env->spr[s->spr] &= ~s->mask;
    env->spr[s->spr] |= s->value;
}

static void set_spr(CPUState *cs, int spr, target_ulong value,
                    target_ulong mask)
{
    struct SPRSyncState s = {
        .spr = spr,
        .value = value,
        .mask = mask
    };
    run_on_cpu(cs, do_spr_sync, RUN_ON_CPU_HOST_PTR(&s));
}

static bool has_spr(PowerPCCPU *cpu, int spr)
{
    /* We can test whether the SPR is defined by checking for a valid name */
    return cpu->env.spr_cb[spr].name != NULL;
}

static inline bool valid_ptex(PowerPCCPU *cpu, target_ulong ptex)
{
    /*
     * hash value/pteg group index is normalized by HPT mask
     */
    if (((ptex & ~7ULL) / HPTES_PER_GROUP) & ~ppc_hash64_hpt_mask(cpu)) {
        return false;
    }
    return true;
}

static bool is_ram_address(sPAPRMachineState *spapr, hwaddr addr)
{
    MachineState *machine = MACHINE(spapr);
    MemoryHotplugState *hpms = &spapr->hotplug_memory;

    if (addr < machine->ram_size) {
        return true;
    }
    if ((addr >= hpms->base)
        && ((addr - hpms->base) < memory_region_size(&hpms->mr))) {
        return true;
    }

    return false;
}

static target_ulong h_enter(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                            target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong ptex = args[1];
    target_ulong pteh = args[2];
    target_ulong ptel = args[3];
    unsigned apshift;
    target_ulong raddr;
    target_ulong slot;
    const ppc_hash_pte64_t *hptes;

    apshift = ppc_hash64_hpte_page_shift_noslb(cpu, pteh, ptel);
    if (!apshift) {
        /* Bad page size encoding */
        return H_PARAMETER;
    }

    raddr = (ptel & HPTE64_R_RPN) & ~((1ULL << apshift) - 1);

    if (is_ram_address(spapr, raddr)) {
        /* Regular RAM - should have WIMG=0010 */
        if ((ptel & HPTE64_R_WIMG) != HPTE64_R_M) {
            return H_PARAMETER;
        }
    } else {
        target_ulong wimg_flags;
        /* Looks like an IO address */
        /* FIXME: What WIMG combinations could be sensible for IO?
         * For now we allow WIMG=010x, but are there others? */
        /* FIXME: Should we check against registered IO addresses? */
        wimg_flags = (ptel & (HPTE64_R_W | HPTE64_R_I | HPTE64_R_M));

        if (wimg_flags != HPTE64_R_I &&
            wimg_flags != (HPTE64_R_I | HPTE64_R_M)) {
            return H_PARAMETER;
        }
    }

    pteh &= ~0x60ULL;

    if (!valid_ptex(cpu, ptex)) {
        return H_PARAMETER;
    }

    slot = ptex & 7ULL;
    ptex = ptex & ~7ULL;

    if (likely((flags & H_EXACT) == 0)) {
        hptes = ppc_hash64_map_hptes(cpu, ptex, HPTES_PER_GROUP);
        for (slot = 0; slot < 8; slot++) {
            if (!(ppc_hash64_hpte0(cpu, hptes, slot) & HPTE64_V_VALID)) {
                break;
            }
        }
        ppc_hash64_unmap_hptes(cpu, hptes, ptex, HPTES_PER_GROUP);
        if (slot == 8) {
            return H_PTEG_FULL;
        }
    } else {
        hptes = ppc_hash64_map_hptes(cpu, ptex + slot, 1);
        if (ppc_hash64_hpte0(cpu, hptes, 0) & HPTE64_V_VALID) {
            ppc_hash64_unmap_hptes(cpu, hptes, ptex + slot, 1);
            return H_PTEG_FULL;
        }
        ppc_hash64_unmap_hptes(cpu, hptes, ptex, 1);
    }

    ppc_hash64_store_hpte(cpu, ptex + slot, pteh | HPTE64_V_HPTE_DIRTY, ptel);

    args[0] = ptex + slot;
    return H_SUCCESS;
}

typedef enum {
    REMOVE_SUCCESS = 0,
    REMOVE_NOT_FOUND = 1,
    REMOVE_PARM = 2,
    REMOVE_HW = 3,
} RemoveResult;

static RemoveResult remove_hpte(PowerPCCPU *cpu, target_ulong ptex,
                                target_ulong avpn,
                                target_ulong flags,
                                target_ulong *vp, target_ulong *rp)
{
    const ppc_hash_pte64_t *hptes;
    target_ulong v, r;

    if (!valid_ptex(cpu, ptex)) {
        return REMOVE_PARM;
    }

    hptes = ppc_hash64_map_hptes(cpu, ptex, 1);
    v = ppc_hash64_hpte0(cpu, hptes, 0);
    r = ppc_hash64_hpte1(cpu, hptes, 0);
    ppc_hash64_unmap_hptes(cpu, hptes, ptex, 1);

    if ((v & HPTE64_V_VALID) == 0 ||
        ((flags & H_AVPN) && (v & ~0x7fULL) != avpn) ||
        ((flags & H_ANDCOND) && (v & avpn) != 0)) {
        return REMOVE_NOT_FOUND;
    }
    *vp = v;
    *rp = r;
    ppc_hash64_store_hpte(cpu, ptex, HPTE64_V_HPTE_DIRTY, 0);
    ppc_hash64_tlb_flush_hpte(cpu, ptex, v, r);
    return REMOVE_SUCCESS;
}

static target_ulong h_remove(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                             target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];
    target_ulong ptex = args[1];
    target_ulong avpn = args[2];
    RemoveResult ret;

    ret = remove_hpte(cpu, ptex, avpn, flags,
                      &args[0], &args[1]);

    switch (ret) {
    case REMOVE_SUCCESS:
        check_tlb_flush(env, true);
        return H_SUCCESS;

    case REMOVE_NOT_FOUND:
        return H_NOT_FOUND;

    case REMOVE_PARM:
        return H_PARAMETER;

    case REMOVE_HW:
        return H_HARDWARE;
    }

    g_assert_not_reached();
}

#define H_BULK_REMOVE_TYPE             0xc000000000000000ULL
#define   H_BULK_REMOVE_REQUEST        0x4000000000000000ULL
#define   H_BULK_REMOVE_RESPONSE       0x8000000000000000ULL
#define   H_BULK_REMOVE_END            0xc000000000000000ULL
#define H_BULK_REMOVE_CODE             0x3000000000000000ULL
#define   H_BULK_REMOVE_SUCCESS        0x0000000000000000ULL
#define   H_BULK_REMOVE_NOT_FOUND      0x1000000000000000ULL
#define   H_BULK_REMOVE_PARM           0x2000000000000000ULL
#define   H_BULK_REMOVE_HW             0x3000000000000000ULL
#define H_BULK_REMOVE_RC               0x0c00000000000000ULL
#define H_BULK_REMOVE_FLAGS            0x0300000000000000ULL
#define   H_BULK_REMOVE_ABSOLUTE       0x0000000000000000ULL
#define   H_BULK_REMOVE_ANDCOND        0x0100000000000000ULL
#define   H_BULK_REMOVE_AVPN           0x0200000000000000ULL
#define H_BULK_REMOVE_PTEX             0x00ffffffffffffffULL

#define H_BULK_REMOVE_MAX_BATCH        4

static target_ulong h_bulk_remove(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                  target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    int i;
    target_ulong rc = H_SUCCESS;

    for (i = 0; i < H_BULK_REMOVE_MAX_BATCH; i++) {
        target_ulong *tsh = &args[i*2];
        target_ulong tsl = args[i*2 + 1];
        target_ulong v, r, ret;

        if ((*tsh & H_BULK_REMOVE_TYPE) == H_BULK_REMOVE_END) {
            break;
        } else if ((*tsh & H_BULK_REMOVE_TYPE) != H_BULK_REMOVE_REQUEST) {
            return H_PARAMETER;
        }

        *tsh &= H_BULK_REMOVE_PTEX | H_BULK_REMOVE_FLAGS;
        *tsh |= H_BULK_REMOVE_RESPONSE;

        if ((*tsh & H_BULK_REMOVE_ANDCOND) && (*tsh & H_BULK_REMOVE_AVPN)) {
            *tsh |= H_BULK_REMOVE_PARM;
            return H_PARAMETER;
        }

        ret = remove_hpte(cpu, *tsh & H_BULK_REMOVE_PTEX, tsl,
                          (*tsh & H_BULK_REMOVE_FLAGS) >> 26,
                          &v, &r);

        *tsh |= ret << 60;

        switch (ret) {
        case REMOVE_SUCCESS:
            *tsh |= (r & (HPTE64_R_C | HPTE64_R_R)) << 43;
            break;

        case REMOVE_PARM:
            rc = H_PARAMETER;
            goto exit;

        case REMOVE_HW:
            rc = H_HARDWARE;
            goto exit;
        }
    }
 exit:
    check_tlb_flush(env, true);

    return rc;
}

static target_ulong h_protect(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                              target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    target_ulong flags = args[0];
    target_ulong ptex = args[1];
    target_ulong avpn = args[2];
    const ppc_hash_pte64_t *hptes;
    target_ulong v, r;

    if (!valid_ptex(cpu, ptex)) {
        return H_PARAMETER;
    }

    hptes = ppc_hash64_map_hptes(cpu, ptex, 1);
    v = ppc_hash64_hpte0(cpu, hptes, 0);
    r = ppc_hash64_hpte1(cpu, hptes, 0);
    ppc_hash64_unmap_hptes(cpu, hptes, ptex, 1);

    if ((v & HPTE64_V_VALID) == 0 ||
        ((flags & H_AVPN) && (v & ~0x7fULL) != avpn)) {
        return H_NOT_FOUND;
    }

    r &= ~(HPTE64_R_PP0 | HPTE64_R_PP | HPTE64_R_N |
           HPTE64_R_KEY_HI | HPTE64_R_KEY_LO);
    r |= (flags << 55) & HPTE64_R_PP0;
    r |= (flags << 48) & HPTE64_R_KEY_HI;
    r |= flags & (HPTE64_R_PP | HPTE64_R_N | HPTE64_R_KEY_LO);
    ppc_hash64_store_hpte(cpu, ptex,
                          (v & ~HPTE64_V_VALID) | HPTE64_V_HPTE_DIRTY, 0);
    ppc_hash64_tlb_flush_hpte(cpu, ptex, v, r);
    /* Flush the tlb */
    check_tlb_flush(env, true);
    /* Don't need a memory barrier, due to qemu's global lock */
    ppc_hash64_store_hpte(cpu, ptex, v | HPTE64_V_HPTE_DIRTY, r);
    return H_SUCCESS;
}

static target_ulong h_read(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong ptex = args[1];
    uint8_t *hpte;
    int i, ridx, n_entries = 1;

    if (!valid_ptex(cpu, ptex)) {
        return H_PARAMETER;
    }

    if (flags & H_READ_4) {
        /* Clear the two low order bits */
        ptex &= ~(3ULL);
        n_entries = 4;
    }

    hpte = spapr->htab + (ptex * HASH_PTE_SIZE_64);

    for (i = 0, ridx = 0; i < n_entries; i++) {
        args[ridx++] = ldq_p(hpte);
        args[ridx++] = ldq_p(hpte + (HASH_PTE_SIZE_64/2));
        hpte += HASH_PTE_SIZE_64;
    }

    return H_SUCCESS;
}

struct sPAPRPendingHPT {
    /* These fields are read-only after initialization */
    int shift;
    QemuThread thread;

    /* These fields are protected by the BQL */
    bool complete;

    /* These fields are private to the preparation thread if
     * !complete, otherwise protected by the BQL */
    int ret;
    void *hpt;
};

static void free_pending_hpt(sPAPRPendingHPT *pending)
{
    if (pending->hpt) {
        qemu_vfree(pending->hpt);
    }

    g_free(pending);
}

static void *hpt_prepare_thread(void *opaque)
{
    sPAPRPendingHPT *pending = opaque;
    size_t size = 1ULL << pending->shift;

    pending->hpt = qemu_memalign(size, size);
    if (pending->hpt) {
        memset(pending->hpt, 0, size);
        pending->ret = H_SUCCESS;
    } else {
        pending->ret = H_NO_MEM;
    }

    qemu_mutex_lock_iothread();

    if (SPAPR_MACHINE(qdev_get_machine())->pending_hpt == pending) {
        /* Ready to go */
        pending->complete = true;
    } else {
        /* We've been cancelled, clean ourselves up */
        free_pending_hpt(pending);
    }

    qemu_mutex_unlock_iothread();
    return NULL;
}

/* Must be called with BQL held */
static void cancel_hpt_prepare(sPAPRMachineState *spapr)
{
    sPAPRPendingHPT *pending = spapr->pending_hpt;

    /* Let the thread know it's cancelled */
    spapr->pending_hpt = NULL;

    if (!pending) {
        /* Nothing to do */
        return;
    }

    if (!pending->complete) {
        /* thread will clean itself up */
        return;
    }

    free_pending_hpt(pending);
}

/* Convert a return code from the KVM ioctl()s implementing resize HPT
 * into a PAPR hypercall return code */
static target_ulong resize_hpt_convert_rc(int ret)
{
    if (ret >= 100000) {
        return H_LONG_BUSY_ORDER_100_SEC;
    } else if (ret >= 10000) {
        return H_LONG_BUSY_ORDER_10_SEC;
    } else if (ret >= 1000) {
        return H_LONG_BUSY_ORDER_1_SEC;
    } else if (ret >= 100) {
        return H_LONG_BUSY_ORDER_100_MSEC;
    } else if (ret >= 10) {
        return H_LONG_BUSY_ORDER_10_MSEC;
    } else if (ret > 0) {
        return H_LONG_BUSY_ORDER_1_MSEC;
    }

    switch (ret) {
    case 0:
        return H_SUCCESS;
    case -EPERM:
        return H_AUTHORITY;
    case -EINVAL:
        return H_PARAMETER;
    case -ENXIO:
        return H_CLOSED;
    case -ENOSPC:
        return H_PTEG_FULL;
    case -EBUSY:
        return H_BUSY;
    case -ENOMEM:
        return H_NO_MEM;
    default:
        return H_HARDWARE;
    }
}

static target_ulong h_resize_hpt_prepare(PowerPCCPU *cpu,
                                         sPAPRMachineState *spapr,
                                         target_ulong opcode,
                                         target_ulong *args)
{
    target_ulong flags = args[0];
    int shift = args[1];
    sPAPRPendingHPT *pending = spapr->pending_hpt;
    uint64_t current_ram_size = MACHINE(spapr)->ram_size;
    int rc;

    if (spapr->resize_hpt == SPAPR_RESIZE_HPT_DISABLED) {
        return H_AUTHORITY;
    }

    if (!spapr->htab_shift) {
        /* Radix guest, no HPT */
        return H_NOT_AVAILABLE;
    }

    trace_spapr_h_resize_hpt_prepare(flags, shift);

    if (flags != 0) {
        return H_PARAMETER;
    }

    if (shift && ((shift < 18) || (shift > 46))) {
        return H_PARAMETER;
    }

    current_ram_size = pc_existing_dimms_capacity(&error_fatal);

    /* We only allow the guest to allocate an HPT one order above what
     * we'd normally give them (to stop a small guest claiming a huge
     * chunk of resources in the HPT */
    if (shift > (spapr_hpt_shift_for_ramsize(current_ram_size) + 1)) {
        return H_RESOURCE;
    }

    rc = kvmppc_resize_hpt_prepare(cpu, flags, shift);
    if (rc != -ENOSYS) {
        return resize_hpt_convert_rc(rc);
    }

    if (pending) {
        /* something already in progress */
        if (pending->shift == shift) {
            /* and it's suitable */
            if (pending->complete) {
                return pending->ret;
            } else {
                return H_LONG_BUSY_ORDER_100_MSEC;
            }
        }

        /* not suitable, cancel and replace */
        cancel_hpt_prepare(spapr);
    }

    if (!shift) {
        /* nothing to do */
        return H_SUCCESS;
    }

    /* start new prepare */

    pending = g_new0(sPAPRPendingHPT, 1);
    pending->shift = shift;
    pending->ret = H_HARDWARE;

    qemu_thread_create(&pending->thread, "sPAPR HPT prepare",
                       hpt_prepare_thread, pending, QEMU_THREAD_DETACHED);

    spapr->pending_hpt = pending;

    /* In theory we could estimate the time more accurately based on
     * the new size, but there's not much point */
    return H_LONG_BUSY_ORDER_100_MSEC;
}

static uint64_t new_hpte_load0(void *htab, uint64_t pteg, int slot)
{
    uint8_t *addr = htab;

    addr += pteg * HASH_PTEG_SIZE_64;
    addr += slot * HASH_PTE_SIZE_64;
    return  ldq_p(addr);
}

static void new_hpte_store(void *htab, uint64_t pteg, int slot,
                           uint64_t pte0, uint64_t pte1)
{
    uint8_t *addr = htab;

    addr += pteg * HASH_PTEG_SIZE_64;
    addr += slot * HASH_PTE_SIZE_64;

    stq_p(addr, pte0);
    stq_p(addr + HASH_PTE_SIZE_64 / 2, pte1);
}

static int rehash_hpte(PowerPCCPU *cpu,
                       const ppc_hash_pte64_t *hptes,
                       void *old_hpt, uint64_t oldsize,
                       void *new_hpt, uint64_t newsize,
                       uint64_t pteg, int slot)
{
    uint64_t old_hash_mask = (oldsize >> 7) - 1;
    uint64_t new_hash_mask = (newsize >> 7) - 1;
    target_ulong pte0 = ppc_hash64_hpte0(cpu, hptes, slot);
    target_ulong pte1;
    uint64_t avpn;
    unsigned base_pg_shift;
    uint64_t hash, new_pteg, replace_pte0;

    if (!(pte0 & HPTE64_V_VALID) || !(pte0 & HPTE64_V_BOLTED)) {
        return H_SUCCESS;
    }

    pte1 = ppc_hash64_hpte1(cpu, hptes, slot);

    base_pg_shift = ppc_hash64_hpte_page_shift_noslb(cpu, pte0, pte1);
    assert(base_pg_shift); /* H_ENTER shouldn't allow a bad encoding */
    avpn = HPTE64_V_AVPN_VAL(pte0) & ~(((1ULL << base_pg_shift) - 1) >> 23);

    if (pte0 & HPTE64_V_SECONDARY) {
        pteg = ~pteg;
    }

    if ((pte0 & HPTE64_V_SSIZE) == HPTE64_V_SSIZE_256M) {
        uint64_t offset, vsid;

        /* We only have 28 - 23 bits of offset in avpn */
        offset = (avpn & 0x1f) << 23;
        vsid = avpn >> 5;
        /* We can find more bits from the pteg value */
        if (base_pg_shift < 23) {
            offset |= ((vsid ^ pteg) & old_hash_mask) << base_pg_shift;
        }

        hash = vsid ^ (offset >> base_pg_shift);
    } else if ((pte0 & HPTE64_V_SSIZE) == HPTE64_V_SSIZE_1T) {
        uint64_t offset, vsid;

        /* We only have 40 - 23 bits of seg_off in avpn */
        offset = (avpn & 0x1ffff) << 23;
        vsid = avpn >> 17;
        if (base_pg_shift < 23) {
            offset |= ((vsid ^ (vsid << 25) ^ pteg) & old_hash_mask)
                << base_pg_shift;
        }

        hash = vsid ^ (vsid << 25) ^ (offset >> base_pg_shift);
    } else {
        error_report("rehash_pte: Bad segment size in HPTE");
        return H_HARDWARE;
    }

    new_pteg = hash & new_hash_mask;
    if (pte0 & HPTE64_V_SECONDARY) {
        assert(~pteg == (hash & old_hash_mask));
        new_pteg = ~new_pteg;
    } else {
        assert(pteg == (hash & old_hash_mask));
    }
    assert((oldsize != newsize) || (pteg == new_pteg));
    replace_pte0 = new_hpte_load0(new_hpt, new_pteg, slot);
    /*
     * Strictly speaking, we don't need all these tests, since we only
     * ever rehash bolted HPTEs.  We might in future handle non-bolted
     * HPTEs, though so make the logic correct for those cases as
     * well.
     */
    if (replace_pte0 & HPTE64_V_VALID) {
        assert(newsize < oldsize);
        if (replace_pte0 & HPTE64_V_BOLTED) {
            if (pte0 & HPTE64_V_BOLTED) {
                /* Bolted collision, nothing we can do */
                return H_PTEG_FULL;
            } else {
                /* Discard this hpte */
                return H_SUCCESS;
            }
        }
    }

    new_hpte_store(new_hpt, new_pteg, slot, pte0, pte1);
    return H_SUCCESS;
}

static int rehash_hpt(PowerPCCPU *cpu,
                      void *old_hpt, uint64_t oldsize,
                      void *new_hpt, uint64_t newsize)
{
    uint64_t n_ptegs = oldsize >> 7;
    uint64_t pteg;
    int slot;
    int rc;

    for (pteg = 0; pteg < n_ptegs; pteg++) {
        hwaddr ptex = pteg * HPTES_PER_GROUP;
        const ppc_hash_pte64_t *hptes
            = ppc_hash64_map_hptes(cpu, ptex, HPTES_PER_GROUP);

        if (!hptes) {
            return H_HARDWARE;
        }

        for (slot = 0; slot < HPTES_PER_GROUP; slot++) {
            rc = rehash_hpte(cpu, hptes, old_hpt, oldsize, new_hpt, newsize,
                             pteg, slot);
            if (rc != H_SUCCESS) {
                ppc_hash64_unmap_hptes(cpu, hptes, ptex, HPTES_PER_GROUP);
                return rc;
            }
        }
        ppc_hash64_unmap_hptes(cpu, hptes, ptex, HPTES_PER_GROUP);
    }

    return H_SUCCESS;
}

static target_ulong h_resize_hpt_commit(PowerPCCPU *cpu,
                                        sPAPRMachineState *spapr,
                                        target_ulong opcode,
                                        target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong shift = args[1];
    sPAPRPendingHPT *pending = spapr->pending_hpt;
    int rc;
    size_t newsize;

    if (spapr->resize_hpt == SPAPR_RESIZE_HPT_DISABLED) {
        return H_AUTHORITY;
    }

    trace_spapr_h_resize_hpt_commit(flags, shift);

    rc = kvmppc_resize_hpt_commit(cpu, flags, shift);
    if (rc != -ENOSYS) {
        return resize_hpt_convert_rc(rc);
    }

    if (flags != 0) {
        return H_PARAMETER;
    }

    if (!pending || (pending->shift != shift)) {
        /* no matching prepare */
        return H_CLOSED;
    }

    if (!pending->complete) {
        /* prepare has not completed */
        return H_BUSY;
    }

    /* Shouldn't have got past PREPARE without an HPT */
    g_assert(spapr->htab_shift);

    newsize = 1ULL << pending->shift;
    rc = rehash_hpt(cpu, spapr->htab, HTAB_SIZE(spapr),
                    pending->hpt, newsize);
    if (rc == H_SUCCESS) {
        qemu_vfree(spapr->htab);
        spapr->htab = pending->hpt;
        spapr->htab_shift = pending->shift;

        if (kvm_enabled()) {
            /* For KVM PR, update the HPT pointer */
            target_ulong sdr1 = (target_ulong)(uintptr_t)spapr->htab
                | (spapr->htab_shift - 18);
            kvmppc_update_sdr1(sdr1);
        }

        pending->hpt = NULL; /* so it's not free()d */
    }

    /* Clean up */
    spapr->pending_hpt = NULL;
    free_pending_hpt(pending);

    return rc;
}

static target_ulong h_set_sprg0(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    cpu_synchronize_state(CPU(cpu));
    cpu->env.spr[SPR_SPRG0] = args[0];

    return H_SUCCESS;
}

static target_ulong h_set_dabr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                               target_ulong opcode, target_ulong *args)
{
    if (!has_spr(cpu, SPR_DABR)) {
        return H_HARDWARE;              /* DABR register not available */
    }
    cpu_synchronize_state(CPU(cpu));

    if (has_spr(cpu, SPR_DABRX)) {
        cpu->env.spr[SPR_DABRX] = 0x3;  /* Use Problem and Privileged state */
    } else if (!(args[0] & 0x4)) {      /* Breakpoint Translation set? */
        return H_RESERVED_DABR;
    }

    cpu->env.spr[SPR_DABR] = args[0];
    return H_SUCCESS;
}

static target_ulong h_set_xdabr(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    target_ulong dabrx = args[1];

    if (!has_spr(cpu, SPR_DABR) || !has_spr(cpu, SPR_DABRX)) {
        return H_HARDWARE;
    }

    if ((dabrx & ~0xfULL) != 0 || (dabrx & H_DABRX_HYPERVISOR) != 0
        || (dabrx & (H_DABRX_KERNEL | H_DABRX_USER)) == 0) {
        return H_PARAMETER;
    }

    cpu_synchronize_state(CPU(cpu));
    cpu->env.spr[SPR_DABRX] = dabrx;
    cpu->env.spr[SPR_DABR] = args[0];

    return H_SUCCESS;
}

static target_ulong h_page_init(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    hwaddr dst = args[1];
    hwaddr src = args[2];
    hwaddr len = TARGET_PAGE_SIZE;
    uint8_t *pdst, *psrc;
    target_long ret = H_SUCCESS;

    if (flags & ~(H_ICACHE_SYNCHRONIZE | H_ICACHE_INVALIDATE
                  | H_COPY_PAGE | H_ZERO_PAGE)) {
        qemu_log_mask(LOG_UNIMP, "h_page_init: Bad flags (" TARGET_FMT_lx "\n",
                      flags);
        return H_PARAMETER;
    }

    /* Map-in destination */
    if (!is_ram_address(spapr, dst) || (dst & ~TARGET_PAGE_MASK) != 0) {
        return H_PARAMETER;
    }
    pdst = cpu_physical_memory_map(dst, &len, 1);
    if (!pdst || len != TARGET_PAGE_SIZE) {
        return H_PARAMETER;
    }

    if (flags & H_COPY_PAGE) {
        /* Map-in source, copy to destination, and unmap source again */
        if (!is_ram_address(spapr, src) || (src & ~TARGET_PAGE_MASK) != 0) {
            ret = H_PARAMETER;
            goto unmap_out;
        }
        psrc = cpu_physical_memory_map(src, &len, 0);
        if (!psrc || len != TARGET_PAGE_SIZE) {
            ret = H_PARAMETER;
            goto unmap_out;
        }
        memcpy(pdst, psrc, len);
        cpu_physical_memory_unmap(psrc, len, 0, len);
    } else if (flags & H_ZERO_PAGE) {
        memset(pdst, 0, len);          /* Just clear the destination page */
    }

    if (kvm_enabled() && (flags & H_ICACHE_SYNCHRONIZE) != 0) {
        kvmppc_dcbst_range(cpu, pdst, len);
    }
    if (flags & (H_ICACHE_SYNCHRONIZE | H_ICACHE_INVALIDATE)) {
        if (kvm_enabled()) {
            kvmppc_icbi_range(cpu, pdst, len);
        } else {
            tb_flush(CPU(cpu));
        }
    }

unmap_out:
    cpu_physical_memory_unmap(pdst, TARGET_PAGE_SIZE, 1, len);
    return ret;
}

#define FLAGS_REGISTER_VPA         0x0000200000000000ULL
#define FLAGS_REGISTER_DTL         0x0000400000000000ULL
#define FLAGS_REGISTER_SLBSHADOW   0x0000600000000000ULL
#define FLAGS_DEREGISTER_VPA       0x0000a00000000000ULL
#define FLAGS_DEREGISTER_DTL       0x0000c00000000000ULL
#define FLAGS_DEREGISTER_SLBSHADOW 0x0000e00000000000ULL

#define VPA_MIN_SIZE           640
#define VPA_SIZE_OFFSET        0x4
#define VPA_SHARED_PROC_OFFSET 0x9
#define VPA_SHARED_PROC_VAL    0x2

static target_ulong register_vpa(CPUPPCState *env, target_ulong vpa)
{
    CPUState *cs = CPU(ppc_env_get_cpu(env));
    uint16_t size;
    uint8_t tmp;

    if (vpa == 0) {
        hcall_dprintf("Can't cope with registering a VPA at logical 0\n");
        return H_HARDWARE;
    }

    if (vpa % env->dcache_line_size) {
        return H_PARAMETER;
    }
    /* FIXME: bounds check the address */

    size = lduw_be_phys(cs->as, vpa + 0x4);

    if (size < VPA_MIN_SIZE) {
        return H_PARAMETER;
    }

    /* VPA is not allowed to cross a page boundary */
    if ((vpa / 4096) != ((vpa + size - 1) / 4096)) {
        return H_PARAMETER;
    }

    env->vpa_addr = vpa;

    tmp = ldub_phys(cs->as, env->vpa_addr + VPA_SHARED_PROC_OFFSET);
    tmp |= VPA_SHARED_PROC_VAL;
    stb_phys(cs->as, env->vpa_addr + VPA_SHARED_PROC_OFFSET, tmp);

    return H_SUCCESS;
}

static target_ulong deregister_vpa(CPUPPCState *env, target_ulong vpa)
{
    if (env->slb_shadow_addr) {
        return H_RESOURCE;
    }

    if (env->dtl_addr) {
        return H_RESOURCE;
    }

    env->vpa_addr = 0;
    return H_SUCCESS;
}

static target_ulong register_slb_shadow(CPUPPCState *env, target_ulong addr)
{
    CPUState *cs = CPU(ppc_env_get_cpu(env));
    uint32_t size;

    if (addr == 0) {
        hcall_dprintf("Can't cope with SLB shadow at logical 0\n");
        return H_HARDWARE;
    }

    size = ldl_be_phys(cs->as, addr + 0x4);
    if (size < 0x8) {
        return H_PARAMETER;
    }

    if ((addr / 4096) != ((addr + size - 1) / 4096)) {
        return H_PARAMETER;
    }

    if (!env->vpa_addr) {
        return H_RESOURCE;
    }

    env->slb_shadow_addr = addr;
    env->slb_shadow_size = size;

    return H_SUCCESS;
}

static target_ulong deregister_slb_shadow(CPUPPCState *env, target_ulong addr)
{
    env->slb_shadow_addr = 0;
    env->slb_shadow_size = 0;
    return H_SUCCESS;
}

static target_ulong register_dtl(CPUPPCState *env, target_ulong addr)
{
    CPUState *cs = CPU(ppc_env_get_cpu(env));
    uint32_t size;

    if (addr == 0) {
        hcall_dprintf("Can't cope with DTL at logical 0\n");
        return H_HARDWARE;
    }

    size = ldl_be_phys(cs->as, addr + 0x4);

    if (size < 48) {
        return H_PARAMETER;
    }

    if (!env->vpa_addr) {
        return H_RESOURCE;
    }

    env->dtl_addr = addr;
    env->dtl_size = size;

    return H_SUCCESS;
}

static target_ulong deregister_dtl(CPUPPCState *env, target_ulong addr)
{
    env->dtl_addr = 0;
    env->dtl_size = 0;

    return H_SUCCESS;
}

static target_ulong h_register_vpa(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    target_ulong flags = args[0];
    target_ulong procno = args[1];
    target_ulong vpa = args[2];
    target_ulong ret = H_PARAMETER;
    CPUPPCState *tenv;
    PowerPCCPU *tcpu;

    tcpu = spapr_find_cpu(procno);
    if (!tcpu) {
        return H_PARAMETER;
    }
    tenv = &tcpu->env;

    switch (flags) {
    case FLAGS_REGISTER_VPA:
        ret = register_vpa(tenv, vpa);
        break;

    case FLAGS_DEREGISTER_VPA:
        ret = deregister_vpa(tenv, vpa);
        break;

    case FLAGS_REGISTER_SLBSHADOW:
        ret = register_slb_shadow(tenv, vpa);
        break;

    case FLAGS_DEREGISTER_SLBSHADOW:
        ret = deregister_slb_shadow(tenv, vpa);
        break;

    case FLAGS_REGISTER_DTL:
        ret = register_dtl(tenv, vpa);
        break;

    case FLAGS_DEREGISTER_DTL:
        ret = deregister_dtl(tenv, vpa);
        break;
    }

    return ret;
}

static target_ulong h_cede(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    CPUPPCState *env = &cpu->env;
    CPUState *cs = CPU(cpu);

    env->msr |= (1ULL << MSR_EE);
    hreg_compute_hflags(env);
    if (!cpu_has_work(cs)) {
        cs->halted = 1;
        cs->exception_index = EXCP_HLT;
        cs->exit_request = 1;
    }
    return H_SUCCESS;
}

static target_ulong h_rtas(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                           target_ulong opcode, target_ulong *args)
{
    target_ulong rtas_r3 = args[0];
    uint32_t token = rtas_ld(rtas_r3, 0);
    uint32_t nargs = rtas_ld(rtas_r3, 1);
    uint32_t nret = rtas_ld(rtas_r3, 2);

    return spapr_rtas_call(cpu, spapr, token, nargs, rtas_r3 + 12,
                           nret, rtas_r3 + 12 + 4*nargs);
}

static target_ulong h_logical_load(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);
    target_ulong size = args[0];
    target_ulong addr = args[1];

    switch (size) {
    case 1:
        args[0] = ldub_phys(cs->as, addr);
        return H_SUCCESS;
    case 2:
        args[0] = lduw_phys(cs->as, addr);
        return H_SUCCESS;
    case 4:
        args[0] = ldl_phys(cs->as, addr);
        return H_SUCCESS;
    case 8:
        args[0] = ldq_phys(cs->as, addr);
        return H_SUCCESS;
    }
    return H_PARAMETER;
}

static target_ulong h_logical_store(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                    target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);

    target_ulong size = args[0];
    target_ulong addr = args[1];
    target_ulong val  = args[2];

    switch (size) {
    case 1:
        stb_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 2:
        stw_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 4:
        stl_phys(cs->as, addr, val);
        return H_SUCCESS;
    case 8:
        stq_phys(cs->as, addr, val);
        return H_SUCCESS;
    }
    return H_PARAMETER;
}

static target_ulong h_logical_memop(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                    target_ulong opcode, target_ulong *args)
{
    CPUState *cs = CPU(cpu);

    target_ulong dst   = args[0]; /* Destination address */
    target_ulong src   = args[1]; /* Source address */
    target_ulong esize = args[2]; /* Element size (0=1,1=2,2=4,3=8) */
    target_ulong count = args[3]; /* Element count */
    target_ulong op    = args[4]; /* 0 = copy, 1 = invert */
    uint64_t tmp;
    unsigned int mask = (1 << esize) - 1;
    int step = 1 << esize;

    if (count > 0x80000000) {
        return H_PARAMETER;
    }

    if ((dst & mask) || (src & mask) || (op > 1)) {
        return H_PARAMETER;
    }

    if (dst >= src && dst < (src + (count << esize))) {
            dst = dst + ((count - 1) << esize);
            src = src + ((count - 1) << esize);
            step = -step;
    }

    while (count--) {
        switch (esize) {
        case 0:
            tmp = ldub_phys(cs->as, src);
            break;
        case 1:
            tmp = lduw_phys(cs->as, src);
            break;
        case 2:
            tmp = ldl_phys(cs->as, src);
            break;
        case 3:
            tmp = ldq_phys(cs->as, src);
            break;
        default:
            return H_PARAMETER;
        }
        if (op == 1) {
            tmp = ~tmp;
        }
        switch (esize) {
        case 0:
            stb_phys(cs->as, dst, tmp);
            break;
        case 1:
            stw_phys(cs->as, dst, tmp);
            break;
        case 2:
            stl_phys(cs->as, dst, tmp);
            break;
        case 3:
            stq_phys(cs->as, dst, tmp);
            break;
        }
        dst = dst + step;
        src = src + step;
    }

    return H_SUCCESS;
}

static target_ulong h_logical_icbi(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    /* Nothing to do on emulation, KVM will trap this in the kernel */
    return H_SUCCESS;
}

static target_ulong h_logical_dcbf(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                   target_ulong opcode, target_ulong *args)
{
    /* Nothing to do on emulation, KVM will trap this in the kernel */
    return H_SUCCESS;
}

static target_ulong h_set_mode_resource_le(PowerPCCPU *cpu,
                                           target_ulong mflags,
                                           target_ulong value1,
                                           target_ulong value2)
{
    CPUState *cs;

    if (value1) {
        return H_P3;
    }
    if (value2) {
        return H_P4;
    }

    switch (mflags) {
    case H_SET_MODE_ENDIAN_BIG:
        CPU_FOREACH(cs) {
            set_spr(cs, SPR_LPCR, 0, LPCR_ILE);
        }
        spapr_pci_switch_vga(true);
        return H_SUCCESS;

    case H_SET_MODE_ENDIAN_LITTLE:
        CPU_FOREACH(cs) {
            set_spr(cs, SPR_LPCR, LPCR_ILE, LPCR_ILE);
        }
        spapr_pci_switch_vga(false);
        return H_SUCCESS;
    }

    return H_UNSUPPORTED_FLAG;
}

static target_ulong h_set_mode_resource_addr_trans_mode(PowerPCCPU *cpu,
                                                        target_ulong mflags,
                                                        target_ulong value1,
                                                        target_ulong value2)
{
    CPUState *cs;
    PowerPCCPUClass *pcc = POWERPC_CPU_GET_CLASS(cpu);

    if (!(pcc->insns_flags2 & PPC2_ISA207S)) {
        return H_P2;
    }
    if (value1) {
        return H_P3;
    }
    if (value2) {
        return H_P4;
    }

    if (mflags == AIL_RESERVED) {
        return H_UNSUPPORTED_FLAG;
    }

    CPU_FOREACH(cs) {
        set_spr(cs, SPR_LPCR, mflags << LPCR_AIL_SHIFT, LPCR_AIL);
    }

    return H_SUCCESS;
}

static target_ulong h_set_mode(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                               target_ulong opcode, target_ulong *args)
{
    target_ulong resource = args[1];
    target_ulong ret = H_P2;

    switch (resource) {
    case H_SET_MODE_RESOURCE_LE:
        ret = h_set_mode_resource_le(cpu, args[0], args[2], args[3]);
        break;
    case H_SET_MODE_RESOURCE_ADDR_TRANS_MODE:
        ret = h_set_mode_resource_addr_trans_mode(cpu, args[0],
                                                  args[2], args[3]);
        break;
    }

    return ret;
}

static target_ulong h_clean_slb(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                target_ulong opcode, target_ulong *args)
{
    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x"TARGET_FMT_lx"%s\n",
                  opcode, " (H_CLEAN_SLB)");
    return H_FUNCTION;
}

static target_ulong h_invalidate_pid(PowerPCCPU *cpu, sPAPRMachineState *spapr,
                                     target_ulong opcode, target_ulong *args)
{
    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x"TARGET_FMT_lx"%s\n",
                  opcode, " (H_INVALIDATE_PID)");
    return H_FUNCTION;
}

static void spapr_check_setup_free_hpt(sPAPRMachineState *spapr,
                                       uint64_t patbe_old, uint64_t patbe_new)
{
    /*
     * We have 4 Options:
     * HASH->HASH || RADIX->RADIX || NOTHING->RADIX : Do Nothing
     * HASH->RADIX                                  : Free HPT
     * RADIX->HASH                                  : Allocate HPT
     * NOTHING->HASH                                : Allocate HPT
     * Note: NOTHING implies the case where we said the guest could choose
     *       later and so assumed radix and now it's called H_REG_PROC_TBL
     */

    if ((patbe_old & PATBE1_GR) == (patbe_new & PATBE1_GR)) {
        /* We assume RADIX, so this catches all the "Do Nothing" cases */
    } else if (!(patbe_old & PATBE1_GR)) {
        /* HASH->RADIX : Free HPT */
        spapr_free_hpt(spapr);
    } else if (!(patbe_new & PATBE1_GR)) {
        /* RADIX->HASH || NOTHING->HASH : Allocate HPT */
        spapr_setup_hpt_and_vrma(spapr);
    }
    return;
}

#define FLAGS_MASK              0x01FULL
#define FLAG_MODIFY             0x10
#define FLAG_REGISTER           0x08
#define FLAG_RADIX              0x04
#define FLAG_HASH_PROC_TBL      0x02
#define FLAG_GTSE               0x01

static target_ulong h_register_process_table(PowerPCCPU *cpu,
                                             sPAPRMachineState *spapr,
                                             target_ulong opcode,
                                             target_ulong *args)
{
    CPUState *cs;
    target_ulong flags = args[0];
    target_ulong proc_tbl = args[1];
    target_ulong page_size = args[2];
    target_ulong table_size = args[3];
    uint64_t cproc;

    if (flags & ~FLAGS_MASK) { /* Check no reserved bits are set */
        return H_PARAMETER;
    }
    if (flags & FLAG_MODIFY) {
        if (flags & FLAG_REGISTER) {
            if (flags & FLAG_RADIX) { /* Register new RADIX process table */
                if (proc_tbl & 0xfff || proc_tbl >> 60) {
                    return H_P2;
                } else if (page_size) {
                    return H_P3;
                } else if (table_size > 24) {
                    return H_P4;
                }
                cproc = PATBE1_GR | proc_tbl | table_size;
            } else { /* Register new HPT process table */
                if (flags & FLAG_HASH_PROC_TBL) { /* Hash with Segment Tables */
                    /* TODO - Not Supported */
                    /* Technically caused by flag bits => H_PARAMETER */
                    return H_PARAMETER;
                } else { /* Hash with SLB */
                    if (proc_tbl >> 38) {
                        return H_P2;
                    } else if (page_size & ~0x7) {
                        return H_P3;
                    } else if (table_size > 24) {
                        return H_P4;
                    }
                }
                cproc = (proc_tbl << 25) | page_size << 5 | table_size;
            }

        } else { /* Deregister current process table */
            /* Set to benign value: (current GR) | 0. This allows
             * deregistration in KVM to succeed even if the radix bit in flags
             * doesn't match the radix bit in the old PATB. */
            cproc = spapr->patb_entry & PATBE1_GR;
        }
    } else { /* Maintain current registration */
        if (!(flags & FLAG_RADIX) != !(spapr->patb_entry & PATBE1_GR)) {
            /* Technically caused by flag bits => H_PARAMETER */
            return H_PARAMETER; /* Existing Process Table Mismatch */
        }
        cproc = spapr->patb_entry;
    }

    /* Check if we need to setup OR free the hpt */
    spapr_check_setup_free_hpt(spapr, spapr->patb_entry, cproc);

    spapr->patb_entry = cproc; /* Save new process table */

    /* Update the UPRT and GTSE bits in the LPCR for all cpus */
    CPU_FOREACH(cs) {
        set_spr(cs, SPR_LPCR,
                ((flags & (FLAG_RADIX | FLAG_HASH_PROC_TBL)) ? LPCR_UPRT : 0) |
                ((flags & FLAG_GTSE) ? LPCR_GTSE : 0),
                LPCR_UPRT | LPCR_GTSE);
    }

    if (kvm_enabled()) {
        return kvmppc_configure_v3_mmu(cpu, flags & FLAG_RADIX,
                                       flags & FLAG_GTSE, cproc);
    }
    return H_SUCCESS;
}

#define H_SIGNAL_SYS_RESET_ALL         -1
#define H_SIGNAL_SYS_RESET_ALLBUTSELF  -2

static target_ulong h_signal_sys_reset(PowerPCCPU *cpu,
                                       sPAPRMachineState *spapr,
                                       target_ulong opcode, target_ulong *args)
{
    target_long target = args[0];
    CPUState *cs;

    if (target < 0) {
        /* Broadcast */
        if (target < H_SIGNAL_SYS_RESET_ALLBUTSELF) {
            return H_PARAMETER;
        }

        CPU_FOREACH(cs) {
            PowerPCCPU *c = POWERPC_CPU(cs);

            if (target == H_SIGNAL_SYS_RESET_ALLBUTSELF) {
                if (c == cpu) {
                    continue;
                }
            }
            run_on_cpu(cs, spapr_do_system_reset_on_cpu, RUN_ON_CPU_NULL);
        }
        return H_SUCCESS;

    } else {
        /* Unicast */
        cs = CPU(spapr_find_cpu(target));
        if (cs) {
            run_on_cpu(cs, spapr_do_system_reset_on_cpu, RUN_ON_CPU_NULL);
            return H_SUCCESS;
        }
        return H_PARAMETER;
    }
}

static uint32_t cas_check_pvr(sPAPRMachineState *spapr, PowerPCCPU *cpu,
                              target_ulong *addr, bool *raw_mode_supported,
                              Error **errp)
{
    bool explicit_match = false; /* Matched the CPU's real PVR */
    uint32_t max_compat = spapr->max_compat_pvr;
    uint32_t best_compat = 0;
    int i;

    /*
     * We scan the supplied table of PVRs looking for two things
     *   1. Is our real CPU PVR in the list?
     *   2. What's the "best" listed logical PVR
     */
    for (i = 0; i < 512; ++i) {
        uint32_t pvr, pvr_mask;

        pvr_mask = ldl_be_phys(&address_space_memory, *addr);
        pvr = ldl_be_phys(&address_space_memory, *addr + 4);
        *addr += 8;

        if (~pvr_mask & pvr) {
            break; /* Terminator record */
        }

        if ((cpu->env.spr[SPR_PVR] & pvr_mask) == (pvr & pvr_mask)) {
            explicit_match = true;
        } else {
            if (ppc_check_compat(cpu, pvr, best_compat, max_compat)) {
                best_compat = pvr;
            }
        }
    }

    if ((best_compat == 0) && (!explicit_match || max_compat)) {
        /* We couldn't find a suitable compatibility mode, and either
         * the guest doesn't support "raw" mode for this CPU, or raw
         * mode is disabled because a maximum compat mode is set */
        error_setg(errp, "Couldn't negotiate a suitable PVR during CAS");
        return 0;
    }

    *raw_mode_supported = explicit_match;

    /* Parsing finished */
    trace_spapr_cas_pvr(cpu->compat_pvr, explicit_match, best_compat);

    return best_compat;
}

static target_ulong h_client_architecture_support(PowerPCCPU *cpu,
                                                  sPAPRMachineState *spapr,
                                                  target_ulong opcode,
                                                  target_ulong *args)
{
    /* Working address in data buffer */
    target_ulong addr = ppc64_phys_to_real(args[0]);
    target_ulong ov_table;
    uint32_t cas_pvr;
    sPAPROptionVector *ov1_guest, *ov5_guest, *ov5_cas_old, *ov5_updates;
    bool guest_radix;
    Error *local_err = NULL;
    bool raw_mode_supported = false;

    cas_pvr = cas_check_pvr(spapr, cpu, &addr, &raw_mode_supported, &local_err);
    if (local_err) {
        error_report_err(local_err);
        return H_HARDWARE;
    }

    /* Update CPUs */
    if (cpu->compat_pvr != cas_pvr) {
        ppc_set_compat_all(cas_pvr, &local_err);
        if (local_err) {
            /* We fail to set compat mode (likely because running with KVM PR),
             * but maybe we can fallback to raw mode if the guest supports it.
             */
            if (!raw_mode_supported) {
                error_report_err(local_err);
                return H_HARDWARE;
            }
            local_err = NULL;
        }
    }

    /* For the future use: here @ov_table points to the first option vector */
    ov_table = addr;

    ov1_guest = spapr_ovec_parse_vector(ov_table, 1);
    ov5_guest = spapr_ovec_parse_vector(ov_table, 5);
    if (spapr_ovec_test(ov5_guest, OV5_MMU_BOTH)) {
        error_report("guest requested hash and radix MMU, which is invalid.");
        exit(EXIT_FAILURE);
    }
    /* The radix/hash bit in byte 24 requires special handling: */
    guest_radix = spapr_ovec_test(ov5_guest, OV5_MMU_RADIX_300);
    spapr_ovec_clear(ov5_guest, OV5_MMU_RADIX_300);

    /*
     * HPT resizing is a bit of a special case, because when enabled
     * we assume an HPT guest will support it until it says it
     * doesn't, instead of assuming it won't support it until it says
     * it does.  Strictly speaking that approach could break for
     * guests which don't make a CAS call, but those are so old we
     * don't care about them.  Without that assumption we'd have to
     * make at least a temporary allocation of an HPT sized for max
     * memory, which could be impossibly difficult under KVM HV if
     * maxram is large.
     */
    if (!guest_radix && !spapr_ovec_test(ov5_guest, OV5_HPT_RESIZE)) {
        int maxshift = spapr_hpt_shift_for_ramsize(MACHINE(spapr)->maxram_size);

        if (spapr->resize_hpt == SPAPR_RESIZE_HPT_REQUIRED) {
            error_report(
                "h_client_architecture_support: Guest doesn't support HPT resizing, but resize-hpt=required");
            exit(1);
        }

        if (spapr->htab_shift < maxshift) {
            /* Guest doesn't know about HPT resizing, so we
             * pre-emptively resize for the maximum permitted RAM.  At
             * the point this is called, nothing should have been
             * entered into the existing HPT */
            spapr_reallocate_hpt(spapr, maxshift, &error_fatal);
            if (kvm_enabled()) {
                /* For KVM PR, update the HPT pointer */
                target_ulong sdr1 = (target_ulong)(uintptr_t)spapr->htab
                    | (spapr->htab_shift - 18);
                kvmppc_update_sdr1(sdr1);
            }
        }
    }

    /* NOTE: there are actually a number of ov5 bits where input from the
     * guest is always zero, and the platform/QEMU enables them independently
     * of guest input. To model these properly we'd want some sort of mask,
     * but since they only currently apply to memory migration as defined
     * by LoPAPR 1.1, 14.5.4.8, which QEMU doesn't implement, we don't need
     * to worry about this for now.
     */
    ov5_cas_old = spapr_ovec_clone(spapr->ov5_cas);
    /* full range of negotiated ov5 capabilities */
    spapr_ovec_intersect(spapr->ov5_cas, spapr->ov5, ov5_guest);
    spapr_ovec_cleanup(ov5_guest);
    /* capabilities that have been added since CAS-generated guest reset.
     * if capabilities have since been removed, generate another reset
     */
    ov5_updates = spapr_ovec_new();
    spapr->cas_reboot = spapr_ovec_diff(ov5_updates,
                                        ov5_cas_old, spapr->ov5_cas);
    /* Now that processing is finished, set the radix/hash bit for the
     * guest if it requested a valid mode; otherwise terminate the boot. */
    if (guest_radix) {
        if (kvm_enabled() && !kvmppc_has_cap_mmu_radix()) {
            error_report("Guest requested unavailable MMU mode (radix).");
            exit(EXIT_FAILURE);
        }
        spapr_ovec_set(spapr->ov5_cas, OV5_MMU_RADIX_300);
    } else {
        if (kvm_enabled() && kvmppc_has_cap_mmu_radix()
            && !kvmppc_has_cap_mmu_hash_v3()) {
            error_report("Guest requested unavailable MMU mode (hash).");
            exit(EXIT_FAILURE);
        }
    }
    spapr->cas_legacy_guest_workaround = !spapr_ovec_test(ov1_guest,
                                                          OV1_PPC_3_00);
    if (!spapr->cas_reboot) {
        spapr->cas_reboot =
            (spapr_h_cas_compose_response(spapr, args[1], args[2],
                                          ov5_updates) != 0);
    }
    spapr_ovec_cleanup(ov5_updates);

    if (spapr->cas_reboot) {
        qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);
    } else {
        /* If ppc_spapr_reset() did not set up a HPT but one is necessary
         * (because the guest isn't going to use radix) then set it up here. */
        if ((spapr->patb_entry & PATBE1_GR) && !guest_radix) {
            /* legacy hash or new hash: */
            spapr_setup_hpt_and_vrma(spapr);
        }
    }

    return H_SUCCESS;
}

static spapr_hcall_fn papr_hypercall_table[(MAX_HCALL_OPCODE / 4) + 1];
static spapr_hcall_fn kvmppc_hypercall_table[KVMPPC_HCALL_MAX - KVMPPC_HCALL_BASE + 1];

void spapr_register_hypercall(target_ulong opcode, spapr_hcall_fn fn)
{
    spapr_hcall_fn *slot;

    if (opcode <= MAX_HCALL_OPCODE) {
        assert((opcode & 0x3) == 0);

        slot = &papr_hypercall_table[opcode / 4];
    } else {
        assert((opcode >= KVMPPC_HCALL_BASE) && (opcode <= KVMPPC_HCALL_MAX));

        slot = &kvmppc_hypercall_table[opcode - KVMPPC_HCALL_BASE];
    }

    assert(!(*slot));
    *slot = fn;
}

target_ulong spapr_hypercall(PowerPCCPU *cpu, target_ulong opcode,
                             target_ulong *args)
{
    sPAPRMachineState *spapr = SPAPR_MACHINE(qdev_get_machine());

    if ((opcode <= MAX_HCALL_OPCODE)
        && ((opcode & 0x3) == 0)) {
        spapr_hcall_fn fn = papr_hypercall_table[opcode / 4];

        if (fn) {
            return fn(cpu, spapr, opcode, args);
        }
    } else if ((opcode >= KVMPPC_HCALL_BASE) &&
               (opcode <= KVMPPC_HCALL_MAX)) {
        spapr_hcall_fn fn = kvmppc_hypercall_table[opcode - KVMPPC_HCALL_BASE];

        if (fn) {
            return fn(cpu, spapr, opcode, args);
        }
    }

    qemu_log_mask(LOG_UNIMP, "Unimplemented SPAPR hcall 0x" TARGET_FMT_lx "\n",
                  opcode);
    return H_FUNCTION;
}

static void hypercall_register_types(void)
{
    /* hcall-pft */
    spapr_register_hypercall(H_ENTER, h_enter);
    spapr_register_hypercall(H_REMOVE, h_remove);
    spapr_register_hypercall(H_PROTECT, h_protect);
    spapr_register_hypercall(H_READ, h_read);

    /* hcall-bulk */
    spapr_register_hypercall(H_BULK_REMOVE, h_bulk_remove);

    /* hcall-hpt-resize */
    spapr_register_hypercall(H_RESIZE_HPT_PREPARE, h_resize_hpt_prepare);
    spapr_register_hypercall(H_RESIZE_HPT_COMMIT, h_resize_hpt_commit);

    /* hcall-splpar */
    spapr_register_hypercall(H_REGISTER_VPA, h_register_vpa);
    spapr_register_hypercall(H_CEDE, h_cede);
    spapr_register_hypercall(H_SIGNAL_SYS_RESET, h_signal_sys_reset);

    /* processor register resource access h-calls */
    spapr_register_hypercall(H_SET_SPRG0, h_set_sprg0);
    spapr_register_hypercall(H_SET_DABR, h_set_dabr);
    spapr_register_hypercall(H_SET_XDABR, h_set_xdabr);
    spapr_register_hypercall(H_PAGE_INIT, h_page_init);
    spapr_register_hypercall(H_SET_MODE, h_set_mode);

    /* In Memory Table MMU h-calls */
    spapr_register_hypercall(H_CLEAN_SLB, h_clean_slb);
    spapr_register_hypercall(H_INVALIDATE_PID, h_invalidate_pid);
    spapr_register_hypercall(H_REGISTER_PROC_TBL, h_register_process_table);

    /* "debugger" hcalls (also used by SLOF). Note: We do -not- differenciate
     * here between the "CI" and the "CACHE" variants, they will use whatever
     * mapping attributes qemu is using. When using KVM, the kernel will
     * enforce the attributes more strongly
     */
    spapr_register_hypercall(H_LOGICAL_CI_LOAD, h_logical_load);
    spapr_register_hypercall(H_LOGICAL_CI_STORE, h_logical_store);
    spapr_register_hypercall(H_LOGICAL_CACHE_LOAD, h_logical_load);
    spapr_register_hypercall(H_LOGICAL_CACHE_STORE, h_logical_store);
    spapr_register_hypercall(H_LOGICAL_ICBI, h_logical_icbi);
    spapr_register_hypercall(H_LOGICAL_DCBF, h_logical_dcbf);
    spapr_register_hypercall(KVMPPC_H_LOGICAL_MEMOP, h_logical_memop);

    /* qemu/KVM-PPC specific hcalls */
    spapr_register_hypercall(KVMPPC_H_RTAS, h_rtas);

    /* ibm,client-architecture-support support */
    spapr_register_hypercall(KVMPPC_H_CAS, h_client_architecture_support);
}

type_init(hypercall_register_types)
