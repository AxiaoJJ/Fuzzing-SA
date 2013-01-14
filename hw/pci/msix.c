/*
 * MSI-X device support
 *
 * This module includes support for MSI-X in pci devices.
 *
 * Author: Michael S. Tsirkin <mst@redhat.com>
 *
 *  Copyright (c) 2009, Red Hat Inc, Michael S. Tsirkin (mst@redhat.com)
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "hw/pci/msix.h"
#include "hw/pci/pci.h"
#include "qemu/range.h"

#define MSIX_CAP_LENGTH 12

/* MSI enable bit and maskall bit are in byte 1 in FLAGS register */
#define MSIX_CONTROL_OFFSET (PCI_MSIX_FLAGS + 1)
#define MSIX_ENABLE_MASK (PCI_MSIX_FLAGS_ENABLE >> 8)
#define MSIX_MASKALL_MASK (PCI_MSIX_FLAGS_MASKALL >> 8)

MSIMessage msix_get_message(PCIDevice *dev, unsigned vector)
{
    uint8_t *table_entry = dev->msix_table + vector * PCI_MSIX_ENTRY_SIZE;
    MSIMessage msg;

    msg.address = pci_get_quad(table_entry + PCI_MSIX_ENTRY_LOWER_ADDR);
    msg.data = pci_get_long(table_entry + PCI_MSIX_ENTRY_DATA);
    return msg;
}

/*
 * Special API for POWER to configure the vectors through
 * a side channel. Should never be used by devices.
 */
void msix_set_message(PCIDevice *dev, int vector, struct MSIMessage msg)
{
    uint8_t *table_entry = dev->msix_table + vector * PCI_MSIX_ENTRY_SIZE;

    pci_set_quad(table_entry + PCI_MSIX_ENTRY_LOWER_ADDR, msg.address);
    pci_set_long(table_entry + PCI_MSIX_ENTRY_DATA, msg.data);
    table_entry[PCI_MSIX_ENTRY_VECTOR_CTRL] &= ~PCI_MSIX_ENTRY_CTRL_MASKBIT;
}

static uint8_t msix_pending_mask(int vector)
{
    return 1 << (vector % 8);
}

static uint8_t *msix_pending_byte(PCIDevice *dev, int vector)
{
    return dev->msix_pba + vector / 8;
}

static int msix_is_pending(PCIDevice *dev, int vector)
{
    return *msix_pending_byte(dev, vector) & msix_pending_mask(vector);
}

void msix_set_pending(PCIDevice *dev, unsigned int vector)
{
    *msix_pending_byte(dev, vector) |= msix_pending_mask(vector);
}

static void msix_clr_pending(PCIDevice *dev, int vector)
{
    *msix_pending_byte(dev, vector) &= ~msix_pending_mask(vector);
}

static bool msix_vector_masked(PCIDevice *dev, unsigned int vector, bool fmask)
{
    unsigned offset = vector * PCI_MSIX_ENTRY_SIZE + PCI_MSIX_ENTRY_VECTOR_CTRL;
    return fmask || dev->msix_table[offset] & PCI_MSIX_ENTRY_CTRL_MASKBIT;
}

bool msix_is_masked(PCIDevice *dev, unsigned int vector)
{
    return msix_vector_masked(dev, vector, dev->msix_function_masked);
}

static void msix_fire_vector_notifier(PCIDevice *dev,
                                      unsigned int vector, bool is_masked)
{
    MSIMessage msg;
    int ret;

    if (!dev->msix_vector_use_notifier) {
        return;
    }
    if (is_masked) {
        dev->msix_vector_release_notifier(dev, vector);
    } else {
        msg = msix_get_message(dev, vector);
        ret = dev->msix_vector_use_notifier(dev, vector, msg);
        assert(ret >= 0);
    }
}

static void msix_handle_mask_update(PCIDevice *dev, int vector, bool was_masked)
{
    bool is_masked = msix_is_masked(dev, vector);

    if (is_masked == was_masked) {
        return;
    }

    msix_fire_vector_notifier(dev, vector, is_masked);

    if (!is_masked && msix_is_pending(dev, vector)) {
        msix_clr_pending(dev, vector);
        msix_notify(dev, vector);
    }
}

static void msix_update_function_masked(PCIDevice *dev)
{
    dev->msix_function_masked = !msix_enabled(dev) ||
        (dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] & MSIX_MASKALL_MASK);
}

/* Handle MSI-X capability config write. */
void msix_write_config(PCIDevice *dev, uint32_t addr,
                       uint32_t val, int len)
{
    unsigned enable_pos = dev->msix_cap + MSIX_CONTROL_OFFSET;
    int vector;
    bool was_masked;

    if (!msix_present(dev) || !range_covers_byte(addr, len, enable_pos)) {
        return;
    }

    was_masked = dev->msix_function_masked;
    msix_update_function_masked(dev);

    if (!msix_enabled(dev)) {
        return;
    }

    pci_device_deassert_intx(dev);

    if (dev->msix_function_masked == was_masked) {
        return;
    }

    for (vector = 0; vector < dev->msix_entries_nr; ++vector) {
        msix_handle_mask_update(dev, vector,
                                msix_vector_masked(dev, vector, was_masked));
    }
}

static uint64_t msix_table_mmio_read(void *opaque, hwaddr addr,
                                     unsigned size)
{
    PCIDevice *dev = opaque;

    return pci_get_long(dev->msix_table + addr);
}

static void msix_table_mmio_write(void *opaque, hwaddr addr,
                                  uint64_t val, unsigned size)
{
    PCIDevice *dev = opaque;
    int vector = addr / PCI_MSIX_ENTRY_SIZE;
    bool was_masked;

    was_masked = msix_is_masked(dev, vector);
    pci_set_long(dev->msix_table + addr, val);
    msix_handle_mask_update(dev, vector, was_masked);
}

static const MemoryRegionOps msix_table_mmio_ops = {
    .read = msix_table_mmio_read,
    .write = msix_table_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static uint64_t msix_pba_mmio_read(void *opaque, hwaddr addr,
                                   unsigned size)
{
    PCIDevice *dev = opaque;
    if (dev->msix_vector_poll_notifier) {
        unsigned vector_start = addr * 8;
        unsigned vector_end = MIN(addr + size * 8, dev->msix_entries_nr);
        dev->msix_vector_poll_notifier(dev, vector_start, vector_end);
    }

    return pci_get_long(dev->msix_pba + addr);
}

static const MemoryRegionOps msix_pba_mmio_ops = {
    .read = msix_pba_mmio_read,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

static void msix_mask_all(struct PCIDevice *dev, unsigned nentries)
{
    int vector;

    for (vector = 0; vector < nentries; ++vector) {
        unsigned offset =
            vector * PCI_MSIX_ENTRY_SIZE + PCI_MSIX_ENTRY_VECTOR_CTRL;
        bool was_masked = msix_is_masked(dev, vector);

        dev->msix_table[offset] |= PCI_MSIX_ENTRY_CTRL_MASKBIT;
        msix_handle_mask_update(dev, vector, was_masked);
    }
}

/* Initialize the MSI-X structures */
int msix_init(struct PCIDevice *dev, unsigned short nentries,
              MemoryRegion *table_bar, uint8_t table_bar_nr,
              unsigned table_offset, MemoryRegion *pba_bar,
              uint8_t pba_bar_nr, unsigned pba_offset, uint8_t cap_pos)
{
    int cap;
    unsigned table_size, pba_size;
    uint8_t *config;

    /* Nothing to do if MSI is not supported by interrupt controller */
    if (!msi_supported) {
        return -ENOTSUP;
    }

    if (nentries < 1 || nentries > PCI_MSIX_FLAGS_QSIZE + 1) {
        return -EINVAL;
    }

    table_size = nentries * PCI_MSIX_ENTRY_SIZE;
    pba_size = QEMU_ALIGN_UP(nentries, 64) / 8;

    /* Sanity test: table & pba don't overlap, fit within BARs, min aligned */
    if ((table_bar_nr == pba_bar_nr &&
         ranges_overlap(table_offset, table_size, pba_offset, pba_size)) ||
        table_offset + table_size > memory_region_size(table_bar) ||
        pba_offset + pba_size > memory_region_size(pba_bar) ||
        (table_offset | pba_offset) & PCI_MSIX_FLAGS_BIRMASK) {
        return -EINVAL;
    }

    cap = pci_add_capability(dev, PCI_CAP_ID_MSIX, cap_pos, MSIX_CAP_LENGTH);
    if (cap < 0) {
        return cap;
    }

    dev->msix_cap = cap;
    dev->cap_present |= QEMU_PCI_CAP_MSIX;
    config = dev->config + cap;

    pci_set_word(config + PCI_MSIX_FLAGS, nentries - 1);
    dev->msix_entries_nr = nentries;
    dev->msix_function_masked = true;

    pci_set_long(config + PCI_MSIX_TABLE, table_offset | table_bar_nr);
    pci_set_long(config + PCI_MSIX_PBA, pba_offset | pba_bar_nr);

    /* Make flags bit writable. */
    dev->wmask[cap + MSIX_CONTROL_OFFSET] |= MSIX_ENABLE_MASK |
                                             MSIX_MASKALL_MASK;

    dev->msix_table = g_malloc0(table_size);
    dev->msix_pba = g_malloc0(pba_size);
    dev->msix_entry_used = g_malloc0(nentries * sizeof *dev->msix_entry_used);

    msix_mask_all(dev, nentries);

    memory_region_init_io(&dev->msix_table_mmio, &msix_table_mmio_ops, dev,
                          "msix-table", table_size);
    memory_region_add_subregion(table_bar, table_offset, &dev->msix_table_mmio);
    memory_region_init_io(&dev->msix_pba_mmio, &msix_pba_mmio_ops, dev,
                          "msix-pba", pba_size);
    memory_region_add_subregion(pba_bar, pba_offset, &dev->msix_pba_mmio);

    return 0;
}

int msix_init_exclusive_bar(PCIDevice *dev, unsigned short nentries,
                            uint8_t bar_nr)
{
    int ret;
    char *name;

    /*
     * Migration compatibility dictates that this remains a 4k
     * BAR with the vector table in the lower half and PBA in
     * the upper half.  Do not use these elsewhere!
     */
#define MSIX_EXCLUSIVE_BAR_SIZE 4096
#define MSIX_EXCLUSIVE_BAR_TABLE_OFFSET 0
#define MSIX_EXCLUSIVE_BAR_PBA_OFFSET (MSIX_EXCLUSIVE_BAR_SIZE / 2)
#define MSIX_EXCLUSIVE_CAP_OFFSET 0

    if (nentries * PCI_MSIX_ENTRY_SIZE > MSIX_EXCLUSIVE_BAR_PBA_OFFSET) {
        return -EINVAL;
    }

    name = g_strdup_printf("%s-msix", dev->name);
    memory_region_init(&dev->msix_exclusive_bar, name, MSIX_EXCLUSIVE_BAR_SIZE);
    g_free(name);

    ret = msix_init(dev, nentries, &dev->msix_exclusive_bar, bar_nr,
                    MSIX_EXCLUSIVE_BAR_TABLE_OFFSET, &dev->msix_exclusive_bar,
                    bar_nr, MSIX_EXCLUSIVE_BAR_PBA_OFFSET,
                    MSIX_EXCLUSIVE_CAP_OFFSET);
    if (ret) {
        memory_region_destroy(&dev->msix_exclusive_bar);
        return ret;
    }

    pci_register_bar(dev, bar_nr, PCI_BASE_ADDRESS_SPACE_MEMORY,
                     &dev->msix_exclusive_bar);

    return 0;
}

static void msix_free_irq_entries(PCIDevice *dev)
{
    int vector;

    for (vector = 0; vector < dev->msix_entries_nr; ++vector) {
        dev->msix_entry_used[vector] = 0;
        msix_clr_pending(dev, vector);
    }
}

static void msix_clear_all_vectors(PCIDevice *dev)
{
    int vector;

    for (vector = 0; vector < dev->msix_entries_nr; ++vector) {
        msix_clr_pending(dev, vector);
    }
}

/* Clean up resources for the device. */
void msix_uninit(PCIDevice *dev, MemoryRegion *table_bar, MemoryRegion *pba_bar)
{
    if (!msix_present(dev)) {
        return;
    }
    pci_del_capability(dev, PCI_CAP_ID_MSIX, MSIX_CAP_LENGTH);
    dev->msix_cap = 0;
    msix_free_irq_entries(dev);
    dev->msix_entries_nr = 0;
    memory_region_del_subregion(pba_bar, &dev->msix_pba_mmio);
    memory_region_destroy(&dev->msix_pba_mmio);
    g_free(dev->msix_pba);
    dev->msix_pba = NULL;
    memory_region_del_subregion(table_bar, &dev->msix_table_mmio);
    memory_region_destroy(&dev->msix_table_mmio);
    g_free(dev->msix_table);
    dev->msix_table = NULL;
    g_free(dev->msix_entry_used);
    dev->msix_entry_used = NULL;
    dev->cap_present &= ~QEMU_PCI_CAP_MSIX;
}

void msix_uninit_exclusive_bar(PCIDevice *dev)
{
    if (msix_present(dev)) {
        msix_uninit(dev, &dev->msix_exclusive_bar, &dev->msix_exclusive_bar);
        memory_region_destroy(&dev->msix_exclusive_bar);
    }
}

void msix_save(PCIDevice *dev, QEMUFile *f)
{
    unsigned n = dev->msix_entries_nr;

    if (!msix_present(dev)) {
        return;
    }

    qemu_put_buffer(f, dev->msix_table, n * PCI_MSIX_ENTRY_SIZE);
    qemu_put_buffer(f, dev->msix_pba, (n + 7) / 8);
}

/* Should be called after restoring the config space. */
void msix_load(PCIDevice *dev, QEMUFile *f)
{
    unsigned n = dev->msix_entries_nr;
    unsigned int vector;

    if (!msix_present(dev)) {
        return;
    }

    msix_clear_all_vectors(dev);
    qemu_get_buffer(f, dev->msix_table, n * PCI_MSIX_ENTRY_SIZE);
    qemu_get_buffer(f, dev->msix_pba, (n + 7) / 8);
    msix_update_function_masked(dev);

    for (vector = 0; vector < n; vector++) {
        msix_handle_mask_update(dev, vector, true);
    }
}

/* Does device support MSI-X? */
int msix_present(PCIDevice *dev)
{
    return dev->cap_present & QEMU_PCI_CAP_MSIX;
}

/* Is MSI-X enabled? */
int msix_enabled(PCIDevice *dev)
{
    return (dev->cap_present & QEMU_PCI_CAP_MSIX) &&
        (dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
         MSIX_ENABLE_MASK);
}

/* Send an MSI-X message */
void msix_notify(PCIDevice *dev, unsigned vector)
{
    MSIMessage msg;

    if (vector >= dev->msix_entries_nr || !dev->msix_entry_used[vector])
        return;
    if (msix_is_masked(dev, vector)) {
        msix_set_pending(dev, vector);
        return;
    }

    msg = msix_get_message(dev, vector);

    stl_le_phys(msg.address, msg.data);
}

void msix_reset(PCIDevice *dev)
{
    if (!msix_present(dev)) {
        return;
    }
    msix_clear_all_vectors(dev);
    dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &=
	    ~dev->wmask[dev->msix_cap + MSIX_CONTROL_OFFSET];
    memset(dev->msix_table, 0, dev->msix_entries_nr * PCI_MSIX_ENTRY_SIZE);
    memset(dev->msix_pba, 0, QEMU_ALIGN_UP(dev->msix_entries_nr, 64) / 8);
    msix_mask_all(dev, dev->msix_entries_nr);
}

/* PCI spec suggests that devices make it possible for software to configure
 * less vectors than supported by the device, but does not specify a standard
 * mechanism for devices to do so.
 *
 * We support this by asking devices to declare vectors software is going to
 * actually use, and checking this on the notification path. Devices that
 * don't want to follow the spec suggestion can declare all vectors as used. */

/* Mark vector as used. */
int msix_vector_use(PCIDevice *dev, unsigned vector)
{
    if (vector >= dev->msix_entries_nr)
        return -EINVAL;
    dev->msix_entry_used[vector]++;
    return 0;
}

/* Mark vector as unused. */
void msix_vector_unuse(PCIDevice *dev, unsigned vector)
{
    if (vector >= dev->msix_entries_nr || !dev->msix_entry_used[vector]) {
        return;
    }
    if (--dev->msix_entry_used[vector]) {
        return;
    }
    msix_clr_pending(dev, vector);
}

void msix_unuse_all_vectors(PCIDevice *dev)
{
    if (!msix_present(dev)) {
        return;
    }
    msix_free_irq_entries(dev);
}

unsigned int msix_nr_vectors_allocated(const PCIDevice *dev)
{
    return dev->msix_entries_nr;
}

static int msix_set_notifier_for_vector(PCIDevice *dev, unsigned int vector)
{
    MSIMessage msg;

    if (msix_is_masked(dev, vector)) {
        return 0;
    }
    msg = msix_get_message(dev, vector);
    return dev->msix_vector_use_notifier(dev, vector, msg);
}

static void msix_unset_notifier_for_vector(PCIDevice *dev, unsigned int vector)
{
    if (msix_is_masked(dev, vector)) {
        return;
    }
    dev->msix_vector_release_notifier(dev, vector);
}

int msix_set_vector_notifiers(PCIDevice *dev,
                              MSIVectorUseNotifier use_notifier,
                              MSIVectorReleaseNotifier release_notifier,
                              MSIVectorPollNotifier poll_notifier)
{
    int vector, ret;

    assert(use_notifier && release_notifier);

    dev->msix_vector_use_notifier = use_notifier;
    dev->msix_vector_release_notifier = release_notifier;
    dev->msix_vector_poll_notifier = poll_notifier;

    if ((dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
        (MSIX_ENABLE_MASK | MSIX_MASKALL_MASK)) == MSIX_ENABLE_MASK) {
        for (vector = 0; vector < dev->msix_entries_nr; vector++) {
            ret = msix_set_notifier_for_vector(dev, vector);
            if (ret < 0) {
                goto undo;
            }
        }
    }
    if (dev->msix_vector_poll_notifier) {
        dev->msix_vector_poll_notifier(dev, 0, dev->msix_entries_nr);
    }
    return 0;

undo:
    while (--vector >= 0) {
        msix_unset_notifier_for_vector(dev, vector);
    }
    dev->msix_vector_use_notifier = NULL;
    dev->msix_vector_release_notifier = NULL;
    return ret;
}

void msix_unset_vector_notifiers(PCIDevice *dev)
{
    int vector;

    assert(dev->msix_vector_use_notifier &&
           dev->msix_vector_release_notifier);

    if ((dev->config[dev->msix_cap + MSIX_CONTROL_OFFSET] &
        (MSIX_ENABLE_MASK | MSIX_MASKALL_MASK)) == MSIX_ENABLE_MASK) {
        for (vector = 0; vector < dev->msix_entries_nr; vector++) {
            msix_unset_notifier_for_vector(dev, vector);
        }
    }
    dev->msix_vector_use_notifier = NULL;
    dev->msix_vector_release_notifier = NULL;
    dev->msix_vector_poll_notifier = NULL;
}
