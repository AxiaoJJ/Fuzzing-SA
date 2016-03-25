/*
 * Inter-Thread Communication Unit emulation.
 *
 * Copyright (c) 2016 Imagination Technologies
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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/hw.h"
#include "hw/sysbus.h"
#include "sysemu/sysemu.h"
#include "hw/misc/mips_itu.h"

#define ITC_TAG_ADDRSPACE_SZ (ITC_ADDRESSMAP_NUM * 8)
/* Initialize as 4kB area to fit all 32 cells with default 128B grain.
   Storage may be resized by the software. */
#define ITC_STORAGE_ADDRSPACE_SZ 0x1000

#define ITC_FIFO_NUM_MAX 16
#define ITC_SEMAPH_NUM_MAX 16
#define ITC_AM1_NUMENTRIES_OFS 20

#define ITC_AM0_BASE_ADDRESS_MASK 0xFFFFFC00ULL
#define ITC_AM0_EN_MASK 0x1

#define ITC_AM1_ADDR_MASK_MASK 0x1FC00
#define ITC_AM1_ENTRY_GRAIN_MASK 0x7

MemoryRegion *mips_itu_get_tag_region(MIPSITUState *itu)
{
    return &itu->tag_io;
}

static uint64_t itc_tag_read(void *opaque, hwaddr addr, unsigned size)
{
    MIPSITUState *tag = (MIPSITUState *)opaque;
    uint64_t index = addr >> 3;
    uint64_t ret = 0;

    switch (index) {
    case 0 ... ITC_ADDRESSMAP_NUM:
        ret = tag->ITCAddressMap[index];
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "Read 0x%" PRIx64 "\n", addr);
        break;
    }

    return ret;
}

static void itc_reconfigure(MIPSITUState *tag)
{
    uint64_t *am = &tag->ITCAddressMap[0];
    MemoryRegion *mr = &tag->storage_io;
    hwaddr address = am[0] & ITC_AM0_BASE_ADDRESS_MASK;
    uint64_t size = (1 << 10) + (am[1] & ITC_AM1_ADDR_MASK_MASK);
    bool is_enabled = (am[0] & ITC_AM0_EN_MASK) != 0;

    memory_region_transaction_begin();
    if (!(size & (size - 1))) {
        memory_region_set_size(mr, size);
    }
    memory_region_set_address(mr, address);
    memory_region_set_enabled(mr, is_enabled);
    memory_region_transaction_commit();
}

static void itc_tag_write(void *opaque, hwaddr addr,
                          uint64_t data, unsigned size)
{
    MIPSITUState *tag = (MIPSITUState *)opaque;
    uint64_t *am = &tag->ITCAddressMap[0];
    uint64_t am_old, mask;
    uint64_t index = addr >> 3;

    switch (index) {
    case 0:
        mask = ITC_AM0_BASE_ADDRESS_MASK | ITC_AM0_EN_MASK;
        break;
    case 1:
        mask = ITC_AM1_ADDR_MASK_MASK | ITC_AM1_ENTRY_GRAIN_MASK;
        break;
    default:
        qemu_log_mask(LOG_GUEST_ERROR, "Bad write 0x%" PRIx64 "\n", addr);
        return;
    }

    am_old = am[index];
    am[index] = (data & mask) | (am_old & ~mask);
    if (am_old != am[index]) {
        itc_reconfigure(tag);
    }
}

static const MemoryRegionOps itc_tag_ops = {
    .read = itc_tag_read,
    .write = itc_tag_write,
    .impl = {
        .max_access_size = 8,
    },
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static inline uint32_t get_num_cells(MIPSITUState *s)
{
    return s->num_fifo + s->num_semaphores;
}

static const MemoryRegionOps itc_storage_ops = {
    .endianness = DEVICE_NATIVE_ENDIAN,
};

static void itc_reset_cells(MIPSITUState *s)
{
    int i;

    memset(s->cell, 0, get_num_cells(s) * sizeof(s->cell[0]));

    for (i = 0; i < s->num_fifo; i++) {
        s->cell[i].tag.E = 1;
        s->cell[i].tag.FIFO = 1;
        s->cell[i].tag.FIFODepth = ITC_CELL_DEPTH_SHIFT;
    }
}

static void mips_itu_init(Object *obj)
{
    SysBusDevice *sbd = SYS_BUS_DEVICE(obj);
    MIPSITUState *s = MIPS_ITU(obj);

    memory_region_init_io(&s->storage_io, OBJECT(s), &itc_storage_ops, s,
                          "mips-itc-storage", ITC_STORAGE_ADDRSPACE_SZ);
    sysbus_init_mmio(sbd, &s->storage_io);

    memory_region_init_io(&s->tag_io, OBJECT(s), &itc_tag_ops, s,
                          "mips-itc-tag", ITC_TAG_ADDRSPACE_SZ);
}

static void mips_itu_realize(DeviceState *dev, Error **errp)
{
    MIPSITUState *s = MIPS_ITU(dev);

    if (s->num_fifo > ITC_FIFO_NUM_MAX) {
        error_setg(errp, "Exceed maximum number of FIFO cells: %d",
                   s->num_fifo);
        return;
    }
    if (s->num_semaphores > ITC_SEMAPH_NUM_MAX) {
        error_setg(errp, "Exceed maximum number of Semaphore cells: %d",
                   s->num_semaphores);
        return;
    }

    s->cell = g_new(ITCStorageCell, get_num_cells(s));
}

static void mips_itu_reset(DeviceState *dev)
{
    MIPSITUState *s = MIPS_ITU(dev);

    s->ITCAddressMap[0] = 0;
    s->ITCAddressMap[1] =
        ((ITC_STORAGE_ADDRSPACE_SZ - 1) & ITC_AM1_ADDR_MASK_MASK) |
        (get_num_cells(s) << ITC_AM1_NUMENTRIES_OFS);
    itc_reconfigure(s);

    itc_reset_cells(s);
}

static Property mips_itu_properties[] = {
    DEFINE_PROP_INT32("num-fifo", MIPSITUState, num_fifo,
                      ITC_FIFO_NUM_MAX),
    DEFINE_PROP_INT32("num-semaphores", MIPSITUState, num_semaphores,
                      ITC_SEMAPH_NUM_MAX),
    DEFINE_PROP_END_OF_LIST(),
};

static void mips_itu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);

    dc->props = mips_itu_properties;
    dc->realize = mips_itu_realize;
    dc->reset = mips_itu_reset;
}

static const TypeInfo mips_itu_info = {
    .name          = TYPE_MIPS_ITU,
    .parent        = TYPE_SYS_BUS_DEVICE,
    .instance_size = sizeof(MIPSITUState),
    .instance_init = mips_itu_init,
    .class_init    = mips_itu_class_init,
};

static void mips_itu_register_types(void)
{
    type_register_static(&mips_itu_info);
}

type_init(mips_itu_register_types)
