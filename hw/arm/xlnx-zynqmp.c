/*
 * Xilinx Zynq MPSoC emulation
 *
 * Copyright (C) 2015 Xilinx Inc
 * Written by Peter Crosthwaite <peter.crosthwaite@xilinx.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 */

#include "hw/arm/xlnx-zynqmp.h"
#include "exec/address-spaces.h"

#define GIC_NUM_SPI_INTR 160

#define GIC_BASE_ADDR       0xf9000000
#define GIC_DIST_ADDR       0xf9010000
#define GIC_CPU_ADDR        0xf9020000

typedef struct XlnxZynqMPGICRegion {
    int region_index;
    uint32_t address;
} XlnxZynqMPGICRegion;

static const XlnxZynqMPGICRegion xlnx_zynqmp_gic_regions[] = {
    { .region_index = 0, .address = GIC_DIST_ADDR, },
    { .region_index = 1, .address = GIC_CPU_ADDR,  },
};

static void xlnx_zynqmp_init(Object *obj)
{
    XlnxZynqMPState *s = XLNX_ZYNQMP(obj);
    int i;

    for (i = 0; i < XLNX_ZYNQMP_NUM_CPUS; i++) {
        object_initialize(&s->cpu[i], sizeof(s->cpu[i]),
                          "cortex-a53-" TYPE_ARM_CPU);
        object_property_add_child(obj, "cpu[*]", OBJECT(&s->cpu[i]),
                                  &error_abort);
    }

    object_initialize(&s->gic, sizeof(s->gic), TYPE_ARM_GIC);
    qdev_set_parent_bus(DEVICE(&s->gic), sysbus_get_default());
}

static void xlnx_zynqmp_realize(DeviceState *dev, Error **errp)
{
    XlnxZynqMPState *s = XLNX_ZYNQMP(dev);
    MemoryRegion *system_memory = get_system_memory();
    uint8_t i;
    Error *err = NULL;

    qdev_prop_set_uint32(DEVICE(&s->gic), "num-irq", GIC_NUM_SPI_INTR + 32);
    qdev_prop_set_uint32(DEVICE(&s->gic), "revision", 2);
    qdev_prop_set_uint32(DEVICE(&s->gic), "num-cpu", XLNX_ZYNQMP_NUM_CPUS);
    object_property_set_bool(OBJECT(&s->gic), true, "realized", &err);
    if (err) {
        error_propagate((errp), (err));
        return;
    }
    assert(ARRAY_SIZE(xlnx_zynqmp_gic_regions) == XLNX_ZYNQMP_GIC_REGIONS);
    for (i = 0; i < XLNX_ZYNQMP_GIC_REGIONS; i++) {
        SysBusDevice *gic = SYS_BUS_DEVICE(&s->gic);
        const XlnxZynqMPGICRegion *r = &xlnx_zynqmp_gic_regions[i];
        MemoryRegion *mr = sysbus_mmio_get_region(gic, r->region_index);
        uint32_t addr = r->address;
        int j;

        sysbus_mmio_map(gic, r->region_index, addr);

        for (j = 0; j < XLNX_ZYNQMP_GIC_ALIASES; j++) {
            MemoryRegion *alias = &s->gic_mr[i][j];

            addr += XLNX_ZYNQMP_GIC_REGION_SIZE;
            memory_region_init_alias(alias, OBJECT(s), "zynqmp-gic-alias", mr,
                                     0, XLNX_ZYNQMP_GIC_REGION_SIZE);
            memory_region_add_subregion(system_memory, addr, alias);
        }
    }

    for (i = 0; i < XLNX_ZYNQMP_NUM_CPUS; i++) {
        object_property_set_int(OBJECT(&s->cpu[i]), QEMU_PSCI_CONDUIT_SMC,
                                "psci-conduit", &error_abort);
        if (i > 0) {
            /* Secondary CPUs start in PSCI powered-down state */
            object_property_set_bool(OBJECT(&s->cpu[i]), true,
                                     "start-powered-off", &error_abort);
        }

        object_property_set_int(OBJECT(&s->cpu[i]), GIC_BASE_ADDR,
                                "reset-cbar", &err);
        if (err) {
            error_propagate((errp), (err));
            return;
        }

        object_property_set_bool(OBJECT(&s->cpu[i]), true, "realized", &err);
        if (err) {
            error_propagate((errp), (err));
            return;
        }

        sysbus_connect_irq(SYS_BUS_DEVICE(&s->gic), i,
                           qdev_get_gpio_in(DEVICE(&s->cpu[i]), ARM_CPU_IRQ));
    }
}

static void xlnx_zynqmp_class_init(ObjectClass *oc, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);

    dc->realize = xlnx_zynqmp_realize;
}

static const TypeInfo xlnx_zynqmp_type_info = {
    .name = TYPE_XLNX_ZYNQMP,
    .parent = TYPE_DEVICE,
    .instance_size = sizeof(XlnxZynqMPState),
    .instance_init = xlnx_zynqmp_init,
    .class_init = xlnx_zynqmp_class_init,
};

static void xlnx_zynqmp_register_types(void)
{
    type_register_static(&xlnx_zynqmp_type_info);
}

type_init(xlnx_zynqmp_register_types)
