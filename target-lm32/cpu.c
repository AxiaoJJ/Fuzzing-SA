/*
 * QEMU LatticeMico32 CPU
 *
 * Copyright (c) 2012 SUSE LINUX Products GmbH
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see
 * <http://www.gnu.org/licenses/lgpl-2.1.html>
 */

#include "cpu-qom.h"
#include "qemu-common.h"


/* CPUClass::reset() */
static void lm32_cpu_reset(CPUState *s)
{
    LM32CPU *cpu = LM32_CPU(s);
    LM32CPUClass *lcc = LM32_CPU_GET_CLASS(cpu);
    CPULM32State *env = &cpu->env;

    lcc->parent_reset(s);

    cpu_state_reset(env);
}

static void lm32_cpu_class_init(ObjectClass *oc, void *data)
{
    LM32CPUClass *lcc = LM32_CPU_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);

    lcc->parent_reset = cc->reset;
    cc->reset = lm32_cpu_reset;
}

static const TypeInfo lm32_cpu_type_info = {
    .name = TYPE_LM32_CPU,
    .parent = TYPE_CPU,
    .instance_size = sizeof(LM32CPU),
    .abstract = false,
    .class_size = sizeof(LM32CPUClass),
    .class_init = lm32_cpu_class_init,
};

static void lm32_cpu_register_types(void)
{
    type_register_static(&lm32_cpu_type_info);
}

type_init(lm32_cpu_register_types)
