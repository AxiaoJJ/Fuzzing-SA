/*
 * LM32 gdb server stub
 *
 * Copyright (c) 2003-2005 Fabrice Bellard
 * Copyright (c) 2013 SUSE LINUX Products GmbH
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
#include "hw/lm32/lm32_pic.h"

static int cpu_gdb_read_register(CPULM32State *env, uint8_t *mem_buf, int n)
{
    if (n < 32) {
        GET_REG32(env->regs[n]);
    } else {
        switch (n) {
        case 32:
            GET_REG32(env->pc);
        /* FIXME: put in right exception ID */
        case 33:
            GET_REG32(0);
        case 34:
            GET_REG32(env->eba);
        case 35:
            GET_REG32(env->deba);
        case 36:
            GET_REG32(env->ie);
        case 37:
            GET_REG32(lm32_pic_get_im(env->pic_state));
        case 38:
            GET_REG32(lm32_pic_get_ip(env->pic_state));
        }
    }
    return 0;
}

static int cpu_gdb_write_register(CPULM32State *env, uint8_t *mem_buf, int n)
{
    LM32CPU *cpu = lm32_env_get_cpu(env);
    CPUClass *cc = CPU_GET_CLASS(cpu);
    uint32_t tmp;

    if (n > cc->gdb_num_core_regs) {
        return 0;
    }

    tmp = ldl_p(mem_buf);

    if (n < 32) {
        env->regs[n] = tmp;
    } else {
        switch (n) {
        case 32:
            env->pc = tmp;
            break;
        case 34:
            env->eba = tmp;
            break;
        case 35:
            env->deba = tmp;
            break;
        case 36:
            env->ie = tmp;
            break;
        case 37:
            lm32_pic_set_im(env->pic_state, tmp);
            break;
        case 38:
            lm32_pic_set_ip(env->pic_state, tmp);
            break;
        }
    }
    return 4;
}
