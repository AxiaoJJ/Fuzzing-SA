/*
 *  ASPEED AST2400 Timer
 *
 *  Andrew Jeffery <andrew@aj.id.au>
 *
 *  Copyright (C) 2016 IBM Corp.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef ASPEED_TIMER_H
#define ASPEED_TIMER_H

#include "hw/ptimer.h"

#define ASPEED_TIMER(obj) \
    OBJECT_CHECK(AspeedTimerCtrlState, (obj), TYPE_ASPEED_TIMER);
#define TYPE_ASPEED_TIMER "aspeed.timer"
#define ASPEED_TIMER_NR_TIMERS 8

typedef struct AspeedTimer {
    qemu_irq irq;

    uint8_t id;

    /**
     * Track the line level as the ASPEED timers implement edge triggered
     * interrupts, signalling with both the rising and falling edge.
     */
    int32_t level;
    ptimer_state *timer;
    uint32_t reload;
    uint32_t match[2];
} AspeedTimer;

typedef struct AspeedTimerCtrlState {
    /*< private >*/
    SysBusDevice parent;

    /*< public >*/
    MemoryRegion iomem;

    uint32_t ctrl;
    uint32_t ctrl2;
    AspeedTimer timers[ASPEED_TIMER_NR_TIMERS];
} AspeedTimerCtrlState;

#endif /* ASPEED_TIMER_H */
