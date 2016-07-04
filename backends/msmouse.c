/*
 * QEMU Microsoft serial mouse emulation
 *
 * Copyright (c) 2008 Lubomir Rintel
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include "qemu/osdep.h"
#include "qemu-common.h"
#include "sysemu/char.h"
#include "ui/console.h"

#define MSMOUSE_LO6(n) ((n) & 0x3f)
#define MSMOUSE_HI2(n) (((n) & 0xc0) >> 6)

typedef struct {
    CharDriverState *chr;
    QEMUPutMouseEntry *entry;
    uint8_t outbuf[32];
    int outlen;
} MouseState;

static void msmouse_chr_accept_input(CharDriverState *chr)
{
    MouseState *mouse = chr->opaque;
    int len;

    len = qemu_chr_be_can_write(chr);
    if (len > mouse->outlen) {
        len = mouse->outlen;
    }
    if (!len) {
        return;
    }

    qemu_chr_be_write(chr, mouse->outbuf, len);
    mouse->outlen -= len;
    if (mouse->outlen) {
        memmove(mouse->outbuf, mouse->outbuf + len, mouse->outlen);
    }
}

static void msmouse_event(void *opaque,
                          int dx, int dy, int dz, int buttons_state)
{
    CharDriverState *chr = (CharDriverState *)opaque;
    MouseState *mouse = chr->opaque;
    unsigned char bytes[4] = { 0x40, 0x00, 0x00, 0x00 };

    /* Movement deltas */
    bytes[0] |= (MSMOUSE_HI2(dy) << 2) | MSMOUSE_HI2(dx);
    bytes[1] |= MSMOUSE_LO6(dx);
    bytes[2] |= MSMOUSE_LO6(dy);

    /* Buttons */
    bytes[0] |= (buttons_state & 0x01 ? 0x20 : 0x00);
    bytes[0] |= (buttons_state & 0x02 ? 0x10 : 0x00);
    bytes[3] |= (buttons_state & 0x04 ? 0x20 : 0x00);

    if (mouse->outlen <= sizeof(mouse->outbuf) - 4) {
        /* We always send the packet of, so that we do not have to keep track
           of previous state of the middle button. This can potentially confuse
           some very old drivers for two button mice though. */
        memcpy(mouse->outbuf + mouse->outlen, bytes, 4);
        mouse->outlen += 4;
    } else {
        /* queue full -> drop event */
    }

    msmouse_chr_accept_input(chr);
}

static int msmouse_chr_write (struct CharDriverState *s, const uint8_t *buf, int len)
{
    /* Ignore writes to mouse port */
    return len;
}

static void msmouse_chr_close (struct CharDriverState *chr)
{
    MouseState *mouse = chr->opaque;

    qemu_remove_mouse_event_handler(mouse->entry);
    g_free(mouse);
    g_free(chr);
}

static CharDriverState *qemu_chr_open_msmouse(const char *id,
                                              ChardevBackend *backend,
                                              ChardevReturn *ret,
                                              Error **errp)
{
    ChardevCommon *common = backend->u.msmouse.data;
    MouseState *mouse;
    CharDriverState *chr;

    chr = qemu_chr_alloc(common, errp);
    chr->chr_write = msmouse_chr_write;
    chr->chr_close = msmouse_chr_close;
    chr->chr_accept_input = msmouse_chr_accept_input;
    chr->explicit_be_open = true;

    mouse = g_new0(MouseState, 1);
    mouse->entry = qemu_add_mouse_event_handler(msmouse_event, chr, 0,
                                                "QEMU Microsoft Mouse");

    mouse->chr = chr;
    chr->opaque = mouse;

    return chr;
}

static void register_types(void)
{
    register_char_driver("msmouse", CHARDEV_BACKEND_KIND_MSMOUSE, NULL,
                         qemu_chr_open_msmouse);
}

type_init(register_types);
