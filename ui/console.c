/*
 * QEMU graphical console
 *
 * Copyright (c) 2004 Fabrice Bellard
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
#include "qemu-common.h"
#include "ui/console.h"
#include "qemu/timer.h"
#include "qmp-commands.h"
#include "sysemu/char.h"

//#define DEBUG_CONSOLE
#define DEFAULT_BACKSCROLL 512
#define MAX_CONSOLES 12
#define CONSOLE_CURSOR_PERIOD 500

#define QEMU_RGBA(r, g, b, a) (((a) << 24) | ((r) << 16) | ((g) << 8) | (b))
#define QEMU_RGB(r, g, b) QEMU_RGBA(r, g, b, 0xff)

typedef struct TextAttributes {
    uint8_t fgcol:4;
    uint8_t bgcol:4;
    uint8_t bold:1;
    uint8_t uline:1;
    uint8_t blink:1;
    uint8_t invers:1;
    uint8_t unvisible:1;
} TextAttributes;

typedef struct TextCell {
    uint8_t ch;
    TextAttributes t_attrib;
} TextCell;

#define MAX_ESC_PARAMS 3

enum TTYState {
    TTY_STATE_NORM,
    TTY_STATE_ESC,
    TTY_STATE_CSI,
};

typedef struct QEMUFIFO {
    uint8_t *buf;
    int buf_size;
    int count, wptr, rptr;
} QEMUFIFO;

static int qemu_fifo_write(QEMUFIFO *f, const uint8_t *buf, int len1)
{
    int l, len;

    l = f->buf_size - f->count;
    if (len1 > l)
        len1 = l;
    len = len1;
    while (len > 0) {
        l = f->buf_size - f->wptr;
        if (l > len)
            l = len;
        memcpy(f->buf + f->wptr, buf, l);
        f->wptr += l;
        if (f->wptr >= f->buf_size)
            f->wptr = 0;
        buf += l;
        len -= l;
    }
    f->count += len1;
    return len1;
}

static int qemu_fifo_read(QEMUFIFO *f, uint8_t *buf, int len1)
{
    int l, len;

    if (len1 > f->count)
        len1 = f->count;
    len = len1;
    while (len > 0) {
        l = f->buf_size - f->rptr;
        if (l > len)
            l = len;
        memcpy(buf, f->buf + f->rptr, l);
        f->rptr += l;
        if (f->rptr >= f->buf_size)
            f->rptr = 0;
        buf += l;
        len -= l;
    }
    f->count -= len1;
    return len1;
}

typedef enum {
    GRAPHIC_CONSOLE,
    TEXT_CONSOLE,
    TEXT_CONSOLE_FIXED_SIZE
} console_type_t;

struct QemuConsole {
    int index;
    console_type_t console_type;
    DisplayState *ds;

    /* Graphic console state.  */
    vga_hw_update_ptr hw_update;
    vga_hw_invalidate_ptr hw_invalidate;
    vga_hw_screen_dump_ptr hw_screen_dump;
    vga_hw_text_update_ptr hw_text_update;
    void *hw;
    int g_width, g_height;

    /* Text console state */
    int width;
    int height;
    int total_height;
    int backscroll_height;
    int x, y;
    int x_saved, y_saved;
    int y_displayed;
    int y_base;
    TextAttributes t_attrib_default; /* default text attributes */
    TextAttributes t_attrib; /* currently active text attributes */
    TextCell *cells;
    int text_x[2], text_y[2], cursor_invalidate;
    int echo;
    bool cursor_visible_phase;
    QEMUTimer *cursor_timer;

    int update_x0;
    int update_y0;
    int update_x1;
    int update_y1;

    enum TTYState state;
    int esc_params[MAX_ESC_PARAMS];
    int nb_esc_params;

    CharDriverState *chr;
    /* fifo for key pressed */
    QEMUFIFO out_fifo;
    uint8_t out_fifo_buf[16];
    QEMUTimer *kbd_timer;
};

static DisplayState *display_state;
static QemuConsole *active_console;
static QemuConsole *consoles[MAX_CONSOLES];
static int nb_consoles = 0;

void vga_hw_update(void)
{
    if (active_console && active_console->hw_update)
        active_console->hw_update(active_console->hw);
}

void vga_hw_invalidate(void)
{
    if (active_console && active_console->hw_invalidate)
        active_console->hw_invalidate(active_console->hw);
}

void qmp_screendump(const char *filename, Error **errp)
{
    QemuConsole *previous_active_console;
    bool cswitch;

    previous_active_console = active_console;
    cswitch = previous_active_console && previous_active_console->index != 0;

    /* There is currently no way of specifying which screen we want to dump,
       so always dump the first one.  */
    if (cswitch) {
        console_select(0);
    }
    if (consoles[0] && consoles[0]->hw_screen_dump) {
        consoles[0]->hw_screen_dump(consoles[0]->hw, filename, cswitch, errp);
    } else {
        error_setg(errp, "device doesn't support screendump");
    }

    if (cswitch) {
        console_select(previous_active_console->index);
    }
}

void vga_hw_text_update(console_ch_t *chardata)
{
    if (active_console && active_console->hw_text_update)
        active_console->hw_text_update(active_console->hw, chardata);
}

static void vga_fill_rect(QemuConsole *con,
                          int posx, int posy, int width, int height,
                          uint32_t color)
{
    DisplaySurface *surface = qemu_console_surface(con);
    pixman_rectangle16_t rect = {
        .x = posx, .y = posy, .width = width, .height = height
    };
    pixman_color_t pcolor;

    pcolor = qemu_pixman_color(&surface->pf, color);
    pixman_image_fill_rectangles(PIXMAN_OP_SRC, surface->image,
                                 &pcolor, 1, &rect);
}

/* copy from (xs, ys) to (xd, yd) a rectangle of size (w, h) */
static void vga_bitblt(QemuConsole *con,
                       int xs, int ys, int xd, int yd, int w, int h)
{
    DisplaySurface *surface = qemu_console_surface(con);

    pixman_image_composite(PIXMAN_OP_SRC,
                           surface->image, NULL, surface->image,
                           xs, ys, 0, 0, xd, yd, w, h);
}

/***********************************************************/
/* basic char display */

#define FONT_HEIGHT 16
#define FONT_WIDTH 8

#include "vgafont.h"

#ifndef CONFIG_CURSES
enum color_names {
    COLOR_BLACK   = 0,
    COLOR_RED     = 1,
    COLOR_GREEN   = 2,
    COLOR_YELLOW  = 3,
    COLOR_BLUE    = 4,
    COLOR_MAGENTA = 5,
    COLOR_CYAN    = 6,
    COLOR_WHITE   = 7
};
#endif

static const uint32_t color_table_rgb[2][8] = {
    {   /* dark */
        QEMU_RGB(0x00, 0x00, 0x00),  /* black */
        QEMU_RGB(0xaa, 0x00, 0x00),  /* red */
        QEMU_RGB(0x00, 0xaa, 0x00),  /* green */
        QEMU_RGB(0xaa, 0xaa, 0x00),  /* yellow */
        QEMU_RGB(0x00, 0x00, 0xaa),  /* blue */
        QEMU_RGB(0xaa, 0x00, 0xaa),  /* magenta */
        QEMU_RGB(0x00, 0xaa, 0xaa),  /* cyan */
        QEMU_RGB(0xaa, 0xaa, 0xaa),  /* white */
    },
    {   /* bright */
        QEMU_RGB(0x00, 0x00, 0x00),  /* black */
        QEMU_RGB(0xff, 0x00, 0x00),  /* red */
        QEMU_RGB(0x00, 0xff, 0x00),  /* green */
        QEMU_RGB(0xff, 0xff, 0x00),  /* yellow */
        QEMU_RGB(0x00, 0x00, 0xff),  /* blue */
        QEMU_RGB(0xff, 0x00, 0xff),  /* magenta */
        QEMU_RGB(0x00, 0xff, 0xff),  /* cyan */
        QEMU_RGB(0xff, 0xff, 0xff),  /* white */
    }
};

#ifdef DEBUG_CONSOLE
static void console_print_text_attributes(TextAttributes *t_attrib, char ch)
{
    if (t_attrib->bold) {
        printf("b");
    } else {
        printf(" ");
    }
    if (t_attrib->uline) {
        printf("u");
    } else {
        printf(" ");
    }
    if (t_attrib->blink) {
        printf("l");
    } else {
        printf(" ");
    }
    if (t_attrib->invers) {
        printf("i");
    } else {
        printf(" ");
    }
    if (t_attrib->unvisible) {
        printf("n");
    } else {
        printf(" ");
    }

    printf(" fg: %d bg: %d ch:'%2X' '%c'\n", t_attrib->fgcol, t_attrib->bgcol, ch, ch);
}
#endif

static void vga_putcharxy(QemuConsole *s, int x, int y, int ch,
                          TextAttributes *t_attrib)
{
    static pixman_image_t *glyphs[256];
    DisplaySurface *surface = qemu_console_surface(s);
    unsigned int fgcol, bgcol;
    pixman_image_t *ifg, *ibg;
    pixman_color_t cfg, cbg;

    if (t_attrib->invers) {
        bgcol = color_table_rgb[t_attrib->bold][t_attrib->fgcol];
        fgcol = color_table_rgb[t_attrib->bold][t_attrib->bgcol];
    } else {
        fgcol = color_table_rgb[t_attrib->bold][t_attrib->fgcol];
        bgcol = color_table_rgb[t_attrib->bold][t_attrib->bgcol];
    }
    cfg = qemu_pixman_color(&surface->pf, fgcol);
    cbg = qemu_pixman_color(&surface->pf, bgcol);
    ifg = pixman_image_create_solid_fill(&cfg);
    ibg = pixman_image_create_solid_fill(&cbg);

    if (!glyphs[ch]) {
        glyphs[ch] = qemu_pixman_glyph_from_vgafont(FONT_HEIGHT, vgafont16, ch);
    }
    qemu_pixman_glyph_render(glyphs[ch], surface->image,
                             &cfg, &cbg, x, y, FONT_WIDTH, FONT_HEIGHT);
}

static void text_console_resize(QemuConsole *s)
{
    TextCell *cells, *c, *c1;
    int w1, x, y, last_width;

    last_width = s->width;
    s->width = s->g_width / FONT_WIDTH;
    s->height = s->g_height / FONT_HEIGHT;

    w1 = last_width;
    if (s->width < w1)
        w1 = s->width;

    cells = g_malloc(s->width * s->total_height * sizeof(TextCell));
    for(y = 0; y < s->total_height; y++) {
        c = &cells[y * s->width];
        if (w1 > 0) {
            c1 = &s->cells[y * last_width];
            for(x = 0; x < w1; x++) {
                *c++ = *c1++;
            }
        }
        for(x = w1; x < s->width; x++) {
            c->ch = ' ';
            c->t_attrib = s->t_attrib_default;
            c++;
        }
    }
    g_free(s->cells);
    s->cells = cells;
}

static inline void text_update_xy(QemuConsole *s, int x, int y)
{
    s->text_x[0] = MIN(s->text_x[0], x);
    s->text_x[1] = MAX(s->text_x[1], x);
    s->text_y[0] = MIN(s->text_y[0], y);
    s->text_y[1] = MAX(s->text_y[1], y);
}

static void invalidate_xy(QemuConsole *s, int x, int y)
{
    if (s->update_x0 > x * FONT_WIDTH)
        s->update_x0 = x * FONT_WIDTH;
    if (s->update_y0 > y * FONT_HEIGHT)
        s->update_y0 = y * FONT_HEIGHT;
    if (s->update_x1 < (x + 1) * FONT_WIDTH)
        s->update_x1 = (x + 1) * FONT_WIDTH;
    if (s->update_y1 < (y + 1) * FONT_HEIGHT)
        s->update_y1 = (y + 1) * FONT_HEIGHT;
}

static void update_xy(QemuConsole *s, int x, int y)
{
    TextCell *c;
    int y1, y2;

    if (s != active_console) {
        return;
    }

    if (s->ds->have_text) {
        text_update_xy(s, x, y);
    }

    if (s->ds->have_gfx) {
        y1 = (s->y_base + y) % s->total_height;
        y2 = y1 - s->y_displayed;
        if (y2 < 0)
            y2 += s->total_height;
        if (y2 < s->height) {
            c = &s->cells[y1 * s->width + x];
            vga_putcharxy(s, x, y2, c->ch,
                          &(c->t_attrib));
            invalidate_xy(s, x, y2);
        }
    }
}

static void console_show_cursor(QemuConsole *s, int show)
{
    TextCell *c;
    int y, y1;
    int x = s->x;

    if (s != active_console) {
        return;
    }

    if (s->ds->have_text) {
        s->cursor_invalidate = 1;
    }

    if (s->ds->have_gfx) {
        if (x >= s->width) {
            x = s->width - 1;
        }
        y1 = (s->y_base + s->y) % s->total_height;
        y = y1 - s->y_displayed;
        if (y < 0)
            y += s->total_height;
        if (y < s->height) {
            c = &s->cells[y1 * s->width + x];
            if (show && s->cursor_visible_phase) {
                TextAttributes t_attrib = s->t_attrib_default;
                t_attrib.invers = !(t_attrib.invers); /* invert fg and bg */
                vga_putcharxy(s, x, y, c->ch, &t_attrib);
            } else {
                vga_putcharxy(s, x, y, c->ch, &(c->t_attrib));
            }
            invalidate_xy(s, x, y);
        }
    }
}

static void console_refresh(QemuConsole *s)
{
    DisplaySurface *surface = qemu_console_surface(s);
    TextCell *c;
    int x, y, y1;

    if (s != active_console)
        return;

    if (s->ds->have_text) {
        s->text_x[0] = 0;
        s->text_y[0] = 0;
        s->text_x[1] = s->width - 1;
        s->text_y[1] = s->height - 1;
        s->cursor_invalidate = 1;
    }

    if (s->ds->have_gfx) {
        vga_fill_rect(s, 0, 0, surface_width(surface), surface_height(surface),
                      color_table_rgb[0][COLOR_BLACK]);
        y1 = s->y_displayed;
        for (y = 0; y < s->height; y++) {
            c = s->cells + y1 * s->width;
            for (x = 0; x < s->width; x++) {
                vga_putcharxy(s, x, y, c->ch,
                              &(c->t_attrib));
                c++;
            }
            if (++y1 == s->total_height) {
                y1 = 0;
            }
        }
        console_show_cursor(s, 1);
        dpy_gfx_update(s, 0, 0,
                       surface_width(surface), surface_height(surface));
    }
}

static void console_scroll(int ydelta)
{
    QemuConsole *s;
    int i, y1;

    s = active_console;
    if (!s || (s->console_type == GRAPHIC_CONSOLE))
        return;

    if (ydelta > 0) {
        for(i = 0; i < ydelta; i++) {
            if (s->y_displayed == s->y_base)
                break;
            if (++s->y_displayed == s->total_height)
                s->y_displayed = 0;
        }
    } else {
        ydelta = -ydelta;
        i = s->backscroll_height;
        if (i > s->total_height - s->height)
            i = s->total_height - s->height;
        y1 = s->y_base - i;
        if (y1 < 0)
            y1 += s->total_height;
        for(i = 0; i < ydelta; i++) {
            if (s->y_displayed == y1)
                break;
            if (--s->y_displayed < 0)
                s->y_displayed = s->total_height - 1;
        }
    }
    console_refresh(s);
}

static void console_put_lf(QemuConsole *s)
{
    TextCell *c;
    int x, y1;

    s->y++;
    if (s->y >= s->height) {
        s->y = s->height - 1;

        if (s->y_displayed == s->y_base) {
            if (++s->y_displayed == s->total_height)
                s->y_displayed = 0;
        }
        if (++s->y_base == s->total_height)
            s->y_base = 0;
        if (s->backscroll_height < s->total_height)
            s->backscroll_height++;
        y1 = (s->y_base + s->height - 1) % s->total_height;
        c = &s->cells[y1 * s->width];
        for(x = 0; x < s->width; x++) {
            c->ch = ' ';
            c->t_attrib = s->t_attrib_default;
            c++;
        }
        if (s == active_console && s->y_displayed == s->y_base) {
            if (s->ds->have_text) {
                s->text_x[0] = 0;
                s->text_y[0] = 0;
                s->text_x[1] = s->width - 1;
                s->text_y[1] = s->height - 1;
            }

            if (s->ds->have_gfx) {
                vga_bitblt(s, 0, FONT_HEIGHT, 0, 0,
                           s->width * FONT_WIDTH,
                           (s->height - 1) * FONT_HEIGHT);
                vga_fill_rect(s, 0, (s->height - 1) * FONT_HEIGHT,
                              s->width * FONT_WIDTH, FONT_HEIGHT,
                              color_table_rgb[0][s->t_attrib_default.bgcol]);
                s->update_x0 = 0;
                s->update_y0 = 0;
                s->update_x1 = s->width * FONT_WIDTH;
                s->update_y1 = s->height * FONT_HEIGHT;
            }
        }
    }
}

/* Set console attributes depending on the current escape codes.
 * NOTE: I know this code is not very efficient (checking every color for it
 * self) but it is more readable and better maintainable.
 */
static void console_handle_escape(QemuConsole *s)
{
    int i;

    for (i=0; i<s->nb_esc_params; i++) {
        switch (s->esc_params[i]) {
            case 0: /* reset all console attributes to default */
                s->t_attrib = s->t_attrib_default;
                break;
            case 1:
                s->t_attrib.bold = 1;
                break;
            case 4:
                s->t_attrib.uline = 1;
                break;
            case 5:
                s->t_attrib.blink = 1;
                break;
            case 7:
                s->t_attrib.invers = 1;
                break;
            case 8:
                s->t_attrib.unvisible = 1;
                break;
            case 22:
                s->t_attrib.bold = 0;
                break;
            case 24:
                s->t_attrib.uline = 0;
                break;
            case 25:
                s->t_attrib.blink = 0;
                break;
            case 27:
                s->t_attrib.invers = 0;
                break;
            case 28:
                s->t_attrib.unvisible = 0;
                break;
            /* set foreground color */
            case 30:
                s->t_attrib.fgcol=COLOR_BLACK;
                break;
            case 31:
                s->t_attrib.fgcol=COLOR_RED;
                break;
            case 32:
                s->t_attrib.fgcol=COLOR_GREEN;
                break;
            case 33:
                s->t_attrib.fgcol=COLOR_YELLOW;
                break;
            case 34:
                s->t_attrib.fgcol=COLOR_BLUE;
                break;
            case 35:
                s->t_attrib.fgcol=COLOR_MAGENTA;
                break;
            case 36:
                s->t_attrib.fgcol=COLOR_CYAN;
                break;
            case 37:
                s->t_attrib.fgcol=COLOR_WHITE;
                break;
            /* set background color */
            case 40:
                s->t_attrib.bgcol=COLOR_BLACK;
                break;
            case 41:
                s->t_attrib.bgcol=COLOR_RED;
                break;
            case 42:
                s->t_attrib.bgcol=COLOR_GREEN;
                break;
            case 43:
                s->t_attrib.bgcol=COLOR_YELLOW;
                break;
            case 44:
                s->t_attrib.bgcol=COLOR_BLUE;
                break;
            case 45:
                s->t_attrib.bgcol=COLOR_MAGENTA;
                break;
            case 46:
                s->t_attrib.bgcol=COLOR_CYAN;
                break;
            case 47:
                s->t_attrib.bgcol=COLOR_WHITE;
                break;
        }
    }
}

static void console_clear_xy(QemuConsole *s, int x, int y)
{
    int y1 = (s->y_base + y) % s->total_height;
    TextCell *c = &s->cells[y1 * s->width + x];
    c->ch = ' ';
    c->t_attrib = s->t_attrib_default;
    update_xy(s, x, y);
}

/* set cursor, checking bounds */
static void set_cursor(QemuConsole *s, int x, int y)
{
    if (x < 0) {
        x = 0;
    }
    if (y < 0) {
        y = 0;
    }
    if (y >= s->height) {
        y = s->height - 1;
    }
    if (x >= s->width) {
        x = s->width - 1;
    }

    s->x = x;
    s->y = y;
}

static void console_putchar(QemuConsole *s, int ch)
{
    TextCell *c;
    int y1, i;
    int x, y;

    switch(s->state) {
    case TTY_STATE_NORM:
        switch(ch) {
        case '\r':  /* carriage return */
            s->x = 0;
            break;
        case '\n':  /* newline */
            console_put_lf(s);
            break;
        case '\b':  /* backspace */
            if (s->x > 0)
                s->x--;
            break;
        case '\t':  /* tabspace */
            if (s->x + (8 - (s->x % 8)) > s->width) {
                s->x = 0;
                console_put_lf(s);
            } else {
                s->x = s->x + (8 - (s->x % 8));
            }
            break;
        case '\a':  /* alert aka. bell */
            /* TODO: has to be implemented */
            break;
        case 14:
            /* SI (shift in), character set 0 (ignored) */
            break;
        case 15:
            /* SO (shift out), character set 1 (ignored) */
            break;
        case 27:    /* esc (introducing an escape sequence) */
            s->state = TTY_STATE_ESC;
            break;
        default:
            if (s->x >= s->width) {
                /* line wrap */
                s->x = 0;
                console_put_lf(s);
            }
            y1 = (s->y_base + s->y) % s->total_height;
            c = &s->cells[y1 * s->width + s->x];
            c->ch = ch;
            c->t_attrib = s->t_attrib;
            update_xy(s, s->x, s->y);
            s->x++;
            break;
        }
        break;
    case TTY_STATE_ESC: /* check if it is a terminal escape sequence */
        if (ch == '[') {
            for(i=0;i<MAX_ESC_PARAMS;i++)
                s->esc_params[i] = 0;
            s->nb_esc_params = 0;
            s->state = TTY_STATE_CSI;
        } else {
            s->state = TTY_STATE_NORM;
        }
        break;
    case TTY_STATE_CSI: /* handle escape sequence parameters */
        if (ch >= '0' && ch <= '9') {
            if (s->nb_esc_params < MAX_ESC_PARAMS) {
                int *param = &s->esc_params[s->nb_esc_params];
                int digit = (ch - '0');

                *param = (*param <= (INT_MAX - digit) / 10) ?
                         *param * 10 + digit : INT_MAX;
            }
        } else {
            if (s->nb_esc_params < MAX_ESC_PARAMS)
                s->nb_esc_params++;
            if (ch == ';')
                break;
#ifdef DEBUG_CONSOLE
            fprintf(stderr, "escape sequence CSI%d;%d%c, %d parameters\n",
                    s->esc_params[0], s->esc_params[1], ch, s->nb_esc_params);
#endif
            s->state = TTY_STATE_NORM;
            switch(ch) {
            case 'A':
                /* move cursor up */
                if (s->esc_params[0] == 0) {
                    s->esc_params[0] = 1;
                }
                set_cursor(s, s->x, s->y - s->esc_params[0]);
                break;
            case 'B':
                /* move cursor down */
                if (s->esc_params[0] == 0) {
                    s->esc_params[0] = 1;
                }
                set_cursor(s, s->x, s->y + s->esc_params[0]);
                break;
            case 'C':
                /* move cursor right */
                if (s->esc_params[0] == 0) {
                    s->esc_params[0] = 1;
                }
                set_cursor(s, s->x + s->esc_params[0], s->y);
                break;
            case 'D':
                /* move cursor left */
                if (s->esc_params[0] == 0) {
                    s->esc_params[0] = 1;
                }
                set_cursor(s, s->x - s->esc_params[0], s->y);
                break;
            case 'G':
                /* move cursor to column */
                set_cursor(s, s->esc_params[0] - 1, s->y);
                break;
            case 'f':
            case 'H':
                /* move cursor to row, column */
                set_cursor(s, s->esc_params[1] - 1, s->esc_params[0] - 1);
                break;
            case 'J':
                switch (s->esc_params[0]) {
                case 0:
                    /* clear to end of screen */
                    for (y = s->y; y < s->height; y++) {
                        for (x = 0; x < s->width; x++) {
                            if (y == s->y && x < s->x) {
                                continue;
                            }
                            console_clear_xy(s, x, y);
                        }
                    }
                    break;
                case 1:
                    /* clear from beginning of screen */
                    for (y = 0; y <= s->y; y++) {
                        for (x = 0; x < s->width; x++) {
                            if (y == s->y && x > s->x) {
                                break;
                            }
                            console_clear_xy(s, x, y);
                        }
                    }
                    break;
                case 2:
                    /* clear entire screen */
                    for (y = 0; y <= s->height; y++) {
                        for (x = 0; x < s->width; x++) {
                            console_clear_xy(s, x, y);
                        }
                    }
                    break;
                }
                break;
            case 'K':
                switch (s->esc_params[0]) {
                case 0:
                    /* clear to eol */
                    for(x = s->x; x < s->width; x++) {
                        console_clear_xy(s, x, s->y);
                    }
                    break;
                case 1:
                    /* clear from beginning of line */
                    for (x = 0; x <= s->x; x++) {
                        console_clear_xy(s, x, s->y);
                    }
                    break;
                case 2:
                    /* clear entire line */
                    for(x = 0; x < s->width; x++) {
                        console_clear_xy(s, x, s->y);
                    }
                    break;
                }
                break;
            case 'm':
                console_handle_escape(s);
                break;
            case 'n':
                /* report cursor position */
                /* TODO: send ESC[row;colR */
                break;
            case 's':
                /* save cursor position */
                s->x_saved = s->x;
                s->y_saved = s->y;
                break;
            case 'u':
                /* restore cursor position */
                s->x = s->x_saved;
                s->y = s->y_saved;
                break;
            default:
#ifdef DEBUG_CONSOLE
                fprintf(stderr, "unhandled escape character '%c'\n", ch);
#endif
                break;
            }
            break;
        }
    }
}

void console_select(unsigned int index)
{
    DisplaySurface *surface;
    QemuConsole *s;

    if (index >= MAX_CONSOLES)
        return;
    if (active_console) {
        surface = qemu_console_surface(active_console);
        active_console->g_width = surface_width(surface);
        active_console->g_height = surface_height(surface);
    }
    s = consoles[index];
    if (s) {
        DisplayState *ds = s->ds;

        if (active_console && active_console->cursor_timer) {
            qemu_del_timer(active_console->cursor_timer);
        }
        active_console = s;
        if (ds->have_gfx) {
            surface = qemu_create_displaysurface(s->g_width, s->g_height);
            dpy_gfx_replace_surface(s, surface);
        }
        if (ds->have_text) {
            dpy_text_resize(s, s->width, s->height);
        }
        if (s->cursor_timer) {
            qemu_mod_timer(s->cursor_timer,
                   qemu_get_clock_ms(rt_clock) + CONSOLE_CURSOR_PERIOD / 2);
        }
        vga_hw_invalidate();
    }
}

static int console_puts(CharDriverState *chr, const uint8_t *buf, int len)
{
    QemuConsole *s = chr->opaque;
    int i;

    s->update_x0 = s->width * FONT_WIDTH;
    s->update_y0 = s->height * FONT_HEIGHT;
    s->update_x1 = 0;
    s->update_y1 = 0;
    console_show_cursor(s, 0);
    for(i = 0; i < len; i++) {
        console_putchar(s, buf[i]);
    }
    console_show_cursor(s, 1);
    if (s->ds->have_gfx && s->update_x0 < s->update_x1) {
        dpy_gfx_update(s, s->update_x0, s->update_y0,
                       s->update_x1 - s->update_x0,
                       s->update_y1 - s->update_y0);
    }
    return len;
}

static void kbd_send_chars(void *opaque)
{
    QemuConsole *s = opaque;
    int len;
    uint8_t buf[16];

    len = qemu_chr_be_can_write(s->chr);
    if (len > s->out_fifo.count)
        len = s->out_fifo.count;
    if (len > 0) {
        if (len > sizeof(buf))
            len = sizeof(buf);
        qemu_fifo_read(&s->out_fifo, buf, len);
        qemu_chr_be_write(s->chr, buf, len);
    }
    /* characters are pending: we send them a bit later (XXX:
       horrible, should change char device API) */
    if (s->out_fifo.count > 0) {
        qemu_mod_timer(s->kbd_timer, qemu_get_clock_ms(rt_clock) + 1);
    }
}

/* called when an ascii key is pressed */
void kbd_put_keysym(int keysym)
{
    QemuConsole *s;
    uint8_t buf[16], *q;
    int c;

    s = active_console;
    if (!s || (s->console_type == GRAPHIC_CONSOLE))
        return;

    switch(keysym) {
    case QEMU_KEY_CTRL_UP:
        console_scroll(-1);
        break;
    case QEMU_KEY_CTRL_DOWN:
        console_scroll(1);
        break;
    case QEMU_KEY_CTRL_PAGEUP:
        console_scroll(-10);
        break;
    case QEMU_KEY_CTRL_PAGEDOWN:
        console_scroll(10);
        break;
    default:
        /* convert the QEMU keysym to VT100 key string */
        q = buf;
        if (keysym >= 0xe100 && keysym <= 0xe11f) {
            *q++ = '\033';
            *q++ = '[';
            c = keysym - 0xe100;
            if (c >= 10)
                *q++ = '0' + (c / 10);
            *q++ = '0' + (c % 10);
            *q++ = '~';
        } else if (keysym >= 0xe120 && keysym <= 0xe17f) {
            *q++ = '\033';
            *q++ = '[';
            *q++ = keysym & 0xff;
        } else if (s->echo && (keysym == '\r' || keysym == '\n')) {
            console_puts(s->chr, (const uint8_t *) "\r", 1);
            *q++ = '\n';
        } else {
            *q++ = keysym;
        }
        if (s->echo) {
            console_puts(s->chr, buf, q - buf);
        }
        if (s->chr->chr_read) {
            qemu_fifo_write(&s->out_fifo, buf, q - buf);
            kbd_send_chars(s);
        }
        break;
    }
}

static void text_console_invalidate(void *opaque)
{
    QemuConsole *s = (QemuConsole *) opaque;
    DisplaySurface *surface = qemu_console_surface(s);

    if (s->ds->have_text && s->console_type == TEXT_CONSOLE) {
        s->g_width = surface_width(surface);
        s->g_height = surface_height(surface);
        text_console_resize(s);
    }
    console_refresh(s);
}

static void text_console_update(void *opaque, console_ch_t *chardata)
{
    QemuConsole *s = (QemuConsole *) opaque;
    int i, j, src;

    if (s->text_x[0] <= s->text_x[1]) {
        src = (s->y_base + s->text_y[0]) * s->width;
        chardata += s->text_y[0] * s->width;
        for (i = s->text_y[0]; i <= s->text_y[1]; i ++)
            for (j = 0; j < s->width; j ++, src ++)
                console_write_ch(chardata ++, s->cells[src].ch |
                                (s->cells[src].t_attrib.fgcol << 12) |
                                (s->cells[src].t_attrib.bgcol << 8) |
                                (s->cells[src].t_attrib.bold << 21));
        dpy_text_update(s, s->text_x[0], s->text_y[0],
                        s->text_x[1] - s->text_x[0], i - s->text_y[0]);
        s->text_x[0] = s->width;
        s->text_y[0] = s->height;
        s->text_x[1] = 0;
        s->text_y[1] = 0;
    }
    if (s->cursor_invalidate) {
        dpy_text_cursor(s, s->x, s->y);
        s->cursor_invalidate = 0;
    }
}

static QemuConsole *new_console(DisplayState *ds, console_type_t console_type)
{
    QemuConsole *s;
    int i;

    if (nb_consoles >= MAX_CONSOLES)
        return NULL;
    s = g_malloc0(sizeof(QemuConsole));
    if (!active_console || ((active_console->console_type != GRAPHIC_CONSOLE) &&
        (console_type == GRAPHIC_CONSOLE))) {
        active_console = s;
    }
    s->ds = ds;
    s->console_type = console_type;
    if (console_type != GRAPHIC_CONSOLE) {
        s->index = nb_consoles;
        consoles[nb_consoles++] = s;
    } else {
        /* HACK: Put graphical consoles before text consoles.  */
        for (i = nb_consoles; i > 0; i--) {
            if (consoles[i - 1]->console_type == GRAPHIC_CONSOLE)
                break;
            consoles[i] = consoles[i - 1];
            consoles[i]->index = i;
        }
        s->index = i;
        consoles[i] = s;
        nb_consoles++;
    }
    return s;
}

static void qemu_alloc_display(DisplaySurface *surface, int width, int height,
                               int linesize, PixelFormat pf, int newflags)
{
    surface->pf = pf;

    qemu_pixman_image_unref(surface->image);
    surface->image = NULL;

    surface->format = qemu_pixman_get_format(&pf);
    assert(surface->format != 0);
    surface->image = pixman_image_create_bits(surface->format,
                                              width, height,
                                              NULL, linesize);
    assert(surface->image != NULL);

    surface->flags = newflags | QEMU_ALLOCATED_FLAG;
#ifdef HOST_WORDS_BIGENDIAN
    surface->flags |= QEMU_BIG_ENDIAN_FLAG;
#endif
}

DisplaySurface *qemu_create_displaysurface(int width, int height)
{
    DisplaySurface *surface = g_new0(DisplaySurface, 1);
    int linesize = width * 4;

    trace_displaysurface_create(surface, width, height);
    qemu_alloc_display(surface, width, height, linesize,
                       qemu_default_pixelformat(32), 0);
    return surface;
}

DisplaySurface *qemu_create_displaysurface_from(int width, int height, int bpp,
                                                int linesize, uint8_t *data,
                                                bool byteswap)
{
    DisplaySurface *surface = g_new0(DisplaySurface, 1);

    trace_displaysurface_create_from(surface, width, height, bpp, byteswap);
    if (byteswap) {
        surface->pf = qemu_different_endianness_pixelformat(bpp);
    } else {
        surface->pf = qemu_default_pixelformat(bpp);
    }

    surface->format = qemu_pixman_get_format(&surface->pf);
    assert(surface->format != 0);
    surface->image = pixman_image_create_bits(surface->format,
                                              width, height,
                                              (void *)data, linesize);
    assert(surface->image != NULL);

#ifdef HOST_WORDS_BIGENDIAN
    surface->flags = QEMU_BIG_ENDIAN_FLAG;
#endif

    return surface;
}

void qemu_free_displaysurface(DisplaySurface *surface)
{
    if (surface == NULL) {
        return;
    }
    trace_displaysurface_free(surface);
    qemu_pixman_image_unref(surface->image);
    g_free(surface);
}

void register_displaychangelistener(DisplayState *ds,
                                    DisplayChangeListener *dcl)
{
    trace_displaychangelistener_register(dcl, dcl->ops->dpy_name);
    dcl->ds = ds;
    QLIST_INSERT_HEAD(&ds->listeners, dcl, next);
    gui_setup_refresh(ds);
    if (dcl->ops->dpy_gfx_switch) {
        dcl->ops->dpy_gfx_switch(dcl, ds->surface);
    }
}

void unregister_displaychangelistener(DisplayChangeListener *dcl)
{
    DisplayState *ds = dcl->ds;
    trace_displaychangelistener_unregister(dcl, dcl->ops->dpy_name);
    QLIST_REMOVE(dcl, next);
    gui_setup_refresh(ds);
}

void dpy_gfx_update(QemuConsole *con, int x, int y, int w, int h)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    int width = pixman_image_get_width(s->surface->image);
    int height = pixman_image_get_height(s->surface->image);

    x = MAX(x, 0);
    y = MAX(y, 0);
    x = MIN(x, width);
    y = MIN(y, height);
    w = MIN(w, width - x);
    h = MIN(h, height - y);

    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_gfx_update) {
            dcl->ops->dpy_gfx_update(dcl, x, y, w, h);
        }
    }
}

void dpy_gfx_replace_surface(QemuConsole *con,
                             DisplaySurface *surface)
{
    DisplayState *s = con->ds;
    DisplaySurface *old_surface = s->surface;
    struct DisplayChangeListener *dcl;

    s->surface = surface;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_gfx_switch) {
            dcl->ops->dpy_gfx_switch(dcl, surface);
        }
    }
    qemu_free_displaysurface(old_surface);
}

void dpy_refresh(DisplayState *s)
{
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_refresh) {
            dcl->ops->dpy_refresh(dcl);
        }
    }
}

void dpy_gfx_copy(QemuConsole *con, int src_x, int src_y,
                  int dst_x, int dst_y, int w, int h)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_gfx_copy) {
            dcl->ops->dpy_gfx_copy(dcl, src_x, src_y, dst_x, dst_y, w, h);
        } else { /* TODO */
            dcl->ops->dpy_gfx_update(dcl, dst_x, dst_y, w, h);
        }
    }
}

void dpy_text_cursor(QemuConsole *con, int x, int y)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_text_cursor) {
            dcl->ops->dpy_text_cursor(dcl, x, y);
        }
    }
}

void dpy_text_update(QemuConsole *con, int x, int y, int w, int h)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_text_update) {
            dcl->ops->dpy_text_update(dcl, x, y, w, h);
        }
    }
}

void dpy_text_resize(QemuConsole *con, int w, int h)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_text_resize) {
            dcl->ops->dpy_text_resize(dcl, w, h);
        }
    }
}

void dpy_mouse_set(QemuConsole *con, int x, int y, int on)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_mouse_set) {
            dcl->ops->dpy_mouse_set(dcl, x, y, on);
        }
    }
}

void dpy_cursor_define(QemuConsole *con, QEMUCursor *cursor)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_cursor_define) {
            dcl->ops->dpy_cursor_define(dcl, cursor);
        }
    }
}

bool dpy_cursor_define_supported(QemuConsole *con)
{
    DisplayState *s = con->ds;
    struct DisplayChangeListener *dcl;
    QLIST_FOREACH(dcl, &s->listeners, next) {
        if (dcl->ops->dpy_cursor_define) {
            return true;
        }
    }
    return false;
}

static void dumb_display_init(void)
{
    DisplayState *ds = g_malloc0(sizeof(DisplayState));
    int width = 640;
    int height = 480;

    if (is_fixedsize_console()) {
        width = active_console->g_width;
        height = active_console->g_height;
    }
    ds->surface = qemu_create_displaysurface(width, height);

    register_displaystate(ds);
}

/***********************************************************/
/* register display */

void register_displaystate(DisplayState *ds)
{
    DisplayState **s;
    s = &display_state;
    while (*s != NULL)
        s = &(*s)->next;
    ds->next = NULL;
    *s = ds;
}

DisplayState *get_displaystate(void)
{
    if (!display_state) {
        dumb_display_init ();
    }
    return display_state;
}

QemuConsole *graphic_console_init(vga_hw_update_ptr update,
                                  vga_hw_invalidate_ptr invalidate,
                                  vga_hw_screen_dump_ptr screen_dump,
                                  vga_hw_text_update_ptr text_update,
                                  void *opaque)
{
    QemuConsole *s;
    DisplayState *ds;

    ds = (DisplayState *) g_malloc0(sizeof(DisplayState));
    s = new_console(ds, GRAPHIC_CONSOLE);
    s->hw_update = update;
    s->hw_invalidate = invalidate;
    s->hw_screen_dump = screen_dump;
    s->hw_text_update = text_update;
    s->hw = opaque;

    ds->surface = qemu_create_displaysurface(640, 480);

    register_displaystate(ds);
    return s;
}

int is_graphic_console(void)
{
    return active_console && active_console->console_type == GRAPHIC_CONSOLE;
}

int is_fixedsize_console(void)
{
    return active_console && active_console->console_type != TEXT_CONSOLE;
}

static void text_console_set_echo(CharDriverState *chr, bool echo)
{
    QemuConsole *s = chr->opaque;

    s->echo = echo;
}

static void text_console_update_cursor(void *opaque)
{
    QemuConsole *s = opaque;

    s->cursor_visible_phase = !s->cursor_visible_phase;
    vga_hw_invalidate();
    qemu_mod_timer(s->cursor_timer,
                   qemu_get_clock_ms(rt_clock) + CONSOLE_CURSOR_PERIOD / 2);
}

static void text_console_do_init(CharDriverState *chr, DisplayState *ds)
{
    QemuConsole *s;

    s = chr->opaque;

    chr->chr_write = console_puts;

    s->out_fifo.buf = s->out_fifo_buf;
    s->out_fifo.buf_size = sizeof(s->out_fifo_buf);
    s->kbd_timer = qemu_new_timer_ms(rt_clock, kbd_send_chars, s);
    s->ds = ds;

    s->y_displayed = 0;
    s->y_base = 0;
    s->total_height = DEFAULT_BACKSCROLL;
    s->x = 0;
    s->y = 0;
    if (s->console_type == TEXT_CONSOLE) {
        s->g_width = surface_width(s->ds->surface);
        s->g_height = surface_height(s->ds->surface);
    }

    s->cursor_timer =
        qemu_new_timer_ms(rt_clock, text_console_update_cursor, s);

    s->hw_invalidate = text_console_invalidate;
    s->hw_text_update = text_console_update;
    s->hw = s;

    /* Set text attribute defaults */
    s->t_attrib_default.bold = 0;
    s->t_attrib_default.uline = 0;
    s->t_attrib_default.blink = 0;
    s->t_attrib_default.invers = 0;
    s->t_attrib_default.unvisible = 0;
    s->t_attrib_default.fgcol = COLOR_WHITE;
    s->t_attrib_default.bgcol = COLOR_BLACK;
    /* set current text attributes to default */
    s->t_attrib = s->t_attrib_default;
    text_console_resize(s);

    if (chr->label) {
        char msg[128];
        int len;

        s->t_attrib.bgcol = COLOR_BLUE;
        len = snprintf(msg, sizeof(msg), "%s console\r\n", chr->label);
        console_puts(chr, (uint8_t*)msg, len);
        s->t_attrib = s->t_attrib_default;
    }

    qemu_chr_be_generic_open(chr);
    if (chr->init)
        chr->init(chr);
}

static CharDriverState *text_console_init(ChardevVC *vc)
{
    CharDriverState *chr;
    QemuConsole *s;
    unsigned width = 0;
    unsigned height = 0;

    chr = g_malloc0(sizeof(CharDriverState));

    if (vc->has_width) {
        width = vc->width;
    } else if (vc->has_cols) {
        width = vc->cols * FONT_WIDTH;
    }

    if (vc->has_height) {
        height = vc->height;
    } else if (vc->has_rows) {
        height = vc->rows * FONT_HEIGHT;
    }

    if (width == 0 || height == 0) {
        s = new_console(NULL, TEXT_CONSOLE);
    } else {
        s = new_console(NULL, TEXT_CONSOLE_FIXED_SIZE);
    }

    if (!s) {
        g_free(chr);
        return NULL;
    }

    s->chr = chr;
    s->g_width = width;
    s->g_height = height;
    chr->opaque = s;
    chr->chr_set_echo = text_console_set_echo;
    return chr;
}

static VcHandler *vc_handler = text_console_init;

CharDriverState *vc_init(ChardevVC *vc)
{
    return vc_handler(vc);
}

void register_vc_handler(VcHandler *handler)
{
    vc_handler = handler;
}

void text_consoles_set_display(DisplayState *ds)
{
    int i;

    for (i = 0; i < nb_consoles; i++) {
        if (consoles[i]->console_type != GRAPHIC_CONSOLE) {
            text_console_do_init(consoles[i]->chr, ds);
        }
    }
}

void qemu_console_resize(QemuConsole *s, int width, int height)
{
    s->g_width = width;
    s->g_height = height;
    if (is_graphic_console()) {
        DisplaySurface *surface;
        surface = qemu_create_displaysurface(width, height);
        dpy_gfx_replace_surface(s, surface);
    }
}

void qemu_console_copy(QemuConsole *con, int src_x, int src_y,
                       int dst_x, int dst_y, int w, int h)
{
    if (is_graphic_console()) {
        dpy_gfx_copy(con, src_x, src_y, dst_x, dst_y, w, h);
    }
}

DisplaySurface *qemu_console_surface(QemuConsole *console)
{
    return console->ds->surface;
}

DisplayState *qemu_console_displaystate(QemuConsole *console)
{
    return console->ds;
}

PixelFormat qemu_different_endianness_pixelformat(int bpp)
{
    PixelFormat pf;

    memset(&pf, 0x00, sizeof(PixelFormat));

    pf.bits_per_pixel = bpp;
    pf.bytes_per_pixel = DIV_ROUND_UP(bpp, 8);
    pf.depth = bpp == 32 ? 24 : bpp;

    switch (bpp) {
        case 24:
            pf.rmask = 0x000000FF;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x00FF0000;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 0;
            pf.gshift = 8;
            pf.bshift = 16;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            break;
        case 32:
            pf.rmask = 0x0000FF00;
            pf.gmask = 0x00FF0000;
            pf.bmask = 0xFF000000;
            pf.amask = 0x00000000;
            pf.amax = 255;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.ashift = 0;
            pf.rshift = 8;
            pf.gshift = 16;
            pf.bshift = 24;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            pf.abits = 8;
            break;
        default:
            break;
    }
    return pf;
}

PixelFormat qemu_default_pixelformat(int bpp)
{
    PixelFormat pf;

    memset(&pf, 0x00, sizeof(PixelFormat));

    pf.bits_per_pixel = bpp;
    pf.bytes_per_pixel = DIV_ROUND_UP(bpp, 8);
    pf.depth = bpp == 32 ? 24 : bpp;

    switch (bpp) {
        case 15:
            pf.bits_per_pixel = 16;
            pf.rmask = 0x00007c00;
            pf.gmask = 0x000003E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 31;
            pf.bmax = 31;
            pf.rshift = 10;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 5;
            pf.bbits = 5;
            break;
        case 16:
            pf.rmask = 0x0000F800;
            pf.gmask = 0x000007E0;
            pf.bmask = 0x0000001F;
            pf.rmax = 31;
            pf.gmax = 63;
            pf.bmax = 31;
            pf.rshift = 11;
            pf.gshift = 5;
            pf.bshift = 0;
            pf.rbits = 5;
            pf.gbits = 6;
            pf.bbits = 5;
            break;
        case 24:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            break;
        case 32:
            pf.rmask = 0x00FF0000;
            pf.gmask = 0x0000FF00;
            pf.bmask = 0x000000FF;
            pf.rmax = 255;
            pf.gmax = 255;
            pf.bmax = 255;
            pf.rshift = 16;
            pf.gshift = 8;
            pf.bshift = 0;
            pf.rbits = 8;
            pf.gbits = 8;
            pf.bbits = 8;
            break;
        default:
            break;
    }
    return pf;
}

static void qemu_chr_parse_vc(QemuOpts *opts, ChardevBackend *backend,
                              Error **errp)
{
    int val;

    backend->vc = g_new0(ChardevVC, 1);

    val = qemu_opt_get_number(opts, "width", 0);
    if (val != 0) {
        backend->vc->has_width = true;
        backend->vc->width = val;
    }

    val = qemu_opt_get_number(opts, "height", 0);
    if (val != 0) {
        backend->vc->has_height = true;
        backend->vc->height = val;
    }

    val = qemu_opt_get_number(opts, "cols", 0);
    if (val != 0) {
        backend->vc->has_cols = true;
        backend->vc->cols = val;
    }

    val = qemu_opt_get_number(opts, "rows", 0);
    if (val != 0) {
        backend->vc->has_rows = true;
        backend->vc->rows = val;
    }
}

static void register_types(void)
{
    register_char_driver_qapi("vc", CHARDEV_BACKEND_KIND_VC,
                              qemu_chr_parse_vc);
}

type_init(register_types);
