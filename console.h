#ifndef CONSOLE_H
#define CONSOLE_H

#include "qemu-char.h"
#include "qdict.h"
#include "notify.h"
#include "monitor.h"
#include "trace.h"
#include "qapi-types.h"
#include "error.h"

/* keyboard/mouse support */

#define MOUSE_EVENT_LBUTTON 0x01
#define MOUSE_EVENT_RBUTTON 0x02
#define MOUSE_EVENT_MBUTTON 0x04

/* identical to the ps/2 keyboard bits */
#define QEMU_SCROLL_LOCK_LED (1 << 0)
#define QEMU_NUM_LOCK_LED    (1 << 1)
#define QEMU_CAPS_LOCK_LED   (1 << 2)

/* in ms */
#define GUI_REFRESH_INTERVAL 30

typedef void QEMUPutKBDEvent(void *opaque, int keycode);
typedef void QEMUPutLEDEvent(void *opaque, int ledstate);
typedef void QEMUPutMouseEvent(void *opaque, int dx, int dy, int dz, int buttons_state);

typedef struct QEMUPutMouseEntry {
    QEMUPutMouseEvent *qemu_put_mouse_event;
    void *qemu_put_mouse_event_opaque;
    int qemu_put_mouse_event_absolute;
    char *qemu_put_mouse_event_name;

    int index;

    /* used internally by qemu for handling mice */
    QTAILQ_ENTRY(QEMUPutMouseEntry) node;
} QEMUPutMouseEntry;

typedef struct QEMUPutLEDEntry {
    QEMUPutLEDEvent *put_led;
    void *opaque;
    QTAILQ_ENTRY(QEMUPutLEDEntry) next;
} QEMUPutLEDEntry;

void qemu_add_kbd_event_handler(QEMUPutKBDEvent *func, void *opaque);
void qemu_remove_kbd_event_handler(void);
QEMUPutMouseEntry *qemu_add_mouse_event_handler(QEMUPutMouseEvent *func,
                                                void *opaque, int absolute,
                                                const char *name);
void qemu_remove_mouse_event_handler(QEMUPutMouseEntry *entry);
void qemu_activate_mouse_event_handler(QEMUPutMouseEntry *entry);

QEMUPutLEDEntry *qemu_add_led_event_handler(QEMUPutLEDEvent *func, void *opaque);
void qemu_remove_led_event_handler(QEMUPutLEDEntry *entry);

void kbd_put_keycode(int keycode);
void kbd_put_ledstate(int ledstate);
void kbd_mouse_event(int dx, int dy, int dz, int buttons_state);

/* Does the current mouse generate absolute events */
int kbd_mouse_is_absolute(void);
void qemu_add_mouse_mode_change_notifier(Notifier *notify);
void qemu_remove_mouse_mode_change_notifier(Notifier *notify);

/* Of all the mice, is there one that generates absolute events */
int kbd_mouse_has_absolute(void);

struct MouseTransformInfo {
    /* Touchscreen resolution */
    int x;
    int y;
    /* Calibration values as used/generated by tslib */
    int a[7];
};

void do_mouse_set(Monitor *mon, const QDict *qdict);

/* keysym is a unicode code except for special keys (see QEMU_KEY_xxx
   constants) */
#define QEMU_KEY_ESC1(c) ((c) | 0xe100)
#define QEMU_KEY_BACKSPACE  0x007f
#define QEMU_KEY_UP         QEMU_KEY_ESC1('A')
#define QEMU_KEY_DOWN       QEMU_KEY_ESC1('B')
#define QEMU_KEY_RIGHT      QEMU_KEY_ESC1('C')
#define QEMU_KEY_LEFT       QEMU_KEY_ESC1('D')
#define QEMU_KEY_HOME       QEMU_KEY_ESC1(1)
#define QEMU_KEY_END        QEMU_KEY_ESC1(4)
#define QEMU_KEY_PAGEUP     QEMU_KEY_ESC1(5)
#define QEMU_KEY_PAGEDOWN   QEMU_KEY_ESC1(6)
#define QEMU_KEY_DELETE     QEMU_KEY_ESC1(3)

#define QEMU_KEY_CTRL_UP         0xe400
#define QEMU_KEY_CTRL_DOWN       0xe401
#define QEMU_KEY_CTRL_LEFT       0xe402
#define QEMU_KEY_CTRL_RIGHT      0xe403
#define QEMU_KEY_CTRL_HOME       0xe404
#define QEMU_KEY_CTRL_END        0xe405
#define QEMU_KEY_CTRL_PAGEUP     0xe406
#define QEMU_KEY_CTRL_PAGEDOWN   0xe407

void kbd_put_keysym(int keysym);

/* consoles */

#define QEMU_BIG_ENDIAN_FLAG    0x01
#define QEMU_ALLOCATED_FLAG     0x02
#define QEMU_REALPIXELS_FLAG    0x04

struct PixelFormat {
    uint8_t bits_per_pixel;
    uint8_t bytes_per_pixel;
    uint8_t depth; /* color depth in bits */
    uint32_t rmask, gmask, bmask, amask;
    uint8_t rshift, gshift, bshift, ashift;
    uint8_t rmax, gmax, bmax, amax;
    uint8_t rbits, gbits, bbits, abits;
};

struct DisplaySurface {
    uint8_t flags;
    int width;
    int height;
    int linesize;        /* bytes per line */
    uint8_t *data;

    struct PixelFormat pf;
};

/* cursor data format is 32bit RGBA */
typedef struct QEMUCursor {
    int                 width, height;
    int                 hot_x, hot_y;
    int                 refcount;
    uint32_t            data[];
} QEMUCursor;

QEMUCursor *cursor_alloc(int width, int height);
void cursor_get(QEMUCursor *c);
void cursor_put(QEMUCursor *c);
QEMUCursor *cursor_builtin_hidden(void);
QEMUCursor *cursor_builtin_left_ptr(void);
void cursor_print_ascii_art(QEMUCursor *c, const char *prefix);
int cursor_get_mono_bpl(QEMUCursor *c);
void cursor_set_mono(QEMUCursor *c,
                     uint32_t foreground, uint32_t background, uint8_t *image,
                     int transparent, uint8_t *mask);
void cursor_get_mono_image(QEMUCursor *c, int foreground, uint8_t *mask);
void cursor_get_mono_mask(QEMUCursor *c, int transparent, uint8_t *mask);

struct DisplayChangeListener {
    int idle;
    uint64_t gui_timer_interval;

    void (*dpy_update)(struct DisplayState *s, int x, int y, int w, int h);
    void (*dpy_resize)(struct DisplayState *s);
    void (*dpy_setdata)(struct DisplayState *s);
    void (*dpy_refresh)(struct DisplayState *s);
    void (*dpy_copy)(struct DisplayState *s, int src_x, int src_y,
                     int dst_x, int dst_y, int w, int h);
    void (*dpy_fill)(struct DisplayState *s, int x, int y,
                     int w, int h, uint32_t c);
    void (*dpy_text_cursor)(struct DisplayState *s, int x, int y);

    struct DisplayChangeListener *next;
};

struct DisplayAllocator {
    DisplaySurface* (*create_displaysurface)(int width, int height);
    DisplaySurface* (*resize_displaysurface)(DisplaySurface *surface, int width, int height);
    void (*free_displaysurface)(DisplaySurface *surface);
};

struct DisplayState {
    struct DisplaySurface *surface;
    void *opaque;
    struct QEMUTimer *gui_timer;

    struct DisplayAllocator* allocator;
    struct DisplayChangeListener* listeners;

    void (*mouse_set)(int x, int y, int on);
    void (*cursor_define)(QEMUCursor *cursor);

    struct DisplayState *next;
};

void register_displaystate(DisplayState *ds);
DisplayState *get_displaystate(void);
DisplaySurface* qemu_create_displaysurface_from(int width, int height, int bpp,
                                                int linesize, uint8_t *data);
void qemu_alloc_display(DisplaySurface *surface, int width, int height,
                        int linesize, PixelFormat pf, int newflags);
PixelFormat qemu_different_endianness_pixelformat(int bpp);
PixelFormat qemu_default_pixelformat(int bpp);

DisplayAllocator *register_displayallocator(DisplayState *ds, DisplayAllocator *da);

static inline DisplaySurface* qemu_create_displaysurface(DisplayState *ds, int width, int height)
{
    return ds->allocator->create_displaysurface(width, height);    
}

static inline DisplaySurface* qemu_resize_displaysurface(DisplayState *ds, int width, int height)
{
    trace_displaysurface_resize(ds, ds->surface, width, height);
    return ds->allocator->resize_displaysurface(ds->surface, width, height);
}

static inline void qemu_free_displaysurface(DisplayState *ds)
{
    trace_displaysurface_free(ds, ds->surface);
    ds->allocator->free_displaysurface(ds->surface);
}

static inline int is_surface_bgr(DisplaySurface *surface)
{
    if (surface->pf.bits_per_pixel == 32 && surface->pf.rshift == 0)
        return 1;
    else
        return 0;
}

static inline int is_buffer_shared(DisplaySurface *surface)
{
    return (!(surface->flags & QEMU_ALLOCATED_FLAG) &&
            !(surface->flags & QEMU_REALPIXELS_FLAG));
}

static inline void register_displaychangelistener(DisplayState *ds, DisplayChangeListener *dcl)
{
    dcl->next = ds->listeners;
    ds->listeners = dcl;
}

static inline void dpy_update(DisplayState *s, int x, int y, int w, int h)
{
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        dcl->dpy_update(s, x, y, w, h);
        dcl = dcl->next;
    }
}

static inline void dpy_resize(DisplayState *s)
{
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        dcl->dpy_resize(s);
        dcl = dcl->next;
    }
}

static inline void dpy_setdata(DisplayState *s)
{
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_setdata) dcl->dpy_setdata(s);
        dcl = dcl->next;
    }
}

static inline void dpy_refresh(DisplayState *s)
{
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_refresh) dcl->dpy_refresh(s);
        dcl = dcl->next;
    }
}

static inline void dpy_copy(struct DisplayState *s, int src_x, int src_y,
                             int dst_x, int dst_y, int w, int h) {
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_copy)
            dcl->dpy_copy(s, src_x, src_y, dst_x, dst_y, w, h);
        else /* TODO */
            dcl->dpy_update(s, dst_x, dst_y, w, h);
        dcl = dcl->next;
    }
}

static inline void dpy_fill(struct DisplayState *s, int x, int y,
                             int w, int h, uint32_t c) {
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_fill) dcl->dpy_fill(s, x, y, w, h, c);
        dcl = dcl->next;
    }
}

static inline void dpy_cursor(struct DisplayState *s, int x, int y) {
    struct DisplayChangeListener *dcl = s->listeners;
    while (dcl != NULL) {
        if (dcl->dpy_text_cursor) dcl->dpy_text_cursor(s, x, y);
        dcl = dcl->next;
    }
}

static inline int ds_get_linesize(DisplayState *ds)
{
    return ds->surface->linesize;
}

static inline uint8_t* ds_get_data(DisplayState *ds)
{
    return ds->surface->data;
}

static inline int ds_get_width(DisplayState *ds)
{
    return ds->surface->width;
}

static inline int ds_get_height(DisplayState *ds)
{
    return ds->surface->height;
}

static inline int ds_get_bits_per_pixel(DisplayState *ds)
{
    return ds->surface->pf.bits_per_pixel;
}

static inline int ds_get_bytes_per_pixel(DisplayState *ds)
{
    return ds->surface->pf.bytes_per_pixel;
}

#ifdef CONFIG_CURSES
#include <curses.h>
typedef chtype console_ch_t;
#else
typedef unsigned long console_ch_t;
#endif
static inline void console_write_ch(console_ch_t *dest, uint32_t ch)
{
    if (!(ch & 0xff))
        ch |= ' ';
    *dest = ch;
}

typedef void (*vga_hw_update_ptr)(void *);
typedef void (*vga_hw_invalidate_ptr)(void *);
typedef void (*vga_hw_screen_dump_ptr)(void *, const char *, bool cswitch,
                                       Error **errp);
typedef void (*vga_hw_text_update_ptr)(void *, console_ch_t *);

DisplayState *graphic_console_init(vga_hw_update_ptr update,
                                   vga_hw_invalidate_ptr invalidate,
                                   vga_hw_screen_dump_ptr screen_dump,
                                   vga_hw_text_update_ptr text_update,
                                   void *opaque);

void vga_hw_update(void);
void vga_hw_invalidate(void);
void vga_hw_text_update(console_ch_t *chardata);

int is_graphic_console(void);
int is_fixedsize_console(void);
CharDriverState *text_console_init(QemuOpts *opts);
void text_consoles_set_display(DisplayState *ds);
void console_select(unsigned int index);
void console_color_init(DisplayState *ds);
void qemu_console_resize(DisplayState *ds, int width, int height);
void qemu_console_copy(DisplayState *ds, int src_x, int src_y,
                       int dst_x, int dst_y, int w, int h);

/* sdl.c */
void sdl_display_init(DisplayState *ds, int full_screen, int no_frame);

/* cocoa.m */
void cocoa_display_init(DisplayState *ds, int full_screen);

/* vnc.c */
void vnc_display_init(DisplayState *ds);
void vnc_display_open(DisplayState *ds, const char *display, Error **errp);
void vnc_display_add_client(DisplayState *ds, int csock, int skipauth);
char *vnc_display_local_addr(DisplayState *ds);
#ifdef CONFIG_VNC
int vnc_display_password(DisplayState *ds, const char *password);
int vnc_display_pw_expire(DisplayState *ds, time_t expires);
#else
static inline int vnc_display_password(DisplayState *ds, const char *password)
{
    return -ENODEV;
}
static inline int vnc_display_pw_expire(DisplayState *ds, time_t expires)
{
    return -ENODEV;
};
#endif

/* curses.c */
void curses_display_init(DisplayState *ds, int full_screen);

/* input.c */
int index_from_key(const char *key);
int index_from_keycode(int code);

#endif
