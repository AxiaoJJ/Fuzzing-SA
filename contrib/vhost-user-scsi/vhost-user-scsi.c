/*
 * vhost-user-scsi sample application
 *
 * Copyright (c) 2016 Nutanix Inc. All rights reserved.
 *
 * Author:
 *  Felipe Franciosi <felipe@nutanix.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 only.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "contrib/libvhost-user/libvhost-user.h"
#include "standard-headers/linux/virtio_scsi.h"
#include "iscsi/iscsi.h"
#include "iscsi/scsi-lowlevel.h"

#include <glib.h>

/* #define VUS_DEBUG 1 */

/** Log helpers **/

#define PPRE                                                          \
    struct timespec ts;                                               \
    char   timebuf[64];                                               \
    struct tm tm;                                                     \
    (void)clock_gettime(CLOCK_REALTIME, &ts);                         \
    (void)strftime(timebuf, 64, "%Y%m%d %T", gmtime_r(&ts.tv_sec, &tm))

#define PEXT(lvl, msg, ...) do {                                      \
    PPRE;                                                             \
    fprintf(stderr, "%s.%06ld " lvl ": %s:%s():%d: " msg "\n",        \
            timebuf, ts.tv_nsec / 1000,                               \
            __FILE__, __func__, __LINE__, ## __VA_ARGS__);            \
} while (0)

#define PNOR(lvl, msg, ...) do {                                      \
    PPRE;                                                             \
    fprintf(stderr, "%s.%06ld " lvl ": " msg "\n",                    \
            timebuf, ts.tv_nsec / 1000, ## __VA_ARGS__);              \
} while (0)

#ifdef VUS_DEBUG
#define PDBG(msg, ...) PEXT("DBG", msg, ## __VA_ARGS__)
#define PERR(msg, ...) PEXT("ERR", msg, ## __VA_ARGS__)
#define PLOG(msg, ...) PEXT("LOG", msg, ## __VA_ARGS__)
#else
#define PDBG(msg, ...) { }
#define PERR(msg, ...) PNOR("ERR", msg, ## __VA_ARGS__)
#define PLOG(msg, ...) PNOR("LOG", msg, ## __VA_ARGS__)
#endif

/** vhost-user-scsi specific definitions **/

#define VUS_ISCSI_INITIATOR "iqn.2016-11.com.nutanix:vhost-user-scsi"

typedef struct VusIscsiLun {
    struct iscsi_context *iscsi_ctx;
    int iscsi_lun;
} VusIscsiLun;

typedef struct VusDev {
    VuDev vu_dev;
    int server_sock;
    GMainLoop *loop;
    GTree *fdmap;   /* fd -> gsource context id */
    VusIscsiLun lun;
} VusDev;

/** glib event loop integration for libvhost-user and misc callbacks **/

QEMU_BUILD_BUG_ON((int)G_IO_IN != (int)VU_WATCH_IN);
QEMU_BUILD_BUG_ON((int)G_IO_OUT != (int)VU_WATCH_OUT);
QEMU_BUILD_BUG_ON((int)G_IO_PRI != (int)VU_WATCH_PRI);
QEMU_BUILD_BUG_ON((int)G_IO_ERR != (int)VU_WATCH_ERR);
QEMU_BUILD_BUG_ON((int)G_IO_HUP != (int)VU_WATCH_HUP);

typedef struct vus_gsrc {
    GSource parent;
    VusDev *vdev_scsi;
    GPollFD gfd;
    vu_watch_cb vu_cb;
} vus_gsrc_t;

static gint vus_fdmap_compare(gconstpointer a, gconstpointer b)
{
    return (b > a) - (b < a);
}

static gboolean vus_gsrc_prepare(GSource *src, gint *timeout)
{
    assert(timeout);

    *timeout = -1;
    return FALSE;
}

static gboolean vus_gsrc_check(GSource *src)
{
    vus_gsrc_t *vus_src = (vus_gsrc_t *)src;

    assert(vus_src);

    return vus_src->gfd.revents & vus_src->gfd.events;
}

static gboolean vus_gsrc_dispatch(GSource *src, GSourceFunc cb, gpointer data)
{
    VusDev *vdev_scsi;
    vus_gsrc_t *vus_src = (vus_gsrc_t *)src;

    assert(vus_src);
    assert(!(vus_src->vu_cb && cb));

    vdev_scsi = vus_src->vdev_scsi;

    assert(vdev_scsi);

    if (cb) {
        return cb(data);
    }
    if (vus_src->vu_cb) {
        vus_src->vu_cb(&vdev_scsi->vu_dev, vus_src->gfd.revents, data);
    }
    return G_SOURCE_CONTINUE;
}

static GSourceFuncs vus_gsrc_funcs = {
    vus_gsrc_prepare,
    vus_gsrc_check,
    vus_gsrc_dispatch,
    NULL
};

static void vus_gsrc_new(VusDev *vdev_scsi, int fd, GIOCondition cond,
                         vu_watch_cb vu_cb, GSourceFunc gsrc_cb, gpointer data)
{
    GSource *vus_gsrc;
    vus_gsrc_t *vus_src;
    guint id;

    assert(vdev_scsi);
    assert(fd >= 0);
    assert(vu_cb || gsrc_cb);
    assert(!(vu_cb && gsrc_cb));

    vus_gsrc = g_source_new(&vus_gsrc_funcs, sizeof(vus_gsrc_t));
    vus_src = (vus_gsrc_t *)vus_gsrc;

    vus_src->vdev_scsi = vdev_scsi;
    vus_src->gfd.fd = fd;
    vus_src->gfd.events = cond;
    vus_src->vu_cb = vu_cb;

    g_source_add_poll(vus_gsrc, &vus_src->gfd);
    g_source_set_callback(vus_gsrc, gsrc_cb, data, NULL);
    id = g_source_attach(vus_gsrc, NULL);
    assert(id);
    g_source_unref(vus_gsrc);

    g_tree_insert(vdev_scsi->fdmap, (gpointer)(uintptr_t)fd,
                                    (gpointer)(uintptr_t)id);
}

/** libiscsi integration **/

typedef struct virtio_scsi_cmd_req VirtIOSCSICmdReq;
typedef struct virtio_scsi_cmd_resp VirtIOSCSICmdResp;

static int vus_iscsi_add_lun(VusIscsiLun *lun, char *iscsi_uri)
{
    struct iscsi_url *iscsi_url;
    struct iscsi_context *iscsi_ctx;
    int ret = 0;

    assert(lun);
    assert(iscsi_uri);
    assert(!lun->iscsi_ctx);

    iscsi_ctx = iscsi_create_context(VUS_ISCSI_INITIATOR);
    if (!iscsi_ctx) {
        PERR("Unable to create iSCSI context");
        return -1;
    }

    iscsi_url = iscsi_parse_full_url(iscsi_ctx, iscsi_uri);
    if (!iscsi_url) {
        PERR("Unable to parse iSCSI URL: %s", iscsi_get_error(iscsi_ctx));
        goto fail;
    }

    iscsi_set_session_type(iscsi_ctx, ISCSI_SESSION_NORMAL);
    iscsi_set_header_digest(iscsi_ctx, ISCSI_HEADER_DIGEST_NONE_CRC32C);
    if (iscsi_full_connect_sync(iscsi_ctx, iscsi_url->portal, iscsi_url->lun)) {
        PERR("Unable to login to iSCSI portal: %s", iscsi_get_error(iscsi_ctx));
        goto fail;
    }

    lun->iscsi_ctx = iscsi_ctx;
    lun->iscsi_lun = iscsi_url->lun;

    PDBG("Context %p created for lun 0: %s", iscsi_ctx, iscsi_uri);

out:
    if (iscsi_url) {
        iscsi_destroy_url(iscsi_url);
    }
    return ret;

fail:
    (void)iscsi_destroy_context(iscsi_ctx);
    ret = -1;
    goto out;
}

static struct scsi_task *scsi_task_new(int cdb_len, uint8_t *cdb, int dir,
                                       int xfer_len)
{
    struct scsi_task *task;

    assert(cdb_len > 0);
    assert(cdb);

    task = g_new0(struct scsi_task, 1);
    memcpy(task->cdb, cdb, cdb_len);
    task->cdb_size = cdb_len;
    task->xfer_dir = dir;
    task->expxferlen = xfer_len;

    return task;
}

static int get_cdb_len(uint8_t *cdb)
{
    assert(cdb);

    switch (cdb[0] >> 5) {
    case 0: return 6;
    case 1: /* fall through */
    case 2: return 10;
    case 4: return 16;
    case 5: return 12;
    }
    PERR("Unable to determine cdb len (0x%02hhX)", cdb[0] >> 5);
    return -1;
}

static int handle_cmd_sync(struct iscsi_context *ctx,
                           VirtIOSCSICmdReq *req,
                           struct iovec *out, unsigned int out_len,
                           VirtIOSCSICmdResp *rsp,
                           struct iovec *in, unsigned int in_len)
{
    struct scsi_task *task;
    uint32_t dir;
    uint32_t len;
    int cdb_len;
    int i;

    assert(ctx);
    assert(req);
    assert(rsp);

    if (!(!req->lun[1] && req->lun[2] == 0x40 && !req->lun[3])) {
        /* Ignore anything different than target=0, lun=0 */
        PDBG("Ignoring unconnected lun (0x%hhX, 0x%hhX)",
             req->lun[1], req->lun[3]);
        rsp->status = SCSI_STATUS_CHECK_CONDITION;
        memset(rsp->sense, 0, sizeof(rsp->sense));
        rsp->sense_len = 18;
        rsp->sense[0] = 0x70;
        rsp->sense[2] = SCSI_SENSE_ILLEGAL_REQUEST;
        rsp->sense[7] = 10;
        rsp->sense[12] = 0x24;

        return 0;
    }

    cdb_len = get_cdb_len(req->cdb);
    if (cdb_len == -1) {
        return -1;
    }

    len = 0;
    if (!out_len && !in_len) {
        dir = SCSI_XFER_NONE;
    } else if (out_len) {
        dir = SCSI_XFER_WRITE;
        for (i = 0; i < out_len; i++) {
            len += out[i].iov_len;
        }
    } else {
        dir = SCSI_XFER_READ;
        for (i = 0; i < in_len; i++) {
            len += in[i].iov_len;
        }
    }

    task = scsi_task_new(cdb_len, req->cdb, dir, len);

    if (dir == SCSI_XFER_WRITE) {
        task->iovector_out.iov = (struct scsi_iovec *)out;
        task->iovector_out.niov = out_len;
    } else if (dir == SCSI_XFER_READ) {
        task->iovector_in.iov = (struct scsi_iovec *)in;
        task->iovector_in.niov = in_len;
    }

    PDBG("Sending iscsi cmd (cdb_len=%d, dir=%d, task=%p)",
         cdb_len, dir, task);
    if (!iscsi_scsi_command_sync(ctx, 0, task, NULL)) {
        PERR("Error serving SCSI command");
        g_free(task);
        return -1;
    }

    memset(rsp, 0, sizeof(*rsp));

    rsp->status = task->status;
    rsp->resid  = task->residual;

    if (task->status == SCSI_STATUS_CHECK_CONDITION) {
        rsp->response = VIRTIO_SCSI_S_FAILURE;
        rsp->sense_len = task->datain.size - 2;
        memcpy(rsp->sense, &task->datain.data[2], rsp->sense_len);
    }

    g_free(task);

    PDBG("Filled in rsp: status=%hhX, resid=%u, response=%hhX, sense_len=%u",
         rsp->status, rsp->resid, rsp->response, rsp->sense_len);

    return 0;
}

/** libvhost-user callbacks **/

static void vus_panic_cb(VuDev *vu_dev, const char *buf)
{
    VusDev *vdev_scsi;

    assert(vu_dev);

    vdev_scsi = container_of(vu_dev, VusDev, vu_dev);
    if (buf) {
        PERR("vu_panic: %s", buf);
    }

    g_main_loop_quit(vdev_scsi->loop);
}

static void vus_add_watch_cb(VuDev *vu_dev, int fd, int vu_evt, vu_watch_cb cb,
                             void *pvt)
{
    VusDev *vdev_scsi;
    guint id;

    assert(vu_dev);
    assert(fd >= 0);
    assert(cb);

    vdev_scsi = container_of(vu_dev, VusDev, vu_dev);
    id = (guint)(uintptr_t)g_tree_lookup(vdev_scsi->fdmap,
                                         (gpointer)(uintptr_t)fd);
    if (id) {
        GSource *vus_src = g_main_context_find_source_by_id(NULL, id);
        assert(vus_src);
        g_source_destroy(vus_src);
        (void)g_tree_remove(vdev_scsi->fdmap, (gpointer)(uintptr_t)fd);
    }

    vus_gsrc_new(vdev_scsi, fd, vu_evt, cb, NULL, pvt);
}

static void vus_del_watch_cb(VuDev *vu_dev, int fd)
{
    VusDev *vdev_scsi;
    guint id;

    assert(vu_dev);
    assert(fd >= 0);

    vdev_scsi = container_of(vu_dev, VusDev, vu_dev);
    id = (guint)(uintptr_t)g_tree_lookup(vdev_scsi->fdmap,
                                         (gpointer)(uintptr_t)fd);
    if (id) {
        GSource *vus_src = g_main_context_find_source_by_id(NULL, id);
        assert(vus_src);
        g_source_destroy(vus_src);
        (void)g_tree_remove(vdev_scsi->fdmap, (gpointer)(uintptr_t)fd);
    }
}

static void vus_proc_req(VuDev *vu_dev, int idx)
{
    VusDev *vdev_scsi;
    VuVirtq *vq;

    assert(vu_dev);

    vdev_scsi = container_of(vu_dev, VusDev, vu_dev);
    if (idx < 0 || idx >= VHOST_MAX_NR_VIRTQUEUE) {
        PERR("VQ Index out of range: %d", idx);
        vus_panic_cb(vu_dev, NULL);
        return;
    }

    vq = vu_get_queue(vu_dev, idx);
    if (!vq) {
        PERR("Error fetching VQ (dev=%p, idx=%d)", vu_dev, idx);
        vus_panic_cb(vu_dev, NULL);
        return;
    }

    PDBG("Got kicked on vq[%d]@%p", idx, vq);

    while (1) {
        VuVirtqElement *elem;
        VirtIOSCSICmdReq *req;
        VirtIOSCSICmdResp *rsp;

        elem = vu_queue_pop(vu_dev, vq, sizeof(VuVirtqElement));
        if (!elem) {
            PDBG("No more elements pending on vq[%d]@%p", idx, vq);
            break;
        }
        PDBG("Popped elem@%p", elem);

        assert(!(elem->out_num > 1 && elem->in_num > 1));
        assert(elem->out_num > 0 && elem->in_num > 0);

        if (elem->out_sg[0].iov_len < sizeof(VirtIOSCSICmdReq)) {
            PERR("Invalid virtio-scsi req header");
            vus_panic_cb(vu_dev, NULL);
            break;
        }
        req = (VirtIOSCSICmdReq *)elem->out_sg[0].iov_base;

        if (elem->in_sg[0].iov_len < sizeof(VirtIOSCSICmdResp)) {
            PERR("Invalid virtio-scsi rsp header");
            vus_panic_cb(vu_dev, NULL);
            break;
        }
        rsp = (VirtIOSCSICmdResp *)elem->in_sg[0].iov_base;

        if (handle_cmd_sync(vdev_scsi->lun.iscsi_ctx,
                            req, &elem->out_sg[1], elem->out_num - 1,
                            rsp, &elem->in_sg[1], elem->in_num - 1) != 0) {
            vus_panic_cb(vu_dev, NULL);
            break;
        }

        vu_queue_push(vu_dev, vq, elem, 0);
        vu_queue_notify(vu_dev, vq);

        free(elem);
    }
}

static void vus_queue_set_started(VuDev *vu_dev, int idx, bool started)
{
    VuVirtq *vq;

    assert(vu_dev);

    if (idx < 0 || idx >= VHOST_MAX_NR_VIRTQUEUE) {
        PERR("VQ Index out of range: %d", idx);
        vus_panic_cb(vu_dev, NULL);
        return;
    }

    vq = vu_get_queue(vu_dev, idx);

    if (idx == 0 || idx == 1) {
        PDBG("queue %d unimplemented", idx);
    } else {
        vu_set_queue_handler(vu_dev, vq, started ? vus_proc_req : NULL);
    }
}

static const VuDevIface vus_iface = {
    .queue_set_started = vus_queue_set_started,
};

static gboolean vus_vhost_cb(gpointer data)
{
    VuDev *vu_dev = (VuDev *)data;

    assert(vu_dev);

    if (!vu_dispatch(vu_dev) != 0) {
        PERR("Error processing vhost message");
        vus_panic_cb(vu_dev, NULL);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

/** misc helpers **/

static int unix_sock_new(char *unix_fn)
{
    int sock;
    struct sockaddr_un un;
    size_t len;

    assert(unix_fn);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock <= 0) {
        perror("socket");
        return -1;
    }

    un.sun_family = AF_UNIX;
    (void)snprintf(un.sun_path, sizeof(un.sun_path), "%s", unix_fn);
    len = sizeof(un.sun_family) + strlen(un.sun_path);

    (void)unlink(unix_fn);
    if (bind(sock, (struct sockaddr *)&un, len) < 0) {
        perror("bind");
        goto fail;
    }

    if (listen(sock, 1) < 0) {
        perror("listen");
        goto fail;
    }

    return sock;

fail:
    (void)close(sock);

    return -1;
}

/** vhost-user-scsi **/

static void vdev_scsi_free(VusDev *vdev_scsi)
{
    if (vdev_scsi->server_sock >= 0) {
        close(vdev_scsi->server_sock);
    }
    g_main_loop_unref(vdev_scsi->loop);
    g_tree_destroy(vdev_scsi->fdmap);
    g_free(vdev_scsi);
}

static VusDev *vdev_scsi_new(int server_sock)
{
    VusDev *vdev_scsi;

    vdev_scsi = g_new0(VusDev, 1);
    vdev_scsi->server_sock = server_sock;
    vdev_scsi->loop = g_main_loop_new(NULL, FALSE);
    vdev_scsi->fdmap = g_tree_new(vus_fdmap_compare);

    return vdev_scsi;
}

static int vdev_scsi_run(VusDev *vdev_scsi)
{
    int cli_sock;
    int ret = 0;

    assert(vdev_scsi);
    assert(vdev_scsi->server_sock >= 0);
    assert(vdev_scsi->loop);

    cli_sock = accept(vdev_scsi->server_sock, NULL, NULL);
    if (cli_sock < 0) {
        perror("accept");
        return -1;
    }

    vu_init(&vdev_scsi->vu_dev,
            cli_sock,
            vus_panic_cb,
            vus_add_watch_cb,
            vus_del_watch_cb,
            &vus_iface);

    vus_gsrc_new(vdev_scsi, cli_sock, G_IO_IN, NULL, vus_vhost_cb,
                 &vdev_scsi->vu_dev);

    g_main_loop_run(vdev_scsi->loop);

    vu_deinit(&vdev_scsi->vu_dev);

    return ret;
}

int main(int argc, char **argv)
{
    VusDev *vdev_scsi = NULL;
    char *unix_fn = NULL;
    char *iscsi_uri = NULL;
    int sock, opt, err = EXIT_SUCCESS;

    while ((opt = getopt(argc, argv, "u:i:")) != -1) {
        switch (opt) {
        case 'h':
            goto help;
        case 'u':
            unix_fn = g_strdup(optarg);
            break;
        case 'i':
            iscsi_uri = g_strdup(optarg);
            break;
        default:
            goto help;
        }
    }
    if (!unix_fn || !iscsi_uri) {
        goto help;
    }

    sock = unix_sock_new(unix_fn);
    if (sock < 0) {
        goto err;
    }
    vdev_scsi = vdev_scsi_new(sock);

    if (vus_iscsi_add_lun(&vdev_scsi->lun, iscsi_uri) != 0) {
        goto err;
    }

    if (vdev_scsi_run(vdev_scsi) != 0) {
        goto err;
    }

out:
    if (vdev_scsi) {
        vdev_scsi_free(vdev_scsi);
        unlink(unix_fn);
    }
    g_free(unix_fn);
    g_free(iscsi_uri);

    return err;

err:
    err = EXIT_FAILURE;
    goto out;

help:
    fprintf(stderr, "Usage: %s [ -u unix_sock_path -i iscsi_uri ] | [ -h ]\n",
            argv[0]);
    fprintf(stderr, "          -u path to unix socket\n");
    fprintf(stderr, "          -i iscsi uri for lun 0\n");
    fprintf(stderr, "          -h print help and quit\n");

    goto err;
}
