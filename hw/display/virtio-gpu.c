/*
 * Virtio GPU Device
 *
 * Copyright Red Hat, Inc. 2013-2014
 *
 * Authors:
 *     Dave Airlie <airlied@redhat.com>
 *     Gerd Hoffmann <kraxel@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.
 * See the COPYING file in the top-level directory.
 */

#include "qemu-common.h"
#include "qemu/iov.h"
#include "ui/console.h"
#include "trace.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-gpu.h"
#include "hw/virtio/virtio-bus.h"

static struct virtio_gpu_simple_resource*
virtio_gpu_find_resource(VirtIOGPU *g, uint32_t resource_id);

static void update_cursor_data_simple(VirtIOGPU *g,
                                      struct virtio_gpu_scanout *s,
                                      uint32_t resource_id)
{
    struct virtio_gpu_simple_resource *res;
    uint32_t pixels;

    res = virtio_gpu_find_resource(g, resource_id);
    if (!res) {
        return;
    }

    if (pixman_image_get_width(res->image)  != s->current_cursor->width ||
        pixman_image_get_height(res->image) != s->current_cursor->height) {
        return;
    }

    pixels = s->current_cursor->width * s->current_cursor->height;
    memcpy(s->current_cursor->data,
           pixman_image_get_data(res->image),
           pixels * sizeof(uint32_t));
}

static void update_cursor(VirtIOGPU *g, struct virtio_gpu_update_cursor *cursor)
{
    struct virtio_gpu_scanout *s;

    if (cursor->pos.scanout_id >= g->conf.max_outputs) {
        return;
    }
    s = &g->scanout[cursor->pos.scanout_id];

    if (cursor->hdr.type != VIRTIO_GPU_CMD_MOVE_CURSOR) {
        if (!s->current_cursor) {
            s->current_cursor = cursor_alloc(64, 64);
        }

        s->current_cursor->hot_x = cursor->hot_x;
        s->current_cursor->hot_y = cursor->hot_y;

        if (cursor->resource_id > 0) {
            update_cursor_data_simple(g, s, cursor->resource_id);
        }
        dpy_cursor_define(s->con, s->current_cursor);
    }
    dpy_mouse_set(s->con, cursor->pos.x, cursor->pos.y,
                  cursor->resource_id ? 1 : 0);
}

static void virtio_gpu_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    memcpy(config, &g->virtio_config, sizeof(g->virtio_config));
}

static void virtio_gpu_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    struct virtio_gpu_config vgconfig;

    memcpy(&vgconfig, config, sizeof(g->virtio_config));

    if (vgconfig.events_clear) {
        g->virtio_config.events_read &= ~vgconfig.events_clear;
    }
}

static uint64_t virtio_gpu_get_features(VirtIODevice *vdev, uint64_t features,
                                        Error **errp)
{
    return features;
}

static void virtio_gpu_notify_event(VirtIOGPU *g, uint32_t event_type)
{
    g->virtio_config.events_read |= event_type;
    virtio_notify_config(&g->parent_obj);
}

static struct virtio_gpu_simple_resource *
virtio_gpu_find_resource(VirtIOGPU *g, uint32_t resource_id)
{
    struct virtio_gpu_simple_resource *res;

    QTAILQ_FOREACH(res, &g->reslist, next) {
        if (res->resource_id == resource_id) {
            return res;
        }
    }
    return NULL;
}

void virtio_gpu_ctrl_response(VirtIOGPU *g,
                              struct virtio_gpu_ctrl_command *cmd,
                              struct virtio_gpu_ctrl_hdr *resp,
                              size_t resp_len)
{
    size_t s;

    if (cmd->cmd_hdr.flags & VIRTIO_GPU_FLAG_FENCE) {
        resp->flags |= VIRTIO_GPU_FLAG_FENCE;
        resp->fence_id = cmd->cmd_hdr.fence_id;
        resp->ctx_id = cmd->cmd_hdr.ctx_id;
    }
    s = iov_from_buf(cmd->elem.in_sg, cmd->elem.in_num, 0, resp, resp_len);
    if (s != resp_len) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: response size incorrect %zu vs %zu\n",
                      __func__, s, resp_len);
    }
    virtqueue_push(cmd->vq, &cmd->elem, s);
    virtio_notify(VIRTIO_DEVICE(g), cmd->vq);
    cmd->finished = true;
}

void virtio_gpu_ctrl_response_nodata(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd,
                                     enum virtio_gpu_ctrl_type type)
{
    struct virtio_gpu_ctrl_hdr resp;

    memset(&resp, 0, sizeof(resp));
    resp.type = type;
    virtio_gpu_ctrl_response(g, cmd, &resp, sizeof(resp));
}

static void
virtio_gpu_fill_display_info(VirtIOGPU *g,
                             struct virtio_gpu_resp_display_info *dpy_info)
{
    int i;

    for (i = 0; i < g->conf.max_outputs; i++) {
        if (g->enabled_output_bitmask & (1 << i)) {
            dpy_info->pmodes[i].enabled = 1;
            dpy_info->pmodes[i].r.width = g->req_state[i].width;
            dpy_info->pmodes[i].r.height = g->req_state[i].height;
        }
    }
}

void virtio_gpu_get_display_info(VirtIOGPU *g,
                                 struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_resp_display_info display_info;

    trace_virtio_gpu_cmd_get_display_info();
    memset(&display_info, 0, sizeof(display_info));
    display_info.hdr.type = VIRTIO_GPU_RESP_OK_DISPLAY_INFO;
    virtio_gpu_fill_display_info(g, &display_info);
    virtio_gpu_ctrl_response(g, cmd, &display_info.hdr,
                             sizeof(display_info));
}

static pixman_format_code_t get_pixman_format(uint32_t virtio_gpu_format)
{
    switch (virtio_gpu_format) {
#ifdef HOST_WORDS_BIGENDIAN
    case VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM:
        return PIXMAN_b8g8r8x8;
    case VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM:
        return PIXMAN_b8g8r8a8;
    case VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM:
        return PIXMAN_x8r8g8b8;
    case VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM:
        return PIXMAN_a8r8g8b8;
    case VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM:
        return PIXMAN_r8g8b8x8;
    case VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM:
        return PIXMAN_r8g8b8a8;
    case VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM:
        return PIXMAN_x8b8g8r8;
    case VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM:
        return PIXMAN_a8b8g8r8;
#else
    case VIRTIO_GPU_FORMAT_B8G8R8X8_UNORM:
        return PIXMAN_x8r8g8b8;
    case VIRTIO_GPU_FORMAT_B8G8R8A8_UNORM:
        return PIXMAN_a8r8g8b8;
    case VIRTIO_GPU_FORMAT_X8R8G8B8_UNORM:
        return PIXMAN_b8g8r8x8;
    case VIRTIO_GPU_FORMAT_A8R8G8B8_UNORM:
        return PIXMAN_b8g8r8a8;
    case VIRTIO_GPU_FORMAT_R8G8B8X8_UNORM:
        return PIXMAN_x8b8g8r8;
    case VIRTIO_GPU_FORMAT_R8G8B8A8_UNORM:
        return PIXMAN_a8b8g8r8;
    case VIRTIO_GPU_FORMAT_X8B8G8R8_UNORM:
        return PIXMAN_r8g8b8x8;
    case VIRTIO_GPU_FORMAT_A8B8G8R8_UNORM:
        return PIXMAN_r8g8b8a8;
#endif
    default:
        return 0;
    }
}

static void virtio_gpu_resource_create_2d(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    pixman_format_code_t pformat;
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_create_2d c2d;

    VIRTIO_GPU_FILL_CMD(c2d);
    trace_virtio_gpu_cmd_res_create_2d(c2d.resource_id, c2d.format,
                                       c2d.width, c2d.height);

    if (c2d.resource_id == 0) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: resource id 0 is not allowed\n",
                      __func__);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    res = virtio_gpu_find_resource(g, c2d.resource_id);
    if (res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: resource already exists %d\n",
                      __func__, c2d.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    res = g_new0(struct virtio_gpu_simple_resource, 1);

    res->width = c2d.width;
    res->height = c2d.height;
    res->format = c2d.format;
    res->resource_id = c2d.resource_id;

    pformat = get_pixman_format(c2d.format);
    if (!pformat) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: host couldn't handle guest format %d\n",
                      __func__, c2d.format);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }
    res->image = pixman_image_create_bits(pformat,
                                          c2d.width,
                                          c2d.height,
                                          NULL, 0);

    if (!res->image) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: resource creation failed %d %d %d\n",
                      __func__, c2d.resource_id, c2d.width, c2d.height);
        g_free(res);
        cmd->error = VIRTIO_GPU_RESP_ERR_OUT_OF_MEMORY;
        return;
    }

    QTAILQ_INSERT_HEAD(&g->reslist, res, next);
}

static void virtio_gpu_resource_destroy(VirtIOGPU *g,
                                        struct virtio_gpu_simple_resource *res)
{
    pixman_image_unref(res->image);
    QTAILQ_REMOVE(&g->reslist, res, next);
    g_free(res);
}

static void virtio_gpu_resource_unref(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_unref unref;

    VIRTIO_GPU_FILL_CMD(unref);
    trace_virtio_gpu_cmd_res_unref(unref.resource_id);

    res = virtio_gpu_find_resource(g, unref.resource_id);
    if (!res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, unref.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }
    virtio_gpu_resource_destroy(g, res);
}

static void virtio_gpu_transfer_to_host_2d(VirtIOGPU *g,
                                           struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    int h;
    uint32_t src_offset, dst_offset, stride;
    int bpp;
    pixman_format_code_t format;
    struct virtio_gpu_transfer_to_host_2d t2d;

    VIRTIO_GPU_FILL_CMD(t2d);
    trace_virtio_gpu_cmd_res_xfer_toh_2d(t2d.resource_id);

    res = virtio_gpu_find_resource(g, t2d.resource_id);
    if (!res || !res->iov) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, t2d.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    if (t2d.r.x > res->width ||
        t2d.r.y > res->height ||
        t2d.r.width > res->width ||
        t2d.r.height > res->height ||
        t2d.r.x + t2d.r.width > res->width ||
        t2d.r.y + t2d.r.height > res->height) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: transfer bounds outside resource"
                      " bounds for resource %d: %d %d %d %d vs %d %d\n",
                      __func__, t2d.resource_id, t2d.r.x, t2d.r.y,
                      t2d.r.width, t2d.r.height, res->width, res->height);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }

    format = pixman_image_get_format(res->image);
    bpp = (PIXMAN_FORMAT_BPP(format) + 7) / 8;
    stride = pixman_image_get_stride(res->image);

    if (t2d.offset || t2d.r.x || t2d.r.y ||
        t2d.r.width != pixman_image_get_width(res->image)) {
        void *img_data = pixman_image_get_data(res->image);
        for (h = 0; h < t2d.r.height; h++) {
            src_offset = t2d.offset + stride * h;
            dst_offset = (t2d.r.y + h) * stride + (t2d.r.x * bpp);

            iov_to_buf(res->iov, res->iov_cnt, src_offset,
                       (uint8_t *)img_data
                       + dst_offset, t2d.r.width * bpp);
        }
    } else {
        iov_to_buf(res->iov, res->iov_cnt, 0,
                   pixman_image_get_data(res->image),
                   pixman_image_get_stride(res->image)
                   * pixman_image_get_height(res->image));
    }
}

static void virtio_gpu_resource_flush(VirtIOGPU *g,
                                      struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_flush rf;
    pixman_region16_t flush_region;
    int i;

    VIRTIO_GPU_FILL_CMD(rf);
    trace_virtio_gpu_cmd_res_flush(rf.resource_id,
                                   rf.r.width, rf.r.height, rf.r.x, rf.r.y);

    res = virtio_gpu_find_resource(g, rf.resource_id);
    if (!res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, rf.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    if (rf.r.x > res->width ||
        rf.r.y > res->height ||
        rf.r.width > res->width ||
        rf.r.height > res->height ||
        rf.r.x + rf.r.width > res->width ||
        rf.r.y + rf.r.height > res->height) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: flush bounds outside resource"
                      " bounds for resource %d: %d %d %d %d vs %d %d\n",
                      __func__, rf.resource_id, rf.r.x, rf.r.y,
                      rf.r.width, rf.r.height, res->width, res->height);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }

    pixman_region_init_rect(&flush_region,
                            rf.r.x, rf.r.y, rf.r.width, rf.r.height);
    for (i = 0; i < VIRTIO_GPU_MAX_SCANOUT; i++) {
        struct virtio_gpu_scanout *scanout;
        pixman_region16_t region, finalregion;
        pixman_box16_t *extents;

        if (!(res->scanout_bitmask & (1 << i))) {
            continue;
        }
        scanout = &g->scanout[i];

        pixman_region_init(&finalregion);
        pixman_region_init_rect(&region, scanout->x, scanout->y,
                                scanout->width, scanout->height);

        pixman_region_intersect(&finalregion, &flush_region, &region);
        pixman_region_translate(&finalregion, -scanout->x, -scanout->y);
        extents = pixman_region_extents(&finalregion);
        /* work out the area we need to update for each console */
        dpy_gfx_update(g->scanout[i].con,
                       extents->x1, extents->y1,
                       extents->x2 - extents->x1,
                       extents->y2 - extents->y1);

        pixman_region_fini(&region);
        pixman_region_fini(&finalregion);
    }
    pixman_region_fini(&flush_region);
}

static void virtio_gpu_set_scanout(VirtIOGPU *g,
                                   struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_scanout *scanout;
    pixman_format_code_t format;
    uint32_t offset;
    int bpp;
    struct virtio_gpu_set_scanout ss;

    VIRTIO_GPU_FILL_CMD(ss);
    trace_virtio_gpu_cmd_set_scanout(ss.scanout_id, ss.resource_id,
                                     ss.r.width, ss.r.height, ss.r.x, ss.r.y);

    g->enable = 1;
    if (ss.resource_id == 0) {
        scanout = &g->scanout[ss.scanout_id];
        if (scanout->resource_id) {
            res = virtio_gpu_find_resource(g, scanout->resource_id);
            if (res) {
                res->scanout_bitmask &= ~(1 << ss.scanout_id);
            }
        }
        if (ss.scanout_id == 0 ||
            ss.scanout_id >= g->conf.max_outputs) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: illegal scanout id specified %d",
                          __func__, ss.scanout_id);
            cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
            return;
        }
        dpy_gfx_replace_surface(g->scanout[ss.scanout_id].con, NULL);
        scanout->ds = NULL;
        scanout->width = 0;
        scanout->height = 0;
        return;
    }

    /* create a surface for this scanout */
    if (ss.scanout_id >= VIRTIO_GPU_MAX_SCANOUT ||
        ss.scanout_id >= g->conf.max_outputs) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal scanout id specified %d",
                      __func__, ss.scanout_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_SCANOUT_ID;
        return;
    }

    res = virtio_gpu_find_resource(g, ss.resource_id);
    if (!res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, ss.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    if (ss.r.x > res->width ||
        ss.r.y > res->height ||
        ss.r.width > res->width ||
        ss.r.height > res->height ||
        ss.r.x + ss.r.width > res->width ||
        ss.r.y + ss.r.height > res->height) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal scanout %d bounds for"
                      " resource %d, (%d,%d)+%d,%d vs %d %d\n",
                      __func__, ss.scanout_id, ss.resource_id, ss.r.x, ss.r.y,
                      ss.r.width, ss.r.height, res->width, res->height);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_PARAMETER;
        return;
    }

    scanout = &g->scanout[ss.scanout_id];

    format = pixman_image_get_format(res->image);
    bpp = (PIXMAN_FORMAT_BPP(format) + 7) / 8;
    offset = (ss.r.x * bpp) + ss.r.y * pixman_image_get_stride(res->image);
    if (!scanout->ds || surface_data(scanout->ds)
        != ((uint8_t *)pixman_image_get_data(res->image) + offset) ||
        scanout->width != ss.r.width ||
        scanout->height != ss.r.height) {
        /* realloc the surface ptr */
        scanout->ds = qemu_create_displaysurface_from
            (ss.r.width, ss.r.height, format,
             pixman_image_get_stride(res->image),
             (uint8_t *)pixman_image_get_data(res->image) + offset);
        if (!scanout->ds) {
            cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
            return;
        }
        dpy_gfx_replace_surface(g->scanout[ss.scanout_id].con, scanout->ds);
    }

    res->scanout_bitmask |= (1 << ss.scanout_id);
    scanout->resource_id = ss.resource_id;
    scanout->x = ss.r.x;
    scanout->y = ss.r.y;
    scanout->width = ss.r.width;
    scanout->height = ss.r.height;
}

int virtio_gpu_create_mapping_iov(struct virtio_gpu_resource_attach_backing *ab,
                                  struct virtio_gpu_ctrl_command *cmd,
                                  struct iovec **iov)
{
    struct virtio_gpu_mem_entry *ents;
    size_t esize, s;
    int i;

    if (ab->nr_entries > 16384) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: nr_entries is too big (%d > 16384)\n",
                      __func__, ab->nr_entries);
        return -1;
    }

    esize = sizeof(*ents) * ab->nr_entries;
    ents = g_malloc(esize);
    s = iov_to_buf(cmd->elem.out_sg, cmd->elem.out_num,
                   sizeof(*ab), ents, esize);
    if (s != esize) {
        qemu_log_mask(LOG_GUEST_ERROR,
                      "%s: command data size incorrect %zu vs %zu\n",
                      __func__, s, esize);
        g_free(ents);
        return -1;
    }

    *iov = g_malloc0(sizeof(struct iovec) * ab->nr_entries);
    for (i = 0; i < ab->nr_entries; i++) {
        hwaddr len = ents[i].length;
        (*iov)[i].iov_len = ents[i].length;
        (*iov)[i].iov_base = cpu_physical_memory_map(ents[i].addr, &len, 1);
        if (!(*iov)[i].iov_base || len != ents[i].length) {
            qemu_log_mask(LOG_GUEST_ERROR, "%s: failed to map MMIO memory for"
                          " resource %d element %d\n",
                          __func__, ab->resource_id, i);
            virtio_gpu_cleanup_mapping_iov(*iov, i);
            g_free(ents);
            g_free(*iov);
            *iov = NULL;
            return -1;
        }
    }
    g_free(ents);
    return 0;
}

void virtio_gpu_cleanup_mapping_iov(struct iovec *iov, uint32_t count)
{
    int i;

    for (i = 0; i < count; i++) {
        cpu_physical_memory_unmap(iov[i].iov_base, iov[i].iov_len, 1,
                                  iov[i].iov_len);
    }
}

static void virtio_gpu_cleanup_mapping(struct virtio_gpu_simple_resource *res)
{
    virtio_gpu_cleanup_mapping_iov(res->iov, res->iov_cnt);
    g_free(res->iov);
    res->iov = NULL;
    res->iov_cnt = 0;
}

static void
virtio_gpu_resource_attach_backing(VirtIOGPU *g,
                                   struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_attach_backing ab;
    int ret;

    VIRTIO_GPU_FILL_CMD(ab);
    trace_virtio_gpu_cmd_res_back_attach(ab.resource_id);

    res = virtio_gpu_find_resource(g, ab.resource_id);
    if (!res) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, ab.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }

    ret = virtio_gpu_create_mapping_iov(&ab, cmd, &res->iov);
    if (ret != 0) {
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        return;
    }

    res->iov_cnt = ab.nr_entries;
}

static void
virtio_gpu_resource_detach_backing(VirtIOGPU *g,
                                   struct virtio_gpu_ctrl_command *cmd)
{
    struct virtio_gpu_simple_resource *res;
    struct virtio_gpu_resource_detach_backing detach;

    VIRTIO_GPU_FILL_CMD(detach);
    trace_virtio_gpu_cmd_res_back_detach(detach.resource_id);

    res = virtio_gpu_find_resource(g, detach.resource_id);
    if (!res || !res->iov) {
        qemu_log_mask(LOG_GUEST_ERROR, "%s: illegal resource specified %d\n",
                      __func__, detach.resource_id);
        cmd->error = VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID;
        return;
    }
    virtio_gpu_cleanup_mapping(res);
}

static void virtio_gpu_simple_process_cmd(VirtIOGPU *g,
                                          struct virtio_gpu_ctrl_command *cmd)
{
    VIRTIO_GPU_FILL_CMD(cmd->cmd_hdr);

    switch (cmd->cmd_hdr.type) {
    case VIRTIO_GPU_CMD_GET_DISPLAY_INFO:
        virtio_gpu_get_display_info(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_CREATE_2D:
        virtio_gpu_resource_create_2d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_UNREF:
        virtio_gpu_resource_unref(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_FLUSH:
        virtio_gpu_resource_flush(g, cmd);
        break;
    case VIRTIO_GPU_CMD_TRANSFER_TO_HOST_2D:
        virtio_gpu_transfer_to_host_2d(g, cmd);
        break;
    case VIRTIO_GPU_CMD_SET_SCANOUT:
        virtio_gpu_set_scanout(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_ATTACH_BACKING:
        virtio_gpu_resource_attach_backing(g, cmd);
        break;
    case VIRTIO_GPU_CMD_RESOURCE_DETACH_BACKING:
        virtio_gpu_resource_detach_backing(g, cmd);
        break;
    default:
        cmd->error = VIRTIO_GPU_RESP_ERR_UNSPEC;
        break;
    }
    if (!cmd->finished) {
        virtio_gpu_ctrl_response_nodata(g, cmd, cmd->error ? cmd->error :
                                        VIRTIO_GPU_RESP_OK_NODATA);
    }
}

static void virtio_gpu_handle_ctrl_cb(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    qemu_bh_schedule(g->ctrl_bh);
}

static void virtio_gpu_handle_cursor_cb(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    qemu_bh_schedule(g->cursor_bh);
}

static void virtio_gpu_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    struct virtio_gpu_ctrl_command *cmd;

    if (!virtio_queue_ready(vq)) {
        return;
    }

    cmd = g_new(struct virtio_gpu_ctrl_command, 1);
    while (virtqueue_pop(vq, &cmd->elem)) {
        cmd->vq = vq;
        cmd->error = 0;
        cmd->finished = false;
        g->stats.requests++;

        virtio_gpu_simple_process_cmd(g, cmd);
        if (!cmd->finished) {
            QTAILQ_INSERT_TAIL(&g->fenceq, cmd, next);
            g->stats.inflight++;
            if (g->stats.max_inflight < g->stats.inflight) {
                g->stats.max_inflight = g->stats.inflight;
            }
            fprintf(stderr, "inflight: %3d (+)\r", g->stats.inflight);
            cmd = g_new(struct virtio_gpu_ctrl_command, 1);
        }
    }
    g_free(cmd);
}

static void virtio_gpu_ctrl_bh(void *opaque)
{
    VirtIOGPU *g = opaque;
    virtio_gpu_handle_ctrl(&g->parent_obj, g->ctrl_vq);
}

static void virtio_gpu_handle_cursor(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    VirtQueueElement elem;
    size_t s;
    struct virtio_gpu_update_cursor cursor_info;

    if (!virtio_queue_ready(vq)) {
        return;
    }
    while (virtqueue_pop(vq, &elem)) {
        s = iov_to_buf(elem.out_sg, elem.out_num, 0,
                       &cursor_info, sizeof(cursor_info));
        if (s != sizeof(cursor_info)) {
            qemu_log_mask(LOG_GUEST_ERROR,
                          "%s: cursor size incorrect %zu vs %zu\n",
                          __func__, s, sizeof(cursor_info));
        } else {
            update_cursor(g, &cursor_info);
        }
        virtqueue_push(vq, &elem, 0);
        virtio_notify(vdev, vq);
    }
}

static void virtio_gpu_cursor_bh(void *opaque)
{
    VirtIOGPU *g = opaque;
    virtio_gpu_handle_cursor(&g->parent_obj, g->cursor_vq);
}

static void virtio_gpu_invalidate_display(void *opaque)
{
}

static void virtio_gpu_update_display(void *opaque)
{
}

static void virtio_gpu_text_update(void *opaque, console_ch_t *chardata)
{
}

static int virtio_gpu_ui_info(void *opaque, uint32_t idx, QemuUIInfo *info)
{
    VirtIOGPU *g = opaque;

    if (idx > g->conf.max_outputs) {
        return -1;
    }

    g->req_state[idx].x = info->xoff;
    g->req_state[idx].y = info->yoff;
    g->req_state[idx].width = info->width;
    g->req_state[idx].height = info->height;

    if (info->width && info->height) {
        g->enabled_output_bitmask |= (1 << idx);
    } else {
        g->enabled_output_bitmask &= ~(1 << idx);
    }

    /* send event to guest */
    virtio_gpu_notify_event(g, VIRTIO_GPU_EVENT_DISPLAY);
    return 0;
}

const GraphicHwOps virtio_gpu_ops = {
    .invalidate = virtio_gpu_invalidate_display,
    .gfx_update = virtio_gpu_update_display,
    .text_update = virtio_gpu_text_update,
    .ui_info = virtio_gpu_ui_info,
};

static void virtio_gpu_device_realize(DeviceState *qdev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(qdev);
    VirtIOGPU *g = VIRTIO_GPU(qdev);
    int i;

    g->config_size = sizeof(struct virtio_gpu_config);
    g->virtio_config.num_scanouts = g->conf.max_outputs;
    virtio_init(VIRTIO_DEVICE(g), "virtio-gpu", VIRTIO_ID_GPU,
                g->config_size);

    g->req_state[0].width = 1024;
    g->req_state[0].height = 768;

    g->ctrl_vq   = virtio_add_queue(vdev, 64, virtio_gpu_handle_ctrl_cb);
    g->cursor_vq = virtio_add_queue(vdev, 16, virtio_gpu_handle_cursor_cb);

    g->ctrl_bh = qemu_bh_new(virtio_gpu_ctrl_bh, g);
    g->cursor_bh = qemu_bh_new(virtio_gpu_cursor_bh, g);
    QTAILQ_INIT(&g->reslist);
    QTAILQ_INIT(&g->fenceq);

    g->enabled_output_bitmask = 1;
    g->qdev = qdev;

    for (i = 0; i < g->conf.max_outputs; i++) {
        g->scanout[i].con =
            graphic_console_init(DEVICE(g), i, &virtio_gpu_ops, g);
        if (i > 0) {
            dpy_gfx_replace_surface(g->scanout[i].con, NULL);
        }
    }
}

static void virtio_gpu_instance_init(Object *obj)
{
}

static void virtio_gpu_reset(VirtIODevice *vdev)
{
    VirtIOGPU *g = VIRTIO_GPU(vdev);
    struct virtio_gpu_simple_resource *res, *tmp;
    int i;

    g->enable = 0;

    QTAILQ_FOREACH_SAFE(res, &g->reslist, next, tmp) {
        virtio_gpu_resource_destroy(g, res);
    }
    for (i = 0; i < g->conf.max_outputs; i++) {
#if 0
        g->req_state[i].x = 0;
        g->req_state[i].y = 0;
        if (i == 0) {
            g->req_state[0].width = 1024;
            g->req_state[0].height = 768;
        } else {
            g->req_state[i].width = 0;
            g->req_state[i].height = 0;
        }
#endif
        g->scanout[i].resource_id = 0;
        g->scanout[i].width = 0;
        g->scanout[i].height = 0;
        g->scanout[i].x = 0;
        g->scanout[i].y = 0;
        g->scanout[i].ds = NULL;
    }
    g->enabled_output_bitmask = 1;
}

static Property virtio_gpu_properties[] = {
    DEFINE_PROP_UINT32("max_outputs", VirtIOGPU, conf.max_outputs, 1),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_gpu_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    vdc->realize = virtio_gpu_device_realize;
    vdc->get_config = virtio_gpu_get_config;
    vdc->set_config = virtio_gpu_set_config;
    vdc->get_features = virtio_gpu_get_features;

    vdc->reset = virtio_gpu_reset;

    dc->props = virtio_gpu_properties;
}

static const TypeInfo virtio_gpu_info = {
    .name = TYPE_VIRTIO_GPU,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOGPU),
    .instance_init = virtio_gpu_instance_init,
    .class_init = virtio_gpu_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_gpu_info);
}

type_init(virtio_register_types)

QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_ctrl_hdr)                != 24);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_update_cursor)           != 56);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resource_unref)          != 32);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resource_create_2d)      != 40);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_set_scanout)             != 48);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resource_flush)          != 48);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_transfer_to_host_2d)     != 56);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_mem_entry)               != 16);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resource_attach_backing) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resource_detach_backing) != 32);
QEMU_BUILD_BUG_ON(sizeof(struct virtio_gpu_resp_display_info)       != 408);
