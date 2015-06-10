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

#ifndef _QEMU_VIRTIO_VGA_H
#define _QEMU_VIRTIO_VGA_H

#include "qemu/queue.h"
#include "ui/qemu-pixman.h"
#include "ui/console.h"
#include "hw/virtio/virtio.h"
#include "hw/pci/pci.h"

#include "standard-headers/linux/virtio_gpu.h"
#define TYPE_VIRTIO_GPU "virtio-gpu-device"
#define VIRTIO_GPU(obj)                                        \
        OBJECT_CHECK(VirtIOGPU, (obj), TYPE_VIRTIO_GPU)

#define VIRTIO_ID_GPU 16

#define VIRTIO_GPU_MAX_SCANOUT 4

struct virtio_gpu_simple_resource {
    uint32_t resource_id;
    uint32_t width;
    uint32_t height;
    uint32_t format;
    struct iovec *iov;
    unsigned int iov_cnt;
    uint32_t scanout_bitmask;
    pixman_image_t *image;
    QTAILQ_ENTRY(virtio_gpu_simple_resource) next;
};

struct virtio_gpu_scanout {
    QemuConsole *con;
    DisplaySurface *ds;
    uint32_t width, height;
    int x, y;
    int invalidate;
    uint32_t resource_id;
    QEMUCursor *current_cursor;
};

struct virtio_gpu_requested_state {
    uint32_t width, height;
    int x, y;
};

struct virtio_gpu_conf {
    uint32_t max_outputs;
};

struct virtio_gpu_ctrl_command {
    VirtQueueElement elem;
    VirtQueue *vq;
    struct virtio_gpu_ctrl_hdr cmd_hdr;
    uint32_t error;
    bool finished;
    QTAILQ_ENTRY(virtio_gpu_ctrl_command) next;
};

typedef struct VirtIOGPU {
    VirtIODevice parent_obj;

    QEMUBH *ctrl_bh;
    QEMUBH *cursor_bh;
    VirtQueue *ctrl_vq;
    VirtQueue *cursor_vq;

    int enable;

    int config_size;
    DeviceState *qdev;

    QTAILQ_HEAD(, virtio_gpu_simple_resource) reslist;
    QTAILQ_HEAD(, virtio_gpu_ctrl_command) fenceq;

    struct virtio_gpu_scanout scanout[VIRTIO_GPU_MAX_SCANOUT];
    struct virtio_gpu_requested_state req_state[VIRTIO_GPU_MAX_SCANOUT];

    struct virtio_gpu_conf conf;
    int enabled_output_bitmask;
    struct virtio_gpu_config virtio_config;

    QEMUTimer *fence_poll;
    QEMUTimer *print_stats;

    struct {
        uint32_t inflight;
        uint32_t max_inflight;
        uint32_t requests;
        uint32_t req_3d;
        uint32_t bytes_3d;
    } stats;
} VirtIOGPU;

extern const GraphicHwOps virtio_gpu_ops;

/* to share between PCI and VGA */
#define DEFINE_VIRTIO_GPU_PCI_PROPERTIES(_state)               \
    DEFINE_PROP_BIT("ioeventfd", _state, flags,                \
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, false), \
    DEFINE_PROP_UINT32("vectors", _state, nvectors, 3)

#define DEFINE_VIRTIO_GPU_PROPERTIES(_state, _conf_field)               \
    DEFINE_PROP_UINT32("max_outputs", _state, _conf_field.max_outputs, 1)

#define VIRTIO_GPU_FILL_CMD(out) do {                                   \
        size_t s;                                                       \
        s = iov_to_buf(cmd->elem.out_sg, cmd->elem.out_num, 0,          \
                       &out, sizeof(out));                              \
        if (s != sizeof(out)) {                                         \
            qemu_log_mask(LOG_GUEST_ERROR,                              \
                          "%s: command size incorrect %zu vs %zu\n",    \
                          __func__, s, sizeof(out));                    \
            return;                                                     \
        }                                                               \
    } while (0)

/* virtio-gpu.c */
void virtio_gpu_ctrl_response(VirtIOGPU *g,
                              struct virtio_gpu_ctrl_command *cmd,
                              struct virtio_gpu_ctrl_hdr *resp,
                              size_t resp_len);
void virtio_gpu_ctrl_response_nodata(VirtIOGPU *g,
                                     struct virtio_gpu_ctrl_command *cmd,
                                     enum virtio_gpu_ctrl_type type);
void virtio_gpu_get_display_info(VirtIOGPU *g,
                                 struct virtio_gpu_ctrl_command *cmd);
int virtio_gpu_create_mapping_iov(struct virtio_gpu_resource_attach_backing *ab,
                                  struct virtio_gpu_ctrl_command *cmd,
                                  struct iovec **iov);
void virtio_gpu_cleanup_mapping_iov(struct iovec *iov, uint32_t count);

#endif
