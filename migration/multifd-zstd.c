/*
 * Multifd zlib compression implementation
 *
 * Copyright (c) 2020 Red Hat Inc
 *
 * Authors:
 *  Juan Quintela <quintela@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include <zstd.h>
#include "qemu/rcu.h"
#include "exec/target_page.h"
#include "qapi/error.h"
#include "migration.h"
#include "trace.h"
#include "multifd.h"

struct zstd_data {
    /* stream for compression */
    ZSTD_CStream *zcs;
    /* stream for decompression */
    ZSTD_DStream *zds;
    /* buffers */
    ZSTD_inBuffer in;
    ZSTD_outBuffer out;
    /* compressed buffer */
    uint8_t *zbuff;
    /* size of compressed buffer */
    uint32_t zbuff_len;
};

/* Multifd zstd compression */

/**
 * zstd_send_setup: setup send side
 *
 * Setup each channel with zstd compression.
 *
 * Returns 0 for success or -1 for error
 *
 * @p: Params for the channel that we are using
 * @errp: pointer to an error
 */
static int zstd_send_setup(MultiFDSendParams *p, Error **errp)
{
    uint32_t page_count = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    struct zstd_data *z = g_new0(struct zstd_data, 1);
    int res;

    p->data = z;
    z->zcs = ZSTD_createCStream();
    if (!z->zcs) {
        g_free(z);
        error_setg(errp, "multifd %d: zstd createCStream failed", p->id);
        return -1;
    }

    res = ZSTD_initCStream(z->zcs, migrate_multifd_zstd_level());
    if (ZSTD_isError(res)) {
        ZSTD_freeCStream(z->zcs);
        g_free(z);
        error_setg(errp, "multifd %d: initCStream failed with error %s",
                   p->id, ZSTD_getErrorName(res));
        return -1;
    }
    /* We will never have more than page_count pages */
    z->zbuff_len = page_count * qemu_target_page_size();
    z->zbuff_len *= 2;
    z->zbuff = g_try_malloc(z->zbuff_len);
    if (!z->zbuff) {
        ZSTD_freeCStream(z->zcs);
        g_free(z);
        error_setg(errp, "multifd %d: out of memory for zbuff", p->id);
        return -1;
    }
    return 0;
}

/**
 * zstd_send_cleanup: cleanup send side
 *
 * Close the channel and return memory.
 *
 * @p: Params for the channel that we are using
 */
static void zstd_send_cleanup(MultiFDSendParams *p, Error **errp)
{
    struct zstd_data *z = p->data;

    ZSTD_freeCStream(z->zcs);
    z->zcs = NULL;
    g_free(z->zbuff);
    z->zbuff = NULL;
    g_free(p->data);
    p->data = NULL;
}

/**
 * zstd_send_prepare: prepare date to be able to send
 *
 * Create a compressed buffer with all the pages that we are going to
 * send.
 *
 * Returns 0 for success or -1 for error
 *
 * @p: Params for the channel that we are using
 * @used: number of pages used
 */
static int zstd_send_prepare(MultiFDSendParams *p, uint32_t used, Error **errp)
{
    struct iovec *iov = p->pages->iov;
    struct zstd_data *z = p->data;
    int ret;
    uint32_t i;

    z->out.dst = z->zbuff;
    z->out.size = z->zbuff_len;
    z->out.pos = 0;

    for (i = 0; i < used; i++) {
        ZSTD_EndDirective flush = ZSTD_e_continue;

        if (i == used - 1) {
            flush = ZSTD_e_flush;
        }
        z->in.src = iov[i].iov_base;
        z->in.size = iov[i].iov_len;
        z->in.pos = 0;

        /*
         * Welcome to compressStream2 semantics
         *
         * We need to loop while:
         * - return is > 0
         * - there is input available
         * - there is output space free
         */
        do {
            ret = ZSTD_compressStream2(z->zcs, &z->out, &z->in, flush);
        } while (ret > 0 && (z->in.size - z->in.pos > 0)
                         && (z->out.size - z->out.pos > 0));
        if (ret > 0 && (z->in.size - z->in.pos > 0)) {
            error_setg(errp, "multifd %d: compressStream buffer too small",
                       p->id);
            return -1;
        }
        if (ZSTD_isError(ret)) {
            error_setg(errp, "multifd %d: compressStream error %s",
                       p->id, ZSTD_getErrorName(ret));
            return -1;
        }
    }
    p->next_packet_size = z->out.pos;
    p->flags |= MULTIFD_FLAG_ZSTD;

    return 0;
}

/**
 * zstd_send_write: do the actual write of the data
 *
 * Do the actual write of the comprresed buffer.
 *
 * Returns 0 for success or -1 for error
 *
 * @p: Params for the channel that we are using
 * @used: number of pages used
 * @errp: pointer to an error
 */
static int zstd_send_write(MultiFDSendParams *p, uint32_t used, Error **errp)
{
    struct zstd_data *z = p->data;

    return qio_channel_write_all(p->c, (void *)z->zbuff, p->next_packet_size,
                                 errp);
}

/**
 * zstd_recv_setup: setup receive side
 *
 * Create the compressed channel and buffer.
 *
 * Returns 0 for success or -1 for error
 *
 * @p: Params for the channel that we are using
 * @errp: pointer to an error
 */
static int zstd_recv_setup(MultiFDRecvParams *p, Error **errp)
{
    uint32_t page_count = MULTIFD_PACKET_SIZE / qemu_target_page_size();
    struct zstd_data *z = g_new0(struct zstd_data, 1);
    int ret;

    p->data = z;
    z->zds = ZSTD_createDStream();
    if (!z->zds) {
        g_free(z);
        error_setg(errp, "multifd %d: zstd createDStream failed", p->id);
        return -1;
    }

    ret = ZSTD_initDStream(z->zds);
    if (ZSTD_isError(ret)) {
        ZSTD_freeDStream(z->zds);
        g_free(z);
        error_setg(errp, "multifd %d: initDStream failed with error %s",
                   p->id, ZSTD_getErrorName(ret));
        return -1;
    }

    /* We will never have more than page_count pages */
    z->zbuff_len = page_count * qemu_target_page_size();
    /* We know compression "could" use more space */
    z->zbuff_len *= 2;
    z->zbuff = g_try_malloc(z->zbuff_len);
    if (!z->zbuff) {
        ZSTD_freeDStream(z->zds);
        g_free(z);
        error_setg(errp, "multifd %d: out of memory for zbuff", p->id);
        return -1;
    }
    return 0;
}

/**
 * zstd_recv_cleanup: setup receive side
 *
 * For no compression this function does nothing.
 *
 * @p: Params for the channel that we are using
 */
static void zstd_recv_cleanup(MultiFDRecvParams *p)
{
    struct zstd_data *z = p->data;

    ZSTD_freeDStream(z->zds);
    z->zds = NULL;
    g_free(z->zbuff);
    z->zbuff = NULL;
    g_free(p->data);
    p->data = NULL;
}

/**
 * zstd_recv_pages: read the data from the channel into actual pages
 *
 * Read the compressed buffer, and uncompress it into the actual
 * pages.
 *
 * Returns 0 for success or -1 for error
 *
 * @p: Params for the channel that we are using
 * @used: number of pages used
 * @errp: pointer to an error
 */
static int zstd_recv_pages(MultiFDRecvParams *p, uint32_t used, Error **errp)
{
    uint32_t in_size = p->next_packet_size;
    uint32_t out_size = 0;
    uint32_t expected_size = used * qemu_target_page_size();
    uint32_t flags = p->flags & MULTIFD_FLAG_COMPRESSION_MASK;
    struct zstd_data *z = p->data;
    int ret;
    int i;

    if (flags != MULTIFD_FLAG_ZSTD) {
        error_setg(errp, "multifd %d: flags received %x flags expected %x",
                   p->id, flags, MULTIFD_FLAG_ZSTD);
        return -1;
    }
    ret = qio_channel_read_all(p->c, (void *)z->zbuff, in_size, errp);

    if (ret != 0) {
        return ret;
    }

    z->in.src = z->zbuff;
    z->in.size = in_size;
    z->in.pos = 0;

    for (i = 0; i < used; i++) {
        struct iovec *iov = &p->pages->iov[i];

        z->out.dst = iov->iov_base;
        z->out.size = iov->iov_len;
        z->out.pos = 0;

        /*
         * Welcome to decompressStream semantics
         *
         * We need to loop while:
         * - return is > 0
         * - there is input available
         * - we haven't put out a full page
         */
        do {
            ret = ZSTD_decompressStream(z->zds, &z->out, &z->in);
        } while (ret > 0 && (z->in.size - z->in.pos > 0)
                         && (z->out.pos < iov->iov_len));
        if (ret > 0 && (z->out.pos < iov->iov_len)) {
            error_setg(errp, "multifd %d: decompressStream buffer too small",
                       p->id);
            return -1;
        }
        if (ZSTD_isError(ret)) {
            error_setg(errp, "multifd %d: decompressStream returned %s",
                       p->id, ZSTD_getErrorName(ret));
            return ret;
        }
        out_size += z->out.pos;
    }
    if (out_size != expected_size) {
        error_setg(errp, "multifd %d: packet size received %d size expected %d",
                   p->id, out_size, expected_size);
        return -1;
    }
    return 0;
}

static MultiFDMethods multifd_zstd_ops = {
    .send_setup = zstd_send_setup,
    .send_cleanup = zstd_send_cleanup,
    .send_prepare = zstd_send_prepare,
    .send_write = zstd_send_write,
    .recv_setup = zstd_recv_setup,
    .recv_cleanup = zstd_recv_cleanup,
    .recv_pages = zstd_recv_pages
};

static void multifd_zstd_register(void)
{
    multifd_register_ops(MULTIFD_COMPRESSION_ZSTD, &multifd_zstd_ops);
}

migration_init(multifd_zstd_register);
