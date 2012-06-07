/*
 * Simple C functions to supplement the C library
 *
 * Copyright (c) 2006 Fabrice Bellard
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
#include "host-utils.h"
#include <math.h>

#include "qemu_socket.h"
#include "iov.h"

void pstrcpy(char *buf, int buf_size, const char *str)
{
    int c;
    char *q = buf;

    if (buf_size <= 0)
        return;

    for(;;) {
        c = *str++;
        if (c == 0 || q >= buf + buf_size - 1)
            break;
        *q++ = c;
    }
    *q = '\0';
}

/* strcat and truncate. */
char *pstrcat(char *buf, int buf_size, const char *s)
{
    int len;
    len = strlen(buf);
    if (len < buf_size)
        pstrcpy(buf + len, buf_size - len, s);
    return buf;
}

int strstart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (*p != *q)
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}

int stristart(const char *str, const char *val, const char **ptr)
{
    const char *p, *q;
    p = str;
    q = val;
    while (*q != '\0') {
        if (qemu_toupper(*p) != qemu_toupper(*q))
            return 0;
        p++;
        q++;
    }
    if (ptr)
        *ptr = p;
    return 1;
}

/* XXX: use host strnlen if available ? */
int qemu_strnlen(const char *s, int max_len)
{
    int i;

    for(i = 0; i < max_len; i++) {
        if (s[i] == '\0') {
            break;
        }
    }
    return i;
}

time_t mktimegm(struct tm *tm)
{
    time_t t;
    int y = tm->tm_year + 1900, m = tm->tm_mon + 1, d = tm->tm_mday;
    if (m < 3) {
        m += 12;
        y--;
    }
    t = 86400 * (d + (153 * m - 457) / 5 + 365 * y + y / 4 - y / 100 + 
                 y / 400 - 719469);
    t += 3600 * tm->tm_hour + 60 * tm->tm_min + tm->tm_sec;
    return t;
}

int qemu_fls(int i)
{
    return 32 - clz32(i);
}

/*
 * Make sure data goes on disk, but if possible do not bother to
 * write out the inode just for timestamp updates.
 *
 * Unfortunately even in 2009 many operating systems do not support
 * fdatasync and have to fall back to fsync.
 */
int qemu_fdatasync(int fd)
{
#ifdef CONFIG_FDATASYNC
    return fdatasync(fd);
#else
    return fsync(fd);
#endif
}

/* io vectors */

void qemu_iovec_init(QEMUIOVector *qiov, int alloc_hint)
{
    qiov->iov = g_malloc(alloc_hint * sizeof(struct iovec));
    qiov->niov = 0;
    qiov->nalloc = alloc_hint;
    qiov->size = 0;
}

void qemu_iovec_init_external(QEMUIOVector *qiov, struct iovec *iov, int niov)
{
    int i;

    qiov->iov = iov;
    qiov->niov = niov;
    qiov->nalloc = -1;
    qiov->size = 0;
    for (i = 0; i < niov; i++)
        qiov->size += iov[i].iov_len;
}

void qemu_iovec_add(QEMUIOVector *qiov, void *base, size_t len)
{
    assert(qiov->nalloc != -1);

    if (qiov->niov == qiov->nalloc) {
        qiov->nalloc = 2 * qiov->nalloc + 1;
        qiov->iov = g_realloc(qiov->iov, qiov->nalloc * sizeof(struct iovec));
    }
    qiov->iov[qiov->niov].iov_base = base;
    qiov->iov[qiov->niov].iov_len = len;
    qiov->size += len;
    ++qiov->niov;
}

/*
 * Copies iovecs from src to the end of dst. It starts copying after skipping
 * the given number of bytes in src and copies until src is completely copied
 * or the total size of the copied iovec reaches size.The size of the last
 * copied iovec is changed in order to fit the specified total size if it isn't
 * a perfect fit already.
 */
void qemu_iovec_copy(QEMUIOVector *dst, QEMUIOVector *src, uint64_t skip,
    size_t size)
{
    int i;
    size_t done;
    void *iov_base;
    uint64_t iov_len;

    assert(dst->nalloc != -1);

    done = 0;
    for (i = 0; (i < src->niov) && (done != size); i++) {
        if (skip >= src->iov[i].iov_len) {
            /* Skip the whole iov */
            skip -= src->iov[i].iov_len;
            continue;
        } else {
            /* Skip only part (or nothing) of the iov */
            iov_base = (uint8_t*) src->iov[i].iov_base + skip;
            iov_len = src->iov[i].iov_len - skip;
            skip = 0;
        }

        if (done + iov_len > size) {
            qemu_iovec_add(dst, iov_base, size - done);
            break;
        } else {
            qemu_iovec_add(dst, iov_base, iov_len);
        }
        done += iov_len;
    }
}

void qemu_iovec_concat(QEMUIOVector *dst, QEMUIOVector *src, size_t size)
{
    qemu_iovec_copy(dst, src, 0, size);
}

void qemu_iovec_destroy(QEMUIOVector *qiov)
{
    assert(qiov->nalloc != -1);

    qemu_iovec_reset(qiov);
    g_free(qiov->iov);
    qiov->nalloc = 0;
    qiov->iov = NULL;
}

void qemu_iovec_reset(QEMUIOVector *qiov)
{
    assert(qiov->nalloc != -1);

    qiov->niov = 0;
    qiov->size = 0;
}

void qemu_iovec_to_buffer(QEMUIOVector *qiov, void *buf)
{
    uint8_t *p = (uint8_t *)buf;
    int i;

    for (i = 0; i < qiov->niov; ++i) {
        memcpy(p, qiov->iov[i].iov_base, qiov->iov[i].iov_len);
        p += qiov->iov[i].iov_len;
    }
}

size_t qemu_iovec_from_buf(QEMUIOVector *qiov, size_t offset,
                           const void *buf, size_t bytes)
{
    return iov_from_buf(qiov->iov, qiov->niov, offset, buf, bytes);
}

size_t qemu_iovec_memset(QEMUIOVector *qiov, size_t offset,
                         int fillc, size_t bytes)
{
    return iov_memset(qiov->iov, qiov->niov, offset, fillc, bytes);
}

/*
 * Checks if a buffer is all zeroes
 *
 * Attention! The len must be a multiple of 4 * sizeof(long) due to
 * restriction of optimizations in this function.
 */
bool buffer_is_zero(const void *buf, size_t len)
{
    /*
     * Use long as the biggest available internal data type that fits into the
     * CPU register and unroll the loop to smooth out the effect of memory
     * latency.
     */

    size_t i;
    long d0, d1, d2, d3;
    const long * const data = buf;

    assert(len % (4 * sizeof(long)) == 0);
    len /= sizeof(long);

    for (i = 0; i < len; i += 4) {
        d0 = data[i + 0];
        d1 = data[i + 1];
        d2 = data[i + 2];
        d3 = data[i + 3];

        if (d0 || d1 || d2 || d3) {
            return false;
        }
    }

    return true;
}

#ifndef _WIN32
/* Sets a specific flag */
int fcntl_setfl(int fd, int flag)
{
    int flags;

    flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        return -errno;

    if (fcntl(fd, F_SETFL, flags | flag) == -1)
        return -errno;

    return 0;
}
#endif

static int64_t suffix_mul(char suffix, int64_t unit)
{
    switch (qemu_toupper(suffix)) {
    case STRTOSZ_DEFSUFFIX_B:
        return 1;
    case STRTOSZ_DEFSUFFIX_KB:
        return unit;
    case STRTOSZ_DEFSUFFIX_MB:
        return unit * unit;
    case STRTOSZ_DEFSUFFIX_GB:
        return unit * unit * unit;
    case STRTOSZ_DEFSUFFIX_TB:
        return unit * unit * unit * unit;
    }
    return -1;
}

/*
 * Convert string to bytes, allowing either B/b for bytes, K/k for KB,
 * M/m for MB, G/g for GB or T/t for TB. End pointer will be returned
 * in *end, if not NULL. Return -1 on error.
 */
int64_t strtosz_suffix_unit(const char *nptr, char **end,
                            const char default_suffix, int64_t unit)
{
    int64_t retval = -1;
    char *endptr;
    unsigned char c;
    int mul_required = 0;
    double val, mul, integral, fraction;

    errno = 0;
    val = strtod(nptr, &endptr);
    if (isnan(val) || endptr == nptr || errno != 0) {
        goto fail;
    }
    fraction = modf(val, &integral);
    if (fraction != 0) {
        mul_required = 1;
    }
    c = *endptr;
    mul = suffix_mul(c, unit);
    if (mul >= 0) {
        endptr++;
    } else {
        mul = suffix_mul(default_suffix, unit);
        assert(mul >= 0);
    }
    if (mul == 1 && mul_required) {
        goto fail;
    }
    if ((val * mul >= INT64_MAX) || val < 0) {
        goto fail;
    }
    retval = val * mul;

fail:
    if (end) {
        *end = endptr;
    }

    return retval;
}

int64_t strtosz_suffix(const char *nptr, char **end, const char default_suffix)
{
    return strtosz_suffix_unit(nptr, end, default_suffix, 1024);
}

int64_t strtosz(const char *nptr, char **end)
{
    return strtosz_suffix(nptr, end, STRTOSZ_DEFSUFFIX_MB);
}

int qemu_parse_fd(const char *param)
{
    int fd;
    char *endptr = NULL;

    fd = strtol(param, &endptr, 10);
    if (*endptr || (fd == 0 && param == endptr)) {
        return -1;
    }
    return fd;
}

/*
 * Send/recv data with iovec buffers
 *
 * This function send/recv data from/to the iovec buffer directly.
 * The first `offset' bytes in the iovec buffer are skipped and next
 * `len' bytes are used.
 *
 * For example,
 *
 *   do_sendv_recvv(sockfd, iov, len, offset, 1);
 *
 * is equal to
 *
 *   char *buf = malloc(size);
 *   iov_to_buf(iov, iovcnt, buf, offset, size);
 *   send(sockfd, buf, size, 0);
 *   free(buf);
 */
static int do_sendv_recvv(int sockfd, struct iovec *iov, int len, int offset,
                          int do_sendv)
{
    int ret, diff, iovlen;
    struct iovec *last_iov;

    /* last_iov is inclusive, so count from one.  */
    iovlen = 1;
    last_iov = iov;
    len += offset;

    while (last_iov->iov_len < len) {
        len -= last_iov->iov_len;

        last_iov++;
        iovlen++;
    }

    diff = last_iov->iov_len - len;
    last_iov->iov_len -= diff;

    while (iov->iov_len <= offset) {
        offset -= iov->iov_len;

        iov++;
        iovlen--;
    }

    iov->iov_base = (char *) iov->iov_base + offset;
    iov->iov_len -= offset;

    {
#if defined CONFIG_IOVEC && defined CONFIG_POSIX
        struct msghdr msg;
        memset(&msg, 0, sizeof(msg));
        msg.msg_iov = iov;
        msg.msg_iovlen = iovlen;

        do {
            if (do_sendv) {
                ret = sendmsg(sockfd, &msg, 0);
            } else {
                ret = recvmsg(sockfd, &msg, 0);
            }
        } while (ret == -1 && errno == EINTR);
#else
        struct iovec *p = iov;
        ret = 0;
        while (iovlen > 0) {
            int rc;
            if (do_sendv) {
                rc = send(sockfd, p->iov_base, p->iov_len, 0);
            } else {
                rc = qemu_recv(sockfd, p->iov_base, p->iov_len, 0);
            }
            if (rc == -1) {
                if (errno == EINTR) {
                    continue;
                }
                if (ret == 0) {
                    ret = -1;
                }
                break;
            }
            if (rc == 0) {
                break;
            }
            ret += rc;
            iovlen--, p++;
        }
#endif
    }

    /* Undo the changes above */
    iov->iov_base = (char *) iov->iov_base - offset;
    iov->iov_len += offset;
    last_iov->iov_len += diff;
    return ret;
}

int qemu_recvv(int sockfd, struct iovec *iov, int len, int iov_offset)
{
    return do_sendv_recvv(sockfd, iov, len, iov_offset, 0);
}

int qemu_sendv(int sockfd, struct iovec *iov, int len, int iov_offset)
{
    return do_sendv_recvv(sockfd, iov, len, iov_offset, 1);
}

