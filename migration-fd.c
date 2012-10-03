/*
 * QEMU live migration via generic fd
 *
 * Copyright Red Hat, Inc. 2009
 *
 * Authors:
 *  Chris Lalancette <clalance@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 * Contributions after 2012-01-13 are licensed under the terms of the
 * GNU GPL, version 2 or (at your option) any later version.
 */

#include "qemu-common.h"
#include "qemu/sockets.h"
#include "migration/migration.h"
#include "monitor/monitor.h"
#include "migration/qemu-file.h"
#include "block/block.h"
#include "qemu/sockets.h"

//#define DEBUG_MIGRATION_FD

#ifdef DEBUG_MIGRATION_FD
#define DPRINTF(fmt, ...) \
    do { printf("migration-fd: " fmt, ## __VA_ARGS__); } while (0)
#else
#define DPRINTF(fmt, ...) \
    do { } while (0)
#endif

static int fd_errno(MigrationState *s)
{
    return errno;
}

static int fd_write(MigrationState *s, const void * buf, size_t size)
{
    return write(s->fd, buf, size);
}

static int fd_close(MigrationState *s)
{
    struct stat st;
    int ret;

    DPRINTF("fd_close\n");
    ret = fstat(s->fd, &st);
    if (ret == 0 && S_ISREG(st.st_mode)) {
        /*
         * If the file handle is a regular file make sure the
         * data is flushed to disk before signaling success.
         */
        ret = fsync(s->fd);
        if (ret != 0) {
            ret = -errno;
            perror("migration-fd: fsync");
            return ret;
        }
    }
    ret = close(s->fd);
    s->fd = -1;
    if (ret != 0) {
        ret = -errno;
        perror("migration-fd: close");
    }
    return ret;
}

void fd_start_outgoing_migration(MigrationState *s, const char *fdname, Error **errp)
{
    s->fd = monitor_get_fd(cur_mon, fdname, errp);
    if (s->fd == -1) {
        return;
    }

    fcntl(s->fd, F_SETFL, O_NONBLOCK);
    s->get_error = fd_errno;
    s->write = fd_write;
    s->close = fd_close;

    migrate_fd_connect(s);
}

static void fd_accept_incoming_migration(void *opaque)
{
    QEMUFile *f = opaque;

    qemu_set_fd_handler2(qemu_get_fd(f), NULL, NULL, NULL, NULL);
    process_incoming_migration(f);
}

void fd_start_incoming_migration(const char *infd, Error **errp)
{
    int fd;
    QEMUFile *f;

    DPRINTF("Attempting to start an incoming migration via fd\n");

    fd = strtol(infd, NULL, 0);
    f = qemu_fdopen(fd, "rb");
    if(f == NULL) {
        error_setg_errno(errp, errno, "failed to open the source descriptor");
        return;
    }

    qemu_set_fd_handler2(fd, NULL, fd_accept_incoming_migration, NULL, f);
}
