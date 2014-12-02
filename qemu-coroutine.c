/*
 * QEMU coroutines
 *
 * Copyright IBM, Corp. 2011
 *
 * Authors:
 *  Stefan Hajnoczi    <stefanha@linux.vnet.ibm.com>
 *  Kevin Wolf         <kwolf@redhat.com>
 *
 * This work is licensed under the terms of the GNU LGPL, version 2 or later.
 * See the COPYING.LIB file in the top-level directory.
 *
 */

#include "trace.h"
#include "qemu-common.h"
#include "qemu/thread.h"
#include "qemu/atomic.h"
#include "block/coroutine.h"
#include "block/coroutine_int.h"

enum {
    POOL_BATCH_SIZE = 64,
};

/** Free list to speed up creation */
static QSLIST_HEAD(, Coroutine) release_pool = QSLIST_HEAD_INITIALIZER(pool);
static unsigned int release_pool_size;
static __thread QSLIST_HEAD(, Coroutine) alloc_pool = QSLIST_HEAD_INITIALIZER(pool);
static __thread unsigned int alloc_pool_size;
static __thread Notifier coroutine_pool_cleanup_notifier;

static void coroutine_pool_cleanup(Notifier *n, void *value)
{
    Coroutine *co;
    Coroutine *tmp;

    QSLIST_FOREACH_SAFE(co, &alloc_pool, pool_next, tmp) {
        QSLIST_REMOVE_HEAD(&alloc_pool, pool_next);
        qemu_coroutine_delete(co);
    }
}

Coroutine *qemu_coroutine_create(CoroutineEntry *entry)
{
    Coroutine *co = NULL;

    if (CONFIG_COROUTINE_POOL) {
        co = QSLIST_FIRST(&alloc_pool);
        if (!co) {
            if (release_pool_size > POOL_BATCH_SIZE) {
                /* Slow path; a good place to register the destructor, too.  */
                if (!coroutine_pool_cleanup_notifier.notify) {
                    coroutine_pool_cleanup_notifier.notify = coroutine_pool_cleanup;
                    qemu_thread_atexit_add(&coroutine_pool_cleanup_notifier);
                }

                /* This is not exact; there could be a little skew between
                 * release_pool_size and the actual size of release_pool.  But
                 * it is just a heuristic, it does not need to be perfect.
                 */
                alloc_pool_size = atomic_xchg(&release_pool_size, 0);
                QSLIST_MOVE_ATOMIC(&alloc_pool, &release_pool);
                co = QSLIST_FIRST(&alloc_pool);
            }
        }
        if (co) {
            QSLIST_REMOVE_HEAD(&alloc_pool, pool_next);
            alloc_pool_size--;
        }
    }

    if (!co) {
        co = qemu_coroutine_new();
    }

    co->entry = entry;
    QTAILQ_INIT(&co->co_queue_wakeup);
    return co;
}

static void coroutine_delete(Coroutine *co)
{
    co->caller = NULL;

    if (CONFIG_COROUTINE_POOL) {
        if (release_pool_size < POOL_BATCH_SIZE * 2) {
            QSLIST_INSERT_HEAD_ATOMIC(&release_pool, co, pool_next);
            atomic_inc(&release_pool_size);
            return;
        }
        if (alloc_pool_size < POOL_BATCH_SIZE) {
            QSLIST_INSERT_HEAD(&alloc_pool, co, pool_next);
            alloc_pool_size++;
            return;
        }
    }

    qemu_coroutine_delete(co);
}

static void coroutine_swap(Coroutine *from, Coroutine *to)
{
    CoroutineAction ret;

    ret = qemu_coroutine_switch(from, to, COROUTINE_YIELD);

    qemu_co_queue_run_restart(to);

    switch (ret) {
    case COROUTINE_YIELD:
        return;
    case COROUTINE_TERMINATE:
        trace_qemu_coroutine_terminate(to);
        coroutine_delete(to);
        return;
    default:
        abort();
    }
}

void qemu_coroutine_enter(Coroutine *co, void *opaque)
{
    Coroutine *self = qemu_coroutine_self();

    trace_qemu_coroutine_enter(self, co, opaque);

    if (co->caller) {
        fprintf(stderr, "Co-routine re-entered recursively\n");
        abort();
    }

    co->caller = self;
    co->entry_arg = opaque;
    coroutine_swap(self, co);
}

void coroutine_fn qemu_coroutine_yield(void)
{
    Coroutine *self = qemu_coroutine_self();
    Coroutine *to = self->caller;

    trace_qemu_coroutine_yield(self, to);

    if (!to) {
        fprintf(stderr, "Co-routine is yielding to no one\n");
        abort();
    }

    self->caller = NULL;
    coroutine_swap(self, to);
}
