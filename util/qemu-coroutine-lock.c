/*
 * coroutine queues and locks
 *
 * Copyright (c) 2011 Kevin Wolf <kwolf@redhat.com>
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
 *
 * The lock-free mutex implementation is based on OSv
 * (core/lfmutex.cc, include/lockfree/mutex.hh).
 * Copyright (C) 2013 Cloudius Systems, Ltd.
 */

#include "qemu/osdep.h"
#include "qemu-common.h"
#include "qemu/coroutine.h"
#include "qemu/coroutine_int.h"
#include "qemu/queue.h"
#include "block/aio.h"
#include "trace.h"

void qemu_co_queue_init(CoQueue *queue)
{
    QSIMPLEQ_INIT(&queue->entries);
}

void coroutine_fn qemu_co_queue_wait(CoQueue *queue)
{
    Coroutine *self = qemu_coroutine_self();
    QSIMPLEQ_INSERT_TAIL(&queue->entries, self, co_queue_next);
    qemu_coroutine_yield();
    assert(qemu_in_coroutine());
}

/**
 * qemu_co_queue_run_restart:
 *
 * Enter each coroutine that was previously marked for restart by
 * qemu_co_queue_next() or qemu_co_queue_restart_all().  This function is
 * invoked by the core coroutine code when the current coroutine yields or
 * terminates.
 */
void qemu_co_queue_run_restart(Coroutine *co)
{
    Coroutine *next;

    trace_qemu_co_queue_run_restart(co);
    while ((next = QSIMPLEQ_FIRST(&co->co_queue_wakeup))) {
        QSIMPLEQ_REMOVE_HEAD(&co->co_queue_wakeup, co_queue_next);
        qemu_coroutine_enter(next);
    }
}

static bool qemu_co_queue_do_restart(CoQueue *queue, bool single)
{
    Coroutine *next;

    if (QSIMPLEQ_EMPTY(&queue->entries)) {
        return false;
    }

    while ((next = QSIMPLEQ_FIRST(&queue->entries)) != NULL) {
        QSIMPLEQ_REMOVE_HEAD(&queue->entries, co_queue_next);
        aio_co_wake(next);
        if (single) {
            break;
        }
    }
    return true;
}

bool coroutine_fn qemu_co_queue_next(CoQueue *queue)
{
    assert(qemu_in_coroutine());
    return qemu_co_queue_do_restart(queue, true);
}

void coroutine_fn qemu_co_queue_restart_all(CoQueue *queue)
{
    assert(qemu_in_coroutine());
    qemu_co_queue_do_restart(queue, false);
}

bool qemu_co_enter_next(CoQueue *queue)
{
    Coroutine *next;

    next = QSIMPLEQ_FIRST(&queue->entries);
    if (!next) {
        return false;
    }

    QSIMPLEQ_REMOVE_HEAD(&queue->entries, co_queue_next);
    qemu_coroutine_enter(next);
    return true;
}

bool qemu_co_queue_empty(CoQueue *queue)
{
    return QSIMPLEQ_FIRST(&queue->entries) == NULL;
}

/* The wait records are handled with a multiple-producer, single-consumer
 * lock-free queue.  There cannot be two concurrent pop_waiter() calls
 * because pop_waiter() can only be called while mutex->handoff is zero.
 * This can happen in three cases:
 * - in qemu_co_mutex_unlock, before the hand-off protocol has started.
 *   In this case, qemu_co_mutex_lock will see mutex->handoff == 0 and
 *   not take part in the handoff.
 * - in qemu_co_mutex_lock, if it steals the hand-off responsibility from
 *   qemu_co_mutex_unlock.  In this case, qemu_co_mutex_unlock will fail
 *   the cmpxchg (it will see either 0 or the next sequence value) and
 *   exit.  The next hand-off cannot begin until qemu_co_mutex_lock has
 *   woken up someone.
 * - in qemu_co_mutex_unlock, if it takes the hand-off token itself.
 *   In this case another iteration starts with mutex->handoff == 0;
 *   a concurrent qemu_co_mutex_lock will fail the cmpxchg, and
 *   qemu_co_mutex_unlock will go back to case (1).
 *
 * The following functions manage this queue.
 */
typedef struct CoWaitRecord {
    Coroutine *co;
    QSLIST_ENTRY(CoWaitRecord) next;
} CoWaitRecord;

static void push_waiter(CoMutex *mutex, CoWaitRecord *w)
{
    w->co = qemu_coroutine_self();
    QSLIST_INSERT_HEAD_ATOMIC(&mutex->from_push, w, next);
}

static void move_waiters(CoMutex *mutex)
{
    QSLIST_HEAD(, CoWaitRecord) reversed;
    QSLIST_MOVE_ATOMIC(&reversed, &mutex->from_push);
    while (!QSLIST_EMPTY(&reversed)) {
        CoWaitRecord *w = QSLIST_FIRST(&reversed);
        QSLIST_REMOVE_HEAD(&reversed, next);
        QSLIST_INSERT_HEAD(&mutex->to_pop, w, next);
    }
}

static CoWaitRecord *pop_waiter(CoMutex *mutex)
{
    CoWaitRecord *w;

    if (QSLIST_EMPTY(&mutex->to_pop)) {
        move_waiters(mutex);
        if (QSLIST_EMPTY(&mutex->to_pop)) {
            return NULL;
        }
    }
    w = QSLIST_FIRST(&mutex->to_pop);
    QSLIST_REMOVE_HEAD(&mutex->to_pop, next);
    return w;
}

static bool has_waiters(CoMutex *mutex)
{
    return QSLIST_EMPTY(&mutex->to_pop) || QSLIST_EMPTY(&mutex->from_push);
}

void qemu_co_mutex_init(CoMutex *mutex)
{
    memset(mutex, 0, sizeof(*mutex));
}

static void coroutine_fn qemu_co_mutex_lock_slowpath(CoMutex *mutex)
{
    Coroutine *self = qemu_coroutine_self();
    CoWaitRecord w;
    unsigned old_handoff;

    trace_qemu_co_mutex_lock_entry(mutex, self);
    w.co = self;
    push_waiter(mutex, &w);

    /* This is the "Responsibility Hand-Off" protocol; a lock() picks from
     * a concurrent unlock() the responsibility of waking somebody up.
     */
    old_handoff = atomic_mb_read(&mutex->handoff);
    if (old_handoff &&
        has_waiters(mutex) &&
        atomic_cmpxchg(&mutex->handoff, old_handoff, 0) == old_handoff) {
        /* There can be no concurrent pops, because there can be only
         * one active handoff at a time.
         */
        CoWaitRecord *to_wake = pop_waiter(mutex);
        Coroutine *co = to_wake->co;
        if (co == self) {
            /* We got the lock ourselves!  */
            assert(to_wake == &w);
            return;
        }

        aio_co_wake(co);
    }

    qemu_coroutine_yield();
    trace_qemu_co_mutex_lock_return(mutex, self);
}

void coroutine_fn qemu_co_mutex_lock(CoMutex *mutex)
{
    Coroutine *self = qemu_coroutine_self();

    if (atomic_fetch_inc(&mutex->locked) == 0) {
        /* Uncontended.  */
        trace_qemu_co_mutex_lock_uncontended(mutex, self);
    } else {
        qemu_co_mutex_lock_slowpath(mutex);
    }
    mutex->holder = self;
    self->locks_held++;
}

void coroutine_fn qemu_co_mutex_unlock(CoMutex *mutex)
{
    Coroutine *self = qemu_coroutine_self();

    trace_qemu_co_mutex_unlock_entry(mutex, self);

    assert(mutex->locked);
    assert(mutex->holder == self);
    assert(qemu_in_coroutine());

    mutex->holder = NULL;
    self->locks_held--;
    if (atomic_fetch_dec(&mutex->locked) == 1) {
        /* No waiting qemu_co_mutex_lock().  Pfew, that was easy!  */
        return;
    }

    for (;;) {
        CoWaitRecord *to_wake = pop_waiter(mutex);
        unsigned our_handoff;

        if (to_wake) {
            Coroutine *co = to_wake->co;
            aio_co_wake(co);
            break;
        }

        /* Some concurrent lock() is in progress (we know this because
         * mutex->locked was >1) but it hasn't yet put itself on the wait
         * queue.  Pick a sequence number for the handoff protocol (not 0).
         */
        if (++mutex->sequence == 0) {
            mutex->sequence = 1;
        }

        our_handoff = mutex->sequence;
        atomic_mb_set(&mutex->handoff, our_handoff);
        if (!has_waiters(mutex)) {
            /* The concurrent lock has not added itself yet, so it
             * will be able to pick our handoff.
             */
            break;
        }

        /* Try to do the handoff protocol ourselves; if somebody else has
         * already taken it, however, we're done and they're responsible.
         */
        if (atomic_cmpxchg(&mutex->handoff, our_handoff, 0) != our_handoff) {
            break;
        }
    }

    trace_qemu_co_mutex_unlock_return(mutex, self);
}

void qemu_co_rwlock_init(CoRwlock *lock)
{
    memset(lock, 0, sizeof(*lock));
    qemu_co_queue_init(&lock->queue);
}

void qemu_co_rwlock_rdlock(CoRwlock *lock)
{
    Coroutine *self = qemu_coroutine_self();

    while (lock->writer) {
        qemu_co_queue_wait(&lock->queue);
    }
    lock->reader++;
    self->locks_held++;
}

void qemu_co_rwlock_unlock(CoRwlock *lock)
{
    Coroutine *self = qemu_coroutine_self();

    assert(qemu_in_coroutine());
    if (lock->writer) {
        lock->writer = false;
        qemu_co_queue_restart_all(&lock->queue);
    } else {
        lock->reader--;
        assert(lock->reader >= 0);
        /* Wakeup only one waiting writer */
        if (!lock->reader) {
            qemu_co_queue_next(&lock->queue);
        }
    }
    self->locks_held--;
}

void qemu_co_rwlock_wrlock(CoRwlock *lock)
{
    Coroutine *self = qemu_coroutine_self();

    while (lock->writer || lock->reader) {
        qemu_co_queue_wait(&lock->queue);
    }
    lock->writer = true;
    self->locks_held++;
}
