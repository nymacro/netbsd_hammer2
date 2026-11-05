/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2022 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of The DragonFly Project nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific, prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _FS_HAMMER2_COMPAT_H_
#define _FS_HAMMER2_COMPAT_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/cdefs.h>
#include <sys/stdint.h>
#include <sys/atomic.h>
#include <sys/lwp.h>
#include <sys/rwlock.h>

#include <machine/cpufunc.h>

/* Taken from sys/sys/cdefs.h in FreeBSD. */
#define __DECONST(type, var)	((type)(__uintptr_t)(const void *)(var))

/* Emulate INVARIANTS in FreeBSD. */
#if 1
#define INVARIANTS	DIAGNOSTIC
#else
#define INVARIANTS	DEBUG
#endif

/* DragonFly KKASSERT is NetBSD KASSERT equivalent. */
#define KKASSERT	KASSERT

/* ia64 seems to have these defined. */
#define atomic_set_int(p, v)	atomic_or_uint((p), (v))
#define atomic_clear_int(p, v)	atomic_and_uint((p), ~(v))

#define atomic_set_32(p, v)	atomic_set_int((p), (v))

#define atomic_set_64(p, v)	atomic_or_64((p), (v))
#define atomic_clear_64(p, v)	atomic_and_64((p), ~(v))

#define atomic_cmpset_int(ptr, old, new)	\
	(atomic_cas_uint((ptr), (old), (new)) == (old))

#define atomic_cmpset_32(ptr, old, new)	\
	(atomic_cas_32((ptr), (old), (new)) == (old))

#define atomic_cmpset_64(ptr, old, new)	\
	(atomic_cas_64((ptr), (old), (new)) == (old))

static __inline unsigned int
atomic_fetchadd_int(volatile unsigned int *p, unsigned int v)
{
	unsigned int value;

	do {
		value = *p;
	} while (!atomic_cmpset_int(p, value, value + v));
	return (value);
}

static __inline uint32_t
atomic_fetchadd_32(volatile uint32_t *p, uint32_t v)
{
	uint32_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_32(p, value, value + v));
	return (value);
}

static __inline uint64_t
atomic_fetchadd_64(volatile uint64_t *p, uint64_t v)
{
	uint64_t value;

	do {
		value = *p;
	} while (!atomic_cmpset_64(p, value, value + v));
	return (value);
}

/* XXX NetBSD only has arch dependent function. */
#if defined(__i386__) || defined(__x86_64__)
#define cpu_pause()	x86_pause()
#else
#define cpu_pause()	do {} while (0)
#endif

#define cpu_ccfence()	__insn_barrier()

#define bqrelse(bp, n)	brelse(bp, n)

/*
 * Mutex compatibility shim: hammer2_mtx_t over rwlock(9).
 *
 * DragonFly hammer2 treats mtx_lock_ex()/mtx_lock_sh() as recursive
 * ("Recursion is allowed", sys/sys/mutex2.h), and the upstream locking
 * code relies on the exclusive half of that contract: rwlock(9) instead
 * forbids recursive acquisition outright ("locking against myself"), so
 * exclusive recursion is emulated here.  The owner LWP and its recursion
 * depth are recorded alongside the rwlock, a nested exclusive acquisition
 * by that owner only bumps refs, and only the last unlock releases the
 * rwlock.  This gives upstream hammer2 its exact hammer2_mtx_refs()
 * meaning ("exclusive recursion depth of the caller", 0 for non-owners)
 * and removes the class of port-local interleaving fixes that existed
 * only to avoid re-acquiring a lock the caller already held (e.g. the
 * syncer's VOP_INACTIVE path).
 *
 * The spin, lock and condvar helpers that share the same rwlock(9)
 * primitive stay in hammer2_os.h, together with the rest of the OS glue.
 * Shared mode is deliberately NOT recursion-emulated: it stays a strict
 * rw_enter(RW_READER), exactly as before.  Upstream tracks no per-LWP
 * shared recursion count either (a shared recursive acquire is just the
 * bare shared count, with the same "a queued writer can deadlock it"
 * caveat rwlock(9) documents), and NetBSD rwlock has no per-reader
 * tracking primitive to build on.
 *
 * Memory ordering and atomics: owner/refs are written ONLY by the LWP
 * that is (or becomes) the exclusive owner -- owner after rw_enter()
 * succeeds and before rw_exit(), refs only while owner still names the
 * current LWP.  `refs` is therefore single-writer state: no other LWP can
 * ever update it (doing so would require owning the mutex, which is
 * impossible while someone else does), so an atomic RMW would add a
 * locked operation per acquisition and buy nothing -- a concurrent writer
 * would be a logic bug that atomicity would merely hide.  For the same
 * reason hammer2_mtx_refs() hands the exact depth only to the owner and
 * derives "held by anyone" from rw_lock_held() for everyone else, so no
 * foreign LWP ever reads refs.
 * For `owner`, every reader compares it against its OWN curlwp and no LWP
 * ever stores another LWP's pointer there, so a racy load can never
 * produce a false positive (a non-owner sees a non-matching or stale
 * pointer and takes the slow path), and the owner itself is the only
 * writer, so it can never see a false negative (its own accesses are
 * same-thread ordered).  Cross-thread visibility of the lock itself is
 * provided by rw_enter()/rw_exit().  Plain loads/stores are therefore
 * sufficient -- no atomics or barriers are needed.
 *
 * Lockdebug/LOCKDEBUG coverage for the conflict class is unchanged (real
 * acquisitions still go through rw_enter/rw_exit); nested acquisitions
 * are, by design, invisible to lockdebug, just like upstream's
 * count-based recursion.
 *
 * Chain locks (hammer2_chain_t.lock) use this same shim but carry their
 * own lockcnt/LOCKAGAIN accounting (hammer2_chain.c): the recursive fast
 * path here makes a same-LWP re-acquire harmless instead of a panic,
 * which matches upstream.  The LOCKAGAIN self-credit machinery remains
 * in place and is independent of this file.
 */
struct krwlock_t_wrapper {
	krwlock_t lock;
	struct lwp *owner;	/* exclusive owner LWP, NULL otherwise */
	int refs;		/* exclusive recursion depth (owner only) */
};
typedef struct krwlock_t_wrapper hammer2_mtx_t;

static __inline void
hammer2_mtx_init(hammer2_mtx_t *p, const char *s)
{
	bzero(p, sizeof(*p));
	rw_init(&p->lock);
}

/*
 * Upstream equivalent: mtx_lock_ex_quick()/_mtx_lock_ex() (a nested
 * acquisition by the owner increments the count and returns).
 */
static __inline void
hammer2_mtx_ex(hammer2_mtx_t *p)
{
	/* Recursive acquisition by the owner: only the depth changes. */
	if (p->owner == curlwp) {
		++p->refs;
		return;
	}
	rw_enter(&p->lock, RW_WRITER);
	p->owner = curlwp;
	p->refs = 1;
}

static __inline void
hammer2_mtx_sh(hammer2_mtx_t *p)
{
	/* No recursion emulation (see the shim comment above). */
	rw_enter(&p->lock, RW_READER);
}

/*
 * Upstream equivalent: mtx_unlock(), which consumes exactly one exclusive
 * count (or one shared count) per call.
 */
static __inline void
hammer2_mtx_unlock(hammer2_mtx_t *p)
{
	if (p->owner == curlwp) {
		/* Exclusive unlock: consume one recursion level. */
		KKASSERT(p->refs > 0);
		if (p->refs > 1) {
			--p->refs;
			return;
		}
		p->refs = 0;
		p->owner = NULL;
	}
	/* Shared unlock, or the final exclusive unlock, releases the mtx. */
	rw_exit(&p->lock);
}

/*
 * Lock count -- upstream mtx_lockrefs() equivalent for the caller's own
 * exclusive hold.  The precise recursion depth is returned only to the LWP
 * that owns the lock: refs is written exclusively by that owner (nested
 * acquires/unlocks are same-thread ops), so it is owner-private state and
 * needs NO atomics -- a foreign RMW cannot happen without a logic bug that
 * atomicity would only hide.  Everyone else gets "held by anyone" (1),
 * derived from the authoritative rwlock state via rw_lock_held(), which
 * also covers the window between rw_enter() and the owner publication
 * (p->owner not yet stored).
 *
 * That is sufficient for both callers: hammer2_inode_lock() tests >1 right
 * after acquiring exclusively (owner path, exact depth), and the inode
 * destruction KASSERT only asks whether the lock is completely free.
 * (Upstream would report a foreign owner's raw count here; the shim
 * deliberately does not read another LWP's refs.)
 */
static __inline int
hammer2_mtx_refs(hammer2_mtx_t *p)
{
	if (p->owner == curlwp)
		return (p->refs);
	return (rw_lock_held(&p->lock) ? 1 : 0);
}

static __inline void
hammer2_mtx_destroy(hammer2_mtx_t *p)
{
	rw_destroy(&p->lock);
}

/*
 * Non-zero if exclusively locked by the calling thread -- upstream
 * mtx_owned(), i.e. it stays true across nested acquisitions (the rwlock
 * itself is held exactly once).
 */
static __inline int
hammer2_mtx_owned(hammer2_mtx_t *p)
{
	return (p->owner == curlwp);
}

/*
 * Non-zero if the read lock is held (by anyone; rwlock(9) exposes no
 * per-reader tracking, which is also why shared recursion is not
 * emulated).  Diagnostic use only.
 */
static __inline int
hammer2_mtx_sh_held(hammer2_mtx_t *p)
{
	return (rw_read_held(&p->lock));
}

#ifdef INVARIANTS
/*
 * assert_ex must mean "exclusively held by ME": under recursion the
 * rwlock is held once no matter how deep the exclusive recursion is, so a
 * lock-state test is not sufficient to prove this thread owns it (and a
 * recursive acquisition must still satisfy the assertion).
 */
static __inline void
hammer2_mtx_assert_ex(hammer2_mtx_t *p)
{
	KASSERT(hammer2_mtx_owned(p));
}

static __inline void
hammer2_mtx_assert_sh(hammer2_mtx_t *p)
{
	KASSERT(rw_read_held(&p->lock));
}

static __inline void
hammer2_mtx_assert_locked(hammer2_mtx_t *p)
{
	KASSERT(rw_lock_held(&p->lock));
}

static __inline void
hammer2_mtx_assert_unlocked(hammer2_mtx_t *p)
{
	KASSERT(!rw_lock_held(&p->lock));
}
#else
#define hammer2_mtx_assert_ex(p)	do {} while (0)
#define hammer2_mtx_assert_sh(p)	do {} while (0)
#define hammer2_mtx_assert_locked(p)	do {} while (0)
#define hammer2_mtx_assert_unlocked(p)	do {} while (0)
#endif

/*
 * Upstream equivalent: mtx_lock_ex_try().  Recursion is allowed there too
 * (_mtx_lock_ex_try() bumps the count when mtx_owner == curthread); plain
 * rw_tryenter() would instead report failure for a self-held lock.
 */
static __inline int
hammer2_mtx_ex_try(hammer2_mtx_t *p)
{
	/* Recursive acquisition by the owner always succeeds. */
	if (p->owner == curlwp) {
		++p->refs;
		return (0);
	}
	if (rw_tryenter(&p->lock, RW_WRITER)) {
		p->owner = curlwp;
		p->refs = 1;
		return (0);
	} else {
		return (1);
	}
}

/*
 * Upstream equivalent: mtx_lock_sh_try(), which fails (EAGAIN) when the
 * lock is already held exclusively -- including by the caller.
 * rw_tryenter(RW_READER) fails in that case as well, so no extra test is
 * needed.
 */
static __inline int
hammer2_mtx_sh_try(hammer2_mtx_t *p)
{
	if (rw_tryenter(&p->lock, RW_READER)) {
		return (0);
	} else {
		return (1);
	}
}

/*
 * Upstream equivalent: mtx_upgrade_try().  It fails unless the shared
 * count is exactly 1, and it SUCCEEDS without changing the count when the
 * caller already holds the lock exclusively.
 */
static __inline int
hammer2_mtx_upgrade_try(hammer2_mtx_t *p)
{
	/*
	 * Already exclusively ours: nothing to upgrade (and rw_tryupgrade()
	 * panics with DIAGNOSTIC if the lock is already ex-locked).
	 */
	if (p->owner == curlwp)
		return (0);

	if (rw_tryupgrade(&p->lock)) {
		/* Now the exclusive owner of the upgraded read lock. */
		p->owner = curlwp;
		p->refs = 1;
		return (0);
	} else {
		return (1);
	}
}

static __inline int
hammer2_mtx_temp_release(hammer2_mtx_t *p)
{
	int x;

	x = hammer2_mtx_owned(p);
	hammer2_mtx_unlock(p);

	return (x);
}

static __inline void
hammer2_mtx_temp_restore(hammer2_mtx_t *p, int x)
{
	if (x)
		hammer2_mtx_ex(p);
	else
		hammer2_mtx_sh(p);
}

/*
 * Bounded self-test for the exclusive-recursion shim (DIAGNOSTIC only).
 * Called once from hammer2_init(); a failure means the shim itself is
 * broken (barrier/owner bookkeeping), not a caller, so it panics at
 * module/kernel init instead of corrupting lock state later.  Prints a
 * single breadcrumb on success.
 */
#ifdef DIAGNOSTIC
static __inline void
hammer2_mtx_selftest(void)
{
	hammer2_mtx_t m;
	int ok = 1;

	hammer2_mtx_init(&m, "h2selftest");
	if (m.owner != NULL || m.refs != 0)
		ok = 0;
	if (hammer2_mtx_owned(&m) || hammer2_mtx_refs(&m) != 0)
		ok = 0;

	/* First exclusive acquisition is a real rw_enter(). */
	hammer2_mtx_ex(&m);
	if (m.owner != curlwp || m.refs != 1)
		ok = 0;
	if (!hammer2_mtx_owned(&m) || hammer2_mtx_refs(&m) != 1)
		ok = 0;

	/* Nested acquisition: depth only, still owned. */
	hammer2_mtx_ex(&m);
	if (m.owner != curlwp || m.refs != 2)
		ok = 0;
	if (!hammer2_mtx_owned(&m) || hammer2_mtx_refs(&m) != 2)
		ok = 0;

	/* Nested unlock does not release; the outer one does. */
	hammer2_mtx_unlock(&m);
	if (m.owner != curlwp || m.refs != 1)
		ok = 0;
	hammer2_mtx_unlock(&m);
	if (m.owner != NULL || m.refs != 0)
		ok = 0;
	if (hammer2_mtx_owned(&m) || hammer2_mtx_refs(&m) != 0)
		ok = 0;

	/* Shared acquisition must not disturb exclusive bookkeeping. */
	hammer2_mtx_sh(&m);
	if (m.owner != NULL || m.refs != 0)
		ok = 0;
	if (hammer2_mtx_owned(&m) || hammer2_mtx_refs(&m) != 1)
		ok = 0;
	hammer2_mtx_unlock(&m);
	if (hammer2_mtx_sh_held(&m) || m.owner != NULL || m.refs != 0)
		ok = 0;
	if (hammer2_mtx_refs(&m) != 0)
		ok = 0;

	/* try/upgrade variants must maintain the same bookkeeping. */
	if (hammer2_mtx_ex_try(&m) != 0 || m.owner != curlwp || m.refs != 1)
		ok = 0;
	if (hammer2_mtx_ex_try(&m) != 0 || m.refs != 2)
		ok = 0;
	hammer2_mtx_unlock(&m);
	hammer2_mtx_unlock(&m);
	if (m.owner != NULL || m.refs != 0)
		ok = 0;

	hammer2_mtx_sh(&m);
	if (hammer2_mtx_upgrade_try(&m) != 0 || m.owner != curlwp || m.refs != 1)
		ok = 0;
	hammer2_mtx_unlock(&m);
	if (m.owner != NULL || m.refs != 0)
		ok = 0;

	hammer2_mtx_destroy(&m);

	if (ok)
		printf("hammer2: recursive mtx shim self-test OK\n");
	else
		panic("hammer2: recursive mtx shim self-test FAILED");
}
#else
#define hammer2_mtx_selftest()	do {} while (0)
#endif

#endif /* !_FS_HAMMER2_COMPAT_H_ */
