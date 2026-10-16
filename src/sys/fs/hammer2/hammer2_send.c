/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2026 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This code is derived from software contributed to The NetBSD Foundation
 * by the HAMMER2 port project.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the same copyright
 *    notice in the binary distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Kernel-side PFS send support (zfs send analog).
 *
 * `hammer2 send` serializes a PFS as a stream of blockrefs and media
 * payloads.  The topology walk is performed here, in the kernel, over
 * the live chain layer (hammer2_chain_scan, the same machinery the
 * bulkfree pass uses), which gives two properties the userland offline
 * walker could not have:
 *
 * - The source PFS is PINNED for the duration of the session, so
 *   `hammer2 pfs-delete` fails with EBUSY while a send is in progress
 *   (prevention, not detection).
 * - Every emitted block passes the chain layer's check-code
 *   verification (hammer2_chain_testcheck on load) and an explicit
 *   re-verification here, so a concurrently modified topology can only
 *   fail the send cleanly (EIO), never produce a silently corrupt
 *   stream.  Held chain references keep the walked topology COW-frozen
 *   (point-in-time view), the same guarantee snapshots rely on.
 *
 * One session is keyed by (device, label); only the owning process may
 * drive it.  The session state survives across SEND_NEXT ioctls (frames
 * hold referenced chain nodes); it is reclaimed when the owning process
 * exits (reaped by a later SEND_START or an explicit SEND_FINISH from
 * any process) and unconditionally at device teardown
 * (hammer2_send_purge_dev, from hammer2_unmount_helper) so a killed
 * sender can never wedge an unmount or leak chain references.
 */

#include "hammer2.h"
#include "hammer2_ioctl.h"
#include "hammer2_xxhash.h"

#include <sys/sha2.h>

/*
 * Walk frames: one per recursion level.  Each frame owns a referenced
 * (between calls UNLOCKED) chain and the chain_scan resume cursor.
 */
typedef struct hammer2_send_frame {
	SLIST_ENTRY(hammer2_send_frame) entry;
	hammer2_chain_t		*chain;		/* referenced */
	hammer2_blockref_t	bref;		/* scan resume position */
	int			first;		/* chain_scan first flag */
} hammer2_send_frame_t;

/*
 * Seen-block set (dedup: a physical block may be referenced multiple
 * times within one PFS, e.g. via dedup or hardlink-like sharing).
 * Keyed by data_off including the radix bits.  The first occurrence of
 * a block is emitted; later references are skipped entirely (their
 * subtree, if any, was already emitted with the first one).
 */
#define HAMMER2_SEND_SEEN_HBITS	14
#define HAMMER2_SEND_SEEN_HSIZE	(1 << HAMMER2_SEND_SEEN_HBITS)

typedef struct hammer2_send_seen {
	struct hammer2_send_seen *next;
	hammer2_off_t		data_off;
} hammer2_send_seen_t;

typedef TAILQ_HEAD(hammer2_send_state_list, hammer2_send_state) \
	hammer2_send_state_list_t;

struct hammer2_send_state {
	TAILQ_ENTRY(hammer2_send_state) entry;
	hammer2_dev_t		*hmp;
	pid_t			pid;		/* owning process */
	uint32_t		flags;		/* HAMMER2_SENDF_* */
	char			label[NAME_MAX+1];
	int			ready;		/* START finished setup */
	int			active;		/* NEXT walk in progress */
	int			dead;		/* FINISH while active; free on release */
	int			done;		/* walk complete */
	int			error;		/* sticky walk error */
	int			depth;		/* frame stack depth */
	SLIST_HEAD(, hammer2_send_frame) frames;
	hammer2_send_seen_t	*seenhash[HAMMER2_SEND_SEEN_HSIZE];
	uint8_t			*rec_data;	/* record payload buffer */
	hammer2_blockref_t	rec_bref;
	uint32_t		rec_size;
	uint32_t		rec_flags;
	uint64_t		count_records;
	uint64_t		count_payload_bytes;
	/* stream header facts captured at START */
	struct uuid		pfs_clid;
	struct uuid		pfs_fsid;
	hammer2_tid_t		mirror_tid;
	hammer2_off_t		volu_size;
	hammer2_blockref_t	root_bref;
};

typedef struct hammer2_send_state hammer2_send_state_t;

/*
 * Pin: prevents `hammer2 pfs-delete` from destroying the source PFS
 * while a send session is active.  Keyed by (device, label) so the pin
 * survives independent pmp lifetime.  Guarded by hammer2_mntlk.
 */
typedef struct hammer2_send_pin {
	TAILQ_ENTRY(hammer2_send_pin) entry;
	hammer2_dev_t		*hmp;
	char			name[NAME_MAX+1];
	int			count;
} hammer2_send_pin_t;

typedef TAILQ_HEAD(hammer2_send_pin_list, hammer2_send_pin) \
	hammer2_send_pin_list_t;

static hammer2_send_state_list_t hammer2_send_states;
static hammer2_send_pin_list_t hammer2_send_pins;
static hammer2_lk_t hammer2_send_lk;

#define HAMMER2_SEND_MAX_DEPTH	16

static void hammer2_send_free(hammer2_send_state_t *, int have_mntlk);

void
hammer2_send_init(void)
{
	hammer2_lk_init(&hammer2_send_lk, "h2_send");
	TAILQ_INIT(&hammer2_send_states);
	TAILQ_INIT(&hammer2_send_pins);
}

void
hammer2_send_done(void)
{
	hammer2_lk_destroy(&hammer2_send_lk);
}

/*
 * Pin accounting.  Callers hold hammer2_mntlk exclusively.
 */
static hammer2_send_pin_t *
hammer2_send_pin_find(hammer2_dev_t *hmp, const char *name)
{
	hammer2_send_pin_t *pin;

	TAILQ_FOREACH(pin, &hammer2_send_pins, entry) {
		if (pin->hmp == hmp && strcmp(pin->name, name) == 0)
			return (pin);
	}
	return (NULL);
}

int
hammer2_send_pin_count(hammer2_dev_t *hmp, const char *name)
{
	hammer2_send_pin_t *pin = hammer2_send_pin_find(hmp, name);

	return (pin ? pin->count : 0);
}

static void
hammer2_send_pin_add(hammer2_dev_t *hmp, const char *name)
{
	hammer2_send_pin_t *pin = hammer2_send_pin_find(hmp, name);

	if (pin) {
		++pin->count;
		return;
	}
	pin = hmalloc(sizeof(*pin), M_HAMMER2, M_WAITOK | M_ZERO);
	pin->hmp = hmp;
	strlcpy(pin->name, name, sizeof(pin->name));
	pin->count = 1;
	TAILQ_INSERT_TAIL(&hammer2_send_pins, pin, entry);
}

static void
hammer2_send_pin_del(hammer2_dev_t *hmp, const char *name)
{
	hammer2_send_pin_t *pin = hammer2_send_pin_find(hmp, name);

	if (pin == NULL)
		return;
	if (--pin->count > 0)
		return;
	TAILQ_REMOVE(&hammer2_send_pins, pin, entry);
	hfree(pin, M_HAMMER2, sizeof(*pin));
}

/*
 * Verify a block's check code against `bytes' of media data.
 * Mirrors hammer2_chain_testcheck() (chain.c) without a chain object.
 * Returns 0 on match, EIO on mismatch/unsupported.
 */
static int
hammer2_send_testcheck(const hammer2_blockref_t *bref, const void *data,
    size_t bytes)
{
	SHA256_CTX hash_ctx;
	union {
		uint8_t		digest[SHA256_DIGEST_LENGTH];
		uint64_t	digest64[SHA256_DIGEST_LENGTH / 8];
	} u;
	uint32_t cv;
	uint64_t cv64;

	switch (HAMMER2_DEC_CHECK(bref->methods)) {
	case HAMMER2_CHECK_NONE:
	case HAMMER2_CHECK_DISABLED:
		return (0);
	case HAMMER2_CHECK_ISCSI32:
		cv = hammer2_icrc32(data, bytes);
		if (bref->check.iscsi32.value == cv)
			return (0);
		break;
	case HAMMER2_CHECK_XXHASH64:
		cv64 = XXH64(data, bytes, XXH_HAMMER2_SEED);
		if (bref->check.xxhash64.value == cv64)
			return (0);
		break;
	case HAMMER2_CHECK_SHA192:
		SHA256_Init(&hash_ctx);
		SHA256_Update(&hash_ctx, data, bytes);
		SHA256_Final(u.digest, &hash_ctx);
		/*
		 * Fold word 3 into word 2, then compare the first 24
		 * bytes (192 bits).  This must match the fold used by
		 * hammer2_chain_calc_check/testcheck and the userland
		 * fsck/recover/debug code, else valid SHA192 blocks
		 * fail verification.
		 */
		u.digest64[2] ^= u.digest64[3];
		if (memcmp(u.digest, bref->check.sha192.data,
			   sizeof(bref->check.sha192.data)) == 0)
			return (0);
		break;
	default:
		break;
	}
	return (EIO);
}

static inline uint32_t
hammer2_send_seen_hash(hammer2_off_t data_off)
{
	return (uint32_t)(data_off * 2654435761U) >>
	    (32 - HAMMER2_SEND_SEEN_HBITS);
}

static int
hammer2_send_seen_find(hammer2_send_state_t *st, hammer2_off_t data_off)
{
	hammer2_send_seen_t *e;

	for (e = st->seenhash[hammer2_send_seen_hash(data_off)]; e; e = e->next)
		if (e->data_off == data_off)
			return (1);
	return (0);
}

static void
hammer2_send_seen_add(hammer2_send_state_t *st, hammer2_off_t data_off)
{
	hammer2_send_seen_t *e;

	e = hmalloc(sizeof(*e), M_HAMMER2, M_WAITOK);
	e->data_off = data_off;
	e->next = st->seenhash[hammer2_send_seen_hash(data_off)];
	st->seenhash[hammer2_send_seen_hash(data_off)] = e;
}

/*
 * Read one block from the media, verify its check code, and stage it as
 * the current record.  `need_payload' is cleared for SKIP_PAYLOAD
 * sessions (brefs only); the block is still read+verified when the
 * classification requires it (inode DIRECTDATA flag).
 */
static int
hammer2_send_emit_block(hammer2_send_state_t *st,
    const hammer2_blockref_t *bref, int need_read)
{
	hammer2_io_t *dio;
	char *data;
	size_t bytes;
	int error, leaf;

	bytes = (size_t)1 << (bref->data_off & HAMMER2_OFF_MASK_RADIX);
	if ((bref->data_off & HAMMER2_OFF_MASK_RADIX) < HAMMER2_RADIX_MIN ||
	    (bref->data_off & HAMMER2_OFF_MASK_RADIX) > HAMMER2_RADIX_MAX) {
		return (EIO);
	}
	KKASSERT(bytes <= HAMMER2_PBUFSIZE);

	leaf = 0;
	if (bref->type == HAMMER2_BREF_TYPE_DATA ||
	    bref->type == HAMMER2_BREF_TYPE_DIRENT)
		leaf = 1;

	if (need_read) {
		error = hammer2_io_bread(st->hmp, bref->type, bref->data_off,
		    (int)bytes, &dio);
		if (error == 0 && dio->error)
			error = dio->error;
		if (error) {
			hammer2_io_bqrelse(&dio);
			return (EIO);
		}
		data = hammer2_io_data(dio, bref->data_off);
		error = hammer2_send_testcheck(bref, data, bytes);
		if (error == 0) {
			if ((st->flags & HAMMER2_SENDF_SKIP_PAYLOAD) == 0)
				memcpy(st->rec_data, data, bytes);
			if (bref->type == HAMMER2_BREF_TYPE_INODE &&
			    (((hammer2_inode_data_t *)data)->meta.op_flags &
			     HAMMER2_OPFLAG_DIRECTDATA))
				leaf = 1;
		}
		hammer2_io_brelse(&dio);
		if (error)
			return (error);
	}

	st->rec_bref = *bref;
	st->rec_size = (need_read &&
	    (st->flags & HAMMER2_SENDF_SKIP_PAYLOAD) == 0) ? (uint32_t)bytes : 0;
	st->rec_flags = leaf ? HAMMER2_SENDREC_LEAF : 0;
	++st->count_records;
	st->count_payload_bytes += st->rec_size;

	return (0);
}

/*
 * Advance the walk until the next record is staged.  Returns 0 with
 * st->rec_* filled, or 0 with HAMMER2_SENDREC_EOF when the walk is
 * complete.  Chain locks are not held on return (the record payload is
 * copied into st->rec_data under the locks).
 */
static int
hammer2_send_walk(hammer2_send_state_t *st)
{
	hammer2_send_frame_t *f;
	hammer2_chain_t *child;
	hammer2_blockref_t bref;
	hammer2_blockref_t pbref;
	hammer2_off_t boff;
	int error, e2;

	for (;;) {
		if (SLIST_EMPTY(&st->frames)) {
			st->done = 1;
			st->rec_bref.data_off = 0;
			st->rec_size = 0;
			st->rec_flags = HAMMER2_SENDREC_EOF;
			return (0);
		}
		f = SLIST_FIRST(&st->frames);
		error = hammer2_chain_lock(f->chain,
		    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
		if (error == 0 && f->chain->error)
			error = hammer2_error_to_errno(f->chain->error);
		if (error)
			return (error);

		/*
		 * Iterate the frame's children.  The cursor (f->bref,
		 * f->first) persists across SEND_NEXT calls.
		 */
		child = NULL;
		e2 = hammer2_chain_scan(f->chain, &child, &f->bref, &f->first,
		    HAMMER2_LOOKUP_NODATA | HAMMER2_LOOKUP_SHARED);
		/*
		 * Capture the frame's own bref while we still hold the
		 * chain lock (a concurrent chain_modify could re-COW it
		 * the instant we unlock).
		 */
		pbref = f->chain->bref;
		hammer2_chain_unlock(f->chain);

		if (e2 & HAMMER2_ERROR_EOF) {
			/*
			 * Frame complete: emit the frame's own block
			 * (post-order; the PFS root inode is emitted
			 * when the last frame pops).
			 */
			SLIST_REMOVE_HEAD(&st->frames, entry);
			--st->depth;
			error = hammer2_send_emit_block(st, &pbref,
			    (st->flags & HAMMER2_SENDF_SKIP_PAYLOAD) ?
			    0 : 1);
			hammer2_chain_drop(f->chain);
			hfree(f, M_HAMMER2, sizeof(*f));
			if (error)
				return (error);
			return (0);
		}
		if (e2 & ~HAMMER2_ERROR_EOF) {
			/*
			 * CHECK errors would have failed the frame's load
			 * above; anything else is a corrupt topology.
			 */
			return (EIO);
		}

		/*
		 * child is non-NULL only for recursable types (the scan
		 * does not instantiate chains for leaf types).  Release
		 * it unless we recurse into it below.
		 */
		bref = f->bref;
		boff = bref.data_off & ~HAMMER2_OFF_MASK_RADIX;
		if (boff == 0) {
			/*
			 * No media reference (embedded dirent name,
			 * zero-fill hole, or empty slot).  The parent's
			 * embedded copy carries everything.
			 */
			if (child) {
				hammer2_chain_unlock(child);
				hammer2_chain_drop(child);
			}
			continue;
		}
		if (hammer2_send_seen_find(st, bref.data_off)) {
			if (child) {
				hammer2_chain_unlock(child);
				hammer2_chain_drop(child);
			}
			continue;
		}

		if (child && (bref.type == HAMMER2_BREF_TYPE_INODE ||
			      bref.type == HAMMER2_BREF_TYPE_INDIRECT)) {
			/*
			 * Recurse.  The child's reference is transferred
			 * to the new frame (stored unlocked).
			 */
			f = hmalloc(sizeof(*f), M_HAMMER2,
			    M_WAITOK | M_ZERO);
			f->chain = child;
			f->first = 1;
			hammer2_chain_unlock(child);
			SLIST_INSERT_HEAD(&st->frames, f, entry);
			if (++st->depth > HAMMER2_SEND_MAX_DEPTH)
				return (EIO);
			hammer2_send_seen_add(st, bref.data_off);
			continue;
		}

		/*
		 * Leaf record: read, verify, stage.
		 */
		hammer2_send_seen_add(st, bref.data_off);
		if (child) {
			hammer2_chain_unlock(child);
			hammer2_chain_drop(child);
			child = NULL;
		}
		error = hammer2_send_emit_block(st, &bref,
		    (st->flags & HAMMER2_SENDF_SKIP_PAYLOAD) ?
		    (bref.type == HAMMER2_BREF_TYPE_INODE) : 1);
		if (error)
			return (error);
		return (0);
	}
}

/*
 * Find a session by (device, label).  Caller holds hammer2_send_lk.
 */
static hammer2_send_state_t *
hammer2_send_state_find(hammer2_dev_t *hmp, const char *label)
{
	hammer2_send_state_t *st;

	TAILQ_FOREACH(st, &hammer2_send_states, entry) {
		if (st->hmp == hmp && strcmp(st->label, label) == 0)
			return (st);
	}
	return (NULL);
}

/*
 * Return 1 if the process exists (a process executing one of our
 * ioctls is alive; NULL from proc_find means it has fully exited, so
 * none of its threads can be inside a send walk any more).
 */
static int
hammer2_send_proc_alive(pid_t pid)
{
	struct proc *p;

	mutex_enter(&proc_lock);
	p = proc_find(pid);
	mutex_exit(&proc_lock);
	return (p != NULL);
}

/*
 * Release a session's resources and its pin.  The session must already
 * have been removed from hammer2_send_states (unreachable).  May sleep;
 * hammer2_send_lk must NOT be held.  With have_mntlk the caller already
 * holds hammer2_mntlk (device teardown path).
 */
static void
hammer2_send_free(hammer2_send_state_t *st, int have_mntlk)
{
	hammer2_send_frame_t *f;
	hammer2_send_seen_t *e;
	int i;

	while (SLIST_FIRST(&st->frames) != NULL) {
		f = SLIST_FIRST(&st->frames);
		SLIST_REMOVE_HEAD(&st->frames, entry);
		hammer2_chain_drop(f->chain);
		hfree(f, M_HAMMER2, sizeof(*f));
	}
	for (i = 0; i < HAMMER2_SEND_SEEN_HSIZE; ++i) {
		while ((e = st->seenhash[i]) != NULL) {
			st->seenhash[i] = e->next;
			hfree(e, M_HAMMER2, sizeof(*e));
		}
	}
	if (st->rec_data)
		hfree(st->rec_data, M_HAMMER2, HAMMER2_PBUFSIZE);

	if (!have_mntlk)
		hammer2_lk_ex(&hammer2_mntlk);
	hammer2_send_pin_del(st->hmp, st->label);
	if (!have_mntlk)
		hammer2_lk_unlock(&hammer2_mntlk);

	hfree(st, M_HAMMER2, sizeof(*st));
}

/*
 * Free a list of sessions previously removed from hammer2_send_states
 * (by reap or a failed START).  Must be called without send_lk held.
 */
static void
hammer2_send_free_list(hammer2_send_state_list_t *freelist)
{
	hammer2_send_state_t *st;

	while ((st = TAILQ_FIRST(freelist)) != NULL) {
		TAILQ_REMOVE(freelist, st, entry);
		hammer2_send_free(st, 0);
	}
}

/*
 * Reclaim sessions whose owning process is gone.  Removed sessions are
 * queued on *freelist for the caller to hammer2_send_free() after
 * dropping hammer2_send_lk.  Caller holds hammer2_send_lk.
 */
static void
hammer2_send_reap(hammer2_dev_t *hmp, const char *label, pid_t pid,
    hammer2_send_state_list_t *freelist)
{
	hammer2_send_state_t *st, *next;

	TAILQ_FOREACH_SAFE(st, &hammer2_send_states, entry, next) {
		if (st->hmp != hmp || strcmp(st->label, label) != 0)
			continue;
		if (st->pid == pid)
			continue;
		if (hammer2_send_proc_alive(st->pid))
			continue;
		TAILQ_REMOVE(&hammer2_send_states, st, entry);
		TAILQ_INSERT_TAIL(freelist, st, entry);
	}
}

/*
 * Purge every session of a device being torn down (called from
 * hammer2_unmount_helper) so a killed sender cannot wedge the unmount
 * with held chain references or leak a stale pin keyed by a
 * soon-to-be-reused hammer2_dev_t pointer.  Callers hold
 * hammer2_mntlk inconsistently, so detect it.
 *
 * Invariant: no session may be mid-walk (->active) here.  An unmount
 * cannot proceed while a sender holds a live fd on the filesystem, so
 * only abandoned (owner-exited) sessions are normally seen.  Report
 * a violation rather than free a live walk silently.
 */
void
hammer2_send_purge_dev(hammer2_dev_t *hmp)
{
	hammer2_send_state_list_t freelist;
	hammer2_send_state_t *st, *next;
	int have_mntlk;

	TAILQ_INIT(&freelist);
	hammer2_lk_ex(&hammer2_send_lk);
	TAILQ_FOREACH_SAFE(st, &hammer2_send_states, entry, next) {
		if (st->hmp != hmp)
			continue;
		TAILQ_REMOVE(&hammer2_send_states, st, entry);
		TAILQ_INSERT_TAIL(&freelist, st, entry);
	}
	hammer2_lk_unlock(&hammer2_send_lk);

	have_mntlk = mutex_owned(&hammer2_mntlk);
	while ((st = TAILQ_FIRST(&freelist)) != NULL) {
		TAILQ_REMOVE(&freelist, st, entry);
		/*
		 * Defensive: freeing a session with a walk in progress
		 * would use-after-free the walker's state, and freeing one
		 * whose owner is still alive would drop its pin under it.
		 * Neither can happen for a quiesced unmount; report if it
		 * does.
		 */
		if (st->active)
			hprintf("hammer2_send_purge_dev: purging ACTIVE "
			    "session \"%s\"\n", st->label);
		else if (hammer2_send_proc_alive(st->pid))
			hprintf("hammer2_send_purge_dev: purging session "
			    "\"%s\" of live pid %d\n",
			    st->label, (int)st->pid);
		hammer2_send_free(st, have_mntlk);
	}
}

/*
 * HAMMER2IOC_SEND_START - resolve the PFS, pin it, initialize the walk.
 *
 * The session is inserted into the list up-front (as a !ready
 * placeholder) so the one-session-per-(device,label) invariant holds
 * even when two sends of the same label race the PFS lookup.
 */
int
hammer2_send_start(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_send_t *send = data;
	hammer2_send_state_list_t freelist;
	hammer2_send_state_t *st;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	hammer2_chain_t *chain, *parent;
	hammer2_send_frame_t *f;
	hammer2_key_t key_next, lhc;
	size_t len;
	int error;

	if (hmp == NULL)
		return (EINVAL);
	if (hmp->nvolumes != 1)
		return (EOPNOTSUPP);

	send->label[sizeof(send->label) - 1] = 0;
	len = strlen(send->label);
	if (len == 0)
		return (EINVAL);
	if (send->flags & ~HAMMER2_SENDF_SKIP_PAYLOAD)
		return (EINVAL);

	/*
	 * Allocate the session up front, then reserve the (device,label)
	 * key under the lock before the (sleeping) PFS lookup, so a
	 * concurrent START of the same label fails EBUSY instead of
	 * creating a second session.
	 */
	st = hmalloc(sizeof(*st), M_HAMMER2, M_WAITOK | M_ZERO);
	st->hmp = hmp;
	st->pid = curproc->p_pid;
	st->flags = send->flags;
	strlcpy(st->label, send->label, sizeof(st->label));
	SLIST_INIT(&st->frames);
	st->rec_data = hmalloc(HAMMER2_PBUFSIZE, M_HAMMER2, M_WAITOK);

	TAILQ_INIT(&freelist);
	hammer2_lk_ex(&hammer2_send_lk);
	hammer2_send_reap(hmp, send->label, curproc->p_pid, &freelist);
	if (hammer2_send_state_find(hmp, send->label) != NULL) {
		hammer2_lk_unlock(&hammer2_send_lk);
		/*
		 * The reservation was never pinned; do NOT go through
		 * hammer2_send_free(), whose pin_del is keyed by
		 * (device,label) and would release the LIVE session's
		 * pin.
		 */
		hfree(st->rec_data, M_HAMMER2, HAMMER2_PBUFSIZE);
		hfree(st, M_HAMMER2, sizeof(*st));
		error = EBUSY;
		goto out;
	}
	TAILQ_INSERT_TAIL(&hammer2_send_states, st, entry);
	hammer2_lk_unlock(&hammer2_send_lk);
	hammer2_send_free_list(&freelist);

	/*
	 * Pin the PFS label against pfs-delete for the session.  The
	 * lookup below does not need mntlk (chain locks serialize the
	 * topology), so mntlk is only held for the cheap list op.
	 */
	hammer2_lk_ex(&hammer2_mntlk);
	hammer2_send_pin_add(hmp, send->label);
	hammer2_lk_unlock(&hammer2_mntlk);

	/*
	 * Resolve the PFS root inode chain under the super-root.
	 */
	chain = NULL;
	parent = NULL;
	error = 0;
	hammer2_inode_lock(hmp->spmp->iroot, HAMMER2_RESOLVE_SHARED);
	parent = hammer2_inode_chain(hmp->spmp->iroot, 0,
	    HAMMER2_RESOLVE_ALWAYS | HAMMER2_RESOLVE_SHARED);
	lhc = hammer2_dirhash(send->label, len);
	chain = hammer2_chain_lookup(&parent, &key_next, lhc,
	    lhc + HAMMER2_DIRHASH_LOMASK, &error, HAMMER2_LOOKUP_SHARED);
	while (chain) {
		if (hammer2_chain_dirent_test(chain, send->label, len))
			break;
		chain = hammer2_chain_next(&parent, chain, &key_next,
		    lhc + HAMMER2_DIRHASH_LOMASK, &error,
		    HAMMER2_LOOKUP_SHARED);
	}
	error = hammer2_error_to_errno(error);

	if (chain == NULL) {
		if (error == 0)
			error = ENOENT;
	} else if (chain->error) {
		error = hammer2_error_to_errno(chain->error);
	} else if (chain->bref.type != HAMMER2_BREF_TYPE_INODE ||
	    (chain->data->ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) == 0) {
		error = EINVAL;
	}
	if (error) {
		if (chain) {
			hammer2_chain_unlock(chain);
			hammer2_chain_drop(chain);
		}
		if (parent) {
			hammer2_chain_unlock(parent);
			hammer2_chain_drop(parent);
		}
		hammer2_inode_unlock(hmp->spmp->iroot);

		/*
		 * Abandon the reservation (also drops the pin taken
		 * above).
		 */
		hammer2_lk_ex(&hammer2_send_lk);
		TAILQ_REMOVE(&hammer2_send_states, st, entry);
		hammer2_lk_unlock(&hammer2_send_lk);
		hammer2_send_free(st, 0);
		return (error);
	}

	/*
	 * Capture the stream header facts and build the walk.
	 */
	st->root_bref = chain->bref;
	st->pfs_clid = chain->data->ipdata.meta.pfs_clid;
	st->pfs_fsid = chain->data->ipdata.meta.pfs_fsid;
	st->mirror_tid = hmp->voldata.mirror_tid;
	st->volu_size = hmp->total_size;

	f = hmalloc(sizeof(*f), M_HAMMER2, M_WAITOK | M_ZERO);
	f->chain = chain;		/* reference transferred */
	f->first = 1;
	st->depth = 1;
	SLIST_INSERT_HEAD(&st->frames, f, entry);
	hammer2_chain_unlock(chain);

	if (parent) {
		hammer2_chain_unlock(parent);
		hammer2_chain_drop(parent);
	}
	hammer2_inode_unlock(hmp->spmp->iroot);

	hammer2_lk_ex(&hammer2_send_lk);
	st->ready = 1;
	hammer2_lk_unlock(&hammer2_send_lk);

	send->rec_flags = 0;
	send->rec_size = 0;
	send->root_bref = st->root_bref;
	send->pfs_clid = st->pfs_clid;
	send->pfs_fsid = st->pfs_fsid;
	send->mirror_tid = st->mirror_tid;
	send->volu_size = st->volu_size;

	return (0);
out:
	hammer2_send_free_list(&freelist);
	return (error);
}

/*
 * HAMMER2IOC_SEND_NEXT - return the next record.  EOF is reported via
 * HAMMER2_SENDREC_EOF (rec_size 0, bref zeroed).
 *
 * hammer2_send_lk only guards the session lookup/flags; the walk and
 * the copyout run WITHOUT any lock (the session is pinned by the
 * active flag, and a concurrent FINISH defers its free via ->dead).
 */
int
hammer2_send_next(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_send_t *send = data;
	hammer2_send_state_t *st;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	int dead, error;

	if (hmp == NULL)
		return (EINVAL);
	send->label[sizeof(send->label) - 1] = 0;

	hammer2_lk_ex(&hammer2_send_lk);
	st = hammer2_send_state_find(hmp, send->label);
	if (st == NULL || st->pid != curproc->p_pid ||
	    st->dead || !st->ready) {
		hammer2_lk_unlock(&hammer2_send_lk);
		return (ENOENT);
	}
	if (st->active) {
		hammer2_lk_unlock(&hammer2_send_lk);
		return (EBUSY);
	}
	st->active = 1;
	hammer2_lk_unlock(&hammer2_send_lk);

	if (st->done) {
		error = 0;
	} else if (st->error) {
		error = st->error;
	} else {
		error = hammer2_send_walk(st);
		if (error)
			st->error = error;
	}
	if (error == 0) {
		send->bref = st->rec_bref;
		send->rec_flags = st->rec_flags;
		send->rec_size = st->rec_size;
		if (st->rec_size)
			error = copyout(st->rec_data, send->payload,
			    st->rec_size);
	}

	hammer2_lk_ex(&hammer2_send_lk);
	st->active = 0;
	dead = st->dead;
	if (dead)
		TAILQ_REMOVE(&hammer2_send_states, st, entry);
	hammer2_lk_unlock(&hammer2_send_lk);
	if (dead)
		hammer2_send_free(st, 0);

	return (error);
}

/*
 * HAMMER2IOC_SEND_FINISH - release the session and its pin.  Only the
 * owning process may finish a live session (another process gets
 * EBUSY); a dead owner's session may be finished by anyone (also
 * reaped by the next SEND_START and at device teardown).
 */
int
hammer2_send_finish(hammer2_inode_t *ip, void *data)
{
	hammer2_ioc_send_t *send = data;
	hammer2_send_state_t *st;
	hammer2_dev_t *hmp = ip->pmp->pfs_hmps[0];
	int error = 0;

	if (hmp == NULL)
		return (EINVAL);
	send->label[sizeof(send->label) - 1] = 0;

	hammer2_lk_ex(&hammer2_send_lk);
	st = hammer2_send_state_find(hmp, send->label);
	if (st == NULL) {
		error = ENOENT;
	} else if (st->pid != curproc->p_pid &&
		   hammer2_send_proc_alive(st->pid)) {
		error = EBUSY;
	} else if (st->active) {
		/*
		 * A walk is in progress in the owning process; defer
		 * the release to the walk's epilogue.
		 */
		st->dead = 1;
	} else {
		TAILQ_REMOVE(&hammer2_send_states, st, entry);
		hammer2_lk_unlock(&hammer2_send_lk);
		hammer2_send_free(st, 0);
		return (0);
	}
	hammer2_lk_unlock(&hammer2_send_lk);

	return (error);
}
