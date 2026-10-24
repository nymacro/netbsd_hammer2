/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2013-2023 The DragonFly Project.  All rights reserved.
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

#include "hammer2.h"

#include <sys/lwp.h> /* curlwp */
#include <uvm/uvm.h> /* curlwp == uvm.pagedaemon_lwp */

#define HAMMER2_DOP_READ	1
#define HAMMER2_DOP_NEW		2
#define HAMMER2_DOP_NEWNZ	3
#define HAMMER2_DOP_READQ	4

/*
 * Implements an abstraction layer for synchronous and asynchronous
 * buffered device I/O.  Can be used as an OS-abstraction but the main
 * purpose is to allow larger buffers to be used against hammer2_chain's
 * using smaller allocations, without causing deadlocks.
 *
 * The DIOs also record temporary state with limited persistence.  This
 * feature is used to keep track of dedupable blocks.
 */
static hammer2_io_t *hammer2_io_hash_lookup(hammer2_dev_t *, hammer2_off_t,
    uint64_t *);
static hammer2_io_t *hammer2_io_hash_enter(hammer2_dev_t *, hammer2_io_t *,
    uint64_t *);
static void hammer2_io_hash_cleanup(hammer2_dev_t *, int);

static __inline void
hammer2_assert_io_refs(hammer2_io_t *dio)
{
	KKASSERT(dio);
	KKASSERT((dio->refs & HAMMER2_DIO_MASK) != 0);
}

/*
 * Wait for an INPROG owner (I/O or lastdrop disposal) to finish.
 *
 * WAITING is registered under waitlk after re-checking INPROG, so a
 * wakeup that races our registration can at worst cost one hz timeout
 * (upstream's exact envelope with tsleep(hz)); the re-check under the
 * mutex removes the common case of sleeping after the owner already
 * finished.
 */
static __inline void
hammer2_io_wait(hammer2_io_t *dio)
{
	hammer2_lk_ex(&dio->waitlk);
	if (dio->refs & HAMMER2_DIO_INPROG) {
		atomic_set_32(&dio->refs, HAMMER2_DIO_WAITING);
		hammer2_lkc_sleep(&dio->cv, &dio->waitlk, "h2dio", hz);
	}
	hammer2_lk_unlock(&dio->waitlk);
}

/*
 * Wake waiters after an INPROG-clearing cmpset succeeded.  orefs is the
 * value read by the successful cmpset: a WAITING set after that instant
 * cannot happen (INPROG is already clear) and would have made the
 * cmpset fail anyway, so the gate is exact.
 */
static __inline void
hammer2_io_wakeup(hammer2_io_t *dio, uint32_t orefs)
{
	if (orefs & HAMMER2_DIO_WAITING) {
		hammer2_lk_ex(&dio->waitlk);
		hammer2_lkc_wakeup(&dio->cv);
		hammer2_lk_unlock(&dio->waitlk);
	}
}

void
hammer2_io_hash_init(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		hammer2_spin_init(&hash->spin, "h2dev_io");
	}
}

void
hammer2_io_hash_destroy(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	int i;

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		hammer2_spin_destroy(&hash->spin);
	}
}

/*
 * Returns the DIO corresponding to the data|radix, creating it if necessary.
 *
 * If createit is 0, NULL can be returned indicating that the DIO does not
 * exist.  (btype) is ignored when createit is 0.
 */
static hammer2_io_t *
hammer2_io_alloc(hammer2_dev_t *hmp, hammer2_off_t data_off, uint8_t btype,
    int createit)
{
	hammer2_volume_t *vol;
	hammer2_io_t *dio, *xio;
	hammer2_off_t lbase, pbase, pmask;
	int lsize, psize;

	/*
	 * The hash is protected per-bucket (hash->spin), not by a global
	 * lock.  Callers may hold any bucket lock that is not the target
	 * bucket; the lookup+enter pair revalidates under the bucket lock
	 * and a DIO with refs is never reclaimed.
	 */

	psize = HAMMER2_PBUFSIZE;
	pmask = ~(hammer2_off_t)(psize - 1);
	if ((int)(data_off & HAMMER2_OFF_MASK_RADIX))
		lsize = 1 << (int)(data_off & HAMMER2_OFF_MASK_RADIX);
	else
		lsize = 0;
	lbase = data_off & ~HAMMER2_OFF_MASK_RADIX;
	pbase = lbase & pmask;

	if (pbase == 0 || ((lbase + lsize - 1) & pmask) != pbase)
		hpanic("illegal base: %016llx %016llx+%08x / %016llx",
		    (long long)pbase, (long long)lbase, lsize,
		    (long long)pmask);

	/*
	 * Access/Allocate the DIO, bump dio->refs to prevent destruction.
	 *
	 * The ref is bumped atomically (the 0->1 transition also moves the
	 * dio out of the free accounting).  If DIO_GOOD is set the ref
	 * prevents it from being cleared out from under us, and the caller
	 * can operate on the buffer without any further interaction.
	 */
	dio = hammer2_io_hash_lookup(hmp, pbase, NULL);
	if (dio) {
		/* NOP */
	} else if (createit) {
		vol = hammer2_get_volume(hmp, pbase);
		dio = hmalloc(sizeof(*dio), M_HAMMER2, M_WAITOK | M_ZERO);
		dio->hmp = hmp;
		dio->devvp = vol->dev->devvp;
		dio->dbase = vol->offset;
		KKASSERT((dio->dbase & HAMMER2_FREEMAP_LEVEL1_MASK) == 0);
		dio->pbase = pbase;
		dio->psize = psize;
		dio->btype = btype;
		dio->id = atomic_inc_64_nv(&hammer2_dio_seq);
		dio->refs = 1;
		dio->act = 5;
		hammer2_lk_init(&dio->waitlk, "h2dio");
		hammer2_lkc_init(&dio->cv, "h2diocv");
		xio = hammer2_io_hash_enter(hmp, dio, NULL);
		if (xio == NULL) {
			atomic_add_int(&hammer2_count_dio_allocated, 1);
		} else {
			hammer2_lkc_destroy(&dio->cv);
			hammer2_lk_destroy(&dio->waitlk);
			hfree(dio, M_HAMMER2, sizeof(*dio));
			dio = xio;
		}
	} else {
		return (NULL);
	}

	dio->ticks = getticks();
	if (dio->act < 10)
		++dio->act;

	hammer2_assert_io_refs(dio);

	return (dio);
}

/*
 * Physical read-ahead, the NetBSD analog of upstream's
 * cluster_readx(..., HAMMER2_PBUFSIZE * hce, ...) device clustering
 * (upstream vfs.hammer2.cluster_meta_read=1 / cluster_data_read=4).
 * The demanded block is read synchronously; the remaining blocks of the
 * run are queued as B_ASYNC device reads, so subsequent DIO breads of
 * those blocks hit the device buffer cache.  Readahead is clamped to the
 * volume holding the block (each volume is an independent device vnode)
 * and never runs in the pagedaemon (its allocations must not wait, see
 * the pagedaemon contract notes).
 */
#define HAMMER2_CLUSTER_READ_MAX	8

/*
 * Issue one B_ASYNC speculative read.  Mirrors bio_doread()'s B_ASYNC
 * arm, except the buffer is acquired with a 1-tick bounded getblk():
 * upstream's speculative acquisition is GETBLK_NOWAIT (sys/kern/
 * vfs_cluster.c) -- a block that turned busy between the incore() check
 * and acquisition must be SKIPPED, not waited on.  A plain blocking
 * getblk() here waits while we still hold the demanded block's DIO lock,
 * which inverts against a thread holding the neighbor's DIO reference
 * (buffer stays BC_BUSY) and re-entering that DIO lock: deadlock.
 */
static void
hammer2_readahead(struct vnode *devvp, daddr_t *rablks, int *rasizes,
    int nrablks)
{
	struct buf *bp;
	int i;

	for (i = 0; i < nrablks; ++i) {
		bp = getblk(devvp, rablks[i], rasizes[i], 0, 1);
		if (bp == NULL)
			continue;
		if (!ISSET(bp->b_oflags, (BO_DONE | BO_DELWRI))) {
			SET(bp->b_flags, B_READ | B_ASYNC);
			BIO_SETPRIO(bp, BPRIO_TIMELIMITED);
			VOP_STRATEGY(devvp, bp);
			/* B_ASYNC: the buffer is released on I/O completion. */
		} else {
			brelse(bp, 0);
		}
	}
}

static int
hammer2_bread(hammer2_dev_t *hmp, hammer2_io_t *dio, daddr_t lblkno)
{
	daddr_t rablks[HAMMER2_CLUSTER_READ_MAX - 1];
	int rasizes[HAMMER2_CLUSTER_READ_MAX - 1];
	struct buf *bp;
	int error, i, hce, nrablks, step;

	hce = (dio->btype == HAMMER2_BREF_TYPE_DATA) ?
	    hammer2_cluster_data_read : hammer2_cluster_meta_read;
	if (hce > HAMMER2_CLUSTER_READ_MAX)
		hce = HAMMER2_CLUSTER_READ_MAX;

	nrablks = 0;
	if (hce > 1 && curlwp != uvm.pagedaemon_lwp) {
		/*
		 * dio->pbase - dio->dbase is the byte offset within the
		 * volume; clamp the run to the volume REMAINDER (size
		 * beyond the current block -- vol->size alone is an
		 * absolute, not a distance) and to the current segment
		 * like upstream's peof calculation.  NOTE:
		 * hammer2_get_volume() panics rather than returning
		 * NULL, there is no failure case to handle.
		 */
		hammer2_volume_t *vol = hammer2_get_volume(hmp,
		    dio->pbase);
		hammer2_off_t voloff = dio->pbase - dio->dbase;
		hammer2_off_t peof = (voloff + (hammer2_off_t)HAMMER2_SEGMASK) &
		    ~(hammer2_off_t)HAMMER2_SEGMASK;
		hammer2_off_t maxoff = MIN(vol->size, peof) - voloff;
		int maxblks = (int)(maxoff >> HAMMER2_PBUFRADIX);

		step = dio->psize / DEV_BSIZE;
		for (i = 1; i < hce && i < maxblks; ++i) {
			rablks[nrablks] = lblkno + (daddr_t)i * step;
			rasizes[nrablks] = dio->psize;
			++nrablks;
		}
	}

	/*
	 * bread() equivalent with the read-ahead queued between starting
	 * the demanded block's I/O and waiting for it (breadn's ordering,
	 * with non-blocking speculative acquisition).  bread()'s flags=0
	 * semantics: no fscow_run, brelse + NULL bp on error.
	 */
	bp = getblk(dio->devvp, lblkno, dio->psize, 0, 0);
	if (bp == NULL)
		return (ENOMEM);
	if (!ISSET(bp->b_oflags, (BO_DONE | BO_DELWRI))) {
		SET(bp->b_flags, B_READ);
		BIO_SETPRIO(bp, BPRIO_TIMECRITICAL);
		VOP_STRATEGY(dio->devvp, bp);
		/* Pay for the read. */
		curlwp->l_ru.ru_inblock++;
	}
	if (nrablks)
		hammer2_readahead(dio->devvp, rablks, rasizes, nrablks);
	error = biowait(bp);
	if (error) {
		brelse(bp, 0);
		hammer2_inc_iostat(&hmp->iostat_read, dio->btype, dio->psize);
		return (error);
	}
	dio->bp = bp;

	hammer2_inc_iostat(&hmp->iostat_read, dio->btype, dio->psize);

	return (error);
}

/*
 * Acquire the requested dio.  If DIO_GOOD is not set we must instantiate
 * a buffer.  If set the buffer already exists and is good to go.
 */
#ifdef HAMMER2_IO_DEBUG

static __inline void
DIO_RECORD(hammer2_io_t *dio HAMMER2_IO_DEBUG_ARGS)
{
	int i;

	i = atomic_fetchadd_int(&dio->debug_index, 1) & HAMMER2_IO_DEBUG_MASK;

	dio->debug_file[i] = file;
	dio->debug_line[i] = line;
	dio->debug_refs[i] = dio->refs;
	dio->debug_td[i] = curthread;
}

#else

#define DIO_RECORD(dio)

#endif

hammer2_io_t *
_hammer2_io_getblk(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase,
    int lsize, int op HAMMER2_IO_DEBUG_ARGS)
{
	hammer2_io_t *dio;
	uint32_t nrefs, orefs;
	daddr_t lblkno;
	int error;

	KKASSERT((1 << (int)(lbase & HAMMER2_OFF_MASK_RADIX)) == lsize);

	if (op == HAMMER2_DOP_READQ) {
		dio = hammer2_io_alloc(hmp, lbase, btype, 0);
		if (dio == NULL)
			return (NULL);
		op = HAMMER2_DOP_READ;
	} else {
		dio = hammer2_io_alloc(hmp, lbase, btype, 1);
	}
	KKASSERT(dio);

	for (;;) {
		orefs = dio->refs;
		cpu_ccfence();

		/*
		 * Buffer is already good, handle the op and return.
		 * The ref we hold prevents GOOD from being cleared.
		 */
		if (orefs & HAMMER2_DIO_GOOD) {
			switch (op) {
			case HAMMER2_DOP_NEW:
				bzero(hammer2_io_data(dio, lbase), lsize);
				/* fall through */
			case HAMMER2_DOP_NEWNZ:
				atomic_set_32(&dio->refs, HAMMER2_DIO_DIRTY);
				break;
			default:
				/* nothing to do */
				break;
			}
			DIO_RECORD(dio HAMMER2_IO_DEBUG_CALL);
			return (dio);
		}

		/*
		 * Try to own the DIO.  If an I/O (or a lastdrop disposal)
		 * is in progress we register as a waiter and sleep.
		 */
		if (orefs & HAMMER2_DIO_INPROG) {
			hammer2_io_wait(dio);
		} else {
			nrefs = orefs | HAMMER2_DIO_INPROG;
			if (atomic_cmpset_32(&dio->refs, orefs, nrefs))
				break;
		}
		cpu_pause();
		/* retry */
	}

	/*
	 * We break to here if GOOD is not set and we acquired INPROG for
	 * the I/O.
	 */
	KKASSERT(dio->bp == NULL);

	error = 0;
	lblkno = (dio->pbase - dio->dbase) / DEV_BSIZE;

	if (dio->pbase == (lbase & ~HAMMER2_OFF_MASK_RADIX) &&
	    dio->psize == lsize) {
		switch (op) {
		case HAMMER2_DOP_NEW:
		case HAMMER2_DOP_NEWNZ:
			dio->bp = getblk(dio->devvp, lblkno, dio->psize, 0, 0);
			if (op == HAMMER2_DOP_NEW)
				bzero(dio->bp->b_data, dio->psize);
			atomic_set_32(&dio->refs, HAMMER2_DIO_DIRTY);
			break;
		default:
			error = hammer2_bread(hmp, dio, lblkno);
			break;
		}
	} else {
		error = hammer2_bread(hmp, dio, lblkno);
		if (dio->bp) {
			KKASSERT(error == 0);
			/*
			 * Handle NEW flags
			 */
			switch (op) {
			case HAMMER2_DOP_NEW:
				bzero(hammer2_io_data(dio, lbase), lsize);
				/* fall through */
			case HAMMER2_DOP_NEWNZ:
				atomic_set_32(&dio->refs, HAMMER2_DIO_DIRTY);
				break;
			default:
				break;
			}
		}
	}
	KKASSERT(error == 0 || dio->bp == NULL);

	/* XXX
	if (dio->bp)
		BUF_KERNPROC(dio->bp);
	*/

	dio->error = error;

	/*
	 * Clear INPROG and WAITING, set GOOD (if no error) and wake up
	 * anyone waiting.
	 */
	for (;;) {
		orefs = dio->refs;
		cpu_ccfence();
		nrefs = orefs & ~(HAMMER2_DIO_INPROG | HAMMER2_DIO_WAITING);
		if (error == 0)
			nrefs |= HAMMER2_DIO_GOOD;
		if (atomic_cmpset_32(&dio->refs, orefs, nrefs)) {
			hammer2_io_wakeup(dio, orefs);
			break;
		}
		cpu_pause();
	}

	/* XXX error handling */
	DIO_RECORD(dio HAMMER2_IO_DEBUG_CALL);

	return (dio);
}

/*
 * Release our ref on *diop.
 *
 * On the 1->0 transition we clear DIO_GOOD, set DIO_INPROG in the same
 * cmpset, and dispose of dio->bp with no lock held (upstream holds no
 * mutex across the disposal either -- the INPROG flag is what keeps
 * concurrent getblk() callers out).  Then we clear DIO_INPROG and
 * DIO_WAITING and wake up any waiters.
 */
void
_hammer2_io_putblk(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	hammer2_dev_t *hmp;
	hammer2_io_t *dio;
	struct buf *bp;
	uint32_t nrefs, orefs;
	int dio_limit;

	dio = *diop;
	*diop = NULL;
	hmp = dio->hmp;
	DIO_RECORD(dio HAMMER2_IO_DEBUG_CALL);

	KKASSERT((dio->refs & HAMMER2_DIO_MASK) != 0);

	/*
	 * Drop refs.
	 *
	 * On the 1->0 transition clear GOOD and set INPROG, and break.
	 * On any other transition we can return early.
	 */
	for (;;) {
		orefs = dio->refs;
		cpu_ccfence();

		if ((orefs & HAMMER2_DIO_MASK) == 1 &&
		    (orefs & HAMMER2_DIO_INPROG) == 0) {
			/*
			 * Lastdrop case.  GOOD must be cleared in the same
			 * cmpset to prevent the getblk shortcut, and INPROG
			 * must be set so other threads do not touch the
			 * buffer while we dispose of it.
			 */
			nrefs = orefs - 1;
			nrefs &= ~(HAMMER2_DIO_GOOD | HAMMER2_DIO_DIRTY);
			nrefs |= HAMMER2_DIO_INPROG;
			if (atomic_cmpset_32(&dio->refs, orefs, nrefs))
				break;
		} else if ((orefs & HAMMER2_DIO_MASK) == 1) {
			/*
			 * Lastdrop case, INPROG already set.  We must
			 * wait for INPROG to clear.
			 */
			hammer2_io_wait(dio);
			/* retry */
		} else {
			/*
			 * Normal drop case.
			 */
			nrefs = orefs - 1;
			if (atomic_cmpset_32(&dio->refs, orefs, nrefs))
				return;
		}
		cpu_pause();
		/* retry */
	}

	/*
	 * Lastdrop (1->0 transition).  INPROG has been set, GOOD and DIRTY
	 * have been cleared.  iofree_count has not yet been incremented,
	 * note that another accessor race will decrement iofree_count so
	 * we have to increment it regardless.
	 * We can now dispose of the buffer.
	 */
	bp = dio->bp;
	dio->bp = NULL;

	/* Write out and dispose of buffer. */
	if ((orefs & HAMMER2_DIO_GOOD) && bp) {
		/*
		 * Non-errored disposal of bp
		 */
		if (orefs & HAMMER2_DIO_DIRTY) {
			/*
			 * Allows dirty buffers to accumulate and
			 * possibly be canceled (e.g. by a 'rm'),
			 * by default we will burst-write later.
			 *
			 * We generally do NOT want to issue an actual
			 * b[a]write() or cluster_write() here.  Due to
			 * the way chains are locked, buffers may be cycled
			 * in and out quite often and disposal here can cause
			 * multiple writes or write-read stalls.
			 *
			 * If FLUSH is set we do want to issue the actual
			 * write.  This typically occurs in the write-behind
			 * case when writing to large files.
			 */
			/* No cluster_write() in NetBSD. */
			if (dio->refs & HAMMER2_DIO_FLUSH)
				bawrite(bp);
			else
				bdwrite(bp);
			hammer2_inc_iostat(&hmp->iostat_write, dio->btype,
			    dio->psize);
		} else {
			bqrelse(bp, 0);
		}
	} else if (bp) {
		/*
		 * Errored disposal of bp
		 */
		brelse(bp, 0);
	}

	/* Update iofree_count before disposing of the dio. */
	atomic_add_int(&hmp->iofree_count, 1);

	/*
	 * Clear INPROG and WAITING (GOOD and DIRTY were already cleared
	 * above).  Also clear FLUSH as it was handled above.
	 */
	KKASSERT(!(dio->refs & HAMMER2_DIO_GOOD));
	for (;;) {
		orefs = dio->refs;
		cpu_ccfence();
		nrefs = orefs & ~(HAMMER2_DIO_INPROG | HAMMER2_DIO_GOOD |
				  HAMMER2_DIO_WAITING | HAMMER2_DIO_FLUSH);
		if (atomic_cmpset_32(&dio->refs, orefs, nrefs)) {
			hammer2_io_wakeup(dio, orefs);
			break;
		}
		cpu_pause();
	}
	/* Another process may come in and get/put this dio. */

	/*
	 * We cache free buffers so re-use cases can use a shared lock, but
	 * if too many build up we have to clean them out.
	 */
	dio_limit = hammer2_dio_limit;
	if (dio_limit < 256)
		dio_limit = 256;
	if (dio_limit > 1024*1024)
		dio_limit = 1024*1024;
	if (hmp->iofree_count > dio_limit)
		hammer2_io_hash_cleanup(hmp, dio_limit);
}

/*
 * Returns a pointer to the requested data.
 */
char *
hammer2_io_data(hammer2_io_t *dio, hammer2_off_t lbase)
{
	struct buf *bp;
	off_t	b_offset;
	int	off;

	bp = dio->bp;
	KASSERTMSG(bp != NULL, "NULL dio buf");

	lbase -= dio->dbase;
	b_offset = (off_t)bp->b_lblkno * DEV_BSIZE;
	off = (lbase & ~HAMMER2_OFF_MASK_RADIX) - b_offset;

	KASSERTMSG(off >= 0, "bad offset not 0x%x >= 0x%x", off, 0);
	KASSERTMSG(off < bp->b_bufsize, "bad offset not 0x%x < 0x%x",
	    off, bp->b_bufsize);

	return ((char *)bp->b_data + off);
}

int
hammer2_io_new(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop)
{
	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_NEW);
	return ((*diop)->error);
}

int
hammer2_io_newnz(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop)
{
	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_NEWNZ);
	return ((*diop)->error);
}

int
_hammer2_io_bread(hammer2_dev_t *hmp, int btype, hammer2_off_t lbase, int lsize,
    hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
#ifdef HAMMER2_IO_DEBUG
	hammer2_io_t *dio;
#endif

	*diop = hammer2_io_getblk(hmp, btype, lbase, lsize, HAMMER2_DOP_READ);
#ifdef HAMMER2_IO_DEBUG
	if ((dio = *diop) != NULL) {
#if 0
		int i = (dio->debug_index - 1) & HAMMER2_IO_DEBUG_MASK;
		dio->debug_data[i] = debug_data;
#endif
	}
#endif
	return ((*diop)->error);
}

hammer2_io_t *
_hammer2_io_getquick(hammer2_dev_t *hmp, off_t lbase,
		     int lsize HAMMER2_IO_DEBUG_ARGS)
{
	hammer2_io_t *dio;

	dio = _hammer2_io_getblk(hmp, 0, lbase, lsize,
				 HAMMER2_DOP_READQ HAMMER2_IO_DEBUG_CALL);
	return (dio);
}

void
_hammer2_io_bawrite(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY | HAMMER2_DIO_FLUSH);
	hammer2_io_putblk(diop);
}

void
_hammer2_io_bdwrite(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY);
	hammer2_io_putblk(diop);
}

int
_hammer2_io_bwrite(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	atomic_set_32(&(*diop)->refs, HAMMER2_DIO_DIRTY | HAMMER2_DIO_FLUSH);
	hammer2_io_putblk(diop);

	return (0); /* XXX */
}

void
hammer2_io_setdirty(hammer2_io_t *dio)
{
	atomic_set_32(&dio->refs, HAMMER2_DIO_DIRTY);
}

void
_hammer2_io_brelse(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	hammer2_io_putblk(diop);
}

void
_hammer2_io_bqrelse(hammer2_io_t **diop HAMMER2_IO_DEBUG_ARGS)
{
	hammer2_io_putblk(diop);
}

static __inline hammer2_io_hash_t *
hammer2_io_hashv(hammer2_dev_t *hmp, hammer2_off_t pbase)
{
	int hv;

	hv = (int)pbase + (int)(pbase >> 16);
	return (&hmp->iohash[hv & HAMMER2_IOHASH_MASK]);
}

/*
 * Lookup and reference the requested dio.
 */
static hammer2_io_t *
hammer2_io_hash_lookup(hammer2_dev_t *hmp, hammer2_off_t pbase, uint64_t *refsp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio;
	uint64_t refs;

	if (refsp)
		*refsp = 0;

	hash = hammer2_io_hashv(hmp, pbase);
	hammer2_spin_sh(&hash->spin);
	for (dio = hash->base; dio; dio = dio->next) {
		if (dio->pbase == pbase) {
			refs = atomic_add_32_nv(&dio->refs, 1) - 1;
			if ((refs & HAMMER2_DIO_MASK) == 0)
				atomic_add_int(&dio->hmp->iofree_count, -1);
			if (refsp)
				*refsp = refs;
			break;
		}
	}
	hammer2_spin_unsh(&hash->spin);

	if (dio)
		hammer2_assert_io_refs(dio);
	return (dio);
}

/*
 * Enter a dio into the hash.  If the pbase already exists in the hash,
 * the xio in the hash is referenced and returned.  If dio is sucessfully
 * entered into the hash, NULL is returned.
 */
static hammer2_io_t *
hammer2_io_hash_enter(hammer2_dev_t *hmp, hammer2_io_t *dio, uint64_t *refsp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *xio, **xiop;
	uint64_t refs;

	hammer2_assert_io_refs(dio);

	if (refsp)
		*refsp = 0;

	hash = hammer2_io_hashv(hmp, dio->pbase);
	hammer2_spin_ex(&hash->spin);
	for (xiop = &hash->base; (xio = *xiop) != NULL; xiop = &xio->next) {
		if (xio->pbase == dio->pbase) {
			refs = atomic_add_32_nv(&xio->refs, 1) - 1;
			if ((refs & HAMMER2_DIO_MASK) == 0)
				atomic_add_int(&xio->hmp->iofree_count, -1);
			if (refsp)
				*refsp = refs;
			goto done;
		}
	}
	dio->next = NULL;
	*xiop = dio;
done:
	hammer2_spin_unex(&hash->spin);

	return (xio);
}

/*
 * Clean out a limited number of freeable DIOs.
 */
static void
hammer2_io_hash_cleanup(hammer2_dev_t *hmp, int dio_limit)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio, **diop, *cleanbase, **cleanapp;
	int count, maxscan, act, i;

	/*
	 * Called with no bucket lock held.  Each bucket is locked
	 * exclusively in turn while entries are detached; the detached
	 * entries are freed after the last bucket lock is dropped.
	 * Concurrent cleanups are benign (entries are detached exactly
	 * once; the scan cursor is advisory).
	 */
	count = hmp->iofree_count - dio_limit + 32;
	if (count <= 0)
		return;

	cleanbase = NULL;
	cleanapp = &cleanbase;
	i = hmp->io_iterator++;
	maxscan = HAMMER2_IOHASH_SIZE;

	while (count > 0 && maxscan--) {
		hash = &hmp->iohash[i & HAMMER2_IOHASH_MASK];
		hammer2_spin_ex(&hash->spin);
		diop = &hash->base;
		while ((dio = *diop) != NULL) {
			if ((dio->refs & (HAMMER2_DIO_MASK |
					  HAMMER2_DIO_INPROG)) != 0) {
				/*
				 * Leak probe: a referenced dio that still
				 * holds its buffer with a stale access time
				 * is a leak candidate (its bp stays BC_BUSY
				 * + DELWRI forever and wedges vflushbuf in
				 * an unbreakable dirty-retry spin).
				 */
				if (dio->bp != NULL && dio->ticks != 0 &&
				    getticks() - dio->ticks > 60 * hz) {
					hprintf("LEAK? dio %p pbase %016llx "
					    "refs %x dirty %d bp %p age %ds\n",
					    dio, (long long)dio->pbase,
					    (int)(dio->refs & HAMMER2_DIO_MASK),
					    (dio->refs & HAMMER2_DIO_DIRTY) != 0,
					    dio->bp,
					    (int)((getticks() - dio->ticks)
					    / hz));
					dio->ticks = getticks(); /* rate-limit */
				}
				diop = &dio->next;
				continue;
			}
			if (dio->act > 0) {
				act = dio->act - (getticks() - dio->ticks) / hz - 1;
				dio->act = (act < 0) ? 0 : act;
			}
			if (dio->act) {
				diop = &dio->next;
				continue;
			}
			KKASSERT(dio->bp == NULL);
			*diop = dio->next;
			dio->next = NULL;
			*cleanapp = dio;
			cleanapp = &dio->next;
			--count;
			/* diop remains unchanged */
			atomic_add_int(&hammer2_count_dio_allocated, -1);
			atomic_add_int(&hmp->iofree_count, -1);
		}
		hammer2_spin_unex(&hash->spin);
		i = hmp->io_iterator++;
	}

	/* Get rid of dios on clean list without holding any locks. */
	while ((dio = cleanbase) != NULL) {
		cleanbase = dio->next;
		dio->next = NULL;
		KKASSERT(dio->bp == NULL &&
		    (dio->refs & (HAMMER2_DIO_MASK | HAMMER2_DIO_INPROG)) == 0);
		if (dio->refs & HAMMER2_DIO_DIRTY)
			hprintf("dirty buffer %016llx/%d\n",
			    (long long)dio->pbase, dio->psize);
		hammer2_lkc_destroy(&dio->cv);
		hammer2_lk_destroy(&dio->waitlk);
		hfree(dio, M_HAMMER2, sizeof(*dio));
	}
}

/*
 * Destroy all DIOs associated with the media.
 */
void
hammer2_io_hash_cleanup_all(hammer2_dev_t *hmp)
{
	hammer2_io_hash_t *hash;
	hammer2_io_t *dio, *cleanbase, **cleanapp;
	int i;

	/*
	 * Teardown path: unmount quiesces all I/O first, so no dio may still
	 * be in its INPROG disposal window here.  Each bucket is locked only
	 * while detaching; the detached list is freed afterwards with no
	 * bucket lock held.
	 */
	cleanbase = NULL;
	cleanapp = &cleanbase;

	for (i = 0; i < HAMMER2_IOHASH_SIZE; ++i) {
		hash = &hmp->iohash[i];
		hammer2_spin_ex(&hash->spin);
		while ((dio = hash->base) != NULL) {
			hash->base = dio->next;
			dio->next = NULL;
			KKASSERT(dio->bp == NULL &&
			    (dio->refs & (HAMMER2_DIO_MASK |
					  HAMMER2_DIO_INPROG)) == 0);
			*cleanapp = dio;
			cleanapp = &dio->next;
			atomic_add_int(&hammer2_count_dio_allocated, -1);
			atomic_add_int(&hmp->iofree_count, -1);
		}
		hammer2_spin_unex(&hash->spin);
	}

	while ((dio = cleanbase) != NULL) {
		cleanbase = dio->next;
		dio->next = NULL;
		if (dio->refs & HAMMER2_DIO_DIRTY)
			hprintf("dirty buffer %016llx/%d\n",
			    (long long)dio->pbase, dio->psize);
		hammer2_lkc_destroy(&dio->cv);
		hammer2_lk_destroy(&dio->waitlk);
		hfree(dio, M_HAMMER2, sizeof(*dio));
	}
}

#define HAMMER2_DEDUP_FRAG	(HAMMER2_PBUFSIZE / 64)
#define HAMMER2_DEDUP_FRAGRADIX	(HAMMER2_PBUFRADIX - 6)

uint64_t
hammer2_dedup_mask(hammer2_io_t *dio, hammer2_off_t data_off, u_int bytes)
{
	int bbeg, bits;
	uint64_t mask;

	bbeg = (int)((data_off & ~HAMMER2_OFF_MASK_RADIX) - dio->pbase) >>
	    HAMMER2_DEDUP_FRAGRADIX;
	bits = (int)((bytes + (HAMMER2_DEDUP_FRAG - 1)) >>
	    HAMMER2_DEDUP_FRAGRADIX);

	if (bbeg + bits == 64)
		mask = (uint64_t)-1;
	else
		mask = ((uint64_t)1 << (bbeg + bits)) - 1;
	mask &= ~(((uint64_t)1 << bbeg) - 1);

	return (mask);
}

/*
 * Set dedup validation bits in a DIO.  We do not need the buffer cache
 * buffer for this.  This must be done concurrent with setting bits in
 * the freemap so as to interlock with bulkfree's clearing of those bits.
 */
void
hammer2_io_dedup_set(hammer2_dev_t *hmp, hammer2_blockref_t *bref)
{
	hammer2_io_t *dio;
	uint64_t mask;
	int lsize;

	dio = hammer2_io_alloc(hmp, bref->data_off, bref->type, 1);
	KKASSERT(dio);

	if ((int)(bref->data_off & HAMMER2_OFF_MASK_RADIX))
		lsize = 1 << (int)(bref->data_off & HAMMER2_OFF_MASK_RADIX);
	else
		lsize = 0;

	mask = hammer2_dedup_mask(dio, bref->data_off, lsize);
	atomic_clear_64(&dio->dedup_valid, mask);
	atomic_set_64(&dio->dedup_alloc, mask);

	hammer2_io_putblk(&dio);
}

/*
 * Clear dedup validation bits in a DIO.  This is typically done when
 * a modified chain is destroyed or by the bulkfree code.  No buffer
 * is needed for this operation.  If the DIO no longer exists it is
 * equivalent to the bits not being set.
 */
void
hammer2_io_dedup_delete(hammer2_dev_t *hmp, uint8_t btype,
    hammer2_off_t data_off, unsigned int bytes)
{
	hammer2_io_t *dio;
	uint64_t mask;

	if ((data_off & ~HAMMER2_OFF_MASK_RADIX) == 0)
		return;
	if (btype != HAMMER2_BREF_TYPE_DATA)
		return;

	dio = hammer2_io_alloc(hmp, data_off, btype, 0);
	if (dio) {
		if (data_off < (hammer2_off_t)dio->pbase ||
		    (data_off & ~HAMMER2_OFF_MASK_RADIX) +
		    (hammer2_off_t)bytes >
		    (hammer2_off_t)dio->pbase + dio->psize)
			hpanic("bad data_off %016llx/%d %016llx",
			    (long long)data_off, bytes, (long long)dio->pbase);

		mask = hammer2_dedup_mask(dio, data_off, bytes);
		atomic_clear_64(&dio->dedup_alloc, mask);
		atomic_clear_64(&dio->dedup_valid, mask);

		hammer2_io_putblk(&dio);
	}
}

/*
 * Assert that dedup allocation bits in a DIO are not set.  This operation
 * does not require a buffer.  The DIO does not need to exist.
 */
void
hammer2_io_dedup_assert(hammer2_dev_t *hmp, hammer2_off_t data_off,
    unsigned int bytes)
{
	hammer2_io_t *dio;

	dio = hammer2_io_alloc(hmp, data_off, HAMMER2_BREF_TYPE_DATA, 0);
	if (dio) {
		KASSERTMSG((dio->dedup_alloc &
		    hammer2_dedup_mask(dio, data_off, bytes)) == 0,
		    "%016llx/%d %016llx/%016llx",
		    (long long)data_off, bytes,
		    (long long)hammer2_dedup_mask(dio, data_off, bytes),
		    (long long)dio->dedup_alloc);

		hammer2_io_putblk(&dio);
	}
}
