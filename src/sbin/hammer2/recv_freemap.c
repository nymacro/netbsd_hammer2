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
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Destination-side freemap allocation for `hammer2 recv' (see
 * recv_freemap.h for the motivation).
 *
 * The freemap tree is rooted at voldata.freemap_blockset and consists of
 * 32KB blocks: FREEMAP_LEAF blocks (256 x 4MB hammer2_bmap_data_t) at
 * LEVEL1 (1GB) and FREEMAP_NODE blocks (256 x 128B blockref) at LEVEL2..5.
 *
 * This module reads that tree, allocates received blocks from free 16KB
 * units (the bitmap granularity), and COW-writes every modified block to a
 * rotated reserve slot before the caller commits the volume header.  A crash
 * before the commit leaves the previous root (and thus the previous freemap)
 * intact; newly written blocks are simply unreferenced.
 *
 * Simplifications relative to the kernel allocator (deliberate, see the plan):
 *   - Allocation is at 16KB-unit granularity; blocks smaller than 16KB are
 *     packed into reserved units by a private cursor.  The kernel's
 *     bmap->linear sub-allocator is not reproduced; bmap->linear is cleared
 *     on modification so the kernel cannot reuse stale sub-unit state.
 *   - Leaf creation is supported by inserting into a free slot of the root
 *     blockset or of an existing node whose children are already LEVEL1
 *     leaves.  Destinations large enough to require a brand new intermediate
 *     node are refused cleanly.
 */

#include <sys/param.h>

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hammer2.h"
#include "recv_freemap.h"

#define FM_LBLK		HAMMER2_FREEMAP_LEVELN_PSIZE	/* 32768 */
#define FM_LRADIX	15				/* 1<<15 == FM_LBLK */
#define FM_LBSIZE	HAMMER2_FREEMAP_BLOCK_SIZE	/* 16384 */
#define FM_UNITS	(HAMMER2_FREEMAP_LEVEL1_SIZE >> HAMMER2_FREEMAP_BLOCK_RADIX)
#define FM_NBREF	(FM_LBLK / HAMMER2_BLOCKREF_BYTES)/* 256 */
#define FM_NBMAP	HAMMER2_FREEMAP_COUNT		/* 256 */
#define FM_LEVEL1	HAMMER2_FREEMAP_LEVEL1_RADIX	/* 30 */
#define FM_ROOT		(-1)
#define FM_BADOFF	((hammer2_off_t)-1)

struct fm_blk {
	struct fm_blk *parent;		/* NULL only for the root */
	struct fm_blk *next;		/* every loaded/created block */
	int		slot;		/* index within parent */
	int		level;		/* keybits, FM_ROOT for the root */
	int		depth;
	int		dirty;
	int		created;	/* no prior on-media copy */
	hammer2_blockref_t bref;
	uint8_t		*data;		/* FM_LBLK bytes, NULL for the root */
};

struct recv_freemap {
	hammer2_volume_data_t *volp;
	hammer2_off_t	alloc_beg;
	hammer2_off_t	volu_end;
	hammer2_tid_t	tid;
	struct fm_blk	root;
	struct fm_blk	*all;
	hammer2_off_t	hint;
	hammer2_off_t	pack_unit;	/* current sub-16KB packing unit */
	uint32_t	pack_off;
	uint64_t	alloc_bytes;
	uint16_t	class_hint;
};

/*
 * Low-level volume I/O (shared with cmd_recv.c).
 */
ssize_t
recv_read_phys(hammer2_off_t data_off, void *buf, size_t bytes)
{
	hammer2_off_t io_off = data_off & ~HAMMER2_OFF_MASK_RADIX;
	int fd = hammer2_get_volume_fd(io_off);
	hammer2_off_t off;

	if (fd < 0)
		return (-1);
	off = io_off - hammer2_get_volume_offset(io_off);
	return (pread(fd, buf, bytes, off));
}

int
recv_write_phys(hammer2_off_t data_off, const void *buf, size_t bytes)
{
	hammer2_off_t io_off = data_off & ~HAMMER2_OFF_MASK_RADIX;
	int fd = hammer2_get_volume_fd(io_off);
	hammer2_off_t off;

	if (fd < 0)
		return (-1);
	off = io_off - hammer2_get_volume_offset(io_off);
	return (pwrite(fd, buf, bytes, off) == (ssize_t)bytes ? 0 : -1);
}

static hammer2_blockref_t *
fm_slots(struct recv_freemap *fm, struct fm_blk *b)
{
	if (b == &fm->root)
		return (fm->volp->freemap_blockset.blockref);
	return ((hammer2_blockref_t *)(void *)b->data);
}

static int
fm_nslots(struct fm_blk *b)
{
	return (b->level == FM_ROOT) ? HAMMER2_SET_COUNT : FM_NBREF;
}

static int
fm_covers(const hammer2_blockref_t *bref, hammer2_off_t key)
{
	hammer2_off_t base = (hammer2_off_t)bref->key;
	hammer2_off_t size = (hammer2_off_t)1 << bref->keybits;

	return (key >= base && key < base + size);
}

int
recv_freemap_present(const hammer2_volume_data_t *voldata)
{
	int i;

	for (i = 0; i < HAMMER2_SET_COUNT; ++i) {
		if (voldata->freemap_blockset.blockref[i].type !=
		    HAMMER2_BREF_TYPE_EMPTY)
			return (1);
	}
	return (0);
}

/*
 * Read and check a freemap node or leaf block.
 */
static struct fm_blk *
fm_read_blk(struct recv_freemap *fm, struct fm_blk *parent, int slot,
    const hammer2_blockref_t *bref)
{
	struct fm_blk *b;
	size_t bytes = (size_t)1 << (bref->data_off & HAMMER2_OFF_MASK_RADIX);

	if (bref->keybits < FM_LEVEL1 ||
	    bref->keybits > HAMMER2_FREEMAP_LEVEL5_RADIX ||
	    bytes != FM_LBLK)
		errx(1, "recv: bogus freemap block (keybits %u radix %u)",
		    bref->keybits,
		    (unsigned)(bref->data_off & HAMMER2_OFF_MASK_RADIX));

	/*
	 * Reuse an already-loaded copy of the same logical block.  Without
	 * this, two leaves created under the same node would be inserted
	 * into two separate in-memory copies that later COW to the same
	 * rotated reserve slot, and the second write would silently discard
	 * the first leaf's insertion.
	 */
	for (b = fm->all; b; b = b->next) {
		if (b->level == bref->keybits && b->bref.key == bref->key)
			return (b);
	}

	b = calloc(1, sizeof(*b));
	if (b == NULL)
		err(1, "recv: out of memory");
	b->data = calloc(1, FM_LBLK);
	if (b->data == NULL)
		err(1, "recv: out of memory");
	b->parent = parent;
	b->slot = slot;
	b->bref = *bref;
	b->level = bref->keybits;
	b->depth = parent->depth + 1;
	b->next = fm->all;
	fm->all = b;

	if (recv_read_phys(bref->data_off, b->data, FM_LBLK) != (ssize_t)FM_LBLK)
		errx(1, "recv: cannot read freemap block at %016jx",
		    (intmax_t)bref->data_off);
	if (bref->check.freemap.icrc32 != hammer2_icrc32(b->data, FM_LBLK))
		errx(1, "recv: freemap check code mismatch at %016jx",
		    (intmax_t)bref->data_off);
	return (b);
}

static struct fm_blk *
fm_descend(struct recv_freemap *fm, struct fm_blk *parent, hammer2_off_t key)
{
	hammer2_blockref_t *s = fm_slots(fm, parent);
	int n = fm_nslots(parent), i;

	for (i = 0; i < n; ++i) {
		struct fm_blk *b;

		if (s[i].type == HAMMER2_BREF_TYPE_EMPTY)
			continue;
		if (!fm_covers(&s[i], key))
			continue;
		b = fm_read_blk(fm, parent, i, &s[i]);
		if (s[i].keybits == FM_LEVEL1)
			return (b);
		return (fm_descend(fm, b, key));
	}
	return (NULL);
}

/*
 * Initialize a newly created LEVEL1 leaf, mirroring hammer2_freemap_init():
 * everything below allocator_beg (and outside the volume) is marked
 * allocated, including the 4MB reserve at the base of the region.
 */
static void
fm_leaf_init(struct recv_freemap *fm, struct fm_blk *leaf, hammer2_off_t region)
{
	hammer2_bmap_data_t *bm = (hammer2_bmap_data_t *)(void *)leaf->data;
	hammer2_off_t lokey, hikey, key;
	int count;

	lokey = (fm->alloc_beg + HAMMER2_SEGMASK64) & ~HAMMER2_SEGMASK64;
	if (lokey < region)
		lokey = region;
	if (lokey < region + HAMMER2_ZONE_SEG64)
		lokey = region + HAMMER2_ZONE_SEG64;

	hikey = region + HAMMER2_FREEMAP_LEVEL1_SIZE;
	if (hikey > fm->volu_end)
		hikey = fm->volu_end & ~HAMMER2_SEGMASK64;

	leaf->bref.check.freemap.avail = HAMMER2_FREEMAP_LEVEL1_SIZE;
	leaf->bref.check.freemap.bigmask = (uint32_t)-1;

	key = region;
	for (count = 0; count < FM_NBMAP; ++count) {
		if (key < lokey || key >= hikey) {
			memset(bm->bitmapq, -1, sizeof(bm->bitmapq));
			bm->avail = 0;
			bm->linear = HAMMER2_SEGSIZE;
			leaf->bref.check.freemap.avail -=
			    HAMMER2_FREEMAP_LEVEL0_SIZE;
		} else {
			bm->avail = HAMMER2_FREEMAP_LEVEL0_SIZE;
		}
		key += HAMMER2_FREEMAP_LEVEL0_SIZE;
		++bm;
	}
}

/*
 * Create a new LEVEL1 leaf for `region'.  It is inserted into a free slot of
 * the root blockset or of an existing node whose children are LEVEL1 leaves.
 * Refuses (returns NULL) if a new intermediate node would be required.
 */
static struct fm_blk *
fm_leaf_create(struct recv_freemap *fm, hammer2_off_t region)
{
	struct fm_blk *parent = &fm->root;
	hammer2_blockref_t zbref;
	int slot = -1;

	for (;;) {
		hammer2_blockref_t *s = fm_slots(fm, parent);
		int n = fm_nslots(parent), i, free_slot = -1, maxlevel = 0;
		struct fm_blk *node = NULL;
		int cover = -1;

		for (i = 0; i < n; ++i) {
			if (s[i].type == HAMMER2_BREF_TYPE_EMPTY) {
				if (free_slot < 0)
					free_slot = i;
				continue;
			}
			if (s[i].keybits > maxlevel)
				maxlevel = s[i].keybits;
			if (fm_covers(&s[i], region)) {
				cover = i;
				break;
			}
		}
		if (cover >= 0) {
			node = fm_read_blk(fm, parent, cover, &s[cover]);
			parent = node;
			continue;
		}
		if (free_slot >= 0 && maxlevel <= FM_LEVEL1) {
			slot = free_slot;
			break;
		}
		return (NULL);
	}

	bzero(&zbref, sizeof(zbref));
	{
		struct fm_blk *leaf;
		hammer2_blockref_t *s;

		leaf = calloc(1, sizeof(*leaf));
		if (leaf == NULL)
			err(1, "recv: out of memory");
		leaf->data = calloc(1, FM_LBLK);
		if (leaf->data == NULL)
			err(1, "recv: out of memory");
		leaf->parent = parent;
		leaf->slot = slot;
		leaf->level = FM_LEVEL1;
		leaf->depth = parent->depth + 1;
		leaf->created = 1;
		leaf->dirty = 1;
		leaf->bref = zbref;
		leaf->bref.type = HAMMER2_BREF_TYPE_FREEMAP_LEAF;
		leaf->bref.methods = HAMMER2_ENC_CHECK(HAMMER2_CHECK_FREEMAP) |
		    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE);
		leaf->bref.keybits = FM_LEVEL1;
		leaf->bref.key = region;
		leaf->bref.mirror_tid = fm->tid;
		leaf->bref.modify_tid = fm->tid;
		leaf->bref.update_tid = fm->tid;
		leaf->next = fm->all;
		fm->all = leaf;

		fm_leaf_init(fm, leaf, region);

		s = fm_slots(fm, parent);
		s[slot] = leaf->bref;
		if (parent != &fm->root)
			parent->dirty = 1;
		return (leaf);
	}
}

static struct fm_blk *
fm_get_leaf(struct recv_freemap *fm, hammer2_off_t region, int create)
{
	struct fm_blk *b;

	for (b = fm->all; b; b = b->next) {
		if (b->level == FM_LEVEL1 && b->bref.key == (hammer2_key_t)region)
			return (b);
	}
	b = fm_descend(fm, &fm->root, region);
	if (b != NULL)
		return (b);
	if (!create)
		return (NULL);
	return (fm_leaf_create(fm, region));
}

/*
 * 16KB-unit bitmap helpers.  Each bitmapq[] element covers 32 units
 * (64 bits / 2).
 */
static int
fm_unit_free(struct fm_blk *leaf, uint32_t unit)
{
	hammer2_bmap_data_t *bm = (hammer2_bmap_data_t *)(void *)leaf->data;
	uint32_t bmi = unit >> 8;		/* 256 units per 4MB bmap */
	uint32_t u = unit & 255;

	return (((bm[bmi].bitmapq[u >> 5] >> ((u & 31) * 2)) & 3) == 0);
}

static void
fm_unit_mark(struct recv_freemap *fm, struct fm_blk *leaf, uint32_t unit)
{
	hammer2_bmap_data_t *bm = (hammer2_bmap_data_t *)(void *)leaf->data;
	uint32_t bmi = unit >> 8;
	uint32_t u = unit & 255;

	bm[bmi].bitmapq[u >> 5] |= (hammer2_bitmap_t)3 << ((u & 31) * 2);
	/*
	 * Clear the kernel's sub-unit linear cursor: it is trusted without a
	 * bitmap test on the fast path, so a stale value could hand out space
	 * we just allocated.
	 */
	bm[bmi].linear = 0;
	if (bm[bmi].class == 0)
		bm[bmi].class = fm->class_hint;
	if (bm[bmi].avail >= FM_LBSIZE)
		bm[bmi].avail -= FM_LBSIZE;
	else
		bm[bmi].avail = 0;
	leaf->dirty = 1;
	fm->alloc_bytes += FM_LBSIZE;
}

/*
 * Find `nunits' consecutive free 16KB units, aligned to `align'.  Returns the
 * physical base or -1.
 */
static hammer2_off_t
fm_alloc_units(struct recv_freemap *fm, uint32_t nunits, hammer2_off_t align)
{
	hammer2_off_t pos = fm->hint;
	hammer2_off_t region;

	if (pos < fm->alloc_beg)
		pos = fm->alloc_beg;
	pos = roundup2(pos, align);

	for (;;) {
		struct fm_blk *leaf;
		uint32_t unit, k;
		hammer2_off_t cand;

		if (pos + ((hammer2_off_t)nunits << HAMMER2_FREEMAP_BLOCK_RADIX)
		    > fm->volu_end)
			return (-1);
		region = H2FMBASE(pos, FM_LEVEL1);
		leaf = fm_get_leaf(fm, region, 1);
		if (leaf == NULL)
			return (-1);
		unit = (uint32_t)((pos - region) >>
		    HAMMER2_FREEMAP_BLOCK_RADIX);
		while (unit + nunits <= FM_UNITS) {
			cand = region +
			    ((hammer2_off_t)unit << HAMMER2_FREEMAP_BLOCK_RADIX);
			if (cand & (align - 1)) {
				++unit;
				continue;
			}
			for (k = 0; k < nunits; ++k) {
				if (!fm_unit_free(leaf, unit + k))
					break;
			}
			if (k == nunits) {
				for (k = 0; k < nunits; ++k)
					fm_unit_mark(fm, leaf, unit + k);
				fm->hint = cand +
				    ((hammer2_off_t)nunits <<
				     HAMMER2_FREEMAP_BLOCK_RADIX);
				return (cand);
			}
			++unit;
		}
		pos = region + HAMMER2_FREEMAP_LEVEL1_SIZE;
	}
}

int
recv_freemap_alloc(struct recv_freemap *fm, int radix, hammer2_off_t *offp)
{
	size_t size;
	hammer2_off_t off;

	if (radix < HAMMER2_RADIX_MIN || radix > HAMMER2_RADIX_MAX)
		return (-1);
	size = (size_t)1 << radix;

	if (radix <= HAMMER2_FREEMAP_BLOCK_RADIX) {
		/*
		 * Sub-16KB (and 16KB) allocations are packed into a 16KB
		 * unit by a private cursor; the unit's two bitmap bits are
		 * set on first use.
		 */
		if (fm->pack_unit == 0 ||
		    fm->pack_off + size > FM_LBSIZE) {
			hammer2_off_t unit = fm_alloc_units(fm, 1, FM_LBSIZE);

			if (unit == FM_BADOFF)
				return (-1);
			fm->pack_unit = unit;
			fm->pack_off = 0;
		}
		if (fm->pack_off & (size - 1)) {
			fm->pack_off = roundup2(fm->pack_off, size);
			if (fm->pack_off + size > FM_LBSIZE) {
				hammer2_off_t unit =
				    fm_alloc_units(fm, 1, FM_LBSIZE);

				if (unit == FM_BADOFF)
					return (-1);
				fm->pack_unit = unit;
				fm->pack_off = 0;
			}
		}
		off = fm->pack_unit + fm->pack_off;
		fm->pack_off += size;
		*offp = off | radix;
		return (0);
	}

	off = fm_alloc_units(fm, (uint32_t)(size >> HAMMER2_FREEMAP_BLOCK_RADIX),
	    (hammer2_off_t)size);
	if (off == FM_BADOFF)
		return (-1);
	*offp = off | radix;
	return (0);
}

/*
 * Reserve-slot layout (hammer2_freemap_reserve).
 */
static hammer2_off_t
fm_reserve_loc(const hammer2_blockref_t *bref, int index)
{
	hammer2_off_t zone;

	switch (bref->keybits) {
	case HAMMER2_FREEMAP_LEVEL1_RADIX:
		zone = HAMMER2_ZONEFM_LEVEL1;
		break;
	case HAMMER2_FREEMAP_LEVEL2_RADIX:
		zone = HAMMER2_ZONEFM_LEVEL2;
		break;
	case HAMMER2_FREEMAP_LEVEL3_RADIX:
		zone = HAMMER2_ZONEFM_LEVEL3;
		break;
	case HAMMER2_FREEMAP_LEVEL4_RADIX:
		zone = HAMMER2_ZONEFM_LEVEL4;
		break;
	case HAMMER2_FREEMAP_LEVEL5_RADIX:
		zone = HAMMER2_ZONEFM_LEVEL5;
		break;
	default:
		return (-1);
	}
	return (H2FMBASE(bref->key, bref->keybits) +
	    ((hammer2_off_t)index * HAMMER2_ZONE_FREEMAP_INC +
	     HAMMER2_ZONE_FREEMAP_00 + zone) * HAMMER2_PBUFSIZE);
}

static int
fm_next_index(const hammer2_blockref_t *bref)
{
	hammer2_off_t o = bref->data_off & ~HAMMER2_OFF_MASK_RADIX;
	int index;

	if (o == 0)
		return (0);
	o &= HAMMER2_SEGMASK;
	o /= HAMMER2_PBUFSIZE;
	index = (int)(o - HAMMER2_ZONE_FREEMAP_00) / HAMMER2_ZONE_FREEMAP_INC;
	if (++index >= HAMMER2_NFREEMAPS)
		index = 0;
	return (index);
}

/*
 * COW-write one modified block to its rotated reserve slot and update the
 * parent's blockref.
 */
static int
fm_cow_write(struct recv_freemap *fm, struct fm_blk *b)
{
	hammer2_off_t newoff;
	hammer2_blockref_t *s;

	newoff = fm_reserve_loc(&b->bref, fm_next_index(&b->bref));
	if (newoff == FM_BADOFF)
		return (-1);

	b->bref.data_off = newoff | FM_LRADIX;
	b->bref.mirror_tid = fm->tid;
	b->bref.modify_tid = fm->tid;
	b->bref.update_tid = fm->tid;
	b->bref.check.freemap.icrc32 = hammer2_icrc32(b->data, FM_LBLK);

	if (recv_write_phys(newoff, b->data, FM_LBLK) != 0)
		return (-1);

	s = fm_slots(fm, b->parent);
	s[b->slot] = b->bref;
	if (b->parent != &fm->root)
		b->parent->dirty = 1;
	return (0);
}

static int
fm_depth_cmp(const void *a, const void *b)
{
	const struct fm_blk *x = *(const struct fm_blk * const *)a;
	const struct fm_blk *y = *(const struct fm_blk * const *)b;

	return (y->depth - x->depth);	/* deepest first */
}

int
recv_freemap_flush(struct recv_freemap *fm, hammer2_tid_t tid)
{
	struct fm_blk **arr, *b;
	int n = 0, i;

	fm->tid = tid;

	for (b = fm->all; b; b = b->next)
		++n;
	arr = calloc(n ? (size_t)n : 1, sizeof(*arr));
	if (arr == NULL)
		err(1, "recv: out of memory");
	for (b = fm->all, i = 0; b; b = b->next)
		arr[i++] = b;
	qsort(arr, (size_t)n, sizeof(*arr), fm_depth_cmp);

	for (i = 0; i < n; ++i) {
		b = arr[i];
		if (!b->dirty)
			continue;
		if (fm_cow_write(fm, b) != 0) {
			free(arr);
			return (-1);
		}
	}
	free(arr);

	if (fm->alloc_bytes >= fm->volp->allocator_free)
		fm->volp->allocator_free = 0;
	else
		fm->volp->allocator_free -= fm->alloc_bytes;
	fm->volp->freemap_tid = fm->tid;

	return (0);
}

struct recv_freemap *
recv_freemap_init(hammer2_volume_data_t *voldata, hammer2_off_t alloc_beg,
    hammer2_off_t volu_end, hammer2_tid_t tid)
{
	struct recv_freemap *fm = calloc(1, sizeof(*fm));

	if (fm == NULL)
		err(1, "recv: out of memory");
	fm->volp = voldata;
	fm->alloc_beg = alloc_beg;
	fm->volu_end = volu_end;
	fm->tid = tid;
	fm->root.level = FM_ROOT;
	fm->root.depth = 0;
	fm->root.parent = NULL;
	fm->hint = alloc_beg;
	fm->class_hint = (HAMMER2_BREF_TYPE_DATA << 8) | HAMMER2_PBUFRADIX;
	return (fm);
}

void
recv_freemap_destroy(struct recv_freemap *fm)
{
	struct fm_blk *b;

	if (fm == NULL)
		return;
	while ((b = fm->all) != NULL) {
		fm->all = b->next;
		free(b->data);
		free(b);
	}
	free(fm);
}
