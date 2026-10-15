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
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * hammer2 recv - deserialize a stream produced by `hammer2 send' onto a
 * destination volume, similar to zfs recv.
 *
 * Payload blocks are reallocated linearly from voldata.allocator_beg,
 * exactly the way newfs_hammer2 allocates its initial blocks: the kernel
 * allocator never hands out blocks below allocator_beg and bulkfree
 * ignores them, so the freemap bitmaps do not have to be touched.  After
 * all blocks are written, allocator_beg is advanced (rounded up to the
 * next 4MB segment so the freemap marks the whole partial segment
 * allocated), a new copy of the super-root inode is written with a dirent
 * for the received PFS, and the volume header(s) are committed last.
 *
 * A crash at any point before the volume header commit leaves the
 * destination in its previous consistent state (the received blocks are
 * simply unreachable); the volume headers are written back-to-front for
 * extra safety.
 *
 * Incremental (-u) streams update an existing PFS: unchanged leaf blocks
 * are located in the destination PFS by bref identity and shared, the way
 * COW snapshots share blocks.  The destination PFS root bref is replaced;
 * the diverged blocks of the previous generation are not reclaimed (they
 * stay below allocator_beg, like all recv allocations).
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "hammer2.h"
#include "hammer2_stream.h"

#define RECV_MAX_DEPTH	16

static ssize_t
read_phys(hammer2_off_t data_off, void *buf, size_t bytes)
{
	hammer2_off_t io_off = data_off & ~HAMMER2_OFF_MASK_RADIX;
	int fd = hammer2_get_volume_fd(io_off);
	hammer2_off_t off;

	if (fd < 0)
		return (-1);
	off = io_off - hammer2_get_volume_offset(io_off);
	return (pread(fd, buf, bytes, off));
}

static int
write_phys(hammer2_off_t data_off, const void *buf, size_t bytes)
{
	hammer2_off_t io_off = data_off & ~HAMMER2_OFF_MASK_RADIX;
	int fd = hammer2_get_volume_fd(io_off);
	hammer2_off_t off;

	if (fd < 0)
		return (-1);
	off = io_off - hammer2_get_volume_offset(io_off);
	return (pwrite(fd, buf, bytes, off) == (ssize_t)bytes ? 0 : -1);
}

static size_t
bref_radix_bytes(const hammer2_blockref_t *bref)
{
	int radix = bref->data_off & HAMMER2_OFF_MASK_RADIX;

	if (radix == 0)
		return (0);
	return ((size_t)1 << radix);
}

/*
 * Compute and store the check code for (rewritten) media data.
 */
static void
calc_check(hammer2_blockref_t *bref, const void *data, size_t bytes)
{
	SHA256_CTX hash_ctx;
	union {
		uint8_t digest[SHA256_DIGEST_LENGTH];
		uint64_t digest64[SHA256_DIGEST_LENGTH / 8];
	} u;

	switch (HAMMER2_DEC_CHECK(bref->methods)) {
	case HAMMER2_CHECK_ISCSI32:
		bref->check.iscsi32.value = hammer2_icrc32(data, bytes);
		break;
	case HAMMER2_CHECK_XXHASH64:
		bref->check.xxhash64.value = XXH64(data, bytes,
		    XXH_HAMMER2_SEED);
		break;
	case HAMMER2_CHECK_SHA192:
		SHA256_Init(&hash_ctx);
		SHA256_Update(&hash_ctx, data, bytes);
		SHA256_Final(u.digest, &hash_ctx);
		u.digest64[2] ^= u.digest64[3];
		bcopy(u.digest, bref->check.sha192.data,
		    sizeof(bref->check.sha192.data));
		break;
	case HAMMER2_CHECK_FREEMAP:
		bref->check.freemap.icrc32 = hammer2_icrc32(data, bytes);
		break;
	default:
		break;
	}
}

static int
test_check(const hammer2_blockref_t *bref, const void *data, size_t bytes)
{
	uint32_t cv;
	uint64_t cv64;
	SHA256_CTX hash_ctx;
	union {
		uint8_t digest[SHA256_DIGEST_LENGTH];
		uint64_t digest64[SHA256_DIGEST_LENGTH / 8];
	} u;

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
		u.digest64[2] ^= u.digest64[3];
		if (memcmp(u.digest, bref->check.sha192.data,
			   sizeof(bref->check.sha192.data)) == 0)
			return (0);
		break;
	case HAMMER2_CHECK_FREEMAP:
		cv = hammer2_icrc32(data, bytes);
		if (bref->check.freemap.icrc32 == cv)
			return (0);
		break;
	default:
		break;
	}
	return (-1);
}

/*
 * Iterate the child blockrefs of a media block (mutable image version).
 */
static int
get_slots_rw(hammer2_blockref_t *bref, void *data, size_t bytes,
	     hammer2_blockref_t **slotsp)
{
	hammer2_inode_data_t *ipdata;
	hammer2_blockref_t *slots;
	int count;

	switch (bref->type) {
	case HAMMER2_BREF_TYPE_INODE:
		ipdata = data;
		if (ipdata->meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA) {
			slots = NULL;
			count = 0;
		} else {
			slots = &ipdata->u.blockset.blockref[0];
			count = HAMMER2_SET_COUNT;
		}
		break;
	case HAMMER2_BREF_TYPE_INDIRECT:
		slots = &((hammer2_media_data_t *)data)->npdata[0];
		count = (int)(bytes / HAMMER2_BLOCKREF_BYTES);
		break;
	default:
		slots = NULL;
		count = 0;
		break;
	}
	*slotsp = slots;
	return (count);
}

/*
 * Map of source data_off -> destination data_off for blocks processed so
 * far.  Parents reference children by source data_off; the map translates.
 */
typedef struct map_entry {
	struct map_entry *next;
	hammer2_off_t old_off;
	hammer2_blockref_t bref;	/* child bref as rewritten (new
					 * data_off and, for rewritten
					 * interior blocks, new methods
					 * and check code) */
} map_entry_t;

#define MAP_HBITS	16
#define MAP_HSIZE	(1 << MAP_HBITS)

static map_entry_t *MapHash[MAP_HSIZE];

static inline uint32_t
map_hash(hammer2_off_t data_off)
{
	return (uint32_t)(data_off * 2654435761U) >> (32 - MAP_HBITS);
}

static map_entry_t *
map_find(hammer2_off_t old_off)
{
	map_entry_t *e;

	for (e = MapHash[map_hash(old_off)]; e; e = e->next)
		if (e->old_off == old_off)
			return (e);
	return (NULL);
}

static void
map_add(hammer2_off_t old_off, const hammer2_blockref_t *newbref)
{
	map_entry_t *e = malloc(sizeof(*e));

	if (e == NULL)
		err(1, "recv: out of memory");
	e->old_off = old_off;
	e->bref = *newbref;
	e->next = MapHash[map_hash(old_off)];
	MapHash[map_hash(old_off)] = e;
}

/*
 * Destination from-generation leaf index (for -u).  Keyed by the bref
 * with data_off zeroed, mapping to the destination data_off.
 */
typedef struct leaf_entry {
	struct leaf_entry *next;
	hammer2_blockref_t key;		/* bref with data_off zeroed */
	hammer2_off_t data_off;		/* destination media location */
} leaf_entry_t;

#define LEAF_HBITS	16
#define LEAF_HSIZE	(1 << LEAF_HBITS)

static leaf_entry_t *LeafHash[LEAF_HSIZE];

static void
leaf_key(const hammer2_blockref_t *bref, hammer2_blockref_t *key)
{
	*key = *bref;
	key->data_off = 0;
}

static inline uint32_t
leaf_hash(const hammer2_blockref_t *key)
{
	const uint8_t *p = (const uint8_t *)(const void *)key;
	uint32_t h = 2166136261U;
	int i;

	for (i = 0; i < HAMMER2_BLOCKREF_BYTES; ++i)
		h = (h ^ p[i]) * 16777619U;
	return (h >> (32 - LEAF_HBITS));
}

static void
leaf_add(const hammer2_blockref_t *bref)
{
	leaf_entry_t *e = malloc(sizeof(*e));

	if (e == NULL)
		err(1, "recv: out of memory");
	leaf_key(bref, &e->key);
	e->data_off = bref->data_off;
	e->next = LeafHash[leaf_hash(&e->key)];
	LeafHash[leaf_hash(&e->key)] = e;
}

static leaf_entry_t *
leaf_find(const hammer2_blockref_t *bref)
{
	leaf_entry_t *e;
	hammer2_blockref_t key;

	leaf_key(bref, &key);
	for (e = LeafHash[leaf_hash(&key)]; e; e = e->next)
		if (memcmp(&e->key, &key, sizeof(key)) == 0)
			return (e);
	return (NULL);
}

static int
is_leaf_bref(const hammer2_blockref_t *bref, const void *data)
{
	if (bref->type == HAMMER2_BREF_TYPE_DATA ||
	    bref->type == HAMMER2_BREF_TYPE_DIRENT)
		return (1);
	if (bref->type == HAMMER2_BREF_TYPE_INODE &&
	    ((const hammer2_inode_data_t *)data)->meta.op_flags &
	    HAMMER2_OPFLAG_DIRECTDATA)
		return (1);
	return (0);
}

/*
 * Linear allocator, newfs_hammer2 style: power-of-2 sized, size-aligned,
 * skipping the 4MB freemap/volhdr reserve at every 1GB boundary.  All
 * received blocks land below the final allocator_beg, so neither the
 * kernel allocator nor bulkfree will ever hand them out again.
 */
static hammer2_off_t AllocBase;
static uint64_t AllocBytes;
static hammer2_off_t VoluEnd;

static int
recv_alloc(int radix, hammer2_off_t *offp)
{
	size_t bytes = (size_t)1 << radix;

	if (radix < HAMMER2_RADIX_MIN || radix > HAMMER2_RADIX_MAX)
		return (-1);
	if (AllocBase & (bytes - 1))
		AllocBase = (AllocBase + bytes - 1) &
		    ~((hammer2_off_t)bytes - 1);
	if ((AllocBase & HAMMER2_FREEMAP_LEVEL1_MASK) < HAMMER2_ZONE_SEG)
		AllocBase = (AllocBase & ~HAMMER2_FREEMAP_LEVEL1_MASK) +
		    HAMMER2_ZONE_SEG;
	if (AllocBase + bytes > VoluEnd)
		return (-1);
	*offp = AllocBase | radix;
	AllocBase += bytes;
	AllocBytes += bytes;
	return (0);
}

static uint64_t RecvRecords;
static uint64_t RecvPayloadBytes;
static uint64_t RecvRefRecords;
static hammer2_tid_t StreamMaxTid;

static void
track_tid(hammer2_tid_t tid)
{
	if (tid > StreamMaxTid)
		StreamMaxTid = tid;
}

/*
 * Translate the source child blockrefs inside a received inode/indirect
 * block image.  Returns the number of substitutions, or -1 on a dangling
 * reference (child never seen in the stream / destination).
 */
static int
substitute_slots(hammer2_blockref_t *bref, void *data, size_t bytes)
{
	hammer2_blockref_t *slots;
	int count, i, nsub = 0;

	count = get_slots_rw(bref, data, bytes, &slots);
	for (i = 0; i < count; ++i) {
		map_entry_t *m;
		hammer2_blockref_t *slot = &slots[i];

		if (slot->data_off == 0)
			continue;
		m = map_find(slot->data_off);
		if (m == NULL)
			return (-1);
		/*
		 * Replace the fields the receiver may have changed:
		 * the media location, and for rewritten interior
		 * blocks the compression bits and the check code (the
		 * block contents changed, so its check changed and
		 * every parent's embedded copy must follow).  The
		 * slot's own key, tids and embedded data stay.
		 */
		if (m->bref.data_off != slot->data_off ||
		    m->bref.methods != slot->methods ||
		    memcmp(&m->bref.check, &slot->check,
			   sizeof(slot->check)) != 0) {
			slot->data_off = m->bref.data_off;
			slot->methods = m->bref.methods;
			slot->check = m->bref.check;
			++nsub;
		}
	}
	return (nsub);
}

/*
 * Find a PFS root inode bref by label under the destination super-root.
 * Recurses through the super-root's blockset and indirect blocks.
 *
 * On a match, PfsSlot is the top-level blockset slot the walk entered
 * through, and PfsIndirect is set when the match was reached through an
 * sroot-level indirect block rather than a top-level slot.
 */
static int PfsSlot = -1;
static int PfsIndirect;

static int
find_dest_pfs(hammer2_blockref_t *bref, const char *label,
	      hammer2_blockref_t *resp, int depth)
{
	hammer2_media_data_t media;
	size_t bytes;
	int i;

	if (depth > 4)
		return (0);
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return (0);
	if (read_phys(bref->data_off, &media, bytes) != (ssize_t)bytes)
		errx(1, "recv: read failed at %016llx",
		    (long long)bref->data_off);
	if (test_check(bref, &media, bytes))
		errx(1, "recv: destination check code mismatch at %016llx",
		    (long long)bref->data_off);

	if (bref->type == HAMMER2_BREF_TYPE_INODE &&
	    media.ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) {
		const char *name = (const char *)media.ipdata.filename;
		int len = media.ipdata.meta.name_len;

		if (len == (int)strlen(label) &&
		    memcmp(name, label, len) == 0) {
			*resp = *bref;
			if (depth != 1)
				PfsIndirect = 1;
			return (1);
		}
	}

	if (bref->type == HAMMER2_BREF_TYPE_INODE) {
		if (media.ipdata.meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA)
			return (0);
		for (i = 0; i < HAMMER2_SET_COUNT; ++i) {
			if (depth == 0)
				PfsSlot = i;
			if (find_dest_pfs(
			    &media.ipdata.u.blockset.blockref[i],
			    label, resp, depth + 1))
				return (1);
		}
	} else if (bref->type == HAMMER2_BREF_TYPE_INDIRECT) {
		int count = (int)(bytes / HAMMER2_BLOCKREF_BYTES);

		for (i = 0; i < count; ++i)
			if (find_dest_pfs(&media.npdata[i], label, resp,
			    depth + 1))
				return (1);
	}
	return (0);
}

static void
collect_dest_labels(hammer2_blockref_t *bref, char ***labelsp, int *nlabelsp,
		    int depth)
{
	hammer2_media_data_t media;
	size_t bytes;
	int i;

	if (depth > 4)
		return;
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return;
	if (read_phys(bref->data_off, &media, bytes) != (ssize_t)bytes)
		return;

	if (bref->type == HAMMER2_BREF_TYPE_INODE &&
	    media.ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) {
		*labelsp = realloc(*labelsp,
			(*nlabelsp + 1) * sizeof(char *));
		if (*labelsp == NULL)
			err(1, "recv: out of memory");
		(*labelsp)[*nlabelsp] = strndup(
		    (const char *)media.ipdata.filename,
		    media.ipdata.meta.name_len);
		if ((*labelsp)[*nlabelsp] == NULL)
			err(1, "recv: out of memory");
		++*nlabelsp;
		if (media.ipdata.meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA)
			return;
		for (i = 0; i < HAMMER2_SET_COUNT; ++i)
			collect_dest_labels(
			    &media.ipdata.u.blockset.blockref[i],
			    labelsp, nlabelsp, depth + 1);
	} else if (bref->type == HAMMER2_BREF_TYPE_INDIRECT) {
		int count = (int)(bytes / HAMMER2_BLOCKREF_BYTES);

		for (i = 0; i < count; ++i)
			collect_dest_labels(&media.npdata[i], labelsp,
			    nlabelsp, depth + 1);
	}
}

/*
 * Build the destination from-generation leaf index (-u).
 */
static uint64_t IndexLeaves;

static void
index_dest_tree(hammer2_blockref_t *bref, int depth)
{
	hammer2_media_data_t media;
	hammer2_blockref_t *slots;
	size_t bytes;
	int count, i;

	if (depth > RECV_MAX_DEPTH)
		return;
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return;
	if (read_phys(bref->data_off, &media, bytes) != (ssize_t)bytes)
		errx(1, "recv: read failed at %016llx",
		    (long long)bref->data_off);
	if (test_check(bref, &media, bytes))
		errx(1, "recv: destination check code mismatch at %016llx",
		    (long long)bref->data_off);

	if (is_leaf_bref(bref, &media) && bref->data_off) {
		leaf_add(bref);
		++IndexLeaves;
	}

	count = get_slots_rw(bref, &media, bytes, &slots);
	for (i = 0; i < count; ++i)
		index_dest_tree(&slots[i], depth + 1);
}

/*
 * Read one record.  Returns 1 on success, 0 on clean EOF.
 */
static int
read_record(FILE *fp, hammer2_stream_record_t *rec, void *buf)
{
	if (fread(rec, sizeof(*rec), 1, fp) != 1) {
		if (ferror(fp))
			err(1, "recv: stream read");
		if (getchar() != EOF)
			errx(1, "recv: truncated stream record");
		return (0);
	}
	if (rec->magic != HAMMER2_STREAM_RECMAGIC)
		errx(1, "recv: bad record magic (corrupt stream)");
	if (rec->flags & ~HAMMER2_STREAM_RECF_REF)
		errx(1, "recv: unknown record flags %08x", rec->flags);
	if (rec->size > HAMMER2_PBUFSIZE)
		errx(1, "recv: record payload too large");
	if (rec->size && fread(buf, rec->size, 1, fp) != 1)
		errx(1, "recv: truncated stream payload");
	if (rec->size && rec->check != hammer2_icrc32(buf, rec->size))
		errx(1, "recv: record payload crc mismatch");
	return (1);
}

/*
 * Process one stream record.  Returns 0 on success.
 * On success with a media block, *newbrefp is the blockref with the
 * DESTINATION data_off substituted (for root tracking).
 */
static int
process_record(const hammer2_stream_record_t *rec, void *buf,
	       hammer2_blockref_t *newbrefp)
{
	hammer2_blockref_t bref = rec->bref;
	hammer2_off_t new_off;
	size_t bytes;
	int nsub;

	track_tid(bref.mirror_tid);
	track_tid(bref.modify_tid);
	track_tid(bref.update_tid);

	if (rec->flags & HAMMER2_STREAM_RECF_REF) {
		leaf_entry_t *le;

		if (bref.data_off == 0)
			errx(1, "recv: REF record without media reference");
		le = leaf_find(&bref);
		if (le == NULL)
			errx(1, "recv: referenced block %016llx not found "
			    "in destination PFS (stream does not match "
			    "destination state)",
			    (long long)bref.data_off);
		bref.data_off = le->data_off;
		map_add(rec->bref.data_off, &bref);
		++RecvRefRecords;
		return (-1);
	}

	bytes = bref_radix_bytes(&bref);
	if (bytes == 0 || rec->size != bytes)
		errx(1, "recv: record size %u does not match bref radix "
		    "(%zu bytes)", rec->size, bytes);
	if (test_check(&bref, buf, bytes))
		errx(1, "recv: stream check code mismatch at %016llx",
		    (long long)bref.data_off);
	if (map_find(bref.data_off) != NULL) {
		/*
		 * Duplicate reference (dedup): the physical block is
		 * already placed, the map entry covers all references.
		 */
		return (-1);
	}

	switch (bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
		nsub = substitute_slots(&bref, buf, bytes);
		if (nsub < 0)
			errx(1, "recv: dangling child reference in %s "
			    "block at %016llx",
			    hammer2_breftype_to_str(bref.type),
			    (long long)bref.data_off);
		if (nsub > 0) {
			/*
			 * Store rewritten interior blocks uncompressed;
			 * only DATA blocks are decompressed by the
			 * kernel on read, so this is what a raw block
			 * looks like.
			 */
			bref.methods = HAMMER2_ENC_CHECK(
			    HAMMER2_DEC_CHECK(bref.methods)) |
			    HAMMER2_ENC_COMP(HAMMER2_COMP_NONE);
			calc_check(&bref, buf, bytes);
		}
		break;
	default:
		break;
	}

	if (recv_alloc(bref.data_off & HAMMER2_OFF_MASK_RADIX, &new_off))
		errx(1, "recv: out of space on destination volume");
	if (write_phys(new_off & ~HAMMER2_OFF_MASK_RADIX, buf, bytes))
		err(1, "recv: write failed at %016llx",
		    (long long)new_off);

	bref.data_off = new_off;
	map_add(rec->bref.data_off, &bref);
	*newbrefp = bref;

	++RecvRecords;
	RecvPayloadBytes += bytes;
	return (0);
}

static int
blkref_cmp(const void *a, const void *b)
{
	const hammer2_blockref_t *b1 = a;
	const hammer2_blockref_t *b2 = b;
	int e1, e2;

	e1 = (b1->type == HAMMER2_BREF_TYPE_EMPTY || b1->type == 0);
	e2 = (b2->type == HAMMER2_BREF_TYPE_EMPTY || b2->type == 0);
	if (e1 != e2)
		return (e1 - e2);
	if (b1->key < b2->key)
		return (-1);
	if (b1->key > b2->key)
		return (1);
	return (0);
}

static void
pick_sroot(const hammer2_volume_data_t *voldata, hammer2_blockref_t *resp,
	   int *slotp)
{
	const hammer2_blockref_t *bref;
	int i;

	bzero(resp, sizeof(*resp));
	*slotp = -1;
	for (i = 0; i < HAMMER2_SET_COUNT; ++i) {
		bref = &voldata->sroot_blockset.blockref[i];
		if (bref->type != HAMMER2_BREF_TYPE_INODE ||
		    bref->data_off == 0)
			continue;
		if (resp->data_off == 0 || resp->mirror_tid < bref->mirror_tid) {
			*resp = *bref;
			*slotp = i;
		}
	}
	if (resp->data_off == 0)
		errx(1, "recv: no super-root in volume header");
}

int
cmd_recv(int ac, char **av)
{
	hammer2_volume_data_t *volp;
	hammer2_volume_data_t voldata;
	hammer2_stream_header_t hdr;
	hammer2_stream_record_t rec;
	hammer2_media_data_t media;
	hammer2_blockref_t sroot_bref;
	hammer2_blockref_t sroot_new;
	hammer2_blockref_t dest_pfs_bref;
	hammer2_blockref_t root_bref;
	hammer2_blockref_t *slots;
	hammer2_tid_t new_tid;
	hammer2_off_t sroot_off;
	char **labels = NULL;
	int nlabels = 0;
	const char *devpath = NULL;
	const char *ulabel = NULL;
	int sroot_slot = -1;
	int pfs_slot = -1;
	int have_root = 0;
	int update = 0;
	int i, rcode = 0;

	for (i = 0; i < ac; ++i) {
		if (strcmp(av[i], "-v") == 0) {
			
		} else if (strcmp(av[i], "-u") == 0) {
			if (i + 1 >= ac)
				errx(1, "recv: -u requires the destination "
				    "PFS label to update");
			ulabel = av[++i];
			update = 1;
		} else if (devpath == NULL) {
			devpath = av[i];
		} else {
			errx(1, "recv: too many arguments");
		}
	}
	if (devpath == NULL)
		errx(1, "recv: requires device path");
	if (update && strlen(ulabel) >= sizeof(hdr.label))
		errx(1, "recv: -u label too long");

	/*
	 * recv writes raw blocks and commits the volume header itself;
	 * it requires exclusive offline access to the destination
	 * volume.  A mounted filesystem (read-only or not) would race
	 * with the commit and corrupt both.
	 */
	if (hammer2_volume_is_mounted(devpath) > 0)
		errx(1, "recv: destination volume %s is mounted", devpath);

	if (fread(&hdr, sizeof(hdr), 1, stdin) != 1)
		errx(1, "recv: cannot read stream header");
	if (memcmp(hdr.magic, HAMMER2_STREAM_MAGIC, sizeof(hdr.magic)) != 0)
		errx(1, "recv: bad stream magic");
	if (hdr.version != HAMMER2_STREAM_VERSION)
		errx(1, "recv: unsupported stream version %u", hdr.version);
	if (hdr.check != hammer2_icrc32(&hdr, sizeof(hdr) -
					sizeof(hdr.check)))
		errx(1, "recv: stream header crc mismatch");
	if (VerboseOpt)
		fprintf(stderr, "recv: stream PFS \"%s\"%s%s flags %08x\n",
		    hdr.label,
		    hdr.fromlabel[0] ? " (from " : "",
		    hdr.fromlabel[0] ? hdr.fromlabel : "",
		    hdr.flags);

	if ((hdr.flags & HAMMER2_STREAM_FLAG_INCR) != 0 && !update)
		errx(1, "recv: stream is incremental, use -u");
	if ((hdr.flags & HAMMER2_STREAM_FLAG_INCR) == 0 && update)
		errx(1, "recv: stream is not incremental, drop -u");

	hammer2_init_volumes(devpath, 0);
	if (hammer2_get_total_size() != hammer2_get_root_volume_size())
		errx(1, "recv: multi-volume destinations are not "
		    "supported yet");
	VoluEnd = hammer2_get_root_volume_size();

	volp = hammer2_read_root_volume_header();
	if (volp == NULL)
		errx(1, "recv: no valid volume header on %s", devpath);
	voldata = *volp;

	pick_sroot(&voldata, &sroot_bref, &sroot_slot);
	if (read_phys(sroot_bref.data_off, &media,
		      bref_radix_bytes(&sroot_bref)) !=
	    (ssize_t)bref_radix_bytes(&sroot_bref))
		errx(1, "recv: cannot read destination super-root");
	if (test_check(&sroot_bref, &media, bref_radix_bytes(&sroot_bref)))
		errx(1, "recv: destination super-root check mismatch");

	bzero(&dest_pfs_bref, sizeof(dest_pfs_bref));
	PfsSlot = -1;
	PfsIndirect = 0;
	if (find_dest_pfs(&sroot_bref, update ? ulabel : hdr.label,
			  &dest_pfs_bref, 0)) {
		if (!update)
			errx(1, "recv: destination already has PFS \"%s\"",
			    hdr.label);
		if (PfsIndirect || PfsSlot < 0)
			errx(1, "recv: PFS \"%s\" is not in the super-root "
			    "blockset, cannot update", ulabel);
		pfs_slot = PfsSlot;
		if (dest_pfs_bref.key != hdr.from_key ||
		    dest_pfs_bref.modify_tid != hdr.from_modify_tid)
			errx(1, "recv: destination PFS \"%s\" does not "
			    "match the stream's from-generation "
			    "(key %016llx/%016llx mtid %ju/%ju)",
			    ulabel,
			    (long long)dest_pfs_bref.key,
			    (long long)hdr.from_key,
			    (uintmax_t)dest_pfs_bref.modify_tid,
			    (uintmax_t)hdr.from_modify_tid);
	} else {
		if (update)
			errx(1, "recv: destination has no PFS \"%s\" to "
			    "update", ulabel);
		collect_dest_labels(&sroot_bref, &labels, &nlabels, 0);
	}

	if (update)
		index_dest_tree(&dest_pfs_bref, 0);

	AllocBase = voldata.allocator_beg;
	if (AllocBase == 0)
		errx(1, "recv: destination volume has allocator_beg == 0");
	if (AllocBase & HAMMER2_PBUFMASK64)
		AllocBase = (AllocBase + HAMMER2_PBUFMASK64) &
		    ~HAMMER2_PBUFMASK64;

	/*
	 * Process the stream.  Nothing on the destination is modified
	 * until the final volume header commit.
	 */
	bzero(&root_bref, sizeof(root_bref));
	while (read_record(stdin, &rec, media.buf)) {
		if (process_record(&rec, media.buf, &root_bref) == 0)
			have_root = 1;
	}
	if (!have_root)
		errx(1, "recv: stream contained no PFS root");
	if (root_bref.type != HAMMER2_BREF_TYPE_INODE ||
	    (root_bref.flags & HAMMER2_BREF_FLAG_PFSROOT) == 0)
		errx(1, "recv: stream root is not a PFS root inode");

	if (update) {
		/*
		 * Keep the destination PFS label: the received root
		 * inode carries the source label, but the super-root
		 * dirent and the label lookup use the destination
		 * name.  Patch the root inode image in place (the
		 * block is ours; nothing references it yet).
		 */
		size_t bl = bref_radix_bytes(&root_bref);
		size_t ulen = strlen(ulabel);

		if (bl != HAMMER2_INODE_BYTES ||
		    read_phys(root_bref.data_off & ~HAMMER2_OFF_MASK_RADIX,
			      &media, bl) != (ssize_t)bl)
			errx(1, "recv: cannot re-read received PFS root");
		bzero(media.ipdata.filename,
		    sizeof(media.ipdata.filename));
		bcopy(ulabel, media.ipdata.filename, ulen);
		media.ipdata.meta.name_len = ulen;
		media.ipdata.meta.name_key = dirhash(ulabel, ulen);
		root_bref.key = media.ipdata.meta.name_key;
		calc_check(&root_bref, &media, bl);
		if (write_phys(root_bref.data_off & ~HAMMER2_OFF_MASK_RADIX,
			       &media, bl))
			err(1, "recv: PFS root relabel write failed");
	}

	/*
	 * Commit: new super-root inode copy, then the volume header(s).
	 */
	new_tid = voldata.mirror_tid;
	if (StreamMaxTid > new_tid)
		new_tid = StreamMaxTid;
	++new_tid;

	root_bref.mirror_tid = new_tid;
	if (recv_alloc(HAMMER2_RADIX_MIN, &sroot_off))
		errx(1, "recv: out of space for super-root");
	if (read_phys(sroot_bref.data_off, &media,
		      bref_radix_bytes(&sroot_bref)) !=
	    (ssize_t)bref_radix_bytes(&sroot_bref))
		errx(1, "recv: cannot re-read destination super-root");
	if (bref_radix_bytes(&sroot_bref) != HAMMER2_INODE_BYTES)
		errx(1, "recv: super-root bref has unexpected size");

	if (update) {
		media.ipdata.u.blockset.blockref[pfs_slot] = root_bref;
	} else {
		int count;

		count = get_slots_rw(&sroot_bref, &media,
		    HAMMER2_INODE_BYTES, &slots);
		for (i = 0; i < count; ++i) {
			if (slots[i].type == HAMMER2_BREF_TYPE_EMPTY)
				break;
		}
		if (i == count)
			errx(1, "recv: destination super-root blockset is "
			    "full (%d PFS entries)", count);
		slots[i] = root_bref;
		count = get_slots_rw(&sroot_bref, &media,
		    HAMMER2_INODE_BYTES, &slots);
		qsort(slots, count, sizeof(*slots), blkref_cmp);
	}

	sroot_new = sroot_bref;
	sroot_new.data_off = sroot_off | HAMMER2_RADIX_MIN;
	sroot_new.mirror_tid = new_tid;
	calc_check(&sroot_new, &media, HAMMER2_INODE_BYTES);
	if (write_phys(sroot_off, &media, HAMMER2_INODE_BYTES))
		err(1, "recv: super-root write failed");

	/*
	 * Advance the allocator past everything we placed, rounded up to
	 * the next 4MB segment so the freemap init marks the whole
	 * partial segment as allocated.
	 */
	voldata.allocator_beg = (AllocBase + HAMMER2_SEGMASK64) &
	    ~HAMMER2_SEGMASK64;
	if (voldata.allocator_beg > VoluEnd)
		voldata.allocator_beg = VoluEnd;
	if (voldata.allocator_free > AllocBytes)
		voldata.allocator_free -= AllocBytes;
	else
		voldata.allocator_free = 0;

	voldata.sroot_blockset.blockref[sroot_slot] = sroot_new;
	voldata.mirror_tid = new_tid;

	voldata.icrc_sects[HAMMER2_VOL_ICRC_SECT1] =
	    hammer2_icrc32((char *)&voldata + HAMMER2_VOLUME_ICRC1_OFF,
			   HAMMER2_VOLUME_ICRC1_SIZE);
	voldata.icrc_sects[HAMMER2_VOL_ICRC_SECT0] =
	    hammer2_icrc32((char *)&voldata + HAMMER2_VOLUME_ICRC0_OFF,
			   HAMMER2_VOLUME_ICRC0_SIZE);
	voldata.icrc_volheader =
	    hammer2_icrc32((char *)&voldata + HAMMER2_VOLUME_ICRCVH_OFF,
			   HAMMER2_VOLUME_ICRCVH_SIZE);

	{
		int fd = hammer2_get_root_volume_fd();

		for (i = HAMMER2_NUM_VOLHDRS - 1; i >= 0; --i) {
			hammer2_off_t off = (hammer2_off_t)i *
			    HAMMER2_ZONE_BYTES64;

			if (off >= VoluEnd)
				continue;
			if (pwrite(fd, &voldata, HAMMER2_VOLUME_BYTES, off)
			    != HAMMER2_VOLUME_BYTES)
				err(1, "recv: volume header write failed");
		}
		if (fsync(fd))
			err(1, "recv: fsync failed");
	}

	fprintf(stderr, "recv: PFS \"%s\"%s%s: %ju blocks (%ju payload "
	    "bytes), %ju refs, allocator_beg %016llx, mirror_tid %ju\n",
	    hdr.label,
	    update ? " (updated" : "",
	    update ? ")" : "",
	    (uintmax_t)RecvRecords,
	    (uintmax_t)RecvPayloadBytes,
	    (uintmax_t)RecvRefRecords,
	    (long long)voldata.allocator_beg,
	    (uintmax_t)voldata.mirror_tid);
	if (VerboseOpt)
		fprintf(stderr, "recv: root bref at %016llx\n",
		    (long long)root_bref.data_off);
	return (rcode);
}
