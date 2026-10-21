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

#include <stddef.h>

#include <sys/sha2.h>

#include "hammer2.h"
#include "hammer2_stream.h"
#include "recv_freemap.h"

#define RECV_MAX_DEPTH	16

static size_t
bref_radix_bytes(const hammer2_blockref_t *bref)
{
	int radix = bref->data_off & HAMMER2_OFF_MASK_RADIX;

	if (radix == 0)
		return (0);
	return ((size_t)1 << radix);
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
 * Destination from-generation leaf index (for -u): hammer2_leaf_add()/
 * hammer2_leaf_find() (subs.c), keyed by bref identity (bref with
 * data_off zeroed, mapping to the destination data_off).
 */

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
 * kernel allocator nor bulkfree will ever hand them out again.  This is
 * only valid for a pristine destination (no on-media freemap); a used
 * destination is allocated from its freemap instead (recv_freemap.c).
 */
static hammer2_off_t AllocBase;
static uint64_t AllocBytes;
static hammer2_off_t VoluEnd;
static struct recv_freemap *Freemap;

static int
recv_alloc(int radix, hammer2_off_t *offp)
{
	size_t bytes = (size_t)1 << radix;

	if (radix < HAMMER2_RADIX_MIN || radix > HAMMER2_RADIX_MAX)
		return (-1);
	if (Freemap != NULL)
		return (recv_freemap_alloc(Freemap, radix, offp));
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
	      hammer2_blockref_t *resp, struct uuid *clidp, int depth)
{
	hammer2_media_data_t media;
	size_t bytes;
	int i;

	if (depth > 4)
		return (0);
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return (0);
	if (bytes > HAMMER2_PBUFSIZE)
		errx(1, "recv: bogus block size at %016jx",
		    (intmax_t)bref->data_off);
	if (recv_read_phys(bref->data_off, &media, bytes) != (ssize_t)bytes)
		errx(1, "recv: read failed at %016jx",
		    (intmax_t)bref->data_off);
	if (hammer2_check_verify(bref, &media, bytes))
		errx(1, "recv: destination check code mismatch at %016jx",
		    (intmax_t)bref->data_off);

	if (bref->type == HAMMER2_BREF_TYPE_INODE &&
	    media.ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) {
		const char *name = (const char *)media.ipdata.filename;
		int len = media.ipdata.meta.name_len;

		/*
		 * PFS roots are leaves of the super-root namespace: never
		 * descend into a PFS's own file tree (that would walk
		 * every unrelated PFS's media and make recv fail on
		 * corruption in a PFS we are not interested in).
		 */
		if (len == (int)strlen(label) &&
		    memcmp(name, label, len) == 0) {
			*resp = *bref;
			*clidp = media.ipdata.meta.pfs_clid;
			if (depth != 1)
				PfsIndirect = 1;
			return (1);
		}
		return (0);
	}

	if (bref->type == HAMMER2_BREF_TYPE_INODE) {
		if (media.ipdata.meta.op_flags & HAMMER2_OPFLAG_DIRECTDATA)
			return (0);
		for (i = 0; i < HAMMER2_SET_COUNT; ++i) {
			if (depth == 0)
				PfsSlot = i;
			if (find_dest_pfs(
			    &media.ipdata.u.blockset.blockref[i],
			    label, resp, clidp, depth + 1))
				return (1);
		}
	} else if (bref->type == HAMMER2_BREF_TYPE_INDIRECT) {
		int count = (int)(bytes / HAMMER2_BLOCKREF_BYTES);

		for (i = 0; i < count; ++i)
			if (find_dest_pfs(&media.npdata[i], label, resp,
			    clidp, depth + 1))
				return (1);
	}
	return (0);
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
	if (bytes > HAMMER2_PBUFSIZE)
		errx(1, "recv: bogus block size at %016jx",
		    (intmax_t)bref->data_off);
	if (recv_read_phys(bref->data_off, &media, bytes) != (ssize_t)bytes)
		errx(1, "recv: read failed at %016jx",
		    (intmax_t)bref->data_off);
	if (hammer2_check_verify(bref, &media, bytes))
		errx(1, "recv: destination check code mismatch at %016jx",
		    (intmax_t)bref->data_off);

	if (is_leaf_bref(bref, &media) && bref->data_off) {
		hammer2_leaf_add(bref);
		++IndexLeaves;
	}

	count = get_slots_rw(bref, &media, bytes, &slots);
	for (i = 0; i < count; ++i)
		index_dest_tree(&slots[i], depth + 1);
}

/*
 * Read one record.  Returns 1 on success, 0 on clean EOF.
 *
 * The header is read in BYTE units: fread(3) only short-counts at EOF or
 * error, so a stream truncated mid-header is detected here immediately
 * (a record-granular fread would consume the partial bytes and report a
 * misleading clean EOF).  Record-boundary truncation (a stream ending
 * exactly between records) remains detected by the root-last/PFSROOT
 * check in the caller's loop.
 */
static int
read_record(FILE *fp, hammer2_stream_record_t *rec, void *buf)
{
	size_t got = 0;

	while (got < sizeof(*rec)) {
		size_t n = fread((char *)rec + got, 1,
		    sizeof(*rec) - got, fp);
		if (n == 0) {
			if (ferror(fp))
				err(1, "recv: stream read");
			if (got != 0)
				errx(1, "recv: truncated stream record");
			return (0);
		}
		got += n;
	}
	if (rec->hcheck != hammer2_icrc32(rec,
	    offsetof(hammer2_stream_record_t, hcheck)))
		errx(1, "recv: record header crc mismatch (corrupt stream)");
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
		hammer2_off_t dest_off;

		if (bref.data_off == 0)
			errx(1, "recv: REF record without media reference");
		dest_off = hammer2_leaf_find(&bref);
		if (dest_off == 0)
			errx(1, "recv: referenced block %016jx not found "
			    "in destination PFS (stream does not match "
			    "destination state)",
			    (intmax_t)bref.data_off);
		bref.data_off = dest_off;
		map_add(rec->bref.data_off, &bref);
		++RecvRefRecords;
		return (-1);
	}

	bytes = bref_radix_bytes(&bref);
	if (bytes == 0 || rec->size != bytes)
		errx(1, "recv: record size %u does not match bref radix "
		    "(%zu bytes)", rec->size, bytes);
	/*
	 * Only block types that can appear in a PFS tree are accepted;
	 * anything else in a stream is corrupt or hand-crafted, and
	 * writing it verbatim would plant garbage on the destination.
	 */
	switch (bref.type) {
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_DIRENT:
		break;
	default:
		errx(1, "recv: unsupported bref type %s (%d) in stream",
		    hammer2_breftype_to_str(bref.type), bref.type);
	}
	if (hammer2_check_verify(&bref, buf, bytes))
		errx(1, "recv: stream check code mismatch at %016jx",
		    (intmax_t)bref.data_off);
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
			    "block at %016jx",
			    hammer2_breftype_to_str(bref.type),
			    (intmax_t)bref.data_off);
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
			hammer2_check_calc(&bref, buf, bytes);
		}
		break;
	default:
		break;
	}

	if (recv_alloc(bref.data_off & HAMMER2_OFF_MASK_RADIX, &new_off))
		errx(1, "recv: out of space on destination volume");
	if (recv_write_phys(new_off & ~HAMMER2_OFF_MASK_RADIX, buf, bytes))
		err(1, "recv: write failed at %016jx",
		    (intmax_t)new_off);

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
	struct uuid dest_clid;
	hammer2_blockref_t root_bref;
	hammer2_blockref_t *slots;
	hammer2_tid_t new_tid;
	hammer2_off_t sroot_off;
	const char *devpath = NULL;
	const char *ulabel = NULL;
	int sroot_slot = -1;
	int pfs_slot = -1;
	int have_root = 0;
	int update = 0;
	int i, rcode = 0;

	for (i = 0; i < ac; ++i) {
		if (strcmp(av[i], "-v") == 0) {
			/* -v is a global option, handled in main() */
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
	/*
	 * Unknown header flag bits are rejected, exactly like unknown
	 * record flags: a sender that knows flag bits this receiver does
	 * not MUST have bumped the stream version (which the version
	 * check above already rejects).
	 */
	if (hdr.flags & ~HAMMER2_STREAM_FLAG_INCR)
		errx(1, "recv: unknown stream header flags %08x", hdr.flags);
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
	if (recv_read_phys(sroot_bref.data_off, &media,
		      bref_radix_bytes(&sroot_bref)) !=
	    (ssize_t)bref_radix_bytes(&sroot_bref))
		errx(1, "recv: cannot read destination super-root");
	if (hammer2_check_verify(&sroot_bref, &media, bref_radix_bytes(&sroot_bref)))
		errx(1, "recv: destination super-root check mismatch");

	bzero(&dest_pfs_bref, sizeof(dest_pfs_bref));
	bzero(&dest_clid, sizeof(dest_clid));
	PfsSlot = -1;
	PfsIndirect = 0;
	if (find_dest_pfs(&sroot_bref, update ? ulabel : hdr.label,
			  &dest_pfs_bref, &dest_clid, 0)) {
		if (!update)
			errx(1, "recv: destination already has PFS \"%s\"",
			    hdr.label);
		if (PfsIndirect || PfsSlot < 0)
			errx(1, "recv: PFS \"%s\" is not in the super-root "
			    "blockset, cannot update", ulabel);
		pfs_slot = PfsSlot;
		/*
		 * Lineage check: the destination PFS (a full copy of the
		 * stream's from-generation) must carry the from-PFS's
		 * pfs_clid.  Snapshots carry a fresh pfs_clid per
		 * snapshot, so the to-PFS's clid does NOT identify the
		 * lineage — and a matching modify_tid alone would be a
		 * 64-bit coincidence, not a lineage proof.
		 */
		uuid_t from_clid = hdr.from_pfs_clid;	/* unaligned in hdr */

		if (!uuid_equal(&dest_clid, &from_clid, NULL)) {
			char *dbuf = NULL, *fbuf = NULL;

			errx(1, "recv: destination PFS \"%s\" belongs to a "
			    "different PFS lineage (dest clid %s, stream "
			    "from clid %s)", ulabel,
			    hammer2_uuid_to_str(&dest_clid, &dbuf),
			    hammer2_uuid_to_str(&from_clid, &fbuf));
		}
		/*
		 * Generation check: the destination PFS must be an
		 * earlier generation of the same stream lineage, matched
		 * by the root inode's modify_tid (the label may differ -
		 * the PFS keeps its label; per-block REF identity
		 * enforces content agreement).
		 */
		if (dest_pfs_bref.modify_tid != hdr.from_modify_tid)
			errx(1, "recv: destination PFS \"%s\" does not "
			    "match the stream's from-generation "
			    "(mtid %ju/%ju)",
			    ulabel,
			    (uintmax_t)dest_pfs_bref.modify_tid,
			    (uintmax_t)hdr.from_modify_tid);
	} else {
		if (update)
			errx(1, "recv: destination has no PFS \"%s\" to "
			    "update", ulabel);
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
	 * A destination that already carries a freemap has been mounted
	 * read-write, so its [allocator_beg, ...) region may hold live
	 * allocations and a stale freemap.  Allocate from the freemap and
	 * commit a COW'd copy of it.  A pristine volume has no freemap and
	 * stays on the linear allocator.
	 */
	if (recv_freemap_present(&voldata))
		Freemap = recv_freemap_init(&voldata, AllocBase, VoluEnd, 0);

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
		    recv_read_phys(root_bref.data_off & ~HAMMER2_OFF_MASK_RADIX,
			      &media, bl) != (ssize_t)bl)
			errx(1, "recv: cannot re-read received PFS root");
		bzero(media.ipdata.filename,
		    sizeof(media.ipdata.filename));
		bcopy(ulabel, media.ipdata.filename, ulen);
		media.ipdata.meta.name_len = ulen;
		media.ipdata.meta.name_key = dirhash(ulabel, ulen);
		root_bref.key = media.ipdata.meta.name_key;
		hammer2_check_calc(&root_bref, &media, bl);
		if (recv_write_phys(root_bref.data_off & ~HAMMER2_OFF_MASK_RADIX,
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
	if (bref_radix_bytes(&sroot_bref) != HAMMER2_INODE_BYTES)
		errx(1, "recv: super-root bref has unexpected size");
	if (recv_read_phys(sroot_bref.data_off, &media,
		      bref_radix_bytes(&sroot_bref)) !=
	    (ssize_t)bref_radix_bytes(&sroot_bref))
		errx(1, "recv: cannot re-read destination super-root");

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
	hammer2_check_calc(&sroot_new, &media, HAMMER2_INODE_BYTES);
	if (recv_write_phys(sroot_off, &media, HAMMER2_INODE_BYTES))
		err(1, "recv: super-root write failed");

	if (Freemap != NULL) {
		/*
		 * The received blocks and the COW'd freemap tree are written
		 * now, before the header commit; allocator_beg is unchanged
		 * and allocator_free / freemap_tid are updated by the flush.
		 */
		if (recv_freemap_flush(Freemap, new_tid) != 0)
			err(1, "recv: freemap commit failed");
	} else {
		/*
		 * Fresh destination: advance allocator_beg past everything
		 * we placed, rounded up to the next 4MB segment so the
		 * freemap leaf created on the next mount marks the whole
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
	}

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

		/*
		 * Durability ordering: the received blocks and the new
		 * super-root must be on stable storage BEFORE the
		 * volume header commit, otherwise a power loss could
		 * persist the header while payload blocks are still
		 * missing (the committed filesystem would reference
		 * garbage).
		 */
		if (fsync(fd))
			err(1, "recv: fsync (pre-commit) failed");

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
	    "bytes), %ju refs, allocator_beg %016jx, mirror_tid %ju\n",
	    hdr.label,
	    update ? " (updated" : "",
	    update ? ")" : "",
	    (uintmax_t)RecvRecords,
	    (uintmax_t)RecvPayloadBytes,
	    (uintmax_t)RecvRefRecords,
	    (intmax_t)voldata.allocator_beg,
	    (uintmax_t)voldata.mirror_tid);
	if (VerboseOpt)
		fprintf(stderr, "recv: root bref at %016jx\n",
		    (intmax_t)root_bref.data_off);
	return (rcode);
}
