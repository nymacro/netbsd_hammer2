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
 * hammer2 send - serialize a PFS (snapshot) as a stream of blockrefs and
 * media payloads, similar to zfs send.  The source is read directly from
 * the volume(s), so the filesystem must be quiescent (unmounted, or a
 * snapshot PFS) while the stream is being produced.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

#include "hammer2.h"
#include "hammer2_stream.h"

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

static size_t
bref_radix_bytes(const hammer2_blockref_t *bref)
{
	int radix = bref->data_off & HAMMER2_OFF_MASK_RADIX;

	if (radix == 0)
		return (0);
	return ((size_t)1 << radix);
}

static int
read_media_bref(const hammer2_blockref_t *bref, void *buf)
{
	size_t bytes = bref_radix_bytes(bref);

	if (bytes == 0 || bytes > HAMMER2_PBUFSIZE)
		return (-1);
	if (read_phys(bref->data_off, buf, bytes) != (ssize_t)bytes)
		return (-1);
	return (0);
}

/*
 * Verify a bref's check code against `bytes' of media data.
 * Returns 0 on success, -1 on mismatch/unsupported.
 */
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
 * The blockref tree of a PFS contains only these types.  Data blocks and
 * dirent name blocks may be compressed (their check code covers the stored
 * bytes); inode and indirect blocks are always stored raw.
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

static int
has_check_method(uint8_t methods)
{
	switch (HAMMER2_DEC_CHECK(methods)) {
	case HAMMER2_CHECK_ISCSI32:
	case HAMMER2_CHECK_XXHASH64:
	case HAMMER2_CHECK_SHA192:
	case HAMMER2_CHECK_FREEMAP:
		return (1);
	default:
		return (0);
	}
}

/*
 * Iterate the child blockrefs of a media block.
 * Returns the number of children and sets *slotsp.
 */
static int
get_slots(const hammer2_blockref_t *bref, const void *data, size_t bytes,
	  const hammer2_blockref_t **slotsp)
{
	const hammer2_inode_data_t *ipdata;
	const hammer2_blockref_t *slots;
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
		slots = &((const hammer2_media_data_t *)data)->npdata[0];
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
 * Seen-block set (dedup: a physical block may be referenced multiple
 * times).  Keyed by data_off including the radix bits.
 */
#define SEEN_HBITS	14
#define SEEN_HSIZE	(1 << SEEN_HBITS)

typedef struct seen_entry {
	struct seen_entry *next;
	hammer2_off_t data_off;
} seen_entry_t;

static seen_entry_t *SeenHash[SEEN_HSIZE];

static inline uint32_t
seen_hash(hammer2_off_t data_off)
{
	return (uint32_t)(data_off * 2654435761U) >> (32 - SEEN_HBITS);
}

static int
seen_find(hammer2_off_t data_off)
{
	seen_entry_t *e;

	for (e = SeenHash[seen_hash(data_off)]; e; e = e->next)
		if (e->data_off == data_off)
			return (1);
	return (0);
}

static void
seen_add(hammer2_off_t data_off)
{
	seen_entry_t *e = malloc(sizeof(*e));

	if (e == NULL)
		err(1, "send: out of memory");
	e->data_off = data_off;
	e->next = SeenHash[seen_hash(data_off)];
	SeenHash[seen_hash(data_off)] = e;
}

/*
 * Independent seen-set for the from-generation index walk (the walk must
 * not consume the emit walk's set: blocks unchanged between generations
 * have identical data_off and would be skipped from the stream).
 */
static seen_entry_t *FSeenHash[SEEN_HSIZE];

static void
fseen_add(hammer2_off_t data_off)
{
	seen_entry_t *e = malloc(sizeof(*e));

	if (e == NULL)
		err(1, "send: out of memory");
	e->data_off = data_off;
	e->next = FSeenHash[seen_hash(data_off)];
	FSeenHash[seen_hash(data_off)] = e;
}

static int
fseen_find(hammer2_off_t data_off)
{
	seen_entry_t *e;

	for (e = FSeenHash[seen_hash(data_off)]; e; e = e->next)
		if (e->data_off == data_off)
			return (1);
	return (0);
}

/*
 * From-generation leaf index for incremental sends.  Keyed by the bref
 * with data_off zeroed (the receiver's copy of the block differs only in
 * data_off).
 */
#define LEAF_HBITS	14
#define LEAF_HSIZE	(1 << LEAF_HBITS)

typedef struct leaf_entry {
	struct leaf_entry *next;
	hammer2_blockref_t bref;	/* stored with data_off zeroed */
} leaf_entry_t;

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
	leaf_entry_t *e;
	hammer2_blockref_t key;

	leaf_key(bref, &key);
	e = malloc(sizeof(*e));
	if (e == NULL)
		err(1, "send: out of memory");
	e->bref = key;
	e->next = LeafHash[leaf_hash(&key)];
	LeafHash[leaf_hash(&key)] = e;
}

static int
leaf_find(const hammer2_blockref_t *bref)
{
	leaf_entry_t *e;
	hammer2_blockref_t key;

	leaf_key(bref, &key);
	for (e = LeafHash[leaf_hash(&key)]; e; e = e->next)
		if (memcmp(&e->bref, &key, sizeof(key)) == 0)
			return (1);
	return (0);
}

static uint64_t EmitRecords;
static uint64_t EmitPayloadBytes;
static uint64_t EmitRefBytes;

static void
write_record(FILE *fp, const hammer2_blockref_t *bref, uint32_t flags,
	     const void *data, uint32_t size)
{
	hammer2_stream_record_t rec;

	bzero(&rec, sizeof(rec));
	rec.magic = HAMMER2_STREAM_RECMAGIC;
	rec.flags = flags;
	rec.size = size;
	rec.check = size ? hammer2_icrc32(data, size) : 0;
	rec.bref = *bref;

	if (fwrite(&rec, sizeof(rec), 1, fp) != 1)
		err(1, "send: stream write");
	++EmitRecords;
	if (flags & HAMMER2_STREAM_RECF_REF) {
		EmitRefBytes += HAMMER2_BLOCKREF_BYTES;
	} else {
		EmitPayloadBytes += size;
		if (size && fwrite(data, size, 1, fp) != 1)
			err(1, "send: stream write");
	}
}

static void
emit_node(FILE *fp, const hammer2_blockref_t *bref, int depth)
{
	hammer2_media_data_t media;
	const hammer2_blockref_t *slots;
	size_t bytes;
	int count, i, leaf;

	if (depth > 16)
		errx(1, "send: topology too deep (corrupt media?)");

	switch (bref->type) {
	case HAMMER2_BREF_TYPE_EMPTY:
	case HAMMER2_BREF_TYPE_INVALID:
		return;
	case HAMMER2_BREF_TYPE_INODE:
	case HAMMER2_BREF_TYPE_INDIRECT:
	case HAMMER2_BREF_TYPE_DATA:
	case HAMMER2_BREF_TYPE_DIRENT:
		break;
	default:
		errx(1, "send: unexpected bref type %d at %016llx",
		    bref->type, (long long)bref->data_off);
	}

	bytes = bref_radix_bytes(bref);
	if (bytes == 0) {
		/*
		 * No media reference (empty slot, embedded dirent name,
		 * or a zero-fill hole).  The parent's embedded copy of
		 * this bref carries everything.
		 */
		return;
	}

	if (seen_find(bref->data_off))
		return;
	seen_add(bref->data_off);

	if (read_media_bref(bref, &media))
		errx(1, "send: read failed at %016llx",
		    (long long)bref->data_off);

	if (test_check(bref, &media, bytes))
		errx(1, "send: check code mismatch at %016llx (%s)",
		    (long long)bref->data_off,
		    hammer2_breftype_to_str(bref->type));

	count = get_slots(bref, &media, bytes, &slots);
	for (i = 0; i < count; ++i)
		emit_node(fp, &slots[i], depth + 1);

	leaf = is_leaf_bref(bref, &media);
	if (leaf && has_check_method(bref->methods) && leaf_find(bref)) {
		/* Unchanged leaf: reference the destination copy. */
		write_record(fp, bref, HAMMER2_STREAM_RECF_REF, NULL, 0);
	} else {
		write_record(fp, bref, 0, &media, bytes);
	}
}

/*
 * Find a PFS root inode bref by label, starting from the super-root.
 * Recurses through the super-root's blockset and any indirect blocks.
 * If labelsp is non-NULL, collects all PFS labels encountered.
 */
static int
find_pfs(const hammer2_blockref_t *bref, const char *label,
	 hammer2_blockref_t *resp, char ***labelsp, int *nlabelsp,
	 int depth)
{
	hammer2_media_data_t media;
	const hammer2_blockref_t *slots;
	size_t bytes;
	int count, i;

	if (depth > 4)
		return (0);
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return (0);
	if (read_media_bref(bref, &media))
		errx(1, "send: read failed at %016llx",
		    (long long)bref->data_off);

	if (bref->type == HAMMER2_BREF_TYPE_INODE &&
	    media.ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) {
		const char *name = (const char *)media.ipdata.filename;
		int len = media.ipdata.meta.name_len;

		if (labelsp) {
			*labelsp = realloc(*labelsp,
				(*nlabelsp + 1) * sizeof(char *));
			if (*labelsp == NULL)
				err(1, "send: out of memory");
			(*labelsp)[*nlabelsp] = strndup(name, len);
			if ((*labelsp)[*nlabelsp] == NULL)
				err(1, "send: out of memory");
			++*nlabelsp;
		}
		if (len == (int)strlen(label) &&
		    memcmp(name, label, len) == 0) {
			*resp = *bref;
			return (1);
		}
	}

	count = get_slots(bref, &media, bytes, &slots);
	for (i = 0; i < count; ++i)
		if (find_pfs(&slots[i], label, resp, labelsp, nlabelsp,
			     depth + 1))
			return (1);
	return (0);
}

static void
pick_sroot(const hammer2_volume_data_t *voldata, hammer2_blockref_t *resp)
{
	const hammer2_blockref_t *bref;
	int i;

	bzero(resp, sizeof(*resp));
	for (i = 0; i < HAMMER2_SET_COUNT; ++i) {
		bref = &voldata->sroot_blockset.blockref[i];
		if (bref->type != HAMMER2_BREF_TYPE_INODE ||
		    bref->data_off == 0)
			continue;
		if (resp->data_off == 0 || resp->mirror_tid < bref->mirror_tid)
			*resp = *bref;
	}
	if (resp->data_off == 0)
		errx(1, "send: no super-root in volume header");
}

/*
 * Walk the from-generation tree building the leaf index.
 */
static uint64_t IndexLeaves;

static void
index_tree(const hammer2_blockref_t *bref, int depth)
{
	hammer2_media_data_t media;
	const hammer2_blockref_t *slots;
	size_t bytes;
	int count, i;

	if (depth > 16)
		return;
	bytes = bref_radix_bytes(bref);
	if (bytes == 0)
		return;
	if (fseen_find(bref->data_off))
		return;
	fseen_add(bref->data_off);
	if (read_media_bref(bref, &media))
		errx(1, "send: read failed at %016llx",
		    (long long)bref->data_off);

	if (is_leaf_bref(bref, &media) && has_check_method(bref->methods)) {
		leaf_add(bref);
		++IndexLeaves;
	}

	count = get_slots(bref, &media, bytes, &slots);
	for (i = 0; i < count; ++i)
		index_tree(&slots[i], depth + 1);
}

int
cmd_send(int ac, char **av)
{
	hammer2_volume_data_t *voldata;
	hammer2_blockref_t sroot_bref;
	hammer2_blockref_t pfs_bref;
	hammer2_blockref_t from_bref;
	hammer2_stream_header_t hdr;
	hammer2_media_data_t media;
	char **labels = NULL;
	int nlabels = 0;
	const char *devpath = NULL;
	const char *label = NULL;
	const char *fromlabel = NULL;
	FILE *fp = stdout;
	int incr = 0;
	int i;

	for (i = 0; i < ac; ++i) {
		if (strcmp(av[i], "-v") == 0) {
			; /* handled globally (VerboseOpt) */
		} else if (strcmp(av[i], "-i") == 0) {
			if (i + 1 >= ac)
				errx(1, "send: -i requires a label");
			fromlabel = av[++i];
			incr = 1;
		} else if (devpath == NULL) {
			devpath = av[i];
		} else if (label == NULL) {
			label = av[i];
		} else {
			errx(1, "send: too many arguments");
		}
	}
	if (devpath == NULL || label == NULL)
		errx(1, "send: requires device path and PFS label");
	if (incr && strcmp(fromlabel, label) == 0)
		errx(1, "send: from and to labels must differ");

	if (isatty(fileno(fp)))
		errx(1, "send: refusing to write binary stream to a "
		    "terminal (redirect stdout)");

	hammer2_init_volumes(devpath, 1);
	voldata = hammer2_read_root_volume_header();
	if (voldata == NULL)
		errx(1, "send: no valid volume header on %s", devpath);

	pick_sroot(voldata, &sroot_bref);
	if (read_media_bref(&sroot_bref, &media))
		errx(1, "send: cannot read super-root");
	if (test_check(&sroot_bref, &media, bref_radix_bytes(&sroot_bref)))
		errx(1, "send: super-root check code mismatch");

	bzero(&pfs_bref, sizeof(pfs_bref));
	if (!find_pfs(&sroot_bref, label, &pfs_bref, &labels, &nlabels, 0)) {
		fprintf(stderr, "send: PFS \"%s\" not found, available:",
		    label);
		for (i = 0; i < nlabels; ++i)
			fprintf(stderr, " %s", labels[i]);
		fprintf(stderr, "\n");
		exit(1);
	}
	if (read_media_bref(&pfs_bref, &media))
		errx(1, "send: cannot read PFS root");
	if ((media.ipdata.meta.op_flags & HAMMER2_OPFLAG_PFSROOT) == 0)
		errx(1, "send: \"%s\" is not a PFS root", label);

	bzero(&hdr, sizeof(hdr));
	bcopy(HAMMER2_STREAM_MAGIC, hdr.magic, sizeof(hdr.magic));
	strlcpy(hdr.label, label, sizeof(hdr.label));
	hdr.pfs_clid = media.ipdata.meta.pfs_clid;
	hdr.pfs_fsid = media.ipdata.meta.pfs_fsid;
	hdr.mirror_tid = voldata->mirror_tid;
	hdr.volu_size = hammer2_get_total_size();

	if (incr) {
		bzero(&from_bref, sizeof(from_bref));
		if (!find_pfs(&sroot_bref, fromlabel, &from_bref, NULL,
			      NULL, 0))
			errx(1, "send: from-PFS \"%s\" not found",
			    fromlabel);
		if (read_media_bref(&from_bref, &media))
			errx(1, "send: cannot read from-PFS root");

		index_tree(&from_bref, 0);

		hdr.flags |= HAMMER2_STREAM_FLAG_INCR;
		strlcpy(hdr.fromlabel, fromlabel, sizeof(hdr.fromlabel));
		hdr.from_modify_tid = from_bref.modify_tid;
		hdr.from_key = from_bref.key;
	}

	hdr.version = HAMMER2_STREAM_VERSION;
	hdr.check = hammer2_icrc32(&hdr, sizeof(hdr) - sizeof(hdr.check));
	if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
		err(1, "send: stream write");

	emit_node(fp, &pfs_bref, 0);

	if (fflush(fp) != 0)
		err(1, "send: stream write");

	fprintf(stderr, "send: PFS \"%s\"", label);
	if (incr)
		fprintf(stderr, " (from \"%s\", %ju indexed leaves)",
		    fromlabel, (uintmax_t)IndexLeaves);
	fprintf(stderr, ": %ju records, %ju payload bytes, %ju ref bytes\n",
	    (uintmax_t)EmitRecords,
	    (uintmax_t)EmitPayloadBytes,
	    (uintmax_t)EmitRefBytes);
	if (VerboseOpt)
		fprintf(stderr, "send: source mirror_tid %ju\n",
		    (uintmax_t)hdr.mirror_tid);
	return (0);
}
