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
 * hammer2 send - serialize a PFS (typically a snapshot) as a stream of
 * blockrefs and media payloads, similar to zfs send.
 *
 * The topology walk runs IN THE KERNEL (HAMMER2IOC_SEND_* ioctls,
 * hammer2_send.c): the source PFS is pinned for the duration of the
 * session (concurrent `hammer2 pfs-delete` fails with EBUSY), every
 * emitted block is check-verified by the kernel, and the walked
 * topology is a point-in-time COW view.  The device therefore does not
 * need to be unmounted - the first argument is any path on the mounted
 * hammer2 filesystem (mount point, or any file within it).
 *
 * This file only implements the stream framing (512B header + records,
 * see hammer2_stream.h) and the incremental -i dedup logic: a first
 * SKIP_PAYLOAD pump pass over the from-generation PFS builds the leaf
 * index, then unchanged leaves in the to-generation walk are emitted as
 * REF records instead of payloads.
 */

#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hammer2.h"
#include "hammer2_stream.h"

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
static uint64_t IndexLeaves;
static uint64_t EmitRecords;
static uint64_t EmitPayloadBytes;
static uint64_t EmitRefBytes;

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
	rec.hcheck = hammer2_icrc32(&rec,
	    offsetof(hammer2_stream_record_t, hcheck));

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

/*
 * Pump a full send session for `label' (brefs + payloads into (*fp) when
 * fp is non-NULL, brefs only otherwise) and apply the caller callback to
 * each record.
 */
typedef void (*send_rec_fn)(FILE *, const hammer2_ioc_send_t *,
			    const void *, void *);

static void
emit_record(FILE *fp, const hammer2_ioc_send_t *ioc, const void *data,
	    void *arg __unused)
{
	if ((ioc->rec_flags & HAMMER2_SENDREC_LEAF) &&
	    has_check_method(ioc->bref.methods) && leaf_find(&ioc->bref)) {
		/* Unchanged leaf: reference the destination copy. */
		write_record(fp, &ioc->bref, HAMMER2_STREAM_RECF_REF, NULL, 0);
	} else {
		write_record(fp, &ioc->bref, 0, data, ioc->rec_size);
	}
}

static void
index_record(FILE *fp __unused, const hammer2_ioc_send_t *ioc,
	     const void *data __unused, void *arg __unused)
{
	if ((ioc->rec_flags & HAMMER2_SENDREC_LEAF) &&
	    has_check_method(ioc->bref.methods)) {
		leaf_add(&ioc->bref);
		++IndexLeaves;
	}
}

static void
send_session(int fd, const char *label, const char *fromlabel,
	     uint32_t flags, int incr, const hammer2_ioc_send_t *fromp,
	     FILE *fp, send_rec_fn fn, void *arg,
	     hammer2_ioc_send_t *startp)
{
	hammer2_stream_header_t hdr;
	hammer2_ioc_send_t ioc;
	void *buf;
	int error;

	buf = malloc(HAMMER2_PBUFSIZE);
	if (buf == NULL)
		err(1, "send: out of memory");

	bzero(&ioc, sizeof(ioc));
	strlcpy(ioc.label, label, sizeof(ioc.label));
	ioc.flags = flags;
	ioc.payload = buf;
	if (ioctl(fd, HAMMER2IOC_SEND_START, &ioc) < 0) {
		error = errno;
		free(buf);
		if (error == ENOENT)
			errx(1, "send: PFS \"%s\" not found", label);
		if (error == EINVAL)
			errx(1, "send: \"%s\" is not a PFS root", label);
		if (error == EBUSY)
			errx(1, "send: PFS \"%s\" is already being sent",
			    label);
		errc(1, error, "send: SEND_START");
	}

	if (startp)
		*startp = ioc;

	if (fp) {
		/*
		 * SEND_START returns the header facts up front, so the
		 * header is written first in the stream, before any
		 * record.  recv requires the header first.
		 */
		bzero(&hdr, sizeof(hdr));
		bcopy(HAMMER2_STREAM_MAGIC, hdr.magic, sizeof(hdr.magic));
		strlcpy(hdr.label, label, sizeof(hdr.label));
		hdr.version = HAMMER2_STREAM_VERSION;
		hdr.pfs_clid = ioc.pfs_clid;
		hdr.pfs_fsid = ioc.pfs_fsid;
		hdr.mirror_tid = ioc.mirror_tid;
		hdr.volu_size = ioc.volu_size;
		if (incr) {
			hdr.flags |= HAMMER2_STREAM_FLAG_INCR;
			strlcpy(hdr.fromlabel, fromlabel, sizeof(hdr.fromlabel));
			hdr.from_modify_tid = fromp->root_bref.modify_tid;
			hdr.from_key = fromp->root_bref.key;
		}
		hdr.check = hammer2_icrc32(&hdr,
					   sizeof(hdr) - sizeof(hdr.check));
		if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1)
			err(1, "send: stream write");
	}

	for (;;) {
		if (ioctl(fd, HAMMER2IOC_SEND_NEXT, &ioc) < 0) {
			error = errno;
			free(buf);
			ioctl(fd, HAMMER2IOC_SEND_FINISH, &ioc);
			errc(1, error, "send: SEND_NEXT");
		}
		if (ioc.rec_flags & HAMMER2_SENDREC_EOF)
			break;
		fn(fp, &ioc, buf, arg);
	}

	if (ioctl(fd, HAMMER2IOC_SEND_FINISH, &ioc) < 0)
		warn("send: SEND_FINISH");
	free(buf);
}

int
cmd_send(int ac, char **av)
{
	hammer2_ioc_send_t start, from_root;
	const char *path = NULL;
	const char *label = NULL;
	const char *fromlabel = NULL;
	FILE *fp = stdout;
	int fd, incr = 0, i;

	bzero(&start, sizeof(start));
	bzero(&from_root, sizeof(from_root));

	for (i = 0; i < ac; ++i) {
		if (strcmp(av[i], "-v") == 0) {
			/* -v is a global option, handled in main() */
		} else if (strcmp(av[i], "-i") == 0) {
			if (i + 1 >= ac)
				errx(1, "send: -i requires a label");
			fromlabel = av[++i];
			incr = 1;
		} else if (path == NULL) {
			path = av[i];
		} else if (label == NULL) {
			label = av[i];
		} else {
			errx(1, "send: too many arguments");
		}
	}
	if (path == NULL || label == NULL)
		errx(1, "send: requires a mounted hammer2 path and PFS label");
	if (incr && strcmp(fromlabel, label) == 0)
		errx(1, "send: from and to labels must differ");
	if (strlen(label) >= HAMMER2_STREAM_LABELSIZE)
		errx(1, "send: PFS label too long (max %d)",
		    HAMMER2_STREAM_LABELSIZE - 1);
	if (incr && strlen(fromlabel) >= HAMMER2_STREAM_LABELSIZE)
		errx(1, "send: from label too long (max %d)",
		    HAMMER2_STREAM_LABELSIZE - 1);

	if (isatty(fileno(fp)))
		errx(1, "send: refusing to write binary stream to a "
		    "terminal (redirect stdout)");

	fd = hammer2_ioctl_handle(path);
	if (fd < 0)
		return (1);

	/*
	 * Incremental: index the from-generation PFS first (brefs only),
	 * then emit the to-generation walk with REF records for unchanged
	 * leaves.  The two sessions use distinct kernel walk states, so
	 * the emit dedup does not consume the index walk (unchanged blocks
	 * have identical data_off and would be silently dropped).
	 */
	if (incr) {
		/*
		 * Index the from-generation PFS first (brefs only); its
		 * root bref feeds the incremental stream header.
		 */
		send_session(fd, fromlabel, NULL, HAMMER2_SENDF_SKIP_PAYLOAD,
		    0, NULL, NULL, index_record, NULL, &from_root);
	}

	/*
	 * The to-session writes the stream header (from the SEND_START
	 * facts) followed by the records; stdout is a stream (often a
	 * pipe), and recv requires the header first.
	 */
	send_session(fd, label, fromlabel, 0, incr, &from_root, fp,
	    emit_record, NULL, &start);

	close(fd);

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
		    (uintmax_t)start.mirror_tid);
	return (0);
}
