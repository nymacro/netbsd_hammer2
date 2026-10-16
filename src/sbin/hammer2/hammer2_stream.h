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
 * HAMMER2 PFS send/recv stream format.
 *
 * A stream is a header followed by any number of records.  Each record
 * carries one 128-byte media blockref plus (usually) its physical media
 * payload.  Records are emitted in post-order (children before parents),
 * so the last record in the stream is always the PFS root inode.
 *
 * The bref's data_off is the SOURCE media offset.  The receiver reallocates
 * every payload block on the destination volume (linearly from
 * voldata.allocator_beg, like newfs_hammer2 does for its initial blocks)
 * and rewrites the embedded child blockrefs inside inode/indirect blocks,
 * recomputing their check codes.  Leaf payloads are copied verbatim,
 * compression and check codes intact.
 *
 * REF records (flag RECF_REF) appear only in incremental streams.  They
 * carry no payload; the bref is byte-identical to the corresponding leaf
 * bref in the source from-generation tree.  The receiver locates the
 * matching block in the destination from-generation PFS by bref identity
 * (all fields except data_off) and shares it, exactly the way COW
 * snapshots share blocks.
 *
 * All fields are host byte order, matching the on-media format.
 */

#ifndef HAMMER2_HAMMER2_STREAM_H_
#define HAMMER2_HAMMER2_STREAM_H_

#include <sys/types.h>
#include <sys/uuid.h>

#include <fs/hammer2/hammer2_disk.h>

#define HAMMER2_STREAM_MAGIC	"H2SEND01"
#define HAMMER2_STREAM_VERSION	1

#define HAMMER2_STREAM_LABELSIZE	64	/* header label/fromlabel size */

#define HAMMER2_STREAM_RECMAGIC	0x48325243	/* "H2RC" */

#define HAMMER2_STREAM_FLAG_INCR	0x0001	/* incremental stream */

#define HAMMER2_STREAM_RECF_REF		0x0001	/* reference, no payload */

/*
 * Stream header, 512 bytes, followed by a trailing icrc32.
 */
struct hammer2_stream_header {
	char		magic[8];			/* HAMMER2_STREAM_MAGIC */
	uint32_t	version;
	uint32_t	flags;				/* STREAM_FLAG_* */
	char		label[HAMMER2_STREAM_LABELSIZE];	/* source PFS label (to) */
	char		fromlabel[HAMMER2_STREAM_LABELSIZE];	/* from-generation label (-i) */
	uuid_t		pfs_clid;			/* source PFS cluster id */
	uuid_t		pfs_fsid;			/* source PFS private id */
	hammer2_tid_t	mirror_tid;			/* source volhdr mirror_tid */
	hammer2_tid_t	from_modify_tid;		/* -i: from PFS root bref */
	hammer2_key_t	from_key;			/* -i: from PFS root bref */
	hammer2_off_t	volu_size;			/* source volume-set size */
	char		reserved[300];
	uint32_t	check;				/* icrc32 of preceding bytes */
} __packed;

typedef struct hammer2_stream_header hammer2_stream_header_t;

/*
 * Record header, 148 bytes, followed by `size' payload bytes.  The header
 * is self-protected by `hcheck' (icrc32 over the header up to but excluding
 * hcheck itself); `check' covers the payload.
 */
struct hammer2_stream_record {
	uint32_t magic;			/* HAMMER2_STREAM_RECMAGIC */
	uint32_t flags;			/* STREAM_RECF_* */
	uint32_t size;			/* payload bytes (0 if none) */
	uint32_t check;			/* icrc32 of payload */
	hammer2_blockref_t bref;	/* source blockref, 128 bytes */
	uint32_t hcheck;		/* icrc32 of header (through bref) */
} __packed;

typedef struct hammer2_stream_record hammer2_stream_record_t;

_Static_assert(sizeof(hammer2_stream_header_t) == 512,
    "hammer2_stream_header size != 512");
_Static_assert(sizeof(hammer2_stream_record_t) ==
    20 + HAMMER2_BLOCKREF_BYTES, "hammer2_stream_record size mismatch");

#endif /* !HAMMER2_HAMMER2_STREAM_H_ */
