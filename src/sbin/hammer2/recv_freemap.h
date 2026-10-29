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
 * Destination-side freemap support for `hammer2 recv'.
 *
 * recv allocates every received block from the destination's on-media
 * freemap and never advances voldata.allocator_beg.  On a volume that has
 * been mounted read-write the persisted freemap marks the dynamic region,
 * so allocating from it (and committing a COW'd copy with the volume
 * header) is the only safe course: writing anywhere else would clobber
 * live kernel-allocated blocks and leave a stale freemap.
 *
 * On a freshly formatted volume (freemap_blockset entirely empty) the same
 * path builds the freemap tree from scratch: LEVEL1 leaves are created
 * lazily per 1GB region as allocations touch them, mirroring the kernel's
 * hammer2_freemap_init() (below-allocator_beg and reserve areas marked
 * allocated).  Because allocator_beg stays frozen, every received block is
 * at or above it and remains visible to the kernel's delete-time freemap
 * adjust and to bulkfree -- deleting a received PFS and running
 * `hammer2 cleanup' reclaims its space.  (The old linear-placement scheme,
 * which advanced allocator_beg, permanently leaked received and -u-diverged
 * blocks; volumes written that way keep their leaks -- no migration.)
 */

#ifndef HAMMER2_RECV_FREEMAP_H_
#define HAMMER2_RECV_FREEMAP_H_

#include <sys/types.h>

#include <fs/hammer2/hammer2_disk.h>

/*
 * Low-level volume I/O shared with cmd_recv.c.  `data_off' keeps its radix
 * bits (they are masked off here).
 */
ssize_t recv_read_phys(hammer2_off_t data_off, void *buf, size_t bytes);
int recv_write_phys(hammer2_off_t data_off, const void *buf, size_t bytes);

struct recv_freemap;

/*
 * Create an allocation context over (*voldata).  The caller keeps ownership of
 * *voldata; the module updates freemap_blockset/freemap_tid/allocator_free in
 * place (committed with the header by the caller).  `alloc_beg' is the volume's
 * allocator_beg (lower bound below which nothing may be allocated), `volu_end'
 * the volume size.
 */
struct recv_freemap *recv_freemap_init(hammer2_volume_data_t *voldata,
    hammer2_off_t alloc_beg, hammer2_off_t volu_end, hammer2_tid_t tid);

/*
 * Allocate one block of 2^radix bytes from free freemap space.  Returns 0 and
 * sets *offp (with the radix bits) on success, -1 on ENOSPC/error.
 */
int recv_freemap_alloc(struct recv_freemap *fm, int radix, hammer2_off_t *offp);

/*
 * COW-write every modified freemap block reachable from the new root and
 * update (*voldata).freemap_blockset/freemap_tid/allocator_free.  `tid' is the
 * commit generation.  Must be called before the volume header commit.
 */
int recv_freemap_flush(struct recv_freemap *fm, hammer2_tid_t tid);

void recv_freemap_destroy(struct recv_freemap *fm);

#endif /* !HAMMER2_RECV_FREEMAP_H_ */
