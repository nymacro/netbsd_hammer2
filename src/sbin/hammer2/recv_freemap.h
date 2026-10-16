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
 * recv used to place every received block linearly from voldata.allocator_beg
 * and never touch the freemap.  That is only safe when the destination's
 * dynamic region has never been used (a freshly formatted volume): the freemap
 * leaf created on the first later allocation marks the received blocks
 * allocated because allocator_beg has advanced past them.
 *
 * On a volume that has already been mounted read-write the persisted freemap
 * still marks [allocator_beg, ...) free, so writing there would both clobber
 * live kernel-allocated blocks and leave a stale freemap that would hand the
 * received blocks back out.
 *
 * This module implements the second case: it allocates each received block
 * from the destination's on-media freemap (allocating from free 16KB units and
 * recording them), and commits a COW'd copy of the freemap tree so the
 * allocation is durable and consistent before the volume header commit.
 *
 * A volume with no freemap at all (voldata.freemap_blockset all empty) keeps
 * using the linear allocator in cmd_recv.c: that region is pristine, so the
 * linear model is correct, and mixing the two models on one volume is never
 * necessary (the freemap only appears once the volume has been mounted).
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
 * Return non-zero if the volume has an on-media freemap (i.e. it has been
 * used at least once and the linear allocator is no longer safe).
 */
int recv_freemap_present(const hammer2_volume_data_t *voldata);

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
