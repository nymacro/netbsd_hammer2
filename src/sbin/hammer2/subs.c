/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2012 The DragonFly Project.  All rights reserved.
 *
 * This code is derived from software contributed to The DragonFly Project
 * by Matthew Dillon <dillon@dragonflybsd.org>
 * by Venkatesh Srinivas <vsrinivas@dragonflybsd.org>
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/disk.h>
#include <sys/disklabel.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <err.h>
#include <uuid.h>

#include <sys/sha2.h>

#include <fs/hammer2/hammer2_disk.h>
#include <fs/hammer2/hammer2_ioctl.h>
#include <fs/hammer2/hammer2_xxhash.h>

#include "hammer2_subs.h"

/*
 * Obtain a file descriptor that the caller can execute ioctl()'s on.
 */
int
hammer2_ioctl_handle(const char *sel_path)
{
	struct hammer2_ioc_version info;
	int fd;

	if (sel_path == NULL)
		sel_path = ".";

	fd = open(sel_path, O_RDONLY, 0);
	if (fd < 0) {
		fprintf(stderr, "hammer2: Unable to open %s: %s\n",
			sel_path, strerror(errno));
		return(-1);
	}
	if (ioctl(fd, HAMMER2IOC_VERSION_GET, &info) < 0) {
		fprintf(stderr, "hammer2: '%s' is not a hammer2 filesystem\n",
			sel_path);
		close(fd);
		return(-1);
	}
	return (fd);
}

const char *
hammer2_time64_to_str(uint64_t htime64, char **strp)
{
	struct tm *tp;
	time_t t;

	if (*strp) {
		free(*strp);
		*strp = NULL;
	}
	*strp = malloc(64);
	t = htime64 / 1000000;
	tp = localtime(&t);
	strftime(*strp, 64, "%d-%b-%Y %H:%M:%S", tp);
	return (*strp);
}

const char *
hammer2_uuid_to_str(const uuid_t *uuid, char **strp)
{
	uint32_t status;
	if (*strp) {
		free(*strp);
		*strp = NULL;
	}
	uuid_to_string(uuid, strp, &status);
	return (*strp);
}

const char *
hammer2_iptype_to_str(uint8_t type)
{
	switch(type) {
	case HAMMER2_OBJTYPE_UNKNOWN:
		return("UNKNOWN");
	case HAMMER2_OBJTYPE_DIRECTORY:
		return("DIR");
	case HAMMER2_OBJTYPE_REGFILE:
		return("FILE");
	case HAMMER2_OBJTYPE_FIFO:
		return("FIFO");
	case HAMMER2_OBJTYPE_CDEV:
		return("CDEV");
	case HAMMER2_OBJTYPE_BDEV:
		return("BDEV");
	case HAMMER2_OBJTYPE_SOFTLINK:
		return("SOFTLINK");
	case HAMMER2_OBJTYPE_SOCKET:
		return("SOCKET");
	case HAMMER2_OBJTYPE_WHITEOUT:
		return("WHITEOUT");
	default:
		return("ILLEGAL");
	}
}

const char *
hammer2_pfstype_to_str(uint8_t type)
{
	switch(type) {
	case HAMMER2_PFSTYPE_NONE:
		return("NONE");
	case HAMMER2_PFSTYPE_SUPROOT:
		return("SUPROOT");
	case HAMMER2_PFSTYPE_DUMMY:
		return("DUMMY");
	case HAMMER2_PFSTYPE_CACHE:
		return("CACHE");
	case HAMMER2_PFSTYPE_SLAVE:
		return("SLAVE");
	case HAMMER2_PFSTYPE_SOFT_SLAVE:
		return("SOFT_SLAVE");
	case HAMMER2_PFSTYPE_SOFT_MASTER:
		return("SOFT_MASTER");
	case HAMMER2_PFSTYPE_MASTER:
		return("MASTER");
	default:
		return("ILLEGAL");
	}
}

const char *
hammer2_pfssubtype_to_str(uint8_t subtype)
{
	switch(subtype) {
	case HAMMER2_PFSSUBTYPE_NONE:
		return("NONE");
	case HAMMER2_PFSSUBTYPE_SNAPSHOT:
		return("SNAPSHOT");
	case HAMMER2_PFSSUBTYPE_AUTOSNAP:
		return("AUTOSNAP");
	default:
		return("ILLEGAL");
	}
}

const char *
hammer2_breftype_to_str(uint8_t type)
{
	switch(type) {
	case HAMMER2_BREF_TYPE_EMPTY:
		return("empty");
	case HAMMER2_BREF_TYPE_INODE:
		return("inode");
	case HAMMER2_BREF_TYPE_INDIRECT:
		return("indirect");
	case HAMMER2_BREF_TYPE_DATA:
		return("data");
	case HAMMER2_BREF_TYPE_DIRENT:
		return("dirent");
	case HAMMER2_BREF_TYPE_FREEMAP_NODE:
		return("freemap_node");
	case HAMMER2_BREF_TYPE_FREEMAP_LEAF:
		return("freemap_leaf");
	case HAMMER2_BREF_TYPE_INVALID:
		return("invalid");
	case HAMMER2_BREF_TYPE_FREEMAP:
		return("freemap");
	case HAMMER2_BREF_TYPE_VOLUME:
		return("volume");
	default:
		return("unknown");
	}
}

const char *
hammer2_compmode_to_str(uint8_t comp_algo)
{
	static char buf[64];
	static const char *comps[] = HAMMER2_COMP_STRINGS;
	int comp = HAMMER2_DEC_ALGO(comp_algo);
	int level = HAMMER2_DEC_LEVEL(comp_algo);

	if (level) {
		if (comp >= 0 && comp < HAMMER2_COMP_STRINGS_COUNT)
			snprintf(buf, sizeof(buf), "%s:%d",
				 comps[comp], level);
		else
			snprintf(buf, sizeof(buf), "unknown(%d):%d",
				 comp, level);
	} else {
		if (comp >= 0 && comp < HAMMER2_COMP_STRINGS_COUNT)
			snprintf(buf, sizeof(buf), "%s:default",
				 comps[comp]);
		else
			snprintf(buf, sizeof(buf), "unknown(%d):default",
				 comp);
	}
	return (buf);
}

const char *
hammer2_checkmode_to_str(uint8_t check_algo)
{
	static char buf[64];
	static const char *checks[] = HAMMER2_CHECK_STRINGS;
	int check = HAMMER2_DEC_ALGO(check_algo);
	int level = HAMMER2_DEC_LEVEL(check_algo);

	/*
	 * NOTE: Check algorithms normally do not encode any level.
	 */
	if (level) {
		if (check >= 0 && check < HAMMER2_CHECK_STRINGS_COUNT)
			snprintf(buf, sizeof(buf), "%s:%d",
				 checks[check], level);
		else
			snprintf(buf, sizeof(buf), "unknown(%d):%d",
				 check, level);
	} else {
		if (check >= 0 && check < HAMMER2_CHECK_STRINGS_COUNT)
			snprintf(buf, sizeof(buf), "%s", checks[check]);
		else
			snprintf(buf, sizeof(buf), "unknown(%d)", check);
	}
	return (buf);
}

const char *
sizetostr(hammer2_off_t size)
{
	static char buf[32];

	if (size < 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2fB", (double)size);
	} else if (size < 1024 * 1024 / 2) {
		snprintf(buf, sizeof(buf), "%6.2fKB",
			(double)size / 1024);
	} else if (size < 1024 * 1024 * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fMB",
			(double)size / (1024 * 1024));
	} else if (size < 1024 * 1024 * 1024LL * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fGB",
			(double)size / (1024 * 1024 * 1024LL));
	} else {
		snprintf(buf, sizeof(buf), "%6.2fTB",
			(double)size / (1024 * 1024 * 1024LL * 1024LL));
	}
	return(buf);
}

const char *
counttostr(hammer2_off_t size)
{
	static char buf[32];

	if (size < 1024 / 2) {
		snprintf(buf, sizeof(buf), "%jd",
			 (intmax_t)size);
	} else if (size < 1024 * 1024 / 2) {
		snprintf(buf, sizeof(buf), "%jd",
			 (intmax_t)size);
	} else if (size < 1024 * 1024 * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fM",
			 (double)size / (1024 * 1024));
	} else if (size < 1024 * 1024 * 1024LL * 1024LL / 2) {
		snprintf(buf, sizeof(buf), "%6.2fG",
			 (double)(size / (1024 * 1024 * 1024LL)));
	} else {
		snprintf(buf, sizeof(buf), "%6.2fT",
			 (double)(size / (1024 * 1024 * 1024LL * 1024LL)));
	}
	return(buf);
}

hammer2_off_t
check_volume(int fd)
{
	struct stat st;
	struct dkwedge_info dkw;
	struct disklabel dl;
	hammer2_off_t size;
	int part;

	/*
	 * Get basic information about the volume.
	 *
	 * NetBSD: DIOCGMEDIASIZE returns the whole-disk size even for a
	 * disklabel partition device, so query the wedge (partition)
	 * size first, then the disklabel partition, and only then the
	 * whole-disk media size.
	 */
	if (ioctl(fd, DIOCGWEDGEINFO, &dkw) == 0) {
		size = (hammer2_off_t)dkw.dkw_size * 512;
	} else if (fstat(fd, &st) == 0 && (S_ISBLK(st.st_mode) ||
	    S_ISCHR(st.st_mode)) && ioctl(fd, DIOCGDINFO, &dl) == 0) {
		part = minor(st.st_rdev) % MAXPARTITIONS;
		size = (hammer2_off_t)dl.d_partitions[part].p_size *
		    dl.d_secsize;
	} else if (ioctl(fd, DIOCGMEDIASIZE, &size) < 0) {
		/*
		 * Allow the formatting of regular files as HAMMER2 volumes
		 */
		if (fstat(fd, &st) < 0)
			err(1, "Unable to stat fd %d", fd);
		if (!S_ISREG(st.st_mode))
			errx(1, "Unsupported file type for fd %d", fd);
		size = st.st_size;
	} else {
		/*
		 * When formatting a block device as a HAMMER2 volume the
		 * sector size must be compatible.  HAMMER2 uses 64K
		 * filesystem buffers but logical buffers for direct I/O
		 * can be as small as HAMMER2_LOGSIZE (16KB).
		 */
		int media_blksize;
		if (!ioctl(fd, DIOCGSECTORSIZE, &media_blksize) &&
		    (media_blksize > HAMMER2_PBUFSIZE ||
		    HAMMER2_PBUFSIZE % media_blksize)) {
			errx(1, "A media sector size of %d is not supported",
			     media_blksize);
		}
	}
	return(size);
}

/*
 * Borrow HAMMER1's directory hash algorithm #1 with a few modifications.
 * The filename is split into fields which are hashed separately and then
 * added together.
 *
 * Differences include: bit 63 must be set to 1 for HAMMER2 (HAMMER1 sets
 * it to 0), this is because bit63=0 is used for hidden hardlinked inodes.
 * (This means we do not need to do a 0-check/or-with-0x100000000 either).
 *
 * Also, the iscsi crc code is used instead of the old crc32 code.
 */
hammer2_key_t
dirhash(const char *aname, size_t len)
{
	uint32_t crcx;
	uint64_t key;
	size_t i;
	size_t j;

	key = 0;

	/*
	 * m32
	 */
	crcx = 0;
	for (i = j = 0; i < len; ++i) {
		if (aname[i] == '.' ||
		    aname[i] == '-' ||
		    aname[i] == '_' ||
		    aname[i] == '~') {
			if (i != j)
				crcx += hammer2_icrc32(aname + j, i - j);
			j = i + 1;
		}
	}
	if (i != j)
		crcx += hammer2_icrc32(aname + j, i - j);

	/*
	 * The directory hash utilizes the top 32 bits of the 64-bit key.
	 * Bit 63 must be set to 1.
	 */
	crcx |= 0x80000000U;
	key |= (uint64_t)crcx << 32;

	/*
	 * l16 - crc of entire filename
	 *
	 * This crc reduces degenerate hash collision conditions.
	 */
	crcx = hammer2_icrc32(aname, len);
	crcx = crcx ^ (crcx << 16);
	key |= crcx & 0xFFFF0000U;

	/*
	 * Set bit 15.  This allows readdir to strip bit 63 so a positive
	 * 64-bit cookie/offset can always be returned, and still guarantee
	 * that the values 0x0000-0x7FFF are available for artificial entries.
	 * ('.' and '..').
	 */
	key |= 0x8000U;

	return (key);
}

char **
get_hammer2_mounts(int *acp)
{
	struct statvfs *fs;
	char **av;
	int n;
	int w;
	int i;

	/*
	 * Get a stable list of mount points
	 */
	n = getmntinfo(&fs, MNT_NOWAIT);
	av = calloc(n, sizeof(char *));

	/*
	 * Pull out hammer2 filesystems only
	 */
	for (i = w = 0; i < n; ++i) {
		if (strcmp(fs[i].f_fstypename, "hammer2") != 0)
			continue;
		av[w++] = strdup(fs[i].f_mntonname);
	}
	*acp = w;

	return av;
}

void
put_hammer2_mounts(int ac, char **av)
{
	while (--ac >= 0)
		free(av[ac]);
	free(av);
}

/*
 * Return 1 if `devpath' backs any mounted hammer2 filesystem, 0 if not,
 * -1 if devpath cannot be stat'ed.  Used by tools that require
 * exclusive offline access to a volume (recv writes raw blocks under a
 * mounted filesystem's cache would corrupt it).
 *
 * Mount-table device names and the caller's path may use different
 * node classes (block vs character) or /dev prefixes, so compare the
 * path basename first, then fall back to stat(2) rdev identity.
 */
static const char *
last_path_component(const char *path)
{
	const char *p = strrchr(path, '/');

	return (p ? p + 1 : path);
}

int
hammer2_volume_is_mounted(const char *devpath)
{
	struct statvfs *fs;
	struct stat st, mst;
	const char *dname;
	int n, i, rv;

	if (stat(devpath, &st) < 0)
		return (-1);

	rv = 0;
	dname = last_path_component(devpath);
	n = getmntinfo(&fs, MNT_NOWAIT);
	for (i = 0; i < n; ++i) {
		if (strcmp(fs[i].f_fstypename, "hammer2") != 0)
			continue;
		if (strcmp(dname,
			   last_path_component(fs[i].f_mntfromname)) == 0) {
			rv = 1;
			continue;
		}
		if (stat(fs[i].f_mntfromname, &mst) == 0 &&
		    major(st.st_rdev) == major(mst.st_rdev) &&
		    minor(st.st_rdev) == minor(mst.st_rdev))
			rv = 1;
	}
	return (rv);
}

/*
 * Compute the check code for (data, bytes) per bref->methods and store
 * it into bref->check.  The single shared implementation of the check
 * algorithms (including the SHA192 word-fold) for the userland tools;
 * the kernel's copy lives in hammer2_bref_testcheck() (chain.c) and
 * must stay in sync with this one.
 */
void
hammer2_check_calc(hammer2_blockref_t *bref, const void *data, size_t bytes)
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
		/*
		 * Fold word 3 into word 2, then store the first 24
		 * bytes (192 bits).
		 */
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

/*
 * Verify media data against the check code in *bref.  Returns 0 on
 * match (also for CHECK_NONE/DISABLED), -1 on mismatch or an unknown
 * check method (stricter than the kernel, which trusts unknown
 * methods).
 */
int
hammer2_check_verify(const hammer2_blockref_t *bref, const void *data,
    size_t bytes)
{
	hammer2_blockref_t cbref = *bref;

	switch (HAMMER2_DEC_CHECK(bref->methods)) {
	case HAMMER2_CHECK_NONE:
	case HAMMER2_CHECK_DISABLED:
		return (0);
	case HAMMER2_CHECK_ISCSI32:
	case HAMMER2_CHECK_XXHASH64:
	case HAMMER2_CHECK_SHA192:
	case HAMMER2_CHECK_FREEMAP:
		hammer2_check_calc(&cbref, data, bytes);
		return (memcmp(&cbref.check, &bref->check,
		    sizeof(bref->check)) ? -1 : 0);
	default:
		return (-1);
	}
}

/*
 * Leaf-blockref index shared by `hammer2 send -i' (from-generation leaf
 * index) and `hammer2 recv -u' (destination from-generation leaf
 * index).  Keyed by bref identity: the bref with data_off zeroed (the
 * receiver's copy of a block differs from the source's only in
 * data_off).  The entry records the media location the block was
 * indexed at, which recv's REF sharing needs and send ignores.
 *
 * Indexed leaves always carry a non-zero data_off, so a 0 return from
 * hammer2_leaf_find() means "not indexed".
 */
#define HAMMER2_LEAF_HBITS	16
#define HAMMER2_LEAF_HSIZE	(1 << HAMMER2_LEAF_HBITS)

typedef struct hammer2_leaf_entry {
	struct hammer2_leaf_entry *next;
	hammer2_blockref_t key;		/* bref with data_off zeroed */
	hammer2_off_t data_off;		/* media location */
} hammer2_leaf_entry_t;

static hammer2_leaf_entry_t *LeafHash[HAMMER2_LEAF_HSIZE];

static inline uint32_t
hammer2_leaf_hash(const hammer2_blockref_t *key)
{
	const uint8_t *p = (const uint8_t *)(const void *)key;
	uint32_t h = 2166136261U;
	int i;

	for (i = 0; i < HAMMER2_BLOCKREF_BYTES; ++i)
		h = (h ^ p[i]) * 16777619U;
	return (h >> (32 - HAMMER2_LEAF_HBITS));
}

void
hammer2_leaf_add(const hammer2_blockref_t *bref)
{
	hammer2_leaf_entry_t *e = malloc(sizeof(*e));

	if (e == NULL)
		err(1, "out of memory");
	e->key = *bref;
	e->key.data_off = 0;
	e->data_off = bref->data_off;
	e->next = LeafHash[hammer2_leaf_hash(&e->key)];
	LeafHash[hammer2_leaf_hash(&e->key)] = e;
}

hammer2_off_t
hammer2_leaf_find(const hammer2_blockref_t *bref)
{
	hammer2_leaf_entry_t *e;
	hammer2_blockref_t key;

	key = *bref;
	key.data_off = 0;
	for (e = LeafHash[hammer2_leaf_hash(&key)]; e; e = e->next)
		if (memcmp(&e->key, &key, sizeof(key)) == 0)
			return (e->data_off);
	return (0);
}
