/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2022-2023 Tomohiro Kusumi <tkusumi@netbsd.org>
 * Copyright (c) 2011-2015 The DragonFly Project.  All rights reserved.
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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mount.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <err.h>

#include "mkfs_hammer2.h"

static void parse_fs_size(hammer2_mkfs_options_t *, const char *);
static void check_not_mounted(const char *);
static void usage(void);

int
main(int ac, char **av)
{
	hammer2_mkfs_options_t opt;
	int ch;
	int label_specified = 0;
	int force = 0;
	int ai;

	/*
	 * Initialize option structure.
	 */
	hammer2_mkfs_init(&opt);

	/*
	 * Parse arguments.
	 */
	while ((ch = getopt(ac, av, "FL:b:r:V:s:d")) != -1) {
		int i;

		switch(ch) {
		case 'F':
			force = 1;
			break;
		case 'b':
			opt.BootAreaSize = getsize(optarg,
					 HAMMER2_NEWFS_ALIGN,
					 HAMMER2_BOOT_MAX_BYTES, 2);
			break;
		case 'r':
			opt.AuxAreaSize = getsize(optarg,
					 HAMMER2_NEWFS_ALIGN,
					 HAMMER2_AUX_MAX_BYTES, 2);
			break;
		case 'V':
			opt.Hammer2Version = strtol(optarg, NULL, 0);
			if (opt.Hammer2Version < HAMMER2_VOL_VERSION_MIN ||
			    opt.Hammer2Version >= HAMMER2_VOL_VERSION_WIP) {
				errx(1, "I don't understand how to format "
				     "HAMMER2 version %d",
				     opt.Hammer2Version);
			}
			break;
		case 'L':
			label_specified = 1;
			if (strcasecmp(optarg, "none") == 0) {
				break;
			}
			for (i = 0; i < opt.NLabels; i++) {
				if (strcasecmp(opt.Label[i], optarg) == 0) {
					errx(1, "duplicate label \"%s\"; "
					    "note \"LOCAL\" is auto-created",
					    optarg);
				}
			}
			if (opt.NLabels >= MAXLABELS) {
				errx(1, "Limit of %d local labels",
				     MAXLABELS - 1);
			}
			if (strlen(optarg) == 0) {
				errx(1, "Volume label '%s' cannot be 0-length",
					optarg);
			}
			if (strlen(optarg) >= HAMMER2_INODE_MAXNAME) {
				errx(1, "Volume label '%s' is too long "
					"(%d chars max)",
					optarg,
					HAMMER2_INODE_MAXNAME - 1);
			}
			opt.Label[opt.NLabels++] = strdup(optarg);
			break;
		case 's':
			parse_fs_size(&opt, optarg);
			break;
		case 'd':
			opt.DebugOpt = 1;
			break;
		default:
			usage();
			break;
		}
	}

	ac -= optind;
	av += optind;

	if (ac == 0)
		errx(1, "You must specify at least one disk device");
	if (ac > HAMMER2_MAX_VOLUMES)
		errx(1, "The maximum number of volumes is %d",
		     HAMMER2_MAX_VOLUMES);

	/*
	 * Refuse to format a mounted device: writing a new volume header
	 * over a live mount corrupts the mounted filesystem (and every
	 * other PFS on the same volume).
	 */
	if (!force) {
		for (ai = 0; ai < ac; ++ai)
			check_not_mounted(av[ai]);
	}

	/*
	 * Check default label type.
	 */
	if (!label_specified) {
		char c = av[0][strlen(av[0]) - 1];
		if (c == 'a')
			opt.DefaultLabelType = HAMMER2_LABEL_BOOT;
		else if (c == 'd')
			opt.DefaultLabelType = HAMMER2_LABEL_ROOT;
		else
			opt.DefaultLabelType = HAMMER2_LABEL_DATA;
	}

	/*
	 * Create Hammer2 filesystem.
	 */
	assert(opt.CompType == HAMMER2_COMP_DEFAULT);
	assert(opt.CheckType == HAMMER2_CHECK_DEFAULT);
	hammer2_mkfs(ac, av, &opt);

	/*
	 * Cleanup option structure.
	 */
	hammer2_mkfs_cleanup(&opt);

	return(0);
}

static
void
parse_fs_size(hammer2_mkfs_options_t *opt, const char *arg)
{
	char *o, *p, *s;

	opt->NFileSystemSizes = 0;
	o = p = strdup(arg);

	while ((s = p) != NULL) {
		if ((p = strchr(p, ':')) != NULL)
			*p++ = 0;
		/* XXX 0x7fffffffffffffff isn't limitation of HAMMER2 */
		opt->FileSystemSize[opt->NFileSystemSizes++] = getsize(s,
				 HAMMER2_FREEMAP_LEVEL1_SIZE,
				 0x7fffffffffffffff, 2);
		if (opt->NFileSystemSizes >= HAMMER2_MAX_VOLUMES)
			break;
	}
	free(o);
}

/*
 * Device-name comparison tolerating the raw(4) char-device 'r' prefix
 * ("rld1d" vs "ld1d"): a mount holds the block device while newfs is
 * commonly pointed at the character device.
 */
static int
devname_eq(const char *a, const char *b)
{
	size_t la = strlen(a), lb = strlen(b);

	if (la == lb && strcasecmp(a, b) == 0)
		return (1);
	if (la == lb + 1 && a[0] == 'r' && strcasecmp(a + 1, b) == 0)
		return (1);
	if (lb == la + 1 && b[0] == 'r' && strcasecmp(b + 1, a) == 0)
		return (1);
	return (0);
}

static
void
check_not_mounted(const char *path)
{
	struct stat st;
	struct statvfs *vfs;
	int n, i;

	/*
	 * Only device nodes can be live-mounted; regular files (offline
	 * disk images) are unaffected.
	 */
	if (stat(path, &st) != 0)
		return;		/* let hammer2_mkfs() report the real error */
	if (!S_ISBLK(st.st_mode) && !S_ISCHR(st.st_mode))
		return;

	n = getvfsstat(NULL, 0, ST_WAIT);
	if (n <= 0)
		return;
	vfs = malloc(n * sizeof(*vfs));
	if (vfs == NULL)
		return;
	n = getvfsstat(vfs, n * sizeof(*vfs), ST_WAIT);
	for (i = 0; i < n; ++i) {
		char devpath[sizeof(vfs[i].f_mntfromname) + 6];
		char devname[sizeof(vfs[i].f_mntfromname)];
		char mntname[sizeof(vfs[i].f_mntonname)];
		const char *mntbase, *tgtbase;
		char *at;
		struct stat mst;

		/*
		 * hammer2 mount sources carry the PFS label as a "@label"
		 * suffix ("ld1d@DATA"); strip it before resolving the
		 * device node.
		 */
		snprintf(devname, sizeof(devname), "%s",
		    vfs[i].f_mntfromname);
		at = strchr(devname, '@');
		if (at)
			*at = '\0';
		if (devname[0] == '/')
			snprintf(devpath, sizeof(devpath), "%s", devname);
		else
			snprintf(devpath, sizeof(devpath), "/dev/%s", devname);

		if (stat(devpath, &mst) != 0)
			continue;
		mntbase = strrchr(devpath, '/');
		mntbase = mntbase ? mntbase + 1 : devpath;
		tgtbase = strrchr(path, '/');
		tgtbase = tgtbase ? tgtbase + 1 : path;
		if (devname_eq(mntbase, tgtbase) ||
		    mst.st_rdev == st.st_rdev) {
			/*
			 * Copy the mount point before freeing vfs[]: errx()
			 * must not format the message from freed memory.
			 */
			snprintf(mntname, sizeof(mntname), "%s",
			    vfs[i].f_mntonname);
			free(vfs);
			errx(1, "%s is mounted on %s -- newfs would corrupt "
			    "the live filesystem (use -F to override)",
			    path, mntname);
		}
	}
	free(vfs);
}

static
void
usage(void)
{
	fprintf(stderr,
		"usage: newfs_hammer2 [-F] [-b bootsize] [-r auxsize] "
		"[-V version] [-L label ...] [-s size] special ...\n"
	);
	exit(1);
}
