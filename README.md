# HAMMER2 file system for NetBSD

Experimental support for DragonFlyBSD's HAMMER2 on NetBSD that might destroy your files.

This started as an experiment playing with an LLM to bring an advanced filesystem lighter than ZFS to NetBSD to be used as a root filesystem. It has been built and tested with NetBSD 11.0 RELEASE.

It hasn't destroyed any files yet on my disk. But it might destroy yours.

## Features

- Write support.
- Root mount support.
- Snapshots.
- Block compression (lz4/zlib) and dedup.
- Integrated with NetBSD virtual memory (uvm), buffer cache (ubc), and kernel authorization (kauth) systems.

### Experimental

- Send and receive of snapshots.

## Unsupported

- Clustering.

## Credits

- [kusumi/netbsd_hammer2](https://github.com/kusumi/netbsd_hammer2) - for the initial work which this is built on
- Every open-source author who has had their source code used in training data for AI companies

