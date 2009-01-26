/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * general range tracking support
 *
 * This API is for keeping track of byte ranges.  Each byte in the range
 * is considered to be "set" or "cleared".  Only continous sub-ranges,
 * specified by offset and length, may be manipulated or queried; however,
 * the range itself may hold arbitrarily disjoint sub-ranges of set or
 * cleared bytes.
 */

#ifndef _NFS_RANGE_H
#define	_NFS_RANGE_H

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Creating / destroying ranges
 * ----------------------------
 *
 * nfs_range_create() - create a range container
 * nfs_range_destroy() - destroy a range container
 *
 * nfs_range_create() allocates and returns a range container.  Initially,
 * the entire range is clear.  To deallocate the range container, use
 * nfs_range_destroy().
 *
 * Example:
 * --------
 *
 * nfs_range_t *range;
 *
 * range = nfs_range_create();
 * . . .
 * nfs_range_destroy(range);
 *
 * Manipulating ranges
 * -------------------
 *
 * nfs_range_set() - set a sub-range of bytes
 * nfs_range_clear() - clear a sub-range of bytes
 *
 * nfs_range_set(range, offset, length, flags) sets the subrange,
 * specified by offset and length.  Returns the status of the entire
 * range as NFS_RANGE_ALL, NFS_RANGE_SOME, or NFS_RANGE_NONE, depending
 * on whether the entire range is now entirely set, partially set, or
 * entirely clear.
 *
 * nfs_range_clear(range, offset, length, flags) clears the subrange,
 * specified by offset and length.  Returns the status of the entire
 * range, the same as nfs_range_set().
 *
 * The "flags" field is reserved for future use.
 *
 * Example:
 * --------
 *
 * Set a sub-range consisting of the first 64k of the range
 *
 * nfs_range_set(range, 0, 65536);
 *
 * Since only the first 64k is set, NFS_RANGE_SOME is returned.
 *
 * Clear the 2nd 4k chunk of the range, splitting the sub-range that was
 * set above
 *
 * nfs_range_clear(range, 4096, 4096);
 *
 * At this point, [0, 4095] is set, and [8192, 65535] is set.
 * nfs_range_clear() returned NFS_RANGE_SOME, again because there were
 * some offsets in the entire range set, but not all.
 *
 * Querying ranges
 * ---------------
 *
 * nfs_range_is_set() - checks for a sub-range being set
 * nfs_range_is_clear() - checks for a sub-range being clear
 *
 * Return values:
 * NFS_RANGE_NONE - indicates that none of the sub-range meets the criteria
 * NFS_RANGE_SOME - indicates that some of the sub-range meets the criteria
 * NFS_RANGE_ALL - indicates that all of the sub-range meets the criteria
 *
 * nfs_range_is_set(range, offsetp, lengthp, flags) determines if a sub-range
 * is set.  It returns NFS_RANGE_NONE, NFS_RANGE_SOME, or NFS_RANGE_ALL,
 * depending on whether none, some, or all of the requested sub-range is set.
 * In the case that the initial offset is not set, NFS_RANGE_NONE will
 * be returned.
 *
 * The desired offset and length are passed by reference.  The values
 * indicated by offsetp and lengthp are modified, so that they fit
 * entirely within the area that is set, unless NFS_RANGE_NONE is
 * returned, in which case they are not modified at all.
 *
 * nfs_range_is_clear(range, offsetp, lengthp, flags) is just like
 * nfs_range_is_set(), except that the query or wait applies to the
 * sub-range being clear.  In the case that the initial offset is
 * not clear, NFS_RANGE_NONE will be returned.
 *
 * NFS_RANGE_NONE is guaranteed to be zero, so it may be used as a
 * generalized boolean.
 *
 * The "flags" field is reserved for future use.
 *
 * Example:
 * --------
 *
 * nfs_range_t *range;
 * uint64_t off, len;
 *
 * range = nfs_range_create();
 * nfs_range_set(range, 0, ULONG_MAX);
 * nfs_range_clear(range, 4096, 4096);
 *
 * off = 0;
 * len = 10;
 * ret = nfs_range_is_set(range, &off, &len, 0);
 *
 * ret is NFS_RANGE_ALL, off remains 0, len remains 10.
 *
 * off = 0;
 * len = 8192;
 * ret = nfs_range_is_set(range, &off, &len, 0);
 *
 * ret is NFS_RANGE_SOME, off is 0, len is 4096
 *
 * off = 1024;
 * len = 65536;
 * ret = nfs_range_is_set(range, &off, &len, 0);
 *
 * ret is NFS_RANGE_SOME, off is 0, len is 4096
 */

typedef struct nfs_range nfs_range_t;

nfs_range_t *nfs_range_create(void);
void nfs_range_destroy(nfs_range_t *);

typedef void *nfs_shared_range_t;

typedef enum {
	NFS_RANGE_NONE = 0,
	NFS_RANGE_SOME,
	NFS_RANGE_ALL
} nfs_range_query_t;

nfs_range_query_t nfs_range_set(nfs_range_t *, uint64_t, uint64_t);
nfs_range_query_t nfs_range_clear(nfs_range_t *, uint64_t, uint64_t);

nfs_range_query_t nfs_range_is_set(nfs_range_t *, uint64_t *, uint64_t *,
    uint32_t);
nfs_range_query_t nfs_range_is_clear(nfs_range_t *, uint64_t *, uint64_t *,
    uint32_t);

/*
 * These routines must be called when the kernel module is loaded or unloaded.
 */
void nfs_range_init(void);
void nfs_range_fini(void);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_RANGE_H */
