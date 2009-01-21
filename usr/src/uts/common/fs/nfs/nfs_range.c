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

#include <nfs/range_impl.h>

#include <sys/debug.h>

static kmem_cache_t *nfs_range_cache;

void
nfs_range_set(nfs_range_t *range, uint64_t offset, uint64_t length)
{
	ASSERT(range->nr_foo == 14);
}

void
nfs_range_clear(nfs_range_t *range, uint64_t offset, uint64_t length)
{
	ASSERT(range->nr_foo == 14);
}

nfs_range_query_t
nfs_range_is_set(nfs_range_t *range, uint64_t *offp, uint64_t *lenp,
    uint32_t flags)
{
	ASSERT(range->nr_foo == 14);
	return (NFS_RANGE_ALL);
}

nfs_range_query_t
nfs_range_is_clear(nfs_range_t *range, uint64_t *offp, uint64_t *lenp,
    uint32_t flags)
{
	ASSERT(range->nr_foo == 14);
	return (NFS_RANGE_NONE);
}

nfs_range_t *
nfs_range_create(void)
{
	nfs_range_t *rc;

	rc = kmem_cache_alloc(nfs_range_cache, KM_SLEEP);

	return (rc);
}

void
nfs_range_destroy(nfs_range_t *range)
{
	ASSERT(range->nr_foo == 14);
	kmem_cache_free(nfs_range_cache, range);
}

/*ARGSUSED*/
static int
nfs_range_construct(void *vrange, void *foo, int bar)
{
	nfs_range_t *range = vrange;

	range->nr_foo = 14;

	return (0);
}

/*ARGSUSED*/
static void
nfs_range_destruct(void *vrange, void *foo)
{
}

void
nfs_range_init(void)
{
	nfs_range_cache = kmem_cache_create("nfs_range_cache",
	    sizeof (nfs_range_t), 0,
	    nfs_range_construct, nfs_range_destruct, NULL,
	    NULL, NULL, 0);
}

void
nfs_range_fini(void)
{
	kmem_cache_destroy(nfs_range_cache);
}
