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

#ifndef _NFS_RANGE_IMPL_H
#define	_NFS_RANGE_IMPL_H

#include <nfs/range.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/avl.h>
#include <sys/kmem.h>
#include <sys/rwlock.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	NFS_RANGE_MAX	(0xffffffffffffffff)

struct nfs_range {
	nfs_range_query_t nr_status;
	krwlock_t nr_lock;
	avl_tree_t nr_tree;
};

typedef struct {
	uint64_t ns_off;
	uint64_t ns_len;
	uint64_t ns_end;
	avl_node_t ns_avl;
} nfs_subrange_t;

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_RANGE_IMPL_H */
