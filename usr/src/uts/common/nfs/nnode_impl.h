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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _NNODE_IMPL_H
#define	_NNODE_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nfs/nnode.h>

#include <sys/vnode.h>
#include <sys/avl.h>
#include <sys/list.h>

#ifdef	__cplusplus
extern "C" {
#endif

struct nnode {
	void *nn_fh_value;
	uint32_t nn_fh_len;
	pid_t nn_instance_id;

	kmutex_t nn_lock;
	uint32_t nn_flags;
	uint32_t nn_refcount;
	kcondvar_t nn_refcount_cv;

	avl_node_t nn_avl;

	void *nn_data_ops_data;
	nnode_data_ops_t *nn_data_ops;

	void *nn_metadata_ops_data;
	nnode_metadata_ops_t *nn_metadata_ops;

	void *nn_state_ops_data;
	nnode_state_ops_t *nn_state_ops;
};

typedef struct {
	avl_tree_t nb_tree;
	krwlock_t nb_lock;
} nnode_bucket_t;

#define	NNODE_HASH_SIZE		251
#define	NNODE_MIN_FH_LEN	8
#define	NNODE_MAX_FH_LEN	256

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_IMPL_H */
