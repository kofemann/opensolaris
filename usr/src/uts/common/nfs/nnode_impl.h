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

#ifndef _NNODE_IMPL_H
#define	_NNODE_IMPL_H

#include <nfs/nnode.h>

#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/avl.h>
#include <sys/list.h>
#include <nfs/nfs4.h>
#include <nfs/export.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The nnode.
 */

struct nnode {
	void *nn_key;
	int (*nn_key_compare)(const void *, const void *);
	void (*nn_key_free)(void *);

	pid_t nn_instance_id;

	kmutex_t nn_lock;
	uint32_t nn_flags;
	int nn_refcount;
	kcondvar_t nn_refcount_cv;
	hrtime_t nn_last_access;

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

typedef enum {
	NNODE_SWEEP_SYNC = 0,
	NNODE_SWEEP_ASYNC
} nnode_sweep_how_t;

struct nnode_bucket_sweep_task;

typedef void (*nnode_bucket_sweep_node_t)(struct nnode_bucket_sweep_task *,
    nnode_t *);

typedef struct nnode_bucket_sweep_task {
	uint32_t nbst_flags;
	nnode_bucket_sweep_node_t nbst_proc;

	nnode_bucket_t *nbst_bucket;

	pid_t nbst_inst_id;
	hrtime_t nbst_maxage;
	exportinfo_t *nbst_export;
} nnode_bucket_sweep_task_t;
#define	NNODE_BUCKET_SWEEP_TASK_SYNC	0x01
#define	NNODE_BUCKET_SWEEP_TASK_FREEME	0x02

#define	NNODE_HASH_SIZE		(251)
#define	NNODE_MAX_WORKERS	(4)
#define	NNODE_MIN_TASKALLOC	(8)
#define	NNODE_MAX_TASKALLOC	(NNODE_HASH_SIZE + NNODE_MIN_TASKALLOC)
#define	NNODE_GC_INTERVAL	(30LL * NANOSEC)
#define	NNODE_GC_TOO_OLD	(45LL * NANOSEC)

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_IMPL_H */
