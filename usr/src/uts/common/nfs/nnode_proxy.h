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

#ifndef _NNODE_PROXY_H
#define	_NNODE_PROXY_H

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mutex.h>
#include <nfs/ds_filehandle.h>
#include <nfs/mds_state.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	MDS_MAXREAD	(1 * 1024 * 1024)

typedef struct {
	DS_READargs args;
	DS_READres res;
} ds_read_t;

typedef struct {
	DS_WRITEargs args;
	DS_WRITEres res;
} ds_write_t;

typedef struct {
	nfs_fh4 fh;
	ds_addrlist_t *ds;
	union {
		ds_read_t read;
		ds_write_t write;
	} ds_io_u;
} ds_io_t;

typedef struct {
	uint64_t offset;
	int len;
	int startidx;
	int stripe_unit;
	int stripe_count;
	int io_array_size;
	ds_io_t *io_array;
} mds_strategy_t;

typedef struct {
	/*
	 * These first four fields have to match those in nnode_vn_data_t.
	 */
	vnode_t		*mnd_vp;
	kmutex_t	mnd_lock;
	uint32_t	mnd_flags;
	vattr_t		mnd_vattr;
	fsid_t		mnd_fsid;
	nfs41_fid_t	mnd_fid;
	uio_t		*mnd_uiop;
	nfs_server_instance_t *mnd_instp;
	mds_layout_t	*mnd_layout;
	mds_strategy_t	*mnd_strategy;
	int		mnd_eof;
} nnode_proxy_data_t;

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_PROXY_H */
