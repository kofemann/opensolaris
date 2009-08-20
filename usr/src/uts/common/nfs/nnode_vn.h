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

#ifndef _NNODE_VN_H
#define	_NNODE_VN_H

#include <nfs/nnode.h>

#include <nfs/nfs4.h>
#include <nfs/export.h>
#include <nfs/nfs41_filehandle.h>

#include <sys/types.h>
#include <sys/cred.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef struct {
	vnode_t *nvd_vp;
	kmutex_t nvd_lock;
	uint32_t nvd_flags;
	vattr_t nvd_vattr;
	exportinfo_t *nvd_exi;
} nnode_vn_data_t;
#define	NNODE_NVD_VATTR_VALID	0x01

typedef struct {
	vnode_t *nvm_vp;
} nnode_vn_md_t;

typedef struct {
	vnode_t *nvs_vp;
} nnode_vn_state_t;

typedef struct {
	fsid_t *nfk_fsid;
	fid_t *nfk_fid;
	uint32_t *nfk_other;
} nnode_fid_key_t;

/*
 * NB: The firsts fields of nnode_fid_key_v41_t must be the same as all
 * of the fields in nnode_fid_key_t.
 */

typedef struct {
	fsid_t *nfk_fsid;
	fid_t *nfk_fid;
	uint32_t *nfk_other;
	fid_t *nfk_xfid;
	fsid_t nfk_real_fsid;
	fid_t nfk_real_fid;
	fid_t nfk_real_xfid;
	uint32_t nfk_real_other;
} nnode_fid_key_v41_t;

/*
 * NB: The firsts fields of nnode_fid_key_v4_t must be the same as all
 * of the fields in nnode_fid_key_t.
 */

typedef struct {
	fsid_t *nfk_fsid;
	fid_t *nfk_fid;
	uint32_t *nfk_other;
	fid_t *nfk_xfid;
	nfs_fh4_fmt_t nfk_fh;
} nnode_fid_key_v4_t;

/*
 * NB: The firsts fields of nnode_fid_key_v3_t must be the same as all
 * of the fields in nnode_fid_key_t.
 */

typedef struct {
	fsid_t *nfk_fsid;
	fid_t *nfk_fid;
	uint32_t *nfk_other;
	nfs_fh3 nfk_fh;
} nnode_fid_key_v3_t;

typedef struct {
	nfs_fh3 *nsv_fh;
	exportinfo_t *nsv_exi;
} nnode_seed_v3data_t;

/*
 * NB: The firsts fields of nnode_fid_key_vp_t must be the same as all
 * of the fields in nnode_fid_key_t.
 */

typedef struct {
	fsid_t *nfk_fsid;
	fid_t *nfk_fid;
	uint32_t *nfk_other;
	fsid_t nfk_real_fsid;
	fid_t nfk_real_fid;
	uint32_t nfk_zero;
} nnode_fid_key_vp_t;

typedef struct {
	vnode_t *nsv_vp;
	fsid_t nsv_fsid;
	fid_t *nsv_fidp;
} nnode_seed_vpdata_t;

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_VN_H */
