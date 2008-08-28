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

#ifndef _NFS4_PNFS_H
#define	_NFS4_PNFS_H

/*
 * Generic and file layout specific pNFS support.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/avl.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_clnt.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_kprot.h>
#include <sys/systm.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/time.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/cmn_err.h>

typedef struct {
	/* key */
	deviceid4	devid;
	avl_node_t	avl;
	uint32_t	count;
	int		flags;
	kcondvar_t	cv[1];

	/* data servers, indexed indentically to ds_addrs */

	nfs4_server_t	**server_list;

	/* xdr decoded information about the data servers */
	nfsv4_1_file_layout_ds_addr4 ds_addrs;
} devnode_t;

#define	DN_GDI_INFLIGHT	1
#define	DN_GDI_FAILED	2

/* per-rnode file layout */
typedef struct {
	uint32_t		refcount;

	nfs4_sharedfh_t		*fh;
	deviceid4		sd_devid;

	kmutex_t		lock;
	verifier4		writeverf;
	uint32_t		flags;
	/*
	 * std_svp and std_n4sp need to be set/cleared together
	 */
	nfs4_server_t		*std_n4sp;
	servinfo4_t		*std_svp;
} stripe_dev_t;
#define	STRIPE_DEV_HAVE_VERIFIER	(0x01)

enum stripetype4 {
	STRIPE4_SPARSE = 0,
	STRIPE4_DENSE = 1
};



/* per-rnode generic layout */
typedef struct pnfs_layout {
	list_node_t		plo_list;
	layoutiomode4		plo_iomode;
	stateid4		plo_stateid;
	int			plo_flags;
	offset4			plo_offset;
	length4			plo_length;
	uint32_t		plo_inusecnt;
	kcondvar_t		plo_wait;
	deviceid4		plo_deviceid;
	uint32_t		plo_stripe_type;
	length4			plo_stripe_unit;
	uint32_t		plo_first_stripe_index;
	uint32_t		plo_stripe_count;
	stripe_dev_t		**plo_stripe_dev;
	kmutex_t		plo_lock;
	uint32_t		plo_refcount;
} pnfs_layout_t;

/* Layout Flag Fields */

#define	PLO_ROC		0x1	/* Return Layout On Close */
#define	PLO_COMMIT_MDS	0x02	/* Commit to MDS */
#define	PLO_RETURN	0x04	/* Layout Being Returned */
#define	PLO_GET		0x08	/* Layoutget In Progress */
#define	PLO_RECALL	0x10	/* Layout Being Recalled */
#define	PLO_BAD		0x20	/* Layout Is Bad */
#define	PLO_UNAVAIL	0x40	/* Layout Unavailable From MDS */
#define	PLO_TRYLATER	0x100	/* RETRY From MDS on Layoutget, Try Later */


/* a batch of read i/o work requested of pNFS */
typedef struct {
	kmutex_t	fir_lock;
	kcondvar_t	fir_cv;
	int32_t		fir_remaining;
	int		fir_error;
	int		fir_eof;
	offset4		fir_eof_offset;
	int		fir_count;
	stateid4	fir_stateid;
} file_io_read_t;

/* units of read i/o work (part of a batch) */
typedef struct {
	file_io_read_t *rt_job;
	stripe_dev_t *rt_dev;
	cred_t *rt_cred;
	vnode_t *rt_vp;
	offset4 rt_offset;
	count4 rt_count;
	char *rt_base;
	int rt_have_uio;
	uint32_t rt_free_uio;
	uio_t rt_uio;
	nfs4_error_t rt_err;
} read_task_t;

typedef struct {
	COMPOUND4args_clnt args;
	nfs_argop4 argop[3];	/* SEQUENCE, PUTFH, READ */
	READ4args *read;
	void **fh;
} pnfs_read_compound_t;

/* a batch of write i/o work requested of pNFS */
typedef struct {
	kmutex_t	fiw_lock;
	kcondvar_t	fiw_cv;
	uint32_t	fiw_flags;
	int32_t		fiw_remaining;
	int		fiw_error;
	stable_how4	fiw_stable_how;
	stateid4	fiw_stateid;
	vnode_t		*fiw_vp;
} file_io_write_t;
#define	FIW_VERIFIER_CHANGED (0x01)

/* units of write i/o work (part of a batch) */
typedef struct {
	file_io_write_t *wt_job;
	stripe_dev_t *wt_dev;
	cred_t *wt_cred;
	vnode_t *wt_vp;
	nfs4_error_t *wt_ep;
	caddr_t wt_base;
	offset4 wt_offset;
	offset4 wt_voff;
	count4 wt_count;
	nfs4_error_t wt_err;
} write_task_t;

typedef struct {
	mntinfo4_t	*tgd_mi;
	cred_t		*tgd_cred;
} task_get_devicelist_t;

typedef struct {
	mntinfo4_t *tlg_mi;
	vnode_t *tlg_vp;
	cred_t *tlg_cred;
	layoutiomode4 tlg_iomode;
	uint32_t tlg_flags;
} task_layoutget_t;
#define	TLG_NOFREE (0x01)

typedef struct {
	mntinfo4_t *tlr_mi;
	vnode_t *tlr_vp;
	cred_t *tlr_cr;
	offset4 tlr_offset;
	length4 tlr_length;
	bool_t tlr_reclaim;
	layoutiomode4 tlr_iomode;
	layouttype4 tlr_layout_type;
	stateid4 tlr_stateid;
	layoutreturn_type4 tlr_return_type;
} task_layoutreturn_t;


extern void	pnfs_layout_hold(struct rnode4 *, struct pnfs_layout *);

#ifdef __cplusplus
}
#endif

#endif /* _NFS4_PNFS_H */
