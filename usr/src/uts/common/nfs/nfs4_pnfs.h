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
#include <nfs/nfssys.h>
#include <sys/systm.h>
#include <sys/taskq.h>
#include <sys/disp.h>
#include <sys/time.h>
#include <rpc/xdr.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <sys/cmn_err.h>

typedef struct {
	/*
	 * This structure mimics the mi_servers and mi_curr_serv
	 * in the mntinfo4_t.  ds_servers is the list of servinfo4s
	 * which refer to the same data server entity, typically, a
	 * multi-homed data server.
	 */
	servinfo4_t	*ds_servers;
	servinfo4_t	*ds_curr_serv;
} ds_info_t;

typedef struct {
	/* key */
	deviceid4	dn_devid;
	avl_node_t	dn_avl;
	uint32_t	dn_count;
	int		dn_flags;
	kcondvar_t	dn_cv[1];

	/* data servers, indexed indentically to ds_addrs */
	ds_info_t	*dn_server_list;

	/* xdr decoded information about the data servers */
	nfsv4_1_file_layout_ds_addr4 dn_ds_addrs;
} devnode_t;

#define	DN_GDI_INFLIGHT	1
#define	DN_GDI_FAILED	2

/*
 * GETDEVICE OTW and NO_OTW
 */
#define	PGD_OTW		0x01
#define	PGD_NO_OTW	0x02

/* per-rnode file layout */
typedef struct {
	uint32_t		std_refcount;

	nfs4_sharedfh_t		*std_fh;
	deviceid4		std_devid;

	kmutex_t		std_lock;
	verifier4		std_writeverf;
	uint32_t		std_flags;
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
	int64_t			plo_creation_sec;
	int64_t			plo_creation_musec;
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
	list_t		fir_task_list;
} file_io_read_t;

/* units of read i/o work (part of a batch) */
typedef struct {
	file_io_read_t *rt_job;
	stripe_dev_t *rt_dev;
	nfs4_call_t *rt_call;
	nfs4_recov_state_t rt_recov_state;
	cred_t *rt_cred;
	offset4 rt_offset;
	count4 rt_count;
	char *rt_base;
	int rt_have_uio;
	uint32_t rt_free_uio;
	uio_t rt_uio;
	list_node_t rt_next;
} read_task_t;

/* a batch of write i/o work requested of pNFS */
typedef struct {
	kmutex_t	fiw_lock;
	kcondvar_t	fiw_cv;
	uint32_t	fiw_flags;
	int32_t		fiw_remaining;
	int		fiw_error;
	stable_how4	fiw_stable_how;
	stable_how4	fiw_stable_result;
	stateid4	fiw_stateid;
	vnode_t		*fiw_vp;
	list_t		fiw_task_list;
} file_io_write_t;

/* units of write i/o work (part of a batch) */
typedef struct {
	file_io_write_t *wt_job;
	stripe_dev_t *wt_dev;
	nfs4_call_t *wt_call;
	nfs4_recov_state_t wt_recov_state;
	cred_t *wt_cred;
	pnfs_layout_t *wt_layout;
	caddr_t wt_base;
	offset4 wt_offset;
	offset4 wt_voff;
	count4 wt_count;
	uint32_t wt_sui;
	list_node_t wt_next;
} write_task_t;

typedef struct {
	kmutex_t	fic_lock;
	kcondvar_t	fic_cv;
	int32_t		fic_remaining;
	int		fic_error;
	vnode_t		*fic_vp;
	page_t		*fic_plist;
} file_io_commit_t;

typedef struct {
	file_io_commit_t *cm_job;
	stripe_dev_t *cm_dev;
	nfs4_call_t *cm_call;
	nfs4_recov_state_t cm_recov_state;
	cred_t *cm_cred;
	pnfs_layout_t *cm_layout;
	offset4 cm_offset;
	count4 cm_count;
	uint32_t cm_sui;
} commit_task_t;

typedef struct {
	offset4 ce_offset;
	length4 ce_length;
} commit_extent_t;

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

/*
 * Layout data structures that get XDR encoded/decoded into the buffer
 * passed via the system call for getting layout information.
 */
typedef struct stripe_info {
	uint32_t stripe_index;
	struct {
		uint_t multipath_list_len;
		struct netaddr4 *multipath_list_val;
	} multipath_list;
} stripe_info_t;

typedef struct layoutstats {
	uint32_t plo_num_layouts;
	uint32_t plo_stripe_count;
	uint32_t plo_stripe_unit;
	uint32_t plo_status;
	layoutiomode4 iomode;
	offset4 plo_offset;
	length4 plo_length;
	uint64_t proxy_iocount;
	uint64_t ds_iocount;
	int64_t plo_creation_sec;
	int64_t plo_creation_musec;
	struct {
		uint_t plo_stripe_info_list_len;
		stripe_info_t *plo_stripe_info_list_val;
	} plo_stripe_info_list;
} layoutstats_t;

/*
 * Error codes to report conditions to the userland. The fields must have the
 * same value as the fields in the user-space file named nfsstat_layout.h.
 */
typedef enum nfsstat_layout_errcodes {
	ENOLAYOUT = 	-1,
	ENOTAFILE = 	-2,
	ENOPNFSSERV = 	-3,
	ESYSCALL = 	-4,
	ENONFS = 	-5
} nfsstat_lo_errcodes_t;

#ifdef __cplusplus
}
#endif

#endif /* _NFS4_PNFS_H */
