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

typedef struct devnode {
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

/*
 * Definitions for dn_flags
 *
 * DN_GDI_INFLIGHT	GETDEVICEINFO is currently OTW
 * DN_GDI_FAILED	GETDEVICEINFO has failed
 * DN_ORPHAN		The devnode is orphaned from the tree
 * DN_INSERTED		the devnode is inserted into the tree
 */
#define	DN_GDI_INFLIGHT	0x01
#define	DN_GDI_FAILED	0x02
#define	DN_ORPHAN	0x04
#define	DN_INSERTED	0x08

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

#define	PNFS_LAYOUTEND	0xffffffffffffffff

/* per-rnode generic layout */
typedef struct pnfs_layout {
	list_node_t		plo_list;
	layoutiomode4		plo_iomode;
	int			plo_flags;
	offset4			plo_offset;
	length4			plo_length;
	offset4			plo_pattern_offset;
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

/*
 * Layout Flag Fields
 * NOTE: PLO_RETURN, PLO_GET and PLO_RECALL can only be set or cleared
 * when the code path "owns" the R4OTWLO bit in the rnode.  However
 * PLO_RETURN, PLO_GET and PLO_RECALL, can still be checked by only
 * having to hold the rnode's r_statelock.
 */
#define	PLO_ROC		0x1	/* Return Layout On Close */
#define	PLO_RETURN	0x02	/* Layout Being Returned. */
#define	PLO_GET		0x04	/* Layoutget in Progress */
#define	PLO_RECALL	0x08	/* Layout Being Recalled */
#define	PLO_BAD		0x10	/* Layout is Bad */
#define	PLO_UNAVAIL	0x20	/* Layout Unavailable from MDS */
#define	PLO_COM2MDS	0x40	/* Commit To MDS */
#define	PLO_TRYLATER	0x80	/* RETRY from MDS on LAYOUTGET, try later */
#define	PLO_COMMIT_MDS	0x100	/* Commit to MDS */
#define	PLO_LOWAITER	0x200	/* Thread waiting for this layout */
#define	PLO_PROCESSED	0x400	/* LAYOUTGET processed this layout */

typedef struct pnfs_lo_matches {
	list_t		lm_layouts;
	offset4 	lm_offset;
	length4 	lm_length;
	uint_t		lm_status;
	uint_t		lm_flags;
	layoutiomode4	lm_mode;
} pnfs_lo_matches_t;

/*
 * Status Flags For lm_status field of pnfs_lo_matches
 */
#define	LOMSTAT_MATCHFOUND	0x1
#define	LOMSTAT_NEEDSWAIT	0x02
#define	LOMSTAT_DELAY		0x04

/*
 * Use bits passed to pnfs_find_layouts() identifying why the layout list
 * is to be acquired.
 */
#define	LOM_USE		0x2
#define	LOM_RETURN	0x4
#define	LOM_RECALL	0x8
#define	LOM_COMMIT	0x10

/*
 * LOM status bits, indicating status of the layout list returned, if any.
 */
#define	LOM_STAT_SUCCESS	0x0
#define	LOM_STAT_RECALLED	0x01    /* Layout(s) recalled */

typedef struct pnfs_lol {
	list_node_t	l_node;
	pnfs_layout_t	*l_layout;
	offset4		l_offset;
	length4		l_length;
	int		l_flags;
} pnfs_lol_t;


/*
 * Flag bits telling the layoutreturn code what type of return
 * it is doing and if it is from a return, or initiated by a recall.
 */
#define	PNFS_LAYOUTRECALL_FILE	0x01
#define	PNFS_LAYOUTRECALL_FSID	0x02
#define	PNFS_LAYOUTRECALL_ALL	0x04
#define	PNFS_LAYOUTRETURN_FILE	0x08

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
	offset4 	ce_offset;
	length4 	ce_length;
	pnfs_layout_t	*ce_lo;
} commit_extent_t;

typedef struct {
	mntinfo4_t	*tgd_mi;
	cred_t		*tgd_cred;
} task_get_devicelist_t;

typedef struct {
	mntinfo4_t 		*tlg_mi;
	vnode_t 		*tlg_vp;
	cred_t 			*tlg_cred;
	layoutiomode4 		tlg_iomode;
	uint32_t 		tlg_flags;
	offset4			tlg_offset;
} task_layoutget_t;

#define	TLG_NOFREE (0x01)
#define	TLG_USE		LOM_USE
#define	TLG_RETURN	LOM_RETURN
#define	TLG_RECALL	LOM_RECALL

typedef struct {
	mntinfo4_t 		*tlr_mi;
	vnode_t 		*tlr_vp;
	cred_t 			*tlr_cr;
	offset4 		tlr_offset;
	length4 		tlr_length;
	bool_t 			tlr_reclaim;
	layoutiomode4 		tlr_iomode;
	layouttype4 		tlr_layout_type;
	pnfs_lo_matches_t	*tlr_lom;
	layoutreturn_type4 	tlr_return_type;
	int			tlr_aflag;
	nfs4_server_t		*tlr_np;
	nfs4_fsidlt_t		*tlr_lt;
} task_layoutreturn_t;

extern void	pnfs_layout_return(vnode_t *, cred_t *, int,
	pnfs_lo_matches_t *, int);

extern pnfs_lo_matches_t *
pnfs_find_layouts(nfs4_server_t *, struct rnode4 *, cred_t *,
layoutiomode4, offset4, length4, int);

extern	int	pnfs_rnode_holds_layouts(struct rnode4 *);
extern void	pnfs_layoutget(vnode_t *, cred_t *, offset4, layoutiomode4);
extern void	pnfs_layout_hold(struct rnode4 *, struct pnfs_layout *);
extern void	pnfs_layout_rele(struct rnode4 *, struct pnfs_layout *);
extern void	pnfs_decr_layout_refcnt(struct rnode4 *, struct pnfs_layout *);
extern void	pnfs_trim_fsid_tree(struct rnode4 *, struct nfs4_fsidlt *, int);
extern void	pnfs_release_layouts(nfs4_server_t *np, struct rnode4 *,
	struct pnfs_lo_matches *, int);
extern void    	pnfs_insert_layout(pnfs_layout_t *, struct rnode4 *,
	struct pnfs_layout *);


/*
 * Layout data structures that get XDR encoded/decoded into the buffer
 * passed via the system call for getting layout information.
 */
typedef struct stripe_info {
	uint32_t 	stripe_index;
	struct {
		uint_t multipath_list_len;
		struct netaddr4 *multipath_list_val;
	} multipath_list;
} stripe_info_t;


typedef struct layoutspecs {
	uint32_t 	plo_stripe_count;
	uint32_t 	plo_stripe_unit;
	uint32_t 	plo_status;
	layoutiomode4 	iomode;
	offset4 	plo_offset;
	length4 	plo_length;
	int64_t 	plo_creation_sec;
	int64_t 	plo_creation_musec;
	devnode_t	*plo_devnode;
	struct {
		uint_t plo_stripe_info_list_len;
		stripe_info_t *plo_stripe_info_list_val;
	} plo_stripe_info_list;
} layoutspecs_t;

typedef struct layoutstats {
	uint64_t	proxy_iocount;
	uint64_t	ds_iocount;
	struct {
		uint_t		total_layouts;
		layoutspecs_t	*lo_specs;
	} plo_data;
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
