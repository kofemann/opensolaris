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

#ifndef	_SYS_DSERV_IMPL_H
#define	_SYS_DSERV_IMPL_H

#include <sys/vfs.h>
#include <sys/list.h>
#include <sys/avl.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs41_kprot.h>
#include <nfs/nfs4.h>
#include <sys/dmu.h>
#include <nfs/ds_prot.h>
#include <nfs/nnode.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSERV_MAXREAD	(1 * 1024 * 1024)
#define	DS_TO_MDS_CTRL_PROTO_RETRIES	5
#define	CTLDS_TIMEO 60 /* seconds */

kmem_cache_t *dserv_open_mdsfs_objset_cache;

/*
 * This data structure creates a unique identifer for a dataset for the
 * data server.
 */
typedef struct dserv_guid {
	uint64_t	dg_zpool_guid; /* SPA GUID */
	uint64_t	dg_objset_guid; /* Object set ID */
} dserv_guid_t;

/*
 * This data structure is used to store the mapping of a MDS Storage ID
 * to a real data server guid (zpool id + id of root pNFS object set).
 */
typedef struct mds_sid_map {
	mds_sid		msm_mds_storid;
	dserv_guid_t	msm_ds_guid;
	list_node_t	msm_mds_sid_map_node;
} mds_sid_map_t;

/*
 * This data structure stores the list of open root object sets that a
 * data server has.
 *
 * oro_objsetname - name of the root pNFS objset
 *
 * oro_osp - pointer to the open root pNFS object set
 *
 * oro_ds_guid - the real zpool guid assigned by the SPA and the real objset
 *	guid assigned by the DMU.
 *
 * oro_mds_zpool_id - The id for this root objset provided by the MDS upon
 *	response to DS_REPORTAVAIL.  This is the value that will be
 *	encoded in the file handle used between the client and data servers.
 *
 * oro_open_mdsfs_objsets - The open child, fsid object sets for this root
 *	pNFS object set.
 *
 * oro_open_objset_node - the linked list node
 */
typedef struct open_root_objset {
	char		oro_objsetname[MAXPATHLEN];
	objset_t	*oro_osp;
	dserv_guid_t	oro_ds_guid;
	list_t		oro_open_mdsfs_objsets;
	list_node_t	oro_open_root_objset_node;
} open_root_objset_t;

typedef uint32_t fsid_objset_flags;

typedef struct open_mdsfs_objset {
	mds_dataset_id		omo_dataset_id;
	objset_t		*omo_osp;
	fsid_objset_flags	omo_flags;
	list_node_t		omo_open_mdsfs_objset_node;
} open_mdsfs_objset_t;

typedef struct dserv_uaddr {
	char		*du_addr;
	char		*du_proto;
	list_node_t	du_list;
} dserv_uaddr_t;

/*
 * Persistent portion of nnode private data.
 * It is stored in the "bonus buffer" of the file.
 */
typedef struct dserv_nnode_data_phys {
	uint64_t	dp_size;	/* file size */
} dserv_nnode_data_phys_t;

/*
 * nnode private data
 */

typedef struct {
	mds_sid		*dnk_sid;
	nfs41_fid_t	*dnk_fid;
	nfs41_fid_t	dnk_real_fid;
} dserv_nnode_key_t;

typedef struct dserv_nnode_data {
	krwlock_t	dnd_rwlock;
	uint32_t	dnd_flags;

	mds_ds_fh	*dnd_fh;
	nfs41_fid_t	*dnd_fid;
	objset_t	*dnd_objset;
	uint64_t	dnd_object;		/* dmu object id */
	uint32_t	dnd_blksize;		/* object block size */
	dserv_nnode_data_phys_t	*dnd_phys;	/* ptr to persistent attrs */
	dmu_buf_t	*dnd_dbuf;		/* buffer containing dnd_phys */
} dserv_nnode_data_t;
#define	DSERV_NNODE_FLAG_OBJSET		0x01
#define	DSERV_NNODE_FLAG_OBJECT		0x02

typedef struct dserv_nnode_state {
	mds_ds_fh *fh;
} dserv_nnode_state_t;

/*
 * Server structures
 */
typedef struct dserv_compound_state {
	nfsstat4	*dcs_statusp;
	int		*dcs_continue;
	nnode_t		*dcs_nnode;
} dserv_compound_state_t;

typedef struct {
	CLIENT		*dmh_client;
	list_node_t	dmh_list;
} dserv_mds_handle_t;

typedef struct {
	pid_t		dmi_pid;
	time_t		dmi_start_time;
	uint64_t	dmi_ds_id;
	uint64_t	dmi_verifier;
	char		*dmi_name;
	avl_node_t	dmi_avl;
	krwlock_t	dmi_inst_lock;
	kmutex_t	dmi_content_lock;
	uint32_t	dmi_flags;
	struct netbuf	dmi_nb;
	struct knetconfig dmi_knc;
	char 		*dmi_mds_addr;
	char		*dmi_mds_netid;
	list_t		dmi_datasets;
	list_t		dmi_mds_sids;
	list_t		dmi_uaddrs;
	list_t		dmi_handles;
	boolean_t	dmi_teardown_in_progress;
	kmutex_t	dmi_zap_lock;
	boolean_t	dmi_recov_in_progress;
	ds_verifier	dmi_mds_boot_verifier;
} dserv_mds_instance_t;

#define	DSERV_MDS_INSTANCE_NET_VALID 0x01

/*
 * Useful macros
 */

#define	DSERV_AVL_RETURN(rc) \
	if (rc < 0) \
		return (-1); \
	if (rc > 0) \
		return (1);

/*
 * Function declarations
 */
void dserv_server_setup(void);
void dserv_server_teardown(void);
void dserv_mds_setup(void);
void dserv_mds_teardown(void);
int dserv_mds_instance_teardown();
int dserv_mds_setmds(char *, char *);
int dserv_mds_addobjset(const char *);
int dserv_mds_addport(const char *, const char *, const char *);
int dserv_mds_reportavail(void);
nfsstat4 dserv_mds_checkstate(void *, compound_state_t *, int mode,
    stateid4 *, bool_t, bool_t *, bool_t, caller_context_t *, clientid4 *);
dserv_mds_instance_t *dserv_mds_get_my_instance(void);
int dserv_instance_enter(krw_t, boolean_t, dserv_mds_instance_t **, pid_t *);
void dserv_instance_exit(dserv_mds_instance_t *);
char *dserv_strdup(const char *);
void dserv_strfree(char *);
int dserv_mds_do_reportavail(dserv_mds_instance_t *, ds_status *);
int dserv_mds_exibi(dserv_mds_instance_t *, ds_status *);
void dserv_mds_heartbeat_thread();

/*
 * Globals
 */

extern int dserv_debug;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DSERV_IMPL_H */
