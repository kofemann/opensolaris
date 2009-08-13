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

#ifndef _NFS_SERV_INST_H
#define	_NFS_SERV_INST_H

#include <sys/door.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * rfs4_deleg_policy is used to signify the server's delegation
 * policy.  The disable/enable delegation functions are used to
 * eliminate a race with exclusive creates.
 */
typedef enum {
	SRV_NEVER_DELEGATE = 0,
	SRV_NORMAL_DELEGATE = 1
} srv_deleg_policy_t;

/*
 * list of all occurrences of NFS Server stateStore.
 */
extern  list_t    nsi_head;
extern  krwlock_t nsi_lock;

struct rfs4_state;
struct rfs4_client;

/*
 * max size of the server instance name
 */
#define	NFS_INST_NAMESZ 	15

/*
 * The server instance inst_flags flag bits::
 */
#define	NFS_INST_STORE_INIT	0x00000001
#define	NFS_INST_SS_ENABLED	0x00000002
#define	NFS_INST_TERMINUS	0x00000004

/*
 * The server instance capabilities
 */
#define	NFS_INST_v40		0x00010000
#define	NFS_INST_v41		0x00020000
#define	NFS_INST_DS		0x00040000

/*
 * NFS stateStore instances.
 */
typedef struct nfs_server_instance {
	list_node_t	nsi_list;
	struct rfs4_database	*state_store;
	callb_id_t	cpr_id;

	char		inst_name[NFS_INST_NAMESZ];

	/* inst_flags is protected via state_lock */
	uint32_t	inst_flags;

	time_t		start_time;
	int		reap_time;
	sysid_t		lockt_sysid;
	u_longlong_t	caller_id;	/* for caller context */
	uint_t		vkey;		/* for VSD */

	krwlock_t	reclaimlst_lock;
	time_t		gstart_time;
	time_t		grace_period;
	time_t		lease_period;

	list_t 		reclaim_head;
	uint_t		reclaim_cnt;

	door_handle_t	dh;

	int		seen_first_compound;

	verifier4	Write4verf;
	verifier4	Readdir4verf;

	kmutex_t	state_lock;

	time_t		file_cache_time;
	krwlock_t	findclient_lock;
	rfs4_table_t	*file_tab;
	rfs4_index_t	*file_idx;

	time_t	client_cache_time;
	rfs4_table_t	*client_tab;
	rfs4_index_t	*clientid_idx;
	rfs4_index_t	*nfsclnt_idx;

	time_t	openowner_cache_time;
	rfs4_table_t	*openowner_tab;
	rfs4_index_t	*openowner_idx;

	time_t	state_cache_time;
	rfs4_table_t	*state_tab;
	rfs4_index_t	*state_idx;
	rfs4_index_t	*state_owner_file_idx;
	rfs4_index_t	*state_file_idx;

	time_t	lo_state_cache_time;
	rfs4_table_t	*lo_state_tab;
	rfs4_index_t	*lo_state_idx;
	rfs4_index_t	*lo_state_owner_idx;

	time_t	lockowner_cache_time;
	rfs4_table_t	*lockowner_tab;
	rfs4_index_t	*lockowner_idx;
	rfs4_index_t	*lockowner_pid_idx;

	time_t	deleg_state_cache_time;
	rfs4_table_t	*deleg_state_tab;
	rfs4_index_t	*deleg_idx;
	rfs4_index_t	*deleg_state_idx;

	/* XXX: rbg, should move the inst_flags  */
	int		deleg_disabled;
	kmutex_t	deleg_lock;
	krwlock_t	deleg_policy_lock;
	srv_deleg_policy_t	deleg_policy;

	int		deleg_wlp;

	rfs4_cbstate_t	(*deleg_cbcheck)(struct rfs4_state *);
	void	(*deleg_cbrecall)(struct rfs4_deleg_state *, bool_t);
	void	(*exi_clean_func)(struct nfs_server_instance *,
	    struct exportinfo *);
	void	(*clnt_clear)(struct rfs4_client *);

	krwlock_t	findsession_lock;
	rfs4_table_t	*mds_session_tab;
	rfs4_index_t	*mds_session_idx;
	rfs4_index_t	*mds_sess_clientid_idx;

	rfs4_table_t	*mds_pool_info_tab;
	rfs4_index_t	*mds_pool_info_idx;
	krwlock_t	mds_pool_info_lock;

	krwlock_t	mds_layout_lock;
	rfs4_table_t	*mds_layout_tab;
	rfs4_index_t	*mds_layout_idx;
	rfs4_index_t	*mds_layout_ID_idx;

	/*
	 * XXX: Need to track the default ID
	 * until the SMF code is added.
	 */
	int		mds_layout_default_idx;

	krwlock_t	mds_layout_grant_lock;
	rfs4_table_t	*mds_layout_grant_tab;
	rfs4_index_t	*mds_layout_grant_idx;
	rfs4_index_t	*mds_layout_grant_ID_idx;

	krwlock_t	mds_ever_grant_lock;
	rfs4_table_t	*mds_ever_grant_tab;
	rfs4_index_t	*mds_ever_grant_idx;
	rfs4_index_t	*mds_ever_grant_fsid_idx;

	krwlock_t	mds_mpd_lock;
	rfs4_table_t	*mds_mpd_tab;
	rfs4_index_t	*mds_mpd_idx;
	id_space_t	*mds_mpd_id_space;

	krwlock_t    	ds_addrlist_lock;
	rfs4_table_t	*ds_addrlist_tab;
	rfs4_index_t	*ds_addrlist_idx;
	rfs4_index_t	*ds_addrlist_ip_idx;
	rfs4_index_t	*ds_addrlist_addrkey_idx;

	krwlock_t	ds_guid_info_lock;

	/*
	 * XXX: Still a hack, but a useful one
	 * to allow people to *not* specify
	 * polices. Will now come out when
	 * we do the SMF work.
	 */
	uint32_t	ds_guid_info_count;

	rfs4_table_t	*ds_guid_info_tab;
	rfs4_index_t	*ds_guid_info_inst_idx;
	rfs4_index_t	*ds_guid_info_idx;
	rfs4_index_t	*ds_guid_info_dataset_name_idx;

	krwlock_t	ds_owner_lock;
	rfs4_table_t	*ds_owner_tab;
	rfs4_index_t	*ds_owner_inst_idx;
	rfs4_index_t	*ds_owner_idx;

	krwlock_t	mds_mapzap_lock;
	rfs4_table_t	*mds_mapzap_tab;
	rfs4_index_t	*mds_mapzap_idx;

	fem_t	*deleg_rdops;
	fem_t	*deleg_wrops;

	attrvers_t	attrvers;
} nfs_server_instance_t;

#define	SSTOR_CT_INIT(p, val, ct)	\
	if (p->val == 0)			\
		p->val = rfs4_lease_time * ct;

extern int nsi_create(char *, nfs_server_instance_t **);

/* temp vvvvvvvv */
extern nfs_server_instance_t *mds_server;
extern nfs_server_instance_t *nfs4_server;
/* temp ^^^^^^^^ */


#ifdef	__cplusplus
}
#endif

#endif /* _NFS_SERV_INST_H */
