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

#ifndef _NFS_SERV_INST_H
#define	_NFS_SERV_INST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * rfs4_deleg_policy is used to signify the server's delegation
 * policy.  The default is to NEVER delegate files and the
 * administrator must configure the server to enable delegations.
 *
 * The disable/enable delegation functions are used to eliminate a
 * race with exclusive creates.
 */
typedef enum {
	SRV_NEVER_DELEGATE = 0,
	SRV_NORMAL_DELEGATE = 1
} srv_deleg_policy_t;

struct rfs4_state;

typedef struct {
	char		inst_name[10];
	time_t		start_time;

	uint32_t	inst_flags;

	int 		default_persona;

	sysid_t		lockt_sysid;
	kmutex_t	servinst_lock;
	rfs4_servinst_t	*cur_servinst;

	int		ss_enabled;
	int		seen_first_compound;


	verifier4	Write4verf;
	verifier4	Readdir4verf;

	krwlock_t    findclient_lock;
	rfs4_table_t *client_tab;
	rfs4_index_t *clientid_idx;
	rfs4_index_t *nfsclnt_idx;

	rfs4_table_t *openowner_tab;
	rfs4_index_t *openowner_idx;

	kmutex_t	state_lock;
	rfs4_table_t *state_tab;
	rfs4_index_t *state_idx;
	rfs4_index_t *state_owner_file_idx;
	rfs4_index_t *state_file_idx;

	rfs4_table_t *lo_state_tab;
	rfs4_index_t *lo_state_idx;
	rfs4_index_t *lo_state_owner_idx;

	rfs4_table_t *lockowner_tab;
	rfs4_index_t *lockowner_idx;
	rfs4_index_t *lockowner_pid_idx;


	rfs4_table_t *deleg_state_tab;
	rfs4_index_t *deleg_idx;
	rfs4_index_t *deleg_state_idx;

	krwlock_t	deleg_policy_lock;
	srv_deleg_policy_t deleg_policy;
	int		deleg_wlp;
	rfs4_cbstate_t (*deleg_cbcheck)(struct rfs4_state *);
	attrvers_t	attrvers;
} nfs_server_instance_t;

extern  nfs_server_instance_t nfs4_server;
extern  nfs_server_instance_t mds_server;
extern	kmutex_t	deleg_lock;

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_SERV_INST_H */
