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

#ifndef	_SYS_DSERV_H
#define	_SYS_DSERV_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <rpc/rpc.h>
#include <nfs/nfs4.h>


#ifdef	__cplusplus
extern "C" {
#endif


typedef enum dserv_ioc_cmd {
	DSERV_IOC_DATASET_INFO,
	DSERV_IOC_SVC,
	DSERV_IOC_SETPORT,
	DSERV_IOC_SETMDS,
	DSERV_IOC_REPORTAVAIL,
	DSERV_IOC_DATASET_PROPS,
	DSERV_IOC_INSTANCE_SHUTDOWN
} dserv_ioc_cmd_t;

/*
 * DSERV_IOC_DATASET_INFO argruments
 */

#define	DSERV_MAX_NETID	32
#define	DSERV_MAX_UADDR	128

typedef struct dserv_dataset_props {
	char ddp_name[MAXPATHLEN];
	char ddp_mds_netid[DSERV_MAX_NETID];
	char ddp_mds_uaddr[DSERV_MAX_UADDR];
} dserv_dataset_props_t;

typedef struct dserv_dataset_info {
	char	dataset_name[MAXPATHLEN];
} dserv_dataset_info_t;

typedef struct dserv_setmds_args {
	char dsm_mds_netid[DSERV_MAX_NETID];
	char dsm_mds_uaddr[DSERV_MAX_UADDR];
} dserv_setmds_args_t;

/*
 * DSERV_IOC_SVC arguments
 */
/*
 * XXX Lisa
 * 1.) If netid is tcp or rdma(?), we'll use a sockaddr_in.  If netid
 * is tcp6, we'll use a sockaddr_in6.  Note: we will only support tcp not udp.
 * 2.) make sure this is packed correctly.
 * 3.) May need versions.
 */

typedef struct dserv_svc_args {
	int	fd;
	char	netid[KNC_STRSIZE];
	int	poolid;
	union {
		struct sockaddr_in	sin;
		struct sockaddr_in6	sin6;
	} sin;
} dserv_svc_args_t;

typedef struct dserv_setport_args {
	char dsa_proto[32]; /* XXX use a constant */
	char dsa_uaddr[128]; /* XXX use a constant */
	char dsa_name[MAXPATHLEN];
} dserv_setport_args_t;

/*
 * Function declarations
 */
int dserv_svc(dserv_svc_args_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DSERV_H */
