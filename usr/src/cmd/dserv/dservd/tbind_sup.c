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

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <libintl.h>
#include <sys/param.h>
#include <sys/tiuser.h>
#include <rpc/svc.h>
#include "nfs_tbind.h"
#include <nfs/nfssys.h>
#include <libdserv.h>
#include <dservd.h>

#define	PNFSCTLMDS	104000
#define	PNFSCTLMDS_V1	1

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

/*
 * The following are all globals used by routines in nfs_tbind.c.
 */
size_t	end_listen_fds;		/* used by conn_close_oldest() */
size_t	num_fds = 0;		/* used by multiple routines */
int	listen_backlog = 32;	/* used by bind_to_{provider,proto}() */
int	num_servers;		/* used by cots_listen_event() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = NULL;
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */

#define	MAXHOSTNAMELEN 64

static dserv_handle_t *do_all_handle;

static char *
get_uaddr(struct netconfig *nconf, struct netbuf *nb)
{
	struct nfs_svc_args nsa;
	char *ua, *ua2, *mua = NULL;
	char me[MAXHOSTNAMELEN];
	struct nd_addrlist *nas;
	struct nd_hostserv hs;
	struct nd_mergearg ma;

	ua = taddr2uaddr(nconf, nb);

	if (ua == NULL) {
		return (NULL);
	}

	gethostname(me, MAXHOSTNAMELEN);

	hs.h_host = me;
	hs.h_serv = "nfs";
	if (netdir_getbyname(nconf, &hs, &nas)) {
		return (NULL);
	}

	ua2 = taddr2uaddr(nconf, nas->n_addrs);

	if (ua2 == NULL) {
		return (NULL);
	}

	ma.s_uaddr = ua;
	ma.c_uaddr = ua2;
	ma.m_uaddr = NULL;

	if (netdir_options(nconf, ND_MERGEADDR, 0, (char *)&ma)) {
		return (NULL);
	}

	mua = ma.m_uaddr;
	return (mua);
}

/*
 * dserv_service is called either with a command of
 * NFS4_KRPC_START or SETPORT. Any other value is
 * invalid.
 */
static int
dserv_service(int fd, struct netbuf *addrmask, struct netconfig *nconf,
    int cmd, struct netbuf *addr)
{
	dserv_svc_args_t svcargs;
	dserv_setport_args_t setportargs;
	char *uaddr;
	int result;

	switch (cmd) {
	case NFS4_KRPC_START:
		svcargs.fd = fd;
		bcopy(addr->buf, &svcargs.sin, addr->len);
		(void) strlcpy(svcargs.netid,
		    nconf->nc_netid, sizeof (svcargs.netid));
		uaddr = get_uaddr(nconf, addr);
		if (uaddr != NULL) {
			dserv_log(do_all_handle, LOG_INFO,
			    gettext("NFS4_KRPC_START: %s"), uaddr);
			free(uaddr);
		}
		result = dserv_kmod_svc(do_all_handle, &svcargs);
		break;

	case NFS4_SETPORT:
		uaddr = get_uaddr(nconf, addr);
		if (uaddr == NULL) {
			dserv_log(do_all_handle, LOG_INFO,
			    gettext("NFS4_SETPORT: get_uaddr failed"));
			return (1);
		}
		(void) strlcpy(setportargs.dsa_uaddr, uaddr,
		    sizeof (setportargs.dsa_uaddr));
		(void) strlcpy(setportargs.dsa_proto, nconf->nc_proto,
		    sizeof (setportargs.dsa_proto));
		(void) strlcpy(setportargs.dsa_name, getenv("SMF_FMRI"),
		    sizeof (setportargs.dsa_name));

		result = dserv_kmod_setport(do_all_handle, &setportargs);

		if (result == 0)
			result = dserv_kmod_reportavail(do_all_handle);
		break;

	default:
		dserv_log(do_all_handle, LOG_ERR,
		    gettext("bad cmd: %d"), cmd);
		return (1);
	}

	if (result != 0) {
		dserv_log(do_all_handle, LOG_ERR, NULL);
		return (1); /* XXX errno? */
	}

	return (0);
}

void
dserv_daemon(dserv_handle_t *handle)
{
	struct svcpool_args dserv_svcpool;
	struct protob dservproto;

	bzero(&dserv_svcpool, sizeof (dserv_svcpool));

	dserv_svcpool.id = UNIQUE_SVCPOOL_ID;

	if (_nfssys(SVCPOOL_CREATE, &dserv_svcpool)) {
		dserv_log(handle, LOG_ERR,
		    gettext("SVCPOOL_CREATE failed: %m"));
		exit(1);
	}

	dserv_set_pool_id(handle, dserv_svcpool.id);

	if (svcwait(dserv_svcpool.id)) {
		dserv_log(handle, LOG_ERR,
		    gettext("svcwait(DSERV_SVCPOOL_ID) failed: %m"));
		exit(1);
	}

	dservproto.serv = "DSERV";
	dservproto.versmin = PNFSCTLMDS_V1;
	dservproto.versmax = PNFSCTLMDS_V1;
	dservproto.program = PNFSCTLMDS;
	dservproto.flags = PROTOB_NO_REGISTER;
	dservproto.next = NULL;

	/*
	 * We love globals!
	 */
	Mysvc4 = dserv_service;
	do_all_handle = handle;
	if (do_all(&dservproto, NULL, 0) == -1) {
		dserv_log(handle, LOG_ERR,
		    gettext("do_all(): %m"));
		exit(1);
	}
	if (num_fds == 0) {
		dserv_log(handle, LOG_ERR,
		    gettext("Could not start DSERV service for any protocol"));
		exit(1);
	}

	end_listen_fds = num_fds;
	poll_for_action();

	dserv_log(handle, LOG_INFO,
	    gettext("I am shutting down now"));

	exit(1);
}
