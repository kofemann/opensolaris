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



#include "nfsstat_layout.h"
#include <netdir.h>
#include <strings.h>
#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bool_t
xdr_offset4(XDR *xdrs, offset4 *objp)
{

	if (!xdr_uint64_t(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_length4(XDR *xdrs, length4 *objp)
{

	if (!xdr_uint64_t(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_netaddr4(XDR *xdrs, netaddr4 *objp)
{

	if (!xdr_string(xdrs, &objp->na_r_netid, ~0))
		return (FALSE);
	if (!xdr_string(xdrs, &objp->na_r_addr, ~0))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_stripe_info_t(XDR *xdrs, stripe_info_t *objp)
{

	if (!xdr_uint32_t(xdrs, &objp->stripe_index))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->multipath_list.multipath_list_val,
	    (uint_t *)&objp->multipath_list.multipath_list_len, ~0,
	    sizeof (netaddr4), (xdrproc_t)xdr_netaddr4))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_layoutspecs_t(XDR *xdrs, layoutspecs_t *objp)
{

	if (!xdr_uint32_t(xdrs, &objp->plo_stripe_count))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->plo_stripe_unit))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->plo_status))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->iomode))
		return (FALSE);
	if (!xdr_offset4(xdrs, &objp->plo_offset))
		return (FALSE);
	if (!xdr_length4(xdrs, &objp->plo_length))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->plo_creation_sec))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->plo_creation_musec))
		return (FALSE);
	if (!xdr_array(xdrs,
	    (char **)&objp->plo_stripe_info_list.plo_stripe_info_list_val,
	    (uint_t *)&objp->plo_stripe_info_list.plo_stripe_info_list_len,
	    ~0, sizeof (stripe_info_t), (xdrproc_t)xdr_stripe_info_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_layoutstats_t(XDR *xdrs, layoutstats_t *objp)
{
	int total_layouts;

	if (!xdr_uint64_t(xdrs, &objp->proxy_iocount))
		return (FALSE);
	if (!xdr_uint64_t(xdrs, &objp->ds_iocount))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->plo_data.lo_specs,
	    (uint_t *)&objp->plo_data.total_layouts, ~0,
	    sizeof (layoutspecs_t), (xdrproc_t)xdr_layoutspecs_t))
		return (FALSE);
	return (TRUE);
}

/*
 * Do a RPC NULL procedure ping to the data servers.
 */
int
null_procedure_ping(char *hostname, char *netid, enum clnt_stat *ds_status)
{

	CLIENT *client = NULL;
	struct timeval to;
	enum clnt_stat rpc_stat;
	struct netconfig *nconf;
	ulong_t prognum = NFS_PROGRAM;
	ulong_t versnum = 4;
	int rc = -1;

	to.tv_sec = 60;
	to.tv_usec = 0;

	client = clnt_create_timed(hostname, prognum, versnum, netid, &to);
	if (client != NULL) {
		rpc_stat = clnt_call(client, NULLPROC, (xdrproc_t)xdr_void,
		    (char *)NULL, (xdrproc_t)xdr_void,
		    (char *)NULL, to);
		*ds_status = rpc_stat;
		rc = 0;
	}
	return (rc);
}

/*
 * Takes a universal address and use that to get port and hostname.
 * Portions of the code borrowed from print_netaddr4 function in snoop_nfs4.c
 */
int
lookup_name_port(netaddr4 *na, long  *port, char *hostname, char *ipaddress)
{
	struct hostent *host;
	struct in_addr addr;
	char *penultimate, *ultimate, *copy;
	int error = 0;
	int rc;

	/*
	 * Check arguments
	 */
	if (na == NULL || port == NULL || hostname == NULL ||
	    ipaddress == NULL) {
			fprintf(stderr, "nfsstat: Invalid arguments to"
			    " lookup_name_port\n");
			return (-1);
	}

	copy = strdup(na->na_r_addr);
	if (copy == NULL) {
		fprintf(stderr, "nfsstat: Cannot allocate memory\n");
		return (-1);
	}

	/* chop off final two octets */
	ultimate = strrchr(copy, '.');
	if (ultimate == NULL) {
		error = EADDRDEC;
		goto final;
	}
	*(ultimate++) = '\0';
	penultimate = strrchr(copy, '.');
	if (penultimate == NULL) {
		error = EADDRDEC;
		goto final;
	}
	*(penultimate++) = '\0';

	/* convert final two octets into port number */
	errno = 0;
	*port = (strtol(penultimate, NULL, 0) << 8) + strtol(ultimate, NULL, 0);
	if (errno != 0) {
		error = EADDRDEC;
		goto final;
	}

	/* get the ip address and hostname */
	strcpy(ipaddress, copy);
	if (strcmp("tcp", na->na_r_netid) == 0) {
		rc = inet_pton(AF_INET, copy, &addr);
		if (rc == 0) {
			error = EADDRDEC;
			goto final;

		}
		if (rc == -1) {
			error = EADDRDEC;
			goto final;
		}
		host = getipnodebyaddr((char *)&addr, 4, AF_INET, &rc);
	} else {
		/* It is a tcp6 address, but confirm anyways. */
		if (strcmp("tcp6", na->na_r_netid) == 0) {
			rc = inet_pton(AF_INET6, copy, &addr);
			if (rc == 0) {
				error = EADDRDEC;
				goto final;
			}
			if (rc == -1) {
				error = EADDRDEC;
				goto final;
			}
		}
		host = getipnodebyaddr((char *)&addr, 16, AF_INET6, &rc);
	}

	/* get the status of the dataserver */
	if (host != NULL) {
		strcpy(hostname, host->h_name);
	} else {
		error = EADDRTRAN;
	}

final:
	free(copy);
	return (error);
}
