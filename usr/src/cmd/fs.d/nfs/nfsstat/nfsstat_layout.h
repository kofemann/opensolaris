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

#ifndef _NFSSTAT_LAYOUT_H
#define	_NFSSTAT_LAYOUT_H

/*
 * Generic and file layout specific pNFS support.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <rpc/xdr.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>

/*
 * Make sure that the definitions are consistent with nfs4_pnfs.h
 */
typedef enum layout_status {
	PLO_ROC = 	0x1,
	PLO_RETURN = 	0x02,
	PLO_GET = 	0x04,
	PLO_RECALL = 	0x08,
	PLO_BAD = 	0x10,
	PLO_UNAVAIL = 	0x20,
	PLO_COM2MDS = 	0x40,
	PLO_TRYLATER = 	0x80,
	R4LAYOUTVALID = 0x400000
} layout_status_t;

/*
 * Keep error codes consistent with nfs4_pnfs.h
 */
typedef enum nfsstat_layout_errcodes {
	ENOLAYOUT = 	-1,
	ENOTAFILE = 	-2,
	ENOPNFSSERV = 	-3,
	ESYSCALL = 	-4,
	ENONFS = 	-5,
	ETLI = 		-6,
	ENETCONF = 	-7,
	ENETADDR = 	-8,
	EADDRDEC = 	-9,
	EADDRTRAN = 	-10
} nfsstat_lo_errcodes_t;

typedef enum layoutiomode4 {
	LAYOUTIOMODE4_READ =	1,
	LAYOUTIOMODE4_RW =	2,
	LAYOUTIOMODE4_ANY = 	3
} layoutiomode4;

typedef struct netaddr4 {
	char *na_r_netid;
	char *na_r_addr;
} netaddr4;

typedef struct stripe_info {
	uint32_t stripe_index;
	struct {
		uint_t multipath_list_len;
		struct netaddr4 *multipath_list_val;
	} multipath_list;
} stripe_info_t;

typedef struct layoutspecs {
	uint32_t plo_stripe_count;
	uint32_t plo_stripe_unit;
	uint32_t plo_status;
	uint32_t iomode;
	offset4 plo_offset;
	length4 plo_length;
	int64_t plo_creation_sec;
	int64_t	plo_creation_musec;
	struct {
		uint_t plo_stripe_info_list_len;
		stripe_info_t *plo_stripe_info_list_val;
	} plo_stripe_info_list;
} layoutspecs_t;

typedef struct layoutstats {
	uint64_t proxy_iocount;
	uint64_t ds_iocount;
	struct {
		uint_t	total_layouts;
		layoutspecs_t	*lo_specs;
	} plo_data;
} layoutstats_t;


extern bool_t xdr_offset4(XDR *xdrs, offset4 *objp);
extern bool_t xdr_length4(XDR *xdrs, length4 *objp);
extern bool_t xdr_netaddr4(XDR* xdrs, netaddr4 *objp);
extern bool_t xdr_stripe_info_t(XDR *xdrs, stripe_info_t *objp);
extern bool_t xdr_layoutstats_t(XDR *xdrs, layoutstats_t *objp);
extern int lookup_name_port(netaddr4 *na, long *port,
    char *hostname, char *ipaddress);
extern int null_procedure_ping(char *hostname, char *netid,
    enum clnt_stat *ds_status);
#ifdef __cplusplus
}
#endif

#endif /* _NFSSTAT_LAYOUT_H */
