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

#if defined(USE_FOR_SNOOP)
%#include "ds_nfs_com.h"
#else
#if defined(RPC_XDR) || defined(RPC_SVC) || defined(RPC_CLNT)
%#include <nfs/ds.h>
#endif
#endif

/*
 *  Dot-x file for common parts of NFS41 pcol and data
 *  server control protocol.
 */

#ifdef USE_FOR_SNOOP

struct netaddr4 {
	string na_r_netid<>;	/* network id */
	string na_r_addr<>;	/* universal address */
};

const NFS4_FHSIZE		= 128;
typedef opaque		nfs_fh4<NFS4_FHSIZE>;

typedef opaque		utf8string<>;
typedef utf8string	utf8str_cs;
typedef utf8str_cs	component4;

/*
 * File access handle
 */

typedef uint64_t	offset4;
typedef uint32_t	count4;
typedef	uint64_t	length4;
typedef uint64_t	clientid4;


struct stateid4 {
	uint32_t	seqid;
	opaque		other[12];
};

/*
 * FSID structure for major/minor
 */
struct fsid4 {
	uint64_t	major;
	uint64_t	minor;
};

/*
 * From RFC 2203
 */
enum rpc_gss_svc_t {
	RPC_GSS_SVC_NONE	= 1,
	RPC_GSS_SVC_INTEGRITY	= 2,
	RPC_GSS_SVC_PRIVACY	= 3
};

typedef opaque		sec_oid4<>;
#endif

typedef uint32_t	qop4;

struct rpcsec_gss_info {
	sec_oid4	oid;
	qop4		qop;
	rpc_gss_svc_t	service;
};

/*
 * WRITE: Write to file
 */
enum stable_how4 {
	UNSTABLE4	= 0,
	DATA_SYNC4	= 1,
	FILE_SYNC4	= 2
};

#ifdef USE_FOR_SNOOP

const NFS4_OPAQUE_LIMIT = 1024;
const NFS4_VERIFIER_SIZE = 8; 
typedef opaque verifier4[NFS4_VERIFIER_SIZE];

/*
 * NFSv4.1 Client Owner (aka long hand client ID)
 */
struct client_owner4 {
	verifier4       co_verifier;
	opaque          co_ownerid<NFS4_OPAQUE_LIMIT>;
};

/*
 * data structures new to NFSv4.1
 */
enum layouttype4 {
	LAYOUT4_NFSV4_1_FILES  = 0x1,
	LAYOUT4_OSD2_OBJECTS   = 0x2,
	LAYOUT4_BLOCK_VOLUME   = 0x3
};

struct layout_content4 {
        layouttype4 loc_type;
        opaque      loc_body<>;
};

struct layouthint4 {
	layouttype4		loh_type;
	opaque			loh_body<>;
};

enum layoutiomode4 {
	LAYOUTIOMODE4_READ	= 1,
	LAYOUTIOMODE4_RW	= 2,
	LAYOUTIOMODE4_ANY	= 3
};

struct layout4 {
	offset4			lo_offset;
	length4			lo_length;
	layoutiomode4		lo_iomode;
	layout_content4		lo_content;
};
#endif
