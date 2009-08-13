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

%#ifdef _KERNEL
%#include <nfs/nfs4_kprot.h>
%#else
%#include <rpc/types.h>
%#include <rpc/xdr.h>
%#include <rpcsvc/nfs4_prot.h>
%#endif

%#include <nfs/spe_prot.h>

/*
%#ifndef _KERNEL
typedef opaque		utf8string<>;
typedef uint32_t	count4;
%#endif
*/

struct spe_stringlist {
	utf8string		ss_name;
	struct spe_stringlist	*next;
};

struct  spe_npool {
	utf8string		sn_name;
	spe_stringlist		*sn_dses;
	struct spe_npool	*next;
};

enum spe_attributes {
	SPE_ATTR_BASE,
	SPE_ATTR_DAY,
	SPE_ATTR_DOMAIN,
	SPE_ATTR_EXTENSION,
	SPE_ATTR_FILE,
	SPE_ATTR_FQDN,
	SPE_ATTR_GID,
	SPE_ATTR_GROUP,
	SPE_ATTR_HOST,
	SPE_ATTR_HOUR,
	SPE_ATTR_IP,
	SPE_ATTR_PATH,
	SPE_ATTR_SUBNET,
	SPE_ATTR_UID,
	SPE_ATTR_USER,
	SPE_ATTR_WEEKDAY
};

enum spe_operators {
	SPE_OP_AND,
	SPE_OP_OR,
	SPE_OP_NOT,
	SPE_OP_EQUAL,
	SPE_OP_NOT_EQUAL
};

enum spe_type {
	SPE_DATA_ADDR,
	SPE_DATA_GID,
	SPE_DATA_INT,
	SPE_DATA_NETNAME,
	SPE_DATA_NETWORK,
	SPE_DATA_STRING,
	SPE_DATA_UID
};

/*
 * If NETNAME, then we use spe_netname.
 * Else, we use spe_network.
 */
struct spe_network {
	char		*sn_name;
	uint32_t	sn_addr;
	uint32_t	sn_mask;
};

union spe_data switch (spe_type sd_type) {
	case SPE_DATA_UID:
		uid_t			uid;
	case SPE_DATA_GID:
		gid_t			gid;
	case SPE_DATA_INT:
		int			i;
	case SPE_DATA_NETNAME:
	case SPE_DATA_STRING:
		string			sz<MAXPATHLEN>;
	case SPE_DATA_ADDR:
	case SPE_DATA_NETWORK:
		spe_network	net;
};

union spe_thunk switch (bool st_is_interior) {
	case FALSE:
		struct spe_leaf		*leaf;
	case TRUE:
		struct spe_interior	*interior;
};

struct spe_leaf {
	bool		sl_is_attr;
	spe_attributes	sl_attr;
	spe_data	sl_data;
};

struct spe_interior {
	spe_operators	si_op;
	bool		si_parens;
	spe_thunk	si_branches<>;
};

struct spe_policy {
	uint32_t		sp_id;
	count4			sp_stripe_count;
	uint32_t		sp_interlace;
	spe_interior		*sp_attr_expr;
	char			*sp_name;
	spe_npool		*sp_npools;
	struct spe_policy	*next;
};

/*
 * Program number is in the transient range since it never
 * goes across the wire...
 */
program NFS4_SPE {
	version	NFS4_SPE_V1 {
		void
		SPETRANSFER(void) = 0;
	} = 1;
} = 0x40000010;
