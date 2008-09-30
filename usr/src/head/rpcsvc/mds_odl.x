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

%#pragma ident	"@(#)mds_odl.x	1.1	08/06/18 SMI"


%#include <nfs/nfs4.h>
%#include <nfs/mds_odl.h> 

const MAX_MDS_SID = 16;

struct odl_sid {
       uint64_t		id;
       uint64_t		aun;
};

struct odl_t {
	uint32_t	start_idx;
	uint32_t	unit_size;
	uint64_t        offset;
	uint64_t        length;
	odl_sid         sid<MAX_MDS_SID>;       
};

enum odl_layout_type {
	PNFS = 0,
	LUSTRE = 1
};

enum odl_pnfs_lo_vers {
     VERS_1 = 1
};

union odl_lo switch (odl_pnfs_lo_vers odl_vers) {
case VERS_1:
	odl_t odl_content<>;
default:
	void;
};

union odl switch (odl_layout_type odl_type) {
case PNFS:
	odl_lo	odl_pnfs;
default:
	void;
};

