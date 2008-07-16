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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/zfs_context.h>

/*ARGSUSED*/
void
zfs_pnfs_create_cb(objset_t *os, void *arg, cred_t *cr, dmu_tx_t *tx)
{
	int error = 0;

	/*
	 * Create the DMU object which will hold all the metadata
	 * about this pNFS dataset.  For now it only contains all MDS
	 * Storage IDs that pertain to this dataset.  A MDS Storage ID
	 * is a unique identifier which specifies the MDS zpool
	 * which contains the metadata for this dataset.
	 */
	/* Can we assume we will always get Object ID 1? */
	error = dmu_object_claim(os, DMU_PNFS_METADATA_OBJECT,
	    DMU_OT_PNFS_DATA, 0, DMU_OT_NONE, 0, tx);

	ASSERT(error == 0);
}
