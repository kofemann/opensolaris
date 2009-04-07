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

#include "libnfs_impl.h"
#include <nfs/nfssys.h>

extern int _nfssys(enum nfssys_op, void *);

int
libnfs_dserv_push_dataset(libnfs_handle_t *handle, const char *dataset,
    const char *netid, const char *uaddr)
{
	dserv_dataset_props_t kprops;
	int ioc;

	if (strlcpy(kprops.ddp_name, dataset,
	    sizeof (kprops.ddp_name)) >=
	    sizeof (kprops.ddp_name)) {
		libnfs_error_set(handle, LIBNFS_ERR_DSERV_LONGDATASET);
		return (-1);
	}
	if (strlcpy(kprops.ddp_mds_netid, netid,
	    sizeof (kprops.ddp_mds_netid)) >=
	    sizeof (kprops.ddp_mds_netid)) {
		libnfs_error_set(handle, LIBNFS_ERR_DSERV_LONGMDSINFO);
		return (-1);
	}
	if (strlcpy(kprops.ddp_mds_uaddr, uaddr,
	    sizeof (kprops.ddp_mds_uaddr)) >=
	    sizeof (kprops.ddp_mds_uaddr)) {
		libnfs_error_set(handle, LIBNFS_ERR_DSERV_LONGMDSINFO);
		return (-1);
	}

	if (_nfssys(DSERV_DATASET_PROPS, &kprops) < 0) {
		libnfs_error_set(handle, LIBNFS_ERR_DSERV_DATASET_PROPS);
		handle->lh_errno_error = errno;
		return (-1);
	}

	return (0);
}

static int
libnfs_dserv_push_one_dataset(zfs_handle_t *zhp, void *vhandle)
{
	libnfs_handle_t *handle = vhandle;
	char mdsprop[256];
	int rc;

	rc = zfs_prop_get(zhp, ZFS_PROP_MDS, mdsprop, sizeof (mdsprop),
	    NULL, NULL, 0, B_FALSE);
	if (rc != 0)
		goto out;

	rc = libnfs_dserv_push_dataset(handle, zfs_get_name(zhp),
	    "tcp", mdsprop);

out:
	zfs_close(zhp);

	return (rc);
}

int
libnfs_dserv_push_inst_datasets(libnfs_handle_t *handle)
{
	libnfs_error_reset(handle);

	return (libnfs_zfs_iter_type(handle, libnfs_dserv_push_one_dataset,
	    ZFS_TYPE_PNFS, handle));
}
