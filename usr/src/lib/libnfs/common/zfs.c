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

#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/param.h>

#include "libnfs_impl.h"

static int
zfs_iter_type_worker(zfs_handle_t *zhp, void *viter)
{
	libnfs_zfs_iter_data_t *iter = viter;
	int rc;

	rc = zfs_iter_children(zhp, zfs_iter_type_worker, viter);
	if (rc != 0) {
		zfs_close(zhp);
		return (rc);
	}

	if (zfs_get_type(zhp) == iter->lzid_type)
		return ((*iter->lzid_func)(zhp, iter->lzid_data));

	zfs_close(zhp);
	return (0);
}

int
libnfs_zfs_iter_type(libnfs_handle_t *handle, libnfs_zfs_iter_func_t func,
    zfs_type_t type, void *data)
{
	libnfs_zfs_iter_data_t iter;

	iter.lzid_type = type;
	iter.lzid_func = func;
	iter.lzid_data = data;

	return (zfs_iter_root(handle->lh_zfs_handle,
	    zfs_iter_type_worker, &iter));
}
