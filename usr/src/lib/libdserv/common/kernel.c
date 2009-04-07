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

#include "libdserv_impl.h"
#include <sys/param.h>
#include <nfs/nfssys.h>

extern int _nfssys(enum nfssys_op, void *);

int
dserv_kmod_regpool(dserv_handle_t *handle, const char *datasetname)
{
	dserv_dataset_info_t kinfo;
	int err;

	if (strlcpy(kinfo.dataset_name, datasetname,
	    sizeof (kinfo.dataset_name)) >=
	    sizeof (kinfo.dataset_name)) {
		handle->dsh_error = DSERV_ERR_LONGDATASET;
		return (-1);
	}

	err = _nfssys(DSERV_DATASET_INFO, &kinfo);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}


int
dserv_kmod_setmds(dserv_handle_t *handle, dserv_setmds_args_t *args)
{
	int err;

	err = _nfssys(DSERV_SETMDS, args);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_svc(dserv_handle_t *handle, dserv_svc_args_t *args)
{
	int err;

	args->poolid = handle->dsh_svc_pool_id;

	err = _nfssys(DSERV_SVC, args);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_setport(dserv_handle_t *handle, dserv_setport_args_t *args)
{
	int err;

	err = _nfssys(DSERV_SETPORT, args);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_reportavail(dserv_handle_t *handle)
{
	int err;

	err = _nfssys(DSERV_REPORTAVAIL, NULL);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_instance_shutdown(dserv_handle_t *handle)
{
	int err;

	err = _nfssys(DSERV_INSTANCE_SHUTDOWN, NULL);
	if (err < 0) {
		handle->dsh_error = DSERV_ERR_NFSSYS;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}
