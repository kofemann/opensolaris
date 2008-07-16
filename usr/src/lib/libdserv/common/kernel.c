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

#include "libdserv_impl.h"
#include <sys/param.h>
#include <sys/dserv.h>

int
dserv_kmod_open(dserv_handle_t *handle)
{
	int rc = 0;

	handle->dsh_dev_fd = open(DSERV_DEV_PATH, O_RDWR);
	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVOPEN;
		handle->dsh_errno_error = errno;
		rc = -1;
	}

	return (rc);
}

int
dserv_kmod_regpool(dserv_handle_t *handle, const char *datasetname)
{
	dserv_dataset_info_t kinfo;
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	if (strlcpy(kinfo.dataset_name, datasetname,
	    sizeof (kinfo.dataset_name)) >=
	    sizeof (kinfo.dataset_name)) {
		handle->dsh_error = DSERV_ERR_LONGDATASET;
		return (-1);
	}

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_DATASET_INFO, &kinfo);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_setmds(dserv_handle_t *handle, dserv_setmds_args_t *args)
{
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_SETMDS, args);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_svc(dserv_handle_t *handle, dserv_svc_args_t *args)
{
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	args->poolid = handle->dsh_svc_pool_id;

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_SVC, args);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_setport(dserv_handle_t *handle, dserv_setport_args_t *args)
{
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_SETPORT, args);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_reportavail(dserv_handle_t *handle)
{
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_REPORTAVAIL, NULL);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}

int
dserv_kmod_instance_shutdown(dserv_handle_t *handle)
{
	int ioc;

	if (handle->dsh_dev_fd < 0) {
		handle->dsh_error = DSERV_ERR_DEVNOTOPEN;
		return (-1);
	}

	ioc = ioctl(handle->dsh_dev_fd, DSERV_IOC_INSTANCE_SHUTDOWN, NULL);
	if (ioc < 0) {
		handle->dsh_error = DSERV_ERR_IOCTL;
		handle->dsh_errno_error = errno;
		return (-1);
	}

	return (0);
}
