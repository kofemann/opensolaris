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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "libdserv_impl.h"
#include <stdio.h>

static int
dserv_manipulate_instance(dserv_handle_t *handle,
    int (*smf_func)(const char *, int))
{
	char fmri[BUFSIZ];

	if (handle->dsh_scf_instance == NULL) {
		handle->dsh_error = DSERV_ERR_NOINSTANCE;
		return (-1);
	}
	if (scf_instance_to_fmri(handle->dsh_scf_instance, fmri,
	    sizeof (fmri)) == -1) {
		handle->dsh_error = DSERV_ERR_SCF;
		handle->dsh_scf_error = scf_error();
		return (-1);
	}
	if (smf_func(fmri, 0) != 0) {
		handle->dsh_error = DSERV_ERR_SCF;
		handle->dsh_scf_error = scf_error();
		return (-1);
	}

	return (0);
}

int
dserv_enable(dserv_handle_t *handle)
{
	return (dserv_manipulate_instance(handle, smf_enable_instance));
}

int
dserv_disable(dserv_handle_t *handle)
{
	return (dserv_manipulate_instance(handle, smf_disable_instance));
}

int
dserv_maintenance(dserv_handle_t *handle)
{
	return (dserv_manipulate_instance(handle, smf_maintain_instance));
}

/*ARGSUSED*/
static int
dserv_refresh_instance(const char *thing, int foo)
{
	return (smf_refresh_instance(thing));
}

int
dserv_refresh(dserv_handle_t *handle)
{
	return (dserv_manipulate_instance(handle, dserv_refresh_instance));
}

int
dserv_create_instance(dserv_handle_t *handle, const char *name)
{
	scf_instance_t *inst;

	if (handle->dsh_scf_instance != NULL) {
		handle->dsh_error = DSERV_ERR_HAVEINSTANCE;
		return (-1);
	}

	inst = scf_instance_create(handle->dsh_scf_handle);
	if (inst == NULL) {
		handle->dsh_scf_error = scf_error();
		handle->dsh_error = DSERV_ERR_SCF;
		return (-1);
	}

	if (scf_service_add_instance(handle->dsh_scf_service,
	    name, inst) != 0) {
		handle->dsh_scf_error = scf_error();
		handle->dsh_error = DSERV_ERR_SCF;
		scf_instance_destroy(inst);
		return (-1);
	}

	scf_instance_destroy(inst);

	return (0);
}

int
dserv_destroy_instance(dserv_handle_t *handle, const char *name)
{
	scf_instance_t *inst;

	if (handle->dsh_scf_instance != NULL) {
		handle->dsh_error = DSERV_ERR_HAVEINSTANCE;
		return (-1);
	}

	inst = scf_instance_create(handle->dsh_scf_handle);
	if (inst == NULL) {
		handle->dsh_scf_error = scf_error();
		handle->dsh_error = DSERV_ERR_SCF;
		return (-1);
	}

	if ((scf_service_get_instance(handle->dsh_scf_service,
	    name, inst) != 0) ||
	    (scf_instance_delete(inst) != 0)) {
		handle->dsh_scf_error = scf_error();
		handle->dsh_error = DSERV_ERR_SCF;
		scf_instance_destroy(inst);
		return (-1);
	}

	scf_instance_destroy(inst);

	return (0);
}
