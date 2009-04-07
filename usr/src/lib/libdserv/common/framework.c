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

#include <stdio.h>
#include <string.h>
#include <libintl.h>
#include <syslog.h>
#include <stdarg.h>
#include <sys/param.h>

#include "libdserv_impl.h"

umem_cache_t *dserv_handle_cache = NULL;

void
dserv_log(dserv_handle_t *handle, int pri, const char *format, ...)
{
	va_list args;

	if ((handle == NULL) ||
	    (! (handle->dsh_flags & DSERV_DSH_FLAG_OSYSLOG))) {
		openlog("dserv", LOG_PID, LOG_DAEMON);
		if (handle != NULL)
			handle->dsh_flags |= DSERV_DSH_FLAG_OSYSLOG;
	}

	if (format == NULL) {
		if ((handle != NULL) && (dserv_error(handle) != DSERV_ERR_NONE))
			syslog(pri, "%s", dserv_strerror(handle));
		return;
	}

	va_start(args, format);
	vsyslog(pri, format, args);
	va_end(args);
}

dserv_handle_t *
dserv_handle_create()
{
	dserv_handle_t *rc;

	if (dserv_handle_cache == NULL)
		dserv_handle_cache = umem_cache_create("dserv_handle_cache",
		    sizeof (dserv_handle_t), 0,
		    NULL, NULL, NULL, NULL, NULL, 0);
	if (dserv_handle_cache == NULL) {
		dserv_log(NULL, LOG_ERR,
		    gettext("unable to create umem cache"));
		return (NULL);
	}
	rc = umem_cache_alloc(dserv_handle_cache, UMEM_NOFAIL);

	rc->dsh_flags = 0;

	rc->dsh_scf_handle = scf_handle_create(SCF_VERSION);
	scf_handle_bind(rc->dsh_scf_handle);
	rc->dsh_scf_service = scf_service_create(rc->dsh_scf_handle);
	if (scf_handle_decode_fmri(rc->dsh_scf_handle,
	    DSERV_SERVICE_FMRI, NULL, rc->dsh_scf_service,
	    NULL, NULL, NULL, 0) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			dserv_log(NULL, LOG_ERR,
			    gettext("dserv service (%s) not in repository"),
			    DSERV_SERVICE_FMRI);
		else
			dserv_log(NULL, LOG_ERR,
			    gettext("unable to parse fmri \"%s\": %s"),
			    DSERV_SERVICE_FMRI, scf_strerror(scf_error()));
		scf_service_destroy(rc->dsh_scf_service);
		scf_handle_destroy(rc->dsh_scf_handle);
		umem_cache_free(dserv_handle_cache, rc);
		return (NULL);
	}
	rc->dsh_scf_instance = NULL;
	rc->dsh_pg_storage = NULL;
	rc->dsh_pg_net = NULL;
	rc->dsh_iter_zpools = NULL;

	return (rc);
}

void
dserv_handle_destroy(dserv_handle_t *handle)
{
	if (handle == NULL)
		return;
	if (dserv_handle_cache == NULL)
		return;

	if (handle->dsh_scf_handle != NULL)
		scf_handle_destroy(handle->dsh_scf_handle);
	if (handle->dsh_scf_service != NULL)
		scf_service_destroy(handle->dsh_scf_service);
	if (handle->dsh_scf_instance != NULL)
		scf_instance_destroy(handle->dsh_scf_instance);
	if (handle->dsh_pg_storage != NULL)
		scf_pg_destroy(handle->dsh_pg_storage);
	if (handle->dsh_pg_net != NULL)
		scf_pg_destroy(handle->dsh_pg_net);
	if (handle->dsh_iter_zpools != NULL)
		scf_iter_destroy(handle->dsh_iter_zpools);

	umem_cache_free(dserv_handle_cache, handle);
}

dserv_error_t
dserv_error(dserv_handle_t *handle)
{
	return (handle->dsh_error);
}

void
dserv_error_reset(dserv_handle_t *handle)
{
	handle->dsh_error = DSERV_ERR_NONE;
	handle->dsh_errstring[0] = '\0';
}

const char *
dserv_strerror(dserv_handle_t *handle)
{
	switch (handle->dsh_error) {
	case DSERV_ERR_NONE:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("no error"), DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_SCF:
		snprintf(handle->dsh_errstring, DSERV_ERRBUF_SIZE,
		    "libscf: %s", scf_strerror(handle->dsh_scf_error));
		break;
	case DSERV_ERR_INVALID_PROP:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("invalid dserv property"), DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_NOINSTANCE:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("dserv instance undefined"), DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_HAVEINSTANCE:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("dserv instance should not be set"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_NOSUCHINSTANCE:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("no such dserv instance exists"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_LONGDATASET:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("dataset name too long"), DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_DUPLICATE_DATASET:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("duplicate dataset; already present in list"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_DATASET_NOT_FOUND:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("Dataset not present in list"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_MDS_EXISTS:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("only one mds can be stored at a time"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_MDS_NOT_FOUND:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("no mds to drop or remove"),
		    DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_DEVOPEN:
		(void) snprintf(handle->dsh_errstring, DSERV_ERRBUF_SIZE,
		    gettext("error opening dserv device: %s"),
		    strerror(handle->dsh_errno_error));
		break;
	case DSERV_ERR_DEVNOTOPEN:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("dserv device not opened"), DSERV_ERRBUF_SIZE);
		break;
	case DSERV_ERR_NFSSYS:
		(void) snprintf(handle->dsh_errstring, DSERV_ERRBUF_SIZE,
		    gettext("nfssys failed: %s"),
		    strerror(handle->dsh_errno_error));
		break;
	default:
		(void) strlcpy(handle->dsh_errstring,
		    gettext("unknown error"), DSERV_ERRBUF_SIZE);
		break;
	}

	return (handle->dsh_errstring);
}

void
dserv_set_pool_id(dserv_handle_t *handle, const int id)
{
	handle->dsh_svc_pool_id = id;
}

int
dserv_setinstance(dserv_handle_t *handle, const char *instname, int flags)
{
	scf_instance_t *inst = scf_instance_create(handle->dsh_scf_handle);

	if (handle->dsh_scf_instance != NULL) {
		scf_instance_destroy(handle->dsh_scf_instance);
		handle->dsh_scf_instance = NULL;
	}

	if (scf_service_get_instance(handle->dsh_scf_service, instname,
	    inst) == 0) {
		handle->dsh_scf_instance = inst;
		return (0);
	}
	if (! (flags & DSERV_INSTANCE_CREATE)) {
		handle->dsh_error = DSERV_ERR_NOSUCHINSTANCE;
		scf_instance_destroy(inst);
		return (-1);
	}
	if (scf_service_add_instance(handle->dsh_scf_service, instname,
	    inst) != 0) {
		handle->dsh_error = DSERV_ERR_SCF;
		handle->dsh_scf_error = scf_error();
		scf_instance_destroy(inst);
		return (-1);
	}

	handle->dsh_scf_instance = inst;

	return (0);
}

void
dserv_dropinstance(dserv_handle_t *handle)
{
	if (handle->dsh_scf_instance == NULL)
		return;

	scf_instance_destroy(handle->dsh_scf_instance);
	handle->dsh_scf_instance = NULL;
}

int
dserv_myinstance(dserv_handle_t *handle)
{
	scf_instance_t *inst = scf_instance_create(handle->dsh_scf_handle);
	char fmri[BUFSIZ];

	if (scf_myname(handle->dsh_scf_handle, fmri, sizeof (fmri)) == -1) {
		handle->dsh_error = DSERV_ERR_SCF;
		handle->dsh_scf_error = scf_error();
		scf_instance_destroy(inst);
		return (-1);
	}

	if (scf_handle_decode_fmri(handle->dsh_scf_handle, fmri,
	    NULL, NULL, inst, NULL, NULL, 0) == -1) {
		handle->dsh_error = DSERV_ERR_SCF;
		handle->dsh_scf_error = scf_error();
		scf_instance_destroy(inst);
		return (-1);
	}

	handle->dsh_scf_instance = inst;

	return (0);
}
