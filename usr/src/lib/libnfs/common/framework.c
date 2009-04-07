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

#include "libnfs_impl.h"

umem_cache_t *libnfs_handle_cache = NULL;

/*
 * Log function with printf()-like formatting.  If you have a handle,
 * pass it in as the first argument; if not, just pass in NULL.
 */

void
libnfs_log(libnfs_handle_t *handle, int pri, const char *format, ...)
{
	va_list args;

	if ((handle == NULL) ||
	    (! (handle->lh_flags & LIBNFS_LH_FLAG_OSYSLOG))) {
		openlog("libnfs", LOG_PID, LOG_DAEMON);
		if (handle != NULL)
			handle->lh_flags |= LIBNFS_LH_FLAG_OSYSLOG;
	}

	if (format == NULL) {
		if ((handle != NULL) &&
		    (libnfs_error(handle) != LIBNFS_ERR_NONE))
			syslog(pri, "%s", libnfs_strerror(handle));
		return;
	}

	va_start(args, format);
	vsyslog(pri, format, args);
	va_end(args);
}

/*
 * This function may be called by a multi-threaded program.  It should
 * be called before the first libnfs_handle_create() is called.  It
 * should be called only once, preferably before the first thread is
 * created.
 *
 * Its purpose is to prevent the race condition of several threads
 * calling libnfs_handle_create() at once, and multiple threads creating
 * the umem cache libnfs_handle_cache.
 *
 * This routine may be ignored by programs that are single-threaded, or
 * programs that are reasonably sure that there is no race to be the
 * first caller to libnfs_handle_create.
 */

void
libnfs_mt_preinit(void)
{
	if (libnfs_handle_cache == NULL)
		libnfs_handle_cache = umem_cache_create("libnfs_handle_cache",
		    sizeof (libnfs_handle_t), 0,
		    NULL, NULL, NULL, NULL, NULL, 0);
	if (libnfs_handle_cache == NULL)
		libnfs_log(NULL, LOG_ERR,
		    gettext("unable to create umem cache"));
}

/*
 * Creates a new handle, to be used as the first argument in most libnfs
 * functions.  Each thread of execution using libnfs should have its own
 * handle.
 */

libnfs_handle_t *
libnfs_handle_create(libnfs_version_t version)
{
	libnfs_handle_t *rc;

	if (version != LIBNFS_VERSION)
		libnfs_log(NULL, LOG_WARNING,
		    gettext("libnfs version mismatch: %d should be %d"),
		    version, LIBNFS_VERSION);
	if (libnfs_handle_cache == NULL)
		libnfs_mt_preinit();
	if (libnfs_handle_cache == NULL)
		return (NULL);
	rc = umem_cache_alloc(libnfs_handle_cache, UMEM_NOFAIL);

	rc->lh_flags = 0;

	rc->lh_scf_handle = scf_handle_create(SCF_VERSION);
	scf_handle_bind(rc->lh_scf_handle);
	rc->lh_scf_service = NULL;
	rc->lh_scf_instance = NULL;

	rc->lh_zfs_handle = libzfs_init();

	return (rc);
}

/*
 * Each allocated handle should be destroyed.
 */

void
libnfs_handle_destroy(libnfs_handle_t *handle)
{
	if (handle == NULL)
		return;
	if (libnfs_handle_cache == NULL)
		return;

	if (handle->lh_scf_instance != NULL)
		scf_instance_destroy(handle->lh_scf_instance);
	if (handle->lh_scf_service != NULL)
		scf_service_destroy(handle->lh_scf_service);
	if (handle->lh_scf_handle != NULL)
		scf_handle_destroy(handle->lh_scf_handle);
	if (handle->lh_flags & LIBNFS_LH_FLAG_DEFOPEN)
		(void) defopen(NULL);

	if (handle->lh_zfs_handle != NULL)
		libzfs_fini(handle->lh_zfs_handle);

	umem_cache_free(libnfs_handle_cache, handle);
}

/*
 * Return numeric error code for most recent libnfs call.  Errors are
 * defined in libnfs.h.
 */

libnfs_error_t
libnfs_error(libnfs_handle_t *handle)
{
	return (handle->lh_error);
}

/*
 * Set (report) an error.  This function is internally called only.
 */

void
libnfs_error_set(libnfs_handle_t *handle, libnfs_error_t error)
{
	handle->lh_error = error;

	switch (handle->lh_error_mode) {
	case LIBNFS_ERRMODE_LOG:
		libnfs_log(handle, LOG_WARNING, NULL);
		break;
	case LIBNFS_ERRMODE_DIE:
		libnfs_log(handle, LOG_WARNING, NULL);
		abort();
		break; /* not reached... */
	}
}

/*
 * Reset the error code for this handle.  Clients do not usually need to
 * call this, but it is available if they do.
 */

void
libnfs_error_reset(libnfs_handle_t *handle)
{
	handle->lh_error = LIBNFS_ERR_NONE;
	handle->lh_errstring[0] = '\0';
}

/*
 * Query the current error handling mode for the given handle.
 */

libnfs_error_mode_t
libnfs_error_mode(libnfs_handle_t *handle)
{
	return (handle->lh_error_mode);
}

/*
 * Set the error mode for the given handle.  Some types, e.g.
 * LIBNFS_ERRMODE_TRY, cannot be set this way; in the case
 * of LIBNFS_ERRMODE_TRY, use libnfs_error_try().
 *
 * Returns 0 if success, nonzero if failure, with error set in
 * the usual way.
 */

int
libnfs_error_mode_set(libnfs_handle_t *handle, libnfs_error_mode_t mode)
{
	switch (mode) {
	case LIBNFS_ERRMODE_NORMAL:
	case LIBNFS_ERRMODE_LOG:
	case LIBNFS_ERRMODE_DIE:
		break;
	default:
		libnfs_error_set(handle, LIBNFS_ERR_INVALID_ERRMODE);
		return (-1);
	}

	handle->lh_error_mode = mode;
	return (0);
}

/*
 * Return a string representing the error for the given handle.
 */

const char *
libnfs_strerror(libnfs_handle_t *handle)
{
	switch (handle->lh_error) {
	case LIBNFS_ERR_NONE:
		(void) strlcpy(handle->lh_errstring,
		    gettext("no error"), LIBNFS_ERRBUF_SIZE);
		break;
	case LIBNFS_ERR_SCF:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    "libscf: %s", scf_strerror(handle->lh_scf_error));
		break;
	case LIBNFS_ERR_NOTPROP:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("invalid libnfs property"));
		break;
	case LIBNFS_ERR_INVALID_ERRMODE:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("invalid libnfs error mode"));
		break;
	case LIBNFS_ERR_ILLEGAL_ERRMODE:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("illegal libnfs error mode"));
		break;
	case LIBNFS_ERR_NOTRY:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("getcontext() failure; try block unreachable"));
		break;
	case LIBNFS_ERR_DSERV_LONGDATASET:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("dataset name too long"));
		break;
	case LIBNFS_ERR_DSERV_LONGMDSINFO:
		snprintf(handle->lh_errstring, LIBNFS_ERRBUF_SIZE,
		    gettext("MDS info too long"));
		break;
	default:
		(void) strlcpy(handle->lh_errstring,
		    gettext("unknown error"), LIBNFS_ERRBUF_SIZE);
		break;
	}

	return (handle->lh_errstring);
}

void *
libnfs_alloc(libnfs_handle_t *handle, uint32_t size)
{
	return (umem_alloc(size, UMEM_NOFAIL));
}

char *
libnfs_strdup(libnfs_handle_t *handle, const char *str)
{
	uint32_t l;
	char *rc;

	l = strlen(str) + 1;
	rc = libnfs_alloc(handle, l);
	(void) memcpy(rc, str, l);
	return (rc);
}

void
libnfs_strfree(libnfs_handle_t *handle, void *ptr)
{
	umem_free(ptr, strlen(ptr) + 1);
}

/*
 * Alter the handle to focus on the SMF instance for the current executable.
 * Error if called from a program that is not under SMF control.
 */

int
libnfs_myinstance(libnfs_handle_t *handle)
{
	scf_instance_t *inst = scf_instance_create(handle->lh_scf_handle);
	char fmri[BUFSIZ];

	if (scf_myname(handle->lh_scf_handle, fmri, sizeof (fmri)) == -1) {
		handle->lh_scf_error = scf_error();
		scf_instance_destroy(inst);
		libnfs_error_set(handle, LIBNFS_ERR_SCF);
		return (-1);
	}

	if (scf_handle_decode_fmri(handle->lh_scf_handle, fmri,
	    NULL, NULL, inst, NULL, NULL, 0) == -1) {
		handle->lh_scf_error = scf_error();
		scf_instance_destroy(inst);
		libnfs_error_set(handle, LIBNFS_ERR_SCF);
		return (-1);
	}

	handle->lh_scf_instance = inst;

	return (0);
}
