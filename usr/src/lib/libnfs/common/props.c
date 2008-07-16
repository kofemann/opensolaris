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

/*
 * Properties: reading, setting, etc.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>

#include "libnfs_impl.h"

static void
props_defopen(libnfs_handle_t *handle)
{
	if (handle->lh_flags & LIBNFS_LH_FLAG_DEFOPEN)
		return;
	defopen(NULL);
	if (defopen(LIBNFS_PATH_ETC_DEFAULT) != 0)
		return;

	handle->lh_flags |= LIBNFS_LH_FLAG_DEFOPEN;
}

static int32_t
props_defread_int(libnfs_handle_t *handle,
    char *propname, uint32_t default_val)
{
	int32_t rc = default_val;
	int32_t raw;
	char *strval;

	props_defopen(handle);
	strval = defread(propname);
	if (strval == NULL)
		return (rc);
	errno = 0;
	raw = strtol(strval, NULL, 10);
	if (errno == 0)
		rc = raw;

	return (rc);
}

typedef struct {
	libnfs_propid_t pid;
	int32_t dflt;
	char *key;
} prop_num_etc_default_t;
prop_num_etc_default_t prop_num_etc_defaults[] = {
	{LIBNFS_PROP_SERVER_MAX_CONNECTIONS,
	    -1, "NFSD_MAX_CONNECTIONS="},
	{LIBNFS_PROP_SERVER_LISTEN_BACKLOG,
	    32, "NFSD_LISTEN_BACKLOG="},
	{LIBNFS_PROP_SERVER_SERVERS,
	    1, "NFSD_SERVERS="},
	{LIBNFS_PROP_SERVER_VERSMIN,
	    NFS_VERSMIN_DEFAULT, "NFS_SERVER_VERSMIN="},
	{LIBNFS_PROP_SERVER_VERSMAX,
	    NFS_VERSMAX_DEFAULT, "NFS_SERVER_VERSMAX="},
	{-1}
};

/*
 * Give a numeric value for a given property.  If an error occurs, returns
 * -1.  However, since -1 may be a valid value for the given property,
 * the caller must subsequently check libnfs_error() if -1 is seen.
 */

int32_t
libnfs_prop_num(libnfs_handle_t *handle, libnfs_propid_t prop)
{
	prop_num_etc_default_t *d;

	libnfs_error_reset(handle);

	for (d = prop_num_etc_defaults; d->pid != -1; d++)
		if (prop == d->pid)
			return (props_defread_int(handle, d->key, d->dflt));

	libnfs_error_set(handle, LIBNFS_ERR_NOTPROP);
	return (-1);
}

typedef struct {
	libnfs_propid_t pid;
	char *dflt;
	char *key;
} prop_string_etc_default_t;
prop_string_etc_default_t prop_string_etc_defaults[] = {
	{LIBNFS_PROP_SERVER_PROTOCOL,
	    "ALL", "NFSD_PROTOCOL_ALL="},
	{LIBNFS_PROP_SERVER_DEVICE,
	    "ALL", "NFSD_DEVICE="},
	{-1}
};

char *
libnfs_prop_string(libnfs_handle_t *handle, libnfs_propid_t prop)
{
	prop_string_etc_default_t *d;

	libnfs_error_reset(handle);

	for (d = prop_string_etc_defaults; d->pid != -1; d++)
		if (prop == d->pid)
			break;
	if (d->pid != -1) {
		props_defopen(handle);
		char *rc = defread(d->key);
		if (rc != NULL)
			return (libnfs_strdup(handle, rc));
		return (libnfs_strdup(handle, d->dflt));
	}

	libnfs_error_set(handle, LIBNFS_ERR_NOTPROP);
	return (NULL);
}

typedef struct {
	libnfs_propid_t pid;
	uint32_t dflt;
	char *trueval;
	char *falseval;
	char *key;
} prop_boolean_etc_default_t;
prop_boolean_etc_default_t prop_boolean_etc_defaults[] = {
	{LIBNFS_PROP_SERVER_DELEGATION,
	    1, "on", "off", "NFS_SERVER_DELEGATION="},
	{-1}
};

uint32_t
libnfs_prop_boolean(libnfs_handle_t *handle, libnfs_propid_t prop)
{
	prop_boolean_etc_default_t *d;

	libnfs_error_reset(handle);

	for (d = prop_boolean_etc_defaults; d->pid != -1; d++)
		if (prop == d->pid)
			break;
	if (d->pid != -1) {
		props_defopen(handle);
		char *rc = defread(d->key);
		if (rc == NULL)
			return (d->dflt);
		if (strcmp(rc, d->trueval) == 0)
			return (1);
		if (strcmp(rc, d->falseval) == 0)
			return (0);
		return (d->dflt);
	}

	libnfs_error_set(handle, LIBNFS_ERR_NOTPROP);
	return (NULL);
}
