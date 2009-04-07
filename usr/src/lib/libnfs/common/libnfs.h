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

#ifndef	_LIBNFS_H
#define	_LIBNFS_H

#include <libscf.h>
#include <syslog.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	LIBNFS_VERSION = 1
} libnfs_version_t;

typedef enum {
	LIBNFS_ERR_NONE = 0,
	LIBNFS_ERR_SCF,
	LIBNFS_ERR_NOTPROP,
	LIBNFS_ERR_INVALID_ERRMODE,
	LIBNFS_ERR_ILLEGAL_ERRMODE,
	LIBNFS_ERR_NOTRY,
	LIBNFS_ERR_DSERV_LONGDATASET,
	LIBNFS_ERR_DSERV_LONGMDSINFO,
	LIBNFS_ERR_DSERV_DATASET_PROPS,
	LIBNFS_ERR_LAST /* must be last */
} libnfs_error_t;

typedef struct libnfs_handle libnfs_handle_t;

typedef enum {
	LIBNFS_PROP_SERVER_MAX_CONNECTIONS,
	LIBNFS_PROP_SERVER_LISTEN_BACKLOG,
	LIBNFS_PROP_SERVER_PROTOCOL,
	LIBNFS_PROP_SERVER_DEVICE,
	LIBNFS_PROP_SERVER_SERVERS,
	LIBNFS_PROP_SERVER_VERSMIN,
	LIBNFS_PROP_SERVER_VERSMAX,
	LIBNFS_PROP_SERVER_DELEGATION
} libnfs_propid_t;

typedef enum {
	LIBNFS_ERRMODE_NORMAL,
	LIBNFS_ERRMODE_LOG,
	LIBNFS_ERRMODE_DIE
} libnfs_error_mode_t;

void libnfs_log(libnfs_handle_t *, int, const char *, ...);
libnfs_handle_t *libnfs_handle_create(libnfs_version_t);
void libnfs_handle_destroy(libnfs_handle_t *);
int libnfs_myinstance(libnfs_handle_t *);
libnfs_error_t libnfs_error(libnfs_handle_t *);
void libnfs_error_reset(libnfs_handle_t *);
libnfs_error_mode_t libnfs_error_mode(libnfs_handle_t *);
int libnfs_error_mode_set(libnfs_handle_t *, libnfs_error_mode_t);
const char *libnfs_strerror(libnfs_handle_t *);
char *libnfs_strdup(libnfs_handle_t *, const char *);
void libnfs_free(libnfs_handle_t *, void *);

int32_t libnfs_prop_num(libnfs_handle_t *, libnfs_propid_t);
char *libnfs_prop_string(libnfs_handle_t *, libnfs_propid_t);
uint32_t libnfs_prop_boolean(libnfs_handle_t *, libnfs_propid_t);

int libnfs_dserv_open(libnfs_handle_t *);
int libnfs_dserv_push_dataset(libnfs_handle_t *, const char *,
    const char *, const char *);
int libnfs_dserv_push_inst_datasets(libnfs_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNFS_H */
