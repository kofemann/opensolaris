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

#ifndef	_LIBDSERV_H
#define	_LIBDSERV_H

#include <libscf.h>
#include <syslog.h>
#include <rpc/rpc.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSERV_PROP_ZPOOLS	"zpools"
#define	DSERV_PROP_MDS		"mds"

typedef enum {
	DSERV_ERR_NONE = 0,
	DSERV_ERR_SCF,
	DSERV_ERR_INVALID_PROP,
	DSERV_ERR_NOINSTANCE,
	DSERV_ERR_HAVEINSTANCE,
	DSERV_ERR_NOSUCHINSTANCE,
	DSERV_ERR_LONGDATASET,
	DSERV_ERR_DUPLICATE_DATASET,
	DSERV_ERR_DATASET_NOT_FOUND,
	DSERV_ERR_MDS_EXISTS,
	DSERV_ERR_MDS_NOT_FOUND,
	DSERV_ERR_DEVOPEN,
	DSERV_ERR_DEVNOTOPEN,
	DSERV_ERR_NFSSYS
} dserv_error_t;

#define	DSERV_INSTANCE_CREATE 0x01

#define	DSERV_DEFAULT_INSTANCE	"default"

typedef struct dserv_handle dserv_handle_t;

void dserv_log(dserv_handle_t *, int, const char *, ...);
dserv_handle_t *dserv_handle_create(void);
void dserv_handle_destroy(dserv_handle_t *);
int dserv_setinstance(dserv_handle_t *, const char *, int);
void dserv_dropinstance(dserv_handle_t *);
int dserv_myinstance(dserv_handle_t *);
dserv_error_t dserv_error(dserv_handle_t *);
void dserv_error_reset(dserv_handle_t *);
const char *dserv_strerror(dserv_handle_t *);
int dserv_enable(dserv_handle_t *);
int dserv_disable(dserv_handle_t *);
int dserv_maintenance(dserv_handle_t *);
int dserv_refresh(dserv_handle_t *);
int dserv_create_instance(dserv_handle_t *, const char *);
int dserv_destroy_instance(dserv_handle_t *, const char *);
void dserv_set_pool_id(dserv_handle_t *, const int);
int dserv_addprop(dserv_handle_t *, const char *, const char *);
int dserv_dropprop(dserv_handle_t *, const char *, const char *);
char *dserv_firstpool(dserv_handle_t *);
char *dserv_nextpool(dserv_handle_t *);
char *dserv_getmds(dserv_handle_t *);

int dserv_kmod_regpool(dserv_handle_t *, const char *);
int dserv_kmod_setmds(dserv_handle_t *, dserv_setmds_args_t *);
int dserv_kmod_svc(dserv_handle_t *, dserv_svc_args_t *);
int dserv_kmod_setport(dserv_handle_t *, dserv_setport_args_t *);
int dserv_kmod_reportavail(dserv_handle_t *);
int dserv_kmod_instance_shutdown(dserv_handle_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDSERV_H */
