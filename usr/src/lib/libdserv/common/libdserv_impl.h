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

#ifndef	_LIBDSERV_IMPL_H
#define	_LIBDSERV_IMPL_H

#include <umem.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libuutil.h>
#include <sys/param.h>

#include <nfs/nfs4.h>
#include <libdserv.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	DSERV_SERVICE_FMRI	"svc:/network/dserv"
#define	DSERV_ERRBUF_SIZE	(1024)
#define	DSERV_ASTRING_SIZE	(1024)

struct dserv_handle {
	uint32_t dsh_flags;
	dserv_error_t dsh_error;
	int dsh_errno_error;
	scf_error_t dsh_scf_error;
	scf_handle_t *dsh_scf_handle;
	scf_service_t *dsh_scf_service;
	scf_instance_t *dsh_scf_instance;
	scf_propertygroup_t *dsh_pg_storage;
	scf_propertygroup_t *dsh_pg_net;
	scf_iter_t *dsh_iter_zpools;
	int dsh_dev_fd;
	int dsh_svc_pool_id;
	char dsh_errstring[DSERV_ERRBUF_SIZE];
	char dsh_astring[DSERV_ASTRING_SIZE];
};

/* dsh_flags */
#define	DSERV_DSH_FLAG_OSYSLOG	0x01

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBDSERV_IMPL_H */
