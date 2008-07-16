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

#ifndef	_LIBNFS_IMPL_H
#define	_LIBNFS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nfs/nfs4.h>
#include <libnfs.h>

#include <umem.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <libuutil.h>
#include <sys/param.h>
#include <deflt.h>
#include <libzfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	LIBNFS_ERRBUF_SIZE	(1024)
#define	LIBNFS_ASTRING_SIZE	(1024)

#define	LIBNFS_PATH_ETC_DEFAULT	"/etc/default/nfs"
#define	LIBNFS_PATH_DSERV "/dev/dserv"

struct libnfs_handle {
	uint32_t lh_flags;
	libnfs_error_t lh_error;
	int lh_errno_error;
	scf_error_t lh_scf_error;
	libnfs_error_mode_t lh_error_mode;
	char lh_errstring[LIBNFS_ERRBUF_SIZE];
	char lh_astring[LIBNFS_ASTRING_SIZE];
	scf_handle_t *lh_scf_handle;
	scf_service_t *lh_scf_service;
	scf_instance_t *lh_scf_instance;
	libzfs_handle_t *lh_zfs_handle;
	int lh_dserv_fd;
};

/* lh_flags */
#define	LIBNFS_LH_FLAG_OSYSLOG	0x01 /* openlog() called */
#define	LIBNFS_LH_FLAG_DEFOPEN	0x02 /* defopen() called */
#define	LIBNFS_LH_FLAG_DSERV	0x04 /* /dev/dserv open */

typedef int (*libnfs_zfs_iter_func_t)(zfs_handle_t *, void *);

typedef struct {
	zfs_type_t lzid_type;
	libnfs_zfs_iter_func_t lzid_func;
	void *lzid_data;
} libnfs_zfs_iter_data_t;

void libnfs_error_set(libnfs_handle_t *, libnfs_error_t);
void *libnfs_alloc(libnfs_handle_t *, uint32_t);

int libnfs_zfs_iter_type(libnfs_handle_t *, libnfs_zfs_iter_func_t,
    zfs_type_t, void *);

extern umem_cache_t *libnfs_zfs_iter_data_cache;

#ifdef	__cplusplus
}
#endif

#endif	/* _LIBNFS_IMPL_H */
