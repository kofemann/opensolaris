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

#ifndef _SPE_IMPL_H
#define	_SPE_IMPL_H

#include <sys/sysmacros.h>
#include <sys/types.h>

#include <nfs/mds_state.h>

/*
 * This is a private header file.  Applications should not directly include
 * this file.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 *  Ask the Policy engine to allocate the pool mds_sids; stripe count
 *  and unit size.
 */
extern int nfs41_spe_allocate(vattr_t *, struct netbuf *, char *,
    layout_core_t *, int);

/*
 * Given a dataset name, get the mds sid
 */
extern int (*nfs41_spe_path2mds_sid)(utf8string *, mds_sid *);
extern int mds_ds_path_to_mds_sid(utf8string *, mds_sid *);

/*
 * Stop and start routines for the kspe.
 */
extern void nfs41_spe_fini(void);
extern void nfs41_spe_init(void);

#ifdef	__cplusplus
}
#endif

#endif /* _SPE_IMPL_H */
