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

#ifndef _DS_H
#define	_DS_H

#include <rpc/svc.h>

#ifdef _KERNEL
#include <nfs/nfs4_kprot.h>
#else
#include <rpcsvc/nfs41_prot.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

void ds_dispatch(struct svc_req *, SVCXPRT *xprt);

/*
 * Protos for nfs4[1] XDR funcs which don't already
 * exist in nfs4[1]_xdr.c are extracted from the
 * header generated from rpcsvc/ds_nfs_com.x.  ds_nfs_com.h
 * isn't kept/used for building because it would redefine
 * several NFS4[1] types.  It is only generated to provide
 * xdr fn protos for NFS4[1] types defined in ds_nfs_com.x,
 * and these protos are placed in the dynamically generated
 * header ds_nfs_xdr.h.
 *
 * This trickery exists to allow for rpcgen to create all
 * XDR code for the control pcol.  The control pcol is problematic
 * because it uses some types defined by the NFS4[1] pcol, and
 * dedicated XDR encode/decode funcs do not exist for all
 * types defined by NFS4[1] -- especially the trivial types
 * (which are simply typedef'd scalars).  For these types,
 * the NFS4[1] XDR code invokes the XDR primitives directly
 * or does the XDR work inline.
 *
 * Since ds_prot.x no longer contains duplicate definitions
 * of the NFS4[1] types it needs, rpcgen will not create
 * all of the dedicated xdr encode/decode funcs for the
 * control pcol.  So, ds_nfs_com.x was created to hold definitions
 * for NFS4[1] types which do not have dedicated XDR encode/decode
 * funcs in nfs4[1]_xdr.c.  All NFS4[1] types referenced within
 * ds_prot.x which are not defined in ds_nfs_com.x must have
 * dedicated XDR encode/decode funcs in nfs4[1]_xdr.c because
 * rpcgen will generate fncalls for them within ds_xdr.c.
 */
#include <nfs/ds_nfs_xdr.h>

extern char *pnfs_dmu_tag;	/* Tag used for DMU interfaces */

#ifdef	__cplusplus
}
#endif

#include <nfs/ds_prot.h>
#include <nfs/ds_filehandle.h>

#endif /* _DS_H */
