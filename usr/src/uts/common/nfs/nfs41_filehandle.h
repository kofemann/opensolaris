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

#ifndef _NFS41_FILEHANDLE_H
#define	_NFS41_FILEHANDLE_H

#ifdef USE_FOR_SNOOP
#define	NFS_FH4MAXDATA 26
#include <sys/vfs.h>
#else
#include <nfs/nfs.h>
#include <nfs/nfs41_fhtype.h>
#include <nfs/nfs4.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	NFS41_FH_v1 = 1
} nfs41_fh_vers_t;

typedef struct {
	uint_t len;
	char val[NFS_FH4MAXDATA];
} nfs41_fid_t;

typedef struct {
	uint32_t flags;
	uint32_t gen;
	fsid_t	export_fsid;
	nfs41_fid_t export_fid;
	nfs41_fid_t obj_fid;
} nfs41_fh_v1_t;

typedef struct {
	nfs41_fh_type_t type;
	nfs41_fh_vers_t vers;
	union {
		nfs41_fh_v1_t v1;
		/* new versions will be added here */
	} fh;
} nfs41_fh_fmt_t;

#define	NFS41_FH_LEN	sizeof (nfs41_fh_fmt_t)

#define	FH41_SET_FLAG(ptr, flag) ((ptr)->fh.v1.flags |= (flag))
#define	FH41_GET_FLAG(ptr, flag) ((ptr)->fh.v1.flags & (flag))
#define	FH41_CLR_FLAG(ptr, flag) ((ptr)->fh.v1.flags &= ~(flag))

/*
 * Possible Flag values
 */
#define	FH41_NAMEDATTR	1
#define	FH41_ATTRDIR	2

#ifndef USE_FOR_SNOOP
extern vnode_t *nfs41_fhtovp(nfs_fh4 *, compound_state_t *);
extern vnode_t *nfs41_fhtovp_exi(nfs_fh4 *, struct exportinfo *, nfsstat4 *);
extern int mknfs41_fh(nfs_fh4 *, vnode_t *, struct exportinfo *);
#endif

extern bool_t xdr_encode_nfs41_fh(XDR *, nfs_fh4 *);
extern bool_t xdr_decode_nfs41_fh(XDR *, nfs_fh4 *);
extern bool_t xdr_nfs41_fh_fmt(XDR *, nfs41_fh_fmt_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS41_FILEHANDLE_H */
