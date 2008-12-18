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


#ifndef _NFS4_CLNT_IMPL_H
#define	_NFS4_CLNT_IMPL_H

#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_clnt.h>
#include <rpc/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum minorop_type {
	MINOROP_GET,
	MINOROP_SET,
	MINOROP_SYNC_START,
	MINOROP_SYNC_END,
	MINOROP_SETUP,
	MINOROP_RELE
} minorop_type_t;

#define	MINORVERS_OPS							\
	uint32_t (*op_oseqid)(nfs4_open_owner_t *, mntinfo4_t *,	\
			minorop_type_t, seqid4, nfs4_tag_type_t);	\
	uint32_t (*op_lseqid)(nfs4_lock_owner_t *, mntinfo4_t *,	\
					minorop_type_t, seqid4);	\
	clientid4 (*op_clientid)(mntinfo4_t *, minorop_type_t,		\
		    servinfo4_t *,  cred_t *, nfs4_server_t *,		\
		    nfs4_error_t *, int *) 		/* NB: No ";" */

typedef struct nfs4_minorvers_ops {
	const char *minor_vers;
	MINORVERS_OPS;
} nfs4_minorvers_ops_t;

/*
 * Minor version specific switch
 */

nfs4_minorvers_ops_t **nfs4protosw;

#define	NFS4_GET_OSEQID(oop, mi)					\
		(nfs4protosw[mi->mi_minorversion])->op_oseqid(		\
					oop, mi, MINOROP_GET, 0, 0)

#define	NFS4_SET_OSEQID(oop, mi, seqid, ctags)				\
		(nfs4protosw[mi->mi_minorversion])->op_oseqid(		\
				oop, mi, MINOROP_SET, seqid, ctags)

#define	NFS4_START_OSEQID_SYNC(oop, mi)				\
		(nfs4protosw[mi->mi_minorversion])->op_oseqid(	\
				oop, mi, MINOROP_SYNC_START, 0, 0)

#define	NFS4_END_OSEQID_SYNC(oop, mi)					\
		(nfs4protosw[mi->mi_minorversion])->op_oseqid(		\
				oop, mi, MINOROP_SYNC_END, 0, 0)

#define	NFS4_GET_LSEQID(lop, mi)					\
		(nfs4protosw[mi->mi_minorversion])->op_lseqid(		\
					lop, mi, MINOROP_GET, 0)

#define	NFS4_SET_LSEQID(lop, mi, seqid)					\
		(nfs4protosw[mi->mi_minorversion])->op_lseqid(		\
					lop, mi, MINOROP_SET, seqid)

#define	NFS4_START_LSEQID_SYNC(lop, mi)					\
		(nfs4protosw[mi->mi_minorversion])->op_lseqid(		\
					lop, mi, MINOROP_SYNC_START, 0)

#define	NFS4_END_LSEQID_SYNC(lop, mi)					\
		(nfs4protosw[mi->mi_minorversion])->op_lseqid(		\
					lop, mi, MINOROP_SYNC_END, 0)
#define	NFS4_GET_CLIENTID(mi)						\
	(nfs4protosw[mi->mi_minorversion])->op_clientid(		\
			mi, MINOROP_GET, NULL, NULL, NULL, NULL, NULL)	\

#define	NFS4_SET_CLIENTID(mi, svp, cr, np, ep, retinusep)		\
	(nfs4protosw[mi->mi_minorversion])->op_clientid(		\
			mi, MINOROP_SET, svp, cr, np, ep, retinusep)

#define	NFS41_CHECK(mi, x)	((NFS4_MINORVERSION(mi) == 1) && x)

#if DEBUG
#define	VERS40_ASSERT(EX, mi)						\
		((NFS4_MINORVERSION(mi) == 0) ? ASSERT(EX) : (void)0)
#else
#define	VERS40_ASSERT(EX, mi)	((void)0)
#endif

void nfs4_protosw_init(nfs4_minorvers_ops_t **);
void nfs4_set_clientid(mntinfo4_t *, servinfo4_t *, cred_t *, bool_t,
		nfs4_error_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS4_CLNT_IMPL_H */
