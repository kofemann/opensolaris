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
#ifndef _NFS4_SRV_READDIR_H
#define	_NFS4_SRV_READDIR_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * RFS4_MINLEN_ENTRY4: XDR-encoded size of smallest possible dirent.
 *	This is used to return NFS4ERR_TOOSMALL when clients specify
 *	maxcount that isn't large enough to hold the smallest possible
 *	XDR encoded dirent.
 *
 *	    sizeof cookie (8 bytes) +
 *	    sizeof name_len (4 bytes) +
 *	    sizeof smallest (padded) name (4 bytes) +
 *	    sizeof bitmap4_len (12 bytes) +   NOTE: we always encode len=2 bm4
 *	    sizeof attrlist4_len (4 bytes) +
 *	    sizeof next boolean (4 bytes)
 *
 * RFS4_MINLEN_RDDIR4: XDR-encoded size of READDIR op reply containing
 * the smallest possible entry4 (assumes no attrs requested).
 *	sizeof nfsstat4 (4 bytes) +
 *	sizeof verifier4 (8 bytes) +
 *	sizeof entsecond_to_ry4list bool (4 bytes) +
 *	sizeof entry4 	(36 bytes) +
 *	sizeof eof bool  (4 bytes)
 *
 * RFS4_MINLEN_RDDIR_BUF: minimum length of buffer server will provide to
 *	VOP_READDIR.  Its value is the size of the maximum possible dirent
 *	for solaris.  The DIRENT64_RECLEN macro returns	the size of dirent
 *	required for a given name length.  MAXNAMELEN is the maximum
 *	filename length allowed in Solaris.  The first two DIRENT64_RECLEN()
 *	macros are to allow for . and .. entries -- just a minor tweak to try
 *	and guarantee that buffer we give to VOP_READDIR will be large enough
 *	to hold ., .., and the largest possible solaris dirent64.
 */
#define	RFS4_MINLEN_ENTRY4 36
#define	RFS4_MINLEN_RDDIR4 (4 + NFS4_VERIFIER_SIZE + 4 + RFS4_MINLEN_ENTRY4 + 4)
#define	RFS4_MINLEN_RDDIR_BUF \
	(DIRENT64_RECLEN(1) + DIRENT64_RECLEN(2) + DIRENT64_RECLEN(MAXNAMELEN))


#ifdef	nextdp
#undef nextdp
#endif
#define	nextdp(dp)	((struct dirent64 *)((char *)(dp) + (dp)->d_reclen))

extern verifier4 Readdir4verf;

extern nfs_ftype4 vt_to_nf4[];

/* This is the set of pathconf data for vfs */
typedef struct {
	uint64_t maxfilesize;
	uint32_t maxlink;
	uint32_t maxname;
} rfs4_pc_encode_t;

/* This is the set of statvfs data that is ready for encoding */
typedef struct {
	uint64_t space_avail;
	uint64_t space_free;
	uint64_t space_total;
	u_longlong_t fa;
	u_longlong_t ff;
	u_longlong_t ft;
} rfs4_sb_encode_t;

/*
 * Macros to handle if we have don't have enough space for the requested
 * attributes and this is the first entry and the
 * requested attributes are more than the minimal useful
 * set, reset the attributes to the minimal set and
 * retry the encoding. If the client has asked for both
 * mounted_on_fileid and fileid, prefer mounted_on_fileid.
 */
#define	RFS4_MINIMAL_RD_MASK			\
	(FATTR4_MOUNTED_ON_FILEID_MASK |	\
	FATTR4_FILEID_MASK |			\
	FATTR4_RDATTR_ERROR_MASK)

extern attrmap4 rfs4_minimal_rd_attrmap;
extern attrmap4 rfs4_minimal_rd_fileid_attrmap;
extern attrmap4 rfs4_minimal_rd_mntfileid_attrmap;

#define	RFS4_MINRDDIR_ATTRMAP(vers)	rfs4_minimal_rd_attrmap
#define	RFS4_MINRDDIR_FILEID(vers)	rfs4_minimal_rd_fileid_attrmap
#define	RFS4_MINRDDIR_MNTFILEID(vers)	rfs4_minimal_rd_mntfileid_attrmap

#define	IXDR_PUT_FATTR4_BITMAP(p, m, aptr, len, v) {		\
								\
	/* save length and start of encoded bitmap bits */	\
	(len) = (m).w.w2 ? 3 : 2;				\
	IXDR_PUT_U_INT32((p), (len));				\
								\
	(aptr) = (p);						\
	IXDR_PUT_HYPER((p), (m).d.d0);				\
	if (len == 3)						\
		IXDR_PUT_U_INT32((p), (m).w.w2);		\
}

#define	IXDR_PUT_BITMAP4(p, m) {				\
	IXDR_PUT_U_INT32((p), ((m).w.w2 ? 3 : 2));		\
	IXDR_PUT_HYPER((p), (m).d.d0);				\
	if ((m).w.w2) {						\
		IXDR_PUT_U_INT32((p), (m).w.w2);		\
	}							\
}

#define	IXDR_REWRITE_FATTR4_BITMAP(p, m, len, v) {		\
								\
	/* save length and start of encoded bitmap bits */	\
	IXDR_PUT_HYPER((p), (m).d.d0);				\
	if ((len) == 3)						\
		IXDR_PUT_U_INT32((p), (m).w.w2);		\
}

/*
 * minmap is either:  rdattr_error | mounted_on_fileid
 * or:  rdattr_error | fileid
 */
#define	MINIMIZE_ATTRMAP(m, minmap)	ATTRMAP_MASK(m, minmap)
#define	IS_MIN_ATTRMAP(m)	(! ATTRMAP_TST_CMPL(m, rfs4_minimal_rd_attrmap))

extern int rfs4_get_sb_encode(vfs_t *, rfs4_sb_encode_t *);
extern int rfs4_get_pc_encode(vnode_t *, rfs4_pc_encode_t *, attrmap4 *,
    cred_t *);
extern int nfs4_readdir_getvp(vnode_t *, char *, vnode_t **,
    struct exportinfo **, struct svc_req *, struct compound_state *, int);

#ifdef __cplusplus
}
#endif

#endif /* _NFS4_SRV_READDIR_H */
