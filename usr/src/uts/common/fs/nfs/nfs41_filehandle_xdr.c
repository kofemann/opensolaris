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

#include <sys/vfs.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>
#include <nfs/nfs41_filehandle.h>
#include <nfs/ds_prot.h>
#include <nfs/ds_filehandle.h>
#include <sys/sdt.h>

bool_t
xdr_nfs41_fh_type_t(XDR *xdrs, nfs41_fh_type_t *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)objp))
		return (FALSE);
	return (TRUE);
}

static bool_t
xdr_nfs41_fh_v1(XDR *xdrs, nfs41_fh_v1_t *objp)
{
	char *ptr;

	if (!xdr_uint32_t(xdrs, &objp->flags))
		return (FALSE);

	if (!xdr_uint32_t(xdrs, &objp->gen))
		return (FALSE);

	if (!xdr_int(xdrs, &objp->export_fsid.val[0]))
		return (FALSE);

	if (!xdr_int(xdrs, &objp->export_fsid.val[1]))
		return (FALSE);

	ptr = &objp->export_fid.val[0];
	if (!xdr_bytes(xdrs, &ptr,
	    (uint_t *)&objp->export_fid.len, NFS_FH4MAXDATA))
		return (FALSE);

	ptr = &objp->obj_fid.val[0];
	if (!xdr_bytes(xdrs, &ptr,
	    (uint_t *)&objp->obj_fid.len, NFS_FH4MAXDATA))
		return (FALSE);

	return (TRUE);
}

static bool_t
xdrnfs41_fh(XDR *xdrs, nfs41_fh_fmt_t *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->vers))
		return (FALSE);

	switch (objp->vers) {
	case NFS41_FH_v1:
		if (!xdr_nfs41_fh_v1(xdrs, &objp->fh.v1))
			return (FALSE);
		break;
	default:
		DTRACE_PROBE(xdr__e__unsuported_fh_vers);
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_nfs41_fh_fmt(XDR *xdrs, nfs41_fh_fmt_t *objp)
{
	if (!xdr_enum(xdrs, (enum_t *)&objp->type))
		return (FALSE);

	switch (objp->type) {
	case FH41_TYPE_NFS:
		if (!xdrnfs41_fh(xdrs, objp))
			return (FALSE);
		break;

	default:
		DTRACE_PROBE(xdr__e__unsuported_fh_type);
		return (FALSE);
	}
	return (TRUE);
}

bool_t
xdr_encode_nfs41_fh(XDR *xdrs, nfs_fh4 *objp)
{
	nfs41_fh_fmt_t *fhp;
	uint_t otw_len;

	ASSERT(xdrs->x_op == XDR_ENCODE);

	fhp = (nfs41_fh_fmt_t *)objp->nfs_fh4_val;

	otw_len = xdr_sizeof(xdr_nfs41_fh_fmt, fhp);

	if (!xdr_uint32_t(xdrs, &otw_len))
		return (FALSE);

	return (xdr_nfs41_fh_fmt(xdrs, fhp));

}

extern bool_t xdr_ds_fh(XDR *, mds_ds_fh *);

/*
 * Put this here so everyone can enjoy it!
 */
void
free_mds_ds_fh(mds_ds_fh *fp)
{
	if (fp->fh.v1.mds_sid.val) {
		kmem_free(fp->fh.v1.mds_sid.val, fp->fh.v1.mds_sid.len);
	}

	kmem_free(fp, sizeof (mds_ds_fh));
}

bool_t
xdr_decode_nfs41_fh(XDR *xdrs, nfs_fh4 *objp)
{
	uint_t otw_len;
	uint_t type;

	ASSERT(xdrs->x_op == XDR_DECODE);

	objp->nfs_fh4_val = NULL;
	objp->nfs_fh4_len = 0;

	/*
	 * consume the filehandle length.
	 */
	if (!xdr_uint32_t(xdrs, &otw_len))
		return (FALSE);

	/* Get the filehandle type */
	if (!xdr_enum(xdrs, (enum_t *)&type))
		return (FALSE);

	switch (type) {
	case FH41_TYPE_NFS: {
		nfs41_fh_fmt_t *nfhp = NULL;

		nfhp = kmem_zalloc(sizeof (nfs41_fh_fmt_t), KM_SLEEP);
		nfhp->type = FH41_TYPE_NFS;
		if (!xdrnfs41_fh(xdrs, nfhp)) {
			kmem_free(nfhp, sizeof (nfs41_fh_fmt_t));
			return (FALSE);
		}

		objp->nfs_fh4_val = (char *)nfhp;
		objp->nfs_fh4_len = sizeof (nfs41_fh_fmt_t);
		break;
	}

	case FH41_TYPE_DMU_DS: {
		struct mds_ds_fh *dfhp = NULL;

		dfhp = kmem_zalloc(sizeof (struct mds_ds_fh), KM_SLEEP);
		dfhp->type = FH41_TYPE_DMU_DS;

		if (!xdr_ds_fh(xdrs, dfhp)) {
			free_mds_ds_fh(dfhp);
			return (FALSE);
		}

		objp->nfs_fh4_val = (char *)dfhp;
		objp->nfs_fh4_len = sizeof (struct mds_ds_fh);
		break;
	}

	default:
		DTRACE_PROBE(xdr__e__unsuported_fh_type);
		return (FALSE);
	}
	return (TRUE);
}

/*
 * XDR a NFSv4 filehandle.
 * Encoding interprets the contents (server).
 * Decoding the contents are opaque (client).
 *
 * This func is used as the xdr fnptr in nfs41_ntov_map
 * [same as xdr_nfs_fh4_modified() except that it encodes 4.1 fh]
 */
bool_t
xdr_nfs_fh41_modified(XDR *xdrs, nfs_fh4 *objp)
{
	switch (xdrs->x_op) {
	case XDR_ENCODE:
		return (xdr_encode_nfs41_fh(xdrs, objp));
	case XDR_DECODE:
		return (xdr_bytes(xdrs, (char **)&objp->nfs_fh4_val,
		    (uint_t *)&objp->nfs_fh4_len, NFS4_FHSIZE));
	case XDR_FREE:
		if (objp->nfs_fh4_val != NULL) {
			kmem_free(objp->nfs_fh4_val, objp->nfs_fh4_len);
			objp->nfs_fh4_val = NULL;
		}
		return (TRUE);
	}
	return (FALSE);
}
