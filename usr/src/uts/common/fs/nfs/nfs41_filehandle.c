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

#include <sys/systm.h>

#include <nfs/nfs4.h>
#include <nfs/export.h>
#include <nfs/ds_prot.h>
#include <nfs/nfs41_filehandle.h>

/*
 * Make an NFSv41 (Version 1) filehandle from a vnode
 */
int
mknfs41_fh(nfs_fh4 *otw_fh, vnode_t *vp, struct exportinfo *exi)
{
	int error;
	nfs41_fh_fmt_t *fhp = (nfs41_fh_fmt_t *)otw_fh->nfs_fh4_val;
	fid_t fid;

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;

	/*
	 * vop_fid_pseudo() is used to set up NFSv4 namespace.
	 */
	error = vop_fid_pseudo(vp, &fid);
	if (error)
		return (error);

	otw_fh->nfs_fh4_len = sizeof (nfs41_fh_fmt_t);

	bzero(fhp, sizeof (*fhp));

	fhp->vers = NFS41_FH_v1;
	fhp->type = FH41_TYPE_NFS;

	/* copy the export fsid */
	fhp->fh.v1.export_fsid = exi->exi_fsid;

	/* copy the fid for the export root */
	fhp->fh.v1.export_fid.len = exi->exi_fh.fh_xlen;
	bcopy(exi->exi_fh.fh_xdata, fhp->fh.v1.export_fid.val,
	    exi->exi_fh.fh_xlen);

	/* copy the fid for the object */
	fhp->fh.v1.obj_fid.len = fid.fid_len;
	bcopy(fid.fid_data, fhp->fh.v1.obj_fid.val, fid.fid_len);

	return (0);
}

/*
 * Using the NFSv41 filehandle from OTW decoded opaque, locate
 * and return the corresponding vnode pointer.
 *
 * Assumes that the caller has already populated the compound
 * state exportinfo pointer.
 *
 * This function understands FH_TYPE_NFS version 1 filehandles.
 */
vnode_t *
nfs41_fhtovp(nfs_fh4 *otw_fh, compound_state_t *cs)
{
	/*
	 * If the compound state does not hold the export info, the
	 * filehandle must be stale (or we were called too soon).
	 */
	if (cs->exi == NULL) {
		*cs->statusp = NFS4ERR_STALE;
		return (NULL);
	}

	ASSERT(cs->exi->exi_vp != NULL);
	if (cs->exi->exi_vp == NULL) {
		*cs->statusp = NFS4ERR_STALE;
		return (NULL);
	}

	return (nfs41_fhtovp_exi(otw_fh, cs->exi, cs->statusp));
}

vnode_t *
nfs41_fhtovp_exi(nfs_fh4 *otw_fh, exportinfo_t *exi, nfsstat4 *statusp)
{
	int error;
	fid_t fidp;
	nfs41_fh_fmt_t *fhp;
	vfs_t *vfsp;
	vnode_t *vp;

	vfsp = exi->exi_vp->v_vfsp;

	ASSERT(vfsp != NULL);
	if (vfsp == NULL) {
		*statusp = NFS4ERR_STALE;
		return (NULL);
	}

	fhp = (nfs41_fh_fmt_t *)otw_fh->nfs_fh4_val;

	fidp.fid_len = fhp->fh.v1.obj_fid.len;

	bcopy(fhp->fh.v1.obj_fid.val,
	    fidp.fid_data, fidp.fid_len);

	error = VFS_VGET(vfsp, &vp, &fidp);

	/*
	 * If we can not get vp from VFS_VGET, perhaps this is
	 * an nfs v2/v3/v4 node in an nfsv4 pseudo filesystem.
	 * Check it out.
	 */
	if (error && PSEUDO(exi))
		error = nfs4_vget_pseudo(exi, &vp, &fidp);

	if (error || vp == NULL) {
		*statusp = NFS4ERR_STALE;
		return (NULL);
	}

	/*
	 * coerce the v_type to VDIR if this is really
	 * an extended attribute directory.
	 */
	if (vp->v_type == VNON && vp->v_flag & V_XATTRDIR)
		vp->v_type = VDIR;

	*statusp = NFS4_OK;

	return (vp);

}
