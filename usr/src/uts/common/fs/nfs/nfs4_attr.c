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

#include <sys/time.h>
#include <sys/systm.h>

#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <nfs/nfs4_clnt.h>
#include <sys/cmn_err.h>


attrmap4 nfs4_fsinfo_attrmap[AV_COUNT] = {
	{NFS4_FSINFO_MASK, 0},
	{NFS41_FSINFO_MASK0, NFS41_FSINFO_MASK1}
};

attrmap4 nfs4_mandatory_attrmap[AV_COUNT] = {
	{FATTR4_MANDATTR_MASK0, 0},
	{FATTR4_MANDATTR_MASK0, FATTR4_SUPPATTR_EXCLCREAT_MASK}
};

/*
 * This attrmap is used to identify attributes that are XDR'd into
 * the nfs4_ga_res_ext struct (instead of nfs4_ga_res).
 */
attrmap4 nfs4_default_attrmap[AV_COUNT] = {
	{NFS4_VATTR_MASK, 0},
	{NFS41_DEFAULT_MASK0, NFS41_DEFAULT_MASK1}
};

attrmap4 nfs4_rddir_attrmap[AV_COUNT] = {
	{NFS4_VATTR_MASK | FATTR4_RDATTR_ERROR_MASK, 0},
	{NFS41_DEFAULT_MASK0 | FATTR4_RDATTR_ERROR_MASK, NFS41_DEFAULT_MASK1}
};

attrmap4 rfs4_supp_attrmap[AV_COUNT] = {
	{NFS4_SRV_SUPP_MASK, 0},
	{NFS41_SRV_SUPP_MASK0, NFS41_SRV_SUPP_MASK1}
};

attrmap4 rfs4_rddir_supp_attrmap[AV_COUNT] = {
	{NFS4_SRV_RDDIR_SUPP_MASK, 0},
	{NFS41_SRV_RDDIR_SUPP_MASK0, NFS41_SRV_RDDIR_SUPP_MASK1}
};

attrmap4 nfs4_empty_attrmap = {0, 0};
attrmap4 nfs4_pathconf_attrmap = {NFS4_PATHCONF_MASK, 0};
attrmap4 nfs4_vattr_attrmap = {NFS4_VATTR_MASK, 0};
attrmap4 nfs4_statfs_attrmap = {NFS4_STATFS_ATTR_MASK, 0};
attrmap4 nfs4_extres_attrmap = {~(NFS4_VATTR_MASK | FATTR4_ACL_MASK), ~0uLL};
attrmap4 nfs4_minrddir_attrmap =
	{FATTR4_MOUNTED_ON_FILEID_MASK | FATTR4_RDATTR_ERROR_MASK, 0};
attrmap4 rfs41_supp_exclcreat_attrmap = {NFS41_SRV_EXCLCREAT_ATTRS, 0};
attrmap4 nfs4_attrcache_attrmap = {NFS4_NTOV_ATTR_CACHE_MASK, 0};
attrmap4 nfs4_leasetime_attrmap = {FATTR4_LEASE_TIME_MASK, 0};
attrmap4 rfs4_fsspace_attrmap = {NFS4_FS_ATTR_MASK, 0};

static int
timestruc_to_settime4(timestruc_t *tt, settime4 *tt4, int flags)
{
	int	error = 0;

	if (flags & ATTR_UTIME) {
		tt4->set_it = SET_TO_CLIENT_TIME4;
		error = nfs4_time_vton(tt, &tt4->time);
	} else {
		tt4->set_it = SET_TO_SERVER_TIME4;
	}
	return (error);
}


/*
 * nfs4_ver_fattr4_attr translates a vattr attribute into a fattr4 attribute
 * for use by nfsv4 verify.  For setting atime or mtime use the entry for
 * time_XX (XX == access or modify).
 * Return TRUE if arg was set (even if there was an error) and FALSE
 * otherwise. Also set error code. The caller should not continue
 * if error was set, whether or not the return is TRUE or FALSE. Returning
 * FALSE does not mean there was an error, only that the attr was not set.
 *
 * Note: For now we only have the options used by setattr. In the future
 * the switch statement below should cover all vattr attrs and possibly
 * sys attrs as well.
 */
/* ARGSUSED */
static bool_t
nfs4_ver_fattr4_attr(vattr_t *vap, struct nfs4_ntov_map *ntovp,
	union nfs4_attr_u *nap, int flags, int *errorp)
{
	bool_t	retval = TRUE;

	/*
	 * Special case for time set: if setting the
	 * time, ignore entry for time access/modify set (setattr)
	 * and instead use that of time access/modify.
	 */
	*errorp = 0;
	/*
	 * Bit matches the mask
	 */
	switch (ntovp->vbit & vap->va_mask) {
	case AT_SIZE:
		nap->size = vap->va_size;
		break;
	case AT_MODE:
		nap->mode = vap->va_mode;
		break;
	case AT_UID:
		/*
		 * if no mapping, uid could be mapped to a numeric string,
		 * e.g. 12345->"12345"
		 */
		if (*errorp = nfs_idmap_uid_str(vap->va_uid, &nap->owner,
		    FALSE))
			retval = FALSE;
		break;
	case AT_GID:
		/*
		 * if no mapping, gid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_gid_str(vap->va_gid, &nap->owner_group,
		    FALSE))
			retval = FALSE;
		break;
	case AT_ATIME:
		if ((ntovp->nval != FATTR4_TIME_ACCESS) ||
		    (*errorp =
		    nfs4_time_vton(&vap->va_ctime, &nap->time_access))) {
			/*
			 * either asked for FATTR4_TIME_ACCESS_SET -
			 *	not used for setattr
			 * or system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	case AT_MTIME:
		if ((ntovp->nval != FATTR4_TIME_MODIFY) ||
		    (*errorp =
		    nfs4_time_vton(&vap->va_mtime, &nap->time_modify))) {
			/*
			 * either asked for FATTR4_TIME_MODIFY_SET -
			 *	not used for setattr
			 * or system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	case AT_CTIME:
		if (*errorp =
		    nfs4_time_vton(&vap->va_ctime, &nap->time_metadata)) {
			/*
			 * system time invalid for otw transfers
			 */
			retval = FALSE;
		}
		break;
	default:
		retval = FALSE;
	}
	return (retval);
}

/*
 * nfs4_set_fattr4_attr translates a vattr attribute into a fattr4 attribute
 * for use by nfs4_setattr.  For setting atime or mtime use the entry for
 * time_XX_set rather than time_XX (XX == access or modify).
 * Return TRUE if arg was set (even if there was an error) and FALSE
 * otherwise. Also set error code. The caller should not continue
 * if error was set, whether or not the return is TRUE or FALSE. Returning
 * FALSE does not mean there was an error, only that the attr was not set.
 */
static bool_t
nfs4_set_fattr4_attr(vattr_t *vap, vsecattr_t *vsap,
    struct nfs4_ntov_map *ntovp, union nfs4_attr_u *nap, int flags, int *errorp)
{
	bool_t	retval = TRUE;

	/*
	 * Special case for time set: if setting the
	 * time, ignore entry for time access/modify
	 * and instead use that of time access/modify set.
	 */
	*errorp = 0;
	/*
	 * Bit matches the mask
	 */
	switch (ntovp->vbit & vap->va_mask) {
	case AT_SIZE:
		nap->size = vap->va_size;
		break;
	case AT_MODE:
		nap->mode = vap->va_mode;
		break;
	case AT_UID:
		/*
		 * if no mapping, uid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_uid_str(vap->va_uid, &nap->owner,
		    FALSE))
			retval = FALSE;
		break;
	case AT_GID:
		/*
		 * if no mapping, gid will be mapped to a number string,
		 * e.g. "12345"
		 */
		if (*errorp = nfs_idmap_gid_str(vap->va_gid, &nap->owner_group,
		    FALSE))
			retval = FALSE;
		break;
	case AT_ATIME:
		if ((ntovp->nval != FATTR4_TIME_ACCESS_SET) ||
		    (*errorp = timestruc_to_settime4(&vap->va_atime,
		    &nap->time_access_set, flags))) {
			/* FATTR4_TIME_ACCESS - not used for verify */
			retval = FALSE;
		}
		break;
	case AT_MTIME:
		if ((ntovp->nval != FATTR4_TIME_MODIFY_SET) ||
		    (*errorp = timestruc_to_settime4(&vap->va_mtime,
		    &nap->time_modify_set, flags))) {
			/* FATTR4_TIME_MODIFY - not used for verify */
			retval = FALSE;
		}
		break;
	default:
		/*
		 * If the ntovp->vbit == 0 this is most likely the ACL.
		 */
		if (ntovp->vbit == 0 && ATTR_ISSET(ntovp->fbit, ACL)) {
			ASSERT(vsap->vsa_mask == (VSA_ACE | VSA_ACECNT));
			nap->acl.fattr4_acl_len = vsap->vsa_aclcnt;
			nap->acl.fattr4_acl_val = vsap->vsa_aclentp;
		} else
			retval = FALSE;
	}

	return (retval);
}

/*
 * vattr_to_fattr4 takes creates the fattr4 arg for the setattr, open, create,
 * nverify, and verify ops.  Only a subset of writeable attributes are
 * supported by the lower level attr converstion functions: size, mode,
 * uid/gid, times, and layouthint.
 */
int
vattr_to_fattr4(vattr_t *vap, vsecattr_t *vsap, fattr4 *fattrp, int flags,
    enum nfs_opnum4 op, attrmap4 *supp, int avers, file_layouthint4 *floh)
{
	int i, j;
	union nfs4_attr_u *na = NULL;
	int attrcnt;
	int uid_attr = -1;
	int gid_attr = -1;
	XDR xdr;
	ulong_t xdr_size;
	char *xdr_attrs;
	int error = 0;
	uint8_t amap[NFS4_MAXNUM_ATTRS];
	uint_t va_mask = vap->va_mask;
	bool_t (*attrfunc)();
	struct nfs4_ntov_map *nvmap;
	attrmap4 todo_amap;

	nvmap = NFS4_NTOV_MAP(avers);
	fattrp->attrmask = NFS4_EMPTY_ATTRMAP(avers);
	fattrp->attrlist4_len = 0;
	fattrp->attrlist4 = NULL;
	na = kmem_zalloc(sizeof (union nfs4_attr_u) * NFS4_NTOV_MAP_SIZE(avers),
	    KM_SLEEP);

	if (op == OP_SETATTR || op == OP_CREATE || op == OP_OPEN) {
		/*
		 * Note we need to set the attrmask for set operations.
		 * In particular mtime and atime will be set to the
		 * servers time.
		 */
		nfs4_vmask_to_nmask_set(va_mask, &fattrp->attrmask);
		if (vsap)
			ATTR_SET(fattrp->attrmask, ACL);
		if (floh)
			ATTR_SET(fattrp->attrmask, LAYOUT_HINT);

		attrfunc = nfs4_set_fattr4_attr;
	} else {	/* verify/nverify */
		/*
		 * Verfy/nverify use the "normal vmask_to_nmask
		 * this routine knows how to handle all vmask bits
		 */
		nfs4_vmask_to_nmask(va_mask, &fattrp->attrmask, avers);

		/*
		 * nfs4_vmask_to_nmask will set change whenever AT_CTIME
		 * or AT_MTIME is requested.  Client verify/nverify only
		 * works for a subset of attrs that directly map to
		 * vattr_t attrs, but not change.  Turn off change here
		 * because nfs4_ver_fattr4_attr will not generate proper
		 * args to verify change.
		 */
		ATTR_CLR(fattrp->attrmask, CHANGE);
		attrfunc = nfs4_ver_fattr4_attr;
	}

	/*
	 * Mask out any rec attrs unsupported by server.
	 */
	ATTRMAP_MASK(fattrp->attrmask, *supp);
	todo_amap = fattrp->attrmask;

	attrcnt = 0;
	xdr_size = 0;
	for (i = 0; i < NFS4_NTOV_MAP_SIZE(avers); i++) {
		/*
		 * Skip this nfs attr if not requested or not supported
		 * by server
		 */
		if (!(ATTRMAP_TST(fattrp->attrmask, nvmap[i].fbit)))
			continue;

		/*
		 * Skip if caller did not provide data for attr
		 */
		switch (nvmap[i].nval) {
		case FATTR4_ACL:
			if (vsap == NULL)
				continue;
			break;
		case FATTR4_LAYOUT_HINT:
			if (floh == NULL)
				continue;
			break;
		default:
			if (! (nvmap[i].vbit & vap->va_mask))
				continue;
			break;
		}

		if (attrfunc == nfs4_set_fattr4_attr) {

			if (nvmap[i].nval == FATTR4_LAYOUT_HINT) {
				na[attrcnt].file_layouthint = *floh;
			} else if (!(*attrfunc)(vap, vsap, &nvmap[i],
			    &na[attrcnt], flags, &error))
				continue;

		} else if (attrfunc == nfs4_ver_fattr4_attr) {
			if (!(*attrfunc)(vap, &nvmap[i], &na[attrcnt],
			    flags, &error))
				continue;
		}

		if (error)
			goto done;	/* Exit! */

		/*
		 * Calculate XDR size
		 */
		if (nvmap[i].xdr_size != 0) {
			/*
			 * If we are setting attributes (attrfunc is
			 * nfs4_set_fattr4_attr) and are setting the
			 * mtime or atime, adjust the xdr size down by
			 * 3 words, since we are using the server's
			 * time as the current time.  Exception: if
			 * ATTR_UTIME is set, the client sends the
			 * time, so leave the xdr size alone.
			 */
			xdr_size += nvmap[i].xdr_size;
			if ((nvmap[i].nval == FATTR4_TIME_ACCESS_SET ||
			    nvmap[i].nval == FATTR4_TIME_MODIFY_SET) &&
			    attrfunc == nfs4_set_fattr4_attr &&
			    !(flags & ATTR_UTIME)) {
				xdr_size -= 3 * BYTES_PER_XDR_UNIT;
			}
		} else {
			/*
			 * The only zero xdr_sizes we should see
			 * are AT_UID, AT_GID and FATTR4_ACL_MASK
			 */
			ASSERT(nvmap[i].vbit == AT_UID ||
			    nvmap[i].vbit == AT_GID ||
			    ATTR_ISSET(nvmap[i].fbit, ACL));
			if (nvmap[i].vbit == AT_UID) {
				uid_attr = attrcnt;
				xdr_size += BYTES_PER_XDR_UNIT;	/* length */
				xdr_size +=
				    RNDUP(na[attrcnt].owner.utf8string_len);
			} else if (nvmap[i].vbit == AT_GID) {
				gid_attr = attrcnt;
				xdr_size += BYTES_PER_XDR_UNIT;	/* length */
				xdr_size +=
				    RNDUP(
				    na[attrcnt].owner_group.utf8string_len);
			} else if (nvmap[i].nval == FATTR4_ACL) {
				nfsace4 *tmpacl = (nfsace4 *)vsap->vsa_aclentp;

				/* fattr4_acl_len */
				xdr_size += BYTES_PER_XDR_UNIT;
				/* fattr4_acl_val */
				xdr_size += RNDUP((vsap->vsa_aclcnt *
				    (sizeof (acetype4) + sizeof (aceflag4)
				    + sizeof (acemask4))));

				for (j = 0; j < vsap->vsa_aclcnt; j++) {
					/* who - utf8string_len */
					xdr_size += BYTES_PER_XDR_UNIT;
					/* who - utf8string_val */
					xdr_size +=
					    RNDUP(tmpacl[j].who.utf8string_len);
				}
			}
		}

		/*
		 * This attr is going otw
		 */
		amap[attrcnt] = (uint8_t)nvmap[i].nval;
		attrcnt++;

		/*
		 * Clear this bit from test mask so we stop
		 * as soon as all requested attrs are done.
		 */
		ATTRMAP_CLR(todo_amap, nvmap[i].fbit);
		if (ATTRMAP_EMPTY(todo_amap))
			break;
	}

	/*
	 * Only bits for skipped attrs remain todo_amap.  Any bits
	 * set in todo_amap must be cleared in fattrp->attrmask.
	 */
	ATTRMAP_CLR(fattrp->attrmask, todo_amap);

	if (attrcnt == 0) {
		goto done;
	}

	fattrp->attrlist4 = xdr_attrs = kmem_alloc(xdr_size, KM_SLEEP);
	fattrp->attrlist4_len = xdr_size;
	xdrmem_create(&xdr, xdr_attrs, xdr_size, XDR_ENCODE);
	for (i = 0; i < attrcnt; i++) {
		if ((*nvmap[amap[i]].xfunc)(&xdr, &na[i]) == FALSE) {
			cmn_err(CE_WARN, "vattr_to_fattr4: xdr encode of "
			    "attribute failed\n");
			error = EINVAL;
			break;
		}
	}
done:
	/*
	 * Free any malloc'd attrs, can only be uid or gid
	 */
	if (uid_attr != -1 && na[uid_attr].owner.utf8string_val != NULL) {
		kmem_free(na[uid_attr].owner.utf8string_val,
		    na[uid_attr].owner.utf8string_len);
	}
	if (gid_attr != -1 && na[gid_attr].owner_group.utf8string_val != NULL) {
		kmem_free(na[gid_attr].owner_group.utf8string_val,
		    na[gid_attr].owner_group.utf8string_len);
	}

	/* xdrmem_destroy(&xdrs); */	/* NO-OP */
	kmem_free(na, sizeof (union nfs4_attr_u) * NFS4_NTOV_MAP_SIZE(avers));
	if (error)
		nfs4_fattr4_free(fattrp);
	return (error);
}

void
nfs4_fattr4_free(fattr4 *attrp)
{
	/*
	 * set attrlist4val/len to 0 because...
	 *
	 * op_readdir resfree function could call us again
	 * for last entry4 if it was able to encode the name
	 * and cookie but couldn't encode the attrs because
	 * of maxcount violation (from rddir args).  In that
	 * case, the last/partial entry4's fattr4 has already
	 * been freed, but the entry4 remains on the end of
	 * the list.
	 *
	 * NFS4_EMPTY_ATTRMAP(AV_NFS41) is not an error.  The
	 * attr version is not available here, but the value
	 * of an empty attrmap is the same for all attr versions.
	 * The argument to NFS4_EMPTY_ATTRMAP() does not affect
	 * the result.
	 */
	attrp->attrmask = NFS4_EMPTY_ATTRMAP(AV_NFS41);

	if (attrp->attrlist4) {
		kmem_free(attrp->attrlist4, attrp->attrlist4_len);
		attrp->attrlist4 = NULL;
		attrp->attrlist4_len = 0;
	}
}

/*
 * Translate a vattr_t mask to a fattr4 type bitmap, caller is
 * responsible for zeroing bitsval if needed.
 */
void
nfs4_vmask_to_nmask(uint_t vmask, attrmap4 *bitsval, int vers)
{
	ASSERT(vers == 0 || vers == 1);

	if (vmask == AT_ALL || vmask == NFS4_VTON_ATTR_MASK) {
		*bitsval = NFS4_DEFAULT_ATTRMAP(vers);
		return;
	}

	*bitsval = NFS4_EMPTY_ATTRMAP(vers);

	vmask &= NFS4_VTON_ATTR_MASK;
	if (vmask == 0) {
		return;
	}

	if (vmask & AT_TYPE)
		ATTR_SET(*bitsval, TYPE);
	if (vmask & AT_MODE)
		ATTR_SET(*bitsval, MODE);
	if (vmask & AT_UID)
		ATTR_SET(*bitsval, OWNER);
	if (vmask & AT_GID)
		ATTR_SET(*bitsval, OWNER_GROUP);
	if (vmask & AT_FSID)
		ATTR_SET(*bitsval, FSID);
	/* set mounted_on_fileid when AT_NODEID requested */
	if (vmask & AT_NODEID) {
		ATTR_SET(*bitsval, FILEID);
		ATTR_SET(*bitsval, MOUNTED_ON_FILEID);
	}
	if (vmask & AT_NLINK)
		ATTR_SET(*bitsval, NUMLINKS);
	if (vmask & AT_SIZE)
		ATTR_SET(*bitsval, SIZE);
	if (vmask & AT_ATIME)
		ATTR_SET(*bitsval, TIME_ACCESS);
	if (vmask & AT_MTIME)
		ATTR_SET(*bitsval, TIME_MODIFY);
	/* also set CHANGE whenever AT_CTIME requested */
	if (vmask & AT_CTIME) {
		ATTR_SET(*bitsval, TIME_METADATA);
		ATTR_SET(*bitsval, CHANGE);
	}
	if (vmask & AT_NBLOCKS)
		ATTR_SET(*bitsval, SPACE_USED);
	if (vmask & AT_RDEV)
		ATTR_SET(*bitsval, RAWDEV);

}

/*
 * nfs4_vmask_to_nmask_set is used for setattr. A separate function needed
 * because of special treatment to timeset.
 */
void
nfs4_vmask_to_nmask_set(uint_t vmask, attrmap4 *bitsval)
{
	vmask &= NFS4_VTON_ATTR_MASK_SET;

	*bitsval = NFS4_EMPTY_ATTRMAP(AV_NFS41);
	if (vmask == 0) {
		return;
	}

	if (vmask & AT_MODE)
		ATTR_SET(*bitsval, MODE);
	if (vmask & AT_UID)
		ATTR_SET(*bitsval, OWNER);
	if (vmask & AT_GID)
		ATTR_SET(*bitsval, OWNER_GROUP);
	if (vmask & AT_SIZE)
		ATTR_SET(*bitsval, SIZE);
	if (vmask & AT_ATIME)
		ATTR_SET(*bitsval, TIME_ACCESS_SET);
	if (vmask & AT_MTIME)
		ATTR_SET(*bitsval, TIME_MODIFY_SET);
}

/*
 * Convert NFS Version 4 over the network attributes to the local
 * virtual attributes.
 */
vtype_t nf4_to_vt[] = {
	VBAD, VREG, VDIR, VBLK, VCHR, VLNK, VSOCK, VFIFO, VDIR, VREG
};


/*
 * All nfs4_ntov_map structs will contain the same number of entries.
 * Entries not defined by a minor version will contain only null fn ptrs.
 */
struct nfs4_ntov_map nfs40_ntov_map[NFS41_ATTR_COUNT] = {
	/*
	 *	{ {fbit.d.d0, fbit.d.d1},
	 *		vbit, vfsstat, mandatory,
	 *		nval, xdr_size,
	 *		xfunc,	sv_getit, prtstr },
	 */
	{ {FATTR4_SUPPORTED_ATTRS_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_SUPPORTED_ATTRS, 3 * BYTES_PER_XDR_UNIT,
		xdr_attrmap4, NULL, "fattr4_supported_attrs" },

	{ {FATTR4_TYPE_MASK, 0},
		AT_TYPE, FALSE, TRUE,
		FATTR4_TYPE, BYTES_PER_XDR_UNIT,
		xdr_int, NULL, "fattr4_type" },

	{ {FATTR4_FH_EXPIRE_TYPE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_FH_EXPIRE_TYPE, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_fh_expire_type" },

	{ {FATTR4_CHANGE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_CHANGE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_change" },

	{ {FATTR4_SIZE_MASK, 0},
		AT_SIZE, FALSE, TRUE,
		FATTR4_SIZE,  2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_size" },

	{ {FATTR4_LINK_SUPPORT_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_LINK_SUPPORT, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_link_support" },

	{ {FATTR4_SYMLINK_SUPPORT_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_SYMLINK_SUPPORT, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_symlink_support" },

	{ {FATTR4_NAMED_ATTR_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_NAMED_ATTR, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_named_attr" },

	{ {FATTR4_FSID_MASK, 0},
		AT_FSID, FALSE, TRUE,
		FATTR4_FSID, 4 * BYTES_PER_XDR_UNIT,
		xdr_fattr4_fsid, NULL, "fattr4_fsid" },

	{ {FATTR4_UNIQUE_HANDLES_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_UNIQUE_HANDLES, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_unique_handles" },

	{ {FATTR4_LEASE_TIME_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_LEASE_TIME, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_lease_time" },

	{ {FATTR4_RDATTR_ERROR_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_RDATTR_ERROR, BYTES_PER_XDR_UNIT,
		xdr_int, NULL, "fattr4_rdattr_error" },

	{ {FATTR4_ACL_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ACL, 0,
		xdr_fattr4_acl, NULL, "fattr4_acl" },

	{ {FATTR4_ACLSUPPORT_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ACLSUPPORT, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_aclsupport" },

	{ {FATTR4_ARCHIVE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ARCHIVE, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_archive" },

	{ {FATTR4_CANSETTIME_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CANSETTIME, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_cansettime" },

	{ {FATTR4_CASE_INSENSITIVE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CASE_INSENSITIVE, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_case_insensitive" },

	{ {FATTR4_CASE_PRESERVING_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CASE_PRESERVING, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_case_preserving" },

	{ {FATTR4_CHOWN_RESTRICTED_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CHOWN_RESTRICTED, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_chown_restricted" },

	{ {FATTR4_FILEHANDLE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_FILEHANDLE, 0,
		xdr_nfs_fh4_modified, NULL, "fattr4_filehandle" },

	{ {FATTR4_FILEID_MASK, 0},
		AT_NODEID, FALSE, FALSE,
		FATTR4_FILEID, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_fileid" },

	{ {FATTR4_FILES_AVAIL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_AVAIL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_avail" },

	{ {FATTR4_FILES_FREE_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_FREE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_free" },

	{ {FATTR4_FILES_TOTAL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_TOTAL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_total" },

	{ {FATTR4_FS_LOCATIONS_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_FS_LOCATIONS, 0,
		xdr_fattr4_fs_locations, NULL, "fattr4_fs_locations" },

	{ {FATTR4_HIDDEN_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_HIDDEN, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_hidden" },

	{ {FATTR4_HOMOGENEOUS_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_HOMOGENEOUS, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_homogeneous" },

	{ {FATTR4_MAXFILESIZE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXFILESIZE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxfilesize" },

	{ {FATTR4_MAXLINK_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXLINK, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_maxlink" },

	{ {FATTR4_MAXNAME_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXNAME, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_maxname" },

	{ {FATTR4_MAXREAD_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXREAD, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxread" },

	{ {FATTR4_MAXWRITE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXWRITE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxwrite" },

	{ {FATTR4_MIMETYPE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MIMETYPE, 0,
		xdr_utf8string, NULL, "fattr4_mimetype" },

	{ {FATTR4_MODE_MASK, 0},
		AT_MODE, FALSE, FALSE,
		FATTR4_MODE, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_mode" },

	{ {FATTR4_NO_TRUNC_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_NO_TRUNC, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_no_trunc" },

	{ {FATTR4_NUMLINKS_MASK, 0},
		AT_NLINK, FALSE, FALSE,
		FATTR4_NUMLINKS, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_numlinks" },

	{ {FATTR4_OWNER_MASK, 0},
		AT_UID, FALSE, FALSE,
		FATTR4_OWNER, 0,
		xdr_utf8string,	NULL, "fattr4_owner" },

	{ {FATTR4_OWNER_GROUP_MASK, 0},
		AT_GID, FALSE, FALSE,
		FATTR4_OWNER_GROUP, 0,
		xdr_utf8string, NULL, "fattr4_owner_group" },

	{ {FATTR4_QUOTA_AVAIL_HARD_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_HARD, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_avail_hard" },

	{ {FATTR4_QUOTA_AVAIL_SOFT_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_SOFT, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_avail_soft" },

	{ {FATTR4_QUOTA_USED_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_USED, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_used" },

	{ {FATTR4_RAWDEV_MASK, 0},
		AT_RDEV, FALSE, FALSE,
		FATTR4_RAWDEV, 2 * BYTES_PER_XDR_UNIT,
		xdr_fattr4_rawdev, NULL, "fattr4_rawdev" },

	{ {FATTR4_SPACE_AVAIL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_AVAIL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_avail" },

	{ {FATTR4_SPACE_FREE_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_FREE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_free" },

	{ {FATTR4_SPACE_TOTAL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_TOTAL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_total" },

	{ {FATTR4_SPACE_USED_MASK, 0},
		AT_NBLOCKS, FALSE, FALSE,
		FATTR4_SPACE_USED, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_used" },

	{ {FATTR4_SYSTEM_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_SYSTEM, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_system" },

	{ {FATTR4_TIME_ACCESS_MASK, 0},
		AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_access" },

	{ {FATTR4_TIME_ACCESS_SET_MASK, 0},
		AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS_SET, 4 * BYTES_PER_XDR_UNIT,
		xdr_settime4, NULL, "fattr4_time_access_set" },

	{ {FATTR4_TIME_BACKUP_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_BACKUP, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_backup" },

	{ {FATTR4_TIME_CREATE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_CREATE, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_create" },

	{ {FATTR4_TIME_DELTA_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_DELTA, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_delta" },

	{ {FATTR4_TIME_METADATA_MASK, 0},
		AT_CTIME, FALSE, FALSE,
		FATTR4_TIME_METADATA, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_metadata" },

	{ {FATTR4_TIME_MODIFY_MASK, 0},
		AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_modify" },

	{ {FATTR4_TIME_MODIFY_SET_MASK, 0},
		AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY_SET, 4 * BYTES_PER_XDR_UNIT,
		xdr_settime4, NULL, "fattr4_time_modify_set" },

	{ {FATTR4_MOUNTED_ON_FILEID_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MOUNTED_ON_FILEID, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_mounted_on_fileid" },

	/* 56 */
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dir_notif_delay" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dirent_notify_delay" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dacl" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_sacl" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_change_policy" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_status" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_layout_type" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_layout_hint" },

	/* 64 */
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_layout_type" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_layout_blksize" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_layout_alignment" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_locations_info" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_mdsthreshold" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_get" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_set" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retentevt_get" },

	/* 72 */
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retentevt_set" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_hold" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_mode_set_masked" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_suppattr_exclcreat" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_charset_cap" }
};


struct nfs4_ntov_map nfs41_ntov_map[NFS41_ATTR_COUNT] = {
	/*
	 *	{ {fbit.d.d0, fbit.d.d1},
	 *		vbit, vfsstat, mandatory,
	 *		nval, xdr_size,
	 *		xfunc,	sv_getit, prtstr },
	 */
	{ {FATTR4_SUPPORTED_ATTRS_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_SUPPORTED_ATTRS, 4 * BYTES_PER_XDR_UNIT,
		xdr_attrmap4, NULL, "fattr4_supported_attrs" },

	{ {FATTR4_TYPE_MASK, 0},
		AT_TYPE, FALSE, TRUE,
		FATTR4_TYPE, BYTES_PER_XDR_UNIT,
		xdr_int, NULL, "fattr4_type" },

	{ {FATTR4_FH_EXPIRE_TYPE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_FH_EXPIRE_TYPE, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_fh_expire_type" },

	{ {FATTR4_CHANGE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_CHANGE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_change" },

	{ {FATTR4_SIZE_MASK, 0},
		AT_SIZE, FALSE, TRUE,
		FATTR4_SIZE,  2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_size" },

	{ {FATTR4_LINK_SUPPORT_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_LINK_SUPPORT, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_link_support" },

	{ {FATTR4_SYMLINK_SUPPORT_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_SYMLINK_SUPPORT, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_symlink_support" },

	{ {FATTR4_NAMED_ATTR_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_NAMED_ATTR, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_named_attr" },

	{ {FATTR4_FSID_MASK, 0},
		AT_FSID, FALSE, TRUE,
		FATTR4_FSID, 4 * BYTES_PER_XDR_UNIT,
		xdr_fattr4_fsid, NULL, "fattr4_fsid" },

	{ {FATTR4_UNIQUE_HANDLES_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_UNIQUE_HANDLES, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_unique_handles" },

	{ {FATTR4_LEASE_TIME_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_LEASE_TIME, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_lease_time" },

	{ {FATTR4_RDATTR_ERROR_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_RDATTR_ERROR, BYTES_PER_XDR_UNIT,
		xdr_int, NULL, "fattr4_rdattr_error" },

	{ {FATTR4_ACL_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ACL, 0,
		xdr_fattr4_acl, NULL, "fattr4_acl" },

	{ {FATTR4_ACLSUPPORT_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ACLSUPPORT, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_aclsupport" },

	{ {FATTR4_ARCHIVE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_ARCHIVE, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_archive" },

	{ {FATTR4_CANSETTIME_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CANSETTIME, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_cansettime" },

	{ {FATTR4_CASE_INSENSITIVE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CASE_INSENSITIVE, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_case_insensitive" },

	{ {FATTR4_CASE_PRESERVING_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CASE_PRESERVING, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_case_preserving" },

	{ {FATTR4_CHOWN_RESTRICTED_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_CHOWN_RESTRICTED, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_chown_restricted" },

	{ {FATTR4_FILEHANDLE_MASK, 0},
		0, FALSE, TRUE,
		FATTR4_FILEHANDLE, 0,
		xdr_nfs_fh41_modified, NULL, "fattr4_filehandle" },

	{ {FATTR4_FILEID_MASK, 0},
		AT_NODEID, FALSE, FALSE,
		FATTR4_FILEID, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_fileid" },

	{ {FATTR4_FILES_AVAIL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_AVAIL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_avail" },

	{ {FATTR4_FILES_FREE_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_FREE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_free" },

	{ {FATTR4_FILES_TOTAL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_FILES_TOTAL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_files_total" },

	{ {FATTR4_FS_LOCATIONS_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_FS_LOCATIONS, 0,
		xdr_fattr4_fs_locations, NULL, "fattr4_fs_locations" },

	{ {FATTR4_HIDDEN_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_HIDDEN, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_hidden" },

	{ {FATTR4_HOMOGENEOUS_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_HOMOGENEOUS, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_homogeneous" },

	{ {FATTR4_MAXFILESIZE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXFILESIZE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxfilesize" },

	{ {FATTR4_MAXLINK_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXLINK, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_maxlink" },

	{ {FATTR4_MAXNAME_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXNAME, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_maxname" },

	{ {FATTR4_MAXREAD_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXREAD, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxread" },

	{ {FATTR4_MAXWRITE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MAXWRITE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_maxwrite" },

	{ {FATTR4_MIMETYPE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MIMETYPE, 0,
		xdr_utf8string, NULL, "fattr4_mimetype" },

	{ {FATTR4_MODE_MASK, 0},
		AT_MODE, FALSE, FALSE,
		FATTR4_MODE, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_mode" },

	{ {FATTR4_NO_TRUNC_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_NO_TRUNC, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_no_trunc" },

	{ {FATTR4_NUMLINKS_MASK, 0},
		AT_NLINK, FALSE, FALSE,
		FATTR4_NUMLINKS, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_numlinks" },

	{ {FATTR4_OWNER_MASK, 0},
		AT_UID, FALSE, FALSE,
		FATTR4_OWNER, 0,
		xdr_utf8string,	NULL, "fattr4_owner" },

	{ {FATTR4_OWNER_GROUP_MASK, 0},
		AT_GID, FALSE, FALSE,
		FATTR4_OWNER_GROUP, 0,
		xdr_utf8string, NULL, "fattr4_owner_group" },

	{ {FATTR4_QUOTA_AVAIL_HARD_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_HARD, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_avail_hard" },

	{ {FATTR4_QUOTA_AVAIL_SOFT_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_AVAIL_SOFT, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_avail_soft" },

	{ {FATTR4_QUOTA_USED_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_QUOTA_USED, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_quota_used" },

	{ {FATTR4_RAWDEV_MASK, 0},
		AT_RDEV, FALSE, FALSE,
		FATTR4_RAWDEV, 2 * BYTES_PER_XDR_UNIT,
		xdr_fattr4_rawdev, NULL, "fattr4_rawdev" },

	{ {FATTR4_SPACE_AVAIL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_AVAIL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_avail" },

	{ {FATTR4_SPACE_FREE_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_FREE, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_free" },

	{ {FATTR4_SPACE_TOTAL_MASK, 0},
		0, TRUE, FALSE,
		FATTR4_SPACE_TOTAL, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_total" },

	{ {FATTR4_SPACE_USED_MASK, 0},
		AT_NBLOCKS, FALSE, FALSE,
		FATTR4_SPACE_USED, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_space_used" },

	{ {FATTR4_SYSTEM_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_SYSTEM, BYTES_PER_XDR_UNIT,
		xdr_bool, NULL, "fattr4_system" },

	{ {FATTR4_TIME_ACCESS_MASK, 0},
		AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_access" },

	{ {FATTR4_TIME_ACCESS_SET_MASK, 0},
		AT_ATIME, FALSE, FALSE,
		FATTR4_TIME_ACCESS_SET, 4 * BYTES_PER_XDR_UNIT,
		xdr_settime4, NULL, "fattr4_time_access_set" },

	{ {FATTR4_TIME_BACKUP_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_BACKUP, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_backup" },

	{ {FATTR4_TIME_CREATE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_CREATE, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_create" },

	{ {FATTR4_TIME_DELTA_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_TIME_DELTA, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_delta" },

	{ {FATTR4_TIME_METADATA_MASK, 0},
		AT_CTIME, FALSE, FALSE,
		FATTR4_TIME_METADATA, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_metadata" },

	{ {FATTR4_TIME_MODIFY_MASK, 0},
		AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY, 3 * BYTES_PER_XDR_UNIT,
		xdr_nfstime4, NULL, "fattr4_time_modify" },

	{ {FATTR4_TIME_MODIFY_SET_MASK, 0},
		AT_MTIME, FALSE, FALSE,
		FATTR4_TIME_MODIFY_SET, 4 * BYTES_PER_XDR_UNIT,
		xdr_settime4, NULL, "fattr4_time_modify_set" },

	{ {FATTR4_MOUNTED_ON_FILEID_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_MOUNTED_ON_FILEID, 2 * BYTES_PER_XDR_UNIT,
		xdr_u_longlong_t, NULL, "fattr4_mounted_on_fileid" },

	/* 56 */
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dir_notif_delay" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dirent_notify_delay" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_dacl" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_sacl" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_change_policy" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_status" },

	{ {FATTR4_FS_LAYOUT_TYPE_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_FS_LAYOUT_TYPE, 2 * BYTES_PER_XDR_UNIT,
		xdr_layouttypes4, NULL, "fattr4_fs_layout_types" },

	{ {FATTR4_LAYOUT_HINT_MASK, 0},
		0, FALSE, FALSE,
		FATTR4_LAYOUT_HINT, 5 * BYTES_PER_XDR_UNIT,
		xdr_file_layouthint4, NULL, "fattr4_layout_hint" },

	/* 64 */
	{ {0, FATTR4_LAYOUT_TYPE_MASK},
		0, FALSE, FALSE,
		FATTR4_LAYOUT_TYPE, 2 * BYTES_PER_XDR_UNIT,
		xdr_layouttypes4, NULL, "fattr4_layout_types" },

	{ {0, FATTR4_LAYOUT_BLKSIZE_MASK},
		0, FALSE, FALSE,
		FATTR4_LAYOUT_BLKSIZE, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_layout_blksize" },

	{ {0, FATTR4_LAYOUT_ALIGNMENT_MASK},
		0, FALSE, FALSE,
		FATTR4_LAYOUT_ALIGNMENT, BYTES_PER_XDR_UNIT,
		xdr_u_int, NULL, "fattr4_layout_alignment" },

	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_locations_info" },

	{ {0, FATTR4_MDSTHRESHOLD_MASK},
		0, FALSE, FALSE,
		FATTR4_MDSTHRESHOLD, 13 * BYTES_PER_XDR_UNIT,
		xdr_file_mdsthreshold4, NULL, "fattr4_mdsthreshold" },

	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_get" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_set" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retentevt_get" },

	/* 72 */
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retentevt_set" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_retention_hold" },
	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_mode_set_masked" },

	{ {0, FATTR4_SUPPATTR_EXCLCREAT_MASK},
		0, FALSE, FALSE,
		FATTR4_SUPPATTR_EXCLCREAT, 4 * BYTES_PER_XDR_UNIT,
		xdr_attrmap4, NULL, "fattr4_suppattr_exclcreat" },

	{ {0, 0}, 0, FALSE, FALSE, 0, 0, NULL, NULL,
		"fattr4_fs_charset_cap" }
};
