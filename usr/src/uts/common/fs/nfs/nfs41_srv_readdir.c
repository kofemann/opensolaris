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

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cred.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/uio.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/statvfs.h>
#include <sys/kmem.h>
#include <sys/dirent.h>
#include <rpc/types.h>
#include <rpc/auth.h>
#include <rpc/rpcsec_gss.h>
#include <rpc/svc.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/sdt.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_attrmap.h>
#include <nfs/nfs4_attr.h>
#include <nfs/nfs4_srv_attr.h>
#include <nfs/nfs4_srv_readdir.h>
#include <nfs/nfs41_filehandle.h>

/*
 * encode a filehandle all very special for readdir.
 */
static bool_t
encode_nfs41_fh(uint32_t **ptrp, uint32_t *ptr_redzone,
    nfs41_fh_fmt_t *fhp)
{
	XDR xdr;
	uint_t otw_len, ptr_size;
	uint32_t *ptr = *ptrp;

	otw_len = xdr_sizeof(xdr_nfs41_fh_fmt, fhp);

	/*
	 * Make sure we don't exceed our buffer, assume max fh size.
	 */
	if ((ptr + (otw_len  / BYTES_PER_XDR_UNIT)) > ptr_redzone) {
		DTRACE_PROBE(nfss41__e__redzone);
		return (FALSE);
	}

	IXDR_PUT_U_INT32(ptr, otw_len);

	ptr_size = ptr_redzone - ptr;

	xdrmem_create(&xdr, (char *)ptr, ptr_size, XDR_ENCODE);

	if (xdr_nfs41_fh_fmt(&xdr, fhp) == FALSE) {
		DTRACE_PROBE(nfss41__e__encode_fh);
		return (FALSE);
	}

	ptr += otw_len / BYTES_PER_XDR_UNIT;
	*ptrp = ptr;

	return (TRUE);
}

/* ARGSUSED */
void
mds_op_readdir(nfs_argop4 *argop, nfs_resop4 *resop,
    struct svc_req *req, compound_state_t *cs)
{
	READDIR4args *args = &argop->nfs_argop4_u.opreaddir;
	READDIR4res *resp = &resop->nfs_resop4_u.opreaddir;
	struct exportinfo *newexi = NULL;
	int error;
	mblk_t *mp;
	uint_t mpcount;
	int alloc_err = 0;
	vnode_t *dvp = cs->vp;
	vnode_t *vp;
	vattr_t va;
	struct dirent64 *dp;
	rfs4_sb_encode_t dsbe, sbe;
	int vfs_different;
	int rddir_data_len, rddir_result_size;
	caddr_t rddir_data;
	offset_t rddir_next_offset;
	int dircount;
	int no_space;
	int iseofdir;
	uint_t eof;
	struct iovec iov;
	struct uio uio;
	int tsize;
	int check_visible;
	int expseudo = 0;

	uint32_t *ptr, *ptr_redzone;
	uint32_t *beginning_ptr;
	uint32_t *lastentry_ptr;
	uint32_t attrmask_len;
	uint32_t *attrmask_ptr;
	uint32_t *attr_offset_ptr;
	uint32_t attr_length;
	uint32_t rndup;
	uint32_t namelen;
	uint32_t rddirattr_error = 0;
	int nents;
	attrmap4 ar, ae, minrddir;
	rfs4_pc_encode_t dpce, pce;
	ulong_t pc_val;
	uint64_t maxread;
	uint64_t maxwrite;
	uint_t true = TRUE;
	uint_t false = FALSE;
	uid_t lastuid;
	gid_t lastgid;
	int lu_set, lg_set;
	utf8string owner, group;
	int owner_error, group_error;
	attrvers_t avers;

	avers = RFS4_ATTRVERS(cs);
	ar = args->attr_request;
	ATTRMAP_MASK(ar, RFS4_RDDIR_SUPP_ATTRMAP(avers));
	minrddir = ar;
	if (ATTR_ISSET(ar, MOUNTED_ON_FILEID)) {
		ATTRMAP_MASK(minrddir, RFS4_MINRDDIR_MNTFILEID(avers));
	} else {
		ATTRMAP_MASK(minrddir, RFS4_MINRDDIR_FILEID(avers));
	}

	lu_set = lg_set = 0;
	owner.utf8string_len = group.utf8string_len = 0;
	owner.utf8string_val = group.utf8string_val = NULL;

	resp->mblk = NULL;

	/* Maximum read and write size */
	maxread = maxwrite = rfs4_tsize(req);

	if (dvp == NULL) {
		*cs->statusp = resp->status = NFS4ERR_NOFILEHANDLE;
		return;
	}

	/*
	 * If there is an unshared filesystem mounted on this vnode,
	 * do not allow readdir in this directory.
	 */
	if (vn_ismntpt(dvp)) {
		*cs->statusp = resp->status = NFS4ERR_ACCESS;
		return;
	}

	if (dvp->v_type != VDIR) {
		*cs->statusp = resp->status = NFS4ERR_NOTDIR;
		return;
	}

	if (args->maxcount <= RFS4_MINLEN_RDDIR4) {
		*cs->statusp = resp->status = NFS4ERR_TOOSMALL;
		return;
	}

	/*
	 * If write-only attrs are requested, then fail the readdir op
	 */
	if (ATTR_ISSET(ar, TIME_MODIFY_SET) ||
	    ATTR_ISSET(ar, TIME_ACCESS_SET) ||
	    ATTR_ISSET(ar, LAYOUT_HINT)) {
		*cs->statusp = resp->status = NFS4ERR_INVAL;
		return;
	}

	error = VOP_ACCESS(dvp, VREAD, 0, cs->cr, NULL);
	if (error) {
		*cs->statusp = resp->status = puterrno4(error);
		return;
	}

	if (args->cookieverf != Readdir4verf) {
		*cs->statusp = resp->status = NFS4ERR_NOT_SAME;
		return;
	}

	/* Is there pseudo-fs work that is needed for this readdir? */
	check_visible = PSEUDO(cs->exi) ||
	    ! is_exported_sec(cs->nfsflavor, cs->exi) ||
	    cs->access & CS_ACCESS_LIMITED;

	/* Check the requested attributes and only do the work if needed */

	if (ATTR_ISSET(ar, MAXFILESIZE) ||
	    ATTR_ISSET(ar, MAXLINK) ||
	    ATTR_ISSET(ar, MAXNAME)) {
		if (error = rfs4_get_pc_encode(cs->vp, &dpce, &ar, cs->cr)) {
			*cs->statusp = resp->status = puterrno4(error);
			return;
		}
		pce = dpce;
	}

	/* If there is statvfs data requested, pick it up once */
	if (ATTRMAP_TST(ar, RFS4_FS_SPACE_ATTRMAP(avers))) {
		if (error = rfs4_get_sb_encode(dvp->v_vfsp, &dsbe)) {
			*cs->statusp = resp->status = puterrno4(error);
			return;
		}
		sbe = dsbe;
	}

	/*
	 * Max transfer size of the server is the absolute limite.
	 * If the client has decided to max out with something really
	 * tiny, then return toosmall.  Otherwise, move forward and
	 * see if a single entry can be encoded.
	 */
	tsize = rfs4_tsize(req);
	if (args->maxcount > tsize)
		args->maxcount = tsize;
	else if (args->maxcount < RFS4_MINLEN_RDDIR_BUF) {
		if (args->maxcount < RFS4_MINLEN_ENTRY4) {
			*cs->statusp = resp->status = NFS4ERR_TOOSMALL;
			return;
		}
	}

	/*
	 * How large should the mblk be for outgoing encoding.
	 */
	if (args->maxcount < MAXBSIZE)
		mpcount = MAXBSIZE;
	else
		mpcount = args->maxcount;

	/*
	 * mp will contain the data to be sent out in the readdir reply.
	 * It will be freed after the reply has been sent.
	 * Let's roundup the data to a BYTES_PER_XDR_UNIX multiple,
	 * so that the call to xdrmblk_putmblk() never fails.
	 */
	mp = allocb(RNDUP(mpcount), BPRI_MED);

	if (mp == NULL) {
		/*
		 * The allocation of the client's requested size has
		 * failed.  It may be that the size is too large for
		 * current system utilization; step down to a "common"
		 * size and wait for the allocation to occur.
		 */
		if (mpcount > MAXBSIZE)
			args->maxcount = mpcount = MAXBSIZE;
		mp = allocb_wait(RNDUP(mpcount), BPRI_MED,
		    STR_NOSIG, &alloc_err);
	}

	ASSERT(mp != NULL);
	ASSERT(alloc_err == 0);

	resp->mblk = mp;

	ptr = beginning_ptr = (uint32_t *)mp->b_datap->db_base;

	/*
	 * The "redzone" at the end of the encoding buffer is used
	 * to deal with xdr encoding length.  Instead of checking
	 * each encoding of an attribute value before it is done,
	 * make the assumption that it will fit into the buffer and
	 * check occasionally.
	 *
	 * The largest block of attributes that are encoded without
	 * checking the redzone is 18 * BYTES_PER_XDR_UNIT (72 bytes)
	 * "round" to 128 as the redzone size.
	 */
	if (args->maxcount < (mpcount - 128))
		ptr_redzone =
		    (uint32_t *)(((char *)ptr) + RNDUP(args->maxcount));
	else
		ptr_redzone =
		    (uint32_t *)((((char *)ptr) + RNDUP(mpcount)) - 128);

	/*
	 * Set the dircount; this will be used as the size for the
	 * readdir of the underlying filesystem.  First make sure
	 * that it is large enough to do a reasonable readdir (client
	 * may have short changed us - it is an advisory number);
	 * then make sure that it isn't too large.
	 * After all of that, if maxcount is "small" then just use
	 * that for the dircount number.
	 */
	dircount = (args->dircount < MAXBSIZE) ? MAXBSIZE : args->dircount;
	dircount = (dircount > tsize) ? tsize : dircount;
	if (dircount > args->maxcount)
		dircount = args->maxcount;
	if (args->maxcount <= MAXBSIZE) {
		if (args->maxcount < RFS4_MINLEN_RDDIR_BUF)
			dircount = RFS4_MINLEN_RDDIR_BUF;
		else
			dircount = args->maxcount;
	}

	/* number of entries fully encoded in outgoing buffer */
	nents = 0;

	/* ENCODE READDIR4res.cookieverf */
	IXDR_PUT_HYPER(ptr, Readdir4verf);

	rddir_data_len = dircount;
	rddir_data = kmem_alloc(rddir_data_len, KM_NOSLEEP);
	if (rddir_data == NULL) {
		/* The allocation failed; downsize and wait for it this time */
		if (rddir_data_len > MAXBSIZE)
			rddir_data_len = dircount = MAXBSIZE;
		rddir_data = kmem_alloc(rddir_data_len, KM_SLEEP);
	}

	rddir_next_offset = (offset_t)args->cookie;

readagain:

	no_space = FALSE;
	iseofdir = FALSE;

	vp = NULL;

	/* Move on to reading the directory contents */
	iov.iov_base = rddir_data;
	iov.iov_len = rddir_data_len;
	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_extflg = UIO_COPY_CACHED;
	uio.uio_loffset = rddir_next_offset;
	uio.uio_resid = rddir_data_len;

	(void) VOP_RWLOCK(dvp, V_WRITELOCK_FALSE, NULL);

	error = VOP_READDIR(dvp, &uio, cs->cr, &iseofdir, NULL, 0);

	VOP_RWUNLOCK(dvp, V_WRITELOCK_FALSE, NULL);

	if (error) {
		kmem_free((caddr_t)rddir_data, rddir_data_len);
		freeb(resp->mblk);
		resp->mblk = NULL;
		resp->data_len = 0;
		*cs->statusp = resp->status = puterrno4(error);
		return;
	}


	rddir_result_size = rddir_data_len - uio.uio_resid;

	/* Reading at the end of the directory */
	if (iseofdir && (rddir_result_size == 0)) {

		/* encode the BOOLEAN marking no further entries */
		IXDR_PUT_U_INT32(ptr, false);

		/* encode the BOOLEAN signifying end of directory */
		IXDR_PUT_U_INT32(ptr, true);

		resp->data_len = (char *)ptr - (char *)beginning_ptr;
		resp->mblk->b_wptr += resp->data_len;
		kmem_free((caddr_t)rddir_data, rddir_data_len);
		*cs->statusp = resp->status = NFS4_OK;
		return;
	}

	lastentry_ptr = ptr;
	no_space = 0;
	for (dp = (struct dirent64 *)rddir_data;
	    !no_space && rddir_result_size > 0; dp = nextdp(dp)) {

		/* reset expseudo */
		expseudo = 0;

		if (vp) {
			VN_RELE(vp);
			vp = NULL;
		}

		if (newexi)
			newexi = NULL;

		rddir_result_size -= dp->d_reclen;

		/* skip "." and ".." entries */
		if (dp->d_ino == 0 || NFS_IS_DOTNAME(dp->d_name)) {
			rddir_next_offset = dp->d_off;
			continue;
		}

		if (check_visible &&
		    !nfs_visible_inode(cs->exi, dp->d_ino, &expseudo)) {
			rddir_next_offset = dp->d_off;
			continue;
		}

		/*
		 * Only if the client requested attributes...
		 * If the VOP_LOOKUP fails ENOENT, then skip this entry
		 * for the readdir response.  If there was another error,
		 * then set the rddirattr_error and the error will be
		 * encoded later in the "attributes" section.
		 */
		ae = ar;
		if (! ATTRMAP_EMPTY(ar)) {
			error = nfs4_readdir_getvp(dvp, dp->d_name,
			    &vp, &newexi, req, cs, expseudo);
			if (error == ENOENT) {
				rddir_next_offset = dp->d_off;
				continue;
			}

			rddirattr_error = error;

			/*
			 * The vp obtained from above may be from a
			 * different filesystem mount and the vfs-like
			 * attributes should be obtained from that
			 * different vfs; only do this if appropriate.
			 */
			if (vp &&
			    (vfs_different = (dvp->v_vfsp != vp->v_vfsp))) {
				if (ATTRMAP_TST(ar,
				    RFS4_FS_SPACE_ATTRMAP(avers))) {
					if (error =
					    rfs4_get_sb_encode(dvp->v_vfsp,
					    &sbe)) {
						/* Remove attrs from encode */
						ATTRMAP_CLR(ae,
						    RFS4_FS_SPACE_ATTRMAP(
						    avers));
						rddirattr_error = error;
					}
				}
				if (ATTR_ISSET(ar, MAXFILESIZE) ||
				    ATTR_ISSET(ar, MAXLINK) ||
				    ATTR_ISSET(ar, MAXNAME)) {
					if (error = rfs4_get_pc_encode(
					    cs->vp, &pce, &ar, cs->cr)) {
						ATTR_CLR(ar, MAXFILESIZE);
						ATTR_CLR(ar, MAXLINK);
						ATTR_CLR(ar, MAXNAME);
						rddirattr_error = error;
					}
				}
			}
		}

reencode_attrs:
		/* encode the BOOLEAN for the existence of the next entry */
		IXDR_PUT_U_INT32(ptr, true);
		/* encode the COOKIE for the entry */
		IXDR_PUT_U_HYPER(ptr, dp->d_off);

		/* Calculate the dirent name length */
		namelen = strlen(dp->d_name);
		rndup = RNDUP(namelen) / BYTES_PER_XDR_UNIT;

		/* room for LENGTH + string ? */
		if ((ptr + (1 + rndup)) > ptr_redzone) {
			no_space = TRUE;
			continue;
		}

		/* encode the LENGTH of the name */
		IXDR_PUT_U_INT32(ptr, namelen);
		/* encode the RNDUP FILL first */
		ptr[rndup - 1] = 0;
		/* encode the NAME of the entry */
		bcopy(dp->d_name, (char *)ptr, namelen);
		/* now bump the ptr after... */
		ptr += rndup;

		/*
		 * Keep checking on the dircount to see if we have
		 * reached the limit; from the RFC, dircount is to be
		 * the XDR encoded limit of the cookie plus name.
		 * So the count is the name, XDR_UNIT of length for
		 * that name and 2 * XDR_UNIT bytes of cookie;
		 * However, use the regular DIRENT64 to match most
		 * client's APIs.
		 */
		dircount -= DIRENT64_RECLEN(namelen);
		if (nents != 0 && dircount < 0) {
			no_space = TRUE;
			continue;
		}

		/*
		 * Attributes requested?
		 * Gather up the attribute info and the previous VOP_LOOKUP()
		 * succeeded; if an error occurs on the VOP_GETATTR() then
		 * return just the error (again if it is requested).
		 * Note that the previous VOP_LOOKUP() could have failed
		 * itself which leaves this code without anything for
		 * a VOP_GETATTR().
		 * Also note that the readdir_attr_error is left in the
		 * encoding mask if requested and so is the mounted_on_fileid.
		 */
		if (! ATTRMAP_EMPTY(ae)) {
			if (!vp) {
				ae = ar;
				ATTRMAP_MASK(ae,
				    RFS4_MINRDDIR_ATTRMAP(avers));
			} else {
				va.va_mask = AT_ALL;
				rddirattr_error =
				    VOP_GETATTR(vp, &va, 0, cs->cr, NULL);
				if (rddirattr_error) {
					ae = ar;
					ATTRMAP_MASK(ae,
					    RFS4_MINRDDIR_ATTRMAP(avers));
				}
			}
		}

		/* START OF ATTRIBUTE ENCODING */

		/* encode the BITMAP4 */
		IXDR_PUT_FATTR4_BITMAP(ptr, ae, attrmask_ptr, attrmask_len,
		    avers);
		attr_offset_ptr = ptr;
		/* encode the default LENGTH of the attributes for entry */
		IXDR_PUT_U_INT32(ptr, 0);

		if (ptr > ptr_redzone) {
			no_space = TRUE;
			continue;
		}

		/* Check if any of the first 32 attributes are being encoded */
		if (ae.w.w0) {
			/*
			 * [SUPPORTED_ATTRS - RDATTR_ERROR]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 18 * BYTES_PER_XDR_UNIT of data
			 */
			if (ATTR_ISSET(ae, SUPPORTED_ATTRS)) {
				IXDR_PUT_BITMAP4(ptr, RFS4_SUPP_ATTRMAP(avers));
			}
			if (ATTR_ISSET(ae, TYPE)) {
				uint_t ftype = vt_to_nf4[va.va_type];
				if (dvp->v_flag & V_XATTRDIR) {
					if (va.va_type == VDIR)
						ftype = NF4ATTRDIR;
					else
						ftype = NF4NAMEDATTR;
				}
				IXDR_PUT_U_INT32(ptr, ftype);
			}
			if (ATTR_ISSET(ae, FH_EXPIRE_TYPE)) {
				uint_t expire_type = FH4_PERSISTENT;
				IXDR_PUT_U_INT32(ptr, expire_type);
			}
			if (ATTR_ISSET(ae, CHANGE)) {
				u_longlong_t change;
				NFS4_SET_FATTR4_CHANGE(change, va.va_ctime);
				IXDR_PUT_HYPER(ptr, change);
			}
			if (ATTR_ISSET(ae, SIZE)) {
				u_longlong_t size = va.va_size;
				IXDR_PUT_HYPER(ptr, size);
			}
			if (ATTR_ISSET(ae, LINK_SUPPORT)) {
				IXDR_PUT_U_INT32(ptr, true);
			}
			if (ATTR_ISSET(ae, SYMLINK_SUPPORT)) {
				IXDR_PUT_U_INT32(ptr, true);
			}
			if (ATTR_ISSET(ae, NAMED_ATTR)) {
				uint_t isit;
				pc_val = FALSE;

				if (!(vp->v_vfsp->vfs_flag & VFS_XATTR)) {
					isit = FALSE;
				} else {
					(void) VOP_PATHCONF(vp,
					    _PC_XATTR_EXISTS, &pc_val,
					    cs->cr, NULL);
				}
				isit = (pc_val ? TRUE : FALSE);
				IXDR_PUT_U_INT32(ptr, isit);
			}
			if (ATTR_ISSET(ae, FSID)) {
				u_longlong_t major, minor;
				struct exportinfo *exi;

				exi = newexi ? newexi : cs->exi;
				if (exi->exi_volatile_dev) {
					int *pmaj = (int *)&major;

					pmaj[0] = exi->exi_fsid.val[0];
					pmaj[1] = exi->exi_fsid.val[1];
					minor = 0;
				} else {
					major = getmajor(va.va_fsid);
					minor = getminor(va.va_fsid);
				}
				IXDR_PUT_HYPER(ptr, major);
				IXDR_PUT_HYPER(ptr, minor);
			}
			if (ATTR_ISSET(ae, UNIQUE_HANDLES)) {
				IXDR_PUT_U_INT32(ptr, false);
			}
			if (ATTR_ISSET(ae, LEASE_TIME)) {
				uint_t lt = rfs4_lease_time;
				IXDR_PUT_U_INT32(ptr, lt);
			}
			if (ATTR_ISSET(ae, RDATTR_ERROR)) {
				rddirattr_error = (rddirattr_error == 0 ? 0 :
				    puterrno4(rddirattr_error));
				IXDR_PUT_U_INT32(ptr, rddirattr_error);
			}

			/*
			 * [SUPPORTED_ATTRS - RDATTR_ERROR]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [ACL - CHOWN_RESTRICTED]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 4 * BYTES_PER_XDR_UNIT of data.
			 * NOTE: that if ACLs are supported that the
			 * redzone calculations will need to change.
			 */
			ASSERT(ATTR_ISSET(ae, ACL) == 0);
			ASSERT(ATTR_ISSET(ae, ACLSUPPORT) == 0);
			ASSERT(ATTR_ISSET(ae, ARCHIVE) == 0);

			if (ATTR_ISSET(ae, CANSETTIME)) {
				IXDR_PUT_U_INT32(ptr, true);
			}

			if (ATTR_ISSET(ae, CASE_INSENSITIVE)) {
				IXDR_PUT_U_INT32(ptr, false);
			}

			if (ATTR_ISSET(ae, CASE_PRESERVING)) {
				IXDR_PUT_U_INT32(ptr, true);
			}

			if (ATTR_ISSET(ae, CHOWN_RESTRICTED)) {
				uint_t isit;
				pc_val = FALSE;
				(void) VOP_PATHCONF(vp, _PC_CHOWN_RESTRICTED,
				    &pc_val, cs->cr, NULL);
				isit = (pc_val ? TRUE : FALSE);
				IXDR_PUT_U_INT32(ptr, isit);
			}
			/*
			 * [ACL - CHOWN_RESTRICTED]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [FILEHANDLE - FILEID]
			 * Redzone check is done before the filehandle
			 * is encoded.
			 */
			if (ATTR_ISSET(ae, FILEHANDLE)) {
				struct {
					uint_t len;
					char *val;
					char fh[NFS41_FH_LEN];
				} fh;
				fh.len = 0;
				fh.val = fh.fh;
				(void) mknfs41_fh((nfs_fh4 *)&fh, vp,
				    (newexi ? newexi : cs->exi));

				if (!encode_nfs41_fh(
				    &ptr, ptr_redzone,
				    (nfs41_fh_fmt_t *)fh.val)) {
					if (nents || IS_MIN_ATTRMAP(ar)) {
						no_space = TRUE;
						continue;
					}
					MINIMIZE_ATTRMAP(ar, minrddir);
					ae = ar;
					ptr = lastentry_ptr;
					goto reencode_attrs;
				}
			}
			if (ATTR_ISSET(ae, FILEID)) {
				IXDR_PUT_HYPER(ptr, va.va_nodeid);
			}
			/*
			 * [FILEHANDLE - FILEID]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [FILES_AVAIL - MAXWRITE]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 15 * BYTES_PER_XDR_UNIT of data.
			 */
			if (ATTR_ISSET(ae, FILES_AVAIL)) {
				IXDR_PUT_HYPER(ptr, sbe.fa);
			}
			if (ATTR_ISSET(ae, FILES_FREE)) {
				IXDR_PUT_HYPER(ptr, sbe.ff);
			}
			if (ATTR_ISSET(ae, FILES_TOTAL)) {
				IXDR_PUT_HYPER(ptr, sbe.ft);
			}

			ASSERT(ATTR_ISSET(ae, FS_LOCATIONS) == 0);
			ASSERT(ATTR_ISSET(ae, HIDDEN) == 0);

			if (ATTR_ISSET(ae, HOMOGENEOUS)) {
				IXDR_PUT_U_INT32(ptr, true);
			}
			if (ATTR_ISSET(ae, MAXFILESIZE)) {
				IXDR_PUT_HYPER(ptr, pce.maxfilesize);
			}
			if (ATTR_ISSET(ae, MAXLINK)) {
				IXDR_PUT_U_INT32(ptr, pce.maxlink);
			}
			if (ATTR_ISSET(ae, MAXNAME)) {
				IXDR_PUT_U_INT32(ptr, pce.maxname);
			}
			if (ATTR_ISSET(ae, MAXREAD)) {
				IXDR_PUT_HYPER(ptr, maxread);
			}
			if (ATTR_ISSET(ae, MAXWRITE)) {
				IXDR_PUT_HYPER(ptr, maxwrite);
			}
			/*
			 * [FILES_AVAIL - MAXWRITE]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}
		}
		if (ae.w.w1) {
			/*
			 * [MIMETYPE - NUMLINKS]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 3 * BYTES_PER_XDR_UNIT of data.
			 */
			ASSERT(ATTR_ISSET(ae, MIMETYPE) == 0);

			if (ATTR_ISSET(ae, MODE)) {
				uint_t m = va.va_mode;
				IXDR_PUT_U_INT32(ptr, m);
			}
			if (ATTR_ISSET(ae, NO_TRUNC)) {
				IXDR_PUT_U_INT32(ptr, true);
			}
			if (ATTR_ISSET(ae, NUMLINKS)) {
				IXDR_PUT_U_INT32(ptr, va.va_nlink);
			}
			/*
			 * [MIMETYPE - NUMLINKS]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * OWNER
			 * Redzone check is done before the encoding of the
			 * owner string since the length is indeterminate.
			 */
			if (ATTR_ISSET(ae, OWNER)) {
				if (!lu_set) {
					owner_error = nfs_idmap_uid_str(
					    va.va_uid, &owner, TRUE);
					if (!owner_error) {
						lu_set = TRUE;
						lastuid = va.va_uid;
					}
				} else {
					if (va.va_uid != lastuid) {
						if (owner.utf8string_len != 0) {
							kmem_free(
							    owner.
							    utf8string_val,
							    owner.
							    utf8string_len);
							owner.utf8string_len =
							    0;
							owner.utf8string_val =
							    NULL;
						}
						owner_error = nfs_idmap_uid_str(
						    va.va_uid, &owner, TRUE);
						if (!owner_error) {
							lastuid = va.va_uid;
						} else {
							lu_set = FALSE;
						}
					}
				}
				if (!owner_error) {
					if ((ptr +
					    (owner.utf8string_len /
					    BYTES_PER_XDR_UNIT)
					    + 2) > ptr_redzone) {
						if (nents ||
						    IS_MIN_ATTRMAP(ar)) {
							no_space = TRUE;
							continue;
						}
						MINIMIZE_ATTRMAP(ar, minrddir);
						ae = ar;
						ptr = lastentry_ptr;
						goto reencode_attrs;
					}
					/* encode the LENGTH of owner string */
					IXDR_PUT_U_INT32(ptr,
					    owner.utf8string_len);
					/* encode the RNDUP FILL first */
					rndup = RNDUP(owner.utf8string_len) /
					    BYTES_PER_XDR_UNIT;
					ptr[rndup - 1] = 0;
					/* encode the OWNER */
					bcopy(owner.utf8string_val, ptr,
					    owner.utf8string_len);
					ptr += rndup;
				}
			}
			/*
			 * OWNER_GROUP
			 * Redzone check is done before the encoding of the
			 * group string since the length is indeterminate.
			 */
			if (ATTR_ISSET(ae, OWNER_GROUP)) {
				if (!lg_set) {
					group_error = nfs_idmap_gid_str(
					    va.va_gid, &group, TRUE);
					if (!group_error) {
						lg_set = TRUE;
						lastgid = va.va_gid;
					}
				} else {
					if (va.va_gid != lastgid) {
						if (group.utf8string_len != 0) {
							kmem_free(
							    group.
							    utf8string_val,
							    group.
							    utf8string_len);
							group.utf8string_len =
							    0;
							group.utf8string_val =
							    NULL;
						}
						group_error =
						    nfs_idmap_gid_str(va.va_gid,
						    &group, TRUE);
						if (!group_error)
							lastgid = va.va_gid;
						else
							lg_set = FALSE;
					}
				}
				if (!group_error) {
					if ((ptr +
					    (group.utf8string_len /
					    BYTES_PER_XDR_UNIT)
					    + 2) > ptr_redzone) {
						if (nents ||
						    IS_MIN_ATTRMAP(ar)) {
							no_space = TRUE;
							continue;
						}
						MINIMIZE_ATTRMAP(ar, minrddir);
						ae = ar;
						ptr = lastentry_ptr;
						goto reencode_attrs;
					}
					/* encode the LENGTH of owner string */
					IXDR_PUT_U_INT32(ptr,
					    group.utf8string_len);
					/* encode the RNDUP FILL first */
					rndup = RNDUP(group.utf8string_len) /
					    BYTES_PER_XDR_UNIT;
					ptr[rndup - 1] = 0;
					/* encode the OWNER */
					bcopy(group.utf8string_val, ptr,
					    group.utf8string_len);
					ptr += rndup;
				}
			}
			ASSERT(ATTR_ISSET(ae, QUOTA_AVAIL_HARD) == 0);
			ASSERT(ATTR_ISSET(ae, QUOTA_AVAIL_SOFT) == 0);
			ASSERT(ATTR_ISSET(ae, QUOTA_USED) == 0);

			/*
			 * [RAWDEV - SYSTEM]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 10 * BYTES_PER_XDR_UNIT of data.
			 */
			if (ATTR_ISSET(ae, RAWDEV)) {
				fattr4_rawdev rd;
				rd.specdata1 = (uint32)getmajor(va.va_rdev);
				rd.specdata2 = (uint32)getminor(va.va_rdev);
					IXDR_PUT_U_INT32(ptr, rd.specdata1);
					IXDR_PUT_U_INT32(ptr, rd.specdata2);
			}
			if (ATTR_ISSET(ae, SPACE_AVAIL)) {
				IXDR_PUT_HYPER(ptr, sbe.space_avail);
			}
			if (ATTR_ISSET(ae, SPACE_FREE)) {
				IXDR_PUT_HYPER(ptr, sbe.space_free);
			}
			if (ATTR_ISSET(ae, SPACE_TOTAL)) {
				IXDR_PUT_HYPER(ptr, sbe.space_total);
			}
			if (ATTR_ISSET(ae, SPACE_USED)) {
				u_longlong_t su;
				su = (fattr4_space_used) DEV_BSIZE *
				    (fattr4_space_used) va.va_nblocks;
				IXDR_PUT_HYPER(ptr, su);
			}
			ASSERT(ATTR_ISSET(ae, SYSTEM) == 0);

			/*
			 * [RAWDEV - SYSTEM]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [TIME_ACCESS - MOUNTED_ON_FILEID]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 14 * BYTES_PER_XDR_UNIT of data.
			 */
			if (ATTR_ISSET(ae, TIME_ACCESS)) {
				u_longlong_t sec =
				    (u_longlong_t)va.va_atime.tv_sec;
				uint_t nsec = (uint_t)va.va_atime.tv_nsec;
				IXDR_PUT_HYPER(ptr, sec);
				IXDR_PUT_INT32(ptr, nsec);
			}
			ASSERT(ATTR_ISSET(ae, TIME_ACCESS_SET) == 0);
			ASSERT(ATTR_ISSET(ae, TIME_BACKUP) == 0);
			ASSERT(ATTR_ISSET(ae, TIME_CREATE) == 0);

			if (ATTR_ISSET(ae, TIME_DELTA)) {
				u_longlong_t sec = 0;
				uint_t nsec = 1000;
				IXDR_PUT_HYPER(ptr, sec);
				IXDR_PUT_INT32(ptr, nsec);
			}
			if (ATTR_ISSET(ae, TIME_METADATA)) {
				u_longlong_t sec =
				    (u_longlong_t)va.va_ctime.tv_sec;
				uint_t nsec = (uint_t)va.va_ctime.tv_nsec;
				IXDR_PUT_HYPER(ptr, sec);
				IXDR_PUT_INT32(ptr, nsec);
			}
			if (ATTR_ISSET(ae, TIME_MODIFY)) {
				u_longlong_t sec =
				    (u_longlong_t)va.va_mtime.tv_sec;
				uint_t nsec = (uint_t)va.va_mtime.tv_nsec;
				IXDR_PUT_HYPER(ptr, sec);
				IXDR_PUT_INT32(ptr, nsec);
			}
			ASSERT(ATTR_ISSET(ae, TIME_MODIFY_SET) == 0);

			if (ATTR_ISSET(ae, MOUNTED_ON_FILEID)) {
				IXDR_PUT_HYPER(ptr, dp->d_ino);
			}
			/*
			 * [TIME_ACCESS - MOUNTED_ON_FILEID]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [DIR_NOTIF_DELAY - LAYOUT_HINT]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 2 * BYTES_PER_XDR_UNIT of data.
			 */
			ASSERT(ATTR_ISSET(ae, DIR_NOTIF_DELAY) == 0);
			ASSERT(ATTR_ISSET(ae, DIRENT_NOTIF_DELAY) == 0);
			ASSERT(ATTR_ISSET(ae, DACL) == 0);
			ASSERT(ATTR_ISSET(ae, SACL) == 0);
			ASSERT(ATTR_ISSET(ae, CHANGE_POLICY) == 0);
			ASSERT(ATTR_ISSET(ae, FS_STATUS) == 0);

			if (ATTR_ISSET(ae, FS_LAYOUT_TYPE)) {
				IXDR_PUT_INT32(ptr, 1);
				IXDR_PUT_INT32(ptr, LAYOUT4_NFSV4_1_FILES);
			}

			/* write only attr */
			ASSERT(ATTR_ISSET(ae, LAYOUT_HINT) == 0);

			/*
			 * [DIR_NOTIF_DELAY - LAYOUT_HINT]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}
		}

		if (ae.w.w2) {
			/*
			 * [LAYOUT_TYPE - RETENTEVT_GET]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 17 * BYTES_PER_XDR_UNIT of data.
			 */
			if (ATTR_ISSET(ae, LAYOUT_TYPE)) {
				IXDR_PUT_INT32(ptr, 1);
				IXDR_PUT_INT32(ptr, LAYOUT4_NFSV4_1_FILES);
			}

			if (ATTR_ISSET(ae, LAYOUT_BLKSIZE)) {
				IXDR_PUT_INT32(ptr,
				    RFS41_DEFAULT_LAYOUT_BLKSIZE);
			}

			if (ATTR_ISSET(ae, LAYOUT_ALIGNMENT)) {
				IXDR_PUT_INT32(ptr,
				    RFS41_DEFAULT_LAYOUT_ALIGNMENT);
			}

			ASSERT(ATTR_ISSET(ae, FS_LOCATIONS_INFO) == 0);

			if (ATTR_ISSET(ae, MDSTHRESHOLD)) {
				uint64_t zero = 0;
				uint32_t mth = (TH4_READ_SIZE_MASK |
				    TH4_WRITE_SIZE_MASK |
				    TH4_READ_IOSIZE_MASK |
				    TH4_WRITE_IOSIZE_MASK);

				IXDR_PUT_INT32(ptr, 1);
				IXDR_PUT_INT32(ptr, LAYOUT4_NFSV4_1_FILES);
				IXDR_PUT_INT32(ptr, 1);
				IXDR_PUT_INT32(ptr, mth);
				IXDR_PUT_INT32(ptr,
				    (BYTES_PER_XDR_UNIT * 2) * 4);
				IXDR_PUT_HYPER(ptr, zero);
				IXDR_PUT_HYPER(ptr, zero);
				IXDR_PUT_HYPER(ptr, zero);
				IXDR_PUT_HYPER(ptr, zero);
			}

			ASSERT(ATTR_ISSET(ae, RETENTION_GET)  == 0);
			ASSERT(ATTR_ISSET(ae, RETENTION_SET)  == 0);
			ASSERT(ATTR_ISSET(ae, RETENTEVT_GET)  == 0);

			/*
			 * [LAYOUT_TYPE - RETENTEVT_GET]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}

			/*
			 * [RETENTEVT - FS_CHARSET_CAP]
			 * Redzone check is done at the end of this section.
			 * This particular section will encode a maximum of
			 * 3 * BYTES_PER_XDR_UNIT of data.
			 */
			ASSERT(ATTR_ISSET(ae, RETENTEVT_SET)  == 0);
			ASSERT(ATTR_ISSET(ae, RETENTION_HOLD)  == 0);
			ASSERT(ATTR_ISSET(ae, MODE_SET_MASKED) == 0);

			if (ATTR_ISSET(ae, SUPPATTR_EXCLCREAT)) {
				IXDR_PUT_BITMAP4(ptr,
				    RFS41_EXCLCREAT_ATTRMAP(avers));
			}

			ASSERT(ATTR_ISSET(ae, FS_CHARSET_CAP) == 0);

			/*
			 * [RETENTEVT - FS_CHARSET_CAP]
			 * Check the redzone boundary
			 */
			if (ptr > ptr_redzone) {
				if (nents || IS_MIN_ATTRMAP(ar)) {
					no_space = TRUE;
					continue;
				}
				MINIMIZE_ATTRMAP(ar, minrddir);
				ae = ar;
				ptr = lastentry_ptr;
				goto reencode_attrs;
			}
		}

		/* Reset to directory's vfs info when encoding complete */
		if (vfs_different) {
			dsbe = sbe;
			dpce = pce;
			vfs_different = 0;
		}

		/* "go back" and encode the attributes' length */
		attr_length = (char *)ptr - (char *)attr_offset_ptr -
		    BYTES_PER_XDR_UNIT;
		IXDR_PUT_U_INT32(attr_offset_ptr, attr_length);

		/*
		 * If there was trouble obtaining a mapping for either
		 * the owner or group attributes, then remove them from
		 * bitmap4 for this entry and reset the bitmap value
		 * in the data stream.
		 */
		if (owner_error || group_error) {
			if (owner_error)
				ATTR_CLR(ae, OWNER);
			if (group_error)
				ATTR_CLR(ae, OWNER_GROUP);
			IXDR_REWRITE_FATTR4_BITMAP(attrmask_ptr, ae,
			    attrmask_len, avers);
		}

		/* END OF ATTRIBUTE ENCODING */

		lastentry_ptr = ptr;
		nents++;
		rddir_next_offset = dp->d_off;
	}

	/*
	 * Check for the case that another VOP_READDIR() has to be done.
	 * - no space encoding error
	 * - no entry successfully encoded
	 * - still more directory to read
	 */
	if (!no_space && nents == 0 && !iseofdir)
		goto readagain;

	*cs->statusp = resp->status = NFS4_OK;

	/*
	 * If no_space is set then we terminated prematurely,
	 * rewind to the last entry and this can never be EOF.
	 */
	if (no_space) {
		ptr = lastentry_ptr;
		eof = FALSE; /* ended encoded prematurely */
	} else {
		eof = (iseofdir ? TRUE : FALSE);
	}

	/*
	 * If we have entries, always return them, otherwise only error
	 * if we ran out of space.
	 */
	if (nents || !no_space) {
		ASSERT(ptr != NULL);
		/* encode the BOOLEAN marking no further entries */
		IXDR_PUT_U_INT32(ptr, false);
		/* encode the BOOLEAN signifying end of directory */
		IXDR_PUT_U_INT32(ptr, eof);

		resp->data_len = (char *)ptr - (char *)beginning_ptr;
		resp->mblk->b_wptr += resp->data_len;
	} else {
		freeb(mp);
		resp->mblk = NULL;
		resp->data_len = 0;
		*cs->statusp = resp->status = NFS4ERR_TOOSMALL;
	}

	kmem_free((caddr_t)rddir_data, rddir_data_len);
	if (vp)
		VN_RELE(vp);
	if (owner.utf8string_len != 0)
		kmem_free(owner.utf8string_val,	owner.utf8string_len);
	if (group.utf8string_len != 0)
		kmem_free(group.utf8string_val, group.utf8string_len);
}
