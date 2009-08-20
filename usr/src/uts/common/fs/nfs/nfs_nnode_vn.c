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

#include <nfs/nnode_vn.h>
#include <sys/vnode.h>
#include <nfs/nfs41_filehandle.h>
#include <nfs/ds_filehandle.h>
#include <nfs/nfs41_fhtype.h>

#include <sys/crc32.h>
#include <sys/nbmlock.h>

static uint32_t nnode_key_fid_hash(nnode_fid_key_t *);
static int nnode_compare_fsid(const void *, const void *);
static nnode_error_t nnode_from_fh_v41_nfs(nnode_t **, nfs_fh4 *);
static void nnode_fid_key_v41_free(void *);
static void nnode_fid_key_v4_free(void *);
static void nnode_fid_key_v3_free(void *);
static void nnode_fid_key_vp_free(void *);
static nnode_error_t nnode_build_v41(nnode_seed_t *, void *);
static nnode_error_t nnode_build_v4(nnode_seed_t *, void *);
static nnode_error_t nnode_build_v3(nnode_seed_t *, void *);
static nnode_error_t nnode_build_vp(nnode_seed_t *, void *);
static int nnode_fid_key_v41_construct(void *, void *, int);
static int nnode_fid_key_v4_construct(void *, void *, int);
static int nnode_fid_key_v3_construct(void *, void *, int);
static int nnode_fid_key_vp_construct(void *, void *, int);
static int nnode_vn_data_construct(void *, void *, int);
static void nnode_vn_data_destroy(void *, void *);
static nnode_vn_data_t *nnode_vn_data_alloc(void);
static void nnode_vn_data_free(void *);
static nnode_vn_md_t *nnode_vn_md_alloc(void);
static void nnode_vn_md_free(void *);
static nnode_vn_state_t *nnode_vn_state_alloc(void);
static void nnode_vn_state_free(void *);
void nnode_data_setup(nnode_seed_t *, vnode_t *, fsid_t, int, char *,
    exportinfo_t *);
void nnode_vn_data_setup(nnode_seed_t *, vnode_t *, exportinfo_t *);
void nnode_proxy_data_setup(nnode_seed_t *, vnode_t *, fsid_t, int, char *);

int nnode_vn_io_prep(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, offset_t, size_t, bslabel_t *);
int nnode_vn_read(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, uio_t *, int);
int nnode_vn_write(void *, nnode_io_flags_t *, uio_t *, int, cred_t *,
    caller_context_t *, wcc_data *);
void nnode_vn_io_release(void *, nnode_io_flags_t, caller_context_t *);
void nnode_vn_post_op_attr(void *, post_op_attr *);
void nnode_vn_wcc_data_err(void *, wcc_data *);
vnode_t *nnode_vn_io_getvp(void *);

static vnode_t *nnode_vn_md_getvp(void *);

static nfsstat4 nnode_vn_st_checkstate(void *, compound_state_t *, int,
    stateid4 *, bool_t, bool_t *, bool_t, caller_context_t *, clientid4 *);

static nnode_data_ops_t nnode_vn_data_ops = {
	.ndo_io_prep = nnode_vn_io_prep,
	.ndo_read = nnode_vn_read,
	.ndo_write = nnode_vn_write,
	.ndo_io_release = nnode_vn_io_release,
	.ndo_post_op_attr = nnode_vn_post_op_attr,
	.ndo_wcc_data_err = nnode_vn_wcc_data_err,
	.ndo_getvp = nnode_vn_io_getvp,
	.ndo_free = nnode_vn_data_free
};
static nnode_metadata_ops_t nnode_vn_md_ops = {
	.nmo_getvp = nnode_vn_md_getvp,
	.nmo_free = nnode_vn_md_free
};
static nnode_state_ops_t nnode_vn_state_ops = {
	.nso_checkstate = nnode_vn_st_checkstate,
	.nso_free = nnode_vn_state_free
};

static kmem_cache_t *nnode_vn_data_cache;
static kmem_cache_t *nnode_vn_md_cache;
static kmem_cache_t *nnode_vn_state_cache;
static kmem_cache_t *nnode_fid_key_v41_cache;
static kmem_cache_t *nnode_fid_key_v4_cache;
static kmem_cache_t *nnode_fid_key_v3_cache;
static kmem_cache_t *nnode_fid_key_vp_cache;

extern int nfs_ds_present;

/* vnode-based nnode ops */

/*
 * Prepare for i/o.
 *
 * Do the "critical" rain dance, check permissions, return the actual size.
 */

int
nnode_vn_io_prep(void *vdata, nnode_io_flags_t *flags, cred_t *cr,
    caller_context_t *ct, offset_t off, size_t len, bslabel_t *clabel)
{
	nnode_vn_data_t *data = vdata;
	vnode_t *vp = data->nvd_vp;
	nbl_op_t op;
	vattr_t *vap;
	int rc;
	int lockstatus;
	int acc, writelock, labelcheck;

	*flags &= ~NNODE_IO_FLAG_IN_CRIT;

	if (*flags & NNODE_IO_FLAG_WRITE) {
		op = NBL_WRITE;
		acc = VWRITE;
		writelock = V_WRITELOCK_TRUE;
		labelcheck = EQUALITY_CHECK;
	} else {
		op = NBL_READ;
		acc = VREAD;
		writelock = V_WRITELOCK_FALSE;
		labelcheck = DOMINANCE_CHECK;
	}

	if (vp->v_type != VREG) {
		rc = (vp->v_type == VDIR) ? NNODE_ERROR_IODIR : EINVAL;
		goto out;
	}

	if ((clabel != NULL) && (!blequal(&l_admin_low->tsl_label, clabel)) &&
	    (!do_rfs_label_check(clabel, vp, labelcheck, data->nvd_exi))) {
		rc = EACCES;
		goto out;
	}

	if (nbl_need_check(vp)) {
		nbl_start_crit(vp, RW_READER);
		*flags |= NNODE_IO_FLAG_IN_CRIT;
		if (nbl_conflict(vp, op, off, len, 0, ct)) {
			rc = NNODE_ERROR_LOCK;
			goto out;
		}
	}

	mutex_enter(&data->nvd_lock);
	data->nvd_flags &= ~NNODE_NVD_VATTR_VALID;
	vap = &data->nvd_vattr;
	vap->va_mask = AT_MODE | AT_UID | AT_SIZE | AT_MTIME | AT_SEQ;
	rc = VOP_GETATTR(vp, vap, 0, cr, ct);
	if (rc != 0) {
		mutex_exit(&data->nvd_lock);
		goto out;
	}
	data->nvd_flags |= NNODE_NVD_VATTR_VALID;
	mutex_exit(&data->nvd_lock);

	if (crgetuid(cr) != vap->va_uid) {
		rc = VOP_ACCESS(vp, acc, 0, cr, ct);
		if (rc != 0) {
			if (*flags & NNODE_IO_FLAG_WRITE) {
				goto out;
			} else {
				rc = VOP_ACCESS(vp, VEXEC, 0, cr, ct);
				if (rc != 0)
					goto out;
			}
		}
	}

	if (MANDLOCK(vp, vap->va_mode)) {
		rc = EACCES;
		goto out;
	}

	if (off > vap->va_size)
		*flags |= NNODE_IO_FLAG_PAST_EOF;

	/*
	 * XXX: Need to investigate and ensure that the pNFS gate code is aware
	 * of the proper  usage rules while calling VOP_RWLOCK if we intend to
	 * support UFS file systems with forcedirectio on the server.
	 */

	lockstatus = VOP_RWLOCK(vp, writelock, ct);
	if ((lockstatus == EAGAIN) && (ct->cc_flags & CC_WOULDBLOCK)) {
		rc = NNODE_ERROR_AGAIN;
	} else {
		*flags |= NNODE_IO_FLAG_RWLOCK;
		rc = 0;
	}

out:
	if (rc != 0) {
		if (*flags & NNODE_IO_FLAG_IN_CRIT) {
			nbl_end_crit(vp);
			*flags &= ~NNODE_IO_FLAG_IN_CRIT;
		}
		if (*flags & NNODE_IO_FLAG_RWLOCK) {
			VOP_RWUNLOCK(vp, writelock, ct);
			*flags &= ~NNODE_IO_FLAG_RWLOCK;
		}
	}

	return (rc);
}

int
nnode_vn_read(void *vdata, nnode_io_flags_t *flags, cred_t *cr,
    caller_context_t *ct, uio_t *uiop, int ioflag)
{
	nnode_vn_data_t *data = vdata;
	vnode_t *vp = data->nvd_vp;
	vattr_t *vap = &data->nvd_vattr;
	uint64_t off;
	uint64_t moved;
	int rc;

	ASSERT((*flags & (NNODE_IO_FLAG_WRITE | NNODE_IO_FLAG_EOF)) == 0);

	off = uiop->uio_loffset;
	moved = uiop->uio_resid;

	rc = VOP_READ(vp, uiop, ioflag, cr, ct);
	if (rc != 0)
		goto out;

	moved -= uiop->uio_resid;

	mutex_enter(&data->nvd_lock);
	vap->va_mask = AT_ALL;
	rc = VOP_GETATTR(vp, vap, 0, cr, ct);
	if (rc != 0) {
		data->nvd_flags &= ~NNODE_NVD_VATTR_VALID;
		mutex_exit(&data->nvd_lock);
		goto out;
	}
	data->nvd_flags |= NNODE_NVD_VATTR_VALID;
	mutex_exit(&data->nvd_lock);

	if (off + moved == vap->va_size)
		*flags |= NNODE_IO_FLAG_EOF;
	else
		*flags &= ~NNODE_IO_FLAG_EOF;
out:

	return (rc);
}

int
nnode_vn_write(void *vdata, nnode_io_flags_t *flags, uio_t *uiop, int ioflags,
    cred_t *cr, caller_context_t *ct, wcc_data *wcc)
{
	nnode_vn_data_t *data = vdata;
	vnode_t *vp = data->nvd_vp;
	vattr_t before, *beforep, *afterp;
	int rc;

	ASSERT(*flags & NNODE_IO_FLAG_WRITE);

	rc = VOP_WRITE(vp, uiop, ioflags, cr, ct);
	if (rc != 0)
		goto out;

	mutex_enter(&data->nvd_lock);
	if (wcc != NULL) {
		if (data->nvd_flags & NNODE_NVD_VATTR_VALID) {
			bcopy(&data->nvd_vattr, &before, sizeof (before));
			beforep = &before;
		} else {
			beforep = NULL;
		}
	}
	data->nvd_vattr.va_mask = AT_ALL;
	if (VOP_GETATTR(vp, &data->nvd_vattr, 0, cr, ct) == 0) {
		data->nvd_flags |= NNODE_NVD_VATTR_VALID;
		afterp = &data->nvd_vattr;
	} else {
		data->nvd_flags &= ~NNODE_NVD_VATTR_VALID;
		afterp = NULL;
	}
	if (wcc != NULL) {
		if ((beforep != NULL) && ((beforep->va_mask &
		    (AT_SIZE | AT_MTIME | AT_SEQ)) !=
		    (AT_SIZE | AT_MTIME | AT_SEQ)))
			beforep = NULL;
		if ((beforep != NULL) && (afterp != NULL) &&
		    (beforep->va_seq + 1 != afterp->va_seq))
			beforep = NULL;
		vattr_to_wcc_data(beforep, afterp, wcc);
	}
	mutex_exit(&data->nvd_lock);

out:

	return (rc);
}

void
nnode_vn_io_release(void *vdata, nnode_io_flags_t flags, caller_context_t *ct)
{
	nnode_vn_data_t *data = vdata;
	vnode_t *vp = data->nvd_vp;
	int which;

	which = (flags & NNODE_IO_FLAG_WRITE) ? V_WRITELOCK_TRUE :
	    V_WRITELOCK_FALSE;

	if (flags & NNODE_IO_FLAG_RWLOCK)
		VOP_RWUNLOCK(vp, which, ct);
	if (flags & NNODE_IO_FLAG_IN_CRIT)
		nbl_end_crit(vp);
}

void
nnode_vn_post_op_attr(void *vdata, post_op_attr *poa)
{
	nnode_vn_data_t *data = vdata;

	vattr_to_post_op_attr(&data->nvd_vattr, poa);
}

void
nnode_vn_wcc_data_err(void *vdata, wcc_data *wcc)
{
	nnode_vn_data_t *data = vdata;
	vattr_t *before;

	mutex_enter(&data->nvd_lock);
	before = (data->nvd_flags & NNODE_NVD_VATTR_VALID) ?
	    &data->nvd_vattr : NULL;
	vattr_to_wcc_data(before, NULL, wcc);
	mutex_exit(&data->nvd_lock);
}

vnode_t *
nnode_vn_io_getvp(void *vdata)
{
	nnode_vn_data_t *data = vdata;
	vnode_t *vp = data->nvd_vp;

	VN_HOLD(vp);

	return (vp);
}

static vnode_t *
nnode_vn_md_getvp(void *vmd)
{
	nnode_vn_md_t *md = vmd;
	vnode_t *vp = md->nvm_vp;

	VN_HOLD(vp);

	return (vp);
}

static nfsstat4
nnode_vn_st_checkstate(void *vstate, compound_state_t *cs, int mode,
    stateid4 *stateid, bool_t trunc, bool_t *deleg, bool_t do_access,
    caller_context_t *ct, clientid4 *clientid)
{
	nnode_vn_state_t *state = vstate;

	return (check_stateid(mode, cs, state->nvs_vp, stateid, trunc,
	    deleg, do_access, ct, clientid));
}

/* creating and destroying vnode-based nnodes */

nnode_error_t
nnode_from_fh_v3(nnode_t **npp, nfs_fh3 *fh3, exportinfo_t *exi)
{
	nnode_fid_key_t fidkey;
	nnode_seed_v3data_t v3data;
	nnode_key_t key;
	uint32_t hash;

	v3data.nsv_fh = fh3;
	v3data.nsv_exi = exi;

	fidkey.nfk_fsid = &fh3->fh3_fsid;
	fidkey.nfk_fid = FH3TOFIDP(fh3);
	fidkey.nfk_other = &fh3->fh3_flags;

	hash = nnode_key_fid_hash(&fidkey);

	key.nk_keydata = &fidkey;
	key.nk_compare = nnode_compare_fsid;

	return (nnode_find_or_create(npp, &key, hash, &v3data,
	    nnode_build_v3));
}

nnode_error_t
nnode_from_fh_v4(nnode_t **npp, nfs_fh4 *fh4)
{
	nnode_fid_key_t fidkey;
	nnode_key_t key;
	nfs_fh4_fmt_t *fh4fmt = (nfs_fh4_fmt_t *)fh4->nfs_fh4_val;
	uint32_t hash;

	if (fh4->nfs_fh4_len < NFS_FH4_LEN)
		return (NNODE_ERROR_BADFH);

	fidkey.nfk_fsid = &fh4fmt->fh4_fsid;
	fidkey.nfk_fid = (fid_t *)&fh4fmt->fh4_len;
	fidkey.nfk_other = &fh4fmt->fh4_flag;

	hash = nnode_key_fid_hash(&fidkey);

	key.nk_keydata = &fidkey;
	key.nk_compare = nnode_compare_fsid;

	return (nnode_find_or_create(npp, &key, hash, fh4,
	    nnode_build_v4));
}

nnode_error_t
nnode_from_fh_v41_nfs(nnode_t **npp, nfs_fh4 *fh4)
{
	nfs41_fh_fmt_t *fh41 = (nfs41_fh_fmt_t *)fh4->nfs_fh4_val;
	nnode_key_t key;
	nnode_fid_key_t fidkey;
	uint32_t hash;

	if (fh4->nfs_fh4_len < NFS41_FH_LEN)
		return (ESTALE);

	fidkey.nfk_fsid = &fh41->fh.v1.export_fsid;
	fidkey.nfk_fid = (fid_t *)&fh41->fh.v1.obj_fid.len;
	fidkey.nfk_other = &fh41->fh.v1.flags;

	hash = nnode_key_fid_hash(&fidkey);

	key.nk_keydata = &fidkey;
	key.nk_compare = nnode_compare_fsid;

	return (nnode_find_or_create(npp, &key, hash, fh4,
	    nnode_build_v41));
}

nnode_error_t (*nnode_from_fh_ds)(nnode_t **, mds_ds_fh *) = NULL;

nnode_error_t
nnode_from_fh_v41(nnode_t **npp, nfs_fh4 *fh4)
{
	nfs41_fh_fmt_t *mdsfh = (nfs41_fh_fmt_t *)fh4->nfs_fh4_val;

	if (fh4->nfs_fh4_len < MIN(sizeof (nfs41_fh_type_t),
	    sizeof (mds_ds_fh)))
		return (ESTALE); /* XXX badfh */

	switch (mdsfh->type) {
	case FH41_TYPE_NFS:
		return (nnode_from_fh_v41_nfs(npp, fh4));
	case FH41_TYPE_DMU_DS:
		if (nnode_from_fh_ds == NULL)
			return (ESTALE); /* XXX something else */
		return (nnode_from_fh_ds(npp, (mds_ds_fh *)fh4->nfs_fh4_val));
	default:
		return (ESTALE); /* XXX badfh */
	}
}

nnode_error_t
nnode_from_vnode(nnode_t **npp, vnode_t *vp)
{
	nnode_fid_key_t fidkey;
	nnode_key_t key;
	uint32_t hash;
	nnode_seed_vpdata_t vpdata;
	vfs_t *vfs;
	fid_t fid;
	fsid_t fsid;
	int error;
	uint32_t zero = 0;

	vfs = vp->v_vfsp;
	fsid = vfs->vfs_fsid;
	fid.fid_len = sizeof (fid.fid_data);
	error = VOP_FID(vp, &fid, NULL);
	if (error != 0)
		return (ESTALE);

	fidkey.nfk_fsid = &fsid;
	fidkey.nfk_fid = &fid;
	fidkey.nfk_other = &zero;

	hash = nnode_key_fid_hash(&fidkey);

	key.nk_keydata = &fidkey;
	key.nk_compare = nnode_compare_fsid;

	vpdata.nsv_vp = vp;
	vpdata.nsv_fsid = fsid;
	vpdata.nsv_fidp = &fid;

	return (nnode_find_or_create(npp, &key, hash, &vpdata,
	    nnode_build_vp));
}

static uint32_t
nnode_key_fid_hash(nnode_fid_key_t *key)
{
	uint32_t rc;

	CRC32(rc, key->nfk_fsid, sizeof (fsid_t), -1U, crc32_table);
	CRC32(rc, key->nfk_fid->fid_data, key->nfk_fid->fid_len, rc,
	    crc32_table);

	return (rc);
}

static int
nnode_compare_fsid(const void *va, const void *vb)
{
	const nnode_fid_key_t *a = va;
	const nnode_fid_key_t *b = vb;
	int rc;

	rc = memcmp(a->nfk_fsid, b->nfk_fsid, sizeof (fsid_t));
	NFS_AVL_RETURN(rc);

	rc = a->nfk_fid->fid_len - b->nfk_fid->fid_len;
	NFS_AVL_RETURN(rc);

	/*
	 * It is conceivable that a filehandle could have an absurdly
	 * large value for fid_len.  However, in order for the memcmp()
	 * to run with this value, there would have to be an existing
	 * nnode with the same fid_len.  Such an nnode would never
	 * be instantiated, because VFS_VGET() would first fail.
	 */

	rc = memcmp(a->nfk_fid->fid_data, b->nfk_fid->fid_data,
	    a->nfk_fid->fid_len);
	NFS_AVL_RETURN(rc);

	rc = *a->nfk_other - *b->nfk_other;
	NFS_AVL_RETURN(rc);

	return (0);
}

static nnode_vn_data_t *
nnode_vn_data_alloc(void)
{
	nnode_vn_data_t *rc;

	rc = kmem_cache_alloc(nnode_vn_data_cache, KM_SLEEP);
	rc->nvd_vp = NULL;
	rc->nvd_exi = NULL;
	rc->nvd_flags = 0;

	return (rc);
}

static nnode_vn_md_t *
nnode_vn_md_alloc(void)
{
	nnode_vn_md_t *rc;

	rc = kmem_cache_alloc(nnode_vn_md_cache, KM_SLEEP);
	rc->nvm_vp = NULL;

	return (rc);
}

static nnode_vn_state_t *
nnode_vn_state_alloc(void)
{
	nnode_vn_state_t *rc;

	rc = kmem_cache_alloc(nnode_vn_state_cache, KM_SLEEP);
	rc->nvs_vp = NULL;

	return (rc);
}

static void
nnode_fid_key_v41_free(void *vkey)
{
	kmem_cache_free(nnode_fid_key_v41_cache, vkey);
}

static void
nnode_fid_key_v4_free(void *vkey)
{
	kmem_cache_free(nnode_fid_key_v4_cache, vkey);
}

static void
nnode_fid_key_v3_free(void *vkey)
{
	kmem_cache_free(nnode_fid_key_v3_cache, vkey);
}

static void
nnode_fid_key_vp_free(void *vkey)
{
	kmem_cache_free(nnode_fid_key_vp_cache, vkey);
}

static void
nnode_vn_data_free(void *vdata)
{
	nnode_vn_data_t *data = vdata;

	if (data->nvd_vp)
		VN_RELE(data->nvd_vp);

/* TDH */
	kmem_cache_free(nnode_vn_data_cache, data);
}

static void
nnode_vn_md_free(void *vmd)
{
	nnode_vn_md_t *md = vmd;

	if (md->nvm_vp)
		VN_RELE(md->nvm_vp);

	kmem_cache_free(nnode_vn_md_cache, md);
}

static void
nnode_vn_state_free(void *vstate)
{
	nnode_vn_state_t *state = vstate;

	if (state->nvs_vp)
		VN_RELE(state->nvs_vp);

	kmem_cache_free(nnode_vn_state_cache, state);
}

void
nnode_vn_data_setup(nnode_seed_t *seed, vnode_t *vp, exportinfo_t *exi)
{
	nnode_vn_data_t *data;

	data = nnode_vn_data_alloc();
	data->nvd_exi = exi;
	data->nvd_vp = vp;
	/* no need to VN_HOLD; we steal the reference */
	seed->ns_data = data;
	seed->ns_data_ops = &nnode_vn_data_ops;
}

void
nnode_data_setup(nnode_seed_t *seed, vnode_t *vp, fsid_t fsid,
    int len, char *fid, exportinfo_t *exi)
{
	if (nfs_ds_present)
		nnode_proxy_data_setup(seed, vp, fsid, len, fid);
	else
		nnode_vn_data_setup(seed, vp, exi);
}

/*
 * Initialize the nnode_seed_t.  Each of the data structures
 * nnode_vn_data_t, nnode_vn_md_t, and nnode_vn_state_t are
 * allocated, and each has one reference to a vnode.  Thus,
 * the corresponding free functions need a VN_RELE() for the
 * held vnode.
 */
static nnode_error_t
nnode_build_v3(nnode_seed_t *seed, void *vv3seed)
{
	nnode_seed_v3data_t *v3seed = vv3seed;
	nnode_fid_key_v3_t *key;
	vnode_t *vp;
	nnode_vn_md_t *md;
	nnode_vn_state_t *state;
	int rc = 0;
	fsid_t fsid;
	int fidlen;
	char *fid;

	key = kmem_cache_alloc(nnode_fid_key_v3_cache, KM_SLEEP);
	bcopy(v3seed->nsv_fh, &key->nfk_fh, sizeof (key->nfk_fh));

	vp = nfs3_fhtovp(v3seed->nsv_fh, v3seed->nsv_exi);
	if (vp == NULL) {
		rc = ESTALE;
		goto out;
	}

	fsid = v3seed->nsv_fh->fh3_fsid;
	fidlen = v3seed->nsv_fh->fh3_len;
	fid = v3seed->nsv_fh->fh3_data;
	nnode_data_setup(seed, vp, fsid, fidlen, fid, v3seed->nsv_exi);
	md = nnode_vn_md_alloc();
	md->nvm_vp = vp;
	VN_HOLD(md->nvm_vp);
	state = nnode_vn_state_alloc();
	state->nvs_vp = vp;
	VN_HOLD(state->nvs_vp);

	seed->ns_key = key;
	seed->ns_key_compare = nnode_compare_fsid;
	seed->ns_key_free = nnode_fid_key_v3_free;
	seed->ns_metadata_ops = &nnode_vn_md_ops;
	seed->ns_metadata = md;
	seed->ns_state_ops = &nnode_vn_state_ops;
	seed->ns_state = state;

out:
	return (rc);
}

/*
 * Initialize the nnode_seed_t.  Each of the data structures
 * nnode_vn_data_t, nnode_vn_md_t, and nnode_vn_state_t are
 * allocated, and each has one reference to a vnode.  Thus,
 * the corresponding free functions need a VN_RELE() for the
 * held vnode.
 */
static nnode_error_t
nnode_build_vp(nnode_seed_t *seed, void *vvpseed)
{
	nnode_seed_vpdata_t *vpseed = vvpseed;
	nnode_fid_key_vp_t *key;
	nnode_vn_md_t *md;
	nnode_vn_state_t *state;
	fsid_t fsid;
	int fidlen;
	char *fid;

	key = kmem_cache_alloc(nnode_fid_key_vp_cache, KM_SLEEP);
	key->nfk_real_fsid = vpseed->nsv_fsid;
	bcopy(vpseed->nsv_fidp, &key->nfk_real_fid,
	    sizeof (key->nfk_real_fid));

	fsid = vpseed->nsv_fsid;
	fidlen = vpseed->nsv_fidp->fid_len;
	fid = vpseed->nsv_fidp->fid_data;

	/* XXX: Is it okay to pass NULL for the exi? */
	nnode_data_setup(seed, vpseed->nsv_vp, fsid, fidlen, fid, NULL);
	VN_HOLD(vpseed->nsv_vp);
	md = nnode_vn_md_alloc();
	md->nvm_vp = vpseed->nsv_vp;
	VN_HOLD(md->nvm_vp);
	state = nnode_vn_state_alloc();
	state->nvs_vp = vpseed->nsv_vp;
	VN_HOLD(state->nvs_vp);

	seed->ns_key = key;
	seed->ns_key_compare = nnode_compare_fsid;
	seed->ns_key_free = nnode_fid_key_vp_free;
	seed->ns_metadata_ops = &nnode_vn_md_ops;
	seed->ns_metadata = md;
	seed->ns_state_ops = &nnode_vn_state_ops;
	seed->ns_state = state;

	return (0);
}

/*
 * Initialize the nnode_seed_t.  Each of the data structures
 * nnode_vn_data_t, nnode_vn_md_t, and nnode_vn_state_t are
 * allocated, and each has one reference to a vnode.  Thus,
 * the corresponding free functions need a VN_RELE() for the
 * held vnode.
 */
static nnode_error_t
nnode_build_v41(nnode_seed_t *seed, void *vfh)
{
	nfs_fh4 *fh = vfh;
	nnode_fid_key_v41_t *key;
	nfs41_fh_fmt_t *fmt = (nfs41_fh_fmt_t *)fh->nfs_fh4_val;
	struct exportinfo *exi;
	nfsstat4 stat; /* XXX */
	vnode_t *vp;
	nnode_vn_md_t *md;
	nnode_vn_state_t *state;
	int rc = 0;
	fsid_t fsid;
	int fidlen;
	char *fid;

	key = kmem_cache_alloc(nnode_fid_key_v41_cache, KM_SLEEP);
	key->nfk_real_fid.fid_len = fmt->fh.v1.obj_fid.len;
	key->nfk_real_xfid.fid_len = fmt->fh.v1.export_fid.len;
	bcopy(fmt->fh.v1.obj_fid.val, &key->nfk_real_fid.fid_data,
	    key->nfk_real_fid.fid_len);
	bcopy(fmt->fh.v1.export_fid.val, &key->nfk_real_xfid.fid_data,
	    key->nfk_real_xfid.fid_len);
	key->nfk_real_fsid = fmt->fh.v1.export_fsid;
	key->nfk_real_other = fmt->fh.v1.flags;

	exi = checkexport4(key->nfk_fsid, key->nfk_xfid, NULL);
	if (exi != NULL)
		vp = nfs41_fhtovp_exi(fh, exi, &stat);
	if ((exi == NULL) || (vp == NULL)) {
		rc = ESTALE;
		goto out;
	}

	fsid = fmt->fh.v1.export_fsid;
	fidlen = fmt->fh.v1.obj_fid.len;
	fid = fmt->fh.v1.obj_fid.val;
	nnode_data_setup(seed, vp, fsid, fidlen, fid, exi);
	md = nnode_vn_md_alloc();
	md->nvm_vp = vp;
	VN_HOLD(md->nvm_vp);
	state = nnode_vn_state_alloc();
	state->nvs_vp = vp;
	VN_HOLD(state->nvs_vp);

	seed->ns_key = key;
	seed->ns_key_compare = nnode_compare_fsid;
	seed->ns_key_free = nnode_fid_key_v41_free;
	seed->ns_metadata_ops = &nnode_vn_md_ops;
	seed->ns_metadata = md;
	seed->ns_state_ops = &nnode_vn_state_ops;
	seed->ns_state = state;

out:
	if (rc != 0)
		kmem_cache_free(nnode_fid_key_v41_cache, key);
	return (rc);
}

/*
 * Initialize the nnode_seed_t.  Each of the data structures
 * nnode_vn_data_t, nnode_vn_md_t, and nnode_vn_state_t are
 * allocated, and each has one reference to a vnode.  Thus,
 * the corresponding free functions need a VN_RELE() for the
 * held vnode.
 */
static nnode_error_t
nnode_build_v4(nnode_seed_t *seed, void *vfh)
{
	nfs_fh4 *fh = vfh;
	nnode_fid_key_v4_t *key;
	struct exportinfo *exi;
	nfsstat4 stat;
	vnode_t *vp;
	nnode_vn_md_t *md;
	nnode_vn_state_t *state;
	int rc = 0;
	fsid_t fsid;
	int fidlen;
	char *fid;

	key = kmem_cache_alloc(nnode_fid_key_v4_cache, KM_SLEEP);
	bcopy(fh->nfs_fh4_val, &key->nfk_fh, sizeof (key->nfk_fh));

	exi = checkexport4(key->nfk_fsid, key->nfk_xfid, NULL);
	if (exi != NULL)
		vp = nfs4_fhtovp(fh, exi, &stat);
	if ((exi == NULL) || (vp == NULL)) {
		rc = ESTALE;
		goto out;
	}

	fsid = exi->exi_fsid;
	fidlen = key->nfk_fid->fid_len;
	fid = key->nfk_fid->fid_data;
	nnode_data_setup(seed, vp, fsid, fidlen, fid, exi);
	md = nnode_vn_md_alloc();
	md->nvm_vp = vp;
	VN_HOLD(md->nvm_vp);
	state = nnode_vn_state_alloc();
	state->nvs_vp = vp;
	VN_HOLD(state->nvs_vp);

	seed->ns_key = key;
	seed->ns_key_compare = nnode_compare_fsid;
	seed->ns_key_free = nnode_fid_key_v4_free;
	seed->ns_metadata_ops = &nnode_vn_md_ops;
	seed->ns_metadata = md;
	seed->ns_state_ops = &nnode_vn_state_ops;
	seed->ns_state = state;

out:
	if (rc != 0)
		kmem_cache_free(nnode_fid_key_v4_cache, key);
	return (rc);
}

/*ARGSUSED*/
static int
nnode_fid_key_v41_construct(void *vnfk, void *foo, int bar)
{
	nnode_fid_key_v41_t *nfk = vnfk;

	nfk->nfk_fsid = &nfk->nfk_real_fsid;
	nfk->nfk_fid = &nfk->nfk_real_fid;
	nfk->nfk_other = &nfk->nfk_real_other;
	nfk->nfk_xfid = &nfk->nfk_real_xfid;

	return (0);
}

/*ARGSUSED*/
static int
nnode_fid_key_v4_construct(void *vnfk, void *foo, int bar)
{
	nnode_fid_key_v4_t *nfk = vnfk;

	nfk->nfk_fsid = &nfk->nfk_fh.fh4_fsid;
	nfk->nfk_fid = (fid_t *)&nfk->nfk_fh.fh4_len;
	nfk->nfk_other = &nfk->nfk_fh.fh4_flag;
	nfk->nfk_xfid = (fid_t *)&nfk->nfk_fh.fh4_xlen;

	return (0);
}

/*ARGSUSED*/
static int
nnode_fid_key_v3_construct(void *vnfk, void *foo, int bar)
{
	nnode_fid_key_v3_t *nfk = vnfk;

	nfk->nfk_fsid = &nfk->nfk_fh.fh3_fsid;
	nfk->nfk_fid = FH3TOFIDP(&nfk->nfk_fh);
	nfk->nfk_other = &nfk->nfk_fh.fh3_flags;

	return (0);
}

/*ARGSUSED*/
static int
nnode_fid_key_vp_construct(void *vnfk, void *foo, int bar)
{
	nnode_fid_key_vp_t *nfk = vnfk;

	nfk->nfk_fsid = &nfk->nfk_real_fsid;
	nfk->nfk_fid = &nfk->nfk_real_fid;
	nfk->nfk_other = &nfk->nfk_zero;
	nfk->nfk_zero = 0;

	return (0);
}

/*ARGSUSED*/
static int
nnode_vn_data_construct(void *vdata, void *foo, int bar)
{
	nnode_vn_data_t *data = vdata;

	mutex_init(&data->nvd_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
nnode_vn_data_destroy(void *vdata, void *foo)
{
	nnode_vn_data_t *data = vdata;

	mutex_destroy(&data->nvd_lock);
}

void
nnode_vn_init(void)
{
	nnode_fid_key_v41_cache = kmem_cache_create("nfs_fid_key_v41_cache",
	    sizeof (nnode_fid_key_v41_t), 0,
	    nnode_fid_key_v41_construct, NULL, NULL,
	    NULL, NULL, 0);
	nnode_fid_key_v4_cache = kmem_cache_create("nfs_fid_key_v4_cache",
	    sizeof (nnode_fid_key_v4_t), 0,
	    nnode_fid_key_v4_construct, NULL, NULL,
	    NULL, NULL, 0);
	nnode_fid_key_v3_cache = kmem_cache_create("nfs_fid_key_v3_cache",
	    sizeof (nnode_fid_key_v3_t), 0,
	    nnode_fid_key_v3_construct, NULL, NULL,
	    NULL, NULL, 0);
	nnode_fid_key_vp_cache = kmem_cache_create("nfs_fid_key_vp_cache",
	    sizeof (nnode_fid_key_vp_t), 0,
	    nnode_fid_key_vp_construct, NULL, NULL,
	    NULL, NULL, 0);
	nnode_vn_data_cache = kmem_cache_create("nnode_vn_data_cache",
	    sizeof (nnode_vn_data_t), 0,
	    nnode_vn_data_construct, nnode_vn_data_destroy, NULL,
	    NULL, NULL, 0);
	nnode_vn_md_cache = kmem_cache_create("nnode_vn_md_cache",
	    sizeof (nnode_vn_md_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	nnode_vn_state_cache = kmem_cache_create("nnode_vn_state_cache",
	    sizeof (nnode_vn_state_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
}

void
nnode_vn_fini(void)
{
	kmem_cache_destroy(nnode_fid_key_v41_cache);
	kmem_cache_destroy(nnode_fid_key_v4_cache);
	kmem_cache_destroy(nnode_fid_key_v3_cache);
	kmem_cache_destroy(nnode_fid_key_vp_cache);
	kmem_cache_destroy(nnode_vn_data_cache);
	kmem_cache_destroy(nnode_vn_md_cache);
	kmem_cache_destroy(nnode_vn_state_cache);
}
