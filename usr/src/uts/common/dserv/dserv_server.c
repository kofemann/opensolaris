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

#include <sys/dserv_impl.h>

#include <sys/list.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs41_sessions.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nnode.h>
#include <nfs/ds_prot.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/txg.h>
#include <rpc/xdr.h>
#include <nfs/ds.h>
#include <sys/crc32.h>
#include <sys/sysmacros.h>

uint32_t max_blksize = SPA_MAXBLOCKSIZE;

static nnode_error_t dserv_nnode_from_fh_ds(nnode_t **, nfs_fh4 *);
static void dserv_nnode_key_free(void *);
static dserv_nnode_data_t *dserv_nnode_data_alloc(void);

static nnode_error_t dserv_nnode_data_getobject(dserv_nnode_data_t *, int);
static void dserv_dispatch(struct svc_req *, SVCXPRT *);
static void dmov_dispatch(struct svc_req *, SVCXPRT *);

static int dserv_get_objset(ds_fh_v1 *, objset_t **);
static void dserv_grow_blocksize(dserv_nnode_data_t *, uint32_t, dmu_tx_t *);

static void ds_commit(DS_COMMITargs *,  DS_COMMITres *,
    struct svc_req *);
static void ds_getattr(DS_GETATTRargs *, DS_GETATTRres *,
    struct svc_req *);
static void ds_setattr(DS_SETATTRargs *, DS_SETATTRres *,
    struct svc_req *);
static void ds_read(DS_READargs *, DS_READres *,
    struct svc_req *);
static void ds_obj_move(DS_OBJ_MOVEargs *, DS_OBJ_MOVEres *,
    struct svc_req *);
static void ds_obj_move_abort(DS_OBJ_MOVE_ABORTargs *, DS_OBJ_MOVE_ABORTres *,
    struct svc_req *);
static void ds_obj_move_status(DS_OBJ_MOVE_STATUSargs *,
    DS_OBJ_MOVE_STATUSres *, struct svc_req *);
static void ds_remove(DS_REMOVEargs *, DS_REMOVEres *,
    struct svc_req *);
static void ds_write(DS_WRITEargs *, DS_WRITEres *,
    struct svc_req *);
static void ds_invalidate(DS_INVALIDATEargs *, DS_INVALIDATEres *,
    struct svc_req *);
static void ds_list(DS_LISTargs *, DS_LISTres *,
    struct svc_req *);
static void ds_stat(DS_STATargs *, DS_STATres *,
    struct svc_req *);
static void ds_snap(DS_SNAPargs *, DS_SNAPres *,
    struct svc_req *);
static void ds_pnfsstat(DS_PNFSSTATargs *, DS_PNFSSTATres *,
    struct svc_req *);
static void cp_nullfree(void);

void dispatch_dserv_nfsv41(struct svc_req *, SVCXPRT *);

static int dserv_nnode_io_prep(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, offset_t, size_t, bslabel_t *);
static int dserv_nnode_read(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, uio_t *, int);
static int dserv_nnode_write(void *, nnode_io_flags_t *, uio_t *, int,
    cred_t *, caller_context_t *, wcc_data *);
static void dserv_nnode_data_free(void *);

static kmem_cache_t *dserv_nnode_key_cache;
static kmem_cache_t *dserv_nnode_data_cache;

time_t dserv_start_time;

static SVC_CALLOUT dserv_sc[] = {
	{ PNFSCTLMDS, PNFSCTLMDS_V1, PNFSCTLMDS_V1, dserv_dispatch },
	{ PNFSCTLMV, PNFSCTLMV_V1, PNFSCTLMV_V1, dmov_dispatch },
	/* The following is need to dispatch non-2049 NFS traffic */
	{ NFS_PROGRAM, 4, 4, dispatch_dserv_nfsv41 }
};

static SVC_CALLOUT_TABLE dserv_sct = {
	sizeof (dserv_sc) / sizeof (dserv_sc[0]), FALSE, dserv_sc
};

/*
 * Dispatch structure for the control protocol
 */
struct nfs_cp_disp {
	void	(*proc)();
	xdrproc_t decode_args;
	xdrproc_t encode_reply;
	void	(*resfree)();
	char    *name;
};

union nfs_mds_cp_sarg {
	DS_COMMITargs 		ds_commit;
	DS_GETATTRargs 		ds_getattr;
	DS_SETATTRargs 		ds_setattr;
	DS_READargs 		ds_read;
	DS_REMOVEargs 		ds_remove;
	DS_WRITEargs 		ds_write;
	DS_INVALIDATEargs 	ds_invalidate;
	DS_LISTargs 		ds_list;
	DS_STATargs 		ds_stat;
	DS_SNAPargs 		ds_snap;
	DS_PNFSSTATargs 	ds_pnfsstat;
};

union nfs_mds_cp_sres {
	DS_COMMITres 		ds_commit;
	DS_GETATTRres 		ds_getattr;
	DS_SETATTRres 		ds_setattr;
	DS_READres 		ds_read;
	DS_REMOVEres 		ds_remove;
	DS_WRITEres 		ds_write;
	DS_INVALIDATEres 	ds_invalidate;
	DS_LISTres 		ds_list;
	DS_STATres 		ds_stat;
	DS_SNAPres 		ds_snap;
	DS_PNFSSTATres 		ds_pnfsstat;
};

struct nfs_cp_disp nfs_mds_cp_v1[] = {
	{ NULL, NULL, NULL, NULL, NULL },
	{ds_commit, xdr_DS_COMMITargs, xdr_DS_COMMITres,
	    cp_nullfree, "DS_COMMIT"},
	{ds_getattr, xdr_DS_GETATTRargs, xdr_DS_GETATTRres,
	    cp_nullfree, "DS_GETATTR"},
	{ds_invalidate, xdr_DS_INVALIDATEargs, xdr_DS_INVALIDATEres,
	    cp_nullfree, "DS_INVALIDATE"},
	{ds_list, xdr_DS_LISTargs, xdr_DS_LISTres,
	    cp_nullfree, "DS_LIST"},
	{ds_obj_move, xdr_DS_OBJ_MOVEargs, xdr_DS_OBJ_MOVEres,
	    cp_nullfree, "DS_OBJ_MOVE"},
	{ds_obj_move_abort, xdr_DS_OBJ_MOVE_ABORTargs, xdr_DS_OBJ_MOVE_ABORTres,
	    cp_nullfree, "DS_OBJ_MOVE_ABORT"},
	{ds_obj_move_status, xdr_DS_OBJ_MOVE_STATUSargs,
	    xdr_DS_OBJ_MOVE_STATUSres, cp_nullfree, "DS_OBJ_MOVE_STATUS"},
	{ds_pnfsstat, xdr_DS_PNFSSTATargs, xdr_DS_PNFSSTATres,
	    cp_nullfree, "DS_PNFSSTAT"},
	{ds_read, xdr_DS_READargs, xdr_DS_READres,
	    cp_nullfree, "DS_READ"},
	{ds_remove, xdr_DS_REMOVEargs, xdr_DS_REMOVEres,
	    cp_nullfree, "DS_REMOVE"},
	{ds_setattr, xdr_DS_SETATTRargs, xdr_DS_SETATTRres,
	    cp_nullfree, "DS_SETATTR"},
	{ds_stat, xdr_DS_STATargs, xdr_DS_STATres,
	    cp_nullfree, "DS_STAT"},
	{ds_snap, xdr_DS_SNAPargs, xdr_DS_SNAPres,
	    cp_nullfree, "DS_SNAP"},
	{ds_write, xdr_DS_WRITEargs, xdr_DS_WRITEres,
	    cp_nullfree, "DS_WRITE"},
};

static uint_t nfs_mds_cp_cnt =
    sizeof (nfs_mds_cp_v1) / sizeof (struct nfs_cp_disp);

#define	NFS_MDS_CP_ILLEGAL_PROC (nfs_mds_cp_cnt)

static nnode_data_ops_t dserv_nnode_data_ops = {
	.ndo_read = dserv_nnode_read,
	.ndo_write = dserv_nnode_write,
	.ndo_io_prep = dserv_nnode_io_prep,
	.ndo_free = dserv_nnode_data_free
};

int dserv_debug = 0;

static void
send_nfs4err(nfsstat4 stat, SVCXPRT *xprt)
{
	COMPOUND4res_srv comp_resp;

	bzero(&comp_resp, sizeof (comp_resp));
	comp_resp.status = stat;
	comp_resp.minorversion = NFS4_MINOR_v1;

	if (!svc_sendreply(xprt,  xdr_COMPOUND4res_srv, (char *)&comp_resp)) {
		svcerr_systemerr(xprt);
	}
}

/* the non port 2049 point of entry */
void
dispatch_dserv_nfsv41(struct svc_req *req, SVCXPRT *xprt)
{
	COMPOUND4args_srv args;
	int error;

	/* NULL, is easy */
	if (req->rq_proc == RFS_NULL) {
		if (!svc_sendreply(xprt, xdr_void, NULL)) {
			DTRACE_PROBE(dserv__e__svc_reply_nullproc);
			svcerr_systemerr(xprt);
		}
		return;
	}

	/* HAS to be a COMPOUND */
	ASSERT(req->rq_proc == 1);

	bzero(&args, sizeof (args));

	if (!SVC_GETARGS(xprt, xdr_COMPOUND4args_srv, (char *)&args)) {
		DTRACE_PROBE(dserv__e__svc_getargs);
		svcerr_decode(xprt);
		return;
	}

	/*
	 * Minor version has to be 1 or else return MINOR_VERS_MISMATCH error
	 */
	if (args.minorversion != 1) {
		send_nfs4err(NFS4ERR_MINOR_VERS_MISMATCH, xprt);
		DTRACE_PROBE(dserv__e__minorvers_mismatch);
	} else {
		dserv_mds_instance_t *inst;

		error = dserv_instance_enter(RW_READER, B_FALSE, &inst);
		if (error) {
			/*
			 * Either we weren't able to find our instance
			 * (e.g. it has been shutdown) or the instance
			 * is in the process of being shutdown.  Either
			 * way, this is a non-recoverable error.
			 */
			send_nfs4err(NFS4ERR_IO, xprt);
		}

		(void) rfs41_dispatch(req, xprt, (char *)&args);
		dserv_instance_exit(inst);
	}

	if (!SVC_FREEARGS(xprt, xdr_COMPOUND4args_srv, (char *)&args))
		DTRACE_PROBE(dserv__e__svc_freeargs);
}

static uint32_t
dserv_nnode_hash(dserv_nnode_key_t *key)
{
	uint32_t rc;

	CRC32(rc, key->dnk_fid->mds_fid_val, key->dnk_fid->mds_fid_len,
	    -1U, crc32_table);

	return (rc);
}

static int
dserv_nnode_compare(const void *va, const void *vb)
{
	const dserv_nnode_key_t *a = va;
	const dserv_nnode_key_t *b = vb;
	int rc;

	NFS_AVL_COMPARE(a->dnk_fid->mds_fid_len, b->dnk_fid->mds_fid_len);
	rc = memcmp(a->dnk_fid->mds_fid_val, b->dnk_fid->mds_fid_val,
	    a->dnk_fid->mds_fid_len);
	NFS_AVL_RETURN(rc);

	return (0);
}

static nnode_error_t
dserv_nnode_build(nnode_seed_t *seed, void *vfh)
{
	mds_ds_fh *fh = vfh;
	dserv_nnode_key_t *key = NULL;
	nnode_error_t rc = 0;
	dserv_nnode_data_t *data = NULL;
	objset_t *osp;

	rc = dserv_get_objset(&fh->fh.v1, &osp);
	if (rc != 0)
		goto out;

	/* XXX do some sid stuff */

	key = kmem_cache_alloc(dserv_nnode_key_cache, KM_SLEEP);
	key->dnk_real_fid.mds_fid_len = fh->fh.v1.mds_fid.mds_fid_len;
	bcopy(fh->fh.v1.mds_fid.mds_fid_val, key->dnk_real_fid.mds_fid_val,
	    key->dnk_real_fid.mds_fid_len);

	data = dserv_nnode_data_alloc();
	data->dnd_fid = key->dnk_fid;
	data->dnd_objset = osp;
	data->dnd_flags = DSERV_NNODE_FLAG_OBJSET;

	seed->ns_key = key;
	seed->ns_key_compare = dserv_nnode_compare;
	seed->ns_key_free = dserv_nnode_key_free;
	seed->ns_data_ops = &dserv_nnode_data_ops;
	seed->ns_data = data;

out:
	if (rc != 0) {
		if (key != NULL)
			dserv_nnode_key_free(key);
		if (data != NULL)
			dserv_nnode_data_free(data);
	}

	return (rc);
}

static nnode_error_t
dserv_nnode_from_fh_ds(nnode_t **npp, nfs_fh4 *fh)
{
	mds_ds_fh *fmt = (mds_ds_fh *)fh->nfs_fh4_val;
	dserv_nnode_key_t dskey;
	nnode_key_t key;
	uint32_t hash;

	if (fh->nfs_fh4_len < sizeof (*fmt))
		return (ESTALE); /* XXX badhandle */
	if (fmt->vers < 1)
		return (ESTALE); /* XXX badhandle */
	if (fmt->fh.v1.mds_fid.mds_fid_len < 8) /* XXX stupid */
		return (ESTALE);
	if (fmt->fh.v1.mds_fid.mds_fid_len > DS_MAXFIDSZ)
		return (ESTALE);
	/* XXX cannot do sid until mds_sid is sane */
	dskey.dnk_sid = NULL;
	dskey.dnk_fid = &fmt->fh.v1.mds_fid;

	hash = dserv_nnode_hash(&dskey);

	key.nk_keydata = &dskey;
	key.nk_compare = dserv_nnode_compare;

	return (nnode_find_or_create(npp, &key, hash, fmt, dserv_nnode_build));
}

static char *
dserv_tohex(const void *bytes, int len)
{
	static char *hexvals = "0123456789ABCDEF";
	char *rc;
	const unsigned char *c = bytes;
	int i;

	rc = kmem_alloc(len * 2 + 1, KM_SLEEP);
	rc[len * 2] = '\0';

	for (i = 0; i < len; i++) {
		rc[2 * i] = hexvals[c[i] >> 4];
		rc[2 * i + 1] = hexvals[c[i] & 0xf];
	}

	return (rc);
}

static void
cp_nullfree(void)
{
}

/*
 * Finds or creates an FSID object set with the given name.
 */
static int
get_create_fsid_objset(char *fsid_objset_name, objset_t **osp)
{
	dmu_tx_t *tx;
	int error = 0;

	DTRACE_PROBE1(dserv__i__get_create_fsid_objset, char *,
	    fsid_objset_name);

	error = dmu_objset_open(fsid_objset_name, DMU_OST_PNFS,
	    DS_MODE_OWNER, osp);

	if (error) {
		DTRACE_PROBE1(dserv__e__fsid_dmu_objset_open, int, error);
		if (error == ENOENT) {
			/* The object set needs to be created */
			error = dmu_objset_create(fsid_objset_name,
			    DMU_OST_PNFS, NULL, 0, NULL, NULL);

			if (error) {
				DTRACE_PROBE1(dserv__e__fsid_dmu_objset_create,
				    int, error);
				return (error);
			}

			/* Open the object set */
			error = dmu_objset_open(fsid_objset_name,
			    DMU_OST_PNFS, DS_MODE_OWNER, osp);

			if (error) {
				DTRACE_PROBE2(
				    dserv__e__fsid_dmu_objset_open_after_create,
				    int, error, objset_t *, *osp);
				return (error);
			}

			/* Create the FID to Object ID ZAP object. */
			tx = dmu_tx_create(*osp);
			dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
			error = dmu_tx_assign(tx, TXG_WAIT);

			if (error) {
				DTRACE_PROBE1(dserv__e__fsid_dmu_tx_assign,
				    int, error);
				dmu_tx_abort(tx);
				return (error);
			}
			error = zap_create_claim(*osp,
			    DMU_PNFS_FID_TO_OBJID_OBJECT,
			    DMU_OT_PNFS_INFO,
			    DMU_OT_NONE, 0, tx);

			if (error) {
				DTRACE_PROBE1(dserv__e__fsid_zap_create_claim,
				    int, error);
				dmu_tx_abort(tx);
				return (error);
			}
			dmu_tx_commit(tx);
		} else /* Any other than ENOENT, return the error! */
			return (error);
	}

	return (0);
}

/*
 * Maps the elements of the file handle (MDS PPID, MDS DATASET ID) to the
 * object set holding the data.
 */
/* ARGSUSED */
static int
dserv_get_objset(ds_fh_v1 *ds_fh, objset_t **osp)
{
	dserv_mds_instance_t *inst;
	open_root_objset_t *tmp_root;
	open_fsid_objset_t *tmp_fsid;
	open_fsid_objset_t *new_fsid;
	char fsid_objset_name[MAXPATHLEN];
	int error = 0;
	char *fsidmajor;
	char *fsidminor;
#if 0
	mds_sid_map_t *tmp_sid;
	int found_root_objset = 0;
	int found_mds_sid = 0;
#endif

	inst = dserv_mds_get_my_instance();

	DTRACE_PROBE4(dserv__i__dserv_get_objset_printfh,
	    uint64_t, ds_fh->mds_id,
	    uint64_t, ds_fh->mds_dataset_id,
	    uint64_t, ds_fh->fsid.major,
	    uint64_t, ds_fh->fsid.minor);

	mutex_enter(&inst->dmi_content_lock);
	if (list_is_empty(&inst->dmi_datasets)) {
		mutex_exit(&inst->dmi_content_lock);
		DTRACE_PROBE(dserv__i__dataset_list_is_empty);
		return (EIO);
	}

	/*
	 * We will be using the MDS SID to find the root pNFS object set,
	 * but for now we are just taking the first object set in our list.
	 * This introduces the stipulation that we can only have ONE root
	 * pNFS dataset on the data server for now.  This will be changed
	 * in the future.
	 */
	tmp_root = list_head(&inst->dmi_datasets);

#if 0
	found_root_objset = 1;
	/*
	 * Use the MDS SID (from the file handle) to find the real data
	 * server guid (zpool guid + id of the root pNFS object set).
	 * Note: Need to change to treating the MDS SID as opaque.
	 */
	for (tmp_sid = list_head(&inst->dmi_mds_sids); tmp_sid != NULL;
	    tmp_sid = list_next(&inst->dmi_mds_sids)) {
		if (ds_fh->mds_ds_fh_u.fh_v1.mds_zpoolid.id ==
		    tmp_sid->mpm_mds_zpoolid.id &&
		    ds_fh->mds_ds_fh_u.fh_v1.mds_zpoolid.aun ==
		    tmp_sid->mpm_mds_zpoolid.aun) {
			found_mds_sid = 1;
			ds_guid = tmp_sid->mpm_ds_guid;
			break;
		}
	}

	/*
	 * If we have no record of the given MDS SID it may mean that
	 * we haven't been able to do the REPORTAVAIL for this particular
	 * resource.  Therefore, just tell the client to try again later.
	 */
	if (found_mdsppid != 1) {
		mutex_exit(&inst->dmi_content_lock);
		return (EAGAIN);
	}

	/*
	 * Find the root pNFS object set.
	 */
	for (tmp_root = list_head(&inst->dmi_datasets); tmp_root != NULL;
	    tmp_root = list_next(&inst->dmi_datasets, tmp_root)) {
		if (ds_guid->dg_zpool_guid ==
		    tmp_root->oro_ds_guid.dg_zpool_guid &&
		    ds_guid->dg_objset_guid ==
		    tmp_root->oro_ds_guid.dg_objset_guid) {
			/*
			 * This is our root pNFS object set!
			 */
			found_root_objset = 1;
			break;
		}
	}

	if (found_root_objset != 1) {
		mutex_exit(&inst->dmi_content_lock);
		return (EIO);
	}
#endif

	/*
	 * Look for a dataset named after the fsid in the file handle.
	 * This will be the object set that the data object will reside in.
	 * If this object set does not exist, we will create it here.
	 */
	for (tmp_fsid = list_head(&tmp_root->oro_open_fsid_objsets);
	    tmp_fsid != NULL;
	    tmp_fsid = list_next(&tmp_root->oro_open_fsid_objsets, tmp_fsid)) {
		if (ds_fh->fsid.major ==
		    tmp_fsid->ofo_fsid.major &&
		    ds_fh->fsid.minor ==
		    tmp_fsid->ofo_fsid.minor) {
			mutex_exit(&inst->dmi_content_lock);
			DTRACE_PROBE(dserv__i__fsid_objset_found);
			*osp = tmp_fsid->ofo_osp;
			return (0);
		}
	}

	DTRACE_PROBE(dserv__i__fsid_objset_not_found);

	/*
	 * We didn't find the fsid object set and it means either:
	 * 1. The object set exists, but has not yet been opened.
	 *	or
	 * 2. The object set does not exist and needs to be created.
	 */

	/*
	 * The format of the fsid object set name is:
	 * <zpool-name>/<rootpnfs-objset-name>/<fsidmajor.fsidminor>
	 *
	 * The name of the root pNFS dataset is stored by the data server
	 * in the open_root_objset_t.
	 * We may want to move away from doing this just in case the root
	 * pNFS dataset gets renamed.  If we continue to store the dataset
	 * name we will have to handle the case where a dataset gets renamed.
	 */
	fsidmajor = dserv_tohex(&ds_fh->fsid.major, 8);
	fsidminor = dserv_tohex(&ds_fh->fsid.minor, 8);
	(void) snprintf(fsid_objset_name, MAXPATHLEN, "%s%s%s%s%s",
	    tmp_root->oro_objsetname, "/", fsidmajor, ".", fsidminor);

	error = get_create_fsid_objset(fsid_objset_name, osp);
	if (error) {
		mutex_exit(&inst->dmi_content_lock);
		DTRACE_PROBE1(dserv__e__get_create_fsid_objset, int, error);
		return (error);
	}

	/* Place entry in the the fsid objset linked list */
	new_fsid = kmem_cache_alloc(dserv_open_fsid_objset_cache, KM_SLEEP);
	new_fsid->ofo_fsid.major = ds_fh->fsid.major;
	new_fsid->ofo_fsid.minor = ds_fh->fsid.minor;
	new_fsid->ofo_osp = *osp;

	list_insert_tail(&tmp_root->oro_open_fsid_objsets, new_fsid);

	mutex_exit(&inst->dmi_content_lock);
	kmem_free(fsidmajor, strlen(fsidmajor) + 1);
	kmem_free(fsidminor, strlen(fsidminor) + 1);
	return (0);
}

/*ARGSUSED*/
static int
dserv_nnode_io_prep(void *vdata, nnode_io_flags_t *nnflags, cred_t *cr,
    caller_context_t *ct, offset_t off, size_t len, bslabel_t *clabel)
{
	dserv_nnode_data_t *data = vdata;
	nnode_error_t err = 0;

	rw_enter(&data->dnd_rwlock, RW_READER);
	if (! (data->dnd_flags & DSERV_NNODE_FLAG_OBJECT)) {
		int create;

		create = (*nnflags & NNODE_IO_FLAG_WRITE) ? B_TRUE : B_FALSE;
		err = dserv_nnode_data_getobject(data, create);
		if ((err == ENOENT) && (! (*nnflags & NNODE_IO_FLAG_WRITE))) {
			*nnflags |= NNODE_IO_FLAG_PAST_EOF;
			err = 0;
			goto out;
		}
		if (err)
			goto out;
	}

	if (off > data->dnd_phys->dp_size)
		*nnflags |= NNODE_IO_FLAG_PAST_EOF;
out:
	rw_exit(&data->dnd_rwlock);

	return (err);
}

/*ARGSUSED*/
static int
dserv_nnode_read(void *vdata, nnode_io_flags_t *nnflags, cred_t *cr,
    caller_context_t *ct, uio_t *uiop, int ioflag)
{
	dserv_nnode_data_t *data = vdata;
	nnode_error_t err;

	rw_enter(&data->dnd_rwlock, RW_READER);
	ASSERT(data->dnd_flags & DSERV_NNODE_FLAG_OBJECT);
	err = dmu_read_uio(data->dnd_objset, data->dnd_object, uiop,
	    uiop->uio_resid);

out:
	rw_exit(&data->dnd_rwlock);
	return (err);
}

/*ARGSUSED*/
static int
dserv_nnode_write(void *vdata, nnode_io_flags_t *nnflags, uio_t *uiop,
    int ioflags, cred_t *cr, caller_context_t *ct, wcc_data *wcc)
{
	dserv_nnode_data_t *data = vdata;
	offset_t end = uiop->uio_loffset + uiop->uio_resid;
	uint64_t new_blksize = 0;
	uint64_t new_size = 0;
	krw_t rw = RW_READER;
	nnode_error_t err;
	dmu_tx_t *tx;


	ASSERT(wcc == NULL); /* No NFSv3 access */

again:
	rw_enter(&data->dnd_rwlock, rw);
	if (end > data->dnd_phys->dp_size) {
		if ((rw == RW_READER) &&
		    (! rw_tryupgrade(&data->dnd_rwlock))) {
			rw = RW_WRITER;
			rw_exit(&data->dnd_rwlock);
			goto again;
		}

		if (end > data->dnd_blksize) {
			new_size = end;
			if (data->dnd_blksize < max_blksize)
				new_blksize = MIN(end, max_blksize);
			else if (!ISP2(data->dnd_blksize))
				new_blksize = MIN(end, SPA_MAXBLOCKSIZE);
		}
	}

	tx = dmu_tx_create(data->dnd_objset);
	dmu_tx_hold_write(tx, data->dnd_object, uiop->uio_loffset,
	    uiop->uio_resid);
	err = dmu_tx_assign(tx, TXG_WAIT);
	if (err) {
		dmu_tx_abort(tx);
		err = EIO;
		goto out;
	}
	if (new_blksize)
		dserv_grow_blocksize(data, new_blksize, tx);
	if (new_size) {
		dmu_buf_will_dirty(data->dnd_dbuf, tx);
		data->dnd_phys->dp_size = new_size;
	}

	dmu_write_uio(data->dnd_objset, data->dnd_object, uiop,
	    uiop->uio_resid, tx);
	dmu_tx_commit(tx);
	err = 0;

out:
	rw_exit(&data->dnd_rwlock);

	return (err);
}

/*ARGSUSED*/
static int
dserv_nnode_data_construct(void *vdnd, void *foo, int bar)
{
	dserv_nnode_data_t *dnd = vdnd;

	rw_init(&dnd->dnd_rwlock, NULL, RW_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
dserv_nnode_data_destroy(void *vdnd, void *foo)
{
	dserv_nnode_data_t *dnd = vdnd;

	rw_destroy(&dnd->dnd_rwlock);
}

static dserv_nnode_data_t *
dserv_nnode_data_alloc(void)
{
	dserv_nnode_data_t *dnd;

	dnd = kmem_cache_alloc(dserv_nnode_data_cache, KM_SLEEP);

	dnd->dnd_flags = 0;
	dnd->dnd_fid = NULL;
	dnd->dnd_objset = NULL;
	dnd->dnd_dbuf = NULL;
	dnd->dnd_phys = NULL;
	dnd->dnd_blksize = 0;

	return (dnd);
}

static void
dserv_nnode_data_free(void *vdnd)
{
	dserv_nnode_data_t *dnd = vdnd;
	dmu_buf_t *db = dnd->dnd_dbuf;

	if (db != NULL) {
		ASSERT(dnd->dnd_flags & DSERV_NNODE_FLAG_OBJECT);
		VERIFY(dnd == dmu_buf_update_user(db, dnd, NULL, NULL, NULL));
		dmu_buf_rele(db, NULL);
	}
	dnd->dnd_flags = 0;
	dnd->dnd_fid = NULL;
	dnd->dnd_objset = NULL;
	dnd->dnd_dbuf = NULL;
	dnd->dnd_phys = NULL;
	kmem_cache_free(dserv_nnode_data_cache, dnd);
}

/*ARGSUSED*/
static int
dserv_nnode_key_construct(void *vdnk, void *foo, int bar)
{
	dserv_nnode_key_t *key = vdnk;

	key->dnk_fid = &key->dnk_real_fid;

	return (0);
}

static void
dserv_nnode_key_free(void *dnk)
{
	kmem_cache_free(dserv_nnode_key_cache, dnk);
}

void
dserv_server_setup()
{
	dserv_start_time = gethrestime_sec();

	dserv_nnode_key_cache = kmem_cache_create("dserv_nnode_key_cache",
	    sizeof (dserv_nnode_key_t), 0,
	    dserv_nnode_key_construct, NULL, NULL,
	    NULL, NULL, 0);
	dserv_nnode_data_cache = kmem_cache_create("dserv_nnode_data_cache",
	    sizeof (dserv_nnode_data_t), 0,
	    dserv_nnode_data_construct, dserv_nnode_data_destroy, NULL,
	    NULL, NULL, 0);

	nnode_from_fh_ds = dserv_nnode_from_fh_ds;
}

void
dserv_server_teardown()
{
	nnode_from_fh_ds = NULL;

	kmem_cache_destroy(dserv_nnode_data_cache);
	kmem_cache_destroy(dserv_nnode_key_cache);
}

char *
dserv_strdup(const char *what)
{
	char *rc;
	int len;

	len = strlen(what);
	rc = kmem_alloc(len + 1, KM_SLEEP);
	rc[len] = '\0';
	bcopy(what, rc, len);

	return (rc);
}

void
dserv_strfree(char *what)
{
	int len = strlen(what);
	kmem_free(what, len + 1);
}

/*
 * This function starts the dserv server which responds to dserv and dmov
 * protocol requests.
 */
int
dserv_svc(dserv_svc_args_t *svcargs)
{
	int error;
	file_t *fp;
	struct netbuf addrmask;
	SVCMASTERXPRT *xprt;
	char *six;

	if ((fp = getf(svcargs->fd)) == NULL)
		return (EBADF);

	/*
	 * Just tcp, thank-you very much.
	 */
	if (strncmp("tcp", svcargs->netid, 3) != 0) {
		DTRACE_PROBE2(dserv__e__not_starting_pool,
		    int, svcargs->poolid, char *, svcargs->netid);
		return (EINVAL);
	}

	six = strchr(svcargs->netid, '6');
	if (six == NULL)
		addrmask.len = addrmask.maxlen = sizeof (struct sockaddr_in);
	else
		addrmask.len = addrmask.maxlen = sizeof (struct sockaddr_in6);

	addrmask.buf = kmem_alloc(addrmask.len, KM_SLEEP);
	bcopy((void *)&svcargs->sin, (void *)addrmask.buf, addrmask.len);

	/*
	 * XXX - Determine the correct way to set the max receive size
	 * (the second parameter).
	 */
	error = svc_tli_kcreate(fp, 1024 * 1024, svcargs->netid, &addrmask,
	    &xprt, &dserv_sct, NULL, svcargs->poolid, TRUE);
	if (error != 0)
		kmem_free(addrmask.buf, addrmask.len);
	releasef(svcargs->fd);

	return (error);
}

/* ARGSUSED */
void
ds_commit(DS_COMMITargs *argp, DS_COMMITres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_getattr(DS_GETATTRargs *argp, DS_GETATTRres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_setattr(DS_SETATTRargs *argp, DS_SETATTRres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_read(DS_READargs *argp, DS_READres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_remove(DS_REMOVEargs *argp, DS_REMOVEres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_obj_move(DS_OBJ_MOVEargs *argp, DS_OBJ_MOVEres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_obj_move_abort(DS_OBJ_MOVE_ABORTargs *argp, DS_OBJ_MOVE_ABORTres *resp,
    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_obj_move_status(DS_OBJ_MOVE_STATUSargs *argp, DS_OBJ_MOVE_STATUSres *resp,
    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_write(DS_WRITEargs *argp, DS_WRITEres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_invalidate(DS_INVALIDATEargs *argp, DS_INVALIDATEres *resp,
	    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_list(DS_LISTargs *argp, DS_LISTres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_stat(DS_STATargs *argp, DS_STATres * resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_snap(DS_SNAPargs *argp, DS_SNAPres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}


/* ARGSUSED */
void
ds_pnfsstat(DS_PNFSSTATargs *argp, DS_PNFSSTATres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
static void
dserv_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	rpcproc_t the_proc;
	union nfs_mds_cp_sarg darg;
	union nfs_mds_cp_sres dres;
	struct nfs_cp_disp *disp;

	/*
	 * validate version and procedure
	 */
	if (req->rq_vers != PNFSCTLMDS_V1) {
		svcerr_progvers(xprt, PNFSCTLMDS_V1, PNFSCTLMDS_V1);
		DTRACE_PROBE2(dserv__e__mdscp__badvers, rpcvers_t, req->rq_vers,
		    rpcvers_t, PNFSCTLMDS_V1);
		return;
	}

	the_proc = req->rq_proc;
	if (the_proc < 0 || the_proc >= NFS_MDS_CP_ILLEGAL_PROC) {
		svcerr_noproc(xprt);
		DTRACE_PROBE1(dserv__e__mdscp__badproc, rpcproc_t, the_proc);
		return;
	}

	/* If it's NULL Proc short circuit */
	if (the_proc == 0) {
		if (!svc_sendreply(xprt, xdr_void, NULL)) {
			DTRACE_PROBE(dserv__e__svc_reply_nullproc);
			svcerr_systemerr(xprt);
		}
		return;
	}

	disp = &nfs_mds_cp_v1[the_proc];

	/*
	 * decode args
	 */
	bzero(&darg, sizeof (union nfs_mds_cp_sarg));
	if (!SVC_GETARGS(xprt, disp->decode_args, (char *)&darg)) {
		svcerr_decode(xprt);
		DTRACE_PROBE2(dserv__e__mdscp__decode, rpcvers_t, req->rq_vers,
		    rpcproc_t, the_proc);
		return;
	}

	DTRACE_PROBE1(dserv__i__dserv_dispatch, int, the_proc);

	/*
	 * dispatch the call
	 * XXX - idempotency / dup checking
	 * XXX - getfh to check export
	 * XXX - T_DONTPEND/T_WOULDBLOCK
	 * XXX - auth_tooweak check
	 * XXX - counters of any kind
	 */
	bzero(&dres, sizeof (union nfs_mds_cp_sres));
	(*disp->proc)(darg, dres, req);

	/*
	 * send the reply
	 */
	if (!svc_sendreply(xprt, disp->encode_reply, (char *)&dres)) {
		DTRACE_PROBE(dserv__e__svc_sendreply);
		svcerr_systemerr(xprt);
	}

	/*
	 * free results
	 */
	if (disp->resfree)
		(*disp->resfree)(dres);

	/*
	 * free args
	 */
	if (!SVC_FREEARGS(xprt, disp->decode_args, (char *)&darg)) {
		DTRACE_PROBE(dserv__e__svc_freeargs);
	}

}

/* ARGSUSED */
static void
dmov_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	DTRACE_PROBE(dserv__i__dmov_dispatch);
}

/*ARGSUSED*/
static void
nnode_evict_error(dmu_buf_t *dbuf, void *user_ptr)
{
	/*
	 * We should never drop all dbuf refs without first clearing
	 * the eviction callback.
	 */
	panic("evicting nnode %p\n", user_ptr);
}

/*
 * Grabs the object id out of the File Handle map, if it exists.
 *
 * We are using the Fat ZAP because our name values will be > 50 characters and
 * we expect to have more than 2047 entries (which would correspond to the
 * number of distinct file objects stored on the data server).  This violates
 * the rules for using the Micro ZAP.
 */
static nnode_error_t
get_object_state(dserv_nnode_data_t *dnd, char *hex_fh)
{
	int error = 0;
	dmu_object_info_t doi;
	dmu_buf_t *db;

	/*
	 * Lookup based on the File Handle
	 */
	DTRACE_PROBE2(dserv__i__get_object_state, char *, hex_fh,
	    int, strlen(hex_fh));
	error = zap_lookup(dnd->dnd_objset, DMU_PNFS_FID_TO_OBJID_OBJECT,
	    hex_fh, 8, 1, &dnd->dnd_object);
	if (error)
		return (error);

	error = dmu_object_info(dnd->dnd_objset, dnd->dnd_object, &doi);
	if (error)
		return (error);
	if ((doi.doi_bonus_type != DMU_OT_NNODE) ||
	    (doi.doi_bonus_size != sizeof (dserv_nnode_data_phys_t)))
		return (ENOTTY);
	dnd->dnd_blksize = doi.doi_data_block_size;

	error = dmu_bonus_hold(dnd->dnd_objset, dnd->dnd_object, NULL, &db);
	if (error)
		return (error);
	dnd->dnd_dbuf = db;

	VERIFY(NULL == dmu_buf_set_user_ie(db, dnd, &dnd->dnd_phys,
	    nnode_evict_error));

	return (0);
}

static int
get_create_object_state(dserv_nnode_data_t *dnd, char *hex_fh)
{
	dserv_mds_instance_t *inst;
	int error = 0;
	dmu_tx_t *tx;
	dmu_buf_t *db;

	inst = dserv_mds_get_my_instance();
	if (inst == NULL) {
		DTRACE_PROBE(dserv__e__dserv_mds_get_my_instance);
		return (ESRCH);
	}

	mutex_enter(&inst->dmi_zap_lock);
	error = get_object_state(dnd, hex_fh);
	if (error != 0) {
		DTRACE_PROBE1(dserv__e__get_object_state, int, error);

		if (error == ENOENT) {
		/*
		 * ToDo: 1.) need to make sure that the offsets being
		 * written does not extend into a range that is not to be
		 * covered by this file (i.e. make sure the data belongs in
		 * this stripe).
		 */
			tx = dmu_tx_create(dnd->dnd_objset);
			dmu_tx_hold_bonus(tx, DMU_NEW_OBJECT);
			dmu_tx_hold_zap(tx, DMU_PNFS_FID_TO_OBJID_OBJECT, TRUE,
			    NULL);
			error = dmu_tx_assign(tx, TXG_WAIT);
			if (error) {
				DTRACE_PROBE1(dserv__e__dmu_tx_assign,
				    int, error);
				mutex_exit(&inst->dmi_zap_lock);
				dmu_tx_abort(tx);
				return (error);
			}

			/*
			 * Create the object.
			 */
			dnd->dnd_object = dmu_object_alloc(dnd->dnd_objset,
			    DMU_OT_PNFS_DATA, 0,
			    DMU_OT_NNODE, sizeof (dserv_nnode_data_phys_t),
			    tx);

			/*
			 * Get the persistent meta data.
			 */
			error = dmu_bonus_hold(dnd->dnd_objset, dnd->dnd_object,
			    NULL, &db);
			if (error) {
				mutex_exit(&inst->dmi_zap_lock);
				DTRACE_PROBE1(dserv__e__dmu_bonus_hold, int,
				    error);
				dmu_tx_commit(tx);
				return (error);
			}

			/*
			 * Create the File Handle map entry
			 */
			error = zap_add(dnd->dnd_objset,
			    DMU_PNFS_FID_TO_OBJID_OBJECT,
			    hex_fh, 8, 1, &dnd->dnd_object, tx);
			if (error) {
				mutex_exit(&inst->dmi_zap_lock);
				DTRACE_PROBE1(dserv__e__zap_add, int, error);
				/*
				 * Must call dmu_tx_commit(); dmu_tx_abort()
				 * cannot be called after dmu_tx_assign()
				 * has successfully completed.
				 */
				/* XXX any cleanup needed? */
				dmu_tx_commit(tx);
				dmu_buf_rele(db, NULL);
				return (error);
			}

			/*
			 * Initialize the persistent meta data.
			 */
			dnd->dnd_dbuf = db;
			VERIFY(NULL == dmu_buf_set_user_ie(db, dnd,
			    &dnd->dnd_phys, nnode_evict_error));
			dmu_buf_will_dirty(db, tx);
			bzero(dnd->dnd_phys, sizeof (dserv_nnode_data_phys_t));

			dmu_tx_commit(tx);
		} else {
			/*
			 * Some other error occured when trying to
			 * check for pre-existing objectid
			 */
			mutex_exit(&inst->dmi_zap_lock);
			return (error);
		}
	}

	mutex_exit(&inst->dmi_zap_lock);

	return (0);
}

static void
dserv_grow_blocksize(dserv_nnode_data_t *dnd, uint32_t size, dmu_tx_t *tx)
{
	int error;
	u_longlong_t dummy;

	ASSERT(size > dnd->dnd_blksize);

	/*
	 * If the file size is already greater than the current blocksize,
	 * we will not grow.  If there is more than one block in a file,
	 * the blocksize cannot change.
	 */
	if (dnd->dnd_blksize &&
	    dnd->dnd_phys->dp_size > dnd->dnd_blksize)
		return;

	error = dmu_object_set_blocksize(dnd->dnd_objset, dnd->dnd_object,
	    size, 0, tx);
	if (error == ENOTSUP)
		return;
	ASSERT3U(error, ==, 0);

	/* What blocksize did we actually get? */
	dmu_object_size_from_db(dnd->dnd_dbuf, &dnd->dnd_blksize, &dummy);
}

static nnode_error_t
dserv_nnode_data_getobject(dserv_nnode_data_t *dnd, int create)
{
	nnode_error_t rc = 0;
	char *hexfid;

	ASSERT(RW_READ_HELD(&dnd->dnd_rwlock));

	if (dnd->dnd_flags & DSERV_NNODE_FLAG_OBJECT)
		return (0);

	if (!rw_tryupgrade(&dnd->dnd_rwlock)) {
		rw_exit(&dnd->dnd_rwlock);
		rw_enter(&dnd->dnd_rwlock, RW_WRITER);
		if (dnd->dnd_flags & DSERV_NNODE_FLAG_OBJECT)
			goto out;
	}

	ASSERT(dnd->dnd_flags & DSERV_NNODE_FLAG_OBJSET);

	hexfid = dserv_tohex(dnd->dnd_fid->mds_fid_val,
	    dnd->dnd_fid->mds_fid_len);
	if (create)
		rc = get_create_object_state(dnd, hexfid);
	else
		rc = get_object_state(dnd, hexfid);
	dserv_strfree(hexfid);
	if (rc != 0) {
		DTRACE_PROBE1(dserv__e__dserv_getobject_get_object_state,
		    nnode_error_t, rc);
		goto out;
	}

	dnd->dnd_flags |= DSERV_NNODE_FLAG_OBJECT;

out:
	rw_downgrade(&dnd->dnd_rwlock);
	return (rc);
}
