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

#include <nfs/dserv_impl.h>

#include <sys/list.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs41_sessions.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfssys.h>
#include <nfs/nnode.h>
#include <nfs/ds_prot.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
#include <sys/dmu.h>
#include <sys/zap.h>
#include <sys/zio.h>
#include <sys/txg.h>
#include <sys/crc32.h>
#include <sys/sysmacros.h>
#include <sys/nbmlock.h>
#include <sys/strsubr.h>
#include <rpc/xdr.h>
#include <nfs/ds.h>
#include <nfs/export.h>

uint32_t max_blksize = SPA_MAXBLOCKSIZE;

char *pnfs_dmu_tag = "pNFS_TAG";	/* Tag used for DMU interfaces */

static nnode_error_t dserv_nnode_from_fh_ds(nnode_t **, mds_ds_fh *);
static void dserv_nnode_key_free(void *);
static dserv_nnode_data_t *dserv_nnode_data_alloc(void);
static dserv_nnode_state_t *dserv_nnode_state_alloc(void);
static nnode_error_t dserv_nnode_data_getobject(dserv_nnode_data_t *, int);
static nnode_error_t dserv_nnode_data_getobjset(dserv_nnode_data_t *, int);

static void dserv_dispatch(struct svc_req *, SVCXPRT *);
static void dmov_dispatch(struct svc_req *, SVCXPRT *);
static void dserv_grow_blocksize(dserv_nnode_data_t *, uint32_t, dmu_tx_t *);

union ctl_mds_srv_res;

static void ds_commit(DS_COMMITargs *,  DS_COMMITres *,
    struct svc_req *);
static void ds_getattr(DS_GETATTRargs *, DS_GETATTRres *,
    struct svc_req *);
static void ds_invalidate(DS_INVALIDATEargs *, DS_INVALIDATEres *,
    struct svc_req *);
static void ds_list(DS_LISTargs *, DS_LISTres *,
    struct svc_req *);
static void ds_obj_move(DS_OBJ_MOVEargs *, DS_OBJ_MOVEres *,
    struct svc_req *);
static void ds_obj_move_abort(DS_OBJ_MOVE_ABORTargs *, DS_OBJ_MOVE_ABORTres *,
    struct svc_req *);
static void ds_obj_move_status(DS_OBJ_MOVE_STATUSargs *,
    DS_OBJ_MOVE_STATUSres *,
    struct svc_req *);
static void ds_pnfsstat(DS_PNFSSTATargs *, DS_PNFSSTATres *,
    struct svc_req *);
static void ds_read(DS_READargs *, DS_READres *,
    struct svc_req *);
static void ds_obj_move(DS_OBJ_MOVEargs *, DS_OBJ_MOVEres *,
    struct svc_req *);
static void ds_obj_move_abort(DS_OBJ_MOVE_ABORTargs *, DS_OBJ_MOVE_ABORTres *,
    struct svc_req *);
static void ds_obj_move_status(DS_OBJ_MOVE_STATUSargs *,
    DS_OBJ_MOVE_STATUSres *, struct svc_req *);
static void ctl_mds_srv_remove(CTL_MDS_REMOVEargs *, CTL_MDS_REMOVEres *,
    struct svc_req *);
static void ds_setattr(DS_SETATTRargs *, DS_SETATTRres *,
    struct svc_req *);
static void ds_stat(DS_STATargs *, DS_STATres *,
    struct svc_req *);
static void ds_snap(DS_SNAPargs *, DS_SNAPres *,
    struct svc_req *);
static void ds_write(DS_WRITEargs *, DS_WRITEres *,
    struct svc_req *);
static void cp_nullfree(void);
static void ds_read_free(union ctl_mds_srv_res *);
static void ds_write_free(union ctl_mds_srv_res *);

extern u_longlong_t dserv_caller_id;

void dispatch_dserv_nfsv41(struct svc_req *, SVCXPRT *);

static int dserv_nnode_io_prep(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, offset_t, size_t, bslabel_t *);
static int dserv_nnode_read(void *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, uio_t *, int);
static int dserv_nnode_write(void *, nnode_io_flags_t *, uio_t *, int,
    cred_t *, caller_context_t *, wcc_data *);
static int dserv_nnode_remove_obj(void *);
static void dserv_nnode_data_free(void *);
static void dserv_nnode_state_free(void *);

static kmem_cache_t *dserv_nnode_key_cache;
static kmem_cache_t *dserv_nnode_data_cache;
static kmem_cache_t *dserv_nnode_state_cache;

time_t dserv_start_time;

static SVC_CALLOUT dserv_sc[] = {
	{ PNFS_CTL_MDS, PNFS_CTL_MDS_V1, PNFS_CTL_MDS_V1, dserv_dispatch },
	{ PNFSCTLMV, PNFSCTLMV_V1, PNFSCTLMV_V1, dmov_dispatch },
	/* The following is need to dispatch non-2049 NFS traffic */
	{ NFS_PROGRAM, 4, 4, dispatch_dserv_nfsv41 }
};

static SVC_CALLOUT_TABLE dserv_sct = {
	sizeof (dserv_sc) / sizeof (dserv_sc[0]), FALSE, dserv_sc
};

/*
 * Dispatch structure for the PNFS_CTL_MDS RPC program (MDS to DS control
 * protocol)
 */
struct ctl_mds_srv_disp {
	void		(*proc)();
	xdrproc_t	decode_args;
	xdrproc_t	encode_reply;
	void		(*resfree)();
	char		*name;
};

union ctl_mds_srv_arg {
	DS_COMMITargs 		ds_commit;
	DS_GETATTRargs 		ds_getattr;
	DS_SETATTRargs 		ds_setattr;
	DS_READargs 		ds_read;
	CTL_MDS_REMOVEargs 	ctl_mds_remove_args;
	DS_WRITEargs 		ds_write;
	DS_INVALIDATEargs 	ds_invalidate;
	DS_LISTargs 		ds_list;
	DS_STATargs 		ds_stat;
	DS_SNAPargs 		ds_snap;
	DS_PNFSSTATargs 	ds_pnfsstat;
};

union ctl_mds_srv_res {
	DS_COMMITres 		ds_commit;
	DS_GETATTRres 		ds_getattr;
	DS_SETATTRres 		ds_setattr;
	DS_READres 		ds_read;
	CTL_MDS_REMOVEres 	ctl_mds_remove_res;
	DS_WRITEres 		ds_write;
	DS_INVALIDATEres 	ds_invalidate;
	DS_LISTres 		ds_list;
	DS_STATres 		ds_stat;
	DS_SNAPres 		ds_snap;
	DS_PNFSSTATres 		ds_pnfsstat;
};

struct ctl_mds_srv_disp ctl_mds_srv_v1[] = {
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
	    ds_read_free, "DS_READ"},
	{ctl_mds_srv_remove, xdr_CTL_MDS_REMOVEargs, xdr_CTL_MDS_REMOVEres,
	    cp_nullfree, "DS_REMOVE"},
	{ds_setattr, xdr_DS_SETATTRargs, xdr_DS_SETATTRres,
	    cp_nullfree, "DS_SETATTR"},
	{ds_stat, xdr_DS_STATargs, xdr_DS_STATres,
	    cp_nullfree, "DS_STAT"},
	{ds_snap, xdr_DS_SNAPargs, xdr_DS_SNAPres,
	    cp_nullfree, "DS_SNAP"},
	{ds_write, xdr_DS_WRITEargs, xdr_DS_WRITEres,
	    ds_write_free, "DS_WRITE"}
};

static uint_t ctl_mds_srv_cnt =
    sizeof (ctl_mds_srv_v1) / sizeof (struct ctl_mds_srv_disp);

#define	CTL_MDS_ILLEGAL_PROC (ctl_mds_srv_cnt)

static nnode_data_ops_t dserv_nnode_data_ops = {
	.ndo_read = dserv_nnode_read,
	.ndo_write = dserv_nnode_write,
	.ndo_io_prep = dserv_nnode_io_prep,
	.ndo_remove_obj = dserv_nnode_remove_obj,
	.ndo_free = dserv_nnode_data_free
};


static nnode_state_ops_t dserv_nnode_state_ops = {
	.nso_checkstate = dserv_mds_checkstate,
	.nso_free = dserv_nnode_state_free
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

		error = dserv_instance_enter(RW_READER, B_FALSE, &inst, NULL);
		if (!error) {
			(void) rfs41_dispatch(req, xprt, (char *)&args);
			dserv_instance_exit(inst);
		} else {
			/*
			 * This is a non-recoverable error.
			 * Either we weren't able to find our instance
			 * (e.g. it has been shutdown) or the instance
			 * is in the process of being shutdown.
			 */
			send_nfs4err(NFS4ERR_IO, xprt);
			DTRACE_PROBE1(dserv__e__instancing, int, error);
		}
	}

	if (!SVC_FREEARGS(xprt, xdr_COMPOUND4args_srv, (char *)&args))
		DTRACE_PROBE(dserv__e__svc_freeargs);
}

static uint32_t
dserv_nnode_hash(dserv_nnode_key_t *key)
{
	uint32_t rc;

	CRC32(rc, key->dnk_fid->val, key->dnk_fid->len,
	    -1U, crc32_table);

	return (rc);
}

static int
dserv_nnode_compare(const void *va, const void *vb)
{
	const dserv_nnode_key_t *a = va;
	const dserv_nnode_key_t *b = vb;
	int rc;

	NFS_AVL_COMPARE(a->dnk_sid->len, b->dnk_sid->len);
	rc = memcmp(a->dnk_sid->val, b->dnk_sid->val, a->dnk_sid->len);
	NFS_AVL_RETURN(rc);

	NFS_AVL_COMPARE(a->dnk_fid->len, b->dnk_fid->len);
	rc = memcmp(a->dnk_fid->val, b->dnk_fid->val, a->dnk_fid->len);
	NFS_AVL_RETURN(rc);

	return (0);
}

/*
 * Allocates memory for dest_fh and copies source_fh into it.  Caller is
 * responsible for freeing memory allocated (using free_mds_ds_fh()).
 *
 * Function will return 0 on success and non-zero on failure.
 */
static nnode_error_t
copy_ds_fh(mds_ds_fh *source_fh, mds_ds_fh **dest_fh)
{
	nnode_error_t error = 0;

	*dest_fh = kmem_zalloc(sizeof (mds_ds_fh), KM_SLEEP);

	/* Shallow copy what we can */
	bcopy(source_fh, *dest_fh, sizeof (mds_ds_fh));

	/* Deep copy the pointers */
	switch (source_fh->vers) {
	case (DS_FH_v1):
		(*dest_fh)->fh.v1.mds_sid.len = source_fh->fh.v1.mds_sid.len;
		(*dest_fh)->fh.v1.mds_sid.val =
		    kmem_alloc(source_fh->fh.v1.mds_sid.len, KM_SLEEP);
		bcopy(source_fh->fh.v1.mds_sid.val,
		    (*dest_fh)->fh.v1.mds_sid.val,
		    source_fh->fh.v1.mds_sid.len);

		(*dest_fh)->fh.v1.mds_dataset_id.len =
		    source_fh->fh.v1.mds_dataset_id.len;
		bcopy(&source_fh->fh.v1.mds_dataset_id.val,
		    (*dest_fh)->fh.v1.mds_dataset_id.val,
		    source_fh->fh.v1.mds_dataset_id.len);

		goto out;
	default:
		error = EINVAL;
		goto out;
	}

out:
	return (error);
}


static nnode_error_t
dserv_nnode_build(nnode_seed_t *seed, void *vfh)
{
	mds_ds_fh *fhp = vfh;
	dserv_nnode_key_t *key = NULL;
	nnode_error_t rc = 0;
	dserv_nnode_data_t *data = NULL;
	dserv_nnode_state_t *state = NULL;

	key = kmem_cache_alloc(dserv_nnode_key_cache, KM_SLEEP);
	key->dnk_real_fid.len = fhp->fh.v1.mds_fid.len;
	bcopy(fhp->fh.v1.mds_fid.val, key->dnk_real_fid.val,
	    key->dnk_real_fid.len);
	key->dnk_sid = kmem_alloc(sizeof (mds_sid), KM_SLEEP);
	key->dnk_sid->len = fhp->fh.v1.mds_sid.len;
	key->dnk_sid->val = kmem_alloc(key->dnk_sid->len,
	    KM_SLEEP);

	bcopy(fhp->fh.v1.mds_sid.val, key->dnk_sid->val,
	    key->dnk_sid->len);

	data = dserv_nnode_data_alloc();
	data->dnd_fid = key->dnk_fid;
	rc = copy_ds_fh(fhp, &data->dnd_fh);
	if (rc)
		goto out;

	seed->ns_key = key;
	seed->ns_key_compare = dserv_nnode_compare;
	seed->ns_key_free = dserv_nnode_key_free;
	seed->ns_data_ops = &dserv_nnode_data_ops;
	seed->ns_data = data;

	state = dserv_nnode_state_alloc();
	rc = copy_ds_fh(fhp, &state->fh);
	if (rc)
		goto out;

	seed->ns_state_ops = &dserv_nnode_state_ops;
	seed->ns_state = state;

out:
	if (rc != 0) {
		if (key != NULL)
			dserv_nnode_key_free(key);
		if (data != NULL)
			dserv_nnode_data_free(data);
		if (state != NULL)
			dserv_nnode_state_free(state);
	}

	return (rc);
}

static nnode_error_t
dserv_nnode_from_fh_ds(nnode_t **npp, mds_ds_fh *fhp)
{
	dserv_nnode_key_t	dskey;

	nnode_key_t	key;
	uint32_t	hash;

	nnode_error_t	ne;

	if (fhp->vers < 1)
		return (ESTALE); /* XXX badhandle */
	if (fhp->fh.v1.mds_fid.len < 8) /* XXX stupid */
		return (ESTALE);
	if (fhp->fh.v1.mds_fid.len > DS_MAXFIDSZ)
		return (ESTALE);

	dskey.dnk_sid = kmem_alloc(sizeof (mds_sid), KM_SLEEP);
	dskey.dnk_sid->len = fhp->fh.v1.mds_sid.len;
	dskey.dnk_sid->val = kmem_alloc(dskey.dnk_sid->len,
	    KM_SLEEP);

	bcopy(fhp->fh.v1.mds_sid.val, dskey.dnk_sid->val,
	    dskey.dnk_sid->len);

	dskey.dnk_fid = &fhp->fh.v1.mds_fid;

	hash = dserv_nnode_hash(&dskey);

	key.nk_keydata = &dskey;
	key.nk_compare = dserv_nnode_compare;

	ne = nnode_find_or_create(npp, &key, hash, fhp, dserv_nnode_build);

	kmem_free(dskey.dnk_sid->val, dskey.dnk_sid->len);
	kmem_free(dskey.dnk_sid, sizeof (mds_sid));

	return (ne);
}

static void
cp_nullfree(void)
{
}

/*
 * Finds an MDS-FS object set with the given name.  If the object set does not
 * exist, this function DOES NOT create it.
 */
static int
get_mdsfs_objset(char *mdsfs_objset_name, objset_t **osp)
{
	int error = 0;

	DTRACE_PROBE1(dserv__i__get_mdsfs_objset, char *,
	    mdsfs_objset_name);

	error = dmu_objset_own(mdsfs_objset_name, DMU_OST_PNFS, B_FALSE,
	    pnfs_dmu_tag, osp);
	return (error);
}

/*
 * Finds or creates an MDS-FS object set with the given name.
 */
static int
get_create_mdsfs_objset(char *mdsfs_objset_name, objset_t **osp)
{
	dmu_tx_t *tx;
	int error = 0;

	error = get_mdsfs_objset(mdsfs_objset_name, osp);
	if (error) {
		if (error == ENOENT) {
			/* The object set needs to be created */
			error = dmu_objset_create(mdsfs_objset_name,
			    DMU_OST_PNFS, 0, NULL, NULL);

			if (error)
				return (error);

			/* Open the object set */
			error = dmu_objset_own(mdsfs_objset_name,
			    DMU_OST_PNFS, B_FALSE, pnfs_dmu_tag, osp);

			if (error) {
				DTRACE_PROBE2(
				    dserv__e__dmu_objset_open_after_create,
				    int, error, objset_t *, *osp);
				return (error);
			}

			/* Create the FID to Object ID ZAP object. */
			tx = dmu_tx_create(*osp);
			dmu_tx_hold_zap(tx, DMU_NEW_OBJECT, FALSE, NULL);
			error = dmu_tx_assign(tx, TXG_WAIT);

			if (error) {
				DTRACE_PROBE1(dserv__e__dmu_tx_assign,
				    int, error);
				dmu_tx_abort(tx);
				return (error);
			}
			error = zap_create_claim(*osp,
			    DMU_PNFS_FID_TO_OBJID_OBJECT,
			    DMU_OT_PNFS_INFO,
			    DMU_OT_NONE, 0, tx);

			if (error) {
				DTRACE_PROBE1(dserv__e___zap_create_claim,
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
 * Search the data server's open root object set data structures to see if
 * we have the root object set, which pertains to the MDS SID, open.
 *
 * Returns the open root object set in root_objset, if found.
 * Returns ENOENT if the root object set can't be found.
 */
/*ARGSUSED*/
static int
find_open_root_objset(dserv_mds_instance_t *inst, mds_sid mds_sid,
    open_root_objset_t **root_objset)
{
	int found_root_objset = 0;
	int found_mds_sid = 0;

	dserv_guid_t ds_guid;

	mds_sid_map_t		*sid_map;
	open_root_objset_t	*poro;

	ASSERT(MUTEX_HELD(&inst->dmi_content_lock));

	/*
	 * If this list is empty it means that the data server is not
	 * sharing any datasets (i.e. no root datasets have sharepnfs=on)
	 */
	if (list_is_empty(&inst->dmi_datasets)) {
		DTRACE_PROBE(dserv__i__root_dataset_list_is_empty);
		return (ENOENT);
	}

	/*
	 * XXX: This portion of the code will be put in when:
	 * 1. the data server populates its MDS SID to DS_GUID map
	 * (in memory (mds_sid_map_t) and on disk).
	 *
	 * Not yet done.
	 *
	 * 2. the MDS is embedding the appropriate MDS SIDs in
	 * its file handle.
	 *
	 * Done in the sense that the MDS SID is the dataset info
	 * sent in the DS_REPORTAVAIL...
	 */

	/*
	 * Use the MDS SID (from the file handle) to find the real data
	 * server guid (zpool guid + id of the root pNFS object set).
	 */
	sid_map = list_head(&inst->dmi_mds_sids);

	for (sid_map = list_head(&inst->dmi_mds_sids); sid_map != NULL;
	    sid_map = list_next(&inst->dmi_mds_sids, sid_map)) {
		if ((mds_sid.len == sid_map->msm_mds_storid.len) &&
		    (memcmp(mds_sid.val, sid_map->msm_mds_storid.val,
		    sid_map->msm_mds_storid.len) == 0)) {
			found_mds_sid = 1;
			ds_guid = sid_map->msm_ds_guid;
			break;
		}
	}

	/*
	 * If we have no record of the given MDS SID it may mean that
	 * we haven't been able to do the REPORTAVAIL for this particular
	 * resource.  Therefore, just tell the client to try again later.
	 * In the future, we will attempt to ask the MDS for this information
	 * via DS_MAP_MDSSID.
	 */
	if (found_mds_sid != 1)
		return (EAGAIN);

	/*
	 * Find the root pNFS object set.
	 */
	for (poro = list_head(&inst->dmi_datasets);
	    poro != NULL;
	    poro = list_next(&inst->dmi_datasets, poro)) {
		if (ds_guid.dg_zpool_guid ==
		    poro->oro_ds_guid.dg_zpool_guid &&
		    ds_guid.dg_objset_guid ==
		    poro->oro_ds_guid.dg_objset_guid) {
			/*
			 * This is our root pNFS object set!
			 */
			*root_objset = poro;
			found_root_objset = 1;
			break;
		}
	}

	if (found_root_objset != 1)
		return (ENOENT);

	return (0);
}

/*
 * Search the data server's open object set data structures to see if
 * we already hold an object set pointer pertaining to the given
 * MDS DATASET ID.  The object set pertaining to the MDS DATASET ID is
 * referred to as the "MDS-FS" object set.
 *
 * Return ENOENT if the object set is not open.
 */
/* ARGSUSED */
static int
find_open_mdsfs_objset(dserv_mds_instance_t *inst, mds_dataset_id dataset_id,
    open_root_objset_t *root_objset, objset_t **mdsfs_osp)
{
	open_mdsfs_objset_t *tmp_mdsfs;

	ASSERT(MUTEX_HELD(&inst->dmi_content_lock));

	/*
	 * Look for a dataset named after the MDS DATASET ID in the file handle.
	 * This will be the object set that the data object will reside in.
	 */
	for (tmp_mdsfs = list_head(&root_objset->oro_open_mdsfs_objsets);
	    tmp_mdsfs != NULL;
	    tmp_mdsfs = list_next(&root_objset->oro_open_mdsfs_objsets,
	    tmp_mdsfs)) {
		if ((dataset_id.len == tmp_mdsfs->omo_dataset_id.len) &&
		    (memcmp(dataset_id.val, tmp_mdsfs->omo_dataset_id.val,
		    tmp_mdsfs->omo_dataset_id.len) == 0)) {
			DTRACE_PROBE(dserv__i__mdsfs_objset_found);
			*mdsfs_osp = tmp_mdsfs->omo_osp;
			return (0);
		}
	}

	/*
	 * Falling through to here means we have not found the open MDS-FS
	 * object set.
	 */
	DTRACE_PROBE(dserv__i__mdsfs_objset_not_found);
	return (ENOENT);
}

/*
 * Retrieves the MDS-FS object set pointer that is associated with the given
 * MDS SID and MDS DATASET ID.  If the object set does not exist and create
 * is set, this function will create the MDS-FS object set.
 *
 * This function will return 0 on success.  It will return ENOENT if the object
 * set does not exist and create is not set. In the case of an unrecoverable
 * error (i.e. dmu_* functions return error), those errors will be passed
 * through to the caller of this function.
 */
static nnode_error_t
dserv_nnode_data_getobjset(dserv_nnode_data_t *dnd, int create)
{
	dserv_mds_instance_t *inst;
	open_root_objset_t *root_objset;
	mds_sid sid = dnd->dnd_fh->fh.v1.mds_sid;
	mds_dataset_id dataset_id = dnd->dnd_fh->fh.v1.mds_dataset_id;
	open_mdsfs_objset_t *new_mdsfs;
	char mdsfs_objset_name[MAXPATHLEN];
	char *mdsfs = NULL;
	nnode_error_t error = 0;

	ASSERT(RW_READ_HELD(&dnd->dnd_rwlock));

	if (dnd->dnd_flags & DSERV_NNODE_FLAG_OBJSET)
		return (0);

	if (!rw_tryupgrade(&dnd->dnd_rwlock)) {
		rw_exit(&dnd->dnd_rwlock);
		rw_enter(&dnd->dnd_rwlock, RW_WRITER);
		if (dnd->dnd_flags & DSERV_NNODE_FLAG_OBJSET) {
			rw_downgrade(&dnd->dnd_rwlock);
			return (0);
		}
	}

	inst = dserv_mds_get_my_instance();
	if (inst == NULL) {
		rw_downgrade(&dnd->dnd_rwlock);
		DTRACE_PROBE(dserv__e__dserv_mds_get_my_instance);
		return (ESRCH);
	}

	mutex_enter(&inst->dmi_content_lock);
	error = find_open_root_objset(inst, sid, &root_objset);
	if (error) {
		error = (error == ENOENT) ? EIO : error;
		goto out;
	}

	error = find_open_mdsfs_objset(inst, dataset_id, root_objset,
	    &(dnd->dnd_objset));
	if (error == 0 || error != ENOENT) {
		if (error == 0)
			dnd->dnd_flags |= DSERV_NNODE_FLAG_OBJSET;
		goto out;
	}

	/*
	 * error == ENOENT
	 *
	 * We didn't find the MDS-FS object set and it may just mean the
	 * object set exists, but has not yet been opened.
	 */

	/*
	 * The format of the MDS-FS object set name is:
	 * <zpool-name>/<rootpnfs-objset-name>/<mds_dataset_id>
	 *
	 * The name of the root pNFS dataset is stored by the data server
	 * in the open_root_objset_t.
	 * We may want to move away from doing this just in case the root
	 * pNFS dataset gets renamed.  If we continue to store the dataset
	 * name we will have to handle the case where a dataset gets renamed.
	 */
	mdsfs = tohex(dataset_id.val, dataset_id.len);
	(void) snprintf(mdsfs_objset_name, MAXPATHLEN, "%s%s%s",
	    root_objset->oro_objsetname, "/", mdsfs);

	if (create) {
		error = get_create_mdsfs_objset(mdsfs_objset_name,
		    &dnd->dnd_objset);
		if (error)
			goto out;
	} else {
		error = get_mdsfs_objset(mdsfs_objset_name, &dnd->dnd_objset);
		if (error)
			goto out;
	}

	/* Place entry in the the MDS-FS objset linked list */
	new_mdsfs = kmem_cache_alloc(dserv_open_mdsfs_objset_cache,
	    KM_SLEEP);
	bcopy(dataset_id.val, new_mdsfs->omo_dataset_id.val,
	    dataset_id.len);
	new_mdsfs->omo_dataset_id.len = dataset_id.len;
	new_mdsfs->omo_osp = dnd->dnd_objset;

	list_insert_tail(&root_objset->oro_open_mdsfs_objsets,
	    new_mdsfs);

	/*
	 * Set the OBJSET flag in the nnode signifying that we have
	 * found the object set!
	 */
	dnd->dnd_flags |= DSERV_NNODE_FLAG_OBJSET;

out:
	mutex_exit(&inst->dmi_content_lock);
	rw_downgrade(&dnd->dnd_rwlock);
	if (mdsfs != NULL)
		dserv_strfree(mdsfs);

	return (error);
}

/*ARGSUSED*/
static int
dserv_nnode_io_prep(void *vdata, nnode_io_flags_t *nnflags, cred_t *cr,
    caller_context_t *ct, offset_t off, size_t len, bslabel_t *clabel)
{
	dserv_nnode_data_t *data = vdata;
	nnode_error_t err = 0;
	int create;

	create = (*nnflags & NNODE_IO_FLAG_WRITE) ? B_TRUE : B_FALSE;

	rw_enter(&data->dnd_rwlock, RW_READER);
	if (! data->dnd_flags & DSERV_NNODE_FLAG_OBJSET) {
		/* Get the Object Set */
		err = dserv_nnode_data_getobjset(data, create);
		if (err)
			goto out;
	}

	if (! (data->dnd_flags & DSERV_NNODE_FLAG_OBJECT)) {
		/* Get the Object */
		err = dserv_nnode_data_getobject(data, create);
		if (err)
			goto out;
	}

	if (off > data->dnd_phys->dp_size)
		*nnflags |= NNODE_IO_FLAG_PAST_EOF;
out:
	rw_exit(&data->dnd_rwlock);

	if ((err == ENOENT) && !(*nnflags & NNODE_IO_FLAG_WRITE) &&
	    !(*nnflags & NNODE_IO_REMOVE_OBJ)) {
		*nnflags |= NNODE_IO_FLAG_PAST_EOF;
		err = 0;
	}
	return (err);
}

offset_t dserv_read_chunk_size = 1024 * 1024; /* Tunable */

/*ARGSUSED*/
static int
dserv_nnode_read(void *vdata, nnode_io_flags_t *nnflags, cred_t *cr,
    caller_context_t *ct, uio_t *uiop, int ioflag)
{
	dserv_nnode_data_t *data = vdata;
	nnode_error_t err = 0;
	ssize_t n, nbytes;

	rw_enter(&data->dnd_rwlock, RW_READER);
	if (uiop->uio_loffset >= data->dnd_phys->dp_size)
		goto out;

	ASSERT(data->dnd_flags & DSERV_NNODE_FLAG_OBJECT);
	n = MIN(uiop->uio_resid, data->dnd_phys->dp_size - uiop->uio_loffset);
	while (n > 0) {
		nbytes = MIN(n, dserv_read_chunk_size -
		    P2PHASE(uiop->uio_loffset, dserv_read_chunk_size));
		err = dmu_read_uio(data->dnd_objset, data->dnd_object, uiop,
		    nbytes);
		if (err != 0) {
			if (err == ECKSUM)
				err = EIO;
			goto out;
		}
		n -= nbytes;
	}

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

		new_size = end;
		if (end > data->dnd_blksize) {
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
	dnd->dnd_fh = NULL;
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

	if (dnd->dnd_fh != NULL)
		free_mds_ds_fh(dnd->dnd_fh);

	dnd->dnd_flags = 0;
	dnd->dnd_fh = NULL;
	dnd->dnd_fid = NULL;
	dnd->dnd_objset = NULL;
	dnd->dnd_dbuf = NULL;
	dnd->dnd_phys = NULL;
	kmem_cache_free(dserv_nnode_data_cache, dnd);
}

static dserv_nnode_state_t *
dserv_nnode_state_alloc(void)
{
	dserv_nnode_state_t *dns;
	dns = kmem_cache_alloc(dserv_nnode_state_cache, KM_SLEEP);
	dns->fh = NULL;

	return (dns);
}

static void
dserv_nnode_state_free(void *dstate)
{
	dserv_nnode_state_t *dns = dstate;

	if (dns->fh != NULL)
		free_mds_ds_fh(dns->fh);

	kmem_cache_free(dserv_nnode_state_cache, dns);
}

/*ARGSUSED*/
static int
dserv_nnode_key_construct(void *vdnk, void *foo, int bar)
{
	dserv_nnode_key_t *key = vdnk;

	key->dnk_sid = NULL;
	key->dnk_fid = &key->dnk_real_fid;

	return (0);
}

static void
dserv_nnode_key_free(void *dnk)
{
	dserv_nnode_key_t *key = dnk;

	if (key->dnk_sid) {
		kmem_free(key->dnk_sid->val, key->dnk_sid->len);
		kmem_free(key->dnk_sid, sizeof (mds_sid));
	}

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
	/*
	 * XXX: No constructor function needed for now. At this point, the only
	 * element of dserv_nnode_state_t is the DS filehandle, which gets
	 * initialized when the nnode is first created, and never modified
	 * after that. Thus, there is no need for any locking constructs for
	 * now. As we add more elements in dserv_nnode_state_t, we will add the
	 * locking.
	 *
	 * The elements of dserv_nnode_state_t will interact with the general
	 * state caching infrastructure, and hence the locking design will be
	 * done along with the design of state caching infrastructure.
	 */
	dserv_nnode_state_cache = kmem_cache_create("dserv_nnode_state_cache",
	    sizeof (dserv_nnode_state_t), 0, NULL, NULL, NULL, NULL,
	    NULL, 0);

	nnode_from_fh_ds = dserv_nnode_from_fh_ds;
}

void
dserv_server_teardown()
{
	nnode_from_fh_ds = NULL;

	kmem_cache_destroy(dserv_nnode_data_cache);
	kmem_cache_destroy(dserv_nnode_key_cache);
	kmem_cache_destroy(dserv_nnode_state_cache);
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
static void
ds_commit(DS_COMMITargs *argp, DS_COMMITres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__commit__done, DS_COMMITres *, resp);
}

/* ARGSUSED */
static void
ds_getattr(DS_GETATTRargs *argp, DS_GETATTRres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__getattr__done, DS_GETATTRres *, resp);
}

/* ARGSUSED */
static void
ds_invalidate(DS_INVALIDATEargs *argp, DS_INVALIDATEres *resp,
    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__invalidate__done, DS_INVALIDATEres *, resp);
}

/* ARGSUSED */
static void
ds_list(DS_LISTargs *argp, DS_LISTres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__list__done, DS_LISTres *, resp);
}

/* ARGSUSED */
static void
ds_obj_move(DS_OBJ_MOVEargs *argp, DS_OBJ_MOVEres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__obj_move__done, DS_OBJ_MOVEres *, resp);
}

/* ARGSUSED */
static void
ds_obj_move_abort(DS_OBJ_MOVE_ABORTargs *argp, DS_OBJ_MOVE_ABORTres *resp,
    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__obj_move_abort__done,
	    DS_OBJ_MOVE_ABORTres *, resp);
}

/* ARGSUSED */
static void
ds_obj_move_status(DS_OBJ_MOVE_STATUSargs *argp, DS_OBJ_MOVE_STATUSres *resp,
    struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__obj_move_status__done,
	    DS_OBJ_MOVE_STATUSres *, resp);
}

/* ARGSUSED */
static void
ds_pnfsstat(DS_PNFSSTATargs *argp, DS_PNFSSTATres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__pnfsstat__done, DS_PNFSSTATres *, resp);
}

/* ARGSUSED */
static void
ds_read(DS_READargs *argp, DS_READres *resp, struct svc_req *req)
{
	nnode_t *nn = NULL;
	nnode_error_t nerr;
	nnode_io_flags_t nnioflags = 0;
	struct iovec iov;
	struct uio uio;
	u_offset_t offset;
	caller_context_t ct;
	int i, segs, length;
	int prep = 0;
	ds_fileseg *segp;
	DS_READresok *rrok;
	mds_ds_fh *ds_fh;
	nfs_fh4 *otw_fh;

	/* Find nnode from filehandle */
	otw_fh =  &argp->fh;
	ds_fh = get_mds_ds_fh(otw_fh);
	if ((ds_fh == NULL)) {
		resp->status = DSERR_BADHANDLE;
		goto final;
	}
	nerr = nnode_from_fh_ds(&nn, ds_fh);
	free_mds_ds_fh(ds_fh);

	switch (nerr) {
	case 0:
		break;
	case ESTALE:
		resp->status = DSERR_STALE;
		goto final;
	default:
		resp->status = DSERR_BADHANDLE;
		goto final;
	}

	ct.cc_sysid = 0;
	ct.cc_pid = 0;
	ct.cc_caller_id = dserv_caller_id;

	rrok = &resp->DS_READres_u.res_ok;
	ASSERT(rrok);

	/* Got work? */
	if (argp->count == 0) {
		rrok->count = 0;
		resp->status = DS_OK;
		goto final;
	}

	/*
	 * Do each requested I/O
	 */
	resp->status = DS_OK;
	rrok->count = 0;
	segs = argp->rdv.rdv_len;
	segp = argp->rdv.rdv_val;
	rrok->rdv.rdv_len = segs;
	rrok->rdv.rdv_val =
	    kmem_zalloc(segs * sizeof (ds_filesegbuf), KM_SLEEP);
	for (i = 0; i < segs; i++) {
		char *base;

		length = segp[i].count;
		offset = segp[i].offset;

		if (length == 0) {
			rrok->count = 0;
			rrok->rdv.rdv_val[i].offset = offset;
			rrok->rdv.rdv_val[i].data.data_len = 0;
			rrok->rdv.rdv_val[i].data.data_val = NULL;
			continue;
		}

		nerr = nnop_io_prep(nn, &nnioflags, NULL, &ct,
		    offset, length, NULL);
		if (nerr != 0) {
			resp->status = DSERR_INVAL;
			goto final;
		}
		prep = 1;

		if (nnioflags & NNODE_IO_FLAG_PAST_EOF) {
			resp->status = DS_OK;
			rrok->eof = TRUE;
			rrok->rdv.rdv_val[i].offset = offset;
			rrok->rdv.rdv_val[i].data.data_len = 0;
			rrok->rdv.rdv_val[i].data.data_val = NULL;
			goto final;
		}

		if (length > rfs4_tsize(req))
			length = rfs4_tsize(req);

		/* Get a buffer to read into */
		base = kmem_alloc(length, KM_SLEEP);
		ASSERT(base != NULL);

		/* Set up a uio for nnop_read() */
		iov.iov_base = base;
		iov.iov_len = length;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_extflg = UIO_COPY_CACHED;
		uio.uio_loffset = offset;
		uio.uio_resid = length;

		nerr = nnop_read(nn, &nnioflags, NULL, &ct, &uio, 0);

		if (nerr) {
			if (base != NULL)
				kmem_free(base, length);
			resp->status = DSERR_INVAL;
			goto final;
		}

		ASSERT(uio.uio_resid >= 0);
		rrok->count = length - uio.uio_resid;
		if (rrok->count != length) {
			char *base2 = NULL;

			if (rrok->count != 0) {
				base2 = kmem_alloc(rrok->count, KM_SLEEP);
				bcopy(base, base2, rrok->count);
			}
			kmem_free(base, length);
			base = base2;
		}
		ASSERT(rrok->rdv.rdv_val);
		rrok->rdv.rdv_val[i].offset = offset;
		rrok->rdv.rdv_val[i].data.data_len = rrok->count;
		rrok->rdv.rdv_val[i].data.data_val = base;

		rrok->eof = (nnioflags & NNODE_IO_FLAG_EOF) ? TRUE : FALSE;

		nnop_io_release(nn, nnioflags, &ct);
		prep = 0;
	}

	resp->status = DS_OK;

final:

	if (prep)
		nnop_io_release(nn, nnioflags, &ct);

	if (nn != NULL)
		nnode_rele(&nn);

	DTRACE_NFSV4_1(ds_op__read__done, DS_READres *, resp);
}

static void
ds_read_free(union ctl_mds_srv_res *dres)
{
	DS_READres *rres = (DS_READres *)dres;
	DS_READresok *rrok;
	int i;

	rrok = &rres->DS_READres_u.res_ok;
	for (i = 0; i < rrok->rdv.rdv_len; i++)
		kmem_free(rrok->rdv.rdv_val[i].data.data_val,
		    rrok->rdv.rdv_val[i].data.data_len);
	kmem_free(rrok->rdv.rdv_val,
	    rrok->rdv.rdv_len * sizeof (ds_filesegbuf));
}

/* ARGSUSED */
static void
ctl_mds_srv_remove(CTL_MDS_REMOVEargs *argp, CTL_MDS_REMOVEres *resp,
    struct svc_req *req)
{
	nnode_t			*nn = NULL;
	nnode_io_flags_t	nnioflags = NNODE_IO_REMOVE_OBJ;

	if (argp->type == CTL_MDS_RM_OBJ) {
		nnode_error_t	nerr;
		int		error = 0;
		int		i;

		/*
		 * A CTL_MDS_REMOVE of type CTL_MDS_RM_OBJ allows the
		 * removal of one to many objects.
		 */
		for (i = 0; i < argp->CTL_MDS_REMOVEargs_u.obj.obj_len; i++) {
			mds_ds_fh	*ds_fh;

			nfs_fh4	*otw_fh =  &(argp->CTL_MDS_REMOVEargs_u.
			    obj.obj_val[i]);

			ds_fh = get_mds_ds_fh(otw_fh);
			if (ds_fh == NULL) {
				resp->status = DSERR_BADHANDLE;
				goto final;
			}

			if (nn != NULL)
				nnode_rele(&nn);
			nerr = nnode_from_fh_ds(&nn, ds_fh);
			free_mds_ds_fh(ds_fh);

			switch (nerr) {
			case 0: /* Success */
				break;
			case ESTALE:
				resp->status = DSERR_STALE;
				goto final;
			default:
				DTRACE_PROBE1(dserv__removefh__problem,
				    nnode_error_t, nerr);
				resp->status = DSERR_BADHANDLE;
				goto final;
			}

			/* Mark the object for removal. */
			/*
			 * If there is an error while removing the object,
			 * this flag will allow us to retry the removal
			 * of the object from the nnode garbage collection
			 * framework.
			 */
			error = nnode_set_flag(nn,
			    NNODE_OBJ_REMOVE_IN_PROGRESS);
			ASSERT(error);

			/*
			 * Prepare for removal of the object.  This includes
			 * retrieveing the object set and the DMU object id
			 * that the object lives in.
			 */
			nerr = nnop_io_prep(nn, &nnioflags, NULL, NULL, 0, 0,
			    NULL);
			if (nerr) {
				resp->status = DSERR_IO;
				goto final;
			}

			/*
			 * If the removal of the object fails, we just return
			 * the error to the MDS and the MDS is responsible for
			 * retrying the message.
			 */
			nerr = nnop_remove_obj(nn);
			switch (nerr) {
			case 0:
				/* Mark the object as removed! */
				error = nnode_clear_flag(nn,
				    NNODE_OBJ_REMOVE_IN_PROGRESS);
				ASSERT(error);

				error = nnode_set_flag(nn, NNODE_OBJ_REMOVED);
				ASSERT(error);
				break;
			default:
				resp->status = DSERR_IO;
				goto final;
			}
		}

		/*
		 * If we are here, we have gotten through all objects and
		 * are ready to return success!
		 */
		resp->status = DS_OK;
	} else if (argp->type == CTL_MDS_RM_MDS_DATASET_ID) {
		resp->status = DSERR_NOTSUPP;
	} else {
		resp->status = DSERR_NOTSUPP;
	}

final:

	/*
	 * Remove the reference on the nnode.
	 * The nnode will be garbage collected later.
	 */
	if (nn != NULL)
		nnode_rele(&nn);

	DTRACE_NFSV4_1(ds_op__remove__done, CTL_MDS_REMOVEres *, resp);
}

static int
dserv_nnode_remove_obj(void *vdnd)
{
	dserv_nnode_data_t *dnd = vdnd;
	char		*hex_fid;
	dmu_tx_t	*tx;
	int		error;

	hex_fid = tohex(dnd->dnd_fid->val, dnd->dnd_fid->len);

	/* The file has to exist on this dh */
	ASSERT(dnd->dnd_objset != NULL);

	tx = dmu_tx_create(dnd->dnd_objset);
	dmu_tx_hold_zap(tx, DMU_PNFS_FID_TO_OBJID_OBJECT, FALSE, NULL);
	error = dmu_tx_assign(tx, TXG_WAIT);
	if (error) {
		dmu_tx_abort(tx);
		kmem_free(hex_fid, strlen(hex_fid) + 1);
		goto final;
	}

	error = zap_remove(dnd->dnd_objset, DMU_PNFS_FID_TO_OBJID_OBJECT,
	    hex_fid, tx);

	/* Free hex_id then check for error */
	dserv_strfree(hex_fid);

	dmu_tx_commit(tx);
	if (!error)
		error = dmu_free_object(dnd->dnd_objset, dnd->dnd_object);

final:

	return (error);
}

/* ARGSUSED */
static void
ds_setattr(DS_SETATTRargs *argp, DS_SETATTRres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__setattr__done, DS_SETATTRres *, resp);
}

/* ARGSUSED */
static void
ds_stat(DS_STATargs *argp, DS_STATres * resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__stat__done, DS_STATres *, resp);
}

/* ARGSUSED */
static void
ds_snap(DS_SNAPargs *argp, DS_SNAPres *resp, struct svc_req *req)
{
	resp->status = DSERR_NOTSUPP;

final:

	DTRACE_NFSV4_1(ds_op__snap__done, DS_SNAPres *, resp);
}

/* ARGSUSED */
static void
ds_write(DS_WRITEargs *argp, DS_WRITEres *resp, struct svc_req *req)
{
	nnode_t *nn = NULL;
	nnode_error_t nerr;
	nnode_io_flags_t nnioflags = NNODE_IO_FLAG_WRITE;
	struct iovec iov;
	struct uio uio;
	u_offset_t offset;
	caller_context_t ct;
	int i, segs, length;
	int prep = 0;
	DS_WRITEresok *wrok;
	ds_filesegbuf *segp;
	mds_ds_fh *ds_fh;
	nfs_fh4 *otw_fh;

	/* Find nnode from filehandle */
	otw_fh =  &argp->fh;
	ds_fh = get_mds_ds_fh(otw_fh);
	if ((ds_fh == NULL)) {
		resp->status = DSERR_BADHANDLE;
		goto final;
	}
	nerr = nnode_from_fh_ds(&nn, ds_fh);
	free_mds_ds_fh(ds_fh);

	switch (nerr) {
	case 0:
		break;
	case ESTALE:
		resp->status = DSERR_STALE;
		goto final;
	default:
		resp->status = DSERR_BADHANDLE;
		goto final;
	}

	ct.cc_sysid = 0;
	ct.cc_pid = 0;
	ct.cc_caller_id = dserv_caller_id;

	wrok = &resp->DS_WRITEres_u.res_ok;
	ASSERT(wrok);

	/* Got work? */
	if (argp->count == 0) {
		wrok->wrv.wrv_len = 0;
		resp->status = DS_OK;
		goto final;
	}

	/*
	 * Do each requested I/O
	 */
	resp->status = DS_OK;
	segs = argp->wrv.wrv_len;
	segp = argp->wrv.wrv_val;
	wrok->wrv.wrv_len = segs;
	wrok->wrv.wrv_val =
	    kmem_zalloc(segs * sizeof (count4), KM_SLEEP);
	for (i = 0; i < segs; i++) {
		char *base;

		length = segp[i].data.data_len;
		offset = segp[i].offset;

		if (length == 0) {
			wrok->wrv.wrv_val[i] = 0;
			continue;
		}

		nerr = nnop_io_prep(nn, &nnioflags, NULL, &ct,
		    offset, length, NULL);
		if (nerr != 0) {
			resp->status = DSERR_INVAL;
			wrok->wrv.wrv_val[i] = 0;
			goto final;
		}
		prep = 1;

		if (length > rfs4_tsize(req))
			length = rfs4_tsize(req);

		/* Find data to write */
		base = segp[i].data.data_val;
		ASSERT(base != NULL);

		/* Set up a uio for nnop_write() */
		iov.iov_base = base;
		iov.iov_len = length;
		uio.uio_iov = &iov;
		uio.uio_iovcnt = 1;
		uio.uio_segflg = UIO_SYSSPACE;
		uio.uio_extflg = UIO_COPY_CACHED;
		uio.uio_loffset = offset;
		uio.uio_resid = length;

		nerr = nnop_write(nn, &nnioflags, &uio, 0, NULL, &ct, NULL);

		if (nerr) {
			resp->status = DSERR_INVAL;
			goto final;
		}

		ASSERT(uio.uio_resid >= 0);
		ASSERT(wrok->wrv.wrv_val);
		wrok->wrv.wrv_val[i] = length - uio.uio_resid;

		nnop_io_release(nn, nnioflags, &ct);
		prep = 0;
	}

	resp->status = DS_OK;

final:

	if (prep)
		nnop_io_release(nn, nnioflags, &ct);

	if (nn != NULL)
		nnode_rele(&nn);

	DTRACE_NFSV4_1(ds_op__write__done, DS_WRITEres *, resp);
}

static void
ds_write_free(union ctl_mds_srv_res *dres)
{
	DS_WRITEres *wres = (DS_WRITEres *)dres;
	DS_WRITEresok *wrok;

	wrok = &wres->DS_WRITEres_u.res_ok;
	kmem_free(wrok->wrv.wrv_val, wrok->wrv.wrv_len * sizeof (count4));
}

/* ARGSUSED */
static void
dserv_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	rpcproc_t the_proc;
	union ctl_mds_srv_arg darg;
	union ctl_mds_srv_res dres;
	struct ctl_mds_srv_disp *disp;

	/*
	 * validate version and procedure
	 */
	if (req->rq_vers != PNFS_CTL_MDS_V1) {
		svcerr_progvers(xprt, PNFS_CTL_MDS_V1, PNFS_CTL_MDS_V1);
		DTRACE_PROBE2(dserv__e__mdscp__badvers, rpcvers_t, req->rq_vers,
		    rpcvers_t, PNFS_CTL_MDS_V1);
		return;
	}

	the_proc = req->rq_proc;
	if (the_proc < 0 || the_proc >= CTL_MDS_ILLEGAL_PROC) {
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

	disp = &ctl_mds_srv_v1[the_proc];

	/*
	 * decode args
	 */
	bzero(&darg, sizeof (union ctl_mds_srv_arg));
	if (!SVC_GETARGS(xprt, disp->decode_args, (char *)&darg)) {
		svcerr_decode(xprt);
		DTRACE_PROBE2(dserv__e__ctl_mds_decode, rpcvers_t, req->rq_vers,
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
	bzero(&dres, sizeof (union ctl_mds_srv_res));
	(void) (*disp->proc)(&darg, &dres, req);

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
		(*disp->resfree)(&dres);

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

static nnode_error_t
get_create_object_state(dserv_nnode_data_t *dnd, char *hex_fh)
{
	dserv_mds_instance_t *inst;
	nnode_error_t error = 0;
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
			goto final;
	}

	ASSERT(dnd->dnd_flags & DSERV_NNODE_FLAG_OBJSET);

	hexfid = tohex(dnd->dnd_fid->val, dnd->dnd_fid->len);
	if (create)
		rc = get_create_object_state(dnd, hexfid);
	else
		rc = get_object_state(dnd, hexfid);
	dserv_strfree(hexfid);
	if (rc != 0) {
		DTRACE_PROBE1(dserv__e__dserv_getobject_get_object_state,
		    nnode_error_t, rc);
		goto final;
	}

	dnd->dnd_flags |= DSERV_NNODE_FLAG_OBJECT;
final:
	rw_downgrade(&dnd->dnd_rwlock);
	return (rc);
}
