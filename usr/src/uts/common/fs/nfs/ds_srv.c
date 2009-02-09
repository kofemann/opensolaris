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

#include <sys/systm.h>
#include <sys/sdt.h>
#include <rpc/types.h>
#include <sys/cmn_err.h>
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfs4.h>
#include <nfs/mds_state.h>
#include <nfs/nfssys.h>
#include <nfs/ds.h>
#include <sys/cmn_err.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>

rfs4_client_t *mds_findclient(nfs_client_id4 *, bool_t *, rfs4_client_t *);

static void nullfree(void);
static void ds_reportavail_free(DS_REPORTAVAILres *);

void ds_map_mds_dataset_id(DS_MAP_MDS_DATASET_IDargs *,
    DS_MAP_MDS_DATASET_IDres *, struct svc_req *);
void ds_checkstate(DS_CHECKSTATEargs *, DS_CHECKSTATEres *, struct svc_req *);
void ds_renew(DS_RENEWargs *, DS_RENEWres *, struct svc_req *);
void ds_reportavail(DS_REPORTAVAILargs *, DS_REPORTAVAILres *,
		    struct svc_req *);
void ds_exchange(DS_EXIBIargs *, DS_EXIBIres *, struct svc_req *);
void ds_sec_info(DS_SECINFOargs *, DS_SECINFOres *, struct svc_req *);
void ds_fmatpt(DS_FMATPTargs *, DS_FMATPTres *, struct svc_req *);
void ds_shutdown(DS_SHUTDOWNargs *, DS_SHUTDOWNres *, struct svc_req *);

void nfs_ds_cp_dispatch(struct svc_req *, SVCXPRT *);

static enum ds_status get_ds_status(nfsstat4);
static void get_access_mode(compound_state_t *, DS_CHECKSTATEres *);

ds_owner_t *mds_dsinfo_alloc(DS_EXIBIargs *);

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


union nfs_ds_cp_sarg {
	DS_EXIBIargs			ds_exchange;
	DS_CHECKSTATEargs		ds_checkstate;
	DS_RENEWargs			ds_renew;
	DS_REPORTAVAILargs		ds_reportavail;
	DS_MAP_MDS_DATASET_IDargs	ds_map_mds_dataset_id;
	DS_SECINFOargs			ds_secinfo;
	DS_FMATPTargs			ds_fmatpt;
	DS_SHUTDOWNargs			ds_shutdown;
};

union nfs_ds_cp_sres {
	DS_EXIBIres			ds_exchange;
	DS_CHECKSTATEres		ds_checkstate;
	DS_RENEWres			ds_renew;
	DS_REPORTAVAILres		ds_reportavail;
	DS_MAP_MDS_DATASET_IDres	ds_map_mds_dataset_id;
	DS_SECINFOres			ds_secinfo;
	DS_FMATPTres			ds_fmatpt;
	DS_SHUTDOWNres			ds_shutdown;
};


struct nfs_cp_disp nfs_ds_cp_v1[] = {
	{NULL, NULL, NULL, NULL, NULL}, /* RPC Null */
	{ds_checkstate, xdr_DS_CHECKSTATEargs, xdr_DS_CHECKSTATEres,
	    nullfree, "DS_CheckSstate"},
	{ds_exchange, xdr_DS_EXIBIargs, xdr_DS_EXIBIres,
	    nullfree, "DS_EXIBI"},
	{ds_fmatpt, xdr_DS_FMATPTargs, xdr_DS_FMATPTres,
	    nullfree, "DS_FmaTpt"},
	{ds_map_mds_dataset_id, xdr_DS_MAP_MDS_DATASET_IDargs,
	    xdr_DS_MAP_MDS_DATASET_IDres, nullfree, "DS_MapMdsDatasetId"},
	{NULL, NULL, NULL, NULL, "DS_MapMdsSid"},
	{ds_renew, xdr_DS_RENEWargs, xdr_DS_RENEWres, nullfree, "DS_Renew"},
	{ds_reportavail, xdr_DS_REPORTAVAILargs, xdr_DS_REPORTAVAILres,
	    ds_reportavail_free, "DS_ReportAvail"},
	{ds_sec_info, xdr_DS_SECINFOargs, xdr_DS_SECINFOres,
	    nullfree, "DS_SecInfo"},
	{ds_shutdown, xdr_DS_SHUTDOWNargs, xdr_DS_SHUTDOWNres,
	    nullfree, "DS_ShutDown"}
};

static uint_t nfs_ds_cp_cnt =
    sizeof (nfs_ds_cp_v1) / sizeof (struct nfs_cp_disp);

#define	NFS_CP_ILLEGAL_PROC (nfs_ds_cp_cnt)

static void
ds_reportavail_free(DS_REPORTAVAILres *resp)
{
	int i, j;

	if (resp->status == DS_OK) {
		DS_REPORTAVAILresok *res_ok =
		    &(resp->DS_REPORTAVAILres_u.res_ok);
		mds_sid *sid_array;
		uint32_t sid_array_len;

		/* Free the contents of the guid_map array */
		for (i = 0; i < res_ok->guid_map.guid_map_len; i++) {
			sid_array =
			    res_ok->guid_map.guid_map_val[i].mds_sid_array.
			    mds_sid_array_val;
			sid_array_len =
			    res_ok->guid_map.guid_map_val[i].mds_sid_array.
			    mds_sid_array_len;

			/* Free the contents of the mds_sid_array */
			for (j = 0; j < sid_array_len; j++) {
				/* Free the mds_sid_content */
				kmem_free(sid_array[j].val,
				    sid_array[j].len);

				/* Free the mds_sid */
				kmem_free(&sid_array[j], sizeof (mds_sid));
			}
		}
		/* Free the guid_map */
		kmem_free(res_ok->guid_map.guid_map_val,
		    res_ok->guid_map.guid_map_len);
	}
}

static void
nullfree(void)
{
}

mds_ds_fh *
get_mds_ds_fh(nfs_fh4 *otw_fh)
{
	XDR x;
	mds_ds_fh *fh;

	xdrmem_create(&x, otw_fh->nfs_fh4_val,
	    otw_fh->nfs_fh4_len, XDR_DECODE);

	fh = kmem_zalloc(sizeof (mds_ds_fh), KM_SLEEP);

	if (! xdr_ds_fh_fmt(&x, fh)) {
		kmem_free(fh, sizeof (mds_ds_fh));
		return (NULL);
	}
	return (fh);
}

vnode_t *
ds_fhtovp(mds_ds_fh *fhp, ds_status *statp)
{
	vnode_t *vp = NULL;
	int error;
	fsid_t *fs_id = (fsid_t *)fhp->fh.v1.mds_dataset_id.val;
	fid_t fidp;
	vfs_t *vfsp;

	vfsp = getvfs(fs_id);
	if (vfsp == NULL) {
		*statp = DSERR_BADHANDLE;
		return (NULL);
	}

	fidp.fid_len = fhp->fh.v1.mds_fid.len;

	bcopy(fhp->fh.v1.mds_fid.val,
	    fidp.fid_data, fidp.fid_len);

	error = VFS_VGET(vfsp, &vp, &fidp);

	/* release the hold from getvfs() */
	VFS_RELE(vfsp);

	if (error != 0) {
		*statp = DSERR_BADHANDLE;
		return (NULL);
	}

	*statp = DS_OK;
	return (vp);
}

rfs4_file_t *
mds_findfile_by_dsfh(nfs_server_instance_t *instp, mds_ds_fh *fhp)
{
	ds_status stat;
	vnode_t *vp;
	rfs4_file_t *fp;

	/* map ds_fh to vp */
	vp = ds_fhtovp(fhp, &stat);
	if (vp == NULL)
		return (NULL);

	mutex_enter(&vp->v_lock);
	fp = (rfs4_file_t *)vsd_get(vp, instp->vkey);
	mutex_exit(&vp->v_lock);

	if (fp == NULL)
		return (NULL);

	rfs4_dbe_lock(fp->dbe);
	if (rfs4_dbe_is_invalid(fp->dbe) ||
	    (rfs4_dbe_refcnt(fp->dbe) == 0)) {
		rfs4_dbe_unlock(fp->dbe);
		return (NULL);
	}

	rfs4_dbe_hold(fp->dbe);
	rfs4_dbe_unlock(fp->dbe);
	return (fp);
}

/*
 * Convert the NFS error into a control protocol error to be returned with
 * control protocol response. Converse of get_nfs_status on the data server
 */
static enum ds_status
get_ds_status(nfsstat4 stat)
{
	ds_status status;
	switch (stat) {
			case NFS4ERR_INVAL:
				status = DSERR_INVAL;
				break;
			case NFS4ERR_EXPIRED:
				status = DSERR_EXPIRED;
				break;
			case NFS4ERR_STALE_STATEID:
				status = DSERR_STALE_STATEID;
				break;
			case NFS4ERR_OPENMODE:
				status = DSERR_ACCESS;
				break;
			case NFS4ERR_BAD_STATEID:
				status = DSERR_BAD_STATEID;
				break;
			case NFS4ERR_OLD_STATEID:
				status = DSERR_OLD_STATEID;
				break;
			case NFS4ERR_GRACE:
				status = DSERR_GRACE;
				break;
			default:
				status = DSERR_RESOURCE;
				break;
		}
	return (status);
}

/*
 * Get access mode from rfs4_file_t.
 */
static void
get_access_mode(compound_state_t *cs, DS_CHECKSTATEres *resp)
{

	rfs4_file_t *fp;
	bool_t create = FALSE;

	fp = rfs4_findfile(cs->instp, cs->vp, NULL, &create);
	if (fp == NULL) {
		resp->status = DSERR_BADHANDLE;
		return;
	}
	rfs4_dbe_lock(fp->dbe);
	resp->DS_CHECKSTATEres_u.file_state.open_mode = fp->share_access;
	rfs4_dbe_unlock(fp->dbe);
	rfs4_file_rele(fp);
}

/* ARGSUSED */
void
ds_checkstate(DS_CHECKSTATEargs *argp, DS_CHECKSTATEres *resp,
		struct svc_req *req)
{
	compound_state_t *cs;
	mds_ds_fh *dfhp = NULL;
	nfsstat4 stat;
	nnode_error_t error;
	bool_t deleg;
	nnode_t *np;
	clientid4 clientid;
	vnode_t *vp;

	bzero(resp, sizeof (*resp));

	/*
	 * Decode the OTW DS file handle.
	 */
	if ((dfhp = get_mds_ds_fh(&argp->fh)) == NULL) {
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * Sanity check. Ensure that we are dealing with a DS file handle.
	 */
	if (dfhp->type != FH41_TYPE_DMU_DS ||
	    dfhp->vers != DS_FH_v1) {
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * Convert the ds file handle to a vnode. vnode is required by
	 * check_stateid.
	 */
	vp = ds_fhtovp(dfhp, &resp->status);

	/*
	 * We steal the reference from VFS_VGET in ds_fhtovp, so do not need to
	 * do VN_HOLD explicity. VN_RELE happens when the compound_state_t gets
	 * back to the kmem_cache via rfs41_compound_state_free.
	 */
	if (vp == NULL) {
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * We need to invoke the check_stateid through the nnode interface.
	 * Currently we do not have a method for deriving an nnode from a DS
	 * filehandle. Hence, we are using vnodes.
	 */
	error = nnode_from_vnode(&np, vp);
	if (error != 0) {
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * Allocate a compound struct, needed by the function
	 * that gets called via the nnode interface.
	 */
	cs = rfs41_compound_state_alloc(mds_server);

	/*
	 * Do a checkstate via nnode interface.
	 * XXX: The nnop_check_stateid function will call nso_checkstate which
	 * is mapped to the v4.0 check_stateid. This works for now because the
	 * way the stateids are being generated. However, when the stateids get
	 * generated with proper v4.1 bits, then either a different function
	 * needs to be called, or the check_stateid has to be enhanced to deal
	 * with v4.1 bits as well.
	 */
	deleg = FALSE;
	if ((stat = nnop_check_stateid(np, cs, argp->mode, &argp->stateid,
	    FALSE, &deleg, TRUE, NULL, &clientid)) != NFS4_OK) {
		resp->status = get_ds_status(stat);
		rfs41_compound_state_free(cs);
		return;
	}

	/*
	 * Copy the clientid that is returned from the check_stateid in the
	 * response.
	 */
	resp->DS_CHECKSTATEres_u.file_state.mds_clid = clientid;

	/*
	 * Obtain file access mode, which is returned as part of the response.
	 */
	get_access_mode(cs, resp);

#ifdef PERSISTENT_LAYOUT_ENABLED
	/*
	 * If layout has not been written to stable storage,
	 * then do so before issuing the reply.
	 */
	if (mds_put_layout(fp->flp, fp->vp)) {
		rfs4_state_rele(sp);
		rfs4_file_rele(fp);
		/*
		 * DSERR_RESOURCE? DSERR_NOSPC?
		 */
		resp->status = DSERR_SERVERFAULT;
		return;
	}
#endif
	/*
	 * XXX: Todo List
	 * Validate security flavor.
	 * Authenticate.
	 * Return layout information.
	 */

	rfs41_compound_state_free(cs);
	resp->status = DS_OK;
}

/*
 * Data Server wants to know pathname at MDS for
 * specified object.
 */

/* ARGSUSED */
void
ds_map_mds_dataset_id(DS_MAP_MDS_DATASET_IDargs *argp,
    DS_MAP_MDS_DATASET_IDres *resp, struct svc_req *req)
{
	/* we're done! */
	resp->status = DSERR_NOTSUPP;
}

ds_owner_t *
mds_find_ds_owner_by_id(ds_id ds_id)
{
	ds_owner_t *dop = NULL;
	bool_t create = FALSE;

	rw_enter(&mds_server->ds_owner_lock, RW_READER);
	dop = (ds_owner_t *)rfs4_dbsearch(mds_server->ds_owner_idx,
	    (void *)(uintptr_t)ds_id,
	    &create, NULL, RFS4_DBS_VALID);
	rw_exit(&mds_server->ds_owner_lock);

	return (dop);
}

/* ARGSUSED */
void
mds_ds_rebooted(ds_owner_t *dop)
{
	/*
	 * clean up MDSs' DS state held or something!
	 */
}


/* ARGSUSED */
void
ds_renew(DS_RENEWargs *argp, DS_RENEWres *resp, struct svc_req *rqstp)
{
	ds_owner_t *dop;

	/* do some basic sanity checks */
	if (argp->ds_id == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	dop = mds_find_ds_owner_by_id(argp->ds_id);

	if (dop == NULL) {
		resp->status = DSERR_EXPIRED;
		return;
	}

	rfs4_dbe_lock(dop->dbe);
	dop->last_access = gethrestime_sec();
	if (dop->verifier != argp->ds_boottime) {
		dop->dsi_flags |= MDS_DSI_REBOOTED;
		dop->verifier = argp->ds_boottime;
	}
	rfs4_dbe_unlock(dop->dbe);

	/* if needed call mds_ds_rebooted() to do cleanup. */

	resp->DS_RENEWres_u.mds_boottime = mds_server->Write4verf;
	resp->status = DS_OK;
}

/* ARGSUSED */
void
ds_sec_info(DS_SECINFOargs *argp, DS_SECINFOres *resp, struct svc_req *rqstp)
{
	/*
	 * insert server code here
	 */
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_fmatpt(DS_FMATPTargs *argp, DS_FMATPTres *resp, struct svc_req *rqstp)
{
	/*
	 * insert server code here
	 */
	resp->status = DSERR_NOTSUPP;
}

/* ARGSUSED */
void
ds_shutdown(DS_SHUTDOWNargs *argp, DS_SHUTDOWNres *resp, struct svc_req *rqstp)
{
	/*
	 * insert server code here
	 */
	resp->status = DSERR_NOTSUPP;
}

int
ds_get_remote_uaddr(struct svc_req *rp, char *buf, int with_port)
{
	const char *kinet_ntop6(uchar_t *, char *, size_t);

	struct sockaddr *sap;
	struct sockaddr_in6 *sin6;
	struct sockaddr_in *sin;
	uchar_t *b;
	char  udder[INET6_ADDRSTRLEN];

	ASSERT(rp);

	sap = (struct sockaddr *)svc_getrpccaller(rp->rq_xprt)->buf;

	if (sap == NULL) {
		return (DS_INVAL);
	}

	switch (sap->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)sap;

		b = (uchar_t *)&sin->sin_addr;
		if (with_port)
			(void) sprintf(buf, "%d.%d.%d.%d.%2d.%2d",
			    b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF,
			    b[3] & 0xFF,
			    sin->sin_port >> 8,
			    sin->sin_port & 255);
		else
			(void) sprintf(buf, "%d.%d.%d.%d",
			    b[0] & 0xFF, b[1] & 0xFF, b[2] & 0xFF,
			    b[3] & 0xFF);

		break;

	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)sap;

		(void) kinet_ntop6((uchar_t *)&sin6->sin6_addr,
		    udder, INET6_ADDRSTRLEN);
		if (with_port)
			(void) sprintf(buf, "%s.%02d.%02d", udder,
			    sin6->sin6_port >> 8,
			    sin6->sin6_port & 255);
		else
			(void) sprintf(buf, "%s", udder);
	default:
		return (DS_INVAL);
	}
	return (DS_OK);
}

/* ARGSUSED */
int
mds_rpt_avail_update(ds_owner_t *dp,
		DS_REPORTAVAILargs *argp,
		DS_REPORTAVAILres *resp)
{
	printf("DS_REPORTAVAIL: Update\n");

	return (0);
}

/* ARGSUSED */
ds_guid_info_t *
ds_guid_info_add(ds_owner_t *dop, struct ds_storinfo *si)
{
	pinfo_create_t pic_arg;
	ds_guid_info_t *pip;

	pic_arg.dop = dop;
	pic_arg.si = si;

	rw_enter(&mds_server->ds_guid_info_lock, RW_WRITER);

	if ((pip = (ds_guid_info_t *)rfs4_dbcreate(
	    mds_server->ds_guid_info_idx,
	    (void *)&pic_arg)) == NULL) {
		rw_exit(&mds_server->ds_guid_info_lock);
		return (NULL);
	}
	rw_exit(&mds_server->ds_guid_info_lock);
	return (pip);
}

char *
kstrdup(const char *s)
{
	size_t len;
	char *new;

	len = strlen(s);
	new = kmem_alloc(len + 1, KM_SLEEP);
	bcopy(s, new, len);
	new[len] = '\0';

	return (new);
}

static char *
uaddr_trunc_port(char *uaddr)
{
	int pos, dc;
	char *port_less = NULL;

	if (uaddr == NULL)
		return (NULL);

	pos = strlen(uaddr);

	for (dc = 2; pos > 0; pos--) {
		if (uaddr[pos] == '.') {
			dc--;
			if (dc == 0) {
				uaddr[pos] = 0;
				port_less = kstrdup(uaddr);
				uaddr[pos] = '.';
				break;
			}
		}
	}
	return (port_less);
}

ds_owner_t *
mds_find_ds_owner(DS_EXIBIargs *args, bool_t *create)
{
	ds_owner_t *dop = NULL;

	/*
	 * using the data-server identity string find
	 * an the ds_owner structure
	 */
	rw_enter(&mds_server->ds_owner_lock, RW_READER);
	dop = (ds_owner_t *)rfs4_dbsearch(mds_server->ds_owner_inst_idx,
	    (void *)args->ds_ident.instance.instance_val,
	    create, (void *)args, RFS4_DBS_VALID);
	rw_exit(&mds_server->ds_owner_lock);

	return (dop);
}

/*
 */
ds_status
mds_ds_addrlist_update(ds_owner_t *dop, struct ds_addr *dap)
{
	struct mds_adddev_args darg;
	bool_t create = FALSE;
	ds_addrlist_t *devp;
	ds_status stat = DS_OK;

	/* search for existing entry */
	rw_enter(&mds_server->ds_addrlist_lock, RW_WRITER);
	if ((devp = (ds_addrlist_t *)rfs4_dbsearch(
	    mds_server->ds_addrlist_uaddr_idx,
	    (void *)dap->addr.na_r_addr,
	    &create, NULL, RFS4_DBS_VALID)) != NULL) {
		MDS_SET_DS_FLAGS(devp->dev_flags, dap->validuse);
		rw_exit(&mds_server->ds_addrlist_lock);
		return (stat);
	}

	bzero(&darg, sizeof (darg));

	darg.dev_netid = kstrdup(dap->addr.na_r_netid);
	darg.dev_addr  = kstrdup(dap->addr.na_r_addr);

	/* make it */
	devp = (ds_addrlist_t *)rfs4_dbcreate(mds_server->ds_addrlist_idx,
	    (void *)&darg);

	if (devp) {
		devp->ds_owner = dop;
		MDS_SET_DS_FLAGS(devp->dev_flags, dap->validuse);
		list_insert_tail(&dop->ds_addrlist_list, devp);
	} else
		stat = DSERR_INVAL;

	rw_exit(&mds_server->ds_addrlist_lock);
	return (stat);
}

/*
 * mds_ds_initnet builds a knetconfig structure for the
 * netid, address and port.
 */
int
mds_ds_initnet(ds_addrlist_t *dp)
{
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	char *devname;
	vnode_t *vp;
	int error;
	int af;
	int newknc = 0, newnb = 0;

	if (dp->dev_knc == NULL) {
		newknc = 1;
		dp->dev_knc = kmem_zalloc(sizeof (struct knetconfig), KM_SLEEP);
	}

	dp->dev_knc->knc_semantics = NC_TPI_COTS;
	if (strcmp(dp->dev_addr.na_r_netid, "tcp") == 0) {
		dp->dev_knc->knc_protofmly = "inet";
		dp->dev_knc->knc_proto = "tcp";
		devname = "/dev/tcp";
		af = AF_INET;
	} else if (strcmp(dp->dev_addr.na_r_netid, "tcp6") == 0) {
		dp->dev_knc->knc_protofmly = "inet6";
		dp->dev_knc->knc_proto = "tcp"; /* why not tcp6? */
		devname = "/dev/tcp6";
		af = AF_INET6;
	} else {
		error = EINVAL;
		goto out;
	}

	error = lookupname(devname, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (error)
		goto out;
	if (vp->v_type != VCHR) {
		VN_RELE(vp);
		error = EINVAL;
		goto out;
	}
	dp->dev_knc->knc_rdev = vp->v_rdev;
	VN_RELE(vp);

	if (dp->dev_nb == NULL) {
		newnb = 1;
		dp->dev_nb = kmem_zalloc(sizeof (struct netbuf), KM_SLEEP);
	} else if (dp->dev_nb->buf)
		kmem_free(dp->dev_nb->buf, dp->dev_nb->maxlen);

	if (af == AF_INET) {
		dp->dev_nb->maxlen = dp->dev_nb->len =
		    sizeof (struct sockaddr_in);
		dp->dev_nb->buf = kmem_zalloc(dp->dev_nb->maxlen, KM_SLEEP);
		addr4 = (struct sockaddr_in *)dp->dev_nb->buf;
		addr4->sin_family = af;
		error = uaddr2sockaddr(af, dp->dev_addr.na_r_addr,
		    &addr4->sin_addr, &addr4->sin_port);
	} else { /* AF_INET6 */
		dp->dev_nb->maxlen = dp->dev_nb->len =
		    sizeof (struct sockaddr_in6);
		dp->dev_nb->buf = kmem_zalloc(dp->dev_nb->maxlen, KM_SLEEP);
		addr6 = (struct sockaddr_in6 *)dp->dev_nb->buf;
		addr6->sin6_family = af;
		error = uaddr2sockaddr(af, dp->dev_addr.na_r_addr,
		    &addr6->sin6_addr, &addr6->sin6_port);
	}

out:
	if (error) {
		if (newknc && dp->dev_knc) {
			kmem_free(dp->dev_knc, sizeof (struct knetconfig));
			dp->dev_knc = NULL;
		}
		if (newnb && dp->dev_nb) {
			if (dp->dev_nb->buf)
				kmem_free(dp->dev_nb->buf, dp->dev_nb->maxlen);
			kmem_free(dp->dev_nb, sizeof (struct netbuf));
			dp->dev_nb = NULL;
		}
	}
	return (error);
}

ds_status
mds_rpt_avail_add(ds_owner_t *dop, DS_REPORTAVAILargs *argp,
    DS_REPORTAVAILres  *resp)
{
	int i, count;
	ds_guid_info_t *gip;
	struct ds_guid_map *guid_map;
	DS_REPORTAVAILresok *res_ok;
	XDR xdr;
	int xdr_size;
	char *xdr_buffer;
	ds_addrlist_t *dp;
	ds_addr *addrp;
	nfs_server_instance_t *instp;

	/*
	 * First deal with the universal addresses
	 */
	for (i = 0; i < argp->ds_addrs.ds_addrs_len; i++) {
		addrp = &argp->ds_addrs.ds_addrs_val[i];
		(void) mds_ds_addrlist_update(dop, addrp);
		instp = dbe_to_instp(dop->dbe);
		dp = mds_find_ds_addrlist_by_uaddr(instp,
		    addrp->addr.na_r_addr);
		if (dp == NULL)
			continue;
		(void) mds_ds_initnet(dp);
	}

	res_ok = &(resp->DS_REPORTAVAILres_u.res_ok);

	/*
	 * Set the attribute version so the data server knows which
	 * set of attributes the MDS knows about.  Note: this is just
	 * ignored right now.
	 */
	res_ok->ds_attrvers = DS_ATTR_v1;

	/*
	 * Now process the data store information.
	 *
	 * The number of entries in the response's guid_map is equal
	 * to the number of storage items the data server sent over
	 * with the REPORTAVAIL.  We will only have a guid_map entry
	 * in the response for the storage items that were sent in
	 * the arguments.
	 */
	guid_map = kmem_alloc(sizeof (struct ds_guid_map) *
	    argp->ds_storinfo.ds_storinfo_len, KM_SLEEP);

	count = 0;
	for (i = 0; i < argp->ds_storinfo.ds_storinfo_len; i++) {
		gip = ds_guid_info_add(dop,
		    &argp->ds_storinfo.ds_storinfo_val[i]);
		if (gip != NULL) {
			mds_sid *sid;
			mds_sid_content sid_content;

			/* Data Server GUIDs */
			/* Only supported type is ZFS */
			ASSERT(gip->ds_guid.stor_type == ZFS);
			guid_map[count].ds_guid = gip->ds_guid;

			ASSERT(gip->ds_guid.ds_guid_u.zfsguid.zfsguid_len
			    == sizeof (mds_sid_content));

			/*
			 * MDS SIDs: these would come from the mds_mapzap,
			 * but for now we just reuse the ds_guid
			 */
			bcopy(gip->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
			    &sid_content, sizeof (sid_content));

			xdr_size = xdr_sizeof(xdr_mds_sid_content,
			    &sid_content);
			ASSERT(xdr_size);

			xdr_buffer = kmem_alloc(xdr_size, KM_SLEEP);
			xdrmem_create(&xdr, xdr_buffer, xdr_size, XDR_ENCODE);

			if (xdr_mds_sid_content(&xdr, &sid_content) ==
			    FALSE) {
				kmem_free(xdr_buffer, xdr_size);
				return (DSERR_XDR);
			}
			sid = kmem_alloc(sizeof (mds_sid), KM_SLEEP);
			sid->len = xdr_size;
			sid->val = xdr_buffer;

			/*
			 * There is only one MDS SID associated with this
			 * DS GUID
			 */
			guid_map[count].mds_sid_array.mds_sid_array_len = 1;
			guid_map[count].mds_sid_array.mds_sid_array_val =
			    sid;
			count++;
			rfs4_dbe_rele(gip->dbe);
		}
	}

	if (count) {
		res_ok->guid_map.guid_map_len = count;
		res_ok->guid_map.guid_map_val = guid_map;
	} else {
		res_ok->guid_map.guid_map_len = 0;
		res_ok->guid_map.guid_map_val = NULL;
	}

	return (DS_OK);
}

/* ARGSUSED */
void
ds_reportavail(DS_REPORTAVAILargs *argp, DS_REPORTAVAILres *resp,
	struct svc_req *rqstp)
{
	ds_owner_t *dop;
	ds_status stat;

	/*
	 * data-server has no id so no soup for you.
	 */
	if (argp->ds_id == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	dop = mds_find_ds_owner_by_id(argp->ds_id);

	if (dop == NULL) {
		resp->status = DSERR_NOT_AUTH;
		return;
	}

	/*
	 * ToDo: Check the verifier (args->ds_verifier).
	 */
	if (list_head(&dop->ds_addrlist_list) == NULL)
		stat = mds_rpt_avail_add(dop, argp, resp);
	else
		stat = mds_rpt_avail_update(dop, argp, resp);

	resp->status = stat;
}

/*
 * XXX:
 * XXX: Needs to have nfs_server_instance passed in to it..
 * XXX:
 */
/* ARGSUSED */
void
ds_exchange(DS_EXIBIargs *argp, DS_EXIBIres *resp, struct svc_req *rqstp)
{
	extern void mds_nuke_layout(nfs_server_instance_t *, uint32_t);

	ds_owner_t *dop;
	ds_addrlist_t *dp;
	bool_t do_create = TRUE;
	DS_EXIBIresok *dser = &(resp->DS_EXIBIres_u.res_ok);

	unsigned long hostid = 0;

	/*
	 * Do some initial validation of the request.
	 */
	if (argp->ds_ident.boot_verifier == 0 ||
	    argp->ds_ident.instance.instance_len == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	dop = mds_find_ds_owner(argp, &do_create);
	ASSERT(dop);
	/*
	 * If the find found the ds_owner we need to do
	 * some clean up
	 */
	if (do_create == FALSE) {
		/*
		 * XXXXXX Needs rework XXXXXXX
		 *
		 * pre-existing ds_owner, for now just
		 * trash existing devices, assume data-server
		 * reboot and remove default layout...
		 */

		/* brute force it */
		rw_enter(&mds_server->ds_addrlist_lock, RW_WRITER);
		while (dp = list_head(&dop->ds_addrlist_list)) {
			rfs4_dbe_invalidate(dp->dbe);
			list_remove(&dop->ds_addrlist_list, dp);
		}
		rw_exit(&mds_server->ds_addrlist_lock);
		/* what about the ds_guid_info list ?? */
	}

	/* Again, needs rework */
	mds_nuke_layout(mds_server, 1);

	/*
	 * XXXX: This would be a good place to notice the
	 * XXXX: data-server has rebooted and we need to
	 * XXXX: trash/invalidate/recall associated
	 * XXXX: state.. of course the device information
	 * XXXX: may have not changed (but ds_verifier would have)
	 * XXXX: Hmmm..perhaps the correct place is in ds_reportavail
	 * XXXX: when we notice an update (as opposed to add)
	 */
	resp->status = DS_OK;
	dser->ds_id = dop->ds_id;

	(void) ddi_strtoul(hw_serial, NULL, 10, &hostid);
	dser->mds_id = (uint64_t)hostid;

	dser->mds_boot_verifier = mds_server->Write4verf;

	dser->mds_lease_period = mds_server->lease_period;
}


void
nfs_ds_cp_dispatch(struct svc_req *req, SVCXPRT *xprt)
{
	rpcproc_t which;
	union nfs_ds_cp_sarg darg;
	union nfs_ds_cp_sres dres;
	struct nfs_cp_disp *disp;

	/*
	 * validate version and procedure
	 */
	if (req->rq_vers != PNFSCTLDS_V1) {
		svcerr_progvers(req->rq_xprt, PNFSCTLDS_V1, PNFSCTLDS_V1);
		DTRACE_PROBE2(nfssrv__e__dscp__badvers, rpcvers_t, req->rq_vers,
		    rpcvers_t, PNFSCTLDS_V1);
		return;
	}

	which = req->rq_proc;
	if (which < 0 || which >= NFS_CP_ILLEGAL_PROC) {
		svcerr_noproc(req->rq_xprt);
		DTRACE_PROBE1(nfssrv__e__dscp__badproc, rpcproc_t, which);
		return;
	}


	/* RPC NULL is the zero proc, so short circuit */
	if (which == 0) {
		(void) svc_sendreply(xprt, xdr_void, NULL);
		return;
	}

	disp = &nfs_ds_cp_v1[which];

	/*
	 * decode args
	 */
	bzero(&darg, sizeof (union nfs_ds_cp_sarg));
	if (!SVC_GETARGS(xprt, disp->decode_args, (char *)&darg)) {
		svcerr_decode(xprt);
		DTRACE_PROBE2(nfssrv__e__dscp__decode, rpcvers_t, req->rq_vers,
		    rpcproc_t, which);
		return;
	}

	(*disp->proc)(&darg, &dres, req);

	/*
	 * encode result
	 */
	if (!svc_sendreply(xprt, disp->encode_reply, (char *)&dres)) {
		DTRACE_PROBE2(nfssrv__e__dscp__sendreply,
		    rpcvers_t, req->rq_vers, rpcproc_t, which);
		svcerr_systemerr(xprt);
	}
}
