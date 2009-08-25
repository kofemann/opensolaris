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
#include <sys/ddi.h>
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
#include <nfs/spe_impl.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>

extern int inet_pton(int, char *, void *);

rfs4_client_t *mds_findclient(nfs_client_id4 *, bool_t *, rfs4_client_t *);

static void nullfree(void);
static void ds_reportavail_free(DS_REPORTAVAILres *);
static void ds_checkstate_free(DS_CHECKSTATEres *);

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
 * XXX
 * This variable is used to select regular NFS server behaviour
 * (no DSs) vs. the need to use proxy I/O to read/write data
 * from the DSs.  At some point, this needs to be replaced by
 * a per-export setting that indicates whether data is local
 * or remote, so that we can handle both pNFS and locally-
 * provisioned UFS or other data.
 */
int nfs_ds_present = 0;			/* Has a DS checked in yet? */

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
	    ds_checkstate_free, "DS_Checkstate"},
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

/*
 * XXX: The layout field of the response is not being filled, and hence
 * will not be freed here. The for loop will not be entered.
 */
static void
ds_checkstate_free(DS_CHECKSTATEres *resp)
{
	int i;
	uint_t lo_len;
	layout4 *lo_val;
	uint_t loc_len;
	char *loc_val;
	ds_filestate *fs;

	fs = &(resp->DS_CHECKSTATEres_u.file_state);
	if (resp->status == DS_OK && fs != NULL) {
		lo_len = fs->layout.layout_len;
		lo_val = fs->layout.layout_val;

		for (i = 0; i < lo_len; i++) {
			loc_len = lo_val[i].lo_content.loc_body.loc_body_len;
			loc_val = lo_val[i].lo_content.loc_body.loc_body_val;
			kmem_free(loc_val, loc_len);
			kmem_free(&lo_val[i], sizeof (layout4));
		}
	}
}

static void
ds_reportavail_free(DS_REPORTAVAILres *resp)
{
	int i, j;

	DS_REPORTAVAILresok *res_ok;
	mds_sid *sid_array;
	uint32_t sid_array_len;

	if (resp->status != DS_OK)
		return;

	res_ok = &(resp->DS_REPORTAVAILres_u.res_ok);

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
		}

		/* Free the mds_sid */
		kmem_free(sid_array, sid_array_len * sizeof (mds_sid));
	}

	/* Free the guid_map */
	kmem_free(res_ok->guid_map.guid_map_val,
	    res_ok->guid_map.guid_map_len *
	    sizeof (struct ds_guid_map));
}

static void
nullfree(void)
{
}

mds_ds_fh *
get_mds_ds_fh(nfs_fh4 *otw_fh)
{
	XDR		x;
	mds_ds_fh	*fh;

	xdrmem_create(&x, otw_fh->nfs_fh4_val,
	    otw_fh->nfs_fh4_len, XDR_DECODE);

	fh = kmem_zalloc(sizeof (mds_ds_fh), KM_SLEEP);

	if (!xdr_ds_fh_fmt(&x, fh)) {
		free_mds_ds_fh(fh);
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

	mutex_enter(&vp->v_vsd_lock);
	fp = (rfs4_file_t *)vsd_get(vp, instp->vkey);
	mutex_exit(&vp->v_vsd_lock);

	if (fp == NULL)
		return (NULL);

	rfs4_dbe_lock(fp->rf_dbe);
	if (rfs4_dbe_is_invalid(fp->rf_dbe) ||
	    (rfs4_dbe_refcnt(fp->rf_dbe) == 0)) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return (NULL);
	}

	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_unlock(fp->rf_dbe);
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
	rfs4_dbe_lock(fp->rf_dbe);
	resp->DS_CHECKSTATEres_u.file_state.open_mode = fp->rf_share_access;
	rfs4_dbe_unlock(fp->rf_dbe);
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
	rfs4_file_t *fp;

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
	if (dfhp->type != FH41_TYPE_DMU_DS || dfhp->vers != DS_FH_v1) {
		free_mds_ds_fh(dfhp);
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * Convert the ds file handle to a vnode. vnode is required by
	 * check_stateid.
	 */
	vp = ds_fhtovp(dfhp, &resp->status);
	free_mds_ds_fh(dfhp);

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
		VN_RELE(vp);
		resp->status = DSERR_BADHANDLE;
		return;
	}

	/*
	 * Allocate a compound struct, needed by the function
	 * that gets called via the nnode interface.
	 */
	cs = rfs41_compound_state_alloc(mds_server);
	cs->vp = vp;
	cs->nn = np;

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

	deleg = FALSE;	/* ugly reuse */
	fp = rfs4_findfile(cs->instp, vp, NULL, &deleg);
	if (fp != NULL) {
		/*
		 * If layout has not been written to stable storage,
		 * then do so before issuing the reply.
		 */
		if (mds_put_layout(fp->rf_mlo, fp->rf_vp)) {
			rfs4_file_rele(fp);
			rfs41_compound_state_free(cs);
			/*
			 * DSERR_RESOURCE? DSERR_NOSPC?
			 */
			resp->status = DSERR_SERVERFAULT;
			return;
		}
		rfs4_file_rele(fp);
		resp->status = DS_OK;
	} else {
		resp->status = DSERR_SERVERFAULT;
	}

	/*
	 * XXX: Todo List
	 * Validate security flavor.
	 * Authenticate.
	 * Return layout information.
	 */

	rfs41_compound_state_free(cs);
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
	 * XXX: clean up MDSs' DS state held or something!
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
		resp->status = DSERR_STALE_DSID;
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

	rfs4_dbe_rele(dop->dbe);   /* search */
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
ds_guid_info_t *
ds_guid_info_add(ds_owner_t *dop, struct ds_storinfo *si)
{
	pinfo_create_t	pic_arg;
	ds_guid_info_t	*pgi;

	bool_t	create = FALSE;

	pic_arg.ds_owner = dop;
	pic_arg.si = si;

	rw_enter(&mds_server->ds_guid_info_lock, RW_WRITER);
	pgi = (ds_guid_info_t *)rfs4_dbsearch(
	    mds_server->ds_guid_info_idx,
	    (void *)&si->ds_storinfo_u.zfs_info.guid_map.ds_guid,
	    &create, (void *)&pic_arg, RFS4_DBS_VALID);

	/*
	 * Get rid of the old one.
	 */
	if (pgi) {
		rfs4_dbe_rele(pgi->dbe);
		rfs4_dbe_invalidate(pgi->dbe);
	}

	pgi = (ds_guid_info_t *)rfs4_dbcreate(
	    mds_server->ds_guid_info_idx,
	    (void *)&pic_arg);

	rw_exit(&mds_server->ds_guid_info_lock);

	return (pgi);
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
	 * the ds_owner structure
	 */
	rw_enter(&mds_server->ds_owner_lock, RW_WRITER);
	dop = (ds_owner_t *)rfs4_dbsearch(mds_server->ds_owner_inst_idx,
	    (void *)args->ds_ident.instance.instance_val,
	    create, (void *)args, RFS4_DBS_VALID);
	rw_exit(&mds_server->ds_owner_lock);

	return (dop);
}

void
mds_ds_address_to_key(ds_addrlist_t *dp, int af)
{
	int	len;
	int	t;

	char	*address, *port;

	address = kstrdup(dp->dev_addr.na_r_addr);
	len = strlen(address) + 1;

	/*
	 * These are network addresses + port information
	 * We don't care about the format for the network
	 * address, but we do care that the port is
	 * described by .NUM.NUM after it.
	 */
	port = strrchr(address, '.');
	if (!port)
		goto error;

	*port++ = '\0';
	t = stoi(&port);
	dp->ds_port_key = t;

	port = strrchr(address, '.');
	if (!port)
		goto error;

	*port++ = '\0';
	t = stoi(&port);
	dp->ds_port_key |= t << 8;

	t = inet_pton(af, address, &dp->ds_addr_key);
	if (t != 1)
		goto error;

	kmem_free(address, len);
	return;

error:
	dp->ds_addr_key = 0;
	dp->ds_port_key = 0;

	kmem_free(address, len);
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

	mds_ds_address_to_key(dp, af);

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

void
mds_ds_addrlist_update(ds_owner_t *dop, struct ds_addr *dap)
{
	struct mds_adddev_args darg;
	bool_t		create = FALSE;
	ds_addrlist_t	*dp;
	ds_addrlist_t	dp_map;

	int		af;

	dp_map.dev_addr.na_r_addr = dap->addr.na_r_addr;
	dp_map.dev_addr.na_r_netid = dap->addr.na_r_netid;
	if (strcmp(dp_map.dev_addr.na_r_netid, "tcp") == 0) {
		af = AF_INET;
	} else if (strcmp(dp_map.dev_addr.na_r_netid, "tcp6") == 0) {
		af = AF_INET6;
	} else {
		return;
	}

	mds_ds_address_to_key(&dp_map, af);

	rw_enter(&mds_server->ds_addrlist_lock, RW_WRITER);

	/* search for existing entry */
	dp = (ds_addrlist_t *)rfs4_dbsearch(
	    mds_server->ds_addrlist_addrkey_idx,
	    (void *)&dp_map.ds_addr_key,
	    &create, NULL, RFS4_DBS_VALID);
	if (dp != NULL) {
		/*
		 * XXX: Check to see that we are on the same port.
		 */
		goto done;
	}

	bzero(&darg, sizeof (darg));

	darg.dev_netid = dap->addr.na_r_netid;
	darg.dev_addr  = dap->addr.na_r_addr;

	/* make it */
	dp = (ds_addrlist_t *)rfs4_dbcreate(mds_server->ds_addrlist_idx,
	    (void *)&darg);
	if (dp == NULL) {
		rw_exit(&mds_server->ds_addrlist_lock);
		return;
	}

	dp->ds_owner = dop;
	rfs4_dbe_hold(dop->dbe);
	list_insert_tail(&dop->ds_addrlist_list, dp);

done:

	MDS_SET_DS_FLAGS(dp->dev_flags, dap->validuse);
	rw_exit(&mds_server->ds_addrlist_lock);
	(void) mds_ds_initnet(dp);

	rfs4_dbe_rele(dp->dbe);
}

/* ARGSUSED */
void
ds_reportavail(DS_REPORTAVAILargs *argp, DS_REPORTAVAILres *resp,
	struct svc_req *rqstp)
{
	ds_owner_t	*dop;

	int	i, j;
	int	count;

	ds_guid_info_t		*pgi;
	struct ds_guid_map	*guid_map;
	DS_REPORTAVAILresok	*res_ok;

	ds_addr	*dap;

	mds_sid_content	sid_content;

	mds_sid		*sid_array;
	uint32_t	sid_array_len;

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

	/*
	 * First deal with the universal addresses
	 */
	for (i = 0; i < argp->ds_addrs.ds_addrs_len; i++) {
		dap = &argp->ds_addrs.ds_addrs_val[i];

		/*
		 * Create the entry and link it into the
		 * ds_owner's list of addrlist entries.
		 */
		mds_ds_addrlist_update(dop, dap);
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
		/*
		 * Note: If we find an pre-existing entry, we
		 * will delete it and create a new one.
		 * If there is then an error, then the old
		 * entry will still be unavailable.
		 */
		pgi = ds_guid_info_add(dop,
		    &argp->ds_storinfo.ds_storinfo_val[i]);
		if (pgi == NULL) {
			continue;
		}

		/* Data Server GUIDs */
		/* Only supported type is ZFS */
		ASSERT(pgi->ds_guid.stor_type == ZFS);
		guid_map[count].ds_guid = pgi->ds_guid;

		ASSERT(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len
		    == sizeof (mds_sid_content));

		/*
		 * MDS SIDs: these would come from the mds_mapzap,
		 * but for now we just reuse the ds_guid
		 *
		 * Note that whatever is used as the MDS SID
		 * can not just be the ZFS id for the root fileset
		 * as a mds could have multiple root filesets...
		 */
		bcopy(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
		    &sid_content, sizeof (sid_content));

		/*
		 * There is only one MDS SID associated with this
		 * DS GUID
		 *
		 * XXX: But as we move a dataset to a new DS,
		 * we might have multiple MDS SIDs.
		 */
		guid_map[count].mds_sid_array.mds_sid_array_len =
		    sid_array_len = 1;
		guid_map[count].mds_sid_array.mds_sid_array_val =
		    sid_array =
		    kmem_zalloc(sid_array_len * sizeof (mds_sid),
		    KM_SLEEP);

		/*
		 * Note, since we stuff the xdr_buffer into the
		 * sid_array, we never explicitly free it by name!
		 */
		sid_array[0].len = pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len;
		sid_array[0].val = kmem_alloc(sid_array[0].len, KM_SLEEP);
		bcopy(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
		    sid_array[0].val, sid_array[0].len);
		count++;

		rfs4_dbe_rele(pgi->dbe);
	}

	if (count) {
		res_ok->guid_map.guid_map_len = count;
		res_ok->guid_map.guid_map_val = guid_map;

		/*
		 * XXX: Once we finish kspe with the SMF work,
		 * we will end up pulling this out!
		 */
		rw_enter(&mds_server->ds_guid_info_lock, RW_WRITER);
		mds_server->ds_guid_info_count += count;
		rw_exit(&mds_server->ds_guid_info_lock);
	} else {
		res_ok->guid_map.guid_map_len = 0;
		res_ok->guid_map.guid_map_val = NULL;
	}

	/*
	 * Make sure we set the bit that we've seen a DS check in
	 */
	if (nfs_ds_present == 0)
		nfs_ds_present = 1;

	rfs4_dbe_rele(dop->dbe);   /* search */

	resp->status = DS_OK;

	return;

cleanup:

	for (i = 0; i < count; i++) {
		sid_array = guid_map[i].mds_sid_array.mds_sid_array_val;
		sid_array_len = guid_map[i].mds_sid_array.mds_sid_array_len;

		pgi = mds_find_ds_guid_info_by_id(&guid_map[i].ds_guid);
		if (pgi != NULL) {
			for (j = 0; j < sid_array_len; j++) {
				kmem_free(sid_array[j].val,
				    sid_array[j].len);
			}

			kmem_free(sid_array,
			    sid_array_len * sizeof (mds_sid));

			rfs4_dbe_rele(pgi->dbe);   /* search */

			list_remove(&pgi->ds_owner->ds_guid_list, pgi);
			rfs4_dbe_rele(pgi->ds_owner->dbe);

			rfs4_dbe_invalidate(pgi->dbe);
		}
	}

	kmem_free(guid_map, sizeof (struct ds_guid_map) *
	    argp->ds_storinfo.ds_storinfo_len);

	rfs4_dbe_rele(dop->dbe);   /* search */
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
	/*
	 * XXX: This will go away with the SMF work!
	 */
	extern void mds_nuke_layout(nfs_server_instance_t *, uint32_t);

	int	lo_id;

	ds_owner_t *dop;
	ds_addrlist_t *dp;
	ds_guid_info_t	*pgi;
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
	if (!dop) {
		resp->status = DSERR_NOENT;
		return;
	}

	/*
	 * We found a match, now we need to see if it is the same
	 * instance as before!
	 */
	if (do_create == FALSE) {
		/*
		 * Only if the verifiers differ should we assume
		 * a reboot.
		 */
		if (argp->ds_ident.boot_verifier != dop->verifier) {
			/* brute force it */
			DTRACE_PROBE(nfssrv__i__dscp_freeing_device_entries);
			rw_enter(&mds_server->ds_addrlist_lock, RW_WRITER);
			while (dp = list_head(&dop->ds_addrlist_list)) {
				list_remove(&dop->ds_addrlist_list, dp);
				dp->ds_owner = NULL;
				rfs4_dbe_rele(dop->dbe);
				rfs4_dbe_invalidate(dp->dbe);
			}
			rw_exit(&mds_server->ds_addrlist_lock);

			rw_enter(&mds_server->ds_guid_info_lock, RW_WRITER);
			while (pgi = list_head(&dop->ds_guid_list)) {
				list_remove(&dop->ds_guid_list, pgi);

				/*
				 * XXX: Hack alert!
				 */
				ASSERT(mds_server->ds_guid_info_count > 0);
				mds_server->ds_guid_info_count--;

				pgi->ds_owner = NULL;
				rfs4_dbe_rele(dop->dbe);
				rfs4_dbe_invalidate(pgi->dbe);
			}
			rw_exit(&mds_server->ds_guid_info_lock);
		}

		/*
		 * XXX: This stuff needs to give way to something
		 * smarter.
		 */
		rw_enter(&mds_server->mds_layout_lock, RW_WRITER);
		lo_id = mds_server->mds_layout_default_idx;
		mds_server->mds_layout_default_idx = 0;
		rw_exit(&mds_server->mds_layout_lock);

		mds_nuke_layout(mds_server, lo_id);
	}

	/*
	 * XXXX: This would be a good place to notice the
	 * XXXX: data-server has rebooted and we need to
	 * XXXX: trash/invalidate/recall associated
	 * XXXX: state.. of course the device information
	 * XXXX: may have not changed (but ds_verifier would have)
	 * XXXX: Hmmm..perhaps the correct place is in ds_reportavail
	 * XXXX: when we notice an update (as opposed to add)
	 *
	 * XXX: But we wouldn't notice an update because we just
	 * emptied the addrlist above.
	 */
	resp->status = DS_OK;
	dser->ds_id = dop->ds_id;

	(void) ddi_strtoul(hw_serial, NULL, 10, &hostid);
	dser->mds_id = (uint64_t)hostid;
	dser->mds_boot_verifier = mds_server->Write4verf;
	dser->mds_lease_period = mds_server->lease_period;

	rfs4_dbe_rele(dop->dbe);   /* create/search */
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

	/*
	 * free results
	 */
	if (disp->resfree) {
		(*disp->resfree)(&dres);
	}

	/*
	 * free arguments
	 */
	if (!SVC_FREEARGS(xprt, disp->decode_args, (char *)&darg)) {
		DTRACE_PROBE2(nfssrv__e__svc__freeargs, rpcvers_t, req->rq_vers,
		    rpcproc_t, which);
	}
}
