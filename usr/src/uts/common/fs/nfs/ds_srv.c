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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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


rfs4_client_t *mds_findclient(nfs_client_id4 *, bool_t *, rfs4_client_t *);

static void nullfree(void);
static void ds_reportavail_free(DS_REPORTAVAILres *);

void ds_map_fsid(DS_MAP_FSIDargs *, DS_MAP_FSIDres *, struct svc_req *);
void ds_checkstate(DS_CHECKSTATEargs *, DS_CHECKSTATEres *, struct svc_req *);
void ds_renew(DS_RENEWargs *, DS_RENEWres *, struct svc_req *);
void ds_reportavail(DS_REPORTAVAILargs *, DS_REPORTAVAILres *,
		    struct svc_req *);
void ds_exchange(DS_EXIBIargs *, DS_EXIBIres *, struct svc_req *);
void ds_sec_info(DS_SECINFOargs *, DS_SECINFOres *, struct svc_req *);
void ds_fmatpt(DS_FMATPTargs *, DS_FMATPTres *, struct svc_req *);
void ds_shutdown(DS_SHUTDOWNargs *, DS_SHUTDOWNres *, struct svc_req *);

void nfs_ds_cp_dispatch(struct svc_req *, SVCXPRT *);


mds_dsinfo_t *mds_dsinfo_alloc(DS_EXIBIargs *);

extern krwlock_t    mds_dsinfo_lock;
extern rfs4_index_t *mds_dsinfo_inst_idx;
extern uint_t nfs4_srv_vkey;

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
	DS_EXIBIargs		ds_exchange;
	DS_CHECKSTATEargs	ds_checkstate;
	DS_RENEWargs		ds_renew;
	DS_REPORTAVAILargs	ds_reportavail;
	DS_MAP_FSIDargs		ds_map_fsid;
	DS_SECINFOargs		ds_secinfo;
	DS_FMATPTargs		ds_fmatpt;
	DS_SHUTDOWNargs		ds_shutdown;
};

union nfs_ds_cp_sres {
	DS_EXIBIres		ds_exchange;
	DS_CHECKSTATEres	ds_checkstate;
	DS_RENEWres		ds_renew;
	DS_REPORTAVAILres	ds_reportavail;
	DS_MAP_FSIDres		ds_map_fsid;
	DS_SECINFOres		ds_secinfo;
	DS_FMATPTres		ds_fmatpt;
	DS_SHUTDOWNres		ds_shutdown;
};


struct nfs_cp_disp nfs_ds_cp_v1[] = {
	{NULL, NULL, NULL, NULL, NULL}, /* RPC Null */
	{ds_exchange, xdr_DS_EXIBIargs, xdr_DS_EXIBIres,
	    nullfree, "DS_EXIBI"},
	{ds_checkstate, xdr_DS_CHECKSTATEargs, xdr_DS_CHECKSTATEres,
	    nullfree, "DS_CheckSstate"},
	{ds_renew, xdr_DS_RENEWargs, xdr_DS_RENEWres, nullfree, "DS_Renew"},
	{ds_reportavail, xdr_DS_REPORTAVAILargs, xdr_DS_REPORTAVAILres,
	    ds_reportavail_free, "DS_ReportAvail"},
	{ds_map_fsid, xdr_DS_MAP_FSIDargs, xdr_DS_MAP_FSIDres,
	    nullfree, "DS_MapFsid"},
	{ds_sec_info, xdr_DS_SECINFOargs, xdr_DS_SECINFOres,
	    nullfree, "DS_SecInfo"},
	{ds_fmatpt, xdr_DS_FMATPTargs, xdr_DS_FMATPTres,
	    nullfree, "DS_FmaTpt"},
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
		DS_REPORTAVAILres_ok *res_ok = &(resp->DS_REPORTAVAILres_u.r);
		mds_ppid *ppid_array;
		uint32_t ppid_array_len;

		/* Free the contents of the guid_map array */
		for (i = 0; i < res_ok->guid_map.guid_map_len; i++) {
			ppid_array =
			    res_ok->guid_map.guid_map_val[i].mds_ppid_array.
			    mds_ppid_array_val;
			ppid_array_len =
			    res_ok->guid_map.guid_map_val[i].mds_ppid_array.
			    mds_ppid_array_len;

			/* Free the contents of the mds_ppid_array */
			for (j = 0; j < ppid_array_len; j++) {
				/* Free the mds_ppid_content */
				kmem_free(ppid_array[j].mds_ppid_val,
				    ppid_array[j].mds_ppid_len);

				/* Free the mds_ppid */
				kmem_free(&ppid_array[j], sizeof (mds_ppid));
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

static mds_ds_fh *
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
	fsid_t fs_id;
	fid_t fidp;
	vfs_t *vfsp;


	fs_id.val[0] = fhp->fh.v1.fsid.major;
	fs_id.val[1] = fhp->fh.v1.fsid.minor;

	vfsp = getvfs(&fs_id);
	if (vfsp == NULL) {
		*statp = DSERR_BAD_FH;
		return (NULL);
	}

	bzero(&fs_id, sizeof (fs_id));

	fidp.fid_len = fhp->fh.v1.mds_fid.mds_fid_len;

	bcopy(fhp->fh.v1.mds_fid.mds_fid_val,
	    fidp.fid_data, fidp.fid_len);

	error = VFS_VGET(vfsp, &vp, &fidp);

	/* release the hold from getvfs() */
	VFS_RELE(vfsp);

	if (error != 0) {
		*statp = DSERR_BAD_FH;
		return (NULL);
	}

	*statp = DS_OK;
	return (vp);
}

rfs4_file_t *
mds_findfile_by_dsfh(mds_ds_fh *fhp)
{
	ds_status stat;
	vnode_t *vp;
	rfs4_file_t *fp;

	/* map ds_fh to vp */
	vp = ds_fhtovp(fhp, &stat);
	if (vp == NULL)
		return (NULL);

	mutex_enter(&vp->v_lock);
	fp = (rfs4_file_t *)vsd_get(vp, nfs4_srv_vkey);
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

int mds_cks_clientid = 0;

/* ARGSUSED */
void
ds_checkstate(DS_CHECKSTATEargs *argp, DS_CHECKSTATEres *resp,
		struct svc_req *req)
{
	struct compound_state cs;
	rfs4_client_t *cp = NULL;
	rfs4_file_t *fp;
	rfs4_state_t *sp;
	bool_t do_create = FALSE;
	mds_ds_fh *fhp;
	nfsstat4 stat;

	rfs4_init_compound_state(&cs);
	cs.instp = &mds_server;

	if (mds_cks_clientid) {
		/* First validate the client id */
		cp = mds_findclient((struct nfs_client_id4 *)&argp->co_owner,
		    &do_create, NULL);
		if (cp == NULL) {
			resp->status = DSERR_STALE_CLIENTID;
			return;
		}
		resp->DS_CHECKSTATEres_u.file_state.mds_clid = cp->clientid;
		rfs4_client_rele(cp);
	}

	/*
	 * now the filehandle;
	 *
	 * First unwrap the OTW present.
	 *
	 */
	if ((fhp = get_mds_ds_fh(&argp->fh)) == NULL) {
		/* decode error */
		resp->status = DSERR_BAD_FH;
		return;
	}

	/*
	 * validate we think that we know what this
	 * could be..
	 */
	if (fhp->type != FH41_TYPE_DMU_DS ||
	    fhp->vers != DS_FH_v1) {
		resp->status = DSERR_BAD_FH;
		return;
	}

	/*
	 * mds_findfile_by_dsfh() will map the data-server
	 * filehandle, and find the corresponding rfs4_file_t
	 */
	fp = mds_findfile_by_dsfh(fhp);
	if (fp == NULL) {
		resp->status = DSERR_BAD_FH;
		return;
	}

	/*
	 * Now get the associated state
	 */
	stat = rfs4_get_state(&cs, &argp->stateid, &sp, RFS4_DBS_VALID);
	if (stat != NFS4_OK) {
		/* mouldy old dough */
		resp->status = DSERR_STALE_STATEID;
		return;
	}

	/*
	 * Validate the stateid is referring to the correct file
	 */
	if (fp->vp != sp->finfo->vp) {
		rfs4_state_rele(sp);
		rfs4_file_rele(fp);
		resp->status = DSERR_BAD_STATEID;
		return;
	}

	rfs4_state_rele(sp);
	rfs4_file_rele(fp);

	/*
	 * Everything looked good so now build the reply back the
	 * the data-server.
	 */
	bzero(resp, sizeof (*resp));

	/* get layout information */

	/* the files dataset id */

	resp->DS_CHECKSTATEres_u.file_state.mds_fsid.major = 0xabba;

	/* we're done! */
	resp->status = DS_OK;
}

/*
 * Data Server wants to know pathname at MDS for
 * specified object.
 */

/* ARGSUSED */
void
ds_map_fsid(DS_MAP_FSIDargs *argp, DS_MAP_FSIDres *resp,
    struct svc_req *req)
{
	/* we're done! */
	resp->dmfr_status = DSERR_NOTSUPP;
}

mds_dsinfo_t *
mds_find_dsinfo_by_id(ds_id ds_id)
{
	mds_dsinfo_t *dip = NULL;
	bool_t create = FALSE;

	rw_enter(&mds_dsinfo_lock, RW_READER);
	dip = (mds_dsinfo_t *)rfs4_dbsearch(mds_dsinfo_idx,
	    (void *)(uintptr_t)ds_id,
	    &create, NULL, RFS4_DBS_VALID);
	rw_exit(&mds_dsinfo_lock);

	return (dip);
}

/* ARGSUSED */
void
mds_ds_rebooted(mds_dsinfo_t *dip)
{
	/*
	 * clean up MDSs' DS state held or something!
	 */
}


/* ARGSUSED */
void
ds_renew(DS_RENEWargs *argp, DS_RENEWres *resp, struct svc_req *rqstp)
{
	mds_dsinfo_t *dip;

	/* do some basic sanity checks */
	if (argp->ds_id == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	dip = mds_find_dsinfo_by_id(argp->ds_id);

	if (dip == NULL) {
		resp->status = DSERR_EXPIRED;
		return;
	}

	rfs4_dbe_lock(dip->dbe);
	dip->last_access = gethrestime_sec();
	if (dip->verifier != argp->ds_boottime) {
		dip->dsi_flags |= MDS_DSI_REBOOTED;
		dip->verifier = argp->ds_boottime;
	}
	rfs4_dbe_unlock(dip->dbe);

	/* if needed call mds_ds_rebooted() to do cleanup. */

	resp->DS_RENEWres_u.mds_boottime = mds_server.Write4verf;
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
mds_rpt_avail_update(mds_dsinfo_t *dp,
		DS_REPORTAVAILargs *argp,
		DS_REPORTAVAILres *resp)
{
	printf("DS_REPORTAVAIL: Update\n");

	return (0);
}

/* ARGSUSED */
mds_pool_info_t *
mds_pinfo_add(mds_dsinfo_t *dip, struct ds_storinfo *si)
{
	extern rfs4_index_t *mds_pool_info_idx;
	extern krwlock_t mds_pool_info_lock;

	pinfo_create_t pic_arg;
	mds_pool_info_t *pip;

	pic_arg.dip = dip;
	pic_arg.si = si;

	rw_enter(&mds_pool_info_lock, RW_WRITER);

	if ((pip = (mds_pool_info_t *)rfs4_dbcreate(mds_pool_info_idx,
	    (void *)&pic_arg)) == NULL) {
		rw_exit(&mds_pool_info_lock);
		return (NULL);
	}
	rw_exit(&mds_pool_info_lock);
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

mds_dsinfo_t *
mds_find_ds_instance(DS_EXIBIargs *args)
{
	mds_dsinfo_t *dip = NULL;
	bool_t create = FALSE;

	/*
	 * using the data-server instance string find
	 * an associcated device
	 */

	rw_enter(&mds_dsinfo_lock, RW_READER);
	dip = (mds_dsinfo_t *)rfs4_dbsearch(mds_dsinfo_inst_idx,
	    (void *)args->ds_ident.instance.instance_val,
	    &create,
	    NULL,
	    RFS4_DBS_VALID);
	rw_exit(&mds_dsinfo_lock);

	return (dip);
}


/*
 */
ds_status
mds_dev_addr_update(mds_dsinfo_t *dip, struct ds_addr *dap)
{
	extern rfs4_index_t *mds_device_uaddr_idx;
	struct mds_adddev_args darg;
	bool_t create = FALSE;
	mds_device_t *devp;
	ds_status stat = DS_OK;

	/* search for existing entry */
	rw_enter(&mds_device_lock, RW_WRITER);
	if ((devp = (mds_device_t *)rfs4_dbsearch(mds_device_uaddr_idx,
	    (void *)dap->addr.na_r_addr,
	    &create,
	    NULL,
	    RFS4_DBS_VALID)) != NULL) {
		MDS_SET_DS_FLAGS(devp->dev_flags, dap->validuse);
		rw_exit(&mds_device_lock);
		return (stat);
	}

	bzero(&darg, sizeof (darg));

	darg.dev_netid = kstrdup(dap->addr.na_r_netid);
	darg.dev_addr  = kstrdup(dap->addr.na_r_addr);

	/* make it */
	devp = (mds_device_t *)rfs4_dbcreate(mds_device_idx, (void *)&darg);

	if (devp) {
		devp->dev_infop = dip;
		MDS_SET_DS_FLAGS(devp->dev_flags, dap->validuse);
		list_insert_tail(&dip->dev_list, devp);
	} else
		stat = DSERR_INVAL;

	rw_exit(&mds_device_lock);
	return (stat);
}

ds_status
mds_rpt_avail_add(mds_dsinfo_t *dip, DS_REPORTAVAILargs *argp,
		DS_REPORTAVAILres  *resp)
{
	int i, count;
	mds_pool_info_t *pip;
	struct ds_guid_map *guid_map;
	DS_REPORTAVAILres_ok *res_ok;
	XDR xdr;
	int xdr_size;
	char *xdr_buffer;

	/*
	 * First deal with the universal addresses
	 */
	for (i = 0; i < argp->ds_addrs.ds_addrs_len; i++)
		(void) mds_dev_addr_update(dip,
		    &argp->ds_addrs.ds_addrs_val[i]);

	res_ok = &(resp->DS_REPORTAVAILres_u.r);

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
		pip = mds_pinfo_add(dip, &argp->ds_storinfo.ds_storinfo_val[i]);
		if (pip != NULL) {
			mds_ppid *ppid;
			mds_ppid_content ppid_content;

			/* Data Server GUIDs */
			/* Only supported type is ZFS */
			ASSERT(pip->ds_stortype == ZFS);
			guid_map[count].ds_guid.stor_type = pip->ds_stortype;
			guid_map[count].ds_guid.ds_guid_u.zfsguid.
			    zfsguid_len = pip->ds_guid_len;
			guid_map[count].ds_guid.ds_guid_u.zfsguid.
			    zfsguid_val = pip->ds_guid_val;

			/* MDS PPIDs */
			ppid_content.id = pip->mds_gpoolid;
			/* For now - making a unique value of '1' */
			ppid_content.aun = 1;
			xdr_size = xdr_sizeof(xdr_mds_ppid_content,
			    &ppid_content);
			ASSERT(xdr_size);

			xdr_buffer = kmem_alloc(xdr_size, KM_SLEEP);
			xdrmem_create(&xdr, xdr_buffer, xdr_size, XDR_ENCODE);

			if (xdr_mds_ppid_content(&xdr, &ppid_content) ==
			    FALSE) {
				kmem_free(xdr_buffer, xdr_size);
				return (DSERR_XDR);
			}
			ppid = kmem_alloc(sizeof (mds_ppid), KM_SLEEP);
			ppid->mds_ppid_len = xdr_size;
			ppid->mds_ppid_val = xdr_buffer;

			/*
			 * There is only one MDS PPID associated with this
			 * DS GUID
			 */
			guid_map[count].mds_ppid_array.mds_ppid_array_len = 1;
			guid_map[count].mds_ppid_array.mds_ppid_array_val =
			    ppid;
			count++;
			rfs4_dbe_rele(pip->dbe);
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
	mds_dsinfo_t *dip;
	ds_status stat;

	/*
	 * data-server has no id so no soup for you.
	 */
	if (argp->ds_id == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	dip = mds_find_dsinfo_by_id(argp->ds_id);

	if (dip == NULL) {
		resp->status = DSERR_NOT_AUTH;
		return;
	}

	/*
	 * ToDo: Check the verifier (args->ds_verifier).
	 */

	if (list_head(&dip->dev_list) == NULL)
		stat = mds_rpt_avail_add(dip, argp, resp);
	else
		stat = mds_rpt_avail_update(dip, argp, resp);

	resp->status = stat;
}

/* ARGSUSED */
void
ds_exchange(DS_EXIBIargs *argp, DS_EXIBIres *resp, struct svc_req *rqstp)
{
	extern void mds_nuke_layout(uint32_t);

	mds_dsauth_t *dap;
	mds_dsinfo_t *dip;
	mds_device_t *dp;
	char  remote_uaddr[INET6_ADDRSTRLEN];
	char  inst[MAXPATHLEN];
	ds_status stat;
	DS_EXIBIresok *dser = &(resp->DS_EXIBIres_u.dhr_res_ok);

	/*
	 * Do some initial validation of the request.
	 */
	if (argp->ds_ident.boot_verifier == 0 ||
	    argp->ds_ident.instance.instance_len == 0) {
		resp->status = DSERR_INVAL;
		return;
	}

	/*
	 * First search on the instance string
	 */
	dip = mds_find_ds_instance(argp);
	if (dip == NULL) {
		/*
		 * Not known so get just the remote address.
		 */
		stat = ds_get_remote_uaddr(rqstp, remote_uaddr, 0);
		if (stat != DS_OK) {
			resp->status = stat;
			return;
		}

		/*
		 * Hunt down via ip_address, to find matching
		 * device that points to this instance, or
		 * create it.
		 */
		if ((dap = mds_find_dsauth_by_ip(argp, remote_uaddr)) == NULL) {
			/* Still no luck ? -- Punt  */
			resp->status = DSERR_NOT_AUTH;
			return;
		}
		dip = dap->dev_infop;
	} else {
		/*
		 * XXXXXX Needs rework XXXXXXX
		 *
		 * pre-existing instance, for now just
		 * trash existing devices, assume data-server
		 * reboot and remove default layout...
		 */

		/* brute force it */
		rw_enter(&mds_device_lock, RW_WRITER);
		while (dp = list_head(&dip->dev_list)) {
			rfs4_dbe_invalidate(dp->dbe);
			list_remove(&dip->dev_list, dp);
		}
		rw_exit(&mds_device_lock);
	}

	/* Again, needs rework */
	mds_nuke_layout(1);

	/*
	 * XXXX: This would be a good place to notice the
	 * XXXX: data-server has rebooted and we need to
	 * XXXX: trash/invalidate/recall associated
	 * XXXX: state.. of course the device information
	 * XXXX: may have not changed (but ds_verifier would have)
	 * XXXX: Hmmm..perhaphs the correct place is in ds_reportavail
	 * XXXX: when we notice an update (as opposed to add)
	 */
	resp->status = DS_OK;
	dser->ds_id = dip->ds_id;
	dser->mds_ident.boot_verifier = mds_server.Write4verf;

	/* Needs rework */
	(void) sprintf(inst, "%s: %llx", uts_nodename(),
	    (unsigned long long)mds_server.Write4verf);
	dser->mds_ident.instance.instance_len = strlen(inst);
	dser->mds_ident.instance.instance_val = kstrdup(inst);
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
	}
}
