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

#include <sys/flock.h>
#include <nfs/export.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <nfs/lm.h>
#include <sys/pathname.h>
#include <sys/sdt.h>
#include <sys/nvpair.h>
#include <sys/sdt.h>
#include <sys/disp.h>
#include <sys/id_space.h>

extern u_longlong_t nfs4_srv_caller_id;

#include <nfs/nfs_sstor_impl.h>
#include <nfs/mds_state.h>
#include <nfs/nfs41_sessions.h>

#include <nfs/nfs41_filehandle.h>

#include <nfs/spe_impl.h>

static void mds_do_lorecall(mds_lorec_t *);
static int  mds_lorecall_cmd(struct mds_reclo_args *, cred_t *);
static int  mds_notify_device_cmd(struct mds_notifydev_args *, cred_t *);

extern void mds_do_cb_recall(struct rfs4_deleg_state *, bool_t);

/*
 * XXX - slrc_slot_size will more than likely have to be
 *	 computed dynamically as the server adjusts the
 *	 sessions' slot replay cache size. This should be
 *	 good for proto.
 */
slotid4 slrc_slot_size = MAXSLOTS;
slotid4	bc_slot_tab = 0;	/* backchan slots are set by client */

/* The values below are rfs4_lease_time units */

#ifdef DEBUG
#define	SESSION_CACHE_TIME 1
#else
#define	SESSION_CACHE_TIME 10
#endif

#define	ONES_64	(0xFFFFFFFFFFFFFFFFuLL)

/* Sessions */
static void mds_session_destroy(rfs4_entry_t);
static bool_t mds_session_expiry(rfs4_entry_t);
static bool_t mds_session_create(rfs4_entry_t, void *);
static uint32_t sessid_hash(void *);
static bool_t sessid_compare(rfs4_entry_t, void *);
static void *sessid_mkkey(rfs4_entry_t);

/* function pointers for mdsadm */

extern int (*mds_recall_lo)(struct mds_reclo_args *, cred_t *);
extern int (*mds_notify_device)(struct mds_notifydev_args *, cred_t *);

extern char *kstrdup(const char *);

extern rfs4_client_t *findclient(nfs_server_instance_t *, nfs_client_id4 *,
    bool_t *, rfs4_client_t *);

extern rfs4_client_t *findclient_by_id(nfs_server_instance_t *, clientid4);

extern rfs4_openowner_t *findopenowner(nfs_server_instance_t *, open_owner4 *,
    bool_t *, seqid4);

extern void v4prot_sstor_init(nfs_server_instance_t *);

extern void rfs4_ss_retrieve_state(nfs_server_instance_t *);
extern int nfs_doorfd;

#ifdef DEBUG
#define	MDS_TABSIZE 17
#else
#define	MDS_TABSIZE 2047
#endif

#define	MDS_MAXTABSZ 1024*1024

extern uint32_t clientid_hash(void *);

/*
 * Returns the instances capabilities flag word
 * the form of:
 *
 *  EXCHGID4_FLAG_USE_NON_PNFS
 *  EXCHGID4_FLAG_USE_PNFS_MDS
 *  EXCHGID4_FLAG_USE_PNFS_DS
 *
 */
uint32_t
mds_get_capabilities(nfs_server_instance_t *instp)
{
	uint32_t my_abilities = 0;

	if (instp)
		my_abilities =
		    instp->inst_flags & EXCHGID4_FLAG_MASK_PNFS;
	return (my_abilities);
}


/*ARGSUSED*/
static bool_t
mds_do_not_expire(rfs4_entry_t u_entry)
{
	return (FALSE);
}

/*ARGSUSED*/
static stateid_t
mds_create_stateid(rfs4_dbe_t *dbe, stateid_type_t id_type)
{
	stateid_t id;

	id.v41_bits.boottime = dbe_to_instp(dbe)->start_time;
	id.v41_bits.state_ident = rfs4_dbe_getid(dbe);
	id.v41_bits.chgseq = 0;
	id.v41_bits.type = id_type;
	id.v41_bits.pid = 0;

	return (id);
}


rfs4_openowner_t *
mds_findopenowner(nfs_server_instance_t *instp, open_owner4 *openowner,
    bool_t *create)
{
	rfs4_openowner_t *oo;
	rfs4_openowner_t arg;

	arg.ro_owner = *openowner;
	arg.ro_open_seqid = 0;
	oo = (rfs4_openowner_t *)rfs4_dbsearch(instp->openowner_idx,
	    openowner, create, &arg, RFS4_DBS_VALID);
	return (oo);
}

rfs4_lo_state_t *
mds_findlo_state_by_owner(rfs4_lockowner_t *lo,
			rfs4_state_t *sp, bool_t *create)
{
	rfs4_lo_state_t *lsp;
	rfs4_lo_state_t arg;
	nfs_server_instance_t *instp;

	arg.rls_locker = lo;
	arg.rls_state = sp;

	instp = dbe_to_instp(lo->rl_dbe);

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(instp->lo_state_owner_idx,
	    &arg, create, &arg, RFS4_DBS_VALID);

	return (lsp);
}

/* XXX: well clearly this needs to be cleaned up.. */
typedef union {
	struct {
		uint32_t start_time;
		uint32_t c_id;
	} impl_id;
	clientid4 id4;
} cid;

int
mds_check_stateid_seqid(rfs4_state_t *sp, stateid4 *stateid)
{
	stateid_t *id = (stateid_t *)stateid;

	if (rfs4_lease_expired(sp->rs_owner->ro_client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (sp->rs_stateid.v41_bits.chgseq < id->v41_bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (sp->rs_closed == TRUE)
		return (NFS4_CHECK_STATEID_CLOSED);

	return (NFS4_CHECK_STATEID_OKAY);
}

int
mds_fh_is_exi(struct exportinfo *exi, nfs41_fh_fmt_t *fhp)
{
	if (exi->exi_fid.fid_len != fhp->fh.v1.export_fid.len)
		return (0);

	if (bcmp(exi->exi_fid.fid_data, fhp->fh.v1.export_fid.val,
	    fhp->fh.v1.export_fid.len) != 0)
		return (0);

	if (exi->exi_fsid.val[0] != fhp->fh.v1.export_fsid.val[0] ||
	    exi->exi_fsid.val[1] != fhp->fh.v1.export_fsid.val[1])
		return (0);

	return (1);
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the
 * lockowner_state refers to a file that resides within the exportinfo
 * export.  If so, then remove the lock_owner state (file locks and
 * share "locks") for this object since the intent is the server is
 * unexporting the specified directory.  Be sure to invalidate the
 * object after the state has been released
 */
void
mds_lo_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs41_fh_fmt_t   *fhp;

	fhp = (nfs41_fh_fmt_t *)
	    lsp->rls_state->rs_finfo->rf_filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_state_close(lsp->rls_state, FALSE, FALSE, CRED());
		rfs4_dbe_invalidate(lsp->rls_dbe);
		rfs4_dbe_invalidate(lsp->rls_state->rs_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * remove the open state for this object since the intent is the
 * server is unexporting the specified directory.  The main result for
 * this type of entry is to invalidate it such it will not be found in
 * the future.
 */
void
mds_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs41_fh_fmt_t   *fhp;

	fhp =
	    (nfs41_fh_fmt_t *)sp->rs_finfo->rf_filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_state_close(sp, TRUE, FALSE, CRED());
		rfs4_dbe_invalidate(sp->rs_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * remove the deleg state for this object since the intent is the
 * server is unexporting the specified directory.  The main result for
 * this type of entry is to invalidate it such it will not be found in
 * the future.
 */
void
mds_deleg_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs41_fh_fmt_t   *fhp;

	fhp =
	    (nfs41_fh_fmt_t *)dsp->rds_finfo->rf_filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_dbe_invalidate(dsp->rds_dbe);
	}
}

/*
 * This function is used as a target for the rfs4_dbe_walk() call
 * below.  The purpose of this function is to see if the state refers
 * to a file that resides within the exportinfo export.  If so, then
 * release vnode hold for this object since the intent is the server
 * is unexporting the specified directory.  Invalidation will prevent
 * this struct from being found in the future.
 */
void
mds_file_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs41_fh_fmt_t   *fhp;
	vnode_t *vp;
	nfs_server_instance_t *instp;

	fhp = (nfs41_fh_fmt_t *)fp->rf_filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp) == 0)
		return;

	if ((vp = fp->rf_vp) != NULL) {
		instp = dbe_to_instp(fp->rf_dbe);
		ASSERT(instp);

		/*
		 * don't leak monitors and remove the reference
		 * put on the vnode when the delegation was granted.
		 */
		if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_READ) {
			(void) fem_uninstall(vp, instp->deleg_rdops,
			    (void *)fp);
			vn_open_downgrade(vp, FREAD);
		} else if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_WRITE) {
			(void) fem_uninstall(vp, instp->deleg_wrops,
			    (void *)fp);
			vn_open_downgrade(vp, FREAD|FWRITE);
		}

		mutex_enter(&vp->v_lock);
		(void) vsd_set(vp, instp->vkey, NULL);
		mutex_exit(&vp->v_lock);
		VN_RELE(vp);
		fp->rf_vp = NULL;
	}

	rfs4_dbe_invalidate(fp->rf_dbe);
}

/*
 * --------------------------------------------------------
 * MDS - NFSv4.1  Sessions
 * --------------------------------------------------------
 */
static uint32_t
sessid_hash(void *key)
{
	sid *idp = key;

	return (idp->impl_id.s_id);
}

static bool_t
sessid_compare(rfs4_entry_t entry, void *key)
{
	mds_session_t	*sp = (mds_session_t *)entry;
	sessionid4	*idp = (sessionid4 *)key;

	return (bcmp(idp, &sp->sn_sessid, sizeof (sessionid4)) == 0);
}

static void *
sessid_mkkey(rfs4_entry_t entry)
{
	mds_session_t *sp = (mds_session_t *)entry;

	return (&sp->sn_sessid);
}

static bool_t
sess_clid_compare(rfs4_entry_t entry, void *key)
{
	mds_session_t *sp = (mds_session_t *)entry;
	clientid4 *idp = key;

	return (*idp == sp->sn_clnt->rc_clientid);
}

static void *
sess_clid_mkkey(rfs4_entry_t entry)
{
	return (&(((mds_session_t *)entry)->sn_clnt->rc_clientid));
}

void
rfs41_session_rele(mds_session_t *sp)
{
	rfs4_dbe_rele(sp->sn_dbe);
}

mds_session_t *
mds_findsession_by_id(nfs_server_instance_t *instp, sessionid4 sessid)
{
	mds_session_t	*sp;
	rfs4_index_t	*idx = instp->mds_session_idx;
	bool_t		 create = FALSE;

	rw_enter(&instp->findsession_lock, RW_READER);
	sp = (mds_session_t *)rfs4_dbsearch(idx, sessid, &create, NULL,
	    RFS4_DBS_VALID);
	rw_exit(&instp->findsession_lock);

	return (sp);
}

mds_session_t *
mds_findsession_by_clid(nfs_server_instance_t *instp, clientid4 clid)
{
	mds_session_t	*sp;
	bool_t		 create = FALSE;

	rw_enter(&instp->findsession_lock, RW_READER);
	sp = (mds_session_t *)rfs4_dbsearch(instp->mds_sess_clientid_idx, &clid,
	    &create, NULL, RFS4_DBS_VALID);
	rw_exit(&instp->findsession_lock);

	return (sp);
}

/*
 * A clientid can have multiple sessions associated with it. Hence,
 * performing a raw 'mds_findsession' (even for a create) might
 * yield a list of sessions associated with the clientid in question.
 * Instead of delving deep into the rfs4_dbsearch engine to correct
 * this now, we'll call our function directly and create an association
 * between the session table and both primary (sessionid) index and
 * secondary (clientid) index for the newly created session.
 */
mds_session_t	*
mds_createsession(nfs_server_instance_t *instp, session41_create_t *ap)
{
	mds_session_t	*sp = NULL;
	rfs4_index_t	*idx = instp->mds_session_idx;

	rw_enter(&instp->findsession_lock, RW_WRITER);
	if ((sp = (mds_session_t *)rfs4_dbcreate(idx, (void *)ap)) == NULL) {
		DTRACE_PROBE1(mds__srv__createsession__fail,
		    session41_create_t *, ap);
	}
	rw_exit(&instp->findsession_lock);
	return (sp);
}

/*
 * mds_session_inval invalidates the session so other
 * threads won't "find" the session to place additional
 * callbacks. Destroy session even if no backchannel has
 * been established.
 */
nfsstat4
mds_session_inval(mds_session_t	*sp)
{
	nfsstat4	status;

	ASSERT(sp != NULL);
	ASSERT(rfs4_dbe_islocked(sp->sn_dbe));

	if (SN_CB_CHAN_EST(sp)) {
		sess_channel_t	*bcp = sp->sn_back;
		sess_bcsd_t	*bsdp;

		rw_enter(&bcp->cn_lock, RW_READER);
		if ((bsdp = CTOBSD(bcp)) == NULL)
			cmn_err(CE_PANIC, "mds_session_inval: BCSD Not Set");

		rw_enter(&bsdp->bsd_rwlock, RW_READER);
		status = bsdp->bsd_stat = slot_cb_status(bsdp->bsd_stok);
		rw_exit(&bsdp->bsd_rwlock);

		rw_exit(&bcp->cn_lock);
	} else {
		cmn_err(CE_NOTE, "No back chan established");
		status = NFS4_OK;
	}

	/* only invalidate sess if no bc traffic */
	if (status == NFS4_OK)
		rfs4_dbe_invalidate(sp->sn_dbe);

	return (status);
}

/*
 * 1) Invalidate the session in the DB (so it can't be found anymore)
 * 2) Verify that there's no outstanding CB traffic. If so, return err.
 * 3) Eventually the session will be reaped by the reaper_thread
 */
nfsstat4
mds_destroysession(mds_session_t *sp)
{
	nfsstat4	cbs;

	rfs4_dbe_lock(sp->sn_dbe);
	cbs = mds_session_inval(sp);
	rfs4_dbe_unlock(sp->sn_dbe);

	/*
	 * The reference/hold maintained from the session to the client
	 * struct gets nuked when the DB calls rfs4_dbe_destroy, which
	 * in turn calls mds_session_destroy.
	 */
	if (cbs == NFS4_OK)
		rfs41_session_rele(sp);

	return (cbs);
}

sn_chan_dir_t
pd2cd(channel_dir_from_server4 dir)
{
	switch (dir) {
	case CDFS4_FORE:
		return (SN_CHAN_FORE);

	case CDFS4_BACK:
		return (SN_CHAN_BACK);

	case CDFS4_BOTH:
	default:
		return (SN_CHAN_BOTH);
	}
	/* NOTREACHED */
}

/*
 * Delegation CB race detection support
 */
void
rfs41_deleg_rs_hold(rfs4_deleg_state_t *dsp)
{
	atomic_add_32(&dsp->rds_rs.refcnt, 1);
}

void
rfs41_deleg_rs_rele(rfs4_deleg_state_t *dsp)
{
	ASSERT(dsp->rds_rs.refcnt > 0);
	atomic_add_32(&dsp->rds_rs.refcnt, -1);
	if (dsp->rds_rs.refcnt == 0) {
		bzero(dsp->rds_rs.sessid, sizeof (sessionid4));
		dsp->rds_rs.seqid = dsp->rds_rs.slotno = 0;
	}
}

void
rfs41_seq4_hold(void *data, uint32_t flag)
{
	bit_attr_t	*p = (bit_attr_t *)data;
	uint32_t	 idx = log2(flag);

	ASSERT(p[idx].ba_bit == flag);
	atomic_add_32(&p[idx].ba_refcnt, 1);
	p[idx].ba_trigger = gethrestime_sec();
}

void
rfs41_seq4_rele(void *data, uint32_t flag)
{
	bit_attr_t	*p = (bit_attr_t *)data;
	uint32_t	 idx = log2(flag);

	ASSERT(p[idx].ba_bit == flag);
	if (p[idx].ba_refcnt > 0)
		atomic_add_32(&p[idx].ba_refcnt, -1);
	p[idx].ba_trigger = gethrestime_sec();
}

sess_channel_t *
rfs41_create_session_channel(channel_dir_from_server4 dir)
{
	sess_channel_t   *cp;
	sess_bcsd_t	 *bp;

	cp = (sess_channel_t *)kmem_zalloc(sizeof (sess_channel_t), KM_SLEEP);
	rw_init(&cp->cn_lock, NULL, RW_DEFAULT, NULL);

	switch (dir) {
	case CDFS4_FORE:
		break;

	case CDFS4_BOTH:
	case CDFS4_BACK:
		/* BackChan Specific Data */
		bp = (sess_bcsd_t *)kmem_zalloc(sizeof (sess_bcsd_t), KM_SLEEP);
		rw_init(&bp->bsd_rwlock, NULL, RW_DEFAULT, NULL);
		cp->cn_csd = (sess_bcsd_t *)bp;
		break;
	}
	return (cp);
}

void
rfs41_destroy_session_channel(mds_session_t *sp, channel_dir_from_server4 dir)
{
	sess_channel_t	*cp;
	sess_bcsd_t	*bp;

	if (sp == NULL)
		return;
	if (dir == CDFS4_FORE && sp->sn_fore == NULL)
		return;
	if (dir == CDFS4_BACK && sp->sn_back == NULL)
		return;

	if (sp->sn_bdrpc) {
		ASSERT(sp->sn_fore == sp->sn_back);
		sp->sn_fore = NULL;
		goto back;
	}

	if (dir == CDFS4_FORE || dir == CDFS4_BOTH) {
fore:
		if (sp->sn_fore == NULL)
			return;
		cp = sp->sn_fore;

		rw_destroy(&cp->cn_lock);
		kmem_free(cp, sizeof (sess_channel_t));
		sp->sn_fore = NULL;
	}

	if (dir == CDFS4_BACK || dir == CDFS4_BOTH) {
back:
		if (sp->sn_back == NULL)
			return;
		cp = sp->sn_back;

		bp = (sess_bcsd_t *)cp->cn_csd;
		rw_destroy(&bp->bsd_rwlock);
		kmem_free(bp, sizeof (sess_bcsd_t));

		rw_destroy(&cp->cn_lock);
		kmem_free(cp, sizeof (sess_channel_t));
		sp->sn_back = NULL;
	}
}

/*
 * Create/Initialize the session for this rfs4_client_t. Also
 * create its slot replay cache as per the server's resource
 * constraints.
 */
/* ARGSUSED */
static bool_t
mds_session_create(rfs4_entry_t u_entry, void *arg)
{
	mds_session_t		*sp = (mds_session_t *)u_entry;
	session41_create_t	*ap = (session41_create_t *)arg;
	sess_channel_t		*ocp = NULL;
	sid			*sidp;
	SVCMASTERXPRT		*mxprt;
	uint32_t		 i;
	int			 bdrpc;
	rpcprog_t		 prog;
	channel_dir_from_server4 dir;
	sess_bcsd_t		*bsdp;
	nfs_server_instance_t	*instp;
	int			 max_slots;
	nfsstat4		 sle;
	struct svc_req		*req;

	ASSERT(sp != NULL);
	if (sp == NULL)
		return (FALSE);

	instp = dbe_to_instp(sp->sn_dbe);

	/*
	 * Back pointer/ref to parent data struct (rfs4_client_t)
	 */
	sp->sn_clnt = (rfs4_client_t *)ap->cs_client;
	rfs4_dbe_hold(sp->sn_clnt->rc_dbe);
	req = (struct svc_req *)ap->cs_req;
	mxprt = (SVCMASTERXPRT *)req->rq_xprt->xp_master;

	/*
	 * Handcrafting the session id
	 */
	sidp = (sid *)&sp->sn_sessid;
	sidp->impl_id.pad0 = 0x00000000;
	sidp->impl_id.pad1 = 0xFFFFFFFF;
	sidp->impl_id.start_time = instp->start_time;
	sidp->impl_id.s_id = (uint32_t)rfs4_dbe_getid(sp->sn_dbe);

	/*
	 * Process csa_flags; note that CREATE_SESSION4_FLAG_CONN_BACK_CHAN
	 * is processed below since it affects direction and setup of the
	 * backchannel accordingly.
	 */
	sp->sn_csflags = 0;
	if (ap->cs_aotw.csa_flags & CREATE_SESSION4_FLAG_PERSIST)
		/* XXX - Worry about persistence later */
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_PERSIST;

	if (ap->cs_aotw.csa_flags & CREATE_SESSION4_FLAG_CONN_RDMA)
		/* XXX - No RDMA for now */
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_CONN_RDMA;

	/*
	 * Initialize some overall sessions values
	 */
	sp->sn_bc.progno = ap->cs_aotw.csa_cb_program;
	sp->sn_laccess = gethrestime_sec();
	sp->sn_flags = 0;

	/*
	 * Check if client has specified that the FORE channel should
	 * also be used for call back traffic (ie. bidir RPC). If so,
	 * let's try to accomodate the request.
	 */
	DTRACE_PROBE1(csa__flags, uint32_t, ap->cs_aotw.csa_flags);
	bdrpc = ap->cs_aotw.csa_flags & CREATE_SESSION4_FLAG_CONN_BACK_CHAN;

	if (bdrpc) {
		SVCCB_ARGS cbargs;
		prog = sp->sn_bc.progno;
		cbargs.xprt = mxprt;
		cbargs.prog = prog;
		cbargs.vers = NFS_CB;
		cbargs.family = AF_INET;
		cbargs.tag = (void *)sp->sn_sessid;

		if (SVC_CTL(req->rq_xprt, SVCCTL_SET_CBCONN, (void *)&cbargs)) {
			/*
			 * Couldn't create a bi-dir RPC connection. Reset
			 * bdrpc so that the session's channel flags are
			 * set appropriately and the client knows it needs
			 * to do the BIND_CONN_TO_SESSION dance in order
			 * to establish a callback path.
			 */
			bdrpc = 0;
		}
	}

	/*
	 * Session's channel flags depending on bdrpc
	 */
	sp->sn_bdrpc = bdrpc;
	dir = sp->sn_bdrpc ? (CDFS4_FORE | CDFS4_BACK) : CDFS4_FORE;
	ocp = rfs41_create_session_channel(dir);
	ocp->cn_dir = dir;
	sp->sn_fore = ocp;

	/*
	 * Check if channel attrs will be flexible enough for future
	 * purposes. Channel attribute enforcement is done as part of
	 * COMPOUND processing.
	 */
	ocp->cn_attrs = ap->cs_aotw.csa_fore_chan_attrs;
	if (sle = sess_chan_limits(ocp)) {
		ap->cs_error = sle;
		return (FALSE);
	}

	/*
	 * No need for locks/synchronization at this time,
	 * since we're barely creating the session.
	 */
	if (sp->sn_bdrpc) {
		/*
		 * bcsd got built as part of the channel's construction.
		 */
		if ((bsdp = CTOBSD(ocp)) == NULL) {
			cmn_err(CE_PANIC, "Back Chan Spec Data Not Set\t"
			    "<Internal Inconsistency>");
		}
		bc_slot_tab = ap->cs_aotw.csa_back_chan_attrs.ca_maxrequests;
		slrc_table_create(&bsdp->bsd_stok, bc_slot_tab);
		sp->sn_csflags |= CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
		sp->sn_back = ocp;

	} else {
		/*
		 * If not doing bdrpc, then we expect the client to perform
		 * an explicit BIND_CONN_TO_SESSION if it wants callback
		 * traffic. Subsequently, the cb channel should be set up
		 * at that point along with its corresponding slot (see
		 * rfs41_bc_setup).
		 */
		sp->sn_csflags &= ~CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
		sp->sn_back = NULL;
		prog = 0;

		/*
		 * XXX 08/15/2008 (rick) - if the channel is not bidir when
		 *	created in CREATE_SESSION, then we should save off
		 *	the ap->cs_aotw.csa_back_chan_attrs in case later
		 *	a bc2s is called to create the back channel.
		 */
	}

	/*
	 * We're just creating the session... there _shouldn't_ be any
	 * other threads wanting to add connections to this sessions'
	 * conn list, so we purposefully do _not_ take the ocp->cn_lock
	 *
	 * sn_bc fields are all initialized to 0 (via zalloc)
	 */

	SVC_CTL(req->rq_xprt, SVCCTL_SET_TAG, (void *)sp->sn_sessid);

	if (sp->sn_bdrpc) {
		atomic_add_32(&sp->sn_bc.pngcnt, 1);
	}

	/*
	 * Now we allocate space for the slrc, initializing each slot's
	 * sequenceid and slotid to zero and a (pre)cached result of
	 * NFS4ERR_SEQ_MISORDERED. Note that we zero out the entries
	 * by virtue of the z-alloc.
	 */
	max_slots = ocp->cn_attrs.ca_maxrequests;
	slrc_table_create(&sp->sn_replay, max_slots);

	/* only initialize bits relevant to session scope */
	bzero(&sp->sn_seq4, sizeof (bit_attr_t) * BITS_PER_WORD);
	for (i = 1; i <= SEQ4_HIGH_BIT && i != 0; i <<= 1) {
		uint32_t idx = log2(i);

		switch (i) {
		case SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING:
		case SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED:
		case SEQ4_STATUS_CB_PATH_DOWN_SESSION:
		case SEQ4_STATUS_BACKCHANNEL_FAULT:
			sp->sn_seq4[idx].ba_bit = i;
			break;
		default:
			/* already bzero'ed */
			break;
		}
	}

	if (sp->sn_bdrpc) {
		/*
		 * Recall that for CB_PATH_DOWN[_SESSION], the refcnt
		 * indicates the number of active back channel conns
		 */
		rfs41_seq4_hold(&sp->sn_seq4, SEQ4_STATUS_CB_PATH_DOWN_SESSION);
		rfs41_seq4_hold(&sp->sn_clnt->rc_seq4,
		    SEQ4_STATUS_CB_PATH_DOWN);
	}
	return (TRUE);
}

/* ARGSUSED */
static void
mds_session_destroy(rfs4_entry_t u_entry)
{
	mds_session_t	*sp = (mds_session_t *)u_entry;
	sess_bcsd_t	*bsdp;

	if (SN_CB_CHAN_EST(sp) && ((bsdp = CTOBSD(sp->sn_back)) != NULL))
		slrc_table_destroy(bsdp->bsd_stok);

	/*
	 * XXX - A session can have multiple BC clnt handles that need
	 *	 to be discarded. mds_session_inval calls CLNT_DESTROY
	 *	 which will remove the CB client handle from the global
	 *	 list (cb_clnt_list) now. This will have to change once
	 *	 we manage the BC clnt handles per session.
	 */

	/*
	 * Remove the fore and back channels.
	 */
	rfs41_destroy_session_channel(sp, CDFS4_BOTH);

	/*
	 * Nuke slot replay cache for this session
	 */
	if (sp->sn_replay) {
		slrc_table_destroy(sp->sn_replay);
		sp->sn_replay = NULL;
	}

	/*
	 * Remove reference to parent data struct
	 */
	if (sp->sn_clnt)
		rfs4_client_rele(sp->sn_clnt);
}

static bool_t
mds_session_expiry(rfs4_entry_t u_entry)
{
	mds_session_t	*sp = (mds_session_t *)u_entry;

	if (sp == NULL || rfs4_dbe_is_invalid(sp->sn_dbe))
		return (TRUE);

	if (rfs4_lease_expired(sp->sn_clnt))
		return (TRUE);

	return (FALSE);
}

void
mds_kill_session_callout(rfs4_entry_t u_entry, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)arg;
	mds_session_t *sp = (mds_session_t *)u_entry;

	if (sp->sn_clnt == cp && !(rfs4_dbe_is_invalid(sp->sn_dbe))) {
		/*
		 * client is going away; so no need to check for
		 * CB channel traffic before destroying a session.
		 */
		rfs4_dbe_invalidate(sp->sn_dbe);
	}
}

void
mds_clean_up_sessions(rfs4_client_t *cp)
{
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(cp->rc_dbe);

	if (instp->mds_session_tab != NULL)
		rfs4_dbe_walk(instp->mds_session_tab,
		    mds_kill_session_callout, cp);
}

/*
 * -----------------------------------------------
 * MDS: Layout tables.
 * -----------------------------------------------
 */
static uint32_t
mds_layout_hash(void *key)
{
	layout_core_t	*lc = (layout_core_t *)key;
	int		i;
	uint32_t	hash = 0;

	if (lc->lc_stripe_count == 0)
		return (0);

	/*
	 * Hash the first mds_sid
	 */
	for (i = 0; i < lc->lc_mds_sids[0].len; i++) {
		hash <<= 1;
		hash += (uint_t)lc->lc_mds_sids[0].val[i];
	}

	return (hash);
}

static bool_t
mds_layout_compare(rfs4_entry_t entry, void *key)
{
	mds_layout_t	*lp = (mds_layout_t *)entry;
	layout_core_t	*lc = (layout_core_t *)key;

	int		i;

	if (lc->lc_stripe_unit == lp->mlo_lc.lc_stripe_unit) {
		if (lc->lc_stripe_count ==
		    lp->mlo_lc.lc_stripe_count) {
			for (i = 0; i < lc->lc_stripe_count; i++) {
				if (lc->lc_mds_sids[i].len !=
				    lp->mlo_lc.lc_mds_sids[i].len) {
					return (0);
				}

				if (bcmp(lc->lc_mds_sids[i].val,
				    lp->mlo_lc.lc_mds_sids[i].val,
				    lc->lc_mds_sids[i].len)) {
					return (0);
				}
			}

			/*
			 * Everything matches!
			 */
			return (1);
		}
	}

	return (0);
}

static void *
mds_layout_mkkey(rfs4_entry_t entry)
{
	mds_layout_t *lp = (mds_layout_t *)entry;

	return ((void *)&lp->mlo_lc);
}

static uint32_t
mds_layout_id_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static bool_t
mds_layout_id_compare(rfs4_entry_t entry, void *key)
{
	mds_layout_t *lp = (mds_layout_t *)entry;

	return (lp->mlo_id == (int)(uintptr_t)key);
}

static void *
mds_layout_id_mkkey(rfs4_entry_t entry)
{
	mds_layout_t *lp = (mds_layout_t *)entry;

	return ((void *)(uintptr_t)lp->mlo_id);
}

typedef struct {
	uint32_t			id;
	nfsv4_1_file_layout_ds_addr4	*ds_addr4;
} mds_addmpd_t;

/*
 * ================================================================
 *	XXX: Both mds_gather_mds_sids and mds_gen_default_layout
 *	have been left in to support installations with no
 *	policies defined. In short, we do not force people to
 *	set up a policy system. Whenever the SMF portion of the
 *	code comes along, we will nuke these functions and
 *	force a real default to exist.
 *  ================================================================
 */

struct mds_gather_args {
	layout_core_t	lc;
	int 		found;
};

static void
mds_gather_mds_sids(rfs4_entry_t entry, void *arg)
{
	ds_guid_info_t		*pgi = (ds_guid_info_t *)entry;
	struct mds_gather_args	*gap = (struct mds_gather_args *)arg;

	int i, j;

	if (rfs4_dbe_skip_or_invalid(pgi->dbe))
		return;

	if (gap->found < gap->lc.lc_stripe_count) {
		/*
		 * Insert in order.
		 */
		for (i = 0; i < gap->found; i++) {
			if ((pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len <
			    gap->lc.lc_mds_sids[i].len) ||
			    (pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len ==
			    gap->lc.lc_mds_sids[i].len &&
			    bcmp(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
			    gap->lc.lc_mds_sids[i].val,
			    gap->lc.lc_mds_sids[i].len) < 0)) {
				for (j = gap->found; j > i; j--) {
					gap->lc.lc_mds_sids[j].len =
					    gap->lc.lc_mds_sids[j - 1].len;
					gap->lc.lc_mds_sids[j - 1].val =
					    gap->lc.lc_mds_sids[j].val;
				}

				break;
			}
		}

		/*
		 * Either we found it and i is where it goes or we didn't
		 * find it and i is the tail. Either way, same thing happens!
		 */
		gap->lc.lc_mds_sids[i].len =
		    pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len;
		gap->lc.lc_mds_sids[i].val =
		    kmem_alloc(gap->lc.lc_mds_sids[i].len, KM_SLEEP);
		bcopy(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
		    gap->lc.lc_mds_sids[i].val,
		    gap->lc.lc_mds_sids[i].len);

		gap->found++;
	}
}

int mds_default_stripe = 32;

mds_layout_t *
mds_gen_default_layout(nfs_server_instance_t *instp)
{
	struct mds_gather_args	gap;
	mds_layout_t		*lp;

	int			i;

	bzero(&gap, sizeof (gap));

	gap.found = 0;

	rw_enter(&instp->ds_guid_info_lock, RW_READER);
	gap.lc.lc_stripe_count = instp->ds_guid_info_count;
	rw_exit(&instp->ds_guid_info_lock);

	gap.lc.lc_mds_sids = kmem_zalloc(gap.lc.lc_stripe_count *
	    sizeof (mds_sid), KM_SLEEP);

	rw_enter(&instp->ds_guid_info_lock, RW_READER);
	rfs4_dbe_walk(instp->ds_guid_info_tab, mds_gather_mds_sids, &gap);
	rw_exit(&instp->ds_guid_info_lock);

	/*
	 * If we didn't find any devices then we do no service
	 */
	if (gap.found == 0) {
		kmem_free(gap.lc.lc_mds_sids, gap.lc.lc_stripe_count *
		    sizeof (mds_sid));
		return (NULL);
	}

	/*
	 * XXX: What if found != stripe_count ?
	 */

	gap.lc.lc_stripe_unit = mds_default_stripe * 1024;

	rw_enter(&instp->mds_layout_lock, RW_WRITER);
	lp = (mds_layout_t *)rfs4_dbcreate(instp->mds_layout_idx,
	    (void *)&gap.lc);
	if (lp) {
		instp->mds_layout_default_idx = lp->mlo_id;
	}
	rw_exit(&instp->mds_layout_lock);

	for (i = 0; i < gap.lc.lc_stripe_count; i++) {
		kmem_free(gap.lc.lc_mds_sids[i].val,
		    gap.lc.lc_mds_sids[i].len);
	}

	kmem_free(gap.lc.lc_mds_sids, gap.lc.lc_stripe_count *
	    sizeof (mds_sid));
	return (lp);
}

/* ================================================================ */


/*
 * Given a layout, which now is comprised of mds_dataset_ids, instead of
 * devices, generate the list of devices...
 */
static mds_mpd_t *
mds_gen_mpd(nfs_server_instance_t *instp, mds_layout_t *lp)
{
	nfsv4_1_file_layout_ds_addr4	ds_dev;

	/*
	 * The key to understanding the way these data structures
	 * interact is that map points to ds_dev. And map is stuck
	 * into the mds_mpd_idx database.
	 */
	mds_addmpd_t	map = { .id = 0, .ds_addr4 = &ds_dev };
	mds_mpd_t	*mp = NULL;
	uint_t		len;
	int		 i, iLoaded = 0;
	uint32_t	*sivp;
	multipath_list4	*mplp;

	ds_addrlist_t	**adp = NULL;

	ASSERT(instp->mds_mpd_id_space != NULL);
	map.id = id_alloc(instp->mds_mpd_id_space);

	/*
	 * build a nfsv4_1_file_layout_ds_addr4, encode it and
	 * cache it in state_store.
	 */
	len = lp->mlo_lc.lc_stripe_count;

	/* allocate space for the indices */
	sivp = ds_dev.nflda_stripe_indices.nflda_stripe_indices_val =
	    kmem_zalloc(len * sizeof (uint32_t), KM_SLEEP);

	ds_dev.nflda_stripe_indices.nflda_stripe_indices_len = len;

	/* populate the stripe indices */
	for (i = 0; i < len; i++)
		sivp[i] = i;

	/*
	 * allocate space for the multipath_list4 (for now we just
	 * have the one path)
	 */
	mplp = ds_dev.nflda_multipath_ds_list.nflda_multipath_ds_list_val =
	    kmem_zalloc(len * sizeof (multipath_list4), KM_SLEEP);

	ds_dev.nflda_multipath_ds_list.nflda_multipath_ds_list_len = len;

	adp = kmem_zalloc(len * sizeof (ds_addrlist_t *), KM_SLEEP);

	/*
	 * Now populate the netaddrs using the stashed ds_addr
	 * pointers
	 */
	for (i = 0; i < len; i++) {
		ds_addrlist_t	*dp;

		mplp[i].multipath_list4_len = 1;
		dp = mds_find_ds_addrlist_by_mds_sid(instp,
		    &lp->mlo_lc.lc_mds_sids[i]);
		if (!dp) {
			iLoaded = i;
			goto cleanup;
		}

		mplp[i].multipath_list4_val = &dp->dev_addr;
		adp[i] = dp;
	}

	iLoaded = len;

	/*
	 * Add the multipath_list4, this will encode and cache
	 * the result.
	 */
	rw_enter(&instp->mds_mpd_lock, RW_WRITER);

	/*
	 * XXX: Each layout has its own mpd.
	 *
	 * Note that we should fix this....
	 */
	mp = (mds_mpd_t *)rfs4_dbcreate(instp->mds_mpd_idx, (void *)&map);
	if (mp) {
		lp->mlo_mpd_id = mp->mpd_id;

		/*
		 * Put the layout on the layouts list.
		 * Note that we don't decrement the refcnt
		 * here, we keep a hold on it for inserting
		 * this layout on it.
		 */
		list_insert_tail(&mp->mpd_layouts_list, lp);
	}

	rw_exit(&instp->mds_mpd_lock);

cleanup:

	for (i = 0; i < iLoaded; i++) {
		rfs4_dbe_rele(adp[i]->dbe);
	}

	kmem_free(adp, len * sizeof (ds_addrlist_t *));
	kmem_free(mplp, len * sizeof (multipath_list4));
	kmem_free(sivp, len * sizeof (uint32_t));

	if (mp == NULL)
		id_free(instp->mds_mpd_id_space, map.id);

	return (mp);
}

void
mds_nuke_layout(nfs_server_instance_t *instp, uint32_t mlo_id)
{
	bool_t create = FALSE;
	rfs4_entry_t e;

	rw_enter(&instp->mds_layout_lock, RW_WRITER);
	if ((e = rfs4_dbsearch(instp->mds_layout_ID_idx,
	    (void *)(uintptr_t)mlo_id,
	    &create,
	    NULL,
	    RFS4_DBS_VALID)) != NULL) {
		rfs4_dbe_invalidate(e->dbe);
		rfs4_dbe_rele(e->dbe);
	}
	rw_exit(&instp->mds_layout_lock);
}

/*ARGSUSED*/
static bool_t
mds_layout_create(rfs4_entry_t u_entry, void *arg)
{
	mds_layout_t	*lp = (mds_layout_t *)u_entry;
	layout_core_t	*lc = (layout_core_t *)arg;

	nfs_server_instance_t *instp;
	int i;
	bool_t rc = TRUE;

	instp = dbe_to_instp(lp->mlo_dbe);

	lp->mlo_id = rfs4_dbe_getid(lp->mlo_dbe);

	lp->mlo_type = LAYOUT4_NFSV4_1_FILES;
	lp->mlo_lc.lc_stripe_unit = lc->lc_stripe_unit;
	lp->mlo_lc.lc_stripe_count = lc->lc_stripe_count;

	lp->mlo_lc.lc_mds_sids = kmem_zalloc(lp->mlo_lc.lc_stripe_count *
	    sizeof (mds_sid), KM_SLEEP);

	for (i = 0; i < lp->mlo_lc.lc_stripe_count; i++) {
		lp->mlo_lc.lc_mds_sids[i].len = lc->lc_mds_sids[i].len;
		lp->mlo_lc.lc_mds_sids[i].val =
		    kmem_alloc(lp->mlo_lc.lc_mds_sids[i].len, KM_SLEEP);
		bcopy(lc->lc_mds_sids[i].val, lp->mlo_lc.lc_mds_sids[i].val,
		    lp->mlo_lc.lc_mds_sids[i].len);
	}

	/* Need to generate a device for this layout */
	lp->mlo_mpd = mds_gen_mpd(instp, lp);
	if (lp->mlo_mpd == NULL) {
		for (i = 0; i < lp->mlo_lc.lc_stripe_count; i++) {
			kmem_free(lp->mlo_lc.lc_mds_sids[i].val,
			    lp->mlo_lc.lc_mds_sids[i].len);
		}

		kmem_free(lp->mlo_lc.lc_mds_sids, lp->mlo_lc.lc_stripe_count *
		    sizeof (mds_sid));
		lp->mlo_lc.lc_mds_sids = NULL;
		rc = FALSE;
	}

	return (rc);
}

/*ARGSUSED*/
static void
mds_layout_destroy(rfs4_entry_t u_entry)
{
	mds_layout_t		*lp = (mds_layout_t *)u_entry;
	nfs_server_instance_t	*instp;
	int			i;

	instp = dbe_to_instp(u_entry->dbe);

	rw_enter(&instp->mds_mpd_lock, RW_WRITER);
	if (lp->mlo_mpd != NULL) {
		list_remove(&lp->mlo_mpd->mpd_layouts_list, lp);
		rfs4_dbe_rele(lp->mlo_mpd->mpd_dbe);
		lp->mlo_mpd = NULL;
	}
	rw_exit(&instp->mds_mpd_lock);

	if (lp->mlo_lc.lc_mds_sids != NULL) {
		for (i = 0; i < lp->mlo_lc.lc_stripe_count; i++) {
			kmem_free(lp->mlo_lc.lc_mds_sids[i].val,
			    lp->mlo_lc.lc_mds_sids[i].len);
		}

		kmem_free(lp->mlo_lc.lc_mds_sids, lp->mlo_lc.lc_stripe_count *
		    sizeof (mds_sid));
		lp->mlo_lc.lc_mds_sids = NULL;
	}
}

mds_layout_t *
mds_add_layout(layout_core_t *lc)
{
	bool_t create = FALSE;
	mds_layout_t *lp;

	rw_enter(&mds_server->mds_layout_lock, RW_WRITER);

	/*
	 * If it is already in memory, then we can just
	 * bump the refcnt.
	 */
	lp = (mds_layout_t *)rfs4_dbsearch(mds_server->mds_layout_idx,
	    (void *)lc, &create, NULL,
	    RFS4_DBS_VALID);
	if (lp != NULL) {
		rw_exit(&mds_server->mds_layout_lock);
		return (lp);
	}

	lp = (mds_layout_t *)rfs4_dbcreate(mds_server->mds_layout_idx,
	    (void *)lc);
	rw_exit(&mds_server->mds_layout_lock);

	if (lp == NULL) {
		printf("mds_add_layout: failed\n");
		(void) set_errno(EFAULT);
	}

	return (lp);
}

#define	ADDRHASH(key) ((unsigned long)(key) >> 3)

/*
 * -----------------------------------------------
 * MDS: Layout Grant tables.
 * -----------------------------------------------
 *
 */
static uint32_t
mds_layout_grant_hash(void *key)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)key;

	return (ADDRHASH(lg->lo_cp) ^ ADDRHASH(lg->lo_fp));
}

static bool_t
mds_layout_grant_compare(rfs4_entry_t u_entry, void *key)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)u_entry;
	mds_layout_grant_t *klg = (mds_layout_grant_t *)key;

	return (lg->lo_cp == klg->lo_cp && lg->lo_fp == klg->lo_fp);
}

static void *
mds_layout_grant_mkkey(rfs4_entry_t entry)
{
	return (entry);
}

#ifdef NOT_USED_NOW
static uint32_t
mds_layout_grant_id_hash(void *key)
{
	stateid_t *id = (stateid_t *)key;

	return (id->v41_bits.state_ident);
}

static bool_t
mds_layout_grant_id_compare(rfs4_entry_t entry, void *key)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	if (id->v41_bits.type != LAYOUTID)
		return (FALSE);

	rc = (lg->lo_stateid.v41_bits.boottime == id->v41_bits.boottime &&
	    lg->lo_stateid.v41_bits.state_ident == id->v41_bits.state_ident);

	return (rc);
}

static void *
mds_layout_grant_id_mkkey(rfs4_entry_t entry)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)entry;

	return (&lg->lo_stateid);
}
#endif

/*ARGSUSED*/
static bool_t
mds_layout_grant_create(rfs4_entry_t u_entry, void *arg)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)u_entry;
	rfs4_file_t *fp = ((mds_layout_grant_t *)arg)->lo_fp;
	rfs4_client_t *cp = ((mds_layout_grant_t *)arg)->lo_cp;

	/*
	 * We hold onto the rfs4_file_t until we are done with it.
	 */
	rfs4_dbe_hold(fp->rf_dbe);

	lg->lo_status = LO_GRANTED;
	lg->lo_stateid = mds_create_stateid(lg->lo_dbe, LAYOUTID);
	lg->lo_fp = fp;
	lg->lo_cp = cp;
	lg->lor_seqid = lg->lor_reply = 0;
	mutex_init(&lg->lo_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Init layout grant lists for remque/insque */
	lg->lo_grant_list.next = lg->lo_grant_list.prev =
	    &lg->lo_grant_list;
	lg->lo_grant_list.lg = lg;

	lg->lo_clientgrantlist.next = lg->lo_clientgrantlist.prev =
	    &lg->lo_clientgrantlist;
	lg->lo_clientgrantlist.lg = lg;

	lg->lo_range = nfs_range_create();

	return (TRUE);
}

/*ARGSUSED*/
static void
mds_layout_grant_destroy(rfs4_entry_t entry)
{
	mds_layout_grant_t *lg = (mds_layout_grant_t *)entry;

	/*
	 * The code which invalidated this node should have
	 * gone ahead and released the rfs4_file_t.
	 */
	ASSERT(lg->lo_fp == NULL);

	mutex_destroy(&lg->lo_lock);

	nfs_range_destroy(lg->lo_range);
	lg->lo_range = NULL;
}

mds_layout_grant_t *
rfs41_findlogrant(struct compound_state *cs, rfs4_file_t *fp,
    rfs4_client_t *cp, bool_t *create)
{
	mds_layout_grant_t args, *lg;

	args.lo_cp = cp;
	args.lo_fp = fp;

	lg = (mds_layout_grant_t *)rfs4_dbsearch(
	    cs->instp->mds_layout_grant_idx, &args, create,
	    &args, RFS4_DBS_VALID);

	return (lg);
}

void
rfs41_lo_grant_hold(mds_layout_grant_t *lg)
{
	rfs4_dbe_hold(lg->lo_dbe);
}

void
rfs41_lo_grant_rele(mds_layout_grant_t *lg)
{
	rfs4_dbe_rele(lg->lo_dbe);
}

/*
 * -----------------------------------------------
 * MDS: Ever Grant tables.
 * -----------------------------------------------
 *
 */
static uint32_t
mds_ever_grant_hash(void *key)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)key;

	return (ADDRHASH(eg->eg_cp) ^ ADDRHASH(eg->eg_key));
}

static bool_t
mds_ever_grant_compare(rfs4_entry_t u_entry, void *key)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)u_entry;
	mds_ever_grant_t *keg = (mds_ever_grant_t *)key;

	return (eg->eg_cp == keg->eg_cp &&
	    eg->eg_fsid.val[0] == keg->eg_fsid.val[0] &&
	    eg->eg_fsid.val[1] == keg->eg_fsid.val[1]);
}

static void *
mds_ever_grant_mkkey(rfs4_entry_t entry)
{
	return (entry);
}

static bool_t
mds_ever_grant_fsid_compare(rfs4_entry_t entry, void *key)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)entry;
	int64_t g_key = (int64_t)(uintptr_t)key;

	return (eg->eg_key == g_key);
}

#ifdef NOT_USED_NOW
static uint32_t
mds_ever_grant_fsid_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static void *
mds_ever_grant_fsid_mkkey(rfs4_entry_t entry)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)entry;

	return ((void*)(uintptr_t)eg->eg_key);
}
#endif

/*ARGSUSED*/
static bool_t
mds_ever_grant_create(rfs4_entry_t u_entry, void *arg)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)u_entry;
	rfs4_client_t *cp = ((mds_ever_grant_t *)arg)->eg_cp;

	eg->eg_cp = cp;
	eg->eg_fsid = ((mds_ever_grant_t *)arg)->eg_fsid;

	return (TRUE);
}

/*ARGSUSED*/
static void
mds_ever_grant_destroy(rfs4_entry_t foo)
{
}

mds_ever_grant_t *
rfs41_findevergrant(rfs4_client_t *cp, vnode_t *vp, bool_t *create)
{
	nfs_server_instance_t *instp;
	mds_ever_grant_t args, *eg;

	instp = dbe_to_instp(cp->rc_dbe);
	args.eg_cp = cp;
	args.eg_fsid = vp->v_vfsp->vfs_fsid;

	eg = (mds_ever_grant_t *)rfs4_dbsearch(
	    instp->mds_ever_grant_idx, &args, create, &args,
	    RFS4_DBS_VALID);

	return (eg);
}

void
rfs41_ever_grant_rele(mds_ever_grant_t *eg)
{
	rfs4_dbe_rele(eg->eg_dbe);
}

void
mds_kill_eg_callout(rfs4_entry_t u_entry, void *arg)
{
	mds_ever_grant_t *eg = (mds_ever_grant_t *)u_entry;
	rfs4_client_t *cp = (rfs4_client_t *)arg;

	if (eg->eg_cp == cp) {
		eg->eg_cp = NULL;
		rfs4_dbe_invalidate(eg->eg_dbe);
		rfs4_dbe_rele_nolock(eg->eg_dbe);
	}
}

void
mds_clean_up_grants(rfs4_client_t *cp)
{
	mds_layout_grant_t *lg;
	nfs_server_instance_t *instp;

	rfs4_dbe_lock(cp->rc_dbe);
	while (cp->rc_clientgrantlist.next->lg != NULL) {
		lg = cp->rc_clientgrantlist.next->lg;
		remque(&lg->lo_clientgrantlist);
		lg->lo_clientgrantlist.next = lg->lo_clientgrantlist.prev =
		    &lg->lo_clientgrantlist;
		lg->lo_cp = NULL;

		rfs4_dbe_lock(lg->lo_fp->rf_dbe);
		remque(&lg->lo_grant_list);
		rfs4_dbe_unlock(lg->lo_fp->rf_dbe);

		lg->lo_grant_list.next = lg->lo_grant_list.prev =
		    &lg->lo_grant_list;
		rfs4_file_rele(lg->lo_fp);

		lg->lo_fp = NULL;
		rfs4_dbe_invalidate(lg->lo_dbe);
		rfs41_lo_grant_rele(lg);
	}

	instp = dbe_to_instp(cp->rc_dbe);
	rfs4_dbe_unlock(cp->rc_dbe);

	rw_enter(&instp->mds_ever_grant_lock, RW_READER);
	rfs4_dbe_walk(instp->mds_ever_grant_tab, mds_kill_eg_callout, cp);
	rw_exit(&instp->mds_ever_grant_lock);
}

struct grant_arg {
	rfs4_client_t *cp;
	vnode_t *vp;
};

void
mds_rm_grant_callout(rfs4_entry_t u_entry, void *arg)
{
	mds_layout_grant_t	*lg = (mds_layout_grant_t *)u_entry;
	struct grant_arg	*ga = (struct grant_arg *)arg;
	vnode_t			*vp;

	if (rfs4_dbe_skip_or_invalid(lg->lo_dbe)) {
		ASSERT(lg->lo_fp == NULL);
		return;
	}

	ASSERT(lg->lo_fp != NULL);
	vp = lg->lo_fp->rf_vp;

	if (ga->cp == lg->lo_cp && vp && ga->vp->v_vfsp == vp->v_vfsp) {
		rfs4_dbe_lock(lg->lo_cp->rc_dbe);
		remque(&lg->lo_clientgrantlist);
		rfs4_dbe_unlock(lg->lo_cp->rc_dbe);

		lg->lo_clientgrantlist.next = lg->lo_clientgrantlist.prev =
		    &lg->lo_clientgrantlist;
		lg->lo_cp = NULL;

		rfs4_dbe_lock(lg->lo_fp->rf_dbe);
		remque(&lg->lo_grant_list);
		rfs4_dbe_unlock(lg->lo_fp->rf_dbe);

		lg->lo_grant_list.next = lg->lo_grant_list.prev =
		    &lg->lo_grant_list;
		rfs4_file_rele(lg->lo_fp);

		lg->lo_fp = NULL;
		rfs4_dbe_invalidate(lg->lo_dbe);
		rfs4_dbe_rele_nolock(lg->lo_dbe);
	}
}

void
mds_clean_grants_by_fsid(rfs4_client_t *cp, vnode_t *vp)
{
	struct grant_arg ga;
	nfs_server_instance_t *instp;

	ga.cp = cp;
	ga.vp = vp;
	instp = dbe_to_instp(cp->rc_dbe);

	rw_enter(&instp->mds_layout_grant_lock, RW_READER);
	rfs4_dbe_walk(instp->mds_layout_grant_tab, mds_rm_grant_callout, &ga);
	rw_exit(&instp->mds_layout_grant_lock);
}

/*
 * Conforms to Section 12.5.5.2.1.4 of draft-25
 */
void
rfs41_lo_seqid(stateid_t *sp)
{
	if (sp == NULL)
		return;

	if ((sp->v41_bits.chgseq + 1) & (uint32_t)~0)
		atomic_inc_32(&sp->v41_bits.chgseq);
	else
		(void) atomic_swap_32(&sp->v41_bits.chgseq, 1);
}

bool_t
rfs41_lo_still_granted(mds_layout_grant_t *lg)
{
	bool_t	found = TRUE;

	/*
	 * We currently have the layout grant, but is it still valid?
	 * If it has been returned, then the status will be updated as
	 * returned or recalled.  However, it is possible that the client
	 * has gone away while we are still holding this.  When the client
	 * is cleaned up, the pointer to the client and the file will be
	 * set to NULL and it will have been removed from all lists, waiting
	 * to be released and reaped.  In this case, the status may not
	 * have been updated.
	 */
	rfs4_dbe_lock(lg->lo_dbe);
	if (lg->lo_status == LO_RETURNED || lg->lo_status == LO_RECALLED ||
	    lg->lo_cp == NULL)
		found = FALSE;
	rfs4_dbe_unlock(lg->lo_dbe);

	return (found);
}

static void
rfs41_revoke_layout(mds_layout_grant_t *lg)
{
	cmn_err(CE_NOTE, "rfs41_revoke_layout: layout revoked");
	rfs41_seq4_hold(&lg->lo_cp->rc_seq4,
	    SEQ4_STATUS_RECALLABLE_STATE_REVOKED);

	/* XXX - rest of this function TBD */
}

static void
mds_do_lorecall(mds_lorec_t *lorec)
{
	CB_COMPOUND4args	 cb4_args;
	CB_COMPOUND4res		 cb4_res;
	CB_SEQUENCE4args	*cbsap;
	CB_LAYOUTRECALL4args	*cblrap;
	nfs_cb_argop4		*argops;
	struct timeval		 timeout;
	enum clnt_stat		 call_stat = RPC_FAILED;
	int			 zilch = 0;
	layoutrecall_file4	*lorf;
	CLIENT			*ch;
	int			 numops;
	int			 argsz;
	mds_session_t		*sp;
	slot_ent_t		*p;
	mds_layout_grant_t	*lg;
	uint32_t		 sc = 0;
	int			 retried = 0;

	DTRACE_PROBE1(nfssrv__i__sess_lorecall_fh, mds_lorec_t *, lorec);
	if ((sp = lorec->lor_sess) == NULL) {
		kmem_free(lorec, sizeof (mds_lorec_t));
		return;

	} else if (!SN_CB_CHAN_EST(sp)) {
		kmem_free(lorec, sizeof (mds_lorec_t));
		rfs41_session_rele(sp);
		return;
	}

	/*
	 * Per-type pre-processing
	 */
	switch (lorec->lor_type) {
	case LAYOUTRECALL4_FILE:
		if (lorec->lor_lg == NULL)
			return;
		lg = lorec->lor_lg;
		break;

	case LAYOUTRECALL4_FSID:
		sp->sn_clnt->rc_bulk_recall = LAYOUTRETURN4_FSID;
		break;

	case LAYOUTRECALL4_ALL:
		sp->sn_clnt->rc_bulk_recall = LAYOUTRETURN4_ALL;
		break;
	default:
		break;
	}

	/*
	 * set up the compound args
	 */
	numops = 2;	/* CB_SEQUENCE + CB_LAYOUTRECALL */
	argsz = numops * sizeof (nfs_cb_argop4);
	argops = kmem_zalloc(argsz, KM_SLEEP);

	argops[0].argop = OP_CB_SEQUENCE;
	cbsap = &argops[0].nfs_cb_argop4_u.opcbsequence;

	argops[1].argop = OP_CB_LAYOUTRECALL;
	cblrap = &argops[1].nfs_cb_argop4_u.opcblayoutrecall;

	(void) str_to_utf8("cb_lo_recall", &cb4_args.tag);
	cb4_args.minorversion = CB4_MINOR_v1;

	cb4_args.callback_ident = sp->sn_bc.progno;
	cb4_args.array_len = numops;
	cb4_args.array = argops;

	cb4_res.tag.utf8string_val = NULL;
	cb4_res.array = NULL;

	/*
	 * CB_SEQUENCE
	 */
	bcopy(sp->sn_sessid, cbsap->csa_sessionid, sizeof (sessionid4));
	p = svc_slot_alloc(sp);
	mutex_enter(&p->se_lock);
	cbsap->csa_slotid = p->se_sltno;
	cbsap->csa_sequenceid = p->se_seqid;
	cbsap->csa_highest_slotid = svc_slot_maxslot(sp);
	cbsap->csa_cachethis = FALSE;

	/* no referring calling list for lo recall */
	cbsap->csa_rcall_llen = 0;
	cbsap->csa_rcall_lval = NULL;
	mutex_exit(&p->se_lock);

	/*
	 * CB_LAYOUTRECALL
	 *
	 * clora_change:
	 *	1: server prefers that client write modified data through
	 *	   MDS when pushing modified data due to layout recall
	 *	0: server has no DS/MDS preference
	 */
	cblrap->clora_type = LAYOUT4_NFSV4_1_FILES;
	cblrap->clora_iomode = LAYOUTIOMODE4_ANY;
	cblrap->clora_changed = 0;
	cblrap->clora_recall.lor_recalltype = lorec->lor_type;

	switch (lorec->lor_type) {
	case LAYOUTRECALL4_FILE:
		lorf = &cblrap->clora_recall.layoutrecall4_u.lor_layout;
		lorf->lor_offset = 0;
		lorf->lor_length = ONES_64;
		lorf->lor_fh.nfs_fh4_len = lorec->lor_fh.fh_len;
		lorf->lor_fh.nfs_fh4_val = (char *)&lorec->lor_fh.fh_buf;
		bcopy(&lorec->lor_stid, &lorf->lor_stateid, sizeof (stateid4));
		(void) atomic_swap_32(&lg->lor_reply, 0);
		break;

	case LAYOUTRECALL4_FSID:
		cblrap->clora_recall.layoutrecall4_u.lor_fsid = lorec->lor_fsid;
		break;

	case LAYOUTRECALL4_ALL:
	default:
		break;
	}

	/*
	 * Set up the timeout for the callback and make the actual call.
	 * Timeout will be 80% of the lease period.
	 */
	timeout.tv_sec = (dbe_to_instp(sp->sn_dbe)->lease_period * 80) / 100;
	timeout.tv_usec = 0;
retry:
	ch = rfs41_cb_getch(sp);
	(void) CLNT_CONTROL(ch, CLSET_XID, (char *)&zilch);
	call_stat = clnt_call(ch, CB_COMPOUND,
	    xdr_CB_COMPOUND4args_srv, (caddr_t)&cb4_args,
	    xdr_CB_COMPOUND4res, (caddr_t)&cb4_res, timeout);
	rfs41_cb_freech(sp, ch);

	if (call_stat != RPC_SUCCESS) {
		switch (lorec->lor_type) {
		case LAYOUTRECALL4_FILE:
			if (!retried)
				delay(SEC_TO_TICK(rfs4_lease_time));

			if (rfs41_lo_still_granted(lg)) {
				if (!retried) {
					retried = 1;
					goto retry;
				}

				/*
				 * We want to make sure that the layout is
				 * still granted lest we assert a SEQ4 flag
				 * that will never be turned off.
				 */
				rfs41_revoke_layout(lg);
			}
			sc = (call_stat == RPC_CANTSEND ||
			    call_stat == RPC_CANTRECV);
			rfs41_cb_path_down(sp, sc);
			goto done;

		case LAYOUTRECALL4_FSID:
		case LAYOUTRECALL4_ALL:
			sp->sn_clnt->rc_bulk_recall = 0;
			/*
			 * XXX - how do we determine if layouts still
			 *	 outstanding for fsid/all cases ?
			 */
		default:
			break;
		}

	} else {	/* RPC_SUCCESS */

		/*
		 * Per-type results processing
		 */
		switch (lorec->lor_type) {
		case LAYOUTRECALL4_FILE:
			(void) atomic_swap_32(&lg->lor_reply, 1);
			break;

		case LAYOUTRECALL4_FSID:
		case LAYOUTRECALL4_ALL:
		default:
			break;
		}
	}

	if (cb4_res.status != NFS4_OK) {
		nfsstat4	s = cb4_res.status;

		switch (s) {
		case NFS4ERR_BADHANDLE:
		case NFS4ERR_BADIOMODE:
		case NFS4ERR_BADXDR:
		case NFS4ERR_INVAL:
		case NFS4ERR_NOMATCHING_LAYOUT:
		case NFS4ERR_NOTSUPP:
		case NFS4ERR_OP_NOT_IN_SESSION:
		case NFS4ERR_REP_TOO_BIG:
		case NFS4ERR_REP_TOO_BIG_TO_CACHE:
		case NFS4ERR_REQ_TOO_BIG:
		case NFS4ERR_TOO_MANY_OPS:
		case NFS4ERR_UNKNOWN_LAYOUTTYPE:
		case NFS4ERR_WRONG_TYPE:
			/* What do we do when it's our own fault ? */
			cmn_err(CE_NOTE, "cb_lo_recall: %s", nfs41_strerror(s));
			break;

		case NFS4ERR_DELAY:
			switch (lorec->lor_type) {
			case LAYOUTRECALL4_FILE:
				{
				bool_t	granted = FALSE;

				if (!retried)
					delay(SEC_TO_TICK(rfs4_lease_time));

				granted = rfs41_lo_still_granted(lg);
				if (!granted)
					break;

				if (!retried) {
					retried = 1;
					goto retry;
				}

				if (granted)
					rfs41_revoke_layout(lg);
				break;
				}

			case LAYOUTRECALL4_FSID:
			case LAYOUTRECALL4_ALL:
			default:
				break;
			}
			break;

		case NFS4ERR_BAD_STATEID:	/* XXX - retry BAD_STATEID ? */
		default:
			if (lorec->lor_type == LAYOUTRECALL4_FILE)
				if (rfs41_lo_still_granted(lg))
					rfs41_revoke_layout(lg);
			break;
		}

	}
	svc_slot_cb_seqid(&cb4_res, p);
done:
	kmem_free(lorec, sizeof (mds_lorec_t));
	rfs4freeargres(&cb4_args, &cb4_res);

	svc_slot_free(sp, p);
	rfs41_session_rele(sp);

	/*
	 * Per-type post-processing
	 */
	switch (lorec->lor_type) {
	case LAYOUTRECALL4_FILE:
		rfs41_lo_grant_rele(lg);
		break;

	case LAYOUTRECALL4_FSID:
	case LAYOUTRECALL4_ALL:
	default:
		break;
	}
}

/*
 * Bulk Layout Recall (ALL)
 */
static void
all_lor(rfs4_entry_t entry, void *args)
{
	mds_session_t	*sp = (mds_session_t *)entry;
	mds_lorec_t	*lrp = (mds_lorec_t *)args;
	mds_lorec_t	*lorec;

	if (sp == NULL || lrp == NULL)
		return;

	ASSERT(rfs4_dbe_islocked(sp->sn_dbe));
	lorec = kmem_zalloc(sizeof (mds_lorec_t), KM_SLEEP);
	bcopy(args, lorec, sizeof (mds_lorec_t));

	rfs4_dbe_hold(sp->sn_dbe);
	lorec->lor_sess = sp;

	(void) thread_create(NULL, 0, mds_do_lorecall, lorec, 0, &p0, TS_RUN,
	    minclsyspri);
}

/*
 * Layout Recall by FSID
 */
static void
fsid_lor(rfs4_entry_t u_entry, void *args)
{
	mds_lorec_t		*lrp = (mds_lorec_t *)args;
	mds_ever_grant_t	*eg = (mds_ever_grant_t *)u_entry;
	mds_ever_grant_t	key;
	vnode_t			*vp = NULL;

	if (eg == NULL || lrp == NULL || rfs4_dbe_is_invalid(eg->eg_dbe))
		return;

	ASSERT(rfs4_dbe_islocked(eg->eg_dbe));
	if ((vp = (vnode_t *)lrp->lor_vp) == NULL)
		return;

	key.eg_fsid = vp->v_vfsp->vfs_fsid;
	if (mds_ever_grant_fsid_compare(u_entry,
	    (void *)(uintptr_t)key.eg_key)) {
		mds_lorec_t	*lorec;
		mds_session_t	*sp;
		nfs_server_instance_t	*instp;

		instp = dbe_to_instp(u_entry->dbe);

		lorec = kmem_zalloc(sizeof (mds_lorec_t), KM_SLEEP);
		bcopy(args, lorec, sizeof (mds_lorec_t));

		ASSERT(eg->eg_cp != NULL);
		sp = mds_findsession_by_clid(instp, eg->eg_cp->rc_clientid);
		if (sp == NULL) {
			kmem_free(lorec, sizeof (mds_lorec_t));
			return;
		}
		lorec->lor_sess = sp;	/* hold courtesy of findsession */

		(void) thread_create(NULL, 0, mds_do_lorecall, lorec, 0, &p0,
		    TS_RUN, minclsyspri);
	}
}

/*
 * Layout Recall by File
 */
static void
file_lor(rfs4_entry_t entry, void *arg)
{
	mds_lorec_t *lorec;

	lorec = kmem_alloc(sizeof (mds_lorec_t), KM_SLEEP);
	bcopy(arg, lorec, sizeof (mds_lorec_t));
	lorec->lor_sess = (mds_session_t *)entry;

	(void) thread_create(NULL, 0, mds_do_lorecall, lorec, 0, &p0, TS_RUN,
	    minclsyspri);
}


/*
 * Recall a layout:
 *
 *   Either all layouts
 *
 *   ... or
 *
 *   For a given pathname construct FH first (same thing we do
 *   for nfs_sys(GETFH)) args have already been copied into kernel
 *   adspace
 */
static int
mds_lorecall_cmd(struct mds_reclo_args *args, cred_t *cr)
{
	int			 error;
	nfs_fh4			 fh4;
	struct exportinfo	*exi;
	mds_lorec_t		 lorec;
	vnode_t			*vp = NULL;
	vnode_t			*dvp = NULL;
	rfs4_file_t		*fp = NULL;
	rfs4_client_t		*cp = NULL;
	rfs41_grant_list_t	*glp = NULL;
	mds_session_t		*sp = NULL;

	lorec.lor_type = args->lo_type;
	switch (args->lo_type) {
	case LAYOUTRECALL4_ALL:
		if (mds_server->mds_session_tab == NULL)
			return (ECANCELED);

		rfs4_dbe_walk(mds_server->mds_session_tab, all_lor, &lorec);
		return (0);

	case LAYOUTRECALL4_FILE:
	case LAYOUTRECALL4_FSID:
		break;

	default:
		return (EINVAL);
	}

	if (error = lookupname(args->lo_fname, UIO_SYSSPACE, FOLLOW, &dvp, &vp))
		return (error);

	if (vp == NULL) {
		if (dvp != NULL)
			VN_RELE(dvp);
		return (ENOENT);
	}

	/*
	 * 'vp' may be an AUTOFS node, so we perform a VOP_ACCESS()
	 * to trigger the mount of the intended filesystem, so we
	 * can share the intended filesystem instead of the AUTOFS
	 * filesystem.
	 */
	(void) VOP_ACCESS(vp, 0, 0, cr, NULL);

	/*
	 * We're interested in the top most filesystem. This is
	 * specially important when uap->dname is a trigger AUTOFS
	 * node, since we're really interested in sharing the
	 * filesystem AUTOFS mounted as result of the VOP_ACCESS()
	 * call, not the AUTOFS node itself.
	 */
	if (vn_mountedvfs(vp) != NULL) {
		if (error = traverse(&vp))
			goto errout;
	}

	/*
	 * The last arg for nfs_vptoexi says to create a v4 FH
	 * (instead of v3). This will need to be changed to
	 * select the new MDS FH format.
	 */
	rw_enter(&exported_lock, RW_READER);
	exi = nfs_vptoexi(dvp, vp, cr, NULL, &error, TRUE);
	rw_exit(&exported_lock);

	/*
	 * file isn't shared.
	 */
	if (exi == NULL)
		goto errout;

	fh4.nfs_fh4_val = lorec.lor_fh.fh_buf;
	error = mknfs41_fh(&fh4, vp, exi);
	lorec.lor_fh.fh_len = fh4.nfs_fh4_len;
	lorec.lor_sess = NULL;

	switch (lorec.lor_type) {
	case LAYOUTRECALL4_FILE:
		mutex_enter(&vp->v_vsd_lock);
		fp = (rfs4_file_t *)vsd_get(vp, mds_server->vkey);
		mutex_exit(&vp->v_vsd_lock);
		if (fp == NULL) {
			error = EIO;
			goto errout;
		}

		/*
		 * There may be a cleaner way to run the per-file lists,
		 * but this works for now. This sends a cb_lo_recall to
		 * the clients that have an active layout for the file,
		 * only. Stop the blasting !
		 */
		glp = fp->rf_lo_grant_list.next;
		for (; glp && glp->lg; glp = glp->next) {

			if ((cp = glp->lg->lo_cp) == NULL)
				continue;	/* internal inconsistency ? */

			rfs41_lo_grant_hold(glp->lg);
			sp = mds_findsession_by_clid(mds_server,
			    cp->rc_clientid);
			if (sp != NULL) {
				/*
				 * Recall in progress !
				 *
				 * As per spec rules, bump up the seqid (of
				 * the stateid) and make sure we store it in
				 * the layout grant info; this will eventually
				 * be used for layout race detection.
				 */
				rfs4_dbe_lock(glp->lg->lo_dbe);

				glp->lg->lo_status = LO_RECALL_INPROG;
				rfs41_lo_seqid(&glp->lg->lo_stateid);

				mutex_enter(&glp->lg->lo_lock);
				glp->lg->lor_seqid =
				    glp->lg->lo_stateid.v41_bits.chgseq;
				mutex_exit(&glp->lg->lo_lock);

				bcopy(&glp->lg->lo_stateid.stateid,
				    &lorec.lor_stid, sizeof (stateid4));
				lorec.lor_lg = glp->lg;
				rfs41_lo_grant_hold(glp->lg);

				rfs4_dbe_unlock(glp->lg->lo_dbe);
				file_lor((rfs4_entry_t)sp, (void *)&lorec);
			}
			rfs41_lo_grant_rele(glp->lg);
		}
		break;

	case LAYOUTRECALL4_FSID:
		/*
		 * set fsid just like rfs4_fattr4_fsid()
		 */
		if (exi->exi_volatile_dev) {
			int *pmaj = (int *)&lorec.lor_fsid.major;

			pmaj[0] = exi->exi_fsid.val[0];
			pmaj[1] = exi->exi_fsid.val[1];
			lorec.lor_fsid.minor = 0;
		} else {
			vattr_t va;

			va.va_mask = AT_FSID | AT_TYPE;
			error = rfs4_vop_getattr(vp, &va, 0, cr);

			if (error == 0 && va.va_type != VREG)
				error = EINVAL;
			if (error)
				goto errout;

			lorec.lor_fsid.major = getmajor(va.va_fsid);
			lorec.lor_fsid.minor = getminor(va.va_fsid);
		}

		if (mds_server->mds_ever_grant_tab == NULL) {
			error = ECANCELED;
			goto errout;
		}

		lorec.lor_vp = vp;
		VN_HOLD(vp);
		rfs4_dbe_walk(mds_server->mds_ever_grant_tab, fsid_lor, &lorec);
		VN_RELE(vp);
		break;

	default:
		break;
	}

errout:
	VN_RELE(vp);
	if (dvp != NULL)
		VN_RELE(dvp);
	return (error);
}

/* support for device notifications via mdsadm */

typedef struct mds_notify_device {
	mds_session_t			*nd_sess;
	struct mds_notifydev_args	 nd_args;

} mds_notify_device_t;

static void
mds_do_notify_device(mds_notify_device_t *ndp)
{
	CB_COMPOUND4args	 cb4_args;
	CB_COMPOUND4res		 cb4_res;
	CB_SEQUENCE4args	*cbsap;
	CB_NOTIFY_DEVICEID4args *cbndap;
	nfs_cb_argop4		*argops;
	struct timeval		 timeout;
	enum clnt_stat		 call_stat = RPC_FAILED;
	int			 zilch = 0;
	CLIENT			*ch;
	int			 numops;
	int			 argsz;
	mds_session_t		*sp;
	slot_ent_t		*p;
	notify4			 no;
	char			*xdr_buf = NULL;
	int			 xdr_size;
	XDR			 xdr;

	DTRACE_PROBE1(nfssrv__i__sess_notify_device, mds_notify_device_t *,
	    ndp);

	if (ndp->nd_sess == NULL)
		return;
	sp = ndp->nd_sess;

	/*
	 * XXX - until we fix blasting _all_ sessions for one notification,
	 *	make sure that the session in question at least has the
	 *	back chan established.
	 */
	if (!SN_CB_CHAN_EST(sp))
		return;

	/*
	 * set up the compound args
	 */
	numops = 2;	/* CB_SEQUENCE + CB_NOTIFY_DEVICE */
	argsz = numops * sizeof (nfs_cb_argop4);
	argops = kmem_zalloc(argsz, KM_SLEEP);

	argops[0].argop = OP_CB_SEQUENCE;
	cbsap = &argops[0].nfs_cb_argop4_u.opcbsequence;

	argops[1].argop = OP_CB_NOTIFY_DEVICEID;
	cbndap = &argops[1].nfs_cb_argop4_u.opcbnotify_deviceid;

	(void) str_to_utf8("cb_notify_device", &cb4_args.tag);
	cb4_args.minorversion = CB4_MINOR_v1;

	cb4_args.callback_ident = sp->sn_bc.progno;
	cb4_args.array_len = numops;
	cb4_args.array = argops;

	cb4_res.tag.utf8string_val = NULL;
	cb4_res.array = NULL;

	/*
	 * CB_SEQUENCE
	 */
	bcopy(sp->sn_sessid, cbsap->csa_sessionid, sizeof (sessionid4));
	p = svc_slot_alloc(sp);
	mutex_enter(&p->se_lock);
	cbsap->csa_slotid = p->se_sltno;
	cbsap->csa_sequenceid = p->se_seqid;
	cbsap->csa_highest_slotid = svc_slot_maxslot(sp);
	cbsap->csa_cachethis = FALSE;

	/* no referring calling list for device notifications */
	cbsap->csa_rcall_llen = 0;
	cbsap->csa_rcall_lval = NULL;
	mutex_exit(&p->se_lock);

	/*
	 * CB_NOTIFY_DEVICEID (well, d'uh)
	 */
	cbndap->cnda_changes.cnda_changes_len = 1;
	cbndap->cnda_changes.cnda_changes_val = &no;
	if (ndp->nd_args.notify_how == NOTIFY_DEVICEID4_DELETE) {
		notify_deviceid_delete4 nodd;

		no.notify_mask = NOTIFY_DEVICEID4_DELETE_MASK;
		nodd.ndd_layouttype = LAYOUT4_NFSV4_1_FILES;
		(void) memset(&nodd.ndd_deviceid, 0, sizeof (deviceid4));
		bcopy(&ndp->nd_args.dev_id, &nodd.ndd_deviceid,
		    sizeof (ndp->nd_args.dev_id));

		/* encode the notification blob */

		xdr_size = xdr_sizeof(xdr_notify_deviceid_delete4, &nodd);
		ASSERT(xdr_size);
		xdr_buf = kmem_alloc(xdr_size, KM_SLEEP);
		xdrmem_create(&xdr, xdr_buf, xdr_size, XDR_ENCODE);

		if (xdr_notify_deviceid_delete4(&xdr, &nodd) == FALSE)
			goto done;

		/*
		 * Once the blob is encoded, we no longer need
		 * nodd, which goes out of scope here.
		 */

	} else {
		notify_deviceid_change4 nodc;

		no.notify_mask = NOTIFY_DEVICEID4_CHANGE_MASK;
		nodc.ndc_layouttype = LAYOUT4_NFSV4_1_FILES;
		(void) memset(&nodc.ndc_deviceid, 0, sizeof (deviceid4));
		bcopy(&ndp->nd_args.dev_id, &nodc.ndc_deviceid,
		    sizeof (ndp->nd_args.dev_id));

		xdr_size = xdr_sizeof(xdr_notify_deviceid_change4, &nodc);
		ASSERT(xdr_size);
		xdr_buf = kmem_alloc(xdr_size, KM_SLEEP);
		xdrmem_create(&xdr, xdr_buf, xdr_size, XDR_ENCODE);

		if (xdr_notify_deviceid_change4(&xdr, &nodc) == FALSE) {
			kmem_free(xdr_buf, xdr_size);
			xdr_size = 0;
			xdr_buf = NULL;
		}
	}

	no.notify_vals.notifylist4_len = xdr_size;
	no.notify_vals.notifylist4_val = xdr_buf;

	/*
	 * Set up the timeout for the callback and make the actual call.
	 * Timeout will be 80% of the lease period.
	 */
	timeout.tv_sec =
	    (dbe_to_instp(sp->sn_dbe)->lease_period * 80) / 100;
	timeout.tv_usec = 0;

	ch = rfs41_cb_getch(sp);
	(void) CLNT_CONTROL(ch, CLSET_XID, (char *)&zilch);
	call_stat = clnt_call(ch, CB_COMPOUND,
	    xdr_CB_COMPOUND4args_srv, (caddr_t)&cb4_args,
	    xdr_CB_COMPOUND4res, (caddr_t)&cb4_res, timeout);
	rfs41_cb_freech(sp, ch);

	/*
	 * Errors from the client are harmless for now, since this
	 * is invoked by an administrative action for testing purposes.
	 * In the future, if this were part of the normal server action,
	 * these errors would need to be handled.
	 */
	if (call_stat != RPC_SUCCESS) {
		cmn_err(CE_NOTE, "mds_do_notify_device: RPC call failed %d",
		    call_stat);
		goto done;

	} else if (cb4_res.status != NFS4_OK) {
		cmn_err(CE_NOTE, "mds_do_notify_device: compound failed %d",
		    cb4_res.status);

	}
	svc_slot_cb_seqid(&cb4_res, p);
	xdr_free(xdr_CB_COMPOUND4res, (caddr_t)&cb4_res);
done:
	kmem_free(cb4_args.tag.utf8string_val, cb4_args.tag.utf8string_len);
	kmem_free(argops, argsz);
	kmem_free(ndp, sizeof (*ndp));
	if (xdr_buf)
		kmem_free(xdr_buf, xdr_size);
	svc_slot_free(sp, p);
}

static void
mds_sess_notify_device_callout(rfs4_entry_t u_entry, void *arg)
{
	mds_notify_device_t *ndp;

	ndp = kmem_alloc(sizeof (*ndp), KM_SLEEP);
	bcopy(arg, &ndp->nd_args, sizeof (ndp->nd_args));
	ndp->nd_sess = (mds_session_t *)u_entry;

	(void) thread_create(NULL, 0, mds_do_notify_device, ndp, 0, &p0,
	    TS_RUN, minclsyspri);
}

void
inst_notify_device(nfs_server_instance_t *instp, void *args)
{
	if (instp->mds_session_tab != NULL)
		rfs4_dbe_walk(instp->mds_session_tab,
		    mds_sess_notify_device_callout, args);
}

/*ARGSUSED*/
static int
mds_notify_device_cmd(struct mds_notifydev_args *args, cred_t *cr)
{
	/*
	 * Walk the list of server instances, asking each
	 * to notify the specified device.
	 */
	nsi_walk(inst_notify_device, args);
	return (0);
}

/*
 * -----------------------------------------------
 * MDS: DS_ADDR tables.
 * -----------------------------------------------
 *
 */

static uint32_t
ds_addrlist_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static bool_t
ds_addrlist_compare(rfs4_entry_t u_entry, void *key)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)u_entry;

	return (rfs4_dbe_getid(dp->dbe) == (int)(uintptr_t)key);
}

static void *
ds_addrlist_mkkey(rfs4_entry_t entry)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;

	return ((void *)(uintptr_t)rfs4_dbe_getid(dp->dbe));
}

/*ARGSUSED*/
static bool_t
ds_addrlist_create(rfs4_entry_t u_entry, void *arg)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)u_entry;
	struct mds_adddev_args *u_dp = (struct mds_adddev_args *)arg;

	dp->dev_addr.na_r_netid = kstrdup(u_dp->dev_netid);
	dp->dev_addr.na_r_addr = kstrdup(u_dp->dev_addr);
	dp->ds_owner = NULL;
	dp->dev_knc = NULL;
	dp->dev_nb = NULL;
	dp->ds_addr_key = 0;
	dp->ds_port_key = 0;

	return (TRUE);
}

/*ARGSUSED*/
static void
ds_addrlist_destroy(rfs4_entry_t u_entry)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)u_entry;
	int	i;
	nfs_server_instance_t	*instp;

	instp = dbe_to_instp(u_entry->dbe);

	rw_enter(&instp->ds_addrlist_lock, RW_WRITER);
	if (dp->ds_owner != NULL) {
		list_remove(&dp->ds_owner->ds_addrlist_list, dp);
		rfs4_dbe_rele(dp->ds_owner->dbe);
		dp->ds_owner = NULL;
	}
	rw_exit(&instp->ds_addrlist_lock);

	if (dp->dev_addr.na_r_netid) {
		i = strlen(dp->dev_addr.na_r_netid) + 1;
		kmem_free(dp->dev_addr.na_r_netid, i);
	}

	if (dp->dev_addr.na_r_addr) {
		i = strlen(dp->dev_addr.na_r_addr) + 1;
		kmem_free(dp->dev_addr.na_r_addr, i);
	}

	if (dp->dev_knc != NULL)
		kmem_free(dp->dev_knc, sizeof (struct knetconfig));

	if (dp->dev_nb != NULL) {
		if (dp->dev_nb->buf)
			kmem_free(dp->dev_nb->buf, dp->dev_nb->maxlen);
		kmem_free(dp->dev_nb, sizeof (struct netbuf));
	}
}


/*
 * Multipath devices.
 */
static uint32_t
mds_mpd_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static bool_t
mds_mpd_compare(rfs4_entry_t u_entry, void *key)
{
	mds_mpd_t *mp = (mds_mpd_t *)u_entry;

	return (mp->mpd_id == (id_t)(uintptr_t)key);
}

static void *
mds_mpd_mkkey(rfs4_entry_t u_entry)
{
	mds_mpd_t *mp = (mds_mpd_t *)u_entry;

	return ((void*)(uintptr_t)mp->mpd_id);
}

void
mds_mpd_encode(nfsv4_1_file_layout_ds_addr4 *ds_dev, uint_t *len, char **val)
{
	char *xdr_ds_dev;
	int  xdr_size = 0;
	XDR  xdr;

	ASSERT(val);

	xdr_size = xdr_sizeof(xdr_nfsv4_1_file_layout_ds_addr4, ds_dev);

	ASSERT(xdr_size);

	xdr_ds_dev = kmem_alloc(xdr_size, KM_SLEEP);

	xdrmem_create(&xdr, xdr_ds_dev, xdr_size, XDR_ENCODE);

	if (xdr_nfsv4_1_file_layout_ds_addr4(&xdr, ds_dev) == FALSE) {
		*len = 0;
		*val = NULL;
		kmem_free(xdr_ds_dev, xdr_size);
		return;
	}

	*len = xdr_size;
	*val = xdr_ds_dev;
}

/*ARGSUSED*/
static bool_t
mds_mpd_create(rfs4_entry_t u_entry, void *arg)
{
	mds_mpd_t *mp = (mds_mpd_t *)u_entry;
	mds_addmpd_t *maap = (mds_addmpd_t *)arg;

	mp->mpd_id = maap->id;
	mds_mpd_encode(maap->ds_addr4, &(mp->mpd_encoded_len),
	    &(mp->mpd_encoded_val));
	list_create(&mp->mpd_layouts_list, sizeof (mds_layout_t),
	    offsetof(mds_layout_t, mpd_layouts_next));

	return (TRUE);
}


/*ARGSUSED*/
static void
mds_mpd_destroy(rfs4_entry_t u_entry)
{
	mds_mpd_t		*mp = (mds_mpd_t *)u_entry;
	nfs_server_instance_t	*instp;

	instp = dbe_to_instp(u_entry->dbe);
	ASSERT(instp->mds_mpd_id_space != NULL);
	id_free(instp->mds_mpd_id_space, mp->mpd_id);

	kmem_free(mp->mpd_encoded_val, mp->mpd_encoded_len);

#ifdef	DEBUG
	/*
	 * We should never get here as the layouts
	 * entries should be holding a reference against
	 * this mpd!
	 */
	rw_enter(&instp->mds_mpd_lock, RW_WRITER);
	ASSERT(list_is_empty(&mp->mpd_layouts_list));
	rw_exit(&instp->mds_mpd_lock);
#endif
	list_destroy(&mp->mpd_layouts_list);
}

/*
 * The OTW device id is 128bits in length, we however are
 * still using a uint_32 internally.
 */
mds_mpd_t *
mds_find_mpd(nfs_server_instance_t *instp, id_t id)
{
	mds_mpd_t *mp;
	bool_t create = FALSE;

	mp = (mds_mpd_t *)rfs4_dbsearch(instp->mds_mpd_idx,
	    (void *)(uintptr_t)id, &create, NULL, RFS4_DBS_VALID);
	return (mp);
}

/*
 * Plop kernel deviceid into the 128bit OTW deviceid
 */
void
mds_set_deviceid(id_t did, deviceid4 *otw_id)
{
	ba_devid_t d;

	bzero(&d, sizeof (d));
	d.i.did = did;
	bcopy(&d, otw_id, sizeof (d));
}

/*
 * Used by the walker to populate the deviceid list.
 */
void
mds_mpd_list(rfs4_entry_t entry, void *arg)
{
	mds_mpd_t		*mp = (mds_mpd_t *)entry;
	mds_device_list_t	*mdl = (mds_device_list_t *)arg;

	deviceid4   *dlip;

	/*
	 * If this entry is invalid or we should skip it
	 * go to the next one..
	 */
	if (rfs4_dbe_skip_or_invalid(mp->mpd_dbe))
		return;

	dlip = &(mdl->mdl_dl[mdl->mdl_count]);

	mds_set_deviceid(mp->mpd_id, dlip);

	/*
	 * bump to the next devlist_item4
	 */
	mdl->mdl_count++;
}

/* ARGSUSED */
ds_addrlist_t *
mds_find_ds_addrlist_by_mds_sid(nfs_server_instance_t *instp,
    mds_sid *sid)
{
	ds_addrlist_t	*dp = NULL;
	ds_guid_info_t	*pgi;
	ds_owner_t	*dop;
	ds_guid_t	guid;

	/*
	 * Warning, do not, do not ever, free this guid!
	 */
	guid.stor_type = ZFS;
	guid.ds_guid_u.zfsguid.zfsguid_len = sid->len;
	guid.ds_guid_u.zfsguid.zfsguid_val = sid->val;

	/*
	 * First we need to find the ds_guid_info_t which
	 * corresponds to this mds_sid.
	 */
	pgi = mds_find_ds_guid_info_by_id(&guid);
	if (pgi == NULL)
		return (NULL);

	dop = pgi->ds_owner;
	if (!dop)
		goto error;

	/*
	 * XXX: If a ds_owner has multiple addresses, then just grab the first
	 * we find.
	 */
	dp = list_head(&dop->ds_addrlist_list);
	if (dp)
		rfs4_dbe_hold(dp->dbe);

error:

	rfs4_dbe_rele(pgi->dbe);
	return (dp);
}

ds_addrlist_t *
mds_find_ds_addrlist(nfs_server_instance_t *instp, uint32_t id)
{
	ds_addrlist_t *dp;
	bool_t create = FALSE;

	dp = (ds_addrlist_t *)rfs4_dbsearch(instp->ds_addrlist_idx,
	    (void *)(uintptr_t)id, &create, NULL, RFS4_DBS_VALID);
	return (dp);
}

void
mds_ds_addrlist_rele(ds_addrlist_t *dp)
{
	rfs4_dbe_rele(dp->dbe);
}

/*
 */
static uint32_t
mds_str_hash(void *key)
{
	char *addr = (char *)key;
	int i;
	uint32_t hash = 0;

	for (i = 0; addr[i]; i++) {
		hash <<= 1;
		hash += (uint_t)addr[i];
	}

	return (hash);
}

static uint32_t
mds_utf8string_hash(void *key)
{
	utf8string *obj = (utf8string *)key;
	int i;
	uint32_t hash = 0;

	for (i = 0; i < obj->utf8string_len; i++) {
		hash <<= 1;
		hash += (uint_t)obj->utf8string_val[i];
	}

	return (hash);
}

static bool_t
rfs41_invalid_expiry(rfs4_entry_t entry)
{
	if (rfs4_dbe_is_invalid(entry->dbe))
		return (TRUE);

	return (FALSE);
}

static uint32_t
ds_addrlist_addrkey_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static void *
ds_addrlist_addrkey_mkkey(rfs4_entry_t entry)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;

	return (&dp->ds_addr_key);
}

/*
 * Only compare the address portion and not the
 * port info. We do this because the DS may
 * have rebooted and gotten a different port
 * number.
 *
 * XXX: What happens if we have multiple DSes
 * on one box? I.e., a valid case for the same
 * IP, but different ports?
 */
static int
ds_addrlist_addrkey_compare(rfs4_entry_t entry, void *key)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;
	uint64_t addr_key = *(uint64_t *)key;

	return (addr_key == dp->ds_addr_key);
}

/*
 * Data-server information (ds_owner)  tables and indexes.
 */
static uint32_t
ds_owner_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static bool_t
ds_owner_compare(rfs4_entry_t entry, void *key)
{
	ds_owner_t *dop = (ds_owner_t *)entry;

	return (dop->ds_id == (int)(uintptr_t)key);

}

static void *
ds_owner_mkkey(rfs4_entry_t entry)
{
	ds_owner_t *dop = (ds_owner_t *)entry;

	return ((void *)(uintptr_t)dop->ds_id);
}

static bool_t
ds_owner_inst_compare(rfs4_entry_t entry, void *key)
{
	ds_owner_t *dop = (ds_owner_t *)entry;

	return (strcmp(dop->identity, key) == 0);
}

static void *
ds_owner_inst_mkkey(rfs4_entry_t entry)
{
	ds_owner_t *dop = (ds_owner_t *)entry;
	return (dop->identity);
}

/*ARGSUSED*/
static bool_t
ds_owner_create(rfs4_entry_t u_entry, void *arg)
{
	ds_owner_t *dop = (ds_owner_t *)u_entry;
	DS_EXIBIargs *drap = (DS_EXIBIargs *)arg;

	dop->ds_id = rfs4_dbe_getid(dop->dbe);
	dop->verifier = drap->ds_ident.boot_verifier;
	dop->identity = kstrdup(drap->ds_ident.instance.instance_val);
	list_create(&dop->ds_addrlist_list, sizeof (ds_addrlist_t),
	    offsetof(ds_addrlist_t, ds_addrlist_next));
	list_create(&dop->ds_guid_list, sizeof (ds_guid_info_t),
	    offsetof(ds_guid_info_t, ds_guid_next));
	return (TRUE);
}

ds_owner_t *
ds_owner_alloc(DS_EXIBIargs *drap)
{
	ds_owner_t *dop;

	rw_enter(&mds_server->ds_owner_lock, RW_WRITER);
	/* Add the "new" entry */
	dop = (ds_owner_t *)rfs4_dbcreate(mds_server->ds_owner_inst_idx,
	    (void *)drap);
	rw_exit(&mds_server->ds_owner_lock);
	return (dop);
}

static void
ds_owner_destroy(rfs4_entry_t u_entry)
{
	ds_owner_t *dop = (ds_owner_t *)u_entry;

	int	i;
	nfs_server_instance_t	*instp;

	instp = dbe_to_instp(u_entry->dbe);

	i = strlen(dop->identity) + 1;
	kmem_free(dop->identity, i);

#ifdef	DEBUG
	/*
	 * We should never get here as the ds_addrlist
	 * entries should be holding a reference against
	 * this owner!
	 */
	rw_enter(&instp->ds_addrlist_lock, RW_WRITER);
	ASSERT(list_is_empty(&dop->ds_addrlist_list));
	rw_exit(&instp->ds_addrlist_lock);

	/*
	 * We should never get here as the ds_guid_info
	 * entries should be holding a reference against
	 * this owner!
	 */
	rw_enter(&instp->ds_guid_info_lock, RW_WRITER);
	ASSERT(list_is_empty(&dop->ds_guid_list));
	rw_exit(&instp->ds_guid_info_lock);
#endif

	list_destroy(&dop->ds_guid_list);
	list_destroy(&dop->ds_addrlist_list);
}

void
ds_guid_free(ds_guid_t *gp)
{
	if (gp == NULL)
		return;

	/*
	 * Yes, overkill for one stor_type, but ready
	 * to go for more!
	 */
	switch (gp->stor_type) {
	case ZFS:
		kmem_free(gp->ds_guid_u.zfsguid.zfsguid_val,
		    gp->ds_guid_u.zfsguid.zfsguid_len);
		break;
	}
}

/*
 * Duplicate the src guid to dst.
 *
 * return 0 on success or 1 for failure.
 */
int
ds_guid_dup(ds_guid_t *src, ds_guid_t *dst)
{
	dst = src;

	switch (dst->stor_type) {
	case ZFS:
		dst->ds_guid_u.zfsguid.zfsguid_val
		    = kmem_alloc(dst->ds_guid_u.zfsguid.zfsguid_len, KM_SLEEP);
		bcopy(src->ds_guid_u.zfsguid.zfsguid_val,
		    dst->ds_guid_u.zfsguid.zfsguid_val,
		    dst->ds_guid_u.zfsguid.zfsguid_len);
		break;
	default:
		/* if it's unknown zero out the dst */
		bzero(dst, sizeof (ds_guid_t));
		return (1);

	}
	return (0);
}

/*
 * compare ds_guids return 0 for not the same or
 * 1 if they are equal..
 */
int
ds_guid_compare(ds_guid_t *gp1, ds_guid_t *gp2)
{
	if (gp1->stor_type != gp2->stor_type)
		return (0);

	switch (gp1->stor_type) {
	case ZFS:
		if (gp1->ds_guid_u.zfsguid.zfsguid_len !=
		    gp2->ds_guid_u.zfsguid.zfsguid_len)
			return (0);
		if (bcmp(gp1->ds_guid_u.zfsguid.zfsguid_val,
		    gp2->ds_guid_u.zfsguid.zfsguid_val,
		    gp2->ds_guid_u.zfsguid.zfsguid_len) != 0)
			return (0);
		break;

	default:
		return (0);
	}

	return (1);
}

void
mds_free_zfsattr(ds_guid_info_t *dst)
{
	int i;

	if (dst->ds_attr_len == 0)
		return;

	for (i = 0; i < dst->ds_attr_len; i++) {
		UTF8STRING_FREE(dst->ds_attr_val[i].attrname);
		kmem_free(dst->ds_attr_val[i].attrvalue.attrvalue_val,
		    dst->ds_attr_val[i].attrvalue.attrvalue_len);
	}
}

void
mds_dup_zfsattr(ds_zfsattr *src, ds_guid_info_t *dst)
{
	int i;
	int len;

	for (i = 0; i < dst->ds_attr_len; i++) {
		len = dst->ds_attr_val[i].attrname.utf8string_len =
		    src[i].attrname.utf8string_len;

		dst->ds_attr_val[i].attrname.utf8string_val =
		    kmem_alloc(len, KM_SLEEP);

		bcopy(src[i].attrname.utf8string_val,
		    dst->ds_attr_val[i].attrname.utf8string_val, len);

		len = dst->ds_attr_val[i].attrvalue.attrvalue_len =
		    src[i].attrvalue.attrvalue_len;

		dst->ds_attr_val[i].attrvalue.attrvalue_val
		    = kmem_alloc(len, KM_SLEEP);

		bcopy(src[i].attrvalue.attrvalue_val,
		    dst->ds_attr_val[i].attrvalue.attrvalue_val, len);
	}
}

static bool_t
ds_guid_info_create(rfs4_entry_t u_entry, void *arg)
{
	ds_guid_info_t	*pgi = (ds_guid_info_t *)u_entry;
	pinfo_create_t	*pic = (pinfo_create_t *)arg;

	ds_guid		*dest;
	ds_guid		*src;

	ds_zfsinfo	*dz;
	char		*sz;

	int		j;
	uint_t		len;

	/*
	 * Get the dataset name.
	 * Note: We do this first to make the error handling
	 * dead simple, i.e., do nothing!
	 */
	pgi->ds_dataset_name.utf8string_val = NULL;
	pgi->ds_dataset_name.utf8string_len = 0;
	dz = &pic->si->ds_storinfo_u.zfs_info;
	for (j = 0; j < dz->attrs.attrs_len; j++) {
		ds_zfsattr	*attrs_val = &dz->attrs.attrs_val[j];
		int		cmp;

		sz = utf8_to_str(&attrs_val->attrname, &len, NULL);
		cmp = strcmp(sz, "dataset");
		kmem_free(sz, len);
		if (cmp == 0) {
			(void) utf8_copy(
			    (utf8string *)&attrs_val->attrvalue,
			    &pgi->ds_dataset_name);

			break;
		}
	}

	/*
	 * As the dataset name is an index, it must exist!
	 */
	if (UTF8STRING_NULL(pgi->ds_dataset_name)) {
		return (FALSE);
	}

	pgi->ds_owner = pic->ds_owner;
	rfs4_dbe_hold(pgi->ds_owner->dbe);

	list_insert_tail(&pgi->ds_owner->ds_guid_list, pgi);
	rfs4_dbe_hold(pgi->dbe);

	/* Only supported type is ZFS */
	ASSERT(pic->si->type == ZFS);

	src = &(pic->si->ds_storinfo_u.zfs_info.guid_map.ds_guid);
	dest = &pgi->ds_guid;
	dest->stor_type = src->stor_type;

	/*
	 * Copy ds_guid
	 */
	dest->ds_guid_u.zfsguid.zfsguid_len =
	    src->ds_guid_u.zfsguid.zfsguid_len;
	dest->ds_guid_u.zfsguid.zfsguid_val =
	    kmem_zalloc(dest->ds_guid_u.zfsguid.zfsguid_len,
	    KM_SLEEP);
	bcopy(src->ds_guid_u.zfsguid.zfsguid_val,
	    dest->ds_guid_u.zfsguid.zfsguid_val,
	    dest->ds_guid_u.zfsguid.zfsguid_len);

	/*
	 * Copy zfs attrs
	 */
	pgi->ds_attr_len = pic->si->ds_storinfo_u.zfs_info.attrs.attrs_len;
	pgi->ds_attr_val = kmem_alloc(
	    sizeof (ds_zfsattr) * pgi->ds_attr_len, KM_SLEEP);
	mds_dup_zfsattr(pic->si->ds_storinfo_u.zfs_info.attrs.attrs_val,
	    pgi);

	return (TRUE);
}

static void *
ds_guid_info_mkkey(rfs4_entry_t u_entry)
{
	ds_guid_info_t *pgi = (ds_guid_info_t *)u_entry;

	return ((void *)(uintptr_t)&pgi->ds_guid);
}

static bool_t
ds_guid_info_compare(rfs4_entry_t u_entry, void *key)
{
	ds_guid_info_t *pgi = (ds_guid_info_t *)u_entry;
	ds_guid_t *guid = (ds_guid_t *)key;

	return (ds_guid_compare(&pgi->ds_guid, guid));
}

static uint32_t
ds_guid_info_hash(void *key)
{
	ds_guid_t	*pg = (ds_guid_t *)key;
	int		i;
	uint32_t	hash = 0;

	for (i = 0; i < pg->ds_guid_u.zfsguid.zfsguid_len; i++) {
		hash <<= 1;
		hash += (uint_t)pg->ds_guid_u.zfsguid.zfsguid_val[i];
	}

	return (hash);
}

static void *
ds_guid_info_dataset_name_mkkey(rfs4_entry_t u_entry)
{
	ds_guid_info_t *pgi = (ds_guid_info_t *)u_entry;

	return ((void *)&pgi->ds_dataset_name);
}

static bool_t
ds_guid_info_dataset_name_compare(rfs4_entry_t u_entry, void *key)
{
	ds_guid_info_t *pgi = (ds_guid_info_t *)u_entry;

	return (utf8_compare((utf8string *)key,
	    &pgi->ds_dataset_name) == 0);
}

/*ARGSUSED*/
static void
ds_guid_info_destroy(rfs4_entry_t u_entry)
{
	ds_guid_info_t *pgi = (ds_guid_info_t *)u_entry;
	nfs_server_instance_t	*instp;

	instp = dbe_to_instp(u_entry->dbe);

	rw_enter(&instp->ds_guid_info_lock, RW_WRITER);
	if (pgi->ds_owner) {
		list_remove(&pgi->ds_owner->ds_guid_list, pgi);
		rfs4_dbe_rele(pgi->ds_owner->dbe);
	}
	rw_exit(&instp->ds_guid_info_lock);

	ds_guid_free(&pgi->ds_guid);
	mds_free_zfsattr(pgi);

	UTF8STRING_FREE(pgi->ds_dataset_name);
}

ds_guid_info_t *
mds_find_ds_guid_info_by_id(ds_guid_t *guid)
{
	ds_guid_info_t	*pgi;
	bool_t		create = FALSE;

	rw_enter(&mds_server->ds_guid_info_lock, RW_READER);
	pgi = (ds_guid_info_t *)rfs4_dbsearch(mds_server->ds_guid_info_idx,
	    (void *)guid, &create, NULL, RFS4_DBS_VALID);
	rw_exit(&mds_server->ds_guid_info_lock);

	return (pgi);
}

int
mds_ds_path_to_mds_sid(utf8string *dataset_name, mds_sid *sid)
{
	ds_guid_info_t	*pgi;
	bool_t		create = FALSE;

	rw_enter(&mds_server->ds_guid_info_lock, RW_READER);
	pgi = (ds_guid_info_t *)rfs4_dbsearch(
	    mds_server->ds_guid_info_dataset_name_idx,
	    (void *)dataset_name, &create, NULL, RFS4_DBS_VALID);
	rw_exit(&mds_server->ds_guid_info_lock);

	if (pgi == NULL)
		return (1);

	sid->len = pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_len;
	sid->val = kmem_alloc(sid->len, KM_SLEEP);
	bcopy(pgi->ds_guid.ds_guid_u.zfsguid.zfsguid_val,
	    sid->val, sid->len);

	rfs4_dbe_rele(pgi->dbe);

	return (0);
}

/*
 * XXX this should be populated during startup. we
 * XXX should get the data from stable store. For now
 * XXX we are just going to keep the map that the DS
 * XXX provides us..
 */
/*ARGSUSED*/
static bool_t
mds_mapzap_create(nfs_server_instance_t *instp,
		rfs4_entry_t e, void *arg)
{
	mds_mapzap_t *mzp = (mds_mapzap_t *)e;

	mzp->ds_map = *(ds_guid_map_t *)arg;
	/* write to disk */
	return (TRUE);
}

static void *
mds_mapzap_mkkey(rfs4_entry_t e)
{
	mds_mapzap_t *mzp = (mds_mapzap_t *)e;

	return ((void *)(uintptr_t)&mzp->ds_map.ds_guid);
}


static bool_t
mds_mapzap_compare(rfs4_entry_t e, void *key)
{
	mds_mapzap_t *mzp = (mds_mapzap_t *)e;
	ds_guid_t   *gp = (ds_guid_t *)key;

	return ((bool_t)ds_guid_compare(&mzp->ds_map.ds_guid, gp));

}

static uint32_t
mds_mapzap_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

/*ARGSUSED*/
static void
mds_mapzap_destroy(rfs4_entry_t foo)
{
}

/*
 * Used to initialize the NFSv4.1 server's state.
 * All of the tables are created and timers are set.
 *
 * Upon success, the state_lock is held.
 */
int
sstor_init(nfs_server_instance_t *instp, int def_reap)
{
	/*
	 * If the server state store has already been initialized,
	 * skip it
	 */
	mutex_enter(&instp->state_lock);
	if (instp->state_store != NULL) {
		mutex_exit(&instp->state_lock);
		return (0);
	}

	/*
	 * Set the boot time.  If the server has been restarted quickly
	 * and has had the opportunity to service clients, then the start_time
	 * needs to be bumped regardless.  A small window but it exists...
	 */
	if (instp->start_time != gethrestime_sec())
		instp->start_time = gethrestime_sec();
	else
		instp->start_time++;

	/*
	 * If a table does not have a specific reap time,
	 * this value is used.
	 */
	instp->reap_time = def_reap * rfs4_lease_time;

	instp->state_store = rfs4_database_create();
	instp->state_store->db_instp = instp;

	/* reset the "first NFSv4 request" status */
	instp->seen_first_compound = 0;
	instp->exi_clean_func = NULL;

	return (1);
}

/*
 * Create/init just the session stateStore tables.
 * used for data-server
 *
 * NOTE: This code should be very suspect, it has never
 * been called. The DS actually uses the MDS tables!
 */
void
ds_sstor_init(nfs_server_instance_t *instp)
{
	/*
	 * Client table.
	 */
	rw_init(&instp->findclient_lock, NULL, RW_DEFAULT, NULL);

	instp->client_tab = rfs4_table_create(
	    instp, "Client", instp->client_cache_time, 2,
	    rfs4_client_create, rfs4_client_destroy, rfs4_client_expiry,
	    sizeof (rfs4_client_t), TABSIZE, MAXTABSZ/8, 100);

	instp->nfsclnt_idx = rfs4_index_create(instp->client_tab,
	    "nfs_client_id4", nfsclnt_hash, nfsclnt_compare, nfsclnt_mkkey,
	    TRUE);

	instp->clientid_idx = rfs4_index_create(instp->client_tab,
	    "client_id", clientid_hash, clientid_compare, clientid_mkkey,
	    FALSE);

	/*
	 * Session table.
	 */
	rw_init(&instp->findsession_lock, NULL, RW_DEFAULT, NULL);

	instp->mds_session_tab = rfs4_table_create(instp,
	    "Session", instp->reap_time, 2, mds_session_create,
	    mds_session_destroy, mds_do_not_expire, sizeof (mds_session_t),
	    MDS_TABSIZE, MDS_MAXTABSZ/8, 100);

	instp->mds_session_idx = rfs4_index_create(instp->mds_session_tab,
	    "session_idx", sessid_hash, sessid_compare, sessid_mkkey, TRUE);

	instp->mds_sess_clientid_idx = rfs4_index_create(instp->mds_session_tab,
	    "sess_clnt_idx", clientid_hash, sess_clid_compare, sess_clid_mkkey,
	    FALSE);

	/*
	 * Mark it as fully initialized
	 */
	instp->inst_flags |= NFS_INST_STORE_INIT | NFS_INST_DS;

	/*
	 * In case we are ever able to re-init the state,
	 * make sure we clean-up the termination!
	 */
	instp->inst_flags &= ~NFS_INST_TERMINUS;
}

/*
 * Used to initialize the NFSv4.1 server's state.
 * All of the tables are created and timers are set.
 */
void
mds_sstor_init(nfs_server_instance_t *instp)
{
	extern rfs4_cbstate_t mds_cbcheck(rfs4_state_t *);
	int  need_sstor_init;

	/*
	 * Create the state store and set the
	 * start-up time.
	 *
	 * Upon success, the state_lock is held!
	 */
	need_sstor_init = sstor_init(instp, 60);
	if (need_sstor_init == 0)
		return;

	instp->deleg_cbrecall = mds_do_cb_recall;
	instp->deleg_cbcheck  = mds_cbcheck;

	/*
	 * Make the NFSv4.1 kspe policies.
	 */
	nfs41_spe_init();

	/*
	 * Now create the common tables and indexes
	 */
	v4prot_sstor_init(instp);

	rw_init(&instp->mds_mpd_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&instp->ds_addrlist_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&instp->ds_guid_info_lock, NULL, RW_DEFAULT, NULL);
	instp->ds_guid_info_count = 0;

	/*
	 * Session table.
	 */
	rw_init(&instp->findsession_lock, NULL, RW_DEFAULT, NULL);

	instp->mds_session_tab = rfs4_table_create(instp,
	    "Session", instp->reap_time, 2, mds_session_create,
	    mds_session_destroy, mds_session_expiry, sizeof (mds_session_t),
	    MDS_TABSIZE, MDS_MAXTABSZ/8, 100);

	instp->mds_session_idx = rfs4_index_create(instp->mds_session_tab,
	    "session_idx", sessid_hash, sessid_compare, sessid_mkkey, TRUE);

	instp->mds_sess_clientid_idx = rfs4_index_create(instp->mds_session_tab,
	    "sess_clnt_idx", clientid_hash, sess_clid_compare, sess_clid_mkkey,
	    FALSE);

	/*
	 * pNFS layout table.
	 */
	rw_init(&instp->mds_layout_lock, NULL, RW_DEFAULT, NULL);

	/*
	 * A layout might be in use by many files. So, when one
	 * file is done with a layout, it can not invlaidate the
	 * state. Also, as a layout is created, it is immeadiately
	 * assigned to a file, and thus the refcnt will stay at
	 * 2. Thus, if the refcnt is ever 1, that means no file
	 * has a reference and as such, the entry can be reclaimed.
	 */
	instp->mds_layout_tab = rfs4_table_create(instp,
	    "Layout", instp->reap_time, 2, mds_layout_create,
	    mds_layout_destroy, NULL, sizeof (mds_layout_t),
	    MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->mds_layout_idx = rfs4_index_create(instp->mds_layout_tab,
	    "layout-idx", mds_layout_hash, mds_layout_compare, mds_layout_mkkey,
	    TRUE);

	instp->mds_layout_ID_idx =
	    rfs4_index_create(instp->mds_layout_tab,
	    "layout-ID-idx", mds_layout_id_hash,
	    mds_layout_id_compare, mds_layout_id_mkkey, FALSE);

	instp->mds_layout_default_idx = 0;

	/*
	 * Create the layout_grant table.
	 *
	 * This table tracks the layout segments that have been granted
	 * to clients. It is indexed by the layout state_id and also by client.
	 */
	instp->mds_layout_grant_tab = rfs4_table_create(instp,
	    "Layout_grant", instp->reap_time, 1, mds_layout_grant_create,
	    mds_layout_grant_destroy, NULL,
	    sizeof (mds_layout_grant_t), MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->mds_layout_grant_idx =
	    rfs4_index_create(instp->mds_layout_grant_tab,
	    "layout-grant-idx", mds_layout_grant_hash, mds_layout_grant_compare,
	    mds_layout_grant_mkkey, TRUE);

#ifdef NOT_USED_NOW
	instp->mds_layout_grant_ID_idx =
	    rfs4_index_create(instp->mds_layout_grant_tab,
	    "layout-grant-ID-idx", mds_layout_grant_id_hash,
	    mds_layout_grant_id_compare, mds_layout_grant_id_mkkey, FALSE);
#endif

	/*
	 * Create the ever_grant table.
	 *
	 * This table tracks layouts that have been granted to clients that
	 * belong to an FSID. It is indexed by the FSID and also by client.
	 */
	instp->mds_ever_grant_tab = rfs4_table_create(instp,
	    "Ever_grant", instp->reap_time, 1, mds_ever_grant_create,
	    mds_ever_grant_destroy, NULL,
	    sizeof (mds_ever_grant_t), MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->mds_ever_grant_idx =
	    rfs4_index_create(instp->mds_ever_grant_tab,
	    "ever-grant-idx", mds_ever_grant_hash, mds_ever_grant_compare,
	    mds_ever_grant_mkkey, TRUE);

#ifdef NOT_USED_NOW
	instp->mds_ever_grant_fsid_idx =
	    rfs4_index_create(instp->mds_ever_grant_tab,
	    "ever-grant-fsid-idx", mds_ever_grant_fsid_hash,
	    mds_ever_grant_fsid_compare, mds_ever_grant_fsid_mkkey, FALSE);
#endif

	/*
	 * Data server addresses.
	 */
	instp->ds_addrlist_tab = rfs4_table_create(instp,
	    "DSaddrlist", instp->reap_time, 2, ds_addrlist_create,
	    ds_addrlist_destroy, rfs41_invalid_expiry, sizeof (ds_addrlist_t),
	    MDS_TABSIZE, MDS_MAXTABSZ, 200);

	instp->ds_addrlist_idx = rfs4_index_create(instp->ds_addrlist_tab,
	    "dsaddrlist-idx", ds_addrlist_hash, ds_addrlist_compare,
	    ds_addrlist_mkkey, TRUE);

	instp->ds_addrlist_addrkey_idx =
	    rfs4_index_create(instp->ds_addrlist_tab,
	    "dsaddrlist-addrkey-idx", ds_addrlist_addrkey_hash,
	    ds_addrlist_addrkey_compare, ds_addrlist_addrkey_mkkey, FALSE);

	/*
	 * Multipath Device table.
	 */
	{
		uint32_t	maxentries = MDS_MAXTABSZ;
		id_t		start = 200;

		/*
		 * A mpd might be in use by many layouts. So, when one
		 * layout is done with a mpd, it can not invalidate the
		 * state. Also, as a mpd is created, it is immeadiately
		 * assigned to a layout, and thus the refcnt will stay at
		 * 2. Thus, if the refcnt is ever 1, that means no layout
		 * has a reference and as such, the entry can be reclaimed.
		 */
		instp->mds_mpd_tab = rfs4_table_create(instp,
		    "mpd", instp->reap_time, 1, mds_mpd_create,
		    mds_mpd_destroy, NULL,
		    sizeof (mds_mpd_t), MDS_TABSIZE, maxentries, start);

		instp->mds_mpd_idx = rfs4_index_create(instp->mds_mpd_tab,
		    "mpd-idx", mds_mpd_hash, mds_mpd_compare,
		    mds_mpd_mkkey, TRUE);

		if (MDS_MAXTABSZ + (uint32_t)start > (uint32_t)INT32_MAX)
			maxentries = INT32_MAX - start;

		instp->mds_mpd_id_space =
		    id_space_create("mds_mpd_id_space", start,
		    maxentries + start);
	}

	/*
	 * data-server information tables.
	 */
	instp->ds_owner_tab = rfs4_table_create(instp,
	    "DS_owner", instp->reap_time, 2, ds_owner_create,
	    ds_owner_destroy, mds_do_not_expire,
	    sizeof (ds_owner_t), MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->ds_owner_inst_idx = rfs4_index_create(instp->ds_owner_tab,
	    "DS_owner-inst-idx", mds_str_hash, ds_owner_inst_compare,
	    ds_owner_inst_mkkey, TRUE);

	instp->ds_owner_idx = rfs4_index_create(instp->ds_owner_tab,
	    "DS_owner-idx", ds_owner_hash, ds_owner_compare,
	    ds_owner_mkkey, FALSE);

	/*
	 * data-server guid information table.
	 */
	instp->ds_guid_info_tab = rfs4_table_create(instp,
	    "DS_guid", instp->reap_time, 2, ds_guid_info_create,
	    ds_guid_info_destroy, rfs41_invalid_expiry,
	    sizeof (ds_guid_info_t), MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->ds_guid_info_idx = rfs4_index_create(instp->ds_guid_info_tab,
	    "DS_guid-idx", ds_guid_info_hash, ds_guid_info_compare,
	    ds_guid_info_mkkey, TRUE);

	instp->ds_guid_info_dataset_name_idx =
	    rfs4_index_create(instp->ds_guid_info_tab,
	    "DS_guid-dataset-name-idx", mds_utf8string_hash,
	    ds_guid_info_dataset_name_compare, ds_guid_info_dataset_name_mkkey,
	    FALSE);

	instp->attrvers = 1;

	/*
	 * Mark it as fully initialized
	 */
	instp->inst_flags |= NFS_INST_STORE_INIT | NFS_INST_v41;

	/*
	 * In case we are ever able to re-init the state,
	 * make sure we clean-up the termination!
	 */
	instp->inst_flags &= ~NFS_INST_TERMINUS;

	mutex_exit(&instp->state_lock);
}

/*
 * Module load initialization
 */
void
mds_srvrinit(void)
{
	mds_recall_lo = mds_lorecall_cmd;
	mds_notify_device = mds_notify_device_cmd;
}

void
rfs41_srvrinit(void)
{
	rfs41_dispatch_init();
}

static char *
mds_read_odl(char *path, int *size)
{
	struct uio uio;
	struct iovec iov;

	char *odlp;
	vnode_t *vp;
	vattr_t va;
	int sz, err, bad_file;

	*size = 0;
	if (path == NULL)
		return (NULL);

	/*
	 * open the layout file.
	 */
	if ((err = vn_open(path, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0)) != 0) {
		return (NULL);
	}

	if (vp->v_type != VREG) {
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (NULL);
	}

	(void) VOP_RWLOCK(vp, V_WRITELOCK_FALSE, NULL);

	/*
	 * get the file size.
	 */
	va.va_mask = AT_SIZE;
	err = VOP_GETATTR(vp, &va, 0, CRED(), NULL);

	sz = va.va_size;
	bad_file = (sz == 0 || sz < sizeof (odl_t));

	if (err || bad_file) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		return (NULL);
	}

	odlp = kmem_alloc(sz, KM_SLEEP);

	/*
	 * build iovec to read in the file.
	 */
	iov.iov_base = (caddr_t)odlp;
	iov.iov_len = sz;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_loffset = 0;
	uio.uio_resid = iov.iov_len;

	if (err = VOP_READ(vp, &uio, FREAD, CRED(), NULL)) {
		VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
		(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
		kmem_free(odlp, sz);
		return (NULL);
	}

	VOP_RWUNLOCK(vp, V_WRITELOCK_FALSE, NULL);
	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	*size = sz;

	return (odlp);
}

/*
 * blah
 */
static int
mds_write_odl(char *path, char *odlp, int size)
{
	int ioflag, err;
	struct uio uio;
	struct iovec iov;
	vnode_t *vp;

	if (path == NULL)
		return (-1);

	if (vn_open(path, UIO_SYSSPACE, FCREAT|FWRITE|FTRUNC, 0600, &vp,
	    CRCREAT, 0)) {
		return (-1);
	}

	iov.iov_base = (caddr_t)odlp;
	iov.iov_len = size;

	uio.uio_iov = &iov;
	uio.uio_iovcnt = 1;
	uio.uio_loffset = 0;
	uio.uio_segflg = UIO_SYSSPACE;
	uio.uio_llimit = (rlim64_t)MAXOFFSET_T;
	uio.uio_resid = size;

	ioflag = uio.uio_fmode = (FWRITE|FSYNC);
	uio.uio_extflg = UIO_COPY_DEFAULT;

	(void) VOP_RWLOCK(vp, V_WRITELOCK_TRUE, NULL);
	err = VOP_WRITE(vp, &uio, ioflag, CRED(), NULL);
	VOP_RWUNLOCK(vp, V_WRITELOCK_TRUE, NULL);

	(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);

	return (err);
}

static void
mds_remove_odl(char *path)
{
	(void) vn_remove(path, UIO_SYSSPACE, RMFILE);
}

#define	ODL_DIR	"/var/nfs/v4_state/layouts"

int
mds_mkdir(char *parent, char *dirnm)
{
	int err;
	vnode_t *dvp, *vp;
	struct vattr vap;
	cred_t *cr = CRED();

/*
 *	if (err = lookupname(parent, UIO_SYSSPACE, NO_FOLLOW, NULLVPP, &dvp))
 */
	if ((err = vn_open(parent, UIO_SYSSPACE, FREAD, 0, &dvp, 0, 0)))
		return (1);

	vap.va_mask = AT_UID|AT_GID|AT_TYPE|AT_MODE;
	vap.va_uid = crgetuid(cr);
	vap.va_gid = crgetgid(cr);
	vap.va_type = VDIR;
	vap.va_mode = 0755;
	err = VOP_MKDIR(dvp, dirnm, &vap, &vp, cr, NULL, 0, NULL);

	(void) VOP_CLOSE(dvp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(dvp);

	if (err)
		return (1);

	VN_RELE(vp);

	return (0);
}

/*
 * Pathname will be /var/nfs/v4_state/layouts/<fsid>/<fid>
 */
char *
mds_create_name(vnode_t *vp, int *len)
{
	static int parent_created = 0;
	int plen, err;
	fid_t fid;
	statvfs64_t svfs;
	vnode_t *dvp = NULL;
	uint64_t name = 0;
	char *pname;
	char dir[65];

	*len = 0;
	if (!parent_created) {
		if (vn_open(ODL_DIR, UIO_SYSSPACE, FREAD, 0, &dvp, 0, 0)) {
			err = mds_mkdir("/var/nfs/v4_state", "layouts");
			if (err)
				return (NULL);
		} else {
			(void) VOP_CLOSE(dvp, FREAD, 1, (offset_t)0,
			    CRED(), NULL);
			VN_RELE(dvp);
		}
		parent_created = 1;
	}

	/*
	 * fsid = vp->v_vfsp->vfs_fsid;
	 * zfs changes vfs_fsid on reboot, so we can't use it.
	 */
	err = VFS_STATVFS(vp->v_vfsp, &svfs);
	if (err) {
		return (NULL);
	}

	(void) snprintf(dir, 65, "%llx", (long long)svfs.f_fsid);

	plen = MAXPATHLEN;
	pname = kmem_alloc(plen, KM_SLEEP);
	(void) snprintf(pname, plen, "%s/%s", ODL_DIR, dir);

	/* does this dir already exist */
	if (vn_open(pname, UIO_SYSSPACE, FREAD, 0, &dvp, 0, 0)) {
		err = mds_mkdir(ODL_DIR, dir);
		if (err) {
			kmem_free(pname, plen);
			return (NULL);
		}
	} else {
		(void) VOP_CLOSE(dvp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(dvp);
	}

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	err = VOP_FID(vp, &fid, NULL);
	if (err || fid.fid_len == 0) {
		kmem_free(pname, plen);
		return (NULL);
	}

	bcopy(fid.fid_data, &name, fid.fid_len);

	(void) snprintf(pname, plen, "%s/%s/%llx", ODL_DIR, dir,
	    (long long)name);

	*len = plen;
	return (pname);
}

/* xdr encode a mds_layout to the on-disk layout */
static char *
xdr_convert_layout(mds_layout_t *lp, int *size)
{
	int xdr_size;
	char *xdr_buf;
	XDR xdr;
	odl on_disk;
	odl_t odlt;

	/* otw_flo.nfl_first_stripe_index hard coded to 0 */
	odlt.start_idx = 0;
	odlt.unit_size = lp->mlo_lc.lc_stripe_unit;

	/* offset and length are currently hard coded, as well */
	odlt.offset = 0;
	odlt.length = -1;

	odlt.sid.sid_len = lp->mlo_lc.lc_stripe_count;
	odlt.sid.sid_val = lp->mlo_lc.lc_mds_sids;

	on_disk.odl_type = PNFS;
	on_disk.odl_u.odl_pnfs.odl_vers = VERS_1;
	on_disk.odl_u.odl_pnfs.odl_lo_u.odl_content.odl_content_len = 1;
	on_disk.odl_u.odl_pnfs.odl_lo_u.odl_content.odl_content_val = &odlt;

	xdr_size = xdr_sizeof(xdr_odl, (char *)&on_disk);
	xdr_buf = kmem_zalloc(xdr_size, KM_SLEEP);

	xdrmem_create(&xdr, xdr_buf, xdr_size, XDR_ENCODE);

	if (xdr_odl(&xdr, &on_disk) == FALSE) {
		*size = 0;
		kmem_free(xdr_buf, xdr_size);
		return (NULL);
	}

	*size = xdr_size;
	return (xdr_buf);
}

/* xdr decode an on-disk layout to an odl struct */
/*ARGSUSED*/
static odl *
xdr_convert_odl(char *odlp, int size)
{
	int sz;
	char *unxdr_buf;
	XDR xdr;

	sz = sizeof (odl);
	unxdr_buf = kmem_zalloc(sz, KM_SLEEP);

	xdrmem_create(&xdr, odlp, size, XDR_DECODE);

	if (xdr_odl(&xdr, (odl *)unxdr_buf) == FALSE) {
		kmem_free(unxdr_buf, sz);
		return (NULL);
	}

	return ((odl *)unxdr_buf);
}

int
odl_already_written(char *name)
{
	vnode_t	*vp;

	ASSERT(name != NULL);

	if (vn_open(name, UIO_SYSSPACE, FREAD, 0, &vp, 0, 0))
		return (0);	/* does not exist */

	(void) VOP_CLOSE(vp, FREAD, 1, (offset_t)0, CRED(), NULL);
	VN_RELE(vp);
	return (1);	/* has already been written */
}

int
mds_put_layout(mds_layout_t *lp, vnode_t *vp)
{
	char *odlp;
	char *name;
	int len, size, err;

	if (lp == NULL) {
		return (-2);
	}

	name = mds_create_name(vp, &len);
	if (name == NULL) {
		return (-1);
	}

	if (odl_already_written(name)) {
		kmem_free(name, len);
		return (0);
	}

	/* mythical xdr encode routine */
	odlp = xdr_convert_layout(lp, &size);
	if (odlp == NULL) {
		kmem_free(name, len);
		return (-1);
	}

	err = mds_write_odl(name, odlp, size);

	kmem_free(name, len);
	kmem_free(odlp, size);

	return (err);
}

int
mds_get_odl(vnode_t *vp, mds_layout_t **plp)
{
	char	*odlp;
	int	len, size;
	int	i;
	char	*name;

	mds_layout_t	*lp;
	layout_core_t	lc;

	odl	*on_disk;
	odl_t	*odlt;

	ASSERT(plp != NULL);

	name = mds_create_name(vp, &len);
	if (name == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

	odlp = mds_read_odl(name, &size);
	if (odlp == NULL) {
		kmem_free(name, len);
		return (NFS4ERR_LAYOUTTRYLATER);
	}

	/* the magic xdr decode routine */
	on_disk = xdr_convert_odl(odlp, size);

	kmem_free(name, len);
	kmem_free(odlp, size);

	if (on_disk == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

	odlt = on_disk->odl_u.odl_pnfs.odl_lo_u.odl_content.odl_content_val;

	lc.lc_stripe_unit = odlt->unit_size;
	lc.lc_stripe_count = odlt->sid.sid_len;
	lc.lc_mds_sids = odlt->sid.sid_val;

	lp = mds_add_layout(&lc);

	/* these were allocated by the xdr decode process */

	for (i = 0; i < odlt->sid.sid_len; i++) {
		kmem_free(odlt->sid.sid_val[i].val, odlt->sid.sid_val[i].len);
	}

	kmem_free(odlt->sid.sid_val, (odlt->sid.sid_len * sizeof (mds_sid)));
	kmem_free(odlt, sizeof (odl_t));
	kmem_free(on_disk, sizeof (odl));

	if (lp == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

	*plp = lp;

	return (NFS4_OK);
}

void
mds_delete_layout(vnode_t *vp)
{
	int len;
	char *name;

	name = mds_create_name(vp, &len);
	if (name == NULL) {
		return;
	}

	mds_remove_odl(name);

	kmem_free(name, len);
}
