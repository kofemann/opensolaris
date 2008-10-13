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

extern u_longlong_t nfs4_srv_caller_id;

#include <nfs/nfs_sstor_impl.h>
#include <nfs/mds_state.h>
#include <nfs/nfs41_sessions.h>

#include <nfs/rfs41_ds.h>
#include <nfs/nfs41_filehandle.h>

static void mds_do_lorecall(mds_lorec_t *);
static void mds_sess_lorecall_callout(rfs4_entry_t, void *);
static int  mds_lorecall_cmd(struct mds_reclo_args *, cred_t *);

extern void mds_do_cb_recall(struct rfs4_deleg_state *, bool_t);


/*
 * XXX - slrc_slot_size will more than likely have to be
 *	 computed dynamically as the server adjusts the
 *	 sessions' slot replay cache size. This should be
 *	 good for proto.
 */
slotid4 slrc_slot_size = MAXSLOTS;

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

extern int (*mds_recall_lo)(struct mds_reclo_args *, cred_t *);

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
	id.v41_bits.chgseq = 1;
	id.v41_bits.type = id_type;
	id.v41_bits.pid = 0;

	return (id);
}


rfs4_openowner_t *
mds_findopenowner(nfs_server_instance_t *instp, open_owner4 *openowner,
    bool_t *create)
{
	rfs4_openowner_t *op;
	rfs4_openowner_t arg;

	arg.owner = *openowner;
	arg.open_seqid = 0;
	op = (rfs4_openowner_t *)rfs4_dbsearch(instp->openowner_idx,
	    openowner, create, &arg, RFS4_DBS_VALID);
	return (op);
}

rfs4_lo_state_t *
mds_findlo_state_by_owner(rfs4_lockowner_t *lo,
			rfs4_state_t *sp, bool_t *create)
{
	rfs4_lo_state_t *lsp;
	rfs4_lo_state_t arg;
	nfs_server_instance_t *instp;

	arg.locker = lo;
	arg.state = sp;

	instp = dbe_to_instp(lo->dbe);

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(instp->lo_state_owner_idx,
	    &arg, create, &arg, RFS4_DBS_VALID);

	return (lsp);
}

/* well clearly this needs to be cleaned up.. */
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

	if (rfs4_lease_expired(sp->owner->client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (sp->stateid.v41_bits.chgseq < id->v41_bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (sp->closed == TRUE)
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

	fhp =
	    (nfs41_fh_fmt_t *)lsp->state->finfo->filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_state_close(lsp->state, FALSE, FALSE, CRED());
		rfs4_dbe_invalidate(lsp->dbe);
		rfs4_dbe_invalidate(lsp->state->dbe);
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
	    (nfs41_fh_fmt_t *)sp->finfo->filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_state_close(sp, TRUE, FALSE, CRED());
		rfs4_dbe_invalidate(sp->dbe);
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
	    (nfs41_fh_fmt_t *)dsp->finfo->filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp)) {
		rfs4_dbe_invalidate(dsp->dbe);
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

	fhp = (nfs41_fh_fmt_t *)fp->filehandle.nfs_fh4_val;

	if (mds_fh_is_exi(exi, fhp) == 0)
		return;

	if ((vp = fp->vp) != NULL) {

		instp = dbe_to_instp(fp->dbe);
		ASSERT(instp);
		/*
		 * don't leak monitors and remove the reference
		 * put on the vnode when the delegation was granted.
		 */
		if (fp->dinfo->dtype == OPEN_DELEGATE_READ) {
			(void) fem_uninstall(vp, instp->deleg_rdops,
			    (void *)fp);
			vn_open_downgrade(vp, FREAD);
		} else if (fp->dinfo->dtype == OPEN_DELEGATE_WRITE) {
			(void) fem_uninstall(vp, instp->deleg_wrops,
			    (void *)fp);
			vn_open_downgrade(vp, FREAD|FWRITE);
		}
		mutex_enter(&vp->v_lock);
		(void) vsd_set(vp, instp->vkey, NULL);
		mutex_exit(&vp->v_lock);
		VN_RELE(vp);
		fp->vp = NULL;
	}
	rfs4_dbe_invalidate(fp->dbe);
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
	mds_session_t *sessp = (mds_session_t *)entry;
	clientid4 *idp = key;

	return (*idp == sessp->sn_clnt->clientid);
}

static void *
sess_clid_mkkey(rfs4_entry_t entry)
{
	return (&(((mds_session_t *)entry)->sn_clnt->clientid));
}

void
rfs41_session_rele(mds_session_t *sp)
{
	rfs4_dbe_rele(sp->dbe);
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
	ASSERT(rfs4_dbe_islocked(sp->dbe));
	rfs4_dbe_invalidate(sp->dbe);

	if (SN_CB_CHAN_EST(sp)) {
		sess_channel_t	*bcp = sp->sn_back;
		sess_bcsd_t	*bsdp;

		rw_enter(&bcp->cn_lock, RW_READER);
		if ((bsdp = CTOBSD(bcp)) == NULL)
			cmn_err(CE_PANIC, "mds_session_inval: BCSD Not Set");

		mutex_enter(&bsdp->bsd_lock);
		status = bsdp->bsd_stat = slot_cb_status(bsdp->bsd_stok);
		mutex_exit(&bsdp->bsd_lock);

		rw_exit(&bcp->cn_lock);
	} else {
		cmn_err(CE_NOTE, "No back chan established");
		status = NFS4_OK;
	}
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

	rfs4_dbe_lock(sp->dbe);
	cbs = mds_session_inval(sp);
	rfs4_dbe_unlock(sp->dbe);

	/*
	 * XXX - Destruction of a session should not affect any state
	 *	 bound to the clientid (Section 18.37.3 of draft-17).
	 *	 For now, keep destroying the clid until DESTROY_CLIENTID
	 *	 is explicitly done (see Section 18.50.4 of draft-17).
	 * The client struct will expire and the session no longer keeps
	 * a hold on the client struct, so an explicit call to client close
	 * is not needed.
	 */
	if (cbs == NFS4_OK) {
		rfs41_session_rele(sp);
	}
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
	atomic_add_32(&dsp->rs.refcnt, 1);
}

void
rfs41_deleg_rs_rele(rfs4_deleg_state_t *dsp)
{
	ASSERT(dsp->rs.refcnt > 0);
	atomic_add_32(&dsp->rs.refcnt, -1);
	if (dsp->rs.refcnt == 0) {
		bzero(dsp->rs.sessid, sizeof (sessionid4));
		dsp->rs.seqid = dsp->rs.slotno = 0;
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
		mutex_init(&bp->bsd_lock, NULL, MUTEX_DEFAULT, NULL);
		rw_init(&bp->bsd_rwlock, NULL, RW_DEFAULT, NULL);
		cp->cn_csd = (sess_bcsd_t *)bp;
		break;
	}
	return (cp);
}

void
rfs41_destroy_session_channel(sess_channel_t *cp)
{
	sess_bcsd_t	*bp;

	if (cp == NULL)
		return;

	switch (cp->cn_dir) {
	case CDFS4_FORE:
		break;

	case CDFS4_BOTH:
	case CDFS4_BACK:
		bp = (sess_bcsd_t *)cp->cn_csd;
		rw_destroy(&bp->bsd_rwlock);
		mutex_destroy(&bp->bsd_lock);
		kmem_free(bp, sizeof (sess_bcsd_t));
		break;
	}
	rw_destroy(&cp->cn_lock);
	kmem_free(cp, sizeof (sess_channel_t));
}

/*
 * Create/Initialize the session for this rfs4_client_t. Also
 * create its slot replay cache as per the server's resource
 * constraints.
 */
/* ARGSUSED */
static bool_t
mds_session_create(rfs4_entry_t u_entry,
		void *arg)
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
	nfs_server_instance_t *instp;

	ASSERT(sp != NULL);
	if (sp == NULL)
		return (FALSE);

	instp = dbe_to_instp(sp->dbe);

	/*
	 * Back pointer to rfs4_client_t and sessionid
	 */
	sp->sn_clnt = (rfs4_client_t *)ap->cs_client;
	mxprt = (SVCMASTERXPRT *)ap->cs_xprt->xp_master;

	/*
	 * Handcrafting the session id
	 */
	sidp = (sid *)&sp->sn_sessid;
	sidp->impl_id.pad0 = 0x00000000;
	sidp->impl_id.pad1 = 0xFFFFFFFF;
	sidp->impl_id.start_time = instp->start_time;
	sidp->impl_id.s_id = (uint32_t)rfs4_dbe_getid(sp->dbe);

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

		if (SVC_CTL(ap->cs_xprt, SVCCTL_SET_CBCONN, (void *)&cbargs)) {
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
	 * XXX: Let's not worry about channel attribute enforcement now.
	 *	This should occur as part of the COMPOUND processing (in
	 *	the dispatch routine); not on channel creation.
	 */
	ocp->cn_attrs = ap->cs_aotw.csa_fore_chan_attrs;
	if (ocp->cn_attrs.ca_maxrequests > slrc_slot_size)
		ocp->cn_attrs.ca_maxrequests = slrc_slot_size;

	/*
	 * No need for locks/synchronization at this time,
	 * since we're barely creating the session.
	 */
	if (sp->sn_bdrpc) {
		ocp->cn_attrs = ap->cs_aotw.csa_back_chan_attrs;

		/*
		 * bcsd got built as part of the channel's construction.
		 */
		if ((bsdp = CTOBSD(ocp)) == NULL) {
			cmn_err(CE_PANIC, "Back Chan Spec Data Not Set\t"
			    "<Internal Inconsistency>");
		}
		bsdp->bsd_stok = sltab_create(slrc_slot_size);	/* bdrpc */
		sp->sn_csflags |= CREATE_SESSION4_FLAG_CONN_BACK_CHAN;
		sp->sn_back = ocp;

	} else {
		/*
		 * If not doing bdrpc, then we expect the client to perform
		 * an explicit BIND_CONN_TO_SESSION if it wants callback
		 * traffic. Subsequently, the cb channel should be set up
		 * at that point along with its corresponding sltab (see
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

	SVC_CTL(ap->cs_xprt, SVCCTL_SET_TAG, (void *)sp->sn_sessid);

	if (sp->sn_bdrpc) {
		atomic_add_32(&sp->sn_bc.pngcnt, 1);
	}

	/*
	 * Now we allocate space for the slrc, initializing each slot's
	 * sequenceid and slotid to zero and a (pre)cached result of
	 * NFS4ERR_SEQ_MISORDERED. Note that we zero out the entries
	 * by virtue of the z-alloc.
	 */
	sp->sn_slrc =
	    (rfs41_slrc_t *)kmem_zalloc(sizeof (rfs41_slrc_t), KM_SLEEP);
	sp->sn_slrc->sc_maxslot = ocp->cn_attrs.ca_maxrequests;

	for (i = 0; i < sp->sn_slrc->sc_maxslot; i++) {
		sp->sn_slrc->sc_slot[i].status = NFS4ERR_SEQ_MISORDERED;
		sp->sn_slrc->sc_slot[i].res.status = NFS4ERR_SEQ_MISORDERED;
		sp->sn_slrc->sc_slot[i].p = NULL;
	}

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
		rfs41_seq4_hold(&sp->sn_clnt->seq4, SEQ4_STATUS_CB_PATH_DOWN);
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
		sltab_destroy(bsdp->bsd_stok);

	/*
	 * XXX - A session can have multiple BC clnt handles that need
	 *	 to be discarded. mds_session_inval calls CLNT_DESTROY
	 *	 which will remove the CB client handle from the global
	 *	 list (cb_clnt_list) now. This will have to change once
	 *	 we manage the BC clnt handles per session.
	 */

	/*
	 * Remove the fore and back channels; we still
	 * need to drop all associated connections. (XXX)
	 */
	rfs41_destroy_session_channel(sp->sn_fore);
	if (!sp->sn_bdrpc)
		rfs41_destroy_session_channel(sp->sn_back);

	/*
	 * Nuke slot replay cache for this session
	 */
	kmem_free(sp->sn_slrc, sizeof (rfs41_slrc_t));
}

static bool_t
mds_session_expiry(rfs4_entry_t u_entry)
{
	mds_session_t	*sp = (mds_session_t *)u_entry;

	if (sp == NULL || rfs4_dbe_is_invalid(sp->dbe))
		return (TRUE);

	return (FALSE);
}

void
mds_kill_session_callout(rfs4_entry_t u_entry, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)arg;
	mds_session_t *sp = (mds_session_t *)u_entry;

	if (sp->sn_clnt == cp && !(rfs4_dbe_is_invalid(sp->dbe)))
		mds_session_destroy(u_entry);
}

void
mds_clean_up_sessions(rfs4_client_t *cp)
{
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(cp->dbe);

	if (instp->mds_session_tab != NULL)
		rfs4_dbe_walk(instp->mds_session_tab,
		    mds_kill_session_callout, cp);
}


/*
 * -----------------------------------------------
 * MDS: Layout tables.
 * -----------------------------------------------
 *
 */
static uint32_t
mds_layout_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

static bool_t
mds_layout_compare(rfs4_entry_t entry, void *key)
{
	mds_layout_t *lp = (mds_layout_t *)entry;

	return (lp->layout_id == (int)(uintptr_t)key);
}

static void *
mds_layout_mkkey(rfs4_entry_t entry)
{
	mds_layout_t *lp = (mds_layout_t *)entry;

	return ((void *)(uintptr_t)lp->layout_id);
}

struct mds_gather_args {
	struct mds_addlo_args lo_arg;
	uint32_t	dev_id;
	ds_addrlist_t 	*dev_ptr[100];
	int 		max_devs_needed;
	int 		dex;
};

typedef struct {
	uint32_t id;
	nfsv4_1_file_layout_ds_addr4 *ds_addr4;
} mds_addmpd_t;

/*
 * XXX:
 *
 * this of course should trigger a recall of the
 * associated layouts for the mpd.
 */
void
mds_nuke_mpd(nfs_server_instance_t *instp, uint32_t mpd_id)
{
	bool_t create = FALSE;
	rfs4_entry_t e;

	rw_enter(&instp->mds_mpd_lock, RW_WRITER);
	if ((e = rfs4_dbsearch(instp->mds_mpd_idx, (void *)(uintptr_t)mpd_id,
	    &create, NULL, RFS4_DBS_VALID)) != NULL) {
		rfs4_dbe_invalidate(e->dbe);
	}
	rw_exit(&instp->mds_mpd_lock);
}

void
mds_gather_devs(rfs4_entry_t entry, void *arg)
{
	ds_addrlist_t	*dp = (ds_addrlist_t *)entry;
	struct mds_gather_args *gap = (struct mds_gather_args *)arg;

	if (rfs4_dbe_skip_or_invalid(dp->dbe))
		return;

	if (gap->dex < gap->max_devs_needed) {
		gap->lo_arg.lo_devs[gap->dex] = rfs4_dbe_getid(dp->dbe);
		gap->dev_ptr[gap->dex] = dp;
		gap->dex++;
	}
}

/*
 */
mds_mpd_t *
mds_gen_mpd(nfs_server_instance_t *instp, struct mds_gather_args *args)
{
	nfsv4_1_file_layout_ds_addr4 ds_dev;

	mds_addmpd_t map = { .id = 0, .ds_addr4 = &ds_dev };
	mds_mpd_t *mp;
	uint_t len;
	int ii;
	uint32_t *sivp;
	multipath_list4 *mplp;

	/*
	 * build a nfsv4_1_file_layout_ds_addr4, encode it and
	 * cache it in state_store.
	 */
	len = args->dex;

	/* allocate space for the indices */
	sivp = ds_dev.nflda_stripe_indices.nflda_stripe_indices_val =
	    kmem_zalloc(len * sizeof (uint32_t), KM_SLEEP);

	ds_dev.nflda_stripe_indices.nflda_stripe_indices_len = len;

	/* populate the stripe indices */
	for (ii = 0; ii < len; ii++)
		sivp[ii] = ii;

	/*
	 * allocate space for the multipath_list4 (for now we just
	 * have the one path)
	 */
	mplp = ds_dev.nflda_multipath_ds_list.nflda_multipath_ds_list_val =
	    kmem_zalloc(len * sizeof (multipath_list4), KM_SLEEP);

	ds_dev.nflda_multipath_ds_list.nflda_multipath_ds_list_len = len;

	/*
	 * Now populate the netaddrs using the stashed ds_addr
	 * pointers
	 */
	for (ii = 0; ii < len; ii++) {
		ds_addrlist_t *dp;

		mplp[ii].multipath_list4_len = 1;
		dp = args->dev_ptr[ii];
		mplp[ii].multipath_list4_val = &dp->dev_addr;
	}

	/*
	 * Add the multipath_list4, this will encode and cache
	 * the result.
	 */
	rw_enter(&instp->mds_mpd_lock, RW_WRITER);
	mp = (mds_mpd_t *)rfs4_dbcreate(instp->mds_mpd_idx, (void *)&map);
	rw_exit(&instp->mds_mpd_lock);

	/* now clean up after yourself dear boy */
	kmem_free(mplp, len * sizeof (multipath_list4));
	kmem_free(sivp, len * sizeof (uint32_t));
	return (mp);
}

int mds_default_stripe = 32;
int mds_max_lo_devs = 20;

mds_layout_t *
mds_gen_default_layout(nfs_server_instance_t *instp, int max_devs_needed)
{
	struct mds_gather_args args;
	mds_layout_t *lop;

	bzero(&args, sizeof (args));

	args.max_devs_needed = MIN(max_devs_needed,
	    MIN(mds_max_lo_devs, 99));

	rw_enter(&instp->ds_addrlist_lock, RW_READER);
	rfs4_dbe_walk(instp->ds_addrlist_tab, mds_gather_devs, &args);
	rw_exit(&instp->ds_addrlist_lock);

	/*
	 * if we didn't find any devices then we do no service
	 */
	if (args.dex == 0)
		return (NULL);

	args.lo_arg.loid = 1;
	args.lo_arg.lo_stripe_unit = mds_default_stripe * 1024;

	rw_enter(&instp->mds_layout_lock, RW_WRITER);
	lop = (mds_layout_t *)rfs4_dbcreate(instp->mds_layout_idx,
	    (void *)&args);
	rw_exit(&instp->mds_layout_lock);

	return (lop);
}

void
mds_nuke_layout(nfs_server_instance_t *instp, uint32_t layout_id)
{
	bool_t create = FALSE;
	rfs4_entry_t e;

	rw_enter(&instp->mds_layout_lock, RW_WRITER);
	if ((e = rfs4_dbsearch(instp->mds_layout_idx,
	    (void *)(uintptr_t)layout_id,
	    &create,
	    NULL,
	    RFS4_DBS_VALID)) != NULL) {
		rfs4_dbe_invalidate(e->dbe);
	}
	rw_exit(&instp->mds_layout_lock);
}

/*ARGSUSED*/
static bool_t
mds_layout_create(rfs4_entry_t u_entry, void *arg)
{
	mds_layout_t *lp = (mds_layout_t *)u_entry;
	mds_mpd_t *mp;
	ds_addrlist_t *dp;
	struct mds_gather_args *gap = (struct mds_gather_args *)arg;
	struct mds_addlo_args *alop = &gap->lo_arg;

	nfs_server_instance_t *instp;
	int i;


	if (alop->loid == 0)
		lp->layout_id = rfs4_dbe_getid(lp->dbe);
	else
		lp->layout_id = alop->loid;

	instp = dbe_to_instp(lp->dbe);

	lp->layout_type = LAYOUT4_NFSV4_1_FILES;
	lp->stripe_unit = alop->lo_stripe_unit;

	for (i = 0; alop->lo_devs[i] && i < 100; i++) {
		lp->devs[i] = alop->lo_devs[i];
		dp = mds_find_ds_addrlist(instp, alop->lo_devs[i]);
		/* lets hope this doesn't occur */
		if (dp == NULL)
			return (FALSE);
		gap->dev_ptr[i] = dp;
	}

	lp->stripe_count = i;

	/* Need to generate a device for this layout */
	mp = mds_gen_mpd(instp, gap);

	/* save the dev_id save the world */
	lp->dev_id = mp->mpd_id;

	return (TRUE);
}

/*ARGSUSED*/
static void
mds_layout_destroy(rfs4_entry_t bugger)
{
}

void
mds_add_layout(struct mds_addlo_args *lop)
{
	bool_t create = FALSE;
	rfs4_entry_t e;

	rw_enter(&mds_server->mds_layout_lock, RW_WRITER);

	if ((e = rfs4_dbsearch(mds_server->mds_layout_idx,
	    (void *)(uintptr_t)lop->loid,
	    &create,
	    NULL,
	    RFS4_DBS_VALID)) != NULL) {
		/*
		 * Must have already existed, so invalidate
		 * the entry in order to create a new one.
		 */
		rfs4_dbe_invalidate(e->dbe);
	}

	if (rfs4_dbcreate(mds_server->mds_layout_idx, (void *)lop) == NULL) {
		printf("mds_add_layout: failed\n");
		(void) set_errno(EFAULT);
	}
	rw_exit(&mds_server->mds_layout_lock);
	return;

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
	mds_layout_grant_t *lgp = (mds_layout_grant_t *)key;

	return (ADDRHASH(lgp->cp) ^ ADDRHASH(lgp->fp));
}

static bool_t
mds_layout_grant_compare(rfs4_entry_t u_entry, void *key)
{
	mds_layout_grant_t *lgp = (mds_layout_grant_t *)u_entry;
	mds_layout_grant_t *klgp = (mds_layout_grant_t *)key;

	return (lgp->cp == klgp->cp && lgp->fp == klgp->fp);
}

static void *
mds_layout_grant_mkkey(rfs4_entry_t entry)
{
	return (entry);
}

static uint32_t
mds_layout_grant_id_hash(void *key)
{
	stateid_t *id = (stateid_t *)key;

	return (id->v41_bits.state_ident);
}

static bool_t
mds_layout_grant_id_compare(rfs4_entry_t entry, void *key)
{
	mds_layout_grant_t *lgp = (mds_layout_grant_t *)entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	if (id->v41_bits.type != LAYOUTID)
		return (FALSE);

	rc = (lgp->lo_stateid.v41_bits.boottime == id->v41_bits.boottime &&
	    lgp->lo_stateid.v41_bits.state_ident == id->v41_bits.state_ident);

	return (rc);
}

static void *
mds_layout_grant_id_mkkey(rfs4_entry_t entry)
{
	mds_layout_grant_t *lgp = (mds_layout_grant_t *)entry;

	return (&lgp->lo_stateid);
}

struct mds_grant_args {
	mds_layout_t *lop;
};


/*ARGSUSED*/
static bool_t
mds_layout_grant_create(rfs4_entry_t u_entry, void *arg)
{
	mds_layout_grant_t *lgp = (mds_layout_grant_t *)u_entry;
	rfs4_file_t *fp = ((mds_layout_grant_t *)arg)->fp;
	rfs4_client_t *cp = ((mds_layout_grant_t *)arg)->cp;

	rfs4_dbe_hold(fp->dbe);
	rfs4_dbe_hold(cp->dbe);

	lgp->lo_stateid = mds_create_stateid(lgp->dbe, LAYOUTID);
	lgp->fp = fp;
	lgp->cp = cp;

	/* Init layout grant lists for remque/insque */
	lgp->lo_grant_list.next = lgp->lo_grant_list.prev =
	    &lgp->lo_grant_list;
	lgp->lo_grant_list.lgp = lgp;

	lgp->clientgrantlist.next = lgp->clientgrantlist.prev =
	    &lgp->clientgrantlist;
	lgp->clientgrantlist.lgp = lgp;

	/* Insert the grant on the client's list */
	rfs4_dbe_lock(cp->dbe);
	insque(&lgp->clientgrantlist, cp->clientgrantlist.prev);
	rfs4_dbe_unlock(cp->dbe);

	/* Insert the grant on the file's list */
	rfs4_dbe_lock(fp->dbe);
	insque(&lgp->lo_grant_list, fp->lo_grant_list.prev);
	rfs4_dbe_unlock(fp->dbe);

	return (TRUE);
}

/*ARGSUSED*/
static void
mds_layout_grant_destroy(rfs4_entry_t foo)
{
}

mds_layout_grant_t *
rfs41_findlogrant(struct compound_state *cs, rfs4_file_t *fp,
    rfs4_client_t *cp, bool_t *create)
{
	mds_layout_grant_t lg, *lgp;

	lg.cp = cp;
	lg.fp = fp;

	lgp = (mds_layout_grant_t *)rfs4_dbsearch(
	    cs->instp->mds_layout_grant_idx, &lg, create, &lg, RFS4_DBS_VALID);

	return (lgp);
}

void
rfs41_lo_grant_rele(mds_layout_grant_t *lpg)
{
	rfs4_dbe_rele(lpg->dbe);
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

	DTRACE_PROBE1(nfssrv__i__sess_lorecall_fh, mds_lorec_t *, lorec);

	if (lorec->lor_sess == NULL)
		return;
	sp = lorec->lor_sess;

	/*
	 * XXX - until we fix blasting _all_ sessions for one lorecall,
	 *	make sure that the session in question at least has the
	 *	back chan established.
	 */
	if (!SN_CB_CHAN_EST(sp))
		return;

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
	timeout.tv_sec =
	    (dbe_to_instp(lorec->lor_sess->dbe)->lease_period * 80) / 100;
	timeout.tv_usec = 0;

	ch = rfs41_cb_getch(sp);
	(void) CLNT_CONTROL(ch, CLSET_XID, (char *)&zilch);
	call_stat = clnt_call(ch, CB_COMPOUND,
	    xdr_CB_COMPOUND4args_srv, (caddr_t)&cb4_args,
	    xdr_CB_COMPOUND4res, (caddr_t)&cb4_res, timeout);
	rfs41_cb_freech(sp, ch);

	if (call_stat != RPC_SUCCESS) {
		/*
		 * XXX same checks as cb_recall;
		 * a) do we want to retry ?
		 * b) how can we tell layout still "delegated"
		 * c) how much time do we wait before cb_path_down ?
		 *    lease period ?
		 */
		cmn_err(CE_NOTE, "r41_lo_recall: RPC call failed");
		goto done;

	} else if (cb4_res.status != NFS4_OK) {
		/*
		 * XXX check protocol errors. This may be where we
		 *	detect the LAYOUTRECALL / LAYOUTRETURN race
		 */
		cmn_err(CE_NOTE, "r41_lo_recall: status != NFS4_OK");

	}
	svc_slot_cb_seqid(&cb4_res, p);
done:
	kmem_free(lorec, sizeof (mds_lorec_t));
	svc_slot_free(sp, p);
}

static void
mds_sess_lorecall_callout(rfs4_entry_t u_entry, void *arg)
{
	mds_lorec_t *lorec;

	lorec = kmem_alloc(sizeof (mds_lorec_t), KM_SLEEP);
	bcopy(arg, lorec, sizeof (mds_lorec_t));
	lorec->lor_sess = (mds_session_t *)u_entry;

	(void) thread_create(NULL, 0, mds_do_lorecall, lorec, 0, &p0,
	    TS_RUN, minclsyspri);
}

void
inst_lorecall(nfs_server_instance_t *instp, void *args)
{
	if (instp->mds_session_tab != NULL)
		rfs4_dbe_walk(instp->mds_session_tab,
		    mds_sess_lorecall_callout, args);
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
	int error;
	nfs_fh4 fh4;
	struct exportinfo *exi;
	mds_lorec_t lorec;
	vnode_t *vp = NULL, *dvp = NULL;

	/*
	 * XXX - This code works for only one clientid. The code
	 *	blasts layout recalls to all sessions in the dbe
	 *	database. We either need to keep an outstanding
	 *	layout list per clientid or have some way to find
	 *	per-FSID and per-CLIENT layouts efficiently.
	 */
	if ((args->lo_type != LAYOUTRECALL4_FILE) &&
	    (args->lo_type != LAYOUTRECALL4_FSID) &&
	    (args->lo_type != LAYOUTRECALL4_ALL)) {
		return (EINVAL);
	}
	lorec.lor_type = args->lo_type;

	if (lorec.lor_type == LAYOUTRECALL4_ALL) {
		nsi_walk(inst_lorecall, &lorec);
		return (0);
	}
	error = lookupname(args->lo_fname, UIO_SYSSPACE, FOLLOW, &dvp, &vp);
	if (!error && vp == NULL) {
		/*
		 * Last component of fname not found
		 */
		if (dvp != NULL)
			VN_RELE(dvp);
		error = ENOENT;
	}
	if (error)
		return (error);

	/*
	 * 'vp' may be an AUTOFS node, so we perform a
	 * VOP_ACCESS() to trigger the mount of the
	 * intended filesystem, so we can share the intended
	 * filesystem instead of the AUTOFS filesystem.
	 */
	(void) VOP_ACCESS(vp, 0, 0, cr, NULL);

	/*
	 * We're interested in the top most filesystem.
	 * This is specially important when uap->dname is a trigger
	 * AUTOFS node, since we're really interested in sharing the
	 * filesystem AUTOFS mounted as result of the VOP_ACCESS()
	 * call not the AUTOFS node itself.
	 */
	if (vn_mountedvfs(vp) != NULL) {
		if (error = traverse(&vp))
			goto errout;
	}

	/*
	 * The last arg for nfs_vptoexi says to create a v4 FH (instead of v3).
	 * This will need to be changed to select the new MDS FH format.
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

	/*
	 * JFB (just for bakeoff): simply push layout recall
	 * to the back chan of every session.  The "real" code
	 * will first find the rfs4_file_t using the FH created
	 * above, and the file struct will refer to the layout.
	 * Either the layout struct will contain a list of
	 * rfs4_client_t structs granted the layout or another
	 * table/index will be created exist to associate a
	 * layout with the set of clients granted the layout.
	 */
	if (!error)
		nsi_walk(inst_lorecall, &lorec);
errout:
	VN_RELE(vp);
	if (dvp != NULL)
		VN_RELE(dvp);
	return (error);
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
ds_addrlist_compare(rfs4_entry_t entry, void *key)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;

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

	dp->dev_addr.na_r_netid = u_dp->dev_netid;
	dp->dev_addr.na_r_addr = u_dp->dev_addr;
	dp->ds_owner = NULL;
	dp->dev_knc = NULL;
	dp->dev_nb = NULL;
	return (TRUE);
}


/*ARGSUSED*/
static void
ds_addrlist_destroy(rfs4_entry_t foo)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)foo;

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
mds_mpd_compare(rfs4_entry_t entry, void *key)
{
	mds_mpd_t *dp = (mds_mpd_t *)entry;

	return (dp->mpd_id == (uint32_t)(uintptr_t)key);
}

static void *
mds_mpd_mkkey(rfs4_entry_t entry)
{
	mds_mpd_t *dp = (mds_mpd_t *)entry;

	return ((void*)(uintptr_t)dp->mpd_id);
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
		/* don't leak ! */
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
	mds_mpd_t *dp = (mds_mpd_t *)u_entry;
	mds_addmpd_t *maap = (mds_addmpd_t *)arg;

	dp->mpd_id = maap->id;
	mds_mpd_encode(maap->ds_addr4, &(dp->mpd_encoded_len),
	    &(dp->mpd_encoded_val));

	return (TRUE);
}


/*ARGSUSED*/
static void
mds_mpd_destroy(rfs4_entry_t foo)
{
}

/*
 * The OTW device id is 128bits in length, we however are
 * still using a uint_32 internally.
 */
mds_mpd_t *
mds_find_mpd(nfs_server_instance_t *instp, uint32_t id)
{
	mds_mpd_t *dp;
	bool_t create = FALSE;

	dp = (mds_mpd_t *)rfs4_dbsearch(instp->mds_mpd_idx,
	    (void *)(uintptr_t)id, &create, NULL, RFS4_DBS_VALID);
	return (dp);
}

/*
 * Plop a uint32 into the 128bit OTW deviceid
 */
void
mds_set_deviceid(uint32_t did, deviceid4 *otw_id)
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
	mds_mpd_t	*dp = (mds_mpd_t *)entry;
	mds_device_list_t *mdl = (mds_device_list_t *)arg;

	deviceid4   *dlip;

	/*
	 * If this entry is invalid or we should skip it
	 * go to the next one..
	 */
	if (rfs4_dbe_skip_or_invalid(dp->dbe))
		return;

	dlip = &(mdl->dl[mdl->count]);

	mds_set_deviceid(dp->mpd_id, dlip);

	/*
	 * bump to the next devlist_item4
	 */
	mdl->count++;
}

ds_addrlist_t *
mds_find_ds_addrlist_by_uaddr(nfs_server_instance_t *instp, char *ptr)
{
	ds_addrlist_t *dp;
	bool_t create = FALSE;

	dp = (ds_addrlist_t *)rfs4_dbsearch(instp->ds_addrlist_uaddr_idx,
	    (void *)ptr, &create, NULL, RFS4_DBS_VALID);
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


static void *
ds_addrlist_uaddr_mkkey(rfs4_entry_t entry)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;

	return (dp->dev_addr.na_r_addr);
}

static int
ds_addrlist_uaddr_compare(rfs4_entry_t entry, void *key)
{
	ds_addrlist_t *dp = (ds_addrlist_t *)entry;
	char *addr_key = (char *)key;

	return (strcmp(addr_key, dp->dev_addr.na_r_addr) == 0);
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

		dst->ds_attr_val[i].attrname.utf8string_val =
		    kmem_alloc(dst->ds_attr_val[i].attrname.utf8string_len,
		    KM_SLEEP);

		bcopy(src->attrname.utf8string_val,
		    dst->ds_attr_val[i].attrname.utf8string_val,
		    dst->ds_attr_val[i].attrname.utf8string_len);

		len = dst->ds_attr_val[i].attrvalue.attrvalue_len =
		    src->attrvalue.attrvalue_len;

		dst->ds_attr_val[i].attrvalue.attrvalue_val
		    = kmem_alloc(len, KM_SLEEP);

		bcopy(src->attrvalue.attrvalue_val,
		    dst->ds_attr_val[i].attrvalue.attrvalue_val, len);
	}
}

/*
 */
/*ARGSUSED*/
static bool_t
ds_guid_info_create(rfs4_entry_t e, void *arg)
{
	pinfo_create_t *p = (pinfo_create_t *)arg;
	ds_guid_info_t *pip = (ds_guid_info_t *)e;

	pip->ds_ownerp  = p->dop;

	/* Only supported type is ZFS */
	ASSERT(p->si->type == ZFS);

	pip->ds_guid = p->si->ds_storinfo_u.zfs_info.guid_map.ds_guid;

	pip->ds_attr_len = p->si->ds_storinfo_u.zfs_info.attrs.attrs_len;
	pip->ds_attr_val = kmem_alloc(
	    sizeof (ds_zfsattr) * pip->ds_attr_len, KM_SLEEP);
	mds_dup_zfsattr(p->si->ds_storinfo_u.zfs_info.attrs.attrs_val, pip);

	return (TRUE);
}

static void *
ds_guid_info_mkkey(rfs4_entry_t e)
{
	ds_guid_info_t *gip = (ds_guid_info_t *)e;

	return ((void *)(uintptr_t)&gip->ds_guid);
}

static bool_t
ds_guid_info_compare(rfs4_entry_t e, void *key)
{
	ds_guid_info_t *gip = (ds_guid_info_t *)e;
	ds_guid_t *guid = (ds_guid_t *)key;

	return (ds_guid_compare(&gip->ds_guid, guid));
}

static uint32_t
ds_guid_info_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}
/*ARGSUSED*/
static void
ds_guid_info_destroy(rfs4_entry_t e)
{
	ds_guid_info_t *gip = (ds_guid_info_t *)e;
	ds_guid_free(&gip->ds_guid);
	mds_free_zfsattr(gip);
}

/*ARGSUSED*/
static void
ds_owner_destroy(rfs4_entry_t foo)
{
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
 */

int
sstor_init(nfs_server_instance_t *instp, int def_persona, int def_reap)
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
	instp->default_persona = def_persona;

	instp->state_store = rfs4_database_create();
	instp->state_store->instp = instp;

	/* reset the "first NFSv4 request" status */
	instp->seen_first_compound = 0;
	instp->exi_clean_func = NULL;

	return (1);
}

/*
 * Create/init just the session stateStore tables.
 * used for data-server
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
	 */
	need_sstor_init = sstor_init(instp, FH41_TYPE_NFS, 60);

	if (need_sstor_init == 0)
		return;

	instp->deleg_cbrecall = mds_do_cb_recall;
	instp->deleg_cbcheck  = mds_cbcheck;

	/*
	 * Now create the common tables and indexes
	 */
	v4prot_sstor_init(instp);

	rw_init(&instp->mds_mpd_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&instp->ds_addrlist_lock, NULL, RW_DEFAULT, NULL);
	rw_init(&instp->ds_guid_info_lock, NULL, RW_DEFAULT, NULL);

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
	 * pNFS layout table.
	 */
	rw_init(&instp->mds_layout_lock, NULL, RW_DEFAULT, NULL);

	instp->mds_layout_tab = rfs4_table_create(instp,
	    "Layout", instp->reap_time, 2, mds_layout_create,
	    mds_layout_destroy,
	    mds_do_not_expire, sizeof (mds_layout_t), MDS_TABSIZE,
	    MDS_MAXTABSZ, 100);

	instp->mds_layout_idx = rfs4_index_create(instp->mds_layout_tab,
	    "layout-idx", mds_layout_hash, mds_layout_compare, mds_layout_mkkey,
	    TRUE);

	/*
	 * Create the layout_grant table.
	 *
	 * This table tracks the layout segments that have been granted
	 * to clients. It is indexed by the layout state_id and also by client.
	 */
	instp->mds_layout_grant_tab = rfs4_table_create(instp,
	    "Layout_grant", instp->reap_time, 2, mds_layout_grant_create,
	    mds_layout_grant_destroy, mds_do_not_expire,
	    sizeof (mds_layout_grant_t), MDS_TABSIZE, MDS_MAXTABSZ, 100);

	instp->mds_layout_grant_idx =
	    rfs4_index_create(instp->mds_layout_grant_tab,
	    "layout-grant-idx", mds_layout_grant_hash, mds_layout_grant_compare,
	    mds_layout_grant_mkkey, TRUE);

	instp->mds_layout_grant_ID_idx =
	    rfs4_index_create(instp->mds_layout_grant_tab,
	    "layout-grant-ID-idx", mds_layout_grant_id_hash,
	    mds_layout_grant_id_compare, mds_layout_grant_id_mkkey, FALSE);

	/*
	 * Data server addresses.
	 */
	instp->ds_addrlist_tab = rfs4_table_create(instp,
	    "DSaddrlist", instp->reap_time, 3, ds_addrlist_create,
	    ds_addrlist_destroy, mds_do_not_expire, sizeof (ds_addrlist_t),
	    MDS_TABSIZE, MDS_MAXTABSZ, 200);

	instp->ds_addrlist_idx = rfs4_index_create(instp->ds_addrlist_tab,
	    "dsaddrlist-idx", ds_addrlist_hash, ds_addrlist_compare,
	    ds_addrlist_mkkey, TRUE);

	instp->ds_addrlist_uaddr_idx = rfs4_index_create(instp->ds_addrlist_tab,
	    "dsaddrlist-uaddr-idx", mds_str_hash, ds_addrlist_uaddr_compare,
	    ds_addrlist_uaddr_mkkey, FALSE);

	/*
	 * Multipath Device table.
	 */
	instp->mds_mpd_tab = rfs4_table_create(instp,
	    "mpd", instp->reap_time, 3, mds_mpd_create, mds_mpd_destroy,
	    mds_do_not_expire, sizeof (mds_mpd_t), MDS_TABSIZE,
	    MDS_MAXTABSZ, 200);

	instp->mds_mpd_idx = rfs4_index_create(instp->mds_mpd_tab,
	    "mpd-idx", mds_mpd_hash, mds_mpd_compare, mds_mpd_mkkey, TRUE);

	/*
	 * data-server information tables.
	 */
	instp->ds_owner_tab = rfs4_table_create(instp,
	    "DS_owner", instp->reap_time, 2, ds_owner_create,
	    ds_owner_destroy, mds_do_not_expire,
	    sizeof (ds_owner_t),  MDS_TABSIZE,
	    MDS_MAXTABSZ, 100);

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
	    ds_guid_info_destroy,
	    mds_do_not_expire, sizeof (ds_guid_info_t), MDS_TABSIZE,
	    MDS_MAXTABSZ, 100);

	instp->ds_guid_info_idx = rfs4_index_create(instp->ds_guid_info_tab,
	    "DS_guid-idx", ds_guid_info_hash, ds_guid_info_compare,
	    ds_guid_info_mkkey,
	    TRUE);

	instp->attrvers = 1;

	/*
	 * Mark it as fully initialized
	 */
	instp->inst_flags |= NFS_INST_STORE_INIT | NFS_INST_v41;

	mutex_exit(&instp->state_lock);
}

/*
 * Module load initialization
 */
void
mds_srvrinit(void)
{
	mds_recall_lo = mds_lorecall_cmd;
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
		if (err)
			return (NULL);
	} else {
		(void) VOP_CLOSE(dvp, FREAD, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(dvp);
	}

	bzero(&fid, sizeof (fid));
	fid.fid_len = MAXFIDSZ;
	err = VOP_FID(vp, &fid, NULL);
	if (err || fid.fid_len == 0) {
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
xdr_convert_layout(mds_layout_t *lop, int *size)
{
	int xdr_size;
	char *xdr_buf;
	XDR xdr;

	xdr_size = xdr_sizeof(xdr_odl, lop->odl);
	xdr_buf = kmem_zalloc(xdr_size, KM_SLEEP);

	xdrmem_create(&xdr, xdr_buf, xdr_size, XDR_ENCODE);

	if (xdr_odl(&xdr, lop->odl) == FALSE) {
		*size = 0;
		kmem_free(xdr_buf, xdr_size);
		return (NULL);
	}

	*size = xdr_size;
	return (xdr_buf);
}

/* xdr decode an on-disk layout to a mds_layout */
/*ARGSUSED*/
static odl *
xdr_convert_odl(char *odlp, int size)
{
	int sz;
	char *unxdr_buf;
	XDR xdr;

	sz = sizeof (odl);
	unxdr_buf = kmem_zalloc(sz, KM_SLEEP);

	xdrmem_create(&xdr, unxdr_buf, sz, XDR_DECODE);

	if (xdr_odl(&xdr, (odl *)odlp) == FALSE) {
		kmem_free(unxdr_buf, sz);
		return (NULL);
	}

	return ((odl *)unxdr_buf);
}

int
mds_put_layout(mds_layout_t *lop, vnode_t *vp)
{
	char *odlp;
	char *name;
	int len, size, err;

	name = mds_create_name(vp, &len);
	if (name == NULL) {
		return (-1);
	}

	/* mythical xdr encode routine */
	odlp = xdr_convert_layout(lop, &size);
	if (odlp == NULL)
		return (-1);

	err = mds_write_odl(name, odlp, size);

	kmem_free(name, len);
	kmem_free(odlp, size);

	return (err);
}

int
mds_get_odl(vnode_t *vp, mds_layout_t **lopp)
{
	char *odlp;
	int len, size;
	char *name;
	mds_layout_t *lop;

	ASSERT(lopp != NULL);

	name = mds_create_name(vp, &len);
	if (name == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

	odlp = mds_read_odl(name, &size);
	if (odlp == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

	lop = *lopp;

	/* the magic xdr decode routine */
	lop->odl = xdr_convert_odl(odlp, size);

	kmem_free(name, len);
	kmem_free(odlp, size);

	if (lop->odl == NULL)
		return (NFS4ERR_LAYOUTTRYLATER);

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
