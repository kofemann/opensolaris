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
#include <rpc/auth.h>
#include <rpc/auth_unix.h>
#include <rpc/auth_des.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>
#include <nfs/nfs_dispatch.h>
#include <sys/cmn_err.h>
#include <sys/modctl.h>

static kmem_cache_t *rfs41_compound_state_cache = NULL;

/*
 * Needs some clean up
 */
static void
nuke_rtag(COMPOUND4res *rp)
{
	ASSERT(rp != NULL);
	if (rp->tag.utf8string_len == 0 || rp->tag.utf8string_val == NULL)
		return;

	kmem_free(rp->tag.utf8string_val, rp->tag.utf8string_len);
	bzero(&rp->tag, sizeof (utf8string));
}

static void
create_rtag(COMPOUND4args_srv *ap, COMPOUND4res *rp)
{
	ASSERT(rp != NULL);
	ASSERT(ap != NULL);

	if (rp->tag.utf8string_len != 0 && rp->tag.utf8string_val != NULL)
		kmem_free(rp->tag.utf8string_val, rp->tag.utf8string_len);

	rp->tag.utf8string_len = ap->tag.utf8string_len;
	rp->tag.utf8string_val = kmem_alloc(rp->tag.utf8string_len, KM_SLEEP);
	bcopy(ap->tag.utf8string_val, rp->tag.utf8string_val,
	    rp->tag.utf8string_len);
}

/*
 * In NFSv4.1, most all responses are cached (unless specified otherwise
 * by the client). Thus we don't free the results struct right off after
 * the sendreply, but rather after the next request for the slot and seq+1
 * come in (letting the server know it's okay to discard the cached results).
 * Hence, when we reply via an error path, we _must_ construct and free the
 * reply some other way.
 */
static void
seqop_error(COMPOUND4args_srv *ap, COMPOUND4res *rp)
{
	nfs_resop4	*resop;

	ASSERT(rp->status != 0);		/* must be set by caller */

	create_rtag(ap, rp);
	rp->array_len = 1;
	rp->array = kmem_zalloc(sizeof (nfs_resop4), KM_SLEEP);

	resop = &rp->array[0];
	resop->resop = OP_SEQUENCE;
	resop->nfs_resop4_u.opsequence.sr_status = rp->status;
}

static int
seqop_singleton(COMPOUND4res_srv *resp)
{
	ASSERT(resp != NULL && resp->array != NULL);
	ASSERT(resp->array->resop == OP_SEQUENCE);

	/*
	 * No need to check sr_status here, as
	 * seq_failed already checks that scenario.
	 */
	return (resp->array_len == 1);
}

static int
seqop_failed(COMPOUND4res_srv *resp)
{
	SEQUENCE4res	*rp;

	ASSERT(resp != NULL && resp->array != NULL);
	ASSERT(resp->array->resop == OP_SEQUENCE);
	rp = &resp->array->nfs_resop4_u.opsequence;

	return (rp->sr_status != NFS4_OK);
}

/*
 * If this function successfully completes the compound state
 * will contain a session pointer.
 */
nfsstat4
rfs41_find_and_set_session(COMPOUND4args_srv *ap, struct compound_state *cs)
{
	mds_session_t	*sp;
	slotid4		 slot;

	ASSERT(ap != NULL);
	ASSERT(ap->sargs != NULL);

	cs->sp = NULL;

	if ((sp = mds_findsession_by_id(cs->instp,
	    ap->sargs->sa_sessionid)) == NULL)
		return (NFS4ERR_BADSESSION);

	slot = ap->sargs->sa_slotid;
	if (slot < 0 || slot >= sp->sn_replay->st_currw) {
		rfs41_session_rele(sp);
		return (NFS4ERR_BADSLOT);
	}
	cs->sp = sp;
	cs->sact = ap->sargs->sa_cachethis;
	return (NFS4_OK);
}

slrc_stat_t
rfs41_slrc_prologue(mds_session_t *sess, COMPOUND4args_srv *cap,
    COMPOUND4res_srv **rpp)
{
	stok_t *handle = sess->sn_replay;
	slotid4 slot = cap->sargs->sa_slotid;
	sequenceid4 seq = cap->sargs->sa_sequenceid;
	slot_ent_t *slt = NULL;
	int ret = 0;

	ret = slrc_slot_alloc(handle, slot, seq, &slt);
	/* Take care of the replay case. */
	if ((ret == SEQRES_REPLAY) && (slt != NULL)) {
		if (seq == 0)		/* corner case */
			create_rtag(cap, (COMPOUND4res *)*rpp);
		*rpp = &slt->se_buf;
	}
	return (ret);
}

/*
 * rfs41_compute_seq4_flags calculates the SEQUENCE SEQ4_STATUS
 * bit results after the compound has been processed. If any of
 * the flags have a refcnt greater than zero, (with the noted
 * exceptions of CB_PATH_DOWN and CB_PATH_DOWN_SESSION) the
 * corresponding bit in sr_status_flag is set.
 *
 * Upon detection of this condition, the onus is on the client to
 * perform TEST_STATEID's to find the offending deleg and layout
 * stateid's and return them. If only a DELEG_RETURN is done (but
 * assuming no layout is returned) the RECALLABLE_STATE_REVOKED
 * bit continues to be asserted in subsequent SEQUENCE4 replies
 * as described in the specification. Only after a LAYOUT_RETURN
 * is done, will the RECALLABLE_STATE_REVOKED bit be released of
 * the HOLD and hence subsequent SEQUENCE4 replies will now have
 * the RECALLABLE_STATE_REVOKED bit turned off.
 */
static void
rfs41_compute_seq4_flags(COMPOUND4res *rp, compound_state_t *cs)
{
	mds_session_t		*sp = cs->sp;
	rfs4_client_t		*cp = sp->sn_clnt;
	int			 i;
	int			 idx, sn_idx, cp_idx;
	uint32_t		 sflags = 0;
	uint32_t		 cp_flag = SEQ4_STATUS_CB_PATH_DOWN;
	uint32_t		 sn_flag = SEQ4_STATUS_CB_PATH_DOWN_SESSION;
	nfs_resop4		*resop = &rp->array[0];	/* SEQUENCE */
	SEQUENCE4res		*resp  = &resop->nfs_resop4_u.opsequence;
	SEQUENCE4resok		*rok   = &resp->SEQUENCE4res_u.sr_resok4;

	if (resp->sr_status != NFS4_OK)
		return;

	for (i = 1; i <= SEQ4_HIGH_BIT && i != 0; i <<= 1) {
		idx = log2(i);

		if (sp->sn_seq4[idx].ba_bit == sn_flag ||
		    cp->rc_seq4[idx].ba_bit == cp_flag) {
			/*
			 * refcnts for these two bits represent active
			 * connections, so handle them separately.
			 */
			continue;
		}

		if (sp->sn_seq4[idx].ba_refcnt)
			sflags |= sp->sn_seq4[idx].ba_bit;

		if (cp->rc_seq4[idx].ba_refcnt)
			sflags |= cp->rc_seq4[idx].ba_bit;
	}

	/*
	 * Now, compute CB_PATH_DOWN and CB_PATH_DOWN_SESSION flags
	 */
	sn_idx = log2(sn_flag);
	cp_idx = log2(cp_flag);

	if (sp->sn_seq4[sn_idx].ba_refcnt == 0 &&
	    cp->rc_seq4[cp_idx].ba_refcnt == 0) {
		/*
		 * no CB path available at either scope (sess or
		 * clid), so flag gets set based on session ctxt
		 */
		sflags |= (sp->sn_seq4[sn_idx].ba_sonly ? sn_flag : cp_flag);
	}

	/*
	 * Now all that remains is to update the SEQUENCE4res flags
	 *
	 * NOTE: sr_status_flag already contains info from SEQUENCE
	 * operation results; just (logically) OR the new flags and
	 * we're done.
	 */
	rok->sr_status_flags |= sflags;
}

/*
 * Handling section 2.10.6.1.3 of spec. If sa_cachethis is FALSE,
 * server MUST still cache the successful SEQUENCE and the next
 * operation pre-populated w/the NFS4ERR_RETRY_UNCACHED_REP error.
 */
void
rfs41_slrc_cache_contrived(slot_ent_t *slp, COMPOUND4res_srv *rsp)
{
	COMPOUND4res_srv	*crp = NULL;
	int			 len = 2;

	crp = kmem_zalloc(sizeof (COMPOUND4res_srv), KM_SLEEP);

	/* status */
	crp->status = NFS4ERR_RETRY_UNCACHED_REP;

	/* tag */
	crp->tag.utf8string_val = kmem_alloc(rsp->tag.utf8string_len, KM_SLEEP);
	crp->tag.utf8string_len = rsp->tag.utf8string_len;
	bcopy(rsp->tag.utf8string_val, crp->tag.utf8string_val,
	    crp->tag.utf8string_len);

	/* ops */
	crp->array_len = len;
	crp->array = kmem_zalloc(len * sizeof (nfs_resop4), KM_SLEEP);
	crp->array[0] = rsp->array[0];			/* SEQUENCE */

	/* now capture the next op and overload its result */
	crp->array[1].resop = rsp->array[1].resop;	/* NEXT OP */
	SET_RESOP4(&crp->array[1], crp->status);

	/* cache it */
	slp->se_status = crp->status;
	slp->se_buf = *crp;
	slp->se_state = SLRC_CACHED_OKAY;
}

int
rfs41_slrc_epilogue(mds_session_t *sp, COMPOUND4args_srv *cap,
    COMPOUND4res_srv *resp, compound_state_t *cs)
{
	int		 error = 0;
	stok_t		*handle = sp->sn_replay;
	slot_ent_t	*slt = NULL;
	slotid4		 slot = cap->sargs->sa_slotid;

	/* compute SEQ4 flags before caching response */
	rfs41_compute_seq4_flags((COMPOUND4res *)resp, cs);

	slt = slrc_slot_get(handle, slot);
	mutex_enter(&slt->se_lock);
	switch (slt->se_state) {
	case SLRC_INPROG_NEWREQ:
		/*
		 * Evict existing entry, if one exists
		 */
		if (slt->se_buf.array != NULL) {
			slt->se_state = SLRC_CACHED_PURGING;
			DTRACE_PROBE2(nfss41__i__cache_evict,
			    COMPOUND4res *, &slt->se_buf, slot_ent_t *, slt);
			rfs41_compound_free((COMPOUND4res *)&slt->se_buf, cs);
		}

		/*
		 * Cache depending on sa_cachethis
		 */
		if (cs->sact || seqop_singleton(resp)) {
			slt->se_status = resp->status;
			slt->se_buf = *resp;
			slt->se_state = SLRC_CACHED_OKAY;

			DTRACE_PROBE2(nfss41__i__cache_insert,
			    COMPOUND4res *, &slt->se_buf, slot_ent_t *, slt);
		} else {
			rfs41_slrc_cache_contrived(slt, resp);

			DTRACE_PROBE2(nfss41__i__no_cache,
			    COMPOUND4res *, &slt->se_buf, slot_ent_t *, slt);
		}
		break;

	default:
		error = 1;
		break;
	}
	cv_signal(&slt->se_wait);
	mutex_exit(&slt->se_lock);
	return (error);
}

/*ARGSUSED*/
static int
rfs41_compound_state_construct(void *vcs, void *foo, int bar)
{
	return (0);
}

/*ARGSUSED*/
static void
rfs41_compound_state_destroy(void *vcs, void *foo)
{
}

/* module init */
void
rfs41_dispatch_init(void)
{
	rfs41_compound_state_cache = kmem_cache_create(
	    "rfs41_compound_state_cache", sizeof (compound_state_t), 0,
	    rfs41_compound_state_construct, rfs41_compound_state_destroy, NULL,
	    NULL, NULL, 0);
}

compound_state_t *
rfs41_compound_state_alloc(nfs_server_instance_t *instp)
{
	compound_state_t *cs;

	cs = kmem_cache_alloc(rfs41_compound_state_cache, KM_SLEEP);
	bzero(cs, sizeof (*cs));
	cs->instp = instp;
	cs->cont = TRUE;
	cs->fh.nfs_fh4_val = cs->fhbuf;

	return (cs);
}

void
rfs41_compound_state_free(compound_state_t *cs)
{
	if (cs->nn != NULL) {
		nnode_rele(&cs->nn);
	}
	if (cs->vp) {
		VN_RELE(cs->vp);
		cs->vp = NULL;
	}
	if (cs->cr) {
		crfree(cs->cr);
		cs->cr = NULL;
	}
	if (cs->saved_fh.nfs_fh4_val) {
		kmem_free(cs->saved_fh.nfs_fh4_val, NFS4_FHSIZE);
	}
	if (cs->basecr) {
		crfree(cs->basecr);
	}
	if (cs->sp) {
		rfs41_session_rele(cs->sp);
		if (cs->cp)
			rfs4_client_rele(cs->cp);
	}
	kmem_cache_free(rfs41_compound_state_cache, cs);
}

static void
rfs41_slrc_cacheok(mds_session_t *sess, COMPOUND4args_srv *cap)
{
	stok_t *handle = sess->sn_replay;
	slot_ent_t *slt = NULL;
	slotid4 slot;

	slot = cap->sargs->sa_slotid;
	slt = slrc_slot_get(handle, slot);
	mutex_enter(&slt->se_lock);
	slt->se_state = SLRC_CACHED_OKAY;
	slt->se_status = NFS4_OK;
	cv_signal(&slt->se_wait);
	mutex_exit(&slt->se_lock);
}

/* ARGSUSED */
int
rfs41_dispatch(struct svc_req *req, SVCXPRT *xprt, char *ap)
{
	compound_state_t	*cs;
	COMPOUND4res_srv	 res_buf;
	COMPOUND4res_srv	*rbp;
	COMPOUND4args_srv	*cap;
	int			 error = 0;
	int			 rpcerr = 0;
	int			 replay = 0;

	cs = rfs41_compound_state_alloc(mds_server);
	bzero(&res_buf, sizeof (COMPOUND4res_srv));
	rbp = &res_buf;
	rbp->minorversion = NFS4_MINOR_v1;
	cap = (COMPOUND4args_srv *)ap;
	cs->statusp = &rbp->status;

	/*
	 * First check to see if the instance has been
	 * fully setup!
	 *
	 * But wait, we might also be tearing down the
	 * instance!
	 */
	if (mds_server == NULL ||
	    !(mds_server->inst_flags & NFS_INST_STORE_INIT) ||
	    (mds_server->inst_flags & NFS_INST_TERMINUS)) {

		if (mds_server == NULL)
			cmn_err(CE_WARN, "rfs41_dispatch: mds_server is NULL");
		else if (!(mds_server->inst_flags & NFS_INST_STORE_INIT))
			cmn_err(CE_WARN,
			    "rfs41_dispatch: instance not initialized");
		else
			cmn_err(CE_WARN,
			    "rfs41_dispatch: instance being torn down");

		rbp->status = error = NFS4ERR_BADSESSION;
		seqop_error(cap, (COMPOUND4res *)rbp);
		goto reply;
	}

	/*
	 * Validate the first operation in the compound,
	 * If it's not SEQUENCE _or_ it's a new request,
	 * we handle it via mds_compound().
	 */
	if (cap->array[0].argop == OP_SEQUENCE) {
		/*
		 * sargs will be set by the XDR decode function
		 */
		if (cap->sargs != NULL) {
			if (error = rfs41_find_and_set_session(cap, cs)) {
				rbp->status = error;
				seqop_error(cap, (COMPOUND4res *)rbp);
				goto reply;
			}

			switch (rfs41_slrc_prologue(cs->sp, cap, &rbp)) {
			case SEQRES_NEWREQ:
				break;

			case SEQRES_MISORD_REPLAY:
			case SEQRES_MISORD_NEWREQ:
				rbp->status = NFS4ERR_SEQ_MISORDERED;
				seqop_error(cap, (COMPOUND4res *)rbp);
				goto reply;

			case SEQRES_REPLAY:
				replay = 1;
				goto reply;

			case SEQRES_BADSESSION:
				cmn_err(CE_WARN,
				    "rfs41_dispatch: SEQRES_BADSESSION");
			default:
				cmn_err(CE_WARN, "rfs41_dispatch: default");
				rbp->status = NFS4ERR_BADSESSION;
				seqop_error(cap, (COMPOUND4res *)rbp);
				goto reply;
			}
		}
	}

	/* Regular processing */
	curthread->t_flag |= T_DONTPEND;
	mds_compound(cs, (COMPOUND4args *)cap, (COMPOUND4res *)rbp,
	    NULL, req, &rpcerr);
	curthread->t_flag &= ~T_DONTPEND;

	/*
	 * On RPC error, short ckt epilogue and sendreply
	 */
	if (rpcerr) {
		error = rpcerr;
		goto out;
	}

	if (curthread->t_flag & T_WOULDBLOCK) {
		curthread->t_flag &= ~T_WOULDBLOCK;
		rfs41_compound_state_free(cs);
		return (1);
	}

slrc:
	if (cs->sp) {
		if (seqop_failed(rbp)) {
			/*
			 * Don't make modifications to the
			 * slot for failed SEQUENCE ops.
			 */
			DTRACE_PROBE1(nfss41__i__dispatch, COMPOUND4res *, rbp);
		} else {
			(void) rfs41_slrc_epilogue(cs->sp, cap, rbp, cs);
		}
	}

reply:
	/*
	 * Send out the replayed reply or the 'real' one.
	 */
	if (!svc_sendreply(xprt, xdr_COMPOUND4res_srv, (char *)rbp)) {
		DTRACE_PROBE2(nfss41__e__dispatch_sendfail,
		    struct svc_req *, xprt, char *, rbp);
		svcerr_systemerr(xprt);
		error++;
	}

	if (replay) {
		(void) rfs41_slrc_cacheok(cs->sp, cap);
		replay = 0;
	}
out:
	rfs41_compound_state_free(cs);
	return (error);
}
