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

extern mds_session_t *mds_findsession_by_id(sessionid4);
extern void rfs41_compound_free(COMPOUND4res *, compound_node_t *);

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

/*
 * If this function successfully completes the compound state
 * will have contain a session pointer.
 */
nfsstat4
rfs41_find_and_set_session(COMPOUND4args_srv *ap, struct compound_state *cs)
{
	mds_session_t	*sp;
	slotid4		 slot;

	ASSERT(ap != NULL);
	ASSERT(ap->sargs != NULL);

	cs->sp = NULL;

	if ((sp = mds_findsession_by_id(ap->sargs->sa_sessionid)) == NULL)
		return (NFS4ERR_BADSESSION);

	slot = ap->sargs->sa_slotid;
	if (slot < 0 || slot >= sp->sn_slrc->sc_maxslot) {
		rfs41_session_rele(sp);
		return (NFS4ERR_BADSLOT);
	}

	ap->slp = (slot41_t *)&sp->sn_slrc->sc_slot[slot];
	cs->sp = sp;
	return (NFS4_OK);
}

slrc_stat_t
rfs41_slrc_prologue(COMPOUND4args_srv *cap, COMPOUND4res_srv **rpp)
{
	slot41_t	*slp;
	sequenceid4	 seqid;

	slp = cap->slp;
	seqid = cap->sargs->sa_sequenceid;

	if (seqid == slp->seqid) {			/* Replay/Retransmit */

		if (seqid == 0)		/* corner case */
			create_rtag(cap, (COMPOUND4res *)*rpp);

		/*
		 * If cached results exist then reply w/those.
		 */
		switch (slp->state) {
		case SLRC_CACHED_OKAY:
		case SLRC_INPROG_REPLAY:
			/*
			 * We need additional status (SLRC_INPROG_REPLAY)
			 * to show we're already handling this slot/seqid
			 * combo, in case additional retransmissions are
			 * received while the server is executing the req.
			 */
			*rpp = &(slp->res);
			slp->state = SLRC_INPROG_REPLAY;
			return (SEQRES_REPLAY);
			/* NOTREACHED */

		default:
			/*
			 * If no cached results exist, then
			 * treat this replay as a new request.
			 */
			slp->state = SLRC_INPROG_NEWREQ;
			return (SEQRES_NEWREQ);
			/* NOTREACHED */
		}

	} else if (seqid == slp->seqid + 1) {		/* New Request */
		slp->state = SLRC_INPROG_NEWREQ;
		return (SEQRES_NEWREQ);

	} else if (seqid < slp->seqid) {		/* Misordered Replay */
		return (SEQRES_MISORD_REPLAY);

	} else if (seqid >= slp->seqid + 2) {		/* Misordered Request */
		return (SEQRES_MISORD_NEWREQ);
	}

	return (SEQRES_BADSESSION);
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
rfs41_compute_seq4_flags(COMPOUND4res *rp, compound_node_t *cn)
{
	struct compound_state	*cs = cn->cn_state;
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
		    cp->seq4[idx].ba_bit == cp_flag) {
			/*
			 * refcnts for these two bits represent active
			 * connections, so handle them separately.
			 */
			continue;
		}

		if (sp->sn_seq4[idx].ba_refcnt)
			sflags |= sp->sn_seq4[idx].ba_bit;

		if (cp->seq4[idx].ba_refcnt)
			sflags |= cp->seq4[idx].ba_bit;
	}

	/*
	 * Now, compute CB_PATH_DOWN and CB_PATH_DOWN_SESSION flags
	 */
	sn_idx = log2(sn_flag);
	cp_idx = log2(cp_flag);

	if (sp->sn_seq4[sn_idx].ba_refcnt == 0 &&
	    cp->seq4[cp_idx].ba_refcnt == 0) {
		/*
		 * no CB path available at either scope (sess or
		 * clid), so flag gets set based on session ctxt
		 */
		sflags |= sp->sn_seq4[sn_idx].ba_sonly ? sn_flag : cp_flag;
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

int
rfs41_slrc_epilogue(COMPOUND4args_srv *cap, COMPOUND4res_srv *resp,
    compound_node_t *cn)
{
	slot41_t	*slp;
	int		 error = 0;

	/* compute SEQ4 flags before caching response */
	rfs41_compute_seq4_flags((COMPOUND4res *)resp, cn);

	/*
	 * Slot cache entry eviction and insertion
	 */
	slp = (slot41_t *)cap->slp;
	switch (slp->state) {
	case SLRC_INPROG_NEWREQ:
		if (resp->status == NFS4_OK) {
			if (slp->res.array != NULL) {
				slp->state = SLRC_CACHED_PURGING;
				DTRACE_PROBE2(nfss41__i__cache_evict,
				    COMPOUND4res *, &slp->res,
				    nfs_resop4 *, slp->res.array);
				rfs41_compound_free((COMPOUND4res *)&slp->res,
				    cn);
			}
			slp->status = NFS4_OK;
			slp->res = *resp;
			DTRACE_PROBE2(nfss41__i__cache_insert,
			    COMPOUND4res *, &slp->res,
			    nfs_resop4 *, slp->res.array);
			slp->state = SLRC_CACHED_OKAY;
		} else {
			/*
			 * XXX: ?? I'm not sure what this means..
			 */
			slp->state = SLRC_SERVER_ERROR;
			error = 1;
		}
		break;

	case SLRC_INPROG_REPLAY:
		/* response already points to cached results */
		slp->state = SLRC_CACHED_OKAY;
		resp->status = slp->status = slp->res.status;
		break;

	default:
		error = 1;
		break;
	}

	return (error);
}


extern int rfs41_persona_set(nfs41_fh_type_t, struct compound_state *);

void
rfs4_cn_init(compound_node_t *cn,
    nfs_server_instance_t *instp, nfsstat4 *statusp, nfs41_fh_type_t persona)
{
	struct compound_state *cs;

	cs = kmem_zalloc(sizeof (*cs), KM_SLEEP);
	cn->cn_state = cs;
	cn->cn_state_impl = 0;

	rfs4_init_compound_state(cs);
	cs->instp = instp;
	cs->statusp = statusp;

	(void) rfs41_persona_set(persona, cs);

	ASSERT(cs->persona_funcs);

	if (cs->persona_funcs->cs_construct != NULL)
		(*cs->persona_funcs->cs_construct)(cn, statusp, &cs->cont);
}

void
rfs4_cn_release(compound_node_t *cn)
{
	struct compound_state *cs = cn->cn_state;

	if (cs->persona_funcs->cs_destruct != NULL)
		(*cs->persona_funcs->cs_destruct)(cn);

	if (cs->vp)
		VN_RELE(cs->vp);
	if (cs->saved_vp)
		VN_RELE(cs->saved_vp);
	if (cs->saved_fh.nfs_fh4_val)
		kmem_free(cs->saved_fh.nfs_fh4_val, NFS4_FHSIZE);
	if (cs->basecr)
		crfree(cs->basecr);
	if (cs->cr)
		crfree(cs->cr);

	kmem_free(cs, sizeof (*cs));
}

/* ARGSUSED */
int
rfs41_dispatch(struct svc_req *req, SVCXPRT *xprt, char *ap,
    nfs41_fh_type_t persona)
{
	compound_node_t		 cn;
	struct compound_state	*cs;
	COMPOUND4res_srv	 res_buf;
	COMPOUND4res_srv	*rbp;
	COMPOUND4args_srv	*cap;
	int			 error = 0;
	int			 rv;

	bzero(&res_buf, sizeof (COMPOUND4res_srv));
	rbp = &res_buf;
	rbp->minorversion = NFS4_MINOR_v1;
	cap = (COMPOUND4args_srv *)ap;

	rfs4_cn_init(&cn, &mds_server, &rbp->status, persona);
	cs = cn.cn_state;

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

			switch (rfs41_slrc_prologue(cap, &rbp)) {
			case SEQRES_NEWREQ:
				break;

			case SEQRES_MISORD_REPLAY:
			case SEQRES_MISORD_NEWREQ:
				rbp->status = NFS4ERR_SEQ_MISORDERED;
				seqop_error(cap, (COMPOUND4res *)rbp);
				goto reply;

			case SEQRES_BADSESSION:
			default:
				rbp->status = NFS4ERR_BADSESSION;
				seqop_error(cap, (COMPOUND4res *)rbp);
				goto reply;
			}
		}
	}

	/* Regular processing */
	curthread->t_flag |= T_DONTPEND;
	mds_compound(&cn, (COMPOUND4args *)cap, (COMPOUND4res *)rbp,
	    NULL, req, &rv);
	curthread->t_flag &= ~T_DONTPEND;

	if (rv)	{	/* short ckt epilogue and sendreply on error */
		error = rv;
		goto out;
	}

	if (curthread->t_flag & T_WOULDBLOCK) {
		curthread->t_flag &= ~T_WOULDBLOCK;
		return (1);		/* XXX - this may have to change */
	}

slrc:
	if (cs->sp)		/* only cache SEQUENCE'd compounds */
		(void) rfs41_slrc_epilogue(cap, rbp, &cn);

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

out:
	if (cs->sp)
		rfs41_session_rele(cs->sp);

	/*
	 * Only free on error. Otherwise, it stays in the
	 * slot replay cache until ejected by the next
	 * request for the slot.
	 */
	if (rbp->status)
		rfs41_compound_free((COMPOUND4res *)rbp, &cn);

	rfs4_cn_release(&cn);
	return (error);
}
