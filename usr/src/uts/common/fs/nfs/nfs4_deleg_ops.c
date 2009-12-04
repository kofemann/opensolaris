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
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs4.h>
#include <sys/types.h>
#include <sys/mutex.h>
#include <sys/condvar.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/time.h>
#include <sys/fem.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>


/*
 * This file contains the code for the monitors which are placed on the vnodes
 * of files that are granted delegations by the NFSv4 server.  These monitors
 * will detect local access, as well as access from other servers
 * (NFS and CIFS), that conflict with the delegations and recall the
 * delegation from the client before letting the offending operation continue.
 *
 * If the caller does not want to block while waiting for the delegation to
 * be returned, then it should set CC_DONTBLOCK in the flags of caller context.
 * This does not work for vnevnents; remove and rename.  They always block.
 */

static int nsi_count = 2;
/*
 * this is the function to recall a read delegation.  it will check if the
 * caller wishes to block or not while waiting for the delegation to be
 * returned.  if the caller context flag has CC_DONTBLOCK set, then it will
 * return an error instead of waiting for the delegation.
 * this function needs to check for all server instance delegations.
 */
int
recall_read_delegations(
	vnode_t *vp,
	rfs4_file_t *fp,
	caller_context_t *ct)
{
	int	i;
	int	cnt;
	int	active = -1;

	clock_t	rc;

	rfs4_file_t	**fpa;

	nfs_server_instance_t	*instp;

	/*
	 * Put a hold on this 'fp' such that it will be treated
	 * the same as the rest of the array!
	 */
	rfs4_dbe_lock(fp->rf_dbe);
	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_unlock(fp->rf_dbe);

	/*
	 * More than one instance could have given out read delegations to this
	 * file, however, we know that whatever instance owns this 'fp' has
	 * given out a delegation, so kick off the recall before checking for
	 * more.
	 */
	rfs4_recall_deleg(fp, FALSE, NULL);

	/*
	 * Is there more than one file structure for this vp?
	 * Get the vsd for each instance of the server, if it exists.
	 */
	fpa = kmem_zalloc((sizeof (rfs4_file_t *) * nsi_count), KM_SLEEP);

	fpa[0] = fp;
	cnt = 1;
	mutex_enter(&vp->v_vsd_lock);
	for (instp = list_head(&nsi_head); instp != NULL;
	    instp = list_next(&nsi_head, &instp->nsi_list)) {
		rfs4_file_t	*temp;

		temp = (rfs4_file_t *)vsd_get(vp, instp->vkey);
		if (temp && (temp != fp)) {
			ASSERT(cnt < nsi_count);
			fpa[cnt++] = temp;
		}
	}
	mutex_exit(&vp->v_vsd_lock);

	ASSERT(cnt <= nsi_count);

	/*
	 * 'cnt' now equals the number of instances that have a file struct
	 * for this file.  Now check if it is a valid file and if it has
	 * a delegation.  If so, send a recall.
	 */
	for (i = 1; i < cnt; i++) {
		rfs4_dbe_lock(fpa[i]->rf_dbe);
		if (fpa[i]->rf_dinfo->rd_dtype == OPEN_DELEGATE_NONE ||
		    rfs4_dbe_is_invalid(fpa[i]->rf_dbe) ||
		    (rfs4_dbe_refcnt(fpa[i]->rf_dbe) == 0)) {
			rfs4_dbe_unlock(fpa[i]->rf_dbe);
			fpa[i] = NULL;
		} else {
			rfs4_dbe_hold(fpa[i]->rf_dbe);
			rfs4_dbe_unlock(fpa[i]->rf_dbe);
			rfs4_recall_deleg(fpa[i], FALSE, NULL);
		}
	}

	/* optimization */
	delay(NFS4_DELEGATION_CONFLICT_DELAY);

	/*
	 * Check to see if the delegations have been returned already.
	 * If so, then we are done, return success.
	 */
	for (i = 0; i < cnt; i++) {
		if (fpa[i] != NULL) {
			rfs4_dbe_lock(fpa[i]->rf_dbe);
			if (fpa[i]->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
				active = i;
				break;
			}
			rfs4_dbe_rele_nolock(fpa[i]->rf_dbe);
			rfs4_dbe_unlock(fpa[i]->rf_dbe);
			fpa[i] = NULL;	/* this one is done */
		}
	}

	if (i == cnt) {
		kmem_free(fpa, sizeof (rfs4_file_t *) * nsi_count);
		return (0);
	}

	/*
	 * Not all delegations have been returned yet.
	 * fpa[active] is the first file which is undone.
	 * Check the caller context to see if we should wait
	 * for their return, or just return now with an error.
	 */
	if (ct && ct->cc_flags & CC_DONTBLOCK) {
		ASSERT(fpa[active] != NULL);
		rfs4_dbe_unlock(fpa[active]->rf_dbe);
		ct->cc_flags |= CC_WOULDBLOCK;

		/*
		 * Go through the remaining items and
		 * release the hold we put on them for the
		 * fpa array!
		 */
		for (i = active; i < cnt; i++) {
			if (fpa[i] != NULL) {
				rfs4_file_rele(fpa[i]);
			}
		}

		kmem_free(fpa, sizeof (rfs4_file_t *) * nsi_count);
		return (NFS4ERR_DELAY);
	}

	/*
	 * Let the waiting begin.
	 *
	 * Note, if this is the first time through,
	 * then fpa[active] is locked from above. If this is a
	 * jump from below, then fpa[active] is still locked.
	 */
wait:
	ASSERT(fpa[active] != NULL);
	while (fpa[active]->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
		rc = rfs4_dbe_twait(fpa[active]->rf_dbe,
		    ddi_get_lbolt() + SEC_TO_TICK(dbe_to_instp(
		    fpa[active]->rf_dbe)->lease_period));
		if (rc == -1) { /* timed out */
			rfs4_dbe_unlock(fpa[active]->rf_dbe);
			rfs4_recall_deleg(fpa[active], FALSE, NULL);
			rfs4_dbe_lock(fpa[active]->rf_dbe);

			/*
			 * Send recalls to any other instance's clients who
			 * haven't returned their delegation yet.
			 */
			for (i = active + 1; i < cnt; i++) {
				if (fpa[i] == NULL)
					continue;
				rfs4_dbe_lock(fpa[i]->rf_dbe);
				if (fpa[i]->rf_dinfo->rd_dtype !=
				    OPEN_DELEGATE_NONE) {
					rfs4_dbe_unlock(fpa[i]->rf_dbe);
					rfs4_recall_deleg(fpa[i], FALSE, NULL);
				} else {
					rfs4_file_rele(fpa[i]);
					rfs4_dbe_unlock(fpa[i]->rf_dbe);
					fpa[i] = NULL;	/* this one is done */
				}
			}
		}
	}
	rfs4_dbe_rele_nolock(fpa[active]->rf_dbe);
	rfs4_dbe_unlock(fpa[active]->rf_dbe);
	fpa[active] = NULL;

	/* have they all completed returning the delegations? */
	for (i = active + 1; i < cnt; i++) {
		if (fpa[i] == NULL)
			continue;

		/*
		 * We found one which was not done, so lock it
		 * and start waiting again!
		 */
		rfs4_dbe_lock(fpa[i]->rf_dbe);
		if (fpa[i]->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
			active = i;
			goto wait;
		}

		rfs4_dbe_rele_nolock(fpa[i]->rf_dbe);
		rfs4_dbe_unlock(fpa[i]->rf_dbe);
		fpa[i] = NULL;
	}

	kmem_free(fpa, sizeof (rfs4_file_t *) * nsi_count);
	return (0);
}

/*
 * this is the function to recall a write delegation.  there can only be
 * one write delegation handed out to a client.  there is no need to check
 * the other server instances to see if they have delegated this file.
 */
int
recall_all_delegations(rfs4_file_t *fp, bool_t trunc, caller_context_t *ct)
{
	clock_t rc;

	rfs4_recall_deleg(fp, trunc, NULL);
	delay(NFS4_DELEGATION_CONFLICT_DELAY);

	rfs4_dbe_lock(fp->rf_dbe);
	if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_NONE) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return (0);
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	if (ct && ct->cc_flags & CC_DONTBLOCK) {
		ct->cc_flags |= CC_WOULDBLOCK;
		return (NFS4ERR_DELAY);
	}

	rfs4_dbe_lock(fp->rf_dbe);
	while (fp->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
		rc = rfs4_dbe_twait(fp->rf_dbe,
		    ddi_get_lbolt() +
		    SEC_TO_TICK(dbe_to_instp(fp->rf_dbe)->lease_period));
		if (rc == -1) { /* timed out */
			rfs4_dbe_unlock(fp->rf_dbe);
			rfs4_recall_deleg(fp, trunc, NULL);
			rfs4_dbe_lock(fp->rf_dbe);
		}
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	return (0);
}

/*
 * this is the function to recall a write delegation.  there can only be
 * one write delegation handed out to a client.  there is no need to check
 * the other server instances to see if they have delegated this file.
 */
int
recall_write_delegation(rfs4_file_t *fp, bool_t trunc, caller_context_t *ct)
{
	clock_t rc;

	rfs4_recall_deleg(fp, trunc, NULL);
	delay(NFS4_DELEGATION_CONFLICT_DELAY);

	rfs4_dbe_lock(fp->rf_dbe);
	if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_NONE) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return (0);
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	if (ct && ct->cc_flags & CC_DONTBLOCK) {
		ct->cc_flags |= CC_WOULDBLOCK;
		return (NFS4ERR_DELAY);
	}

	rfs4_dbe_lock(fp->rf_dbe);
	while (fp->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
		rc = rfs4_dbe_twait(fp->rf_dbe, ddi_get_lbolt() +
		    SEC_TO_TICK(dbe_to_instp(fp->rf_dbe)->lease_period));
		if (rc == -1) { /* timed out */
			rfs4_dbe_unlock(fp->rf_dbe);
			rfs4_recall_deleg(fp, trunc, NULL);
			rfs4_dbe_lock(fp->rf_dbe);
		}
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	return (0);
}

/* monitor for open on read delegated file */
int
deleg_rd_open(femarg_t *arg, int mode, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = *(arg->fa_vnode.vpp);

	/*
	 * Since this monitor is for a read delegated file, we know that
	 * only an open for write will cause a conflict.
	 */
	if (mode & (FWRITE|FTRUNC)) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_read_delegations(vp, fp, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/* monitor for open on write delegated file */
int
deleg_wr_open(femarg_t *arg, int mode, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/*
	 * Now that the NFSv4 server calls VOP_OPEN, we need to check to
	 * to make sure it is not us calling open (open race) or
	 * we will end up panicing the system.
	 * Since this monitor is for a write delegated file, we know that
	 * any open will cause a conflict.
	 */
	if (ct == NULL || ct->cc_caller_id != instp->caller_id) {
		rc = recall_write_delegation(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_open(arg, mode, cr, ct));
}

/*
 * this is op is for write delegations only and should only be hit
 * by the owner of the delegation.  if not, then someone is
 * doing a read without doing an open first. like from nfs2/3.
 */
int
deleg_wr_read(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != instp->caller_id) {
		rc = recall_write_delegation(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}
	return (vnext_read(arg, uiop, ioflag, cr, ct));
}

/*
 * If someone is doing a write on a read delegated file, it is a conflict.
 * conflicts should be caught at open, but NFSv2&3 don't use OPEN.
 */
int
deleg_rd_write(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_read_delegations(vp, fp, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_write(arg, uiop, ioflag, cr, ct));
}

/*
 * the owner of the delegation can write the file, but nobody else can.
 * conflicts should be caught at open, but NFSv2&3 don't use OPEN.
 */
int
deleg_wr_write(femarg_t *arg, uio_t *uiop, int ioflag, cred_t *cr,
    struct caller_context *ct)
{
	int rc;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != instp->caller_id) {
		rc = recall_write_delegation(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}
	return (vnext_write(arg, uiop, ioflag, cr, ct));
}

/* doing a setattr on a read delegated file is a conflict. */
int
deleg_rd_setattr(femarg_t *arg, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_read_delegations(vp, fp, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setattr(arg, vap, flags, cr, ct));
}

/* only the owner of the write delegation can do a setattr */
int
deleg_wr_setattr(femarg_t *arg, vattr_t *vap, int flags, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	bool_t trunc = FALSE;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/*
	 * Use caller context to compare caller to delegation owner
	 */
	if (ct == NULL || (ct->cc_caller_id != instp->caller_id)) {
		if ((vap->va_mask & AT_SIZE) && (vap->va_size == 0))
			trunc = TRUE;

		rc = recall_write_delegation(fp, trunc, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_setattr(arg, vap, flags, cr, ct));
}

int
deleg_rd_rwlock(femarg_t *arg, int write_lock, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	/*
	 * If this is a write lock, then we got us a conflict.
	 */
	if (write_lock) {
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rc = recall_read_delegations(vp, fp, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

/* Only the owner of the write delegation should be doing this. */
int
deleg_wr_rwlock(femarg_t *arg, int write_lock, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != instp->caller_id) {
		rc = recall_write_delegation(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_rwlock(arg, write_lock, ct));
}

int
deleg_rd_space(femarg_t *arg, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	rc = recall_read_delegations(vp, fp, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_space(arg, cmd, bfp, flag, offset, cr, ct));
}

int
deleg_wr_space(femarg_t *arg, int cmd, flock64_t *bfp, int flag,
    offset_t offset, cred_t *cr, caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	nfs_server_instance_t *instp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
	instp = dbe_to_instp(fp->rf_dbe);

	/* use caller context to compare caller to delegation owner */
	if (ct == NULL || ct->cc_caller_id != instp->caller_id) {
		rc = recall_write_delegation(fp, FALSE, ct);
		if (rc == NFS4ERR_DELAY)
			return (EAGAIN);
	}

	return (vnext_space(arg, cmd, bfp, flag, offset, cr, ct));
}

int
deleg_rd_setsecattr(femarg_t *arg, vsecattr_t *vsap, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;

	/* changing security attribute triggers recall */
	rc = recall_read_delegations(vp, fp, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setsecattr(arg, vsap, flag, cr, ct));
}

int
deleg_wr_setsecattr(femarg_t *arg, vsecattr_t *vsap, int flag, cred_t *cr,
    caller_context_t *ct)
{
	int rc;
	rfs4_file_t *fp;

	fp = (rfs4_file_t *)arg->fa_fnode->fn_available;

	/* changing security attribute triggers recall */
	rc = recall_write_delegation(fp, FALSE, ct);
	if (rc == NFS4ERR_DELAY)
		return (EAGAIN);

	return (vnext_setsecattr(arg, vsap, flag, cr, ct));
}

/* currently, vnevents must do synchronous recalls */
int
deleg_rd_vnevent(femarg_t *arg, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	rfs4_file_t *fp;
	vnode_t *vp = arg->fa_vnode.vp;

	switch (vnevent) {
	case VE_REMOVE:
	case VE_RENAME_DEST:
		/*FALLTHROUGH*/

	case VE_RENAME_SRC:
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		(void) recall_read_delegations(vp, fp, NULL);
		break;

	default:
		break;
	}
	return (vnext_vnevent(arg, vnevent, dvp, name, ct));
}

int
deleg_wr_vnevent(femarg_t *arg, vnevent_t vnevent, vnode_t *dvp, char *name,
    caller_context_t *ct)
{
	clock_t rc;
	rfs4_file_t *fp;
	bool_t trunc = FALSE;

	switch (vnevent) {
	case VE_REMOVE:
	case VE_RENAME_DEST:
		trunc = TRUE;
		/*FALLTHROUGH*/

	case VE_RENAME_SRC:
		fp = (rfs4_file_t *)arg->fa_fnode->fn_available;
		rfs4_recall_deleg(fp, trunc, NULL);
		rfs4_dbe_lock(fp->rf_dbe);
		while (fp->rf_dinfo->rd_dtype != OPEN_DELEGATE_NONE) {
			rc = rfs4_dbe_twait(fp->rf_dbe,
			    ddi_get_lbolt() + SEC_TO_TICK(
			    dbe_to_instp(fp->rf_dbe)->lease_period));
			if (rc == -1) { /* timed out */
				rfs4_dbe_unlock(fp->rf_dbe);
				rfs4_recall_deleg(fp, trunc, NULL);
				rfs4_dbe_lock(fp->rf_dbe);
			}
		}
		rfs4_dbe_unlock(fp->rf_dbe);

		break;

	default:
		break;
	}
	return (vnext_vnevent(arg, vnevent, dvp, name, ct));
}
