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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <nfs/nfs_clnt.h>
#include <nfs/nfs4_pnfs.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <sys/time.h>

static kmem_cache_t *file_io_read_cache;
static kmem_cache_t *read_task_cache;
static kmem_cache_t *stripe_dev_cache;
static kmem_cache_t *pnfs_layout_cache;
static kmem_cache_t *file_io_write_cache;
static kmem_cache_t *file_io_commit_cache;
static kmem_cache_t *write_task_cache;
static kmem_cache_t *commit_task_cache;
static kmem_cache_t *task_get_devicelist_cache;
static kmem_cache_t *task_layoutget_cache;
static kmem_cache_t *task_layoutreturn_cache;

int nfs4_pnfs_io_nthreads = 32;
int nfs4_pnfs_io_maxalloc = 32;
int nfs4_pnfs_other_nthreads = 8;
int nfs4_pnfs_other_maxalloc = 8;

int nfs4_pnfs_stripe_unit = 16384;

/* handy macros for long field names */
#define	stripe_indices_len	nflda_stripe_indices.nflda_stripe_indices_len
#define	stripe_indices		nflda_stripe_indices.nflda_stripe_indices_val
#define	mpl_len	nflda_multipath_ds_list.nflda_multipath_ds_list_len
#define	mpl_val	nflda_multipath_ds_list.nflda_multipath_ds_list_val

#define	DEV_ASSIGN(x, y)	bcopy((y), (x), sizeof (deviceid4))

static int pnfs_getdeviceinfo(mntinfo4_t *, devnode_t *, cred_t *);
static devnode_t *pnfs_create_device(nfs4_server_t *, deviceid4, avl_index_t);
/*
 * The function prototype for encoding/decoding the layout data structures.
 */
extern bool_t xdr_layoutstats_t(XDR *, layoutstats_t *);

static int
nfs4_devid_compare(const void *va, const void *vb)
{
	const devnode_t *a = va;
	const devnode_t *b = vb;
	int m;

	m = memcmp(a->dn_devid, b->dn_devid, sizeof (deviceid4));
	return (m == 0 ? 0 : m < 0 ? -1 : 1);
}

static stripe_dev_t *
stripe_dev_alloc()
{
	stripe_dev_t *rc;

	rc = kmem_cache_alloc(stripe_dev_cache, KM_SLEEP);
	rc->std_refcount = 1;
	rc->std_flags = 0;

	rc->std_svp = NULL;

	return (rc);
}

static void
stripe_dev_hold(stripe_dev_t *stripe)
{
	mutex_enter(&stripe->std_lock);
	stripe->std_refcount++;
	mutex_exit(&stripe->std_lock);
}

static void
stripe_dev_rele(stripe_dev_t **handle)
{
	stripe_dev_t *stripe = *handle;

	*handle = NULL;

	mutex_enter(&stripe->std_lock);
	stripe->std_refcount--;
	if (stripe->std_refcount > 0) {
		mutex_exit(&stripe->std_lock);
		return;
	}
	mutex_exit(&stripe->std_lock);
	sfh4_rele(&stripe->std_fh);
	kmem_cache_free(stripe_dev_cache, stripe);
}



stateid4
pnfs_get_losid(rnode4_t *rp)
{
	ASSERT(MUTEX_HELD(&rp->r_statelock));
	return (rp->r_lostateid);
}

/* stolen from nfs4_srv_deleg.c */
static int
pnfs_uaddr2sockaddr(int af, char *ua, void *ap, in_port_t *pp)
{
	int dots = 0, i, j, len, k;
	unsigned char c;
	in_port_t port = 0;

	len = strlen(ua);

	for (i = len-1; i >= 0; i--) {

		if (ua[i] == '.')
			dots++;

		if (dots == 2) {

			ua[i] = '\0';
			/*
			 * We use k to remember were to stick '.' back, since
			 * ua was kmem_allocateded from the pool len+1.
			 */
			k = i;
			if (inet_pton(af, ua, ap) == 1) {

				c = 0;

				for (j = i+1; j < len; j++) {
					if (ua[j] == '.') {
						port = c << 8;
						c = 0;
					} else if (ua[j] >= '0' &&
					    ua[j] <= '9') {
						c *= 10;
						c += ua[j] - '0';
					} else {
						ua[k] = '.';
						return (EINVAL);
					}
				}
				port += c;


				/* reset to network order */
				if (af == AF_INET) {
					*(uint32_t *)ap =
					    htonl(*(uint32_t *)ap);
					*pp = htons(port);
				} else {
					int ix;
					uint16_t *sap;

					for (sap = ap, ix = 0; ix <
					    sizeof (struct in6_addr) /
					    sizeof (uint16_t); ix++)
						sap[ix] = htons(sap[ix]);

					*pp = htons(port);
				}

				ua[k] = '.';
				return (0);
			} else {
				ua[k] = '.';
				return (EINVAL);
			}
		}
	}

	return (EINVAL);
}

/*ARGSUSED*/
static int
stripe_dev_construct(void *vstripe, void *foo, int bar)
{
	stripe_dev_t *stripe = vstripe;

	mutex_init(&stripe->std_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
stripe_dev_destroy(void *vstripe, void *foo)
{
	stripe_dev_t *stripe = vstripe;

	mutex_destroy(&stripe->std_lock);
}

/*ARGSUSED*/
static int
pnfs_layout_construct(void *vlayout, void *foo, int bar)
{
	pnfs_layout_t *layout = vlayout;

	mutex_init(&layout->plo_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&layout->plo_wait, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
pnfs_layout_destroy(void *vlayout, void *foo)
{

	pnfs_layout_t *layout = vlayout;

	mutex_destroy(&layout->plo_lock);
	cv_destroy(&layout->plo_wait);

	/* AVL for segments */
}

/*ARGSUSED*/
static int
file_io_read_construct(void *vrw, void *b, int c)
{
	file_io_read_t *rw = vrw;

	mutex_init(&rw->fir_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rw->fir_cv, NULL, CV_DEFAULT, NULL);
	list_create(&rw->fir_task_list, sizeof (read_task_t),
	    offsetof(read_task_t, rt_next));

	return (0);
}

/*ARGSUSED*/
static void
file_io_read_destroy(void *vrw, void *b)
{
	file_io_read_t *rw = vrw;

	mutex_destroy(&rw->fir_lock);
	cv_destroy(&rw->fir_cv);
	list_destroy(&rw->fir_task_list);
}

static file_io_read_t *
file_io_read_alloc()
{
	file_io_read_t *rc;

	rc = kmem_cache_alloc(file_io_read_cache, KM_SLEEP);
	rc->fir_remaining = 0;
	rc->fir_error = 0;
	rc->fir_eof = 0;
	rc->fir_eof_offset = 0;

	return (rc);
}

static void
read_task_free(read_task_t *iowork)
{
	nfs4_call_t *cp = iowork->rt_call;

	crfree(iowork->rt_cred);
	stripe_dev_rele(&iowork->rt_dev);
	if (iowork->rt_free_uio)
		kmem_free(iowork->rt_uio.uio_iov, iowork->rt_free_uio);
	if (cp)
		nfs4_call_rele(cp);
	kmem_cache_free(read_task_cache, iowork);
}

static file_io_write_t *
file_io_write_alloc()
{
	file_io_write_t *rc;

	rc = kmem_cache_alloc(file_io_write_cache, KM_SLEEP);
	rc->fiw_remaining = 0;
	rc->fiw_error = 0;
	rc->fiw_flags = 0;

	return (rc);
}

/*ARGSUSED*/
static int
file_io_write_construct(void *vwrite, void *foo, int bar)
{
	file_io_write_t *write = vwrite;

	mutex_init(&write->fiw_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&write->fiw_cv, NULL, CV_DEFAULT, NULL);
	list_create(&write->fiw_task_list, sizeof (write_task_t),
	    offsetof(write_task_t, wt_next));

	return (0);
}

/*ARGSUSED*/
static void
file_io_write_destroy(void *vwrite, void *foo)
{
	file_io_write_t *write = vwrite;

	mutex_destroy(&write->fiw_lock);
	cv_destroy(&write->fiw_cv);
	list_destroy(&write->fiw_task_list);
}

static void
write_task_free(write_task_t *w)
{
	nfs4_call_t *cp = w->wt_call;

	stripe_dev_rele(&w->wt_dev);
	crfree(w->wt_cred);
	if (cp)
		nfs4_call_rele(cp);
	kmem_cache_free(write_task_cache, w);
}

static file_io_commit_t *
file_io_commit_alloc()
{
	file_io_commit_t *rc;

	rc = kmem_cache_alloc(file_io_commit_cache, KM_SLEEP);
	rc->fic_remaining = 0;
	rc->fic_error = 0;

	return (rc);
}

/*ARGSUSED*/
static int
file_io_commit_construct(void *vcommit, void *foo, int bar)
{
	file_io_commit_t *commit = vcommit;

	mutex_init(&commit->fic_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&commit->fic_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
file_io_commit_destroy(void *vcommit, void *foo)
{
	file_io_commit_t *commit = vcommit;

	mutex_destroy(&commit->fic_lock);
	cv_destroy(&commit->fic_cv);
}

static void
commit_task_free(commit_task_t *p)
{
	nfs4_call_t *cp = p->cm_call;

	stripe_dev_rele(&p->cm_dev);
	crfree(p->cm_cred);
	if (cp)
		nfs4_call_rele(cp);
	kmem_cache_free(commit_task_cache, p);
}

static void
task_get_devicelist_free(task_get_devicelist_t *task)
{
	crfree(task->tgd_cred);
	MI4_RELE(task->tgd_mi);

	kmem_cache_free(task_get_devicelist_cache, task);
}

static void
task_layoutget_free(task_layoutget_t *task)
{
	if (task->tlg_flags & TLG_NOFREE)
		return;

	crfree(task->tlg_cred);
	MI4_RELE(task->tlg_mi);
	VN_RELE(task->tlg_vp);

	kmem_cache_free(task_layoutget_cache, task);
}

static void
task_layoutreturn_free(task_layoutreturn_t *task)
{
	if (task->tlr_vp)
		VN_RELE(task->tlr_vp);
	MI4_RELE(task->tlr_mi);
	crfree(task->tlr_cr);

	kmem_cache_free(task_layoutreturn_cache, task);
}

void
nfs4_pnfs_init_mi(mntinfo4_t *mi)
{
	mi->mi_pnfs_io_taskq = taskq_create_proc("pnfs_io_taskq",
	    nfs4_pnfs_io_nthreads,
	    minclsyspri, 1, nfs4_pnfs_io_maxalloc,
	    mi->mi_zone->zone_zsched, 0);
	mi->mi_pnfs_other_taskq = taskq_create_proc("pnfs_other_taskq",
	    nfs4_pnfs_other_nthreads,
	    minclsyspri, 1, nfs4_pnfs_other_maxalloc,
	    mi->mi_zone->zone_zsched, 0);
}

void
nfs4_pnfs_init_n4s(nfs4_server_t *n4sp)
{
	avl_create(&n4sp->s_devid_tree, nfs4_devid_compare,
	    sizeof (devnode_t), offsetof(devnode_t, dn_avl));
}

void
nfs4_pnfs_init()
{
	file_io_read_cache = kmem_cache_create("file_io_read_cache",
	    sizeof (file_io_read_t), 0,
	    file_io_read_construct, file_io_read_destroy, NULL,
	    NULL, NULL, 0);
	read_task_cache = kmem_cache_create("read_task_cache",
	    sizeof (read_task_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	file_io_write_cache = kmem_cache_create("file_io_write_cache",
	    sizeof (file_io_write_t), 0,
	    file_io_write_construct, file_io_write_destroy, NULL,
	    NULL, NULL, 0);
	write_task_cache = kmem_cache_create("write_task_cache",
	    sizeof (write_task_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	file_io_commit_cache = kmem_cache_create("file_io_commit_cache",
	    sizeof (file_io_commit_t), 0,
	    file_io_commit_construct, file_io_commit_destroy, NULL,
	    NULL, NULL, 0);
	commit_task_cache = kmem_cache_create("commit_task_cache",
	    sizeof (commit_task_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	stripe_dev_cache = kmem_cache_create("stripe_dev_cache",
	    sizeof (stripe_dev_t), 0,
	    stripe_dev_construct, stripe_dev_destroy, NULL,
	    NULL, NULL, 0);
	pnfs_layout_cache = kmem_cache_create("pnfs_layout_cache",
	    sizeof (pnfs_layout_t), 0,
	    pnfs_layout_construct, pnfs_layout_destroy, NULL,
	    NULL, NULL, 0);
	task_get_devicelist_cache = kmem_cache_create("task_get_devlist_cache",
	    sizeof (task_get_devicelist_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	task_layoutget_cache = kmem_cache_create("task_layoutget_cache",
	    sizeof (task_layoutget_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	task_layoutreturn_cache = kmem_cache_create("task_layoutreturn_cache",
	    sizeof (task_layoutreturn_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
}

void
pnfs_free_device(nfs4_server_t *np, devnode_t *dp)
{
	int i, ns;
	servinfo4_t *svp;	/* for the data servers */

	ASSERT(MUTEX_HELD(&np->s_lock));
	ASSERT(dp->dn_count == 0);

	if (dp->dn_flags & DN_INSERTED) {
		dp->dn_flags &= ~DN_INSERTED;
		avl_remove(&np->s_devid_tree, dp);
	}

	ns = dp->dn_ds_addrs.mpl_len;
	if (ns > 0) {
		xdr_free(xdr_nfsv4_1_file_layout_ds_addr4,
		    (char *)&dp->dn_ds_addrs);
		/*
		 * Free the servinfo4 from the device.  This will
		 * need to change when multiple servers are present
		 * in the ds_servers list.
		 */
		for (i = 0; i < ns; i++)
			if ((svp = dp->dn_server_list[i].ds_curr_serv) != NULL)
				sv4_free(svp);

		kmem_free(dp->dn_server_list, ns * sizeof (ds_info_t));
	}
	kmem_free(dp, sizeof (devnode_t));
}

/*
 * pnfs_orphan_device - turn the device node into an orphan, meaning
 * that is no longer in the device tree (and cannot be found again).
 * This is used when the nfs4_server for an MDS is decommissioned, yet
 * there is still an active reference, probably from a heartbeat thread.
 * We prod the heartbeat thread to terminate, destroying the session
 * and releasing the devnode, causing it to be freed.
 */
void
pnfs_orphan_device(nfs4_server_t *np, devnode_t *dp)
{
	int i, ns;
	servinfo4_t *svp;
	nfs4_server_t *xp;
	nfs4_error_t e;

	ASSERT(MUTEX_HELD(&np->s_lock));
	ASSERT(dp->dn_count > 0);

	dp->dn_flags |= DN_ORPHAN;
	/* Go ahead and remove it from the tree */
	if (dp->dn_flags & DN_INSERTED) {
		dp->dn_flags &= ~DN_INSERTED;
		avl_remove(&np->s_devid_tree, dp);
	}

	ns = dp->dn_ds_addrs.mpl_len;
	for (i = 0; i < ns; i++) {
		if ((svp = dp->dn_server_list[i].ds_curr_serv) != NULL) {
			mutex_exit(&np->s_lock);
			mutex_enter(&nfs4_server_lst_lock);
			if ((xp = find_nfs4_server_by_servinfo4(svp)) != NULL) {
				if (xp->s_devnode == dp) {
					mutex_exit(&xp->s_lock);
					nfs4destroy_session(xp, xp->s_hb_mi,
					    xp->s_hb_svp, &e,
					    N4DS_TERMINATE_HB_THREAD |
					    N4DS_DESTROY_INZONE);
					/*
					 * The current thread does not
					 * have a reference on the mi, but
					 * the HB thread does.  Using
					 * INZONE lets the HB thread
					 * clean up using its ref.
					 */
				} else
					mutex_exit(&xp->s_lock);
				nfs4_server_rele(xp);
			} else
				/* not found */
				mutex_exit(&nfs4_server_lst_lock);

			mutex_enter(&np->s_lock);
		}
	}
}

/*
 * pnfs_trash_devtree - remove all of the device nodes and remove
 * the device node tree from the nfs4_server_t.
 */
void
pnfs_trash_devtree(nfs4_server_t *n4sp)
{
	devnode_t *dp;
	void *cookie = NULL;

	mutex_enter(&n4sp->s_lock);
	while ((dp = avl_destroy_nodes(&n4sp->s_devid_tree, &cookie)) != NULL) {
		/*
		 * avl_destroy_nodes has removed the node from the
		 * tree, so clear DN_INSERTED so that the destructor
		 * doesn't do avl_remove.
		 */
		dp->dn_flags &= ~DN_INSERTED;
		if (dp->dn_count == 0)
			pnfs_free_device(n4sp, dp);
		else {
			/*
			 * pnfs_orphan_device may need to drop s_lock,
			 * so take a reference on the devnode to prevent
			 * it from disappearing.
			 */
			dp->dn_count++;
			pnfs_orphan_device(n4sp, dp);
			pnfs_rele_device(n4sp, dp);
		}
	}
	avl_destroy(&n4sp->s_devid_tree);
	mutex_exit(&n4sp->s_lock);
}

void
nfs4_pnfs_fini_mi(mntinfo4_t *mi)
{
	mutex_destroy(&mi->mi_pnfs_lock);
}

void
nfs4_pnfs_fini()
{
	kmem_cache_destroy(file_io_read_cache);
	kmem_cache_destroy(read_task_cache);
	kmem_cache_destroy(file_io_write_cache);
	kmem_cache_destroy(write_task_cache);
	kmem_cache_destroy(file_io_commit_cache);
	kmem_cache_destroy(commit_task_cache);
	kmem_cache_destroy(stripe_dev_cache);
	kmem_cache_destroy(pnfs_layout_cache);
	kmem_cache_destroy(task_get_devicelist_cache);
	kmem_cache_destroy(task_layoutget_cache);
	kmem_cache_destroy(task_layoutreturn_cache);
}


/*
 * pnfs_find_layouts returns a pnfs_lo_matches_t structure with a linked
 * list of pnfs_lol_t structures matching the layouts for the byte range
 * requested.  If a NULL is returned, no valid matching layouts were found.
 */
pnfs_lo_matches_t *
pnfs_find_layouts(nfs4_server_t *np, rnode4_t *rp, cred_t *cr,
layoutiomode4 iomode, offset4 off, length4 len, int use)
{
	pnfs_lo_matches_t	*lom = NULL;
	pnfs_layout_t		*lo;
	pnfs_lol_t		*nlol, *lol;
	int			dologet = TRUE;
	length4			length;
	offset4			offset = off;
	length4			end, lomend, loend;
	nfs4_fsidlt_t		lt, *newltp = NULL, *ltp;
	avl_index_t		where;
	rnode4_t		*rfound;
	int			rpadded = 0, cvstat = 0, count = 0;
#ifdef DEBUG
	offset4			prevend = 0;
#endif

	end = PNFS_LAYOUTEND;
	lom = kmem_zalloc(sizeof (*lom), KM_SLEEP);

	list_create(&lom->lm_layouts, sizeof (pnfs_lol_t),
	    offsetof(pnfs_lol_t, l_node));

	/*
	 * For recall if we find a layout marked PLO_GET, PLO_RETURN or
	 * PLO_RECALL, will will only return a lom with an empty
	 * lol list, which is marked LOM_DELAY.  This is to notify the
	 * caller that the thread needs to delay here to wait for
	 * the pnfs_layout states to change.  The recall thread when
	 * seeing this should return NFS4ERR_DELAY to the mds.
	 * For recall, if we find layouts in use, we will still add them
	 * to the lol list, but not wait for them in this function.
	 * The lom will be flagged as LOM_NEEDSWAIT, which can indicate to the
	 * caller that it needs to wait for the inuse counts to go ot zero for
	 * one or more layouts on the list.
	 */
	if (use == LOM_RECALL) {
		lom->lm_offset = offset = 0;
		lom->lm_length = length = PNFS_LAYOUTEND;
	} else {
		lom->lm_offset = offset = off;
		lom->lm_length = length = len;
	}

	mutex_enter(&rp->r_statelock);
	lt.lt_fsid.major = rp->r_srv_fsid.major;
	lt.lt_fsid.minor = rp->r_srv_fsid.minor;
	mutex_exit(&rp->r_statelock);


	mutex_enter(&np->s_lt_lock);
	ltp = avl_find(&np->s_fsidlt, &lt, &where);
	if (ltp == NULL) {
		mutex_exit(&np->s_lt_lock);
		newltp = kmem_zalloc(sizeof (*ltp), KM_SLEEP);
		mutex_enter(&np->s_lt_lock);
		ltp = avl_find(&np->s_fsidlt, &lt, &where);
		if (ltp) {
			kmem_free(newltp, sizeof (*newltp));
			mutex_enter(&ltp->lt_rlt_lock);
		} else {
			ltp = newltp;
			mutex_init(&ltp->lt_rlt_lock, NULL, MUTEX_DEFAULT,
			    NULL);
			avl_create(&ltp->lt_rlayout_tree, layoutcmp,
			    sizeof (rnode4_t), offsetof(rnode4_t, r_avl));
			cv_init(&ltp->lt_lowait, NULL, CV_DEFAULT, NULL);
			ltp->lt_fsid = lt.lt_fsid;
			mutex_enter(&ltp->lt_rlt_lock);
			avl_insert(&np->s_fsidlt, ltp, where);
		}
	} else {
		mutex_enter(&ltp->lt_rlt_lock);
	}
	ASSERT(MUTEX_HELD(&ltp->lt_rlt_lock));
	mutex_enter(&rp->r_lo_lock);
	rfound = avl_find(&ltp->lt_rlayout_tree, rp, &where);
	if (use == LOM_USE) {
		rp->r_activefinds++;
		if (rfound == NULL) {
			avl_insert(&ltp->lt_rlayout_tree, rp, where);
			rpadded = 1;
		}
	}
	mutex_enter(&rp->r_statelock);
	if (rp->r_fsidlt == NULL) {
		rp->r_fsidlt = ltp;
	}
	ASSERT(rp->r_fsidlt == ltp);
	mutex_exit(&rp->r_statelock);
	mutex_exit(&rp->r_lo_lock);

#ifdef DEBUG
	if (use == LOM_RETURN)
		ASSERT(off == 0 && length == PNFS_LAYOUTEND);
#endif

	lomend = (length == PNFS_LAYOUTEND ? PNFS_LAYOUTEND : off + length);

	/*
	 * If there are any bulk layoutrecalls active, no layouts will be
	 * returned.  We can enhance this later and wait here until bulk
	 * layoutsrecalls have completed.
	 */

	if (np->s_loflags & PNFS_CBLORECALL) {
		mutex_exit(&np->s_lt_lock);
		mutex_exit(&ltp->lt_rlt_lock);
		kmem_free(lom, sizeof (*lom));
		if (use == LOM_USE) {
			if (rpadded) {
				mutex_enter(&ltp->lt_rlt_lock);
				mutex_enter(&rp->r_lo_lock);
				rp->r_activefinds--;
				if (list_is_empty(&rp->r_layout) &&
				    rp->r_activefinds == 0) {
					ASSERT(ltp != NULL);
					avl_remove(&ltp->lt_rlayout_tree, rp);
				}
				mutex_exit(&rp->r_lo_lock);
				mutex_exit(&ltp->lt_rlt_lock);
			} else {
				mutex_enter(&rp->r_lo_lock);
				rp->r_activefinds--;
				mutex_exit(&rp->r_lo_lock);
			}
		}
		return (NULL);
	}

	if (ltp->lt_flags & PNFS_CBLORECALL) {
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
		kmem_free(lom, sizeof (*lom));

		if (use == LOM_USE) {
			if (rpadded) {
				mutex_enter(&ltp->lt_rlt_lock);
				mutex_enter(&rp->r_lo_lock);
				if (list_is_empty(&rp->r_layout) &&
				    rp->r_activefinds == 0) {
					ASSERT(ltp != NULL);
					avl_remove(&ltp->lt_rlayout_tree, rp);
				}
				rp->r_activefinds--;
				mutex_exit(&rp->r_lo_lock);
				mutex_exit(&ltp->lt_rlt_lock);
			} else {
				mutex_enter(&rp->r_lo_lock);
				rp->r_activefinds--;
				mutex_exit(&rp->r_lo_lock);
			}
		}
		return (NULL);
	}

	/*
	 * If we are gathering the layouts to do I/O or a commit we will
	 * mark the layouts as "inuse" to prevent the layouts from being
	 * returned while in use.  We also need to track if layouts are
	 * "in use" at the fsid level and the clientid level. This is done
	 * in the nfs4_fsidlt and nfs4_server structures.
	 * The inuse counts in the nfs4_server and nfs4_fsid cause a
	 * bulk layoutrecall from blasting away layouts that may be in use,
	 * or are about to be in use.
	 *
	 * Here are a couple things that may look strange but are
	 * expected:
	 * 1) On the first layoutget for the clientid the nfs4_server's
	 * lo_inuse can be 1, but the locnt is still 0.  Same goes for the
	 * first layoutget for an fsid.  This occurs because we increment
	 * the inuse cnt before we increment the locnt when new layouts
	 * are obtained with layoutget OTW. This is okay as we really
	 * do not have the layout yet.  The bulk
	 * layoutrecall threads will still se the layoutcount as 0
	 * and return NFS4ERR_NOMATCHING_LAYOUT.
	 *
	 * 2) If we receive a bulk layoutrecall after incrementing the
	 * loinuse counters, but before we do the layoutget OTW, and we
	 * determine we need to do a LAYOUTGET otw, then the
	 * pnfs_task_layoutget function will detect this.  It will see that
	 * the PNFS_CBLORECALL bit set in the nfs4_server or nfs4_fsid,
	 * and will return doing nothing.  At this point the bulk layoutrecall
	 * thread will be waiting for the loinuse counter to go to zero.
	 * pnfs_find_layouts will find no matching layouts, decrement
	 * the loinuse counter and wake the bulk layoutrecall thread.
	 *
	 * 3) We could also be gathering the layouts for a layoutreturn
	 * for rnode inactivation for example.  In this case the use flag
	 * will be LOM_RETURN.  We have not incremented any lo_inuse
	 * counters.  A bulk layoutrecall can occur while pnfs_find_layouts
	 * is building the list of layouts.  This is okay.  The bulk layout
	 * recall will hold the r_lo_lock and simply pnfs_layout_rele these
	 * layouts.  The list is protected by the r_lo_lock.  These layouts
	 * will be marked BAD, so if the bulk layoutrecall occurs before
	 * pnfs_find_layouts hold the r_lo_lock, it will simply ignore
	 * these bad layouts.  If the bulk layoutrecall comes in after
	 * the layoutreturn is into pnfs_task_layoutreturn, it will see
	 * the bulkblock incremented and return NFS4ERR_DELAY.
	 */

	if (use == LOM_USE || use == LOM_COMMIT) {
		np->s_loinuse++;
		ltp->lt_loinuse++;
	}

	mutex_exit(&ltp->lt_rlt_lock);
	mutex_exit(&np->s_lt_lock);

	mutex_enter(&rp->r_lo_lock);
	lo = list_head(&rp->r_layout);

	while ((dologet == TRUE) || (dologet == FALSE && lo != NULL)) {
		/*
		 * Any Layouts to process?  If not we have reached the end
		 * of the list.
		 */
		if (lo == NULL) {
			if (use != LOM_USE)
				break;
			/*
			 * We need to do layoutget OTW.  If we are holding
			 * any layouts in the lom list, we need to drop these
			 * because we will re-search this list again after
			 * the layoutget.  Layoutget will drop the
			 * r_statelock and the list we have already built
			 * may change.
			 */
			lol = list_head(&lom->lm_layouts);
			while (lol) {
				if (lol->l_layout)
					pnfs_layout_rele(rp, lol->l_layout);
				nlol = list_next(&lom->lm_layouts, lol);
				list_remove(&lom->lm_layouts, lol);
				kmem_free(lol, sizeof (*lol));
				lol = nlol;
			}
			ASSERT(rp->r_fsidlt != NULL);
			pnfs_layoutget(RTOV(rp), cr, off, iomode);
			mutex_enter(&rp->r_lo_lock);
			offset = lom->lm_offset;
#ifdef DEBUG
			prevend = 0;
#endif
			loend = 0;
			lo = list_head(&rp->r_layout);
			dologet = FALSE;
			continue;
		}

		/*
		 * Is this layout BAD, if so,skip.  If it is
		 * unavailable put it in the list only if it is
		 * for the LOM_USE case.  This tells thes I/O
		 * path that this section must go to proxy I/O.
		 * It also prevents another layoutget.
		 */
		if ((lo->plo_flags & PLO_BAD) || (use != LOM_USE &&
		    (lo->plo_flags & PLO_UNAVAIL))) {
			lo = list_next(&rp->r_layout, lo);
				continue;
		}

		/*
		 * If the offset we are looking for is greater than the
		 * end of this layout's offset, get the next layout.
		 */
		loend = lo->plo_length == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
		    lo->plo_offset + lo->plo_length;
#ifdef DEBUG
		ASSERT(prevend != PNFS_LAYOUTEND);
		if (prevend != lo->plo_offset)
			cmn_err(CE_WARN, "%llu, %llu %p",
			    (unsigned long long)prevend,
			    (unsigned long long)lo->plo_offset,
			    (void *)lo);
		ASSERT(prevend == lo->plo_offset);
		prevend = loend;
#endif
		if (offset >= loend) {
			lo = list_next(&rp->r_layout, lo);
			continue;
		}

		/*
		 * The only gaps we will see in the layout range of layouts on
		 * an rnode are at the end of the file.  Thus if the offset we
		 * are looking for is less than the end of this layout, this
		 * must be the layout we are searching for.
		 */
		ASSERT(offset >= lo->plo_offset);

		/*
		 * We need this layout!
		 */
		pnfs_layout_hold(rp, lo);

		/*
		 * If we stumble acrossed a layout that
		 * has a GET/RETURN or RECALL in progress,
		 * wait for that to finish.  We must then
		 * release all lol's we have and start over after waking
		 * because we had to drop the r_statelock which
		 * locks the rnodes layout list.  The lol's and the
		 * layouts they map could change by the time we
		 * are woken up again.  We must drop everything,
		 * and start over again.
		 */
		if (lo->plo_flags & (PLO_GET|PLO_RETURN|PLO_RECALL)) {
			/*
			 * If this is a layoutrecall wanting these layouts
			 * don't wait!  Simply set the flag in the lom
			 * release anything we have grabbed, and return.
			 */
			if (use == LOM_RECALL) {
				lom->lm_flags |= LOMSTAT_DELAY;
			} else {
				lo->plo_flags |= PLO_LOWAITER;
				cvstat = 0;
				while ((lo->plo_flags &
				    (PLO_GET|PLO_RETURN|PLO_RECALL)) &&
				    !(lo->plo_flags & PLO_BAD) &&
				    cvstat != EINTR) {
					cvstat = cv_wait_sig(&lo->plo_wait,
					    &rp->r_lo_lock);
				}
				lo->plo_flags &= ~PLO_LOWAITER;
				if (cvstat == EINTR)
					lom->lm_status = EINTR;
			}

			lol = list_head(&lom->lm_layouts);
			while (lol) {
				if (lol->l_layout)
					pnfs_layout_rele(rp, lol->l_layout);
				nlol = list_next(&lom->lm_layouts, lol);
				list_remove(&lom->lm_layouts, lol);
				kmem_free(lol, sizeof (*lol));
				lol = nlol;
			}
			/*
			 * Start over.	Do the pnfs_layout_rele
			 * below since we did the hold of this layout
			 * above, but this layout did not exist in the
			 * lom->lm_layouts list yet.
			 */
			pnfs_layout_rele(rp, lo);
			if (use == LOM_RECALL || lom->lm_status == EINTR) {
				mutex_exit(&rp->r_lo_lock);
				return (lom);
			}
			lo = list_head(&rp->r_layout);
			offset = lom->lm_offset;
#ifdef DEBUG
			prevend = 0;
#endif
			loend = 0;
			lom->lm_flags &= ~LOMSTAT_MATCHFOUND;
			if (use == LOM_RECALL) {
				mutex_exit(&rp->r_lo_lock);
				return (lom);
			}
			continue;
		}

		if (use == LOM_RETURN)
			lo->plo_flags |= PLO_RETURN;
		else if (use == LOM_RECALL)
			lo->plo_flags |= PLO_RECALL;

		if (use == LOM_RECALL && lo->plo_inusecnt != 0) {
			/*
			 * We want to return this layout either
			 * from a layoutreturn or a layoutrecall, however
			 * the layout is in use.
			 */
			lom->lm_flags |= LOMSTAT_NEEDSWAIT;
		} else if (use == LOM_RETURN && lo->plo_inusecnt != 0) {
			lo->plo_flags |= PLO_LOWAITER;
			cvstat = 0;
			while (lo->plo_inusecnt && cvstat != EINTR) {
				cvstat = cv_wait_sig(&lo->plo_wait,
				    &rp->r_lo_lock);
			}
			lo->plo_flags &= ~PLO_LOWAITER;
			if (cvstat == EINTR)
				lom->lm_status = EINTR;

			if (lom->lm_status == EINTR) {
				lol = list_head(&lom->lm_layouts);
				while (lol) {
					if (lol->l_layout) {
						lol->l_layout->
						    plo_flags &= ~PLO_RETURN;
						pnfs_layout_rele(rp,
						    lol->l_layout);
					}
					nlol = list_next(&lom->lm_layouts,
					    lol);
					list_remove(
					    &lom->lm_layouts,
					    lol);
					kmem_free(lol,
					    sizeof (*lol));
					lol = nlol;
				}
				mutex_exit(&rp->r_lo_lock);
				return (lom);
			}
			/*
			 * XXXKLR - We dropped the r_lo_lock, do we
			 * have to recheck our list, could the layout
			 * have changed?  We set the RETURN/RECALL,
			 * and have holds on the layout, what could
			 * change other than the inusecnt?  Could be
			 * marked PLO_BAD by recovery, but layout
			 * recovery is not yet coded.  Make sure to
			 * check for this here when recovery is coded.
			 */
		}


		lol = kmem_zalloc(sizeof (*lol), KM_SLEEP);
		lol->l_layout = lo;
		lol->l_offset = lo->plo_offset;
		lol->l_length = lo->plo_length;
		list_insert_tail(&lom->lm_layouts, lol);
		lom->lm_flags |= LOMSTAT_MATCHFOUND;

		end = lo->plo_length == PNFS_LAYOUTEND ? lo->plo_length :
		    lo->plo_length + lo->plo_offset;
		offset = end;

		if (end >= lomend) {
			/*
			 * We have found all that we need.
			 */
			break;
		}
		lo = list_next(&rp->r_layout, lo);
	}

	if ((use == LOM_USE || use == LOM_COMMIT) &&
	    (!(list_is_empty(&lom->lm_layouts)))) {
		count = 0;
		for (lol = list_head(&lom->lm_layouts); lol;
		    lol = list_next(&lom->lm_layouts, lol)) {
			/*
			 * Don't count the unavailable layouts
			 * against the inuse counters.
			 */
			if (!(lol->l_layout->plo_flags & PLO_UNAVAIL)) {
				count++;
				lol->l_layout->plo_inusecnt++;
			}
		}
		/*
		 * Increment the layout in use counters on the
		 * nfs4_server and nfs4_fsidlt.  Add the total
		 * count of layouts found minus 1 to account for the
		 * initial inuse counter added at the beginning of this
		 * function.
		 */
		mutex_exit(&rp->r_lo_lock);
		mutex_enter(&np->s_lt_lock);
		mutex_enter(&ltp->lt_rlt_lock);
		np->s_loinuse += count - 1;
		ltp->lt_loinuse += count - 1;
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
	} else {
		mutex_exit(&rp->r_lo_lock);
	}


	/*
	 * If there are not any layouts in the lom, just free it and return
	 * NULL.
	 */
	if (list_is_empty(&lom->lm_layouts)) {
		kmem_free(lom, sizeof (*lom));
		lom = NULL;
		/*
		 * If we found no matches we need to
		 * decrement the inuse counters added at the
		 * beginning of this function.
		 */
		if (use == LOM_USE || use == LOM_COMMIT) {
			mutex_enter(&np->s_lt_lock);
			mutex_enter(&ltp->lt_rlt_lock);
			np->s_loinuse -= 1;
			if (np->s_loinuse == 0)
				cv_broadcast(&np->s_lowait);
			ltp->lt_loinuse -= 1;
			if (ltp->lt_loinuse == 0)
				cv_broadcast(&ltp->lt_lowait);
			mutex_exit(&ltp->lt_rlt_lock);
			mutex_exit(&np->s_lt_lock);
		}
	} else {
		lol = list_head(&lom->lm_layouts);
		lom->lm_offset = lol->l_offset;
		lol = list_tail(&lom->lm_layouts);
		lom->lm_length = lol->l_length == PNFS_LAYOUTEND ?
		    PNFS_LAYOUTEND : lom->lm_offset + (lol->l_offset +
		    lol->l_length) - 1;
	}

	if (use == LOM_USE) {
		if (rpadded) {
			mutex_enter(&ltp->lt_rlt_lock);
			mutex_enter(&rp->r_lo_lock);
			if (list_is_empty(&rp->r_layout) &&
			    rp->r_activefinds == 0) {
				ASSERT(ltp != NULL);
				avl_remove(&ltp->lt_rlayout_tree, rp);
			}
			rp->r_activefinds--;
			mutex_exit(&rp->r_lo_lock);
			mutex_exit(&ltp->lt_rlt_lock);
		} else {
			mutex_enter(&rp->r_lo_lock);
			rp->r_activefinds--;
			mutex_exit(&rp->r_lo_lock);
		}
	}
	return (lom);
}


void
pnfs_release_layouts(nfs4_server_t *np, rnode4_t *rp, pnfs_lo_matches_t *lom,
int use)
{
	pnfs_lol_t	*lol = NULL, *nlol;
	pnfs_layout_t	*layout = NULL;
	nfs4_fsidlt_t	*ltp = NULL;
	int		count = 0;

	mutex_enter(&rp->r_lo_lock);

	ASSERT(lom != NULL);
	lol = list_head(&lom->lm_layouts);

	if (lol != NULL) {
		layout = lol->l_layout;
	} else {
		mutex_exit(&rp->r_lo_lock);
		kmem_free(lom, sizeof (*lom));
		return;
	}

	mutex_enter(&rp->r_statelock);
	ltp = rp->r_fsidlt;
	ASSERT(ltp != NULL);
	mutex_exit(&rp->r_statelock);

	while (layout) {
		if (use == LOM_USE || use == LOM_COMMIT) {
			/*
			 * For unavailable layouts all we really need
			 * to do is decrement the reference count and
			 * free the lol/lom.
			 */
			if (!(layout->plo_flags & PLO_UNAVAIL)) {
				count++;
				ASSERT(layout->plo_inusecnt != 0);
				layout->plo_inusecnt--;
				if ((layout->plo_flags & PLO_LOWAITER) &&
				    layout->plo_inusecnt == 0) {
					cv_broadcast(&layout->plo_wait);
				}
			}
		}

		if (use == LOM_RETURN) {
			ASSERT(layout->plo_inusecnt == 0);
			layout->plo_flags &= ~PLO_RETURN;
			cv_broadcast(&layout->plo_wait);
		}

		if (use == LOM_RECALL) {
			ASSERT(layout->plo_inusecnt == 0);
			layout->plo_flags &= ~PLO_RECALL;
			cv_broadcast(&layout->plo_wait);
		}

		pnfs_layout_rele(rp, layout);

		lol->l_layout = NULL;
		nlol = list_next(&lom->lm_layouts, lol);
		list_remove(&lom->lm_layouts, lol);
		kmem_free(lol, sizeof (*lol));
		lol = nlol;
		if (lol != NULL)
			layout = lol->l_layout;
		else
			layout = NULL;
	}
	mutex_exit(&rp->r_lo_lock);

	ASSERT(list_is_empty(&lom->lm_layouts));
	kmem_free(lom, sizeof (*lom));

	if ((use != LOM_USE && use != LOM_COMMIT) || count == 0)
		return;

	mutex_enter(&np->s_lt_lock);
	mutex_enter(&ltp->lt_rlt_lock);

	if (use == LOM_USE || use == LOM_COMMIT) {
		np->s_loinuse -= count;
		if (np->s_loinuse == 0)
			cv_broadcast(&np->s_lowait);
		ASSERT(ltp->lt_loinuse > 0);
		ltp->lt_loinuse -= count;
		if (ltp->lt_loinuse == 0)
			cv_broadcast(&ltp->lt_lowait);
	}
	mutex_exit(&ltp->lt_rlt_lock);
	mutex_exit(&np->s_lt_lock);
}


/*
 * Find pages that touch the stripe in the layout
 * that have been written but not committed
 * and mark them modified so they will be written again.
 */
static void
pnfs_set_mod(vnode_t *vp, pnfs_layout_t *layout, uint32_t sui)
{
	page_t *pp;
	kmutex_t *vphm;
	rnode4_t *rp;
	offset4 ps, pe, ls, le;
	uint32_t is, ie;
	int match;

	rp = VTOR4(vp);
	if (IS_SHADOW(vp, rp))
		vp = RTOV4(rp);

	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);

	if ((pp = vp->v_pages) == NULL) {
		mutex_exit(vphm);
		return;
	}

	ls = layout->plo_offset;
	le = ls + layout->plo_length - 1;

	do {
		if (pp->p_fsdata == C_NOCOMMIT4)
			continue;

		ps = pp->p_offset;
		pe = ps + PAGESIZE - 1;

		/* skip this page if no overlap with the layout */
		if (!(((ls <= ps) && (ps <= le)) || ((ls <= pe) && (pe <= le))))
			continue;

		match = 0;

		/* convert byte offsets to stripe unit offsets */
		ps /= layout->plo_stripe_unit;
		pe /= layout->plo_stripe_unit;

		/*
		 * If the page spans a full stripe or more,
		 * then the page needs to be rewritten.
		 */
		if ((pe - ps + 1) >= layout->plo_stripe_count) {
			match = 1;
		} else {
			/*
			 * If a portion of the page overlaps the stripe unit
			 * index (sui) that failed, then the page needs
			 * to be rewritten.
			 */
			is = ps % layout->plo_stripe_count;
			ie = pe % layout->plo_stripe_count;
			match = (is <= ie) ?
			    (is <= sui && sui <= ie) : (sui <= ie || is <= sui);
		}
		if (match) {
			hat_setmod(pp);
			pp->p_fsdata = C_NOCOMMIT4;
		}

	} while ((pp = pp->p_vpnext) != vp->v_pages);
	mutex_exit(vphm);
}

static void
pnfs_set_pageerror(page_t *pp, pnfs_layout_t *layout, uint32_t sui)
{
	page_t *savepp;
	offset4 ps, pe, ls, le;
	uint32_t is, ie;
	int match;

	ls = layout->plo_offset;
	le = ls + layout->plo_length - 1;

	savepp = pp;
	do {
		if (pp->p_fsdata == C_NOCOMMIT4)
			continue;

		ps = pp->p_offset;
		pe = ps + PAGESIZE - 1;

		if (!(((ls <= ps) && (ps <= le)) || ((ls <= pe) && (pe <= le))))
			continue;

		match = 0;

		ps /= layout->plo_stripe_unit;
		pe /= layout->plo_stripe_unit;
		if ((pe - ps + 1) >= layout->plo_stripe_count) {
			match = 1;
		} else {
			is = ps % layout->plo_stripe_count;
			ie = pe % layout->plo_stripe_count;
			match = (is <= ie) ?
			    (is <= sui && sui <= ie) : (sui <= ie || is <= sui);
		}
		if (match) {
			pp->p_fsdata |= C_ERROR4;
		}

	} while ((pp = pp->p_next) != savepp);
}

/*
 * Translate the contents of the netaddr4 into a netbuf and knetconfig.
 */
static int
netaddr2netbuf(netaddr4 *nap, struct netbuf *nbp, struct knetconfig *kncp)
{
	char *devname;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	vnode_t *vp;
	int error;
	int af;

	if (nap == NULL)
		return (EINVAL);

	if ((nap->na_r_netid == NULL) || (nap->na_r_netid[0] == '\0') ||
	    (nap->na_r_addr == NULL) || (nap->na_r_addr[0] == '\0'))
		return (EINVAL);

	kncp->knc_semantics = NC_TPI_COTS;
	if (strcmp(nap->na_r_netid, "tcp") == 0) {
		kncp->knc_protofmly = "inet";
		kncp->knc_proto = "tcp";
		devname = "/dev/tcp";
		af = AF_INET;
	} else if (strcmp(nap->na_r_netid, "tcp6") == 0) {
		kncp->knc_protofmly = "inet6";
		kncp->knc_proto = "tcp";
		devname = "/dev/tcp6";
		af = AF_INET6;
	} else {
		return (EINVAL);
	}

	error = lookupname(devname, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (error)
		return (error);
	if (vp->v_type != VCHR) {
		VN_RELE(vp);
		return (EINVAL);
	}

	kncp->knc_rdev = vp->v_rdev;
	VN_RELE(vp);

	if (af == AF_INET) {
		nbp->maxlen = nbp->len = sizeof (struct sockaddr_in);
		nbp->buf = kmem_zalloc(nbp->maxlen, KM_SLEEP);
		addr4 = (struct sockaddr_in *)nbp->buf;
		addr4->sin_family = af;
		error = pnfs_uaddr2sockaddr(af, nap->na_r_addr,
		    &addr4->sin_addr, &addr4->sin_port);
	} else if (af == AF_INET6) {
		nbp->maxlen = nbp->len = sizeof (struct sockaddr_in6);
		nbp->buf = kmem_zalloc(nbp->maxlen, KM_SLEEP);
		addr6 = (struct sockaddr_in6 *)nbp->buf;
		addr6->sin6_family = af;
		error = pnfs_uaddr2sockaddr(af, nap->na_r_addr,
		    &addr6->sin6_addr, &addr6->sin6_port);
	} else { /* Unknown address family (Can't happen unless we goofed) */
		return (EINVAL);
	}

	if (error)
		kmem_free(nbp->buf, nbp->maxlen);

	return (error);
}

/*
 * Build a servinfo4 structure for the server described by a netaddr4.
 * The caller is responsible for freeing the resulting servinfo4
 * via sv4_free().  The new servinfo4 will inherit characteristics from
 * the servinfo4 for the mi.
 */
static int
netaddr4_to_servinfo4(
	netaddr4 *nap,		/* netaddr4 from the devid_tree */
	mntinfo4_t *mi,		/* mntinfo4 from MDS */
	servinfo4_t **svpp)	/* returned servinfo4 */
{
	struct netbuf nb;
	struct knetconfig knc;
	servinfo4_t *svp;

	if (nap == NULL || mi == NULL) {
		return (EINVAL);
	}

	if (netaddr2netbuf(nap, &nb, &knc)) {
		return (EINVAL);
	}
	svp = new_servinfo4(mi, nap->na_r_addr, &knc, &nb, SV4_ISA_DS);
	kmem_free(nb.buf, nb.maxlen);
	*svpp = svp;
	return (0);
}

/*
 * nfs4_activate_server - Find and activate an nfs4_server for
 * the data server described by a servinfo4.  If necessary, make a new
 * nfs4_server and perform an Exchange ID and Create Session.  This will
 * also cause a new heartbeat thread to be created and that thread will
 * hold a reference on the devnode until it exits.
 * On success, return 0; otherwise, return the error.
 */
static int
nfs4_activate_server(mntinfo4_t *mi, nfs4_server_t *mdsp, servinfo4_t *svp,
    devnode_t *dip)
{
	nfs4_server_t *np;
	nfs4_error_t e = {0, 0, 0};
	int ri;

retry:
	mutex_enter(&nfs4_server_lst_lock);
	if ((np = find_nfs4_server_by_servinfo4(svp)) != NULL) {
		/*
		 * N.B., find_nfs4_server_by_servinfo4() drops the
		 * nfs4_server_lst_lock when it returns a match
		 */
		if (np->s_flags & N4S_EXID_FAILED) {
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			return (EIO);
		}

		if (!(np->s_flags & (N4S_CLIENTID_SET|N4S_SESSION_CREATED))) {
			/* Not ready for prime time */
			cv_wait(&np->s_clientid_pend, &np->s_lock);
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			goto retry;
		}
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		return (0);
	}

	np = add_new_nfs4_server(svp, kcred);
	ASSERT(np->s_devnode == NULL);
	np->s_devnode = dip;
	mutex_exit(&np->s_lock);
	mutex_exit(&nfs4_server_lst_lock);

	mutex_enter(&mdsp->s_lock);
	dip->dn_count++;
	mutex_exit(&mdsp->s_lock);

	/*
	 * XXXrsb - Either we should use start_op/end_op or
	 * nfs4exchange_id_otw() should use start_op/end_op
	 * before it calls (some form of) rfs4call()
	 */
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);

	nfs4exchange_id_otw(mi, svp, kcred, np, &e, &ri);

	nfs_rw_exit(&mi->mi_recovlock);

	if (e.error || e.stat) {
		mutex_enter(&mdsp->s_lock);
		pnfs_rele_device(mdsp, dip);
		mutex_exit(&mdsp->s_lock);

		mutex_enter(&np->s_lock);
		np->s_flags |= N4S_EXID_FAILED;
		cv_broadcast(&np->s_clientid_pend);
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		cmn_err(CE_WARN,
		    "nfs4_activate_server: exchange_id failed %d, %d",
		    e.error, e.stat);
		if (e.error == 0)
			e.error = geterrno4(e.stat);
	} else {
		/* All good, let's go home */
		nfs4_server_rele(np);
	}
	return (e.error);
}

void
pnfs_rele_device(nfs4_server_t *np, devnode_t *dp)
{
	ASSERT(MUTEX_HELD(&np->s_lock));
	ASSERT(dp->dn_count > 0);
	dp->dn_count--;
	if (dp->dn_count > 0)
		return;
	/*
	 * No point in caching a failed getdeviceinfo.  Throw away
	 * the devnode.
	 *
	 * If the device node is an orphan, then go ahead and
	 * free it up.
	 */
	if (dp->dn_flags & DN_GDI_FAILED ||
	    dp->dn_flags & DN_ORPHAN) {
		pnfs_free_device(np, dp);
		return;
	}

	/*
	 * If neither DN_GDI_FAILED nor DN_ORPHAN is set, then
	 * the devnode remains cached.
	 */
}

static int
pnfs_get_device(mntinfo4_t *mi, nfs4_server_t *np, deviceid4 did, cred_t *cr,
    devnode_t **dpp, int otwflag)
{
	devnode_t *dp = NULL;
	devnode_t key;	/* Dummy, only used as key for avl_find() */
	avl_index_t where;
	int error;

	/*
	 * Explicitly setting it NULL here in case *dpp is not NULL when passed.
	 */
	*dpp = NULL;

	DEV_ASSIGN(key.dn_devid, did);
	dp = avl_find(&np->s_devid_tree, &key, &where);

	if (dp == NULL && (otwflag & PGD_NO_OTW)) {
		return (ENODEV);
	}
	if (dp == NULL && (otwflag & PGD_OTW)) {
		/*
		 * The devid is not in the tree, go get the device info.
		 * Create a placeholder devnode and stick it in the tree.
		 */
		dp = pnfs_create_device(np, did, where);
		dp->dn_flags |= DN_GDI_INFLIGHT;
		mutex_exit(&np->s_lock);

		error = pnfs_getdeviceinfo(mi, dp, cr);

		mutex_enter(&np->s_lock);
		dp->dn_flags &= ~DN_GDI_INFLIGHT;
		if (dp->dn_count > 1)
			cv_broadcast(dp->dn_cv);
		if (error) {
			dp->dn_flags |= DN_GDI_FAILED;
			pnfs_rele_device(np, dp);
		}
		else
			*dpp = dp;
		return (error);
	}

	if ((dp->dn_flags & DN_GDI_INFLIGHT) && (otwflag & PGD_NO_OTW)) {
		return (EINPROGRESS);
	}

	dp->dn_count++;

	while (dp->dn_flags & DN_GDI_INFLIGHT)
		cv_wait(dp->dn_cv, &np->s_lock);

	if (dp->dn_flags & DN_GDI_FAILED) {
		pnfs_rele_device(np, dp);
		error = EIO;
	} else {
		error = 0;
		*dpp = dp;
	}
	return (error);
}

/*
 * pnfs_change_device - handle a device change notification.  This
 * function is invoked by a thread running the NFSv4.1 callback program.
 * The goal is to find the device node associated with the device ID
 * passed by the server and delete it.  This will cause the code using
 * the device to notice its disappearance, and re-issue GETDEVICEINFO
 * (to be implemented).
 */
nfsstat4
pnfs_change_device(nfs4_server_t *np, notify_deviceid_change4 *ndc)
{
	devnode_t *dp;
	nfsstat4 stat;

	if (ndc->ndc_layouttype != LAYOUT4_NFSV4_1_FILES)
		return (NFS4ERR_UNKNOWN_LAYOUTTYPE);

	/*
	 * Passing NULL for mi is ok, since it's only needed when the
	 * call goes OTW, which we never want here.  Besides, we don't
	 * really have an mi to pass.  Same for cr.
	 */
	mutex_enter(&np->s_lock);
	if (pnfs_get_device(NULL, np, ndc->ndc_deviceid, NULL, &dp,
	    PGD_NO_OTW) != 0) {
		/*
		 * The device ID isn't found.  The client may have already
		 * reaped it.  Return OK.
		 */
		DTRACE_PROBE(nfsc__i__no_device);
		stat = NFS4_OK;
	} else {

		if (dp->dn_count > 0) {
			/*
			 * XXX - this is interim code.
			 *
			 * This is the interesting case, where the device
			 * is busy.  We should mark the devnode as destroyed
			 * and let the refs wither away.  That also implies
			 * that stripe_dev_t must point to the device node
			 * (and hold a reference), so that as new operations
			 * using its data are done, the callers notice its
			 * demise and back off, ultimately issuing a new
			 * getdeviceinfo to fetch the new stuffs
			 */
			DTRACE_PROBE(nfsc__i__busy_device);
			stat = NFS4_OK;
		} else {
			/*
			 * The device has changed, just remove it, we'll
			 * refetch it again later, if needed
			 */
			DTRACE_PROBE(nfsc__i__device_culled);
			avl_remove(&np->s_devid_tree, dp);
			stat = NFS4_OK;
		}
	}
	mutex_exit(&np->s_lock);
	return (stat);
}

/*
 * pnfs_delete_device - handle a device delete notification.  This
 * function is invoked by a thread running the NFSv4.1 callback program.
 * The goal is to find the device node associated with the device ID
 * passed by the server and delete it.
 */
nfsstat4
pnfs_delete_device(nfs4_server_t *np, notify_deviceid_delete4 *ndd)
{
	devnode_t *dp = NULL;
	nfsstat4 stat;

	if (ndd->ndd_layouttype != LAYOUT4_NFSV4_1_FILES)
		return (NFS4ERR_UNKNOWN_LAYOUTTYPE);

	mutex_enter(&np->s_lock);
	if (pnfs_get_device(NULL, np, ndd->ndd_deviceid, NULL, &dp,
	    PGD_NO_OTW) != 0) {
		DTRACE_PROBE(nfsc__i__no_device);
		stat = NFS4_OK;
	} else {

		if (dp->dn_count > 0) {
			DTRACE_PROBE(nfsc__i__busy_device);
			stat = NFS4_OK;
		} else {
			DTRACE_PROBE(nfsc__i__device_culled);
			avl_remove(&np->s_devid_tree, dp);
			stat = NFS4_OK;
		}
	}
	mutex_exit(&np->s_lock);
	return (stat);
}

static int
stripe_dev_prepare(
	mntinfo4_t *mi,
	stripe_dev_t *dev,
	uint32_t first_stripe_index,
	uint32_t stripe_num,
	cred_t *cr)
{
	devnode_t *dip = NULL;
	int ndx;
	int mpl_index;
	multipath_list4 *mpl_item;
	netaddr4 *nap;
	nfs4_server_t *mdsp;
	servinfo4_t	*svp;	/* servinfo4 for the target DS */
	int error = 0;
	deviceid4 did;

	/*
	 * Check to see if the stripe dev is already initialized,
	 * if so, just return
	 */
	mutex_enter(&dev->std_lock);
	if (dev->std_svp != NULL) {
		mutex_exit(&dev->std_lock);
		return (0);
	}

	DEV_ASSIGN(did, dev->std_devid);
	mutex_exit(&dev->std_lock);

	mdsp = find_nfs4_server_nolock(mi);
	if (mdsp == NULL)
		return (ENODEV);
	if ((error = pnfs_get_device(mi, mdsp, did, cr, &dip, PGD_OTW))) {
		nfs4_server_rele_lockt(mdsp);
		return (error);
	}
	ASSERT(dip != NULL);

	/*
	 * Range check stripe_num and first_stripe_index against
	 * the length of the indices array.
	 */
	if (stripe_num >= dip->dn_ds_addrs.stripe_indices_len ||
	    first_stripe_index >= dip->dn_ds_addrs.stripe_indices_len) {
		pnfs_rele_device(mdsp, dip);
		nfs4_server_rele_lockt(mdsp);
		cmn_err(CE_WARN, "stripe_dev_prepare: stripe_num or "
		    "first_stripe_index out of range: %d, %d, %d",
		    stripe_num, first_stripe_index,
		    dip->dn_ds_addrs.stripe_indices_len);
		return (EIO);
	}
	ndx = (stripe_num+first_stripe_index) %
	    dip->dn_ds_addrs.stripe_indices_len;
	mpl_index = dip->dn_ds_addrs.stripe_indices[ndx];
	/*
	 * Range check the index from the indices
	 */
	if (mpl_index >= dip->dn_ds_addrs.mpl_len) {
		pnfs_rele_device(mdsp, dip);
		nfs4_server_rele_lockt(mdsp);
		cmn_err(CE_WARN, "strip_dev_prepare: mpl_index out "
		    "of range: %d, %d", mpl_index, dip->dn_ds_addrs.mpl_len);
		return (EIO);
	}
	mpl_item = &dip->dn_ds_addrs.mpl_val[mpl_index];
	/* XXX - always choose multipath item 0 */
	nap = &mpl_item->multipath_list4_val[0];

	if ((svp = dip->dn_server_list[mpl_index].ds_curr_serv) == NULL) {

		mutex_exit(&mdsp->s_lock);
		error = netaddr4_to_servinfo4(nap, mi, &svp);

		if (error) {
			mutex_enter(&mdsp->s_lock);
			pnfs_rele_device(mdsp, dip);
			nfs4_server_rele_lockt(mdsp);
			return (error);
		}

		/*
		 * Activate the data server associated with
		 * svp, possibly doing EXID & CR_SESS.
		 */
		error = nfs4_activate_server(mi, mdsp, svp, dip);

		mutex_enter(&mdsp->s_lock);
		if (error) {
			sv4_free(svp);
			pnfs_rele_device(mdsp, dip);
			nfs4_server_rele_lockt(mdsp);
			return (error);
		}

		/* Initialize the server list, if needed */

		if (dip->dn_server_list[mpl_index].ds_curr_serv == NULL) {
			dip->dn_server_list[mpl_index].ds_curr_serv = svp;
		} else {
			/*
			 * Someone else got here first, use the
			 * current server value.
			 *
			 */
			sv4_free(svp);
			svp = dip->dn_server_list[mpl_index].ds_curr_serv;
		}
	}
	pnfs_rele_device(mdsp, dip);
	dip = NULL;
	nfs4_server_rele_lockt(mdsp);

	mutex_enter(&dev->std_lock);
	if (dev->std_svp == NULL)
		dev->std_svp = svp;

	ASSERT(dev->std_svp != NULL);
	mutex_exit(&dev->std_lock);
	return (error);
}

/*
 * pnfs_call() is the heart of the pnfs I/O thread.  Its purpose in life
 * is two-fold:  Call rfs4call() and coordinate with the recovery framework.
 * It doesn't even wait for recovery.  If it notices that recovery will get
 * in its way then it informs the enqueueing thread that the I/O needs to
 * be redriven then returns.
 * N.B., A hold was put on vp in pnfs_read()/pnfs_write() for EACH TASK.
 */
/*ARGSUSED*/
static void
pnfs_call(nfs4_call_t *cp, nfs4_recov_state_t *rsp)
{
	ASSERT(cp->nc_ds_servinfo != NULL);

	cp->nc_flags |= NFS4_CALL_FLAG_RCV_DONTBLOCK;
	cp->nc_e.error = nfs4_start_op(cp, rsp);
	if (cp->nc_e.error)
		return;

	cp->nc_svp = cp->nc_ds_servinfo;
	rfs4call(cp, NULL);

	nfs4_needs_recovery(cp);
	if (cp->nc_needs_recovery) {
		/* does the return value need to go back to ET? */
		(void) nfs4_start_recovery(cp);
	}

	nfs4_end_op(cp, rsp);
}

static void
pnfs_task_read(void *v)
{
	read_task_t *task = v;
	file_io_read_t *job = task->rt_job;
	nfs4_call_t *cp = task->rt_call;
	/* stripe_dev_t *stripe = task->rt_dev; */
	READ4args *rargs;
	READ4res *rres;
	struct timeval wait;
	int error = 0;
	int eof = 0;
	length4 eof_offset;
	int data_len = 0;
	rnode4_t *rp;

	mutex_enter(&job->fir_lock);
	if ((job->fir_error) ||
	    ((job->fir_eof) &&
	    (task->rt_offset + task->rt_count > job->fir_eof_offset))) {
		list_remove(&job->fir_task_list, task);
		job->fir_remaining--;
		if (job->fir_remaining == 0)
			cv_broadcast(&job->fir_cv);
		mutex_exit(&job->fir_lock);
		read_task_free(task);
		return;
	}
	mutex_exit(&job->fir_lock);

	(void) nfs4_op_cputfh(cp, task->rt_dev->std_fh);
	rres = nfs4_op_read(cp, &rargs);

	TICK_TO_TIMEVAL(30 * hz / 10, &wait); /* XXX 30?  SHORTWAIT? */
	rargs->stateid = job->fir_stateid;
	rargs->offset = task->rt_offset;
	rargs->count = task->rt_count;
	rargs->res_data_val_alt = NULL;
	rargs->res_mblk = NULL;
	rargs->res_uiop = NULL;
	rargs->res_maxsize = 0;
	if (task->rt_have_uio)
		rargs->res_uiop = &task->rt_uio;
	else
		rargs->res_data_val_alt = task->rt_base;
	rargs->res_maxsize = task->rt_count;

	pnfs_call(cp, &task->rt_recov_state);
	error = cp->nc_e.error;

	if (error == EAGAIN || cp->nc_needs_recovery) {
		/*
		 * If the task needs recovery or needs to be redriven (EAGAIN),
		 * then leave it on the job list and kick it back to ET.
		 */

		mutex_enter(&job->fir_lock);
		job->fir_remaining--;
		if (job->fir_remaining == 0)
			cv_broadcast(&job->fir_cv);
		mutex_exit(&job->fir_lock);
		return;
	}

	if (error == 0) {
		if (rres->status == NFS4_OK) {
			data_len = rres->data_len;
			if (rres->eof) {
				eof = 1;
				/*
				 * offset may have been modified
				 * if we are using dense stripes,
				 * use the offset in the uio.
				 */
				eof_offset =
				    task->rt_uio.uio_loffset + data_len;
				}

			/*
			 * Registering a data-server-io count for
			 * the file
			 */
			rp = VTOR4(cp->nc_vp1);
			mutex_enter(&rp->r_statelock);
			rp->r_dsio_count++;
			mutex_exit(&rp->r_statelock);
		} else {
			error = geterrno4(cp->nc_res.status);
		}

		ASSERT(cp->nc_e.rpc_status == 0);
	}

	mutex_enter(&job->fir_lock);
	list_remove(&job->fir_task_list, task);
	job->fir_remaining--;
	job->fir_count -= data_len;
	if ((error) && (job->fir_error == 0))
		job->fir_error = error;
	if (eof) {
		if (job->fir_eof == 0)
			job->fir_eof = eof;
		job->fir_eof_offset = MAX(eof_offset, job->fir_eof_offset);
	}
	if ((job->fir_remaining == 0) || (error))
		cv_broadcast(&job->fir_cv);
	mutex_exit(&job->fir_lock);

	read_task_free(task);
}

static void
pnfs_task_read_free(void *v)
{
	file_io_read_t *job = v;

	mutex_enter(&job->fir_lock);
	while (job->fir_remaining > 0)
		cv_wait(&job->fir_cv, &job->fir_lock);
	mutex_exit(&job->fir_lock);

	kmem_cache_free(file_io_read_cache, job);
}

static void
pnfs_task_write(void *v)
{
	write_task_t *task = v;
	file_io_write_t *job = task->wt_job;
	stripe_dev_t *dev = task->wt_dev;
	nfs4_call_t *cp = task->wt_call;
	int error = 0;
	WRITE4args *wargs;
	WRITE4res *wres;
	rnode4_t *rp;
	stable_how4 stable = FILE_SYNC4;

	mutex_enter(&job->fiw_lock);
	if (job->fiw_error) {
		list_remove(&job->fiw_task_list, task);
		job->fiw_remaining--;
		if (job->fiw_remaining == 0)
			cv_broadcast(&job->fiw_cv);
		mutex_exit(&job->fiw_lock);
		write_task_free(task);
		return;
	}
	mutex_exit(&job->fiw_lock);

	(void) nfs4_op_cputfh(cp, dev->std_fh);
	wres = nfs4_op_write(cp, job->fiw_stable_how, &wargs);

	wargs->stateid = job->fiw_stateid;
	wargs->mblk = NULL;
	wargs->offset = task->wt_offset;
	wargs->data_len = task->wt_count;
	wargs->data_val = task->wt_base;

	pnfs_call(cp, &task->wt_recov_state);
	error = cp->nc_e.error;

	if (error == EAGAIN || cp->nc_needs_recovery) {
		/*
		 * If the task needs recovery or needs to be redriven (EAGAIN),
		 * then leave it on the job list and kick it back to ET.
		 */
		mutex_enter(&job->fiw_lock);
		job->fiw_remaining--;
		if (job->fiw_remaining == 0)
			cv_broadcast(&job->fiw_cv);
		mutex_exit(&job->fiw_lock);
		return;
	}

	if (error)
		goto out;
	ASSERT(cp->nc_e.rpc_status == 0);

	if (cp->nc_res.status != NFS4_OK) {
		error = geterrno4(cp->nc_res.status);
		goto out;
	}
	if (wres->status != NFS4_OK) {
		error = geterrno4(wres->status);
		goto out;
	}

	if (wres->committed == UNSTABLE4) {
		stable = UNSTABLE4;
		if (job->fiw_stable_how == DATA_SYNC4 ||
		    job->fiw_stable_how == FILE_SYNC4) {
			zcmn_err(getzoneid(), CE_WARN,
			    "pnfs_task_write: server %s did not commit "
			    "to stable storage",
			    dev->std_svp->sv_hostname);
			error = EIO;
			goto out;
		}
	}

	rp = VTOR4(cp->nc_vp1);

	mutex_enter(&dev->std_lock);
	if (dev->std_flags & STRIPE_DEV_HAVE_VERIFIER) {
		if (wres->writeverf != dev->std_writeverf) {
			pnfs_set_mod(cp->nc_vp1, task->wt_layout,
			    task->wt_sui);
			dev->std_writeverf = wres->writeverf;
			atomic_inc_64(&rp->r_writeverfcnt);
		}
	} else {
		dev->std_writeverf = wres->writeverf;
		dev->std_flags |= STRIPE_DEV_HAVE_VERIFIER;
	}
	mutex_exit(&dev->std_lock);

	mutex_enter(&rp->r_statelock);
	PURGE_ATTRCACHE4_LOCKED(rp);
	rp->r_flags |= R4WRITEMODIFIED | R4LASTBYTE;
	/*
	 * offset+len gives us the size.  However, if we are
	 * using dense stripes, offset won't be right.  Use the
	 * virtual offset (voff), which is the same as offset
	 * for sparse stripes.  Subtract one to convert
	 * to the offset of the last byte written.
	 */

	rp->r_last_write_offset = MAX(rp->r_last_write_offset,
	    task->wt_voff + task->wt_count - 1);

	gethrestime(&rp->r_attr.va_mtime);
	rp->r_attr.va_ctime = rp->r_attr.va_mtime;
	/*
	 * Registering a data-server-io count for the file
	 */
	rp->r_dsio_count++;
	mutex_exit(&rp->r_statelock);

out:
	mutex_enter(&job->fiw_lock);
	if (stable == UNSTABLE4)
		job->fiw_stable_result = stable;
	if (error && job->fiw_error == 0)
		job->fiw_error = error;
	list_remove(&job->fiw_task_list, task);
	job->fiw_remaining--;
	if ((job->fiw_remaining == 0) || (error != 0))
		cv_broadcast(&job->fiw_cv);
	mutex_exit(&job->fiw_lock);
	write_task_free(task);
}

static void
pnfs_task_write_free(void *v)
{
	file_io_write_t *job = v;

	mutex_enter(&job->fiw_lock);
	while (job->fiw_remaining > 0)
		cv_wait(&job->fiw_cv, &job->fiw_lock);
	mutex_exit(&job->fiw_lock);

	kmem_cache_free(file_io_write_cache, job);
}

static void
pnfs_task_commit(void *v)
{
	commit_task_t *task = v;
	file_io_commit_t *job = task->cm_job;
	stripe_dev_t *dev = task->cm_dev;
	nfs4_call_t *cp = task->cm_call;
	int error = 0;
	COMMIT4res *cm_res;
	rnode4_t *rp;

	if (job->fic_error)
		goto out;

	(void) nfs4_op_cputfh(cp, dev->std_fh);
	cm_res = nfs4_op_commit(cp, task->cm_offset, task->cm_count);

	pnfs_call(cp, &task->cm_recov_state);

	/* XXXcommit - Needs to check if recovery is needed */

	error = task->cm_call->nc_e.error;
	if (error)
		goto out;
	ASSERT(task->cm_call->nc_e.rpc_status == 0);

	if (cp->nc_res.status != NFS4_OK) {
		error = geterrno4(cp->nc_res.status);
		goto out;
	}
	if (cm_res->status != NFS4_OK) {
		error = geterrno4(cm_res->status);
		goto out;
	}

	rp = VTOR4(cp->nc_vp1);

	mutex_enter(&dev->std_lock);
	ASSERT(dev->std_flags & STRIPE_DEV_HAVE_VERIFIER);
	if (cm_res->writeverf != dev->std_writeverf) {
		pnfs_set_mod(cp->nc_vp1, task->cm_layout, task->cm_sui);
		dev->std_writeverf = cm_res->writeverf;
		atomic_inc_64(&rp->r_writeverfcnt);
		error = NFS_VERF_MISMATCH;
	}
	mutex_exit(&dev->std_lock);

out:
	mutex_enter(&job->fic_lock);
	if (error && (error != NFS_VERF_MISMATCH))
		pnfs_set_pageerror(job->fic_plist, task->cm_layout,
		    task->cm_sui);
	if (error &&
	    ((job->fic_error == 0) || (job->fic_error == NFS_VERF_MISMATCH)))
		job->fic_error = error;
	job->fic_remaining--;
	if ((job->fic_remaining == 0) || (error != 0))
		cv_broadcast(&job->fic_cv);
	mutex_exit(&job->fic_lock);
	commit_task_free(task);
}

static void
pnfs_task_commit_free(void *v)
{
	file_io_commit_t *job = v;

	mutex_enter(&job->fic_lock);
	while (job->fic_remaining > 0)
		cv_wait(&job->fic_cv, &job->fic_lock);
	mutex_exit(&job->fic_lock);

	kmem_cache_free(file_io_commit_cache, job);
}

int
pnfs_commit_mds(vnode_t *vp, page_t *plist, pnfs_layout_t *layout,
    commit_extent_t *exts, offset4 offset, count4 count, cred_t *cr)
{
	int error, i;
	commit_extent_t *ext;
	stripe_dev_t *dev;
	rnode4_t *rp;
	verifier4 writeverf;

	rp = VTOR4(vp);

	error = nfs4_commit_normal(vp, plist, offset, count, cr);
	if (error == 0) {
		mutex_enter(&rp->r_statelock);
		ASSERT(rp->r_flags & R4HAVEVERF);
		writeverf = rp->r_writeverf;
		mutex_exit(&rp->r_statelock);

		for (i = 0; i < layout->plo_stripe_count; i++) {
			ext = &exts[i];
			if (ext->ce_length == 0)
				continue;
			dev = layout->plo_stripe_dev[i];
			if (writeverf != dev->std_writeverf) {
				error = NFS_VERF_MISMATCH;
				nfs4_set_mod(vp);
				break;
			}
		}
	}
	return (error);
}

static int
pnfs_populate_device(devnode_t *dp, device_addr4 *da)
{
	XDR xdr;

	/* decode the da_addr_body */

	xdrmem_create(&xdr, da->da_addr_body.da_addr_body_val,
	    da->da_addr_body.da_addr_body_len, XDR_DECODE);

	if (!xdr_nfsv4_1_file_layout_ds_addr4(&xdr, &dp->dn_ds_addrs)) {
		cmn_err(CE_WARN, "pnfs_populate_device: XDR_DECODE failed\n");
		return (EAGAIN);
	}

	/* Allocate the server array, it will be initialized later */
	dp->dn_server_list = kmem_zalloc(dp->dn_ds_addrs.mpl_len *
	    sizeof (ds_info_t), KM_SLEEP);

	return (0);
}

static devnode_t *
pnfs_create_device(nfs4_server_t *np, deviceid4 devid, avl_index_t where)
{
	devnode_t *dp;

	ASSERT(MUTEX_HELD(&np->s_lock));
	dp = kmem_zalloc(sizeof (devnode_t), KM_SLEEP);
	DEV_ASSIGN(dp->dn_devid, devid);
	dp->dn_count = 1;
	cv_init(dp->dn_cv, NULL, CV_DEFAULT, NULL);

	/* insert the new devid into the tree */
	avl_insert(&np->s_devid_tree, dp, where);
	dp->dn_flags |= DN_INSERTED;
	return (dp);
}

#define	GDIresok	GETDEVICEINFO4res_u.gdir_resok4

/* set this to 1 to preface GETDEVICEINFO with PUTFH */
int pnfs_gdi_hack = 0;
int pnfs_enable_dino = 1;
bitmap4 pnfs_devno_mask =
	NOTIFY_DEVICEID4_DELETE_MASK|NOTIFY_DEVICEID4_CHANGE_MASK;
int pnfs_gdia_maxcount = 65536;

static int
pnfs_getdeviceinfo(mntinfo4_t *mi, devnode_t *dip, cred_t *cr)
{
	nfs4_call_t *cp;
	GETDEVICEINFO4res *gdi_res;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int abort;
	nfs4_recov_state_t recov_state;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

retry:
	cp = nfs4_call_init(TAG_PNFS_GETDEVINFO, OP_GETDEVICEINFO, OH_OTHER,
	    FALSE, mi, NULL, NULL, cr);

	if (nfs4_start_op(cp, &recov_state))
		goto out;

	if (pnfs_gdi_hack)
		(void) nfs4_op_cputfh(cp, mi->mi_rootfh);
	gdi_res = nfs4_op_getdeviceinfo(cp, dip->dn_devid,
	    LAYOUT4_NFSV4_1_FILES, pnfs_gdia_maxcount,
	    pnfs_enable_dino ? pnfs_devno_mask : 0);

	rfs4call(cp, &e);

	nfs4_needs_recovery(cp);
	if (cp->nc_needs_recovery) {
		abort = nfs4_start_recovery(cp);

		nfs4_end_op(cp, &recov_state);
		nfs4_call_rele(cp);
		if (abort) {
			if (e.error)
				return (e.error);
			else
				return (geterrno4(e.stat));
		}
		goto  retry;
	}

	if ((e.error == 0) && (e.stat == NFS4_OK)) {
		if (gdi_res->gdir_status == 0) {
			/* Populate the device entry */
			e.error = pnfs_populate_device(dip,
			    &gdi_res->GDIresok.gdir_device_addr);
		} else {
			/* XXX - we need to handle this */
			if (gdi_res->gdir_status == NFS4ERR_TOOSMALL)
				cmn_err(CE_WARN,
				    "pnfs_getdeviceinfo: TOOSMALL");
			else
				cmn_err(CE_WARN,
				    "pnfs_getdeviceinfo: gdir_status %d",
				    gdi_res->gdir_status);

			e.error = geterrno4(gdi_res->gdir_status);
		}
	} else if (e.error == 0 && e.stat != NFS4_OK)
		e.error = geterrno4(e.stat);

	nfs4_end_op(cp, &recov_state);
out:
	nfs4_call_rele(cp);

	/* return EAGAIN to trigger MDS I/O */
	return (e.error ? EAGAIN : e.error);
}


static void
pnfs_update_layout(pnfs_layout_t *layout, LAYOUTGET4resok *lores,
nfsv4_1_file_layout4 *file_layout4, layout4 *l4, mntinfo4_t *mi)
{
	int			i;
	timespec_t		now;

	/*
	 * If the layout is NOT marked PLO_GET, then the mds returned a layout
	 * to us that we already have, and have not specifically asked for, as
	 * part of a bigger byte range request than we have asked for.  This is
	 * okay, we don't need to update the pnfs_layout because we already
	 * have this information.
	 * XXXKLR-In debug we could add code to verify that the layout the
	 * mds returned is the same as the one we have.
	 */
	if (!(layout->plo_flags & PLO_GET))
		return;

	layout->plo_pattern_offset = file_layout4->nfl_pattern_offset;
	layout->plo_iomode = l4->lo_iomode;

	if (lores->logr_return_on_close)
		layout->plo_flags |= PLO_ROC;

	if (file_layout4->nfl_util & NFL4_UFLG_COMMIT_THRU_MDS)
		layout->plo_flags |= PLO_COMMIT_MDS;

	DEV_ASSIGN(layout->plo_deviceid, file_layout4->nfl_deviceid);
	layout->plo_first_stripe_index =
	    file_layout4->nfl_first_stripe_index;
	layout->plo_stripe_type =
	    (file_layout4->nfl_util & NFL4_UFLG_DENSE) ?
	    STRIPE4_DENSE : STRIPE4_SPARSE;
	layout->plo_stripe_unit =
	    file_layout4->nfl_util & NFL4_UFLG_STRIPE_UNIT_SIZE_MASK;

	/* stripe count is the number of file handles in the list */
	layout->plo_stripe_count =
	    file_layout4->nfl_fh_list.nfl_fh_list_len;

	layout->plo_stripe_dev = kmem_alloc(layout->plo_stripe_count *
	    sizeof (stripe_dev_t *), KM_SLEEP);
	for (i = 0; i < layout->plo_stripe_count; i++) {
		stripe_dev_t *sd;
		sd = stripe_dev_alloc();
		layout->plo_stripe_dev[i] = sd;
		sd->std_fh = sfh4_get(
		    &file_layout4->nfl_fh_list.nfl_fh_list_val[i], mi);
		DEV_ASSIGN(sd->std_devid, file_layout4->nfl_deviceid);
	}

	gethrestime(&now);
	layout->plo_creation_sec = now.tv_sec;
	layout->plo_creation_musec = now.tv_sec / (NANOSEC / MICROSEC);
}

void
layoutget_to_layout(LAYOUTGET4res *res, rnode4_t *rp, mntinfo4_t *mi)
{
	layout4			*l4;
	nfsv4_1_file_layout4	*file_layout4;
	XDR			xdr;
	int			locnt;
	offset4			loend, l4end;
	pnfs_layout_t		*newlayout, *layout = NULL;

	ASSERT(res != NULL);
	ASSERT(res->logr_status == NFS4_OK);

	if ((res == NULL) || (res->logr_status != NFS4_OK))
		return;

	ASSERT(res->LAYOUTGET4res_u.logr_resok4.logr_layout.logr_layout_len >=
	    1);

	ASSERT(MUTEX_HELD(&rp->r_lo_lock));

	/*
	 * The loop below will walk thru the layouts returned from the mds
	 * and find the pnfs_layout structure whose offset and range
	 * match.  This pnfs_layout structure has no information in it
	 * and was simply a place holder to indicate we had a layoutget
	 * in progress.  Once this pnfs_layout structure is found, its
	 * contents will be updated with the information about the
	 * layout that the MDS has returned.
	 */
	locnt = 0;
	while (locnt < res->LAYOUTGET4res_u.logr_resok4.logr_layout.
	    logr_layout_len) {

		l4 = &res->LAYOUTGET4res_u.logr_resok4.logr_layout.
		    logr_layout_val[locnt];
		if (l4->lo_content.loc_type != LAYOUT4_NFSV4_1_FILES) {
			/*
			 * XXXKLR - Need to handle this?  Or just ignore okay?
			 */
			cmn_err(CE_WARN, "non-file layout; ignoring");
			locnt++;
			layout = NULL;
			continue;
		}

		if (layout == NULL) {
			/*
			 * Find the matching pnfs_layout for this returned
			 * layout, we haven't processed this L4 yet.
			 */
			l4end = (l4->lo_length == PNFS_LAYOUTEND ?
			    l4->lo_length : l4->lo_length + l4->lo_offset - 1);

			for (layout = list_head(&rp->r_layout); layout;
			    list_next(&rp->r_layout, layout)) {
				if (layout->plo_flags & (PLO_BAD|PLO_UNAVAIL))
					continue;
				loend = (layout->plo_length ==
				    PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
				    layout->plo_length + layout->plo_offset
				    - 1);
				if (l4->lo_offset >= layout->plo_offset &&
				    l4end <= loend)
					/*
					 * We want to start with this layout.
					 */
					break;
			}
		}

		/*
		 * We MUST find a matching layout as one was created
		 * prior to the layoutget otw.
		 */
		ASSERT(layout != NULL);

		/*
		 * XDR decode the returned layout into the file_layout4
		 * structure.
		 */
		xdrmem_create(&xdr,
		    l4->lo_content.loc_body.loc_body_val,
		    l4->lo_content.loc_body.loc_body_len,
		    XDR_DECODE);

		file_layout4 = kmem_zalloc(sizeof (*file_layout4), KM_SLEEP);

		/*
		 * XXXKLR - Handle the error differently...do not return
		 * must cleanup, and then what?	 Return error and let
		 * caller cleanup pnfs_layout_t structures probably.
		 */
		if (!xdr_nfsv4_1_file_layout4(&xdr, file_layout4)) {
			cmn_err(CE_WARN, "could not decode file_layouttype4");
			kmem_free(file_layout4, sizeof (*file_layout4));
			return;
		}

		if (!(layout->plo_flags & PLO_GET)) {
			/*
			 * We didn't ask for this layout range
			 * because we already have it. Skip the L4
			 * and continue to the next.
			 */
			layout = NULL;
			locnt++;
			continue;
		}

		/*
		 * According to the draft, table 13, the MDS MUST return
		 * a layout whose beginning offset is either equal to or less
		 * than the offset we asked for.  If it is less than,
		 * then we did not ask for a layout starting at 0.  The only
		 * time we do this is when we already have these layouts.  And
		 * when this happens these pnfs_layout structures will not have
		 * PLO_GET set.  This check is done above, and if so we don't
		 * get here.  So if we get here, our offsets should match.
		 * XXXKLR - If the MDS gives us a layout whose offset is >
		 * than what we asked for, this is a bug as it does not follow
		 * the protocol.  We really should be passing our layoutget
		 * arguments to this function so we can do some validation
		 * checking and handle errors appopriately.  For now we will
		 * just ASSERT.
		 */
		ASSERT(l4->lo_offset == layout->plo_offset);

		l4end = (l4->lo_length == PNFS_LAYOUTEND ? l4->lo_length :
		    l4->lo_length + l4->lo_offset - 1);

		loend = (layout->plo_length == PNFS_LAYOUTEND ?
		    PNFS_LAYOUTEND : layout->plo_length + layout->plo_offset
		    - 1);

		ASSERT(l4end <= loend);
		if (l4->lo_offset == layout->plo_offset && l4end == loend) {
			/*
			 * Exact Match! Now update this pnfs_layout with
			 * the results of the layoutget.
			 */
			pnfs_update_layout(layout,
			    &res->LAYOUTGET4res_u.logr_resok4,
			    file_layout4, l4, mi);
			/*
			 * Mark that we have good results for this layout.
			 */
			layout->plo_flags |= PLO_PROCESSED;
			locnt++;
			layout = list_next(&rp->r_layout, layout);
#ifdef DEBUG
			if (locnt < res->LAYOUTGET4res_u.logr_resok4.
			    logr_layout.logr_layout_len)
				ASSERT(layout != NULL);
#endif
			continue;
		}

		/*
		 * If the starting offsets match, but the ending
		 * offsets do not, then since we only are handling
		 * gaps at the end of the file, this must be for the
		 * ending of the file, or the MDS returned more than
		 * one layout mapping the same byte range as the
		 * pnfs_layout.
		 */
		if (l4->lo_offset == layout->plo_offset && l4end <= loend) {
			/*
			 * Gap at end
			 */
			layout->plo_length = l4->lo_length;
			pnfs_update_layout(layout,
			    &res->LAYOUTGET4res_u.logr_resok4,
			    file_layout4, l4, mi);
			layout->plo_flags |= PLO_PROCESSED;

			if (layout->plo_length == PNFS_LAYOUTEND) {
				/*
				 * this should be the end.
				 */
				ASSERT(locnt > res->LAYOUTGET4res_u.
				    logr_resok4.logr_layout.
				    logr_layout_len);
				break;
			}

			/*
			 * This pnfs_layout is being represented by more than
			 * one layout returned from the mds. Lets look at the
			 * next returned layout.
			 */
			locnt++;

			/*
			 * Here we must create a new layout and insert it into
			 * the list and use it for the next l4 layout
			 * we process.	However, if we have no more
			 * L4's to process, no need for this
			 */
			if (locnt < res->LAYOUTGET4res_u.logr_resok4.
			    logr_layout.logr_layout_len) {
				l4 = &res->LAYOUTGET4res_u.logr_resok4.
				    logr_layout.
				    logr_layout_val[locnt];
				newlayout = kmem_cache_alloc(
				    pnfs_layout_cache, KM_SLEEP);
				newlayout->plo_inusecnt = 0;
				newlayout->plo_creation_sec = 0;
				newlayout->plo_creation_musec = 0;
				newlayout->plo_stripe_count = 0;
				newlayout->plo_stripe_dev = NULL;
				newlayout->plo_first_stripe_index = 0;
				newlayout->plo_stripe_unit = 0;
				newlayout->plo_stripe_type = 0;
				newlayout->plo_flags = (PLO_GET|PLO_PROCESSED);
				newlayout->plo_refcount = 0;
				pnfs_layout_hold(rp, newlayout);
				newlayout->plo_iomode = l4->lo_iomode;
				ASSERT(l4->lo_iomode == LAYOUTIOMODE4_RW);
				newlayout->plo_offset = l4->lo_offset;
				newlayout->plo_flags |= PLO_GET;
				newlayout->plo_length = l4->lo_length;
				pnfs_update_layout(newlayout,
				    &res->LAYOUTGET4res_u.logr_resok4,
				    file_layout4, l4, mi);
				pnfs_insert_layout(layout, rp, newlayout);
				layout = newlayout;
				locnt++;
			}
			continue;
		}

		/*
		 * XXXKLR - If we get here the MDS returned a bogus layout
		 * range.  When we send the layoutget arguments we used to
		 * this function and validate them and return errors when they
		 * are bogus we will never get here.
		 */
		ASSERT(l4end <= loend);
	}
	kmem_free(file_layout4, sizeof (*file_layout4));
	ASSERT(MUTEX_HELD(&rp->r_lo_lock));
}

static void
pnfs_task_layoutreturn(void *v)
{
	task_layoutreturn_t 	*task = v;
	mntinfo4_t 		*mi = task->tlr_mi;
	nfs4_server_t		*np;
	nfs4_fsidlt_t		*ltp;
	rnode4_t 		*rp = NULL;
	nfs4_call_t		*cp;
	LAYOUTRETURN4args 	*arg;
	LAYOUTRETURN4res 	*lrres;
	layoutreturn_file4 	*lrf;
	nfs4_error_t 		e = {0, NFS4_OK, RPC_SUCCESS};
	nfs4_recov_state_t 	recov_state;
	pnfs_layout_t		*layout;
	pnfs_lol_t		*lol;
	int 			returned = 0;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	if (task->tlr_vp != NULL &&
	    (task->tlr_return_type == PNFS_LAYOUTRECALL_FILE ||
	    task->tlr_return_type == PNFS_LAYOUTRETURN_FILE))
		rp = VTOR4(task->tlr_vp);

	if (task->tlr_aflag == LR_ASYNC && (rp != NULL))
		mutex_enter(&rp->r_statelock);
	if (task->tlr_aflag == LR_SYNC && (rp != NULL))
		ASSERT(MUTEX_HELD(&rp->r_statelock));

	if (rp) {
		/*
		 * Hmm, does this need to be a sig wait? Maybe for
		 * return but not for recall.
		 */
		mutex_enter(&rp->r_statelock);
		ASSERT(!(rp->r_flags & R4OTWLO));
		while (rp->r_flags & R4OTWLO) {
			(void) cv_wait(&rp->r_lowait, &rp->r_statelock);
		}
		rp->r_flags |= R4OTWLO;
		mutex_exit(&rp->r_statelock);
	}

	cp = nfs4_call_init(TAG_PNFS_LAYOUTRETURN, OP_LAYOUTRETURN, OH_OTHER,
	    FALSE, mi, NULL, NULL, task->tlr_cr);

	if (nfs4_start_op(cp, &recov_state))
		goto out;

	if (task->tlr_return_type == PNFS_LAYOUTRETURN_FILE ||
	    task->tlr_return_type == PNFS_LAYOUTRECALL_FILE) {
		(void) nfs4_op_cputfh(cp, rp->r_fh);
	} else if (task->tlr_return_type == PNFS_LAYOUTRECALL_FSID) {
		(void) nfs4_op_cputfh(cp, mi->mi_rootfh);
	} else {
		ASSERT(task->tlr_return_type == PNFS_LAYOUTRECALL_ALL);
	}

	lrres = nfs4_op_layoutreturn(cp, &arg);

	if (task->tlr_return_type == PNFS_LAYOUTRETURN_FILE ||
	    task->tlr_return_type == PNFS_LAYOUTRECALL_FILE)
		arg->lora_layoutreturn.lr_returntype =
		    LAYOUTRETURN4_FILE;
	else if (task->tlr_return_type == PNFS_LAYOUTRECALL_FSID)
		arg->lora_layoutreturn.lr_returntype =
		    LAYOUTRETURN4_FSID;
	else if (task->tlr_return_type == PNFS_LAYOUTRECALL_ALL)
		arg->lora_layoutreturn.lr_returntype =
		    LAYOUTRETURN4_ALL;

	lrf = &arg->lora_layoutreturn.layoutreturn4_u.lr_layout;
	lrf->lrf_offset = task->tlr_offset;
	lrf->lrf_length = task->tlr_length;

	if (rp) {
		mutex_enter(&rp->r_statelock);
		lrf->lrf_stateid = rp->r_lostateid;
		mutex_exit(&rp->r_statelock);
	}

	lrf->lrf_body.lrf_body_len = 0;
	arg->lora_reclaim = task->tlr_reclaim;
	arg->lora_iomode = task->tlr_iomode;
	arg->lora_layout_type = LAYOUT4_NFSV4_1_FILES;

	rfs4call(cp, &e);

	/* XXX need needs_recovery/start_recovery logic here */

	if (task->tlr_return_type == PNFS_LAYOUTRECALL_FSID ||
	    task->tlr_return_type == PNFS_LAYOUTRECALL_ALL)
		goto done;

	if (e.error == 0 && e.stat == NFS4_OK) {
		if (lrres->lorr_status == NFS4_OK) {
			ASSERT(arg->lora_layoutreturn.lr_returntype ==
			    LAYOUTRETURN4_FILE);
			if (lrres->LAYOUTRETURN4res_u.lorr_stateid.
			    lrs_present == FALSE) {
				mutex_enter(&rp->r_statelock);
				rp->r_lostateid = clnt_special0;
				mutex_exit(&rp->r_statelock);
				if (!stateid4_cmp(&lrres->LAYOUTRETURN4res_u.
				    lorr_stateid.layoutreturn_stateid_u.
				    lrs_stateid, &clnt_special0)) {
					cmn_err(CE_WARN, "Server sent bogus"
					    "layout stateid in"
					    "LAYOUTRETURN response, should"
					    "be 0");
				}
			} else {
				/*
				 * XXXKLR We really should not see a layout
				 * stateid returned here since the client
				 * will never issue a layoutget on a layout it
				 * already has.  Issue a warning for
				 * now, so if this does occur we know it and
				 * can then start tracing it.  Address this
				 * when adding error handling.
				 */
				cmn_err(CE_WARN, "LAYOUTRETURN Updating"
				    "layout Stateid");
				mutex_enter(&rp->r_statelock);
				rp->r_lostateid = lrres->LAYOUTRETURN4res_u.
				    lorr_stateid.layoutreturn_stateid_u
				    .lrs_stateid;
				mutex_exit(&rp->r_statelock);
			}
		}
	}

done:
	nfs4_end_op(cp, &recov_state);

out:
	/*
	 * Even if the otw fails, we will still drop this layout.
	 * Make sure to decrement counters.
	 */
	if (task->tlr_return_type == PNFS_LAYOUTRECALL_ALL) {
		np = task->tlr_np;
		mutex_enter(&np->s_lt_lock);
		for (ltp = avl_first(&np->s_fsidlt); ltp;
		    ltp = AVL_NEXT(&np->s_fsidlt, ltp)) {
			mutex_enter(&ltp->lt_rlt_lock);
			np->s_locnt -= ltp->lt_locnt;
			ltp->lt_locnt = 0;
			mutex_exit(&ltp->lt_rlt_lock);
		}
		mutex_exit(&np->s_lt_lock);
	} else if (task->tlr_return_type == PNFS_LAYOUTRECALL_FSID) {
		np = task->tlr_np;
		ltp = task->tlr_lt;
		mutex_enter(&np->s_lt_lock);
		mutex_enter(&ltp->lt_rlt_lock);
		np->s_locnt -= ltp->lt_locnt;
		ltp->lt_locnt = 0;
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
	} else {
		ASSERT(task->tlr_return_type == PNFS_LAYOUTRECALL_FILE ||
		    task->tlr_return_type == PNFS_LAYOUTRETURN_FILE);
		np = task->tlr_np;
		ltp = task->tlr_lt;
		ASSERT(rp != NULL);
		ASSERT(task->tlr_lom != NULL);
		lol = list_head(&task->tlr_lom->lm_layouts);
		layout = lol->l_layout;
		ASSERT(layout != NULL);
		mutex_enter(&rp->r_lo_lock);
		while (layout) {
			/*
			 * Mark this layout as bad so other threads that
			 * may have reference on it, know that it has
			 * been returned and no longer valid.  These would
			 * be threads waiting on the plo_wait cv.
			 */
			ASSERT(layout->plo_flags & PLO_RETURN ||
			    (layout->plo_flags & PLO_RECALL));
			layout->plo_flags |= PLO_BAD;
			if (layout->plo_flags & PLO_LOWAITER)
				cv_broadcast(&layout->plo_wait);
			ASSERT(layout->plo_refcount >= 2);
			pnfs_layout_rele(rp, layout);
			returned++;
			lol = list_next(&task->tlr_lom->lm_layouts, lol);
			if (lol != NULL)
				layout = lol->l_layout;
			else
				layout = NULL;
		}
		mutex_exit(&rp->r_lo_lock);

		/*
		 * For a PNFS_LAYOUTRETURN_FILE decrement the
		 * bulk block counters.  These were update
		 * by pnfs_layout_return.  The layoutrecall
		 * versions of this layoutreturn are responsible
		 * for decrementing these counters.
		 */
		if (task->tlr_return_type == PNFS_LAYOUTRETURN_FILE) {
			mutex_enter(&np->s_lt_lock);
			mutex_enter(&ltp->lt_rlt_lock);
			np->s_lobulkblock--;
			ltp->lt_lobulkblock--;
			mutex_exit(&ltp->lt_rlt_lock);
			mutex_exit(&np->s_lt_lock);
		}

		/*
		 * Decrement the total number of layouts
		 * this clientid and the fsid now hold after returning
		 * these layouts.
		 */
		mutex_enter(&np->s_lt_lock);
		mutex_enter(&ltp->lt_rlt_lock);
		np->s_locnt -= returned;
		ltp->lt_locnt -= returned;
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);

		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~R4OTWLO;
		cv_broadcast(&rp->r_lowait);
		mutex_exit(&rp->r_statelock);
	}

	if (task->tlr_aflag == LR_ASYNC) {
		mutex_enter(&np->s_lock);
		nfs4_server_rele_lockt(task->tlr_np);
	}
	nfs4_call_rele(cp);
	task_layoutreturn_free(task);
}

void
pnfs_insert_layout(pnfs_layout_t *afterthis, rnode4_t *rp,
pnfs_layout_t *lo)
{
	uint64_t	layoutend;
	pnfs_layout_t	*layout;

	ASSERT(MUTEX_HELD(&rp->r_lo_lock));
#ifdef DEBUG
	for (layout = list_head(&rp->r_layout); layout;
	    layout = list_next(&rp->r_layout, layout)) {
		layoutend = layout->plo_offset == PNFS_LAYOUTEND ?
		    PNFS_LAYOUTEND : layout->plo_offset + layout->plo_length;
		if (lo->plo_offset >= layout->plo_offset &&
		    lo->plo_offset < layoutend &&
		    ((layout->plo_flags & PLO_BAD) != PLO_BAD)) {
			cmn_err(CE_PANIC, "bad layout insert %p %p",
			    (void *)lo, (void *)layout);
		}
	}
#endif

	list_insert_after(&rp->r_layout, afterthis, lo);
}

int pnfs_no_layoutget;

/*
 * LAYOUTGET may or may not use the offset provided by the caller.  If
 * a layout already exists on the file, the LAYOUTGET request will
 * use the last valid layout on the list to deterime the offset to use.
 * It determines the offset based on the last layout's offset and lenght,
 * to obtain a list of contiguious layout ranges.  This offset may be less than
 * the offset requested by the caller.
 *
 * layoutget can fail for any reason.  The results will be noted when
 * the caller (pnfs_find_layouts basically), re-searches the rnodes
 * layout list and does not find the layout(s) needed, builds a partial, list
 * or return a NULL back to its caller (pnfs_read or pnfs_write), who will
 * fail over to proxy I/O.
 */
static void
pnfs_task_layoutget(void *v)
{
	task_layoutget_t 	*task = v;
	mntinfo4_t		*mi = task->tlg_mi;
	nfs4_server_t 		*np = NULL;
	pnfs_layout_t		*layout, *lastlayout;
	rnode4_t 		*rp = VTOR4(task->tlg_vp);
	nfs4_call_t 		*cp;
	LAYOUTGET4args 		*arg;
	LAYOUTGET4res 		*resp;
	nfs4_error_t 		e = {0, NFS4_OK, RPC_SUCCESS};
	int 			trynext_sid = 0;
	offset4			logoffset = 0;
	nfs4_fsidlt_t		*ltp;
	cred_t 			*cr = task->tlg_cred;
	nfs4_recov_state_t 	recov_state;
	nfs4_stateid_types_t 	sid_types;
	int			newlayouts = 0;

	if (pnfs_no_layoutget)
		goto out;

	ASSERT(MUTEX_HELD(&rp->r_lo_lock));

	lastlayout = list_tail(&rp->r_layout);

	/*
	 * We are walking the rnodes layout list from the end to the
	 * beginning to determine the last byte mapped by a layout.
	 * This last byte will be used as the offset for the layoutget
	 * to attempt to get a layout from the last byte to the end of the
	 * layout.
	 *
	 * We should never see an UNAVAIL layout here because of the
	 * way layouts are obtained and returned.  We do layoutget for
	 * the entire range of the file, if that is UNAVAIL, we won't
	 * be in here trying another layoutget.  If a previous layoutget
	 * resulted in only a portion of the file, we could be in here trying
	 * to get the remainder.  If this occurred previously, the remainder
	 * would map to the end of the file.  Its possible that section
	 * was unavailable and we have an UNAVAIL on the list, but still we
	 * would not be in this function trying to do another layoutget.
	 */
	while (lastlayout != NULL) {
		ASSERT(!(lastlayout->plo_flags & PLO_UNAVAIL));
		if (lastlayout->plo_flags & (PLO_BAD)) {
			lastlayout = list_prev(&rp->r_layout, lastlayout);
			continue;
		}
		logoffset = lastlayout->plo_length == PNFS_LAYOUTEND ?
		    PNFS_LAYOUTEND : lastlayout->plo_offset +
		    lastlayout->plo_length;
		break;
	}

	/*
	 * Create a pnfs_layout structure for this range.
	 */
	layout = kmem_cache_alloc(pnfs_layout_cache, KM_SLEEP);
	layout->plo_inusecnt = 0;
	layout->plo_creation_sec = 0;
	layout->plo_creation_musec = 0;
	layout->plo_stripe_count = 0;
	layout->plo_stripe_dev = NULL;
	layout->plo_first_stripe_index = 0;
	layout->plo_stripe_unit = 0;
	layout->plo_stripe_type = 0;

	layout->plo_refcount = 0;
	pnfs_layout_hold(rp, layout);
	layout->plo_offset = logoffset;
	layout->plo_length = PNFS_LAYOUTEND;
	layout->plo_flags = PLO_GET;

	pnfs_insert_layout(lastlayout, rp, layout);

	mutex_enter(&rp->r_statelock);
	ltp = rp->r_fsidlt;
	mutex_exit(&rp->r_statelock);
	ASSERT(ltp != NULL);

	/*
	 * We grab this extra hold here for security.  We need to release the
	 * rnodes layout list lock (r_lo_lock) to grab the nfs4_server's
	 * s_lt_lock and the fsid lt_rlt_lock.  Its possible at that time
	 * a bulk layoutrecall to come in and pnfs_layout_rele's this layout.
	 * Our extra hold here prevents the layout from being removed from the
	 * rnode and being freed. We check if the layoutrecall occurs after
	 * regrabbing the r_lo_lock, by checking for PLO_BAD.  If PLO_BAD is
	 * set this layout has been returned by a bulk layoutrecall.  All we
	 * have to do here is drop our reference and be done.
	 */
	pnfs_layout_hold(rp, layout);
	mutex_exit(&rp->r_lo_lock);


	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	np = find_nfs4_server_nolock(mi);
	ASSERT(np != NULL);
	mutex_exit(&np->s_lock);


	/*
	 * If there is a bulk CB_LAYOUTRECALL active, we are done.  The
	 * bulk layoutrecall will rele this layout.  Its also possible a
	 * bulk layoutrecall executed and completed and is no longer active
	 * between the time we dropped the r_lo_lock and grabbed the s_lt_lock.
	 * If this occurred the layout we added above would be marked bad, and
	 * our additional hold we added above is keeping this layout on the
	 * rnode list.  Release it, we are done.
	 */
	mutex_enter(&np->s_lt_lock);
	if (np->s_loflags & PNFS_CBLORECALL) {
		mutex_exit(&np->s_lt_lock);
		mutex_enter(&rp->r_lo_lock);
		layout->plo_flags &= ~PLO_GET;
		if (layout->plo_flags & PLO_LOWAITER)
			cv_broadcast(&layout->plo_wait);
		pnfs_layout_rele(rp, layout);
		mutex_exit(&rp->r_lo_lock);

		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~R4OTWLO;
		cv_broadcast(&rp->r_lowait);
		mutex_exit(&rp->r_statelock);
		return;
	}

	mutex_enter(&ltp->lt_rlt_lock);

	if (ltp->lt_flags & PNFS_CBLORECALL) {
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
		mutex_enter(&rp->r_lo_lock);
		layout->plo_flags &= ~PLO_GET;
		if (layout->plo_flags & PLO_LOWAITER)
			cv_broadcast(&layout->plo_wait);
		pnfs_layout_rele(rp, layout);
		mutex_exit(&rp->r_lo_lock);

		mutex_enter(&rp->r_statelock);
		rp->r_flags &= ~R4OTWLO;
		cv_broadcast(&rp->r_lowait);
		mutex_exit(&rp->r_statelock);

		return;
	}

	np->s_lobulkblock++;
	ltp->lt_lobulkblock++;

	mutex_exit(&ltp->lt_rlt_lock);
	mutex_exit(&np->s_lt_lock);

	/*
	 * Release the extra hold we had from above.
	 */
	mutex_enter(&rp->r_lo_lock);
	pnfs_layout_rele(rp, layout);
	mutex_exit(&rp->r_lo_lock);

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/*
	 * If we don't already have a layout, just use the delegation,
	 * lock or open stateID.  Otherwise use the current layout statid.
	 * The fact that we have the R4OTWLO bit set in the rnode, blocks
	 * other threads from changing this stateid until we clear this bit.
	 */
	nfs4_init_stateid_types(&sid_types);

recov_retry:
	cp = nfs4_call_init(TAG_PNFS_LAYOUTGET, OP_LAYOUTGET, OH_OTHER, FALSE,
	    mi, NULL, NULL, cr);

	/*
	 * Must do start op before getting args from rnode that
	 * can change.
	 */
	if (nfs4_start_op(cp, &recov_state)) {
		mutex_enter(&rp->r_lo_lock);
		goto out;
	}

	(void) nfs4_op_cputfh(cp, rp->r_fh);
	resp = nfs4_op_layoutget(cp, &arg);

	arg->loga_layout_type = LAYOUT4_NFSV4_1_FILES;
	arg->loga_iomode = task->tlg_iomode;
	arg->loga_offset = logoffset;
	arg->loga_length = PNFS_LAYOUTEND;
	arg->loga_minlength = 8192;
	arg->loga_maxcount = mi->mi_tsize;



	mutex_enter(&rp->r_statelock);
	if (rp->r_lostateid.seqid == 0) {
		arg->loga_stateid = nfs4_get_stateid(cr, rp, -1, mi, OP_READ,
		    &sid_types, (GETSID_LAYOUT | trynext_sid));
	} else {
		arg->loga_stateid = rp->r_lostateid;
	}
	mutex_exit(&rp->r_statelock);


	/*
	 * If we ended up with the special stateid, this means the
	 * file isn't opened and does not have a delegation stateid to use
	 * either.  At this point we can not get a layout.
	 */
	if (sid_types.cur_sid_type == SPEC_SID) {
		nfs4_end_op(cp, &recov_state);
		mutex_enter(&rp->r_lo_lock);
		goto out;
	}

	rfs4call(cp, &e);

	nfs4_end_op(cp, &recov_state);

	if ((e.error == 0) && (e.stat == NFS4_OK)) {
		mutex_enter(&rp->r_lo_lock);
		layoutget_to_layout(resp, rp, mi);
		/*
		 * Update the layout stateid in the rnode.
		 */
		mutex_enter(&rp->r_statelock);
		rp->r_lostateid = resp->LAYOUTGET4res_u.logr_resok4.
		    logr_stateid;
		mutex_exit(&rp->r_statelock);
	} else if (e.error == 0 && cp->nc_res.status == NFS4ERR_BAD_STATEID &&
	    sid_types.cur_sid_type != OPEN_SID) {
		nfs4_save_stateid(&arg->loga_stateid, &sid_types);
		trynext_sid = GETSID_TRYNEXT;
		nfs4_call_rele(cp);
		goto recov_retry;
	} else if (e.error == 0 &&
	    cp->nc_res.status == NFS4ERR_LAYOUTUNAVAILABLE) {
		/*
		 * Mark the layouts we tried to get as unavailable, but
		 * leave them on the rnode list to prevent further
		 * layoutgets.
		 */
		mutex_enter(&rp->r_lo_lock);
		for (layout = list_head(&rp->r_layout); layout;
		    layout = list_next(&rp->r_layout, layout)) {
			if (layout->plo_flags & PLO_GET) {
				layout->plo_flags &= ~PLO_GET;
				layout->plo_flags |= PLO_UNAVAIL;
				if (layout->plo_flags & PLO_LOWAITER) {
					cv_broadcast(&layout->plo_wait);
				}
			}
		}

		DTRACE_PROBE(nfsc__layout__unavailable);
	} else {
		mutex_enter(&rp->r_lo_lock);
	}

out:
	ASSERT(MUTEX_HELD(&rp->r_lo_lock));

	/*
	 * Okay, here we need to clear the PLO_GET bit, wake any
	 * waiters, mark layouts as bad if the mds did not return one and
	 * rele them so they will be removed from the list.
	 */
	layout = list_head(&rp->r_layout);
	while (layout) {
		if ((layout->plo_flags & PLO_GET) &&
		    !(layout->plo_flags & PLO_PROCESSED)) {
			/*
			 * MDS did not return a layout for this byte
			 * range.  Mark this as BAD, release the layout.
			 */
			layout->plo_flags &= ~PLO_GET;
			if (layout->plo_flags & PLO_LOWAITER)
				cv_broadcast(&layout->plo_wait);
			lastlayout = list_next(&rp->r_layout, layout);
			layout->plo_flags |= PLO_BAD;
			pnfs_layout_rele(rp, layout);
			layout = lastlayout;
		} else if ((layout->plo_flags & (PLO_GET|PLO_PROCESSED))) {
			/*
			 * We got a layout from the MDS for this pnfs_layout!
			 * Clear the GET and PROCESSED bits, and wake any
			 * waiters.
			 */
			newlayouts++;
			layout->plo_flags &= ~(PLO_GET|PLO_PROCESSED);
			if (layout->plo_flags & PLO_LOWAITER) {
				cv_broadcast(&layout->plo_wait);
			}
			layout = list_next(&rp->r_layout, layout);
		} else {
			layout = list_next(&rp->r_layout, layout);
		}

	}

	mutex_exit(&rp->r_lo_lock);

	/*
	 * Decrement the bulkblock counters incremented above.  Increment
	 * total new layouts added from this layoutget to the nfs4_server and
	 * nfs4_fsid layout counts.
	 */
	mutex_enter(&np->s_lt_lock);
	np->s_lobulkblock--;
	np->s_locnt += newlayouts;
	mutex_exit(&np->s_lt_lock);

	mutex_enter(&ltp->lt_rlt_lock);
	ltp->lt_lobulkblock--;
	ltp->lt_locnt += newlayouts;
	mutex_exit(&ltp->lt_rlt_lock);

	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4OTWLO;
	cv_broadcast(&rp->r_lowait);
	mutex_exit(&rp->r_statelock);

	mutex_enter(&np->s_lock);
	nfs4_server_rele_lockt(np);

	nfs4_call_rele(cp);
	if (! (task->tlg_flags & TLG_NOFREE))
		task_layoutget_free(task);
}


void
pnfs_sync_layoutget(vnode_t *vp, cred_t *cr, layoutiomode4 mode,
	offset4 offset, int flags)
{
	task_layoutget_t task;
	mntinfo4_t *mi = VTOMI4(vp);

	task.tlg_flags = TLG_NOFREE;
	task.tlg_cred = cr;
	task.tlg_mi = mi;
	task.tlg_vp = vp;
	task.tlg_iomode = mode;
	task.tlg_flags |= flags;
	task.tlg_offset = offset;

	pnfs_task_layoutget(&task);
}

int
pnfs_rnode_holds_layouts(rnode4_t *rp)
{
	int		total = 0;
	pnfs_layout_t	*lo;

	ASSERT(MUTEX_HELD(&rp->r_lo_lock));

	for (lo = list_head(&rp->r_layout); lo;
	    lo = list_next(&rp->r_layout, lo)) {
		if (!(lo->plo_flags & (PLO_BAD|PLO_UNAVAIL)))
			total++;
	}
	return (total);
}

void
pnfs_layoutget(vnode_t *vp, cred_t *cr, offset4 offset, layoutiomode4 iomode)
{
	task_layoutget_t *task;
	mntinfo4_t *mi = VTOMI4(vp);
	rnode4_t *rp = VTOR4(vp);

	/*
	 * If we don't have an fsid on this rnode, don't bother trying
	 * to get a layout, cause if server does layoutrecall by fsid
	 * we won't know the fsid of this rnode.
	 */

	/*
	 * If a Layoutget is in progress, simply wait
	 * for it to finish and return.  It is still up
	 * to the caller to determine if a layout exists.
	 * The assert below was added because it was thought that
	 * we would never see a waiter here with single layouts being
	 * returned from the MDS.  The ASSERT was a double check
	 * to see when we would have mutliple threads doing a layoutget.
	 * Turns out this does happen with single layouts.  It can occur
	 * when multiple threads are executing at the same time trying to
	 * find the same layout, when the client does not hold any.  One
	 * thread is executing pnfs_task_layoutget, after the rfs4call.  The
	 * layoutget fails with an error (invalid layout type for example).
	 * The pnfs_layout is marked bad and the pnfs_task_layoutget is
	 * waiting for a mutex after doing this.  The other thread is
	 * executing pnfs_find_layouts, holds the r_statelock lets say
	 * sees the plo_bad pnfs_layouts, skips it, does not find any
	 * layout on the list, and calls pnfs_layoutget.  The pnfs_task_
	 * layoutget thread has not yet cleared the R4OTWLO bit, thus
	 * we will wait below.
	 */
#if 0
	ASSERT(!(rp->r_flags & R4OTWLO));
#endif
	/*
	 * If we need to wait here, wait here. However when we are done
	 * waiting, simply return.  We had to drop the r_lo_lock, which
	 * means that the state of the layout list could have completely
	 * changed, it could be that the layout we want we now have.
	 * pnfs_find_layouts will start over and walk the list again, so
	 * just return.
	 */
	if (rp->r_flags & R4OTWLO) {
		mutex_exit(&rp->r_lo_lock);

		mutex_enter(&rp->r_statelock);
		while (rp->r_flags & R4OTWLO) {
			cv_wait(&rp->r_lowait, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
		return;
	}

	mutex_enter(&rp->r_statelock);

	rp->r_flags |= R4OTWLO;
	rp->r_last_layoutget = ddi_get_lbolt();

	mutex_exit(&rp->r_statelock);

	task = kmem_cache_alloc(task_layoutget_cache, KM_SLEEP);
	task->tlg_flags = 0;
	crhold(cr);
	task->tlg_cred = cr;
	MI4_HOLD(mi);
	task->tlg_mi = mi;
	VN_HOLD(vp);
	task->tlg_offset = offset;
	task->tlg_vp = vp;
	task->tlg_iomode = iomode;

	/*
	 * For demo only.  Grab the layout synchronously.  This is
	 * to prevent any i/o from going to the mds.
	 */
#if 0
	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_layoutget, task, 0);
#else
	pnfs_task_layoutget(task);
#endif
}

void
pnfs_layout_return(vnode_t *vp, cred_t *cr, int aflag,
	pnfs_lo_matches_t *lom, int type)
{
	rnode4_t 		*rp = VTOR4(vp);
	mntinfo4_t 		*mi = VTOMI4(vp);
	task_layoutreturn_t 	*task;
	layoutiomode4 		iomode = LAYOUTIOMODE4_RW;
	nfs4_server_t		*np;
	nfs4_fsidlt_t		*ltp;
	pnfs_lo_matches_t	*retlom = NULL;

	if ((aflag == LR_SYNC) &&
	    (nfs_zone() != mi->mi_zone)) {
		return;
	}

	mutex_enter(&rp->r_lo_lock);
	if (lom == NULL && list_is_empty(&rp->r_layout)) {
		mutex_exit(&rp->r_lo_lock);
		return;
	}
	mutex_exit(&rp->r_lo_lock);

	mutex_enter(&rp->r_statelock);
	ltp = rp->r_fsidlt;
	mutex_exit(&rp->r_statelock);

	ASSERT(ltp != NULL);

	np = find_nfs4_server_nolock(mi);
	mutex_exit(&np->s_lock);

	if (lom == NULL) {
		/*
		 * Caller sent NULL lom, which means return all
		 * layouts on the rnode from offset 0 to EOF.
		 * First make sure there are no bulk layoutrecalls
		 * in progress.  If so, no need to return the
		 * layout, it will be dropped by the bulk layout
		 * recall.
		 *
		 */
		mutex_enter(&np->s_lt_lock);
		if (np->s_loflags & PNFS_CBLORECALL) {
			mutex_exit(&np->s_lt_lock);
			return;
		}

		mutex_enter(&ltp->lt_rlt_lock);
		if (ltp->lt_flags & PNFS_CBLORECALL) {
			mutex_exit(&ltp->lt_rlt_lock);
			mutex_exit(&np->s_lt_lock);
			return;
		}
		np->s_lobulkblock++;
		ltp->lt_lobulkblock++;
		mutex_exit(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);

		retlom = pnfs_find_layouts(np, rp, cr, iomode, 0,
		    PNFS_LAYOUTEND, LOM_RETURN);
		if (retlom == NULL) {
			/*
			 * If we have not layouts to return decrement the
			 * bulkblock counters.  Normally the
			 * pnfs_task_layoutreturn will decrement them,
			 * which must happen while we have this crazy async
			 * function wrapper here.
			 */
			mutex_enter(&np->s_lt_lock);
			mutex_enter(&ltp->lt_rlt_lock);
			np->s_lobulkblock--;
			ltp->lt_lobulkblock--;
			mutex_exit(&ltp->lt_rlt_lock);
			mutex_exit(&np->s_lt_lock);

			mutex_enter(&np->s_lock);
			nfs4_server_rele_lockt(np);
			return;
		} else {
			ASSERT(!(list_is_empty(&retlom->lm_layouts)));
		}
	}

	task = kmem_cache_alloc(task_layoutreturn_cache, KM_SLEEP);
	VN_HOLD(vp);
	task->tlr_vp = vp;
	task->tlr_mi = mi;
	task->tlr_np = np;
	task->tlr_lt = ltp;
	MI4_HOLD(mi);
	task->tlr_cr = cr;
	crhold(cr);

	task->tlr_offset = 0;
	task->tlr_length = PNFS_LAYOUTEND;
	task->tlr_reclaim = 0; /* XXX */
	task->tlr_iomode = iomode;
	task->tlr_layout_type = LAYOUT4_NFSV4_1_FILES;
	task->tlr_return_type = type;
	task->tlr_lom = lom == NULL ? retlom : lom;

	ASSERT(aflag == LR_SYNC);

	if (aflag == LR_ASYNC) {
		(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
		    pnfs_task_layoutreturn, task, 0);
	} else {
		pnfs_task_layoutreturn(task);
		if (retlom != NULL)
			pnfs_release_layouts(np, rp, retlom, LOM_RETURN);
		mutex_enter(&np->s_lock);
		nfs4_server_rele_lockt(np);
	}
}

void
pnfs_layoutreturn_bulk(mntinfo4_t *mi, cred_t *cr, int how,
struct nfs4_server *np, struct nfs4_fsidlt *lt)
{
	task_layoutreturn_t *task;

	task = kmem_cache_alloc(task_layoutreturn_cache, KM_SLEEP);
	task->tlr_vp = NULL;
	task->tlr_mi = mi;
	task->tlr_np = np;
	task->tlr_lt = lt;
	MI4_HOLD(mi);
	task->tlr_cr = cr;
	crhold(cr);

	task->tlr_offset = 0;
	task->tlr_length = PNFS_LAYOUTEND;
	/* the spec says reclaim is always false for FSID or ALL */
	task->tlr_reclaim = 0;
	task->tlr_iomode = LAYOUTIOMODE4_ANY;
	task->tlr_layout_type = LAYOUT4_NFSV4_1_FILES;
	task->tlr_return_type = how;
	task->tlr_aflag = LR_SYNC;

	pnfs_task_layoutreturn(task);
}

void
pnfs_layout_hold(rnode4_t *rp, pnfs_layout_t *layout)
{
	ASSERT(MUTEX_HELD(&rp->r_lo_lock));
	layout->plo_refcount++;
}

void
pnfs_trim_fsid_tree(rnode4_t *rp, nfs4_fsidlt_t *ltp, int locklt)
{

	rnode4_t	*found;
	avl_index_t	where;

	if (locklt) {
		mutex_exit(&rp->r_lo_lock);
		/*
		 * Need to grab fsidlt lock, but must first drop
		 * r_lo_lock.  Regrab it, and again check if
		 * the rnode layout list is still empty.  If so remove
		 * the rnode from the fsidlt tree.
		 */
		mutex_enter(&ltp->lt_rlt_lock);
		mutex_enter(&rp->r_lo_lock);
		if (!(list_is_empty(&rp->r_layout))) {
			mutex_exit(&ltp->lt_rlt_lock);
			return;
		}
	}

	found = avl_find(&ltp->lt_rlayout_tree, rp, &where);
	ASSERT(found != NULL);
	if (found)
		avl_remove(&ltp->lt_rlayout_tree, rp);

	if (locklt)
		mutex_exit(&ltp->lt_rlt_lock);

	mutex_enter(&rp->r_statelock);
	rp->r_fsidlt = NULL;
	mutex_exit(&rp->r_statelock);
}

void
pnfs_decr_layout_refcnt(rnode4_t *rp, pnfs_layout_t *layout)
{
	int 		i;

	ASSERT(MUTEX_HELD(&rp->r_lo_lock));

	ASSERT(!(list_is_empty(&rp->r_layout)));

	layout->plo_refcount--;
	if (layout->plo_refcount > 0)
		return;

	ASSERT((layout->plo_flags & (PLO_RETURN|PLO_GET|PLO_RECALL)) == 0);
	ASSERT(layout->plo_inusecnt == 0);

	list_remove(&rp->r_layout, layout);

	for (i = 0; i < layout->plo_stripe_count; i++)
		stripe_dev_rele(layout->plo_stripe_dev + i);

	if (layout->plo_stripe_count != 0)
		kmem_free(layout->plo_stripe_dev,
		    layout->plo_stripe_count * sizeof (stripe_dev_t *));

	kmem_cache_free(pnfs_layout_cache, layout);
}

void
pnfs_layout_rele(rnode4_t *rp, pnfs_layout_t *layout)
{
	nfs4_fsidlt_t	*ltp;

	pnfs_decr_layout_refcnt(rp, layout);

	mutex_enter(&rp->r_statelock);
	ltp = rp->r_fsidlt;
	mutex_exit(&rp->r_statelock);

	if (list_is_empty(&rp->r_layout) && ltp != NULL &&
	    rp->r_activefinds == 0)
		pnfs_trim_fsid_tree(rp, ltp, TRUE);
}

void
pnfs_start_read(read_task_t *task)
{
	nfs4_call_t *cp = task->rt_call;
	/*
	 * Synchronize with recovery actions.  If either the MDS or
	 * the target DS are in recovery, or need recovery, then
	 * start_op will block.
	 */
	if ((cp->nc_e.error = nfs4_start_op(cp, &task->rt_recov_state)) != 0) {
		cmn_err(CE_WARN, "pnfs_start_read: start_op failed");
		return;
	}
	nfs4_end_op(cp, &task->rt_recov_state);
	(void) taskq_dispatch(cp->nc_mi->mi_pnfs_io_taskq,
	    pnfs_task_read, task, 0);
}

int
pnfs_read(vnode_t *vp, caddr_t base, offset_t off, int count, size_t *residp,
    cred_t *cr, bool_t async, struct uio *uiop)
{
	rnode4_t		*rp = VTOR4(vp);
	mntinfo4_t		*mi = VTOMI4(vp);
	int			i, error = 0;
	int			remaining = 0;
	file_io_read_t		*job;
	read_task_t		*task, *next;
	pnfs_layout_t		*layout = NULL;
	uint32_t		stripenum, stripeoff;
	length4 		stripewidth, lomend, ioend;
	nfs4_stateid_types_t 	sid_types;
	offset_t		orig_off = off;
	int			orig_count = count;
	uio_t			*uio_sav = NULL;
	caddr_t			xbase;
	pnfs_lo_matches_t	*lom = NULL;
	pnfs_lol_t		*lol = NULL;
	length4			lcount;
	nfs4_server_t		*np;
	int			nosig;
	int			more_work, too_much;

	np = find_nfs4_server_nolock(mi);
	ASSERT(np != NULL);
	if (np != NULL)
		mutex_exit(&np->s_lock);
	else
		return (EAGAIN);

	lom = pnfs_find_layouts(np, rp, cr, LAYOUTIOMODE4_RW, off,
	    (length4)count, LOM_USE);

	if (lom == NULL) {
		mutex_enter(&rp->r_statelock);
		rp->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		nfs4_server_rele(np);
		return (EAGAIN);
	}

	/*
	 * For now if we have any layouts as UNAVAIL, punt the entier
	 * I/O to proxy I/O.
	 */
	for (lol = list_head(&lom->lm_layouts); lol;
	    lol = list_next(&lom->lm_layouts, lol)) {
		if (lol->l_layout->plo_flags & PLO_UNAVAIL) {
			pnfs_release_layouts(np, rp, lom, LOM_USE);
			mutex_enter(&rp->r_statelock);
			rp->r_proxyio_count++;
			mutex_exit(&rp->r_statelock);
			nfs4_server_rele(np);
			return (EAGAIN);
		}
		ASSERT(lol->l_layout->plo_inusecnt != 0);
	}

	lomend = lom->lm_length == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
	    lom->lm_offset + lom->lm_length;
	ioend = off + count - 1;

	/*
	 * We will have no gaps except at the end of the file. If the range
	 * of layouts we got back does not cover the full range of bytes we
	 * need, for now simply fail back to proxy I/O.
	 */
	lol = list_head(&lom->lm_layouts);
	ASSERT(lol != NULL);

	if (lol == NULL || off < lom->lm_offset || off > lomend ||
	    ioend < lom->lm_offset || ioend > lomend) {
		pnfs_release_layouts(np, rp, lom, LOM_USE);
		mutex_enter(&rp->r_statelock);
		rp->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		nfs4_server_rele(np);
		return (EAGAIN);
	}

	for (lol = list_head(&lom->lm_layouts); lol;
	    lol = list_next(&lom->lm_layouts, lol)) {
		layout = lol->l_layout;
		ASSERT(layout != NULL);

		for (i = 0; i < layout->plo_stripe_count; i++) {
			error = stripe_dev_prepare(mi,
			    layout->plo_stripe_dev[i],
			    layout->plo_first_stripe_index, i, cr);
			if (error) {
				pnfs_release_layouts(np, rp, lom, LOM_USE);
				nfs4_server_rele(np);
				return (error);
			}
		}
	}

	/*
	 * Check for a user address in the uio.  If so, then
	 * we must do a copyback because the backend thread
	 * won't be able to do a uio_move to the user address
	 * (since the task thread will be in a different context).
	 */
	if (uiop && uiop->uio_segflg == UIO_USERSPACE) {
		uio_sav = uiop;
		uiop = NULL;
		xbase = base = kmem_alloc(count, KM_SLEEP);
	}


	job = file_io_read_alloc();
	job->fir_count = count;
	nfs4_init_stateid_types(&sid_types);
	job->fir_stateid = nfs4_get_stateid(cr, rp, curproc->p_pidp->pid_id,
	    mi, OP_READ, &sid_types, (async ? GETSID_TRYNEXT : 0));

	lol = list_head(&lom->lm_layouts);
	layout = lol->l_layout;
	lcount = lol->l_layout->plo_length;

#ifdef DEBUG
	if (layout->plo_offset > off) {
		cmn_err(CE_PANIC, "Missing beginning READ layout, partial I/O "
		    "to layout and Proxy I/O Not Yet Supported");
	}
#endif

	while (count > 0) {
		stripenum = off / layout->plo_stripe_unit;
		stripeoff = off % layout->plo_stripe_unit;
		stripewidth = layout->plo_stripe_unit *
		    layout->plo_stripe_count;

		task = kmem_cache_alloc(read_task_cache, KM_SLEEP);
		task->rt_job = job;
		task->rt_dev =
		    layout->plo_stripe_dev[stripenum %
		    layout->plo_stripe_count];
		stripe_dev_hold(task->rt_dev);
		task->rt_cred = cr;
		crhold(cr);

		ASSERT(off >= layout->plo_pattern_offset);
		task->rt_offset = off - layout->plo_pattern_offset;
		if (layout->plo_stripe_type == STRIPE4_DENSE)
			task->rt_offset = (task->rt_offset / stripewidth)
			    * layout->plo_stripe_unit
			    + stripeoff;
		task->rt_count = MIN(layout->plo_stripe_unit - stripeoff,
		    count);
		task->rt_count = MIN(task->rt_count, lcount);
		task->rt_count = MIN(task->rt_count, mi->mi_tsize);

		task->rt_base = base;
		if (uiop) {
			task->rt_free_uio = uiop->uio_iovcnt * sizeof (iovec_t);
			task->rt_uio.uio_iov = kmem_alloc(task->rt_free_uio,
			    KM_SLEEP);
			(void) uiodup(uiop, &task->rt_uio, task->rt_uio.uio_iov,
			    uiop->uio_iovcnt);
			task->rt_have_uio = 1;
			uioskip(uiop, task->rt_count);
		} else {
			task->rt_have_uio = 0;
			task->rt_free_uio = 0;
			task->rt_uio.uio_loffset = off;
		}
		task->rt_call = nfs4_call_init(TAG_PNFS_READ, OP_READ, OH_READ,
		    FALSE, mi, vp, NULL, cr);
		task->rt_call->nc_vp1 = vp;
		task->rt_call->nc_ds_servinfo = task->rt_dev->std_svp;
		task->rt_recov_state.rs_flags = 0;
		task->rt_recov_state.rs_num_retry_despite_err = 0;

		off += task->rt_count;
		if (base)
			base += task->rt_count;
		count -= task->rt_count;

		lcount = (lcount == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
		    lcount - task->rt_count);
		ASSERT(lcount >= 0 || lcount == PNFS_LAYOUTEND);

		if (lcount != PNFS_LAYOUTEND && lcount == 0) {
			lol = list_next(&lom->lm_layouts, lol);
			if (lol != NULL) {
				layout = lol->l_layout;
				lcount = layout->plo_length;
#ifdef DEBUG
			} else if (count > 0) {
				cmn_err(CE_PANIC, "UNIMPLEMENTED READ Request"
				    " Only A Partial Layout Exists "
				    "Can't fulfill this I/O"
				    " request until Partial Proxy I/O"
				    " is implememnted.");
#endif
			}
		}

		mutex_enter(&job->fir_lock);
		list_insert_head(&job->fir_task_list, task);
		mutex_exit(&job->fir_lock);

		/*
		 * XXXrsb - We really want to call pnfs_start_read()
		 * to synchronize with recovery, but we need to do a
		 * little more work to cancel the remaining tasks
		 * and clean up.  For now, dispatch a pnfs_task_read()
		 * task which is less efficient but does the right thing.
		 */
#if 0
		pnfs_start_read(task);
#endif
		(void) taskq_dispatch(mi->mi_pnfs_io_taskq,
		    pnfs_task_read, task, 0);
		++remaining;
	}

	too_much = 0;
	mutex_enter(&job->fir_lock);
	job->fir_remaining += remaining;
more:
	while (job->fir_remaining > 0) {
		nosig = cv_wait_sig(&job->fir_cv, &job->fir_lock);
		if ((nosig == 0) && (job->fir_error == 0))
			job->fir_error = EINTR;
	}

	/* Check for jobs which need to be redriven (recovery or EAGAIN) */
	more_work = 0;
	for (task = list_head(&job->fir_task_list);
	    task != NULL; task = next) {
		nfs4_call_t *cp = task->rt_call;

		ASSERT(MUTEX_HELD(&job->fir_lock));
		next = list_next(&job->fir_task_list, task);

		/*
		 * If this task has a non-recoverable error (which
		 * will cancel the entire job) and we haven't
		 * already set a fatal error for the job, then
		 * use the task's error to set the job's error.
		 */
		if (cp->nc_e.error && cp->nc_e.error != EAGAIN &&
		    cp->nc_needs_recovery == 0 && job->fir_error == 0) {
			cmn_err(CE_WARN,
			    "Unexpected error in read task redrive: %d\n",
			    cp->nc_e.error);
			job->fir_error = cp->nc_e.error;
		}

		if (job->fir_error) {
			/*
			 * The job has a fatal error... clean up.
			 */
			cmn_err(CE_WARN,
			    "Read redrive: removing tasks (error %d)\n",
			    job->fir_error);
			list_remove(&job->fir_task_list, task);
			mutex_exit(&job->fir_lock);
			read_task_free(task);
			mutex_enter(&job->fir_lock);
			continue;
		}

		/*
		 * If there are no job cancelling errors and we
		 * have reason to redrive the task, then do it.
		 */
		if (cp->nc_needs_recovery || cp->nc_e.error == EAGAIN) {
			/*
			 * The task failed, but the error
			 * indicates that either recovery is needed
			 * or the task needs to be retried (EAGAIN).
			 * Just redispatch the task.
			 *
			 * Dropping the mutex which protects the
			 * list seems ok here.  The current task
			 * could be removed from the list while we
			 * aren't holding the mutex, but we've
			 * already captured next, and it cannot be
			 * removed.
			 */
			nfs4_call_rele(cp);
			task->rt_call = nfs4_call_init(TAG_PNFS_READ, OP_READ,
			    OH_READ, FALSE, mi, vp, NULL, cr);
			task->rt_call->nc_ds_servinfo = task->rt_dev->std_svp;
			mutex_exit(&job->fir_lock);
			pnfs_start_read(task);
			mutex_enter(&job->fir_lock);
			if (cp->nc_e.error == 0)
				job->fir_remaining++;
			more_work = 1;
		} else {
			cmn_err(CE_WARN,
			    "Read redrive: unexpected state "
			    "(error %d, needs_recovery %d, job error %d)\n",
			    cp->nc_e.error,
			    cp->nc_needs_recovery,
			    job->fir_error);
		}
	}

	if (more_work) {
		/*
		 * XXXrsb This is a temporary measure to make sure we
		 * don't spin wildly out of control.  This will be fixed
		 * with the "synchronization" changes.
		 *
		 * Try to avoid sending the same task over and over.
		 * Once we hit the limit, then set the job's error to
		 * EIO and go through the redrive loop one more time
		 * to clean up the remaining tasks.
		 */
		if (too_much++ > 10) {
			cmn_err(CE_WARN,
			    "Insufficient progress on read task redrive,"
			    " setting job error to EIO");
			job->fir_error = EIO;
		} else {
			cmn_err(CE_NOTE, "Redriving read tasks");
		}

		goto more;
	}

	error = job->fir_error;

	if (job->fir_eof) {
		if (job->fir_eof_offset < orig_off ||
		    job->fir_eof_offset > orig_off + orig_count) {
			cmn_err(CE_WARN, "bogus eof_offset 0x%x",
			    (int)job->fir_eof_offset);
			*residp = count;
		} else
			*residp = orig_count - (job->fir_eof_offset - orig_off);
	} else
		*residp = count;
	mutex_exit(&job->fir_lock);

	if (uio_sav) {
		if (error == 0)
			error = uiomove(xbase, (orig_count - *residp),
			    UIO_READ, uio_sav);
		kmem_free(xbase, orig_count);
	}
	pnfs_release_layouts(np, rp, lom, LOM_USE);

	nfs4_server_rele(np);

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_read_free, job, 0);

	return (error);
}

void
pnfs_start_write(write_task_t *task)
{
	nfs4_call_t *cp = task->wt_call;
	/*
	 * Synchronize with recovery actions.  If either the MDS or
	 * the target DS are in recovery, or need recovery, then
	 * start_op will block.
	 */
	if ((cp->nc_e.error = nfs4_start_op(cp, &task->wt_recov_state)) != 0) {
		cmn_err(CE_WARN, "pnfs_start_write: start_op failed");
		return;
	}
	nfs4_end_op(cp, &task->wt_recov_state);
	(void) taskq_dispatch(cp->nc_mi->mi_pnfs_io_taskq,
	    pnfs_task_write, task, 0);
}

int
pnfs_write(vnode_t *vp, caddr_t base, u_offset_t off, int count,
    cred_t *cr, stable_how4 *stab_comm)
{
	int 			i, error = 0;
	file_io_write_t 	*job;
	write_task_t 		*task, *next;
	rnode4_t 		*rp = VTOR4(vp);
	pnfs_layout_t 		*layout;
	uint32_t 		stripenum, stripeoff;
	length4 		stripewidth;
	mntinfo4_t 		*mi = VTOMI4(vp);
	int 			remaining = 0;
	nfs4_stateid_types_t 	sid_types;
	int 			nosig;
	pnfs_lo_matches_t	*lom;
	pnfs_lol_t		*lol;
	length4			lcount;
	length4			ploend, ioend, lomend;
	nfs4_server_t		*np;
	int			more_work, too_much;

	np = find_nfs4_server_nolock(mi);
	ASSERT(np != NULL);
	if (np != NULL)
		mutex_exit(&np->s_lock);
	else
		return (EAGAIN);

	lom = pnfs_find_layouts(np, rp, cr, LAYOUTIOMODE4_RW, off,
	    (length4)count, LOM_USE);

	if (lom == NULL) {
		mutex_enter(&rp->r_statelock);
		rp->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		nfs4_server_rele(np);
		return (EAGAIN);
	}

	/*
	 * For now if we have any layouts as UNAVAIL, punt the entier
	 * I/O to proxy I/O.
	 */
	for (lol = list_head(&lom->lm_layouts); lol;
	    lol = list_next(&lom->lm_layouts, lol)) {
		if (lol->l_layout->plo_flags & PLO_UNAVAIL) {
			pnfs_release_layouts(np, rp, lom, LOM_USE);
			mutex_enter(&rp->r_statelock);
			rp->r_proxyio_count++;
			mutex_exit(&rp->r_statelock);
			nfs4_server_rele(np);
			return (EAGAIN);
		}
		ASSERT(lol->l_layout->plo_inusecnt != 0);
	}

	lomend = lom->lm_length == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
	    lom->lm_offset + lom->lm_length;
	ioend = off + count - 1;

	/*
	 * We will have no gaps except at the end of the file.  If the range
	 * of layouts we got back does not cover the full range of bytes we
	 * need, for now simply fail back to proxy I/O.
	 */
	lol = list_head(&lom->lm_layouts);
	ASSERT(lol != NULL);

	if (lol == NULL || off < lom->lm_offset || off > lomend ||
	    ioend < lom->lm_offset || ioend > lomend) {
		pnfs_release_layouts(np, rp, lom, LOM_USE);
		mutex_enter(&rp->r_statelock);
		rp->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		nfs4_server_rele(np);
		return (EAGAIN);
	}

	for (lol = list_head(&lom->lm_layouts); lol;
	    lol = list_next(&lom->lm_layouts, lol)) {
		layout = lol->l_layout;
		ASSERT(layout != NULL);

		for (i = 0; i < layout->plo_stripe_count; i++) {
			error = stripe_dev_prepare(mi,
			    layout->plo_stripe_dev[i],
			    layout->plo_first_stripe_index, i, cr);
			if (error) {
				pnfs_release_layouts(np, rp, lom, LOM_USE);
				nfs4_server_rele(np);
				return (error);
			}
		}
	}

	job = file_io_write_alloc();
	nfs4_init_stateid_types(&sid_types);
	job->fiw_stateid = nfs4_get_w_stateid(cr, rp, curproc->p_pidp->pid_id,
	    mi, OP_WRITE, &sid_types, NFS4_WSID_PNFS);
	job->fiw_vp = vp;
	job->fiw_stable_how = *stab_comm;
	job->fiw_stable_result = FILE_SYNC4;


	lol = list_head(&lom->lm_layouts);
	layout = lol->l_layout;
	lcount = lol->l_layout->plo_length;
	ploend = layout->plo_length == PNFS_LAYOUTEND ? layout->plo_length :
	    layout->plo_offset + layout->plo_length - 1;
#ifdef DEBUG
	if (layout->plo_offset > off) {
		cmn_err(CE_PANIC, "layout off %llu, write off %llu - "
		    "layout len %llu write len %llu ploend %llu"
		    " Missing beginning WRITE layout, partial I/O"
		    "to layout and Proxy I/O Not Yet Supported",
		    (unsigned long long)layout->plo_offset,
		    (unsigned long long)off,
		    (unsigned long long)layout->plo_length,
		    (unsigned long long)count, (unsigned long long)ploend);
	}
#endif

	while (count > 0) {
		stripenum = off / layout->plo_stripe_unit;
		stripeoff = off % layout->plo_stripe_unit;
		stripewidth = layout->plo_stripe_unit *
		    layout->plo_stripe_count;

		task = kmem_cache_alloc(write_task_cache, KM_SLEEP);
		task->wt_job = job;
		task->wt_cred = cr;
		task->wt_layout = layout;
		crhold(task->wt_cred);
		ASSERT(off >= layout->plo_pattern_offset);
		task->wt_offset = off - layout->plo_pattern_offset;
		task->wt_voff = off;
		if (layout->plo_stripe_type == STRIPE4_DENSE)
			task->wt_offset = (task->wt_offset / stripewidth)
			    * layout->plo_stripe_unit
			    + stripeoff;
		task->wt_sui = stripenum % layout->plo_stripe_count;
		task->wt_dev = layout->plo_stripe_dev[task->wt_sui];
		stripe_dev_hold(task->wt_dev);

		task->wt_base = base;
		/* XXX do we need a more conservative calculation? */
		task->wt_count = MIN(layout->plo_stripe_unit - stripeoff,
		    count);
		task->wt_count = MIN(task->wt_count, lcount);
		task->wt_count = MIN(task->wt_count, mi->mi_stsize);
		task->wt_call = nfs4_call_init(TAG_PNFS_WRITE, OP_WRITE,
		    OH_WRITE, FALSE, mi, vp, NULL, cr);
		task->wt_call->nc_ds_servinfo = task->wt_dev->std_svp;
		task->wt_recov_state.rs_flags = 0;
		task->wt_recov_state.rs_num_retry_despite_err = 0;

		off += task->wt_count;
		base += task->wt_count;
		count -= task->wt_count;

		lcount = (lcount == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
		    lcount - task->wt_count);
#ifdef DEBUG
		if (lcount != PNFS_LAYOUTEND && (signed long long)lcount < 0) {
			cmn_err(CE_PANIC, "bogus lcount %llu, task count %d",
			    (unsigned long long)lcount, task->wt_count);
		}
#endif

		ASSERT(lcount >= 0 || lcount == PNFS_LAYOUTEND);
		if (lcount == 0) {
			lol = list_next(&lom->lm_layouts, lol);
			if (lol != NULL) {
				layout = lol->l_layout;
				lcount = layout->plo_length;
#ifdef DEBUG
			} else if (count > 0) {
				cmn_err(CE_PANIC, "UNIMPLEMENNTED WRITE "
				    "Request"
				    " Only A Partial Layout Exists "
				    "Can't fulfill this I/O"
				    " request until Partial Proxy I/O"
				    " is implememnted.");
#endif
			}
		}

		++remaining;

		mutex_enter(&job->fiw_lock);
		list_insert_head(&job->fiw_task_list, task);
		mutex_exit(&job->fiw_lock);

		/*
		 * XXXrsb - We really want to call pnfs_start_write()
		 * to synchronize with recovery, but we need to do a
		 * little more work to cancel the remaining tasks
		 * and clean up.  For now, dispatch a pnfs_task_read()
		 * task which is less efficient but does the right thing.
		 */
		(void) taskq_dispatch(mi->mi_pnfs_io_taskq,
		    pnfs_task_write, task, 0);
	}

	too_much = 0;
	mutex_enter(&job->fiw_lock);
	job->fiw_remaining += remaining;
more:
	while (job->fiw_remaining > 0) {
		nosig = cv_wait_sig(&job->fiw_cv, &job->fiw_lock);
		if ((nosig == 0) && (job->fiw_error == 0))
			job->fiw_error = EINTR;
	}

	/* Check for jobs which need to be redriven (recovery or EAGAIN) */
	more_work = 0;
	for (task = list_head(&job->fiw_task_list);
	    task != NULL; task = next) {
		nfs4_call_t *cp = task->wt_call;

		ASSERT(MUTEX_HELD(&job->fiw_lock));
		next = list_next(&job->fiw_task_list, task);

		/*
		 * If this task has a non-recoverable error (which
		 * will cancel the entire job) and we haven't
		 * already set a fatal error for the job, then
		 * use the task's error to set the job's error.
		 */
		if (cp->nc_e.error && cp->nc_e.error != EAGAIN &&
		    cp->nc_needs_recovery == 0 && job->fiw_error == 0) {
			cmn_err(CE_WARN,
			    "Unexpected error in write task redrive: %d\n",
			    cp->nc_e.error);
			job->fiw_error = cp->nc_e.error;
		}

		if (job->fiw_error) {
			/*
			 * The job has a fatal error... clean up.
			 */
			cmn_err(CE_WARN,
			    "Write redrive: removing tasks (error %d)\n",
			    job->fiw_error);
			list_remove(&job->fiw_task_list, task);
			mutex_exit(&job->fiw_lock);
			write_task_free(task);
			mutex_enter(&job->fiw_lock);
			continue;
		}

		/*
		 * If there are no job cancelling errors and we
		 * have reason to redrive the task, then do it.
		 */
		if (cp->nc_needs_recovery || cp->nc_e.error == EAGAIN) {
			/*
			 * The task failed, but the error
			 * indicates that either recovery is needed
			 * or the task needs to be retried (EAGAIN).
			 * Just redispatch the task.
			 *
			 * Dropping the mutex which protects the
			 * list seems ok here.  The current task
			 * could be removed from the list while we
			 * aren't holding the mutex, but we've
			 * already captured next, and it cannot be
			 * removed.
			 */
			nfs4_call_rele(cp);
			task->wt_call = nfs4_call_init(TAG_PNFS_WRITE,
			    OP_WRITE, OH_WRITE, FALSE, mi, vp, NULL, cr);
			task->wt_call->nc_ds_servinfo = task->wt_dev->std_svp;
			mutex_exit(&job->fiw_lock);
			pnfs_start_write(task);
			mutex_enter(&job->fiw_lock);
			if (cp->nc_e.error == 0)
				job->fiw_remaining++;
			more_work = 1;
		} else {
			cmn_err(CE_WARN,
			    "Write redrive: unexpected state "
			    "(error %d, needs_recovery %d, job error %d)\n",
			    cp->nc_e.error,
			    cp->nc_needs_recovery,
			    job->fiw_error);
		}
	}

	if (more_work) {
		/*
		 * XXXrsb This is a temporary measure to make sure we
		 * don't spin wildly out of control.  This will be fixed
		 * with the "synchronization" changes.
		 *
		 * Try to avoid sending the same task over and over.
		 * Once we hit the limit, then set the job's error to
		 * EIO and go through the redrive loop one more time
		 * to clean up the remaining tasks.
		 *
		 * BTW, if we wanted to keep this throttle, then we
		 * probably want to pick a more dynamic value.  Maybe:
		 *	N x number-of-original-tasks-for-this-job
		 */
		if (too_much++ > 10) {
			cmn_err(CE_WARN,
			    "Insufficient progress on write task redrive,"
			    " setting job error to EIO");
			job->fiw_error = EIO;
		} else {
			cmn_err(CE_NOTE, "Redriving write tasks (%d)",
			    too_much);
		}

		goto more;
	}

	error = job->fiw_error;
	*stab_comm = job->fiw_stable_result;
	mutex_exit(&job->fiw_lock);

	pnfs_release_layouts(np, rp, lom, LOM_USE);

	nfs4_server_rele(np);

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_write_free, job, 0);

	return (error);
}


int
pnfs_getdevice_layoutstats(nfs4_server_t *np, layoutspecs_t *los,
	pnfs_layout_t *flayout, mntinfo4_t *mi, cred_t *cr)
{
	deviceid4	deviceid;
	devnode_t	*dip = NULL;
	uint32_t	stp_ndx, mpl_index, num_servers;
	int		stripe_num;
	int		error;
	stripe_info_t	*si_node;
	multipath_list4	*mpl_item;

	DEV_ASSIGN(deviceid, flayout->plo_deviceid);

	dip = NULL;
	error = pnfs_get_device(mi, np, flayout->plo_deviceid, cr,
	    &dip, PGD_NO_OTW);

	if (dip != NULL && error == 0) {
		/*
		 * Stripe_info_list_len has already been filled in by
		 * the caller based on the number of stripes listed in
		 * the layout.
		 */
		ASSERT(los->plo_stripe_info_list.plo_stripe_info_list_len !=
		    0);
		los->plo_stripe_info_list.plo_stripe_info_list_val =
		    kmem_zalloc(los->plo_stripe_info_list.
		    plo_stripe_info_list_len *
		    sizeof (stripe_info_t), KM_NOSLEEP);
		if (los->plo_stripe_info_list.plo_stripe_info_list_val ==
		    NULL)
			return (ENOMEM);

		los->plo_devnode = dip;
		for (stripe_num = 0; stripe_num < flayout->plo_stripe_count;
		    stripe_num++) {
			si_node = &los->plo_stripe_info_list.
			    plo_stripe_info_list_val[stripe_num];
			si_node->stripe_index = stripe_num;
			stp_ndx = (stripe_num +
			    flayout->plo_first_stripe_index) %
			    dip->dn_ds_addrs.stripe_indices_len;
			mpl_index =
			    dip->dn_ds_addrs.stripe_indices[stp_ndx];
			mpl_item = &dip->dn_ds_addrs.mpl_val[mpl_index];
			num_servers = mpl_item->multipath_list4_len;
			si_node->multipath_list.multipath_list_len =
			    num_servers;
			si_node->multipath_list.multipath_list_val =
			    mpl_item->multipath_list4_val;

			}
	} else {
		los->plo_stripe_info_list.plo_stripe_info_list_len = 0;
		los->plo_stripe_info_list.plo_stripe_info_list_val = NULL;
	}

	return (0);
}

static void
pnfs_layoutstats_cleanup(layoutstats_t *lostats, nfs4_server_t *np)
{
	int		i;
	layoutspecs_t	*los;

	ASSERT(np != NULL);

	mutex_enter(&np->s_lock);
	for (i = 0; i < lostats->plo_data.total_layouts; i++) {
		los = &lostats->plo_data.lo_specs[i];
		if (los->plo_stripe_info_list.plo_stripe_info_list_val) {
			kmem_free(los->plo_stripe_info_list.
			    plo_stripe_info_list_val,
			    los->plo_stripe_count *
			    sizeof (stripe_info_t));
		}
		if (los->plo_devnode) {
			pnfs_rele_device(np, los->plo_devnode);
		}
	}
	nfs4_server_rele_lockt(np);
}


/*
 * Gather layout statistics, XDR encode them, and copy them to the user space.
 */
int pnfs_collect_layoutstats(struct pnfs_getflo_args *args,
    model_t model, cred_t *cr)
{
	char 			*user_filename; /* User filename */
	char 			*data_buffer; /* XDR encoded stream */
	char 			*user_data_buffer; /* User buffer */
	uint_t			xdr_len;
	uint32_t 		*kernel_bufsize; /* User Buffer size */
	uint32_t 		user_bufsize;
	vnode_t 		*vp;
	rnode4_t 		*rp;
	mntinfo4_t 		*mi;
	XDR			 xdrarg;
	layoutstats_t 		lostats;
	layoutspecs_t 		*los;
	pnfs_layout_t 		*flayout;
	nfsstat_lo_errcodes_t 	ec;
	nfs4_server_t		*np;
	bool_t			encode_failed;


	/*
	 * Get arguments.
	 */
	STRUCT_HANDLE(pnfs_getflo_args, plo_args);
	STRUCT_SET_HANDLE(plo_args, model, args);
	user_filename = STRUCT_FGETP(plo_args, fname);

	/*
	 * Obtain vnode and do basic sanity checks.
	 */
	ec = lookupname(user_filename, UIO_USERSPACE,
	    FOLLOW, NULL, &vp);
	if (ec) {
		return (ec);
	}

	if (vp == NULL) {
		ec = ESYSCALL;
		return (ec);
	}

	/*
	 * Check whether the user supplied path is a regular file.
	 */
	if (vp->v_type != VREG) {
		VN_RELE(vp);
		ec = ENOTAFILE;
		return (ec);
	}

	/*
	 * Check for NFS
	 */
	mutex_enter(&vp->v_lock);
	if (!vn_matchops(vp, nfs4_vnodeops)) {
		mutex_exit(&vp->v_lock);
		VN_RELE(vp);
		ec = ENONFS;
		return (ec);
	}
	mutex_exit(&vp->v_lock);

	/*
	 * Now we are sure that we are talking with an NFS v4 file.
	 * Hence we can go ahead and use the v4 macros.
	 */
	rp = VTOR4(vp);
	mi = VTOMI4(vp);
	if (rp == NULL || mi == NULL) {
		VN_RELE(vp);
		ec = ESYSCALL;
		return (ec);
	}

	/*
	 * Make sure it is a pNFS mount and get a layout.
	 */
	if (!(mi->mi_flags & MI4_PNFS)) {
		VN_RELE(vp);
		ec = ENOPNFSSERV;
		return (ec);
	}

	/*
	 * Obtain the layout and proxy I/O and non-proxy I/O counts for
	 * the file.
	 */

	mutex_enter(&rp->r_statelock);

	lostats.proxy_iocount = rp->r_proxyio_count;
	lostats.ds_iocount = rp->r_dsio_count;
	lostats.plo_data.total_layouts = 0;

	for (flayout = list_head(&rp->r_layout); flayout;
	    flayout = list_next(&rp->r_layout, flayout)) {
		if (!(flayout->plo_flags & PLO_BAD))
			lostats.plo_data.total_layouts++;
	}

	if ((lostats.plo_data.total_layouts == 0) &&
	    (lostats.proxy_iocount == 0)) {
		mutex_exit(&rp->r_statelock);
		VN_RELE(vp);
		ec = ENOLAYOUT;
		return (ec);
	}

	/*
	 * We don't want to hold the r_statelock over a kmem alloc that
	 * could sleep.  But, if we release the r_statelock, kmem_alloc,
	 * then grab the statelock again, the list can change.  It can
	 * maybe change to empty, or from empty to entries,
	 * or the number
	 * of entries on it can change.  This then presents issues as to
	 * what entrys, if any do we return statistic on.
	 * Instead of dealing with this, simply do the kmem_alloc with
	 * KM_NOSLEEP.  If we get back null, return an error.
	 */
	los = kmem_zalloc((sizeof (*los) *
	    lostats.plo_data.total_layouts), KM_NOSLEEP);

	if (los == NULL) {
		mutex_exit(&rp->r_statelock);
		VN_RELE(vp);
		return (EAGAIN);
	}

	lostats.plo_data.lo_specs = los;

	/*
	 * Now pluck the fields off the layout.
	 */
	if (lostats.plo_data.total_layouts != 0) {
		flayout = list_head(&rp->r_layout);
		np = find_nfs4_server_nolock(mi);
		if (np) {
			/*
			 * Got the nfs4_server_t, but we don't need to hold
			 * the lock, just need the reference count on it
			 * that find_nfs4_server_nolock() gives, so release
			 * mutex.
			 */
			mutex_exit(&np->s_lock);
		} else {
			/*
			 * Why would we NOT get an nfs4_server_t?  Not sure
			 * if this would ever happen, assert for now, but
			 * add code to prevent dereferencing a NULL np pointer
			 * futher in this code if this does happen on a non-
			 * debug system.
			 */
			ASSERT(np != NULL);
			mutex_exit(&rp->r_statelock);
			VN_RELE(vp);
			return (EAGAIN);
		}

		while (flayout) {
			if (flayout->plo_flags & (PLO_BAD|PLO_UNAVAIL)) {
				flayout = list_next(&rp->r_layout, flayout);
				los++;
			}

			los->plo_stripe_count =
			    flayout->plo_stripe_count;
			los->plo_stripe_info_list.
			    plo_stripe_info_list_len =
			    flayout->plo_stripe_count;
			los->plo_status = flayout->plo_flags;
			los->plo_stripe_unit =
			    flayout->plo_stripe_unit;
			los->iomode = flayout->plo_iomode;
			los->plo_offset = flayout->plo_offset;
			los->plo_length = flayout->plo_length;

			los->plo_creation_sec =
			    flayout->plo_creation_sec;
			los->plo_creation_musec =
			    flayout->plo_creation_musec;
			ec = pnfs_getdevice_layoutstats(np, los, flayout, mi,
			    cr);
			if (ec) {
				pnfs_layoutstats_cleanup(&lostats, np);
				mutex_exit(&rp->r_statelock);
				VN_RELE(vp);
				return (ec);
			}

			flayout = list_next(&rp->r_layout, flayout);
			los++;
		}
	} else {
		los->plo_stripe_info_list.
		    plo_stripe_info_list_val = NULL;
		los->plo_stripe_info_list.
		    plo_stripe_info_list_len = 0;
		los->plo_stripe_count = 0;
	}

	mutex_exit(&rp->r_statelock);

	/*
	 * Get the user buffer and fill it with XDR encoded stream.
	 */
	xdr_len = xdr_sizeof(xdr_layoutstats_t, &lostats);
	data_buffer = kmem_zalloc(xdr_len, KM_SLEEP);
	xdrmem_create(&xdrarg, data_buffer,  xdr_len, XDR_ENCODE);

	encode_failed = !xdr_layoutstats_t(&xdrarg, &lostats);

	VN_RELE(vp);

	pnfs_layoutstats_cleanup(&lostats, np);

	if (encode_failed) {
		kmem_free(data_buffer, xdr_len);
		cmn_err(CE_WARN, "nfsstat: xdr_layoutstats_t failed"
		    "in the kernel");
		return (ESYSCALL);
	}

	/*
	 * Pass the xdr_len back to the userland in case it needs to
	 * be made bigger as per the check below.
	 */
	kernel_bufsize = STRUCT_FGETP(plo_args, kernel_bufsize);
	if (kernel_bufsize == NULL) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__e__user_memory_null);
		ec = ESYSCALL;
		return (ec);
	}
	if (copyout(&xdr_len, kernel_bufsize, sizeof (uint32_t))) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__e__copyout_failed);
		ec = ESYSCALL;
		return (ec);
	}

	/*
	 * Get the user buffer size and check if it is large enough.
	 */
	user_bufsize = STRUCT_FGET(plo_args, user_bufsize);
	if (xdr_len > user_bufsize) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__i__user_buffer_size_overflow);
		ec = EOVERFLOW;
		return (ec);
	}

	/*
	 * Copy the XDR encoded data to the user space buffer.
	 */
	user_data_buffer = STRUCT_FGETP(plo_args, layoutstats);
	if (user_data_buffer == NULL) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__e__user_memory_null);
		ec = ESYSCALL;
		return (ec);
	}
	if (copyout(data_buffer, user_data_buffer, xdr_len) != 0) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__e__copyout_failed);
		ec = ESYSCALL;
		return (ec);
	}

	/*
	 * Free memory for the XDR stream.
	 */
	kmem_free(data_buffer, xdr_len);
	return (0);
}

#ifdef	USE_GETDEVICELIST

/*
 * This is the old draft 18 code for getdevicelist.  It is no
 * longer used; the client now uses getdeviceinfo.
 */
static void
pnfs_task_getdevicelist(void *v)
{
	task_get_devicelist_t *task = v;
	mntinfo4_t *mi = task->tgd_mi;
	nfs4_call_t *cp;
	GETDEVICELIST4args *gdargs;
	GETDEVICELIST4res *gdres;
	GETDEVICELIST4resok *gdresok;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int i, eof;
	nfs4_recov_state_t recov_state;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	cp = nfs4_call_init(TAG_PNFS_GETDEVLIST, OP_GETDEVICELIST, OH_OTHER,
	    FALSE, mi, NULL, NULL, task->tgd_cred);

	if (nfs4_start_op(cp, &recov_state))
		goto out;

	(void) nfs4_op_cputfh(cp, mi->mi_rootfh);
	gdres = nfs4_op_getdevicelist(cp, &gdargs);

	gdargs->gdla_layout_type = LAYOUT4_NFSV4_1_FILES;
	gdargs->gdla_maxcount = 64; /* XXX make abstraction */
	gdargs->gdla_cookie = 0;
	gdargs->gdla_cookieverf = 0;
	gdargs->gdla_notify_types = 0;

	do {
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_flags &
		    (MI4_PNFS | MI4_ASYNC_MGR_STOP)) != MI4_PNFS) {
			mutex_exit(&mi->mi_lock);
			break;
		}
		mutex_exit(&mi->mi_lock);

		rfs4call(cp, &e);
		if ((e.error == 0) && (e.stat == NFS4_OK)) {
			gdresok = &gdres->GETDEVICELIST4res_u.gdlr_resok4;
			for (i = 0; i < gdresok->GDL_ADDRL; i++)
				pnfs_intern_devlist_item(mi,
				    gdresok->GDL_ADDRV + i,
				    LAYOUT4_NFSV4_1_FILES);
			gdargs->gdla_cookie = gdresok->gdlr_cookie;
			gdargs->gdla_cookieverf = gdresok->gdlr_cookieverf;
			eof = gdresok->gdlr_eof;

			/* XXX */
			if (eof == 0) {
				printf("missing eof = %d", eof);
				eof = 1; /* XXX */
			}
		}
		else
			/* exit loop gracefully on error */
			eof = 1;

		nfs4_call_opresfree(cp);
	} while (! eof);

	nfs4_end_op(cp, &recov_state);
out:
	nfs4_call_rele(cp);
	task_get_devicelist_free(task);
}

void
pnfs_getdevicelist(mntinfo4_t *mi, cred_t *cr)
{
	task_get_devicelist_t *task;

	/* XXX mi_lock? */
	if ((mi->mi_flags & (MI4_PNFS | MI4_ASYNC_MGR_STOP)) != MI4_PNFS)
		return;

	mutex_enter(&mi->mi_pnfs_lock);
	mi->mi_last_getdevicelist = ddi_get_lbolt();
	mutex_exit(&mi->mi_pnfs_lock);

	task = kmem_cache_alloc(task_get_devicelist_cache, KM_SLEEP);
	crhold(cr);
	task->tgd_cred = cr;
	MI4_HOLD(mi);
	task->tgd_mi = mi;

#if 0
	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_getdevicelist, task, 0);
#else
	pnfs_task_getdevicelist(task);
#endif
}
#endif	/* USE_GETDEVICELIST */

/*
 * Commit data that was previously written.
 * Only data from the pages in plist need to be committed.
 * The paramaters offset and count are the minimum
 * offset and count that contain the set of pages in plist.
 */
int
pnfs_commit(vnode_t *vp, page_t *plist, offset4 offset, count4 count,
    cred_t *cr)
{
	int 			i, error = 0;
	file_io_commit_t 	*job = NULL;
	commit_task_t 		*task;

	rnode4_t 		*rp = VTOR4(vp);
	pnfs_layout_t 		*layout;
	length4 		stripewidth, ioend, lomend;
	mntinfo4_t 		*mi = VTOMI4(vp);
	int 			remaining = 0;
	nfs4_stateid_types_t 	sid_types;
	int 			nosig;
	page_t 			*pp;
	offset4 		off, ps, pe, lend;
	commit_extent_t 	*exts, *ext;
	int 			exts_size, ext_index, stripe_count = 0;
	uint32_t		sui;
	nfs4_server_t		*np;
	pnfs_lo_matches_t	*lom;
	pnfs_lol_t		*lol;
	offset4			lastwriteoff = 0;
	nfs4_call_t		*cp;
	LAYOUTCOMMIT4args	*la;
	nfs4_error_t		e = { 0, NFS4_OK, RPC_SUCCESS };
	nfs4_recov_state_t	recov_state;

	np = find_nfs4_server_nolock(mi);
	ASSERT(np != NULL);
	mutex_exit(&np->s_lock);

	pe = offset + count - 1;
	mutex_enter(&rp->r_statelock);

	if ((rp->r_flags & R4LASTBYTE) && (rp->r_last_write_offset > offset) &&
	    (rp->r_last_write_offset <= pe))
		lastwriteoff = rp->r_last_write_offset;
	mutex_exit(&rp->r_statelock);

	lom = pnfs_find_layouts(np, rp, cr, LAYOUTIOMODE4_RW, offset, count,
	    LOM_COMMIT);

	if (lom == NULL) {
		mutex_enter(&np->s_lock);
		nfs4_server_rele_lockt(np);
		return (EAGAIN);
	}

	lomend = lom->lm_length == PNFS_LAYOUTEND ? PNFS_LAYOUTEND :
	    lom->lm_offset + lom->lm_length;
	ioend = offset + count - 1;

	/*
	 * We should have the layouts because we have data that needs to
	 * be committed, which means we did a write to the DS.  Currently
	 * we MAY return the layout without commiting the data.  This is a
	 * bug and will be fixed in the future by guarenteeing that
	 * layoutreturn commits the data before returning the layout.
	 * For now if we don't have a layout for the range we want,
	 * spit out a message.
	 */
	lol = list_head(&lom->lm_layouts);
	ASSERT(lol != NULL);

	if (lol == NULL || offset < lom->lm_offset || offset > lomend ||
	    ioend < lom->lm_offset || ioend > lomend) {
		cmn_err(CE_WARN, "PNFS_COMMIT missing layouts in range"
		    "%llu to %llu for rnode %p",
		    (unsigned long long)offset,
		    (unsigned long long)ioend,
		    (void *)rp);
	}

	lol = list_head(&lom->lm_layouts);
	while (lol) {
		layout = lol->l_layout;
		ASSERT(layout != NULL);
		/*
		 * We should never end up with an unavailable or bad
		 * layout here.  Well for now we might because we
		 * are not doing a pnfs_commit in layout return.
		 * Spit out a message for now incase it helps for
		 * debugging later.
		 */
		if (layout->plo_flags & (PLO_BAD|PLO_UNAVAIL)) {
			cmn_err(CE_WARN, "Commiting to a bogus layout");
		}

		for (i = 0; i < layout->plo_stripe_count; i++) {
			stripe_count += layout->plo_stripe_count;
		}

		lol = list_next(&lom->lm_layouts, lol);
	}

	/*
	 * Allocate an array of extents (offset, length).
	 * One extent for each stripe device.
	 */
	exts_size = sizeof (commit_extent_t) * stripe_count;
	exts = kmem_zalloc(exts_size, KM_SLEEP);

	ext_index = 0;
	lol = list_head(&lom->lm_layouts);
	while (lol) {
		/*
		 * Walk thru the commit_extents allocated and
		 * setup pointers to the lol structures.
		 */
		layout = lol->l_layout;
		for (i = 0; i < layout->plo_stripe_count; i++) {
			ext = &exts[ext_index];
			ext->ce_lo = lol->l_layout;
			ext_index++;
			ASSERT(ext_index <= stripe_count);
		}
		lol = list_next(&lom->lm_layouts, lol);
	}

	/*
	 * Walk the list of pages and update the extents array.
	 * When finished, the extents array will contain the
	 * offset and length that needs to be committed for each device.
	 */
	pp = plist;
	ext_index = 0;

	do {
		ps = pp->p_offset;
		/*
		 * Find the appropriate commit_extent by looking at
		 * the layout it represents.  The first commmit extent
		 * found whose layout holds the page starting byte
		 * is the base of the commit extents for the layout.
		 * Since the layout can map to more than one data server
		 * we then need to index from this base commit extent
		 * using the stripe unit size of the layout and the stripe
		 * count of the layout.
		 */
		for (ext_index = 0; ext_index < stripe_count; ext_index++) {
			ext = &exts[ext_index];
			layout = ext->ce_lo;
			lend = (layout->plo_length == PNFS_LAYOUTEND) ?
			    PNFS_LAYOUTEND : layout->plo_offset +
			    layout->plo_length;
			if (ps >= layout->plo_offset && (ps < lend))
				break;
		}
		/*
		 * We MUST have a match, otherwise pnfs_find_layouts
		 * gave us back a bogus list.
		 */
#ifdef DEBUG
		if (ext_index == stripe_count)
			cmn_err(CE_PANIC, "bogus index %d %d %p", ext_index,
			    stripe_count, (void *)exts);
#endif

		lend = ((layout->plo_length == PNFS_LAYOUTEND) ?
		    PNFS_LAYOUTEND : layout->plo_offset + layout->plo_length);
		ASSERT(ps >= layout->plo_offset && (ps <= lend));
		/*
		 * XXXKLR Ugh!  How do we handle pages that span layouts?
		 * Assert for now that this doesn't happen, deal with this
		 * later...by either not accepting layouts whose
		 * size is less than a page size, or forcing sync
		 * writes to such layouts.
		 */
		pe = ps + PAGESIZE - 1;
		ASSERT(pe > layout->plo_offset && pe < lend);

		/*
		 * Step through the page by stripe unit width
		 * and update the appropriate extent for the offset.
		 */
		do {
			sui = (ps / layout->plo_stripe_unit) %
			    layout->plo_stripe_count;
			sui += ext_index;
			ext = &exts[sui];
			if (ext->ce_length == 0) {
				ext->ce_offset = pp->p_offset;
				ext->ce_length = PAGESIZE;
			} else if (pp->p_offset < ext->ce_offset) {
				ext->ce_length = ext->ce_offset -
				    pp->p_offset + ext->ce_length;
				ext->ce_offset = pp->p_offset;
			} else if ((ext->ce_offset + ext->ce_length) <=
			    pp->p_offset) {
				ext->ce_length = pp->p_offset -
				    ext->ce_offset + PAGESIZE;
			}
			ps += layout->plo_stripe_unit;
		} while (ps < pe);
	} while ((pp = pp->p_next) != plist);

	/*
	 * XXXKLR this needs cleaned up too.  Since we can have
	 * multiple layouts, we may end up with more than one dispatched
	 * to MDS, or some to MDS and still others to DS.  Need to
	 * do commits to MDS async then in another task, so we don't need to
	 * wait for them to complete here before dispatching commits to the
	 * DSes
	 */
	ext_index = 0;
	job = file_io_commit_alloc();
	for (lol = list_head(&lom->lm_layouts); lol;
	    lol = list_next(&lom->lm_layouts, lol)) {
		layout = lol->l_layout;
		ASSERT(layout != NULL);
		if (layout->plo_flags & PLO_COMMIT_MDS) {
			error = pnfs_commit_mds(vp, plist, layout,
			    &exts[ext_index], offset, count, cr);
		} else {
			nfs4_init_stateid_types(&sid_types);
			job->fic_vp = vp;
			job->fic_plist = plist;
			stripewidth = layout->plo_stripe_unit *
			    layout->plo_stripe_count;
			for (i = 0; i < layout->plo_stripe_count; i++) {
				ext = &exts[i + ext_index];
				/* skip data servers that do not need commit */
				if (ext->ce_length == 0) {
					ext_index += layout->plo_stripe_count;
					continue;
				}
				task = kmem_cache_alloc(
				    commit_task_cache, KM_SLEEP);
				task->cm_job = job;
				task->cm_cred = cr;
				crhold(task->cm_cred);
				task->cm_layout = layout;
				off = ext->ce_offset;
				ASSERT(off >= layout->plo_pattern_offset);
				task->cm_offset = off -
				    layout->plo_pattern_offset;
				if (layout->plo_stripe_type ==
				    STRIPE4_DENSE)
					task->cm_offset =
					    (task->cm_offset / stripewidth)
					    * layout->plo_stripe_unit +
					    (off % layout->plo_stripe_unit);
				task->cm_sui = i;
				task->cm_dev = layout->plo_stripe_dev[i];
				stripe_dev_hold(task->cm_dev);
				task->cm_count = ext->ce_length;
				/*
				 * XXXcommit - reconcile vp, cr, opnum, and
				 * ophint between
				 * the commit_task_t and the nfs4_call_t.
				 */
				task->cm_call = nfs4_call_init(TAG_PNFS_COMMIT,
				    OP_COMMIT, OH_COMMIT, FALSE, mi, vp, NULL,
				    cr);
				task->cm_call->nc_ds_servinfo =
				    task->cm_dev->std_svp;
				task->cm_recov_state.rs_flags = 0;
				task->cm_recov_state.rs_num_retry_despite_err
				    = 0;

				/*
				 * XXXcommit - Add the task to the job list
				 * here. Convert task dispatching to
				 * pnfs_commit_start() which will
				 * coordinate with recovery.
				 */
				++remaining;
				(void) taskq_dispatch
				    (mi->mi_pnfs_io_taskq,
				    pnfs_task_commit, task,
				    0);
			}

		}
		ext_index += layout->plo_stripe_count;
	}

	if (job) {
		mutex_enter(&job->fic_lock);
		job->fic_remaining += remaining;
		while (job->fic_remaining > 0) {
			nosig = cv_wait_sig(&job->fic_cv,
			    &job->fic_lock);
			if ((nosig == 0) && (job->fic_error == 0))
				job->fic_error = EINTR;
		}

		/*
		 * XXXcommit - loop through the task list to see if the task
		 * needs to be redispatched or if recovery needs to be
		 * initiated.
		 */
		error = job->fic_error;
		mutex_exit(&job->fic_lock);
	}

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	if (!error && lastwriteoff != 0) {
recov_retry:
		cp = nfs4_call_init(TAG_LAYOUTCOMMIT, OP_LAYOUTCOMMIT,
		    OH_OTHER, FALSE, mi, NULL, NULL, cr);

		e.error = nfs4_start_op(cp, &recov_state);
		/*
		 * XXXKLR - If there is an error here we won't clear
		 * the R4LASTBYTE bit.  Next pnfs_commit will possibly
		 * then do the layoutcommit.  However, if there isn't
		 * another pnfs_commit(), we need a way to make sure
		 * the layoutcommit() is sent to the MDS.  Possibly
		 * set a bit here, R4FORCELASTBYTE, maybe, which
		 * close can check and send the layoutcommit?  Would
		 * we also need to save the last_write_offset here to
		 * in another field in the rnode?  Need to look into this
		 * error handling more.
		 */
		if (e.error)
			goto out;


		/* putfh target fh */
		(void) nfs4_op_cputfh(cp, rp->r_fh);

		(void) nfs4_op_layoutcommit(cp, &la);

		mutex_enter(&rp->r_statelock);
		(void) nfs4_op_cputfh(cp, rp->r_fh);
		la->loca_stateid = pnfs_get_losid(rp);
		mutex_exit(&rp->r_statelock);

		la->loca_last_write_offset.newoffset4_u.no_offset =
		    lastwriteoff;
		la->loca_offset = 0;
		la->loca_length = PNFS_LAYOUTEND;
		la->loca_reclaim = FALSE;
		la->loca_last_write_offset.no_newoffset = TRUE;
		la->loca_time_modify.nt_timechanged = FALSE;
		la->loca_layoutupdate.lou_type = LAYOUT4_NFSV4_1_FILES;
		la->loca_layoutupdate.lou_body.lou_body_len = 0;
		la->loca_layoutupdate.lou_body.lou_body_val = NULL;

		rfs4call(cp, &e);

		nfs4_needs_recovery(cp);
		if (cp->nc_needs_recovery) {
			/*
			 * XXXKLR - If we need recovery, start it here
			 * and just bail for now.  Recovery may actually
			 * handle the layoutcommit, but we are not
			 * guarenteed to still even be holding the layout
			 * after recovery.
			 */
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4_pnfs_commit_layoutcommit: "
			    "initiating recovery\n"));
			(void) nfs4_start_recovery(cp);
			nfs4_end_op(cp, &recov_state);
			nfs4_call_rele(cp);
			goto recov_retry;
		}

		nfs4_end_op(cp, &recov_state);
		nfs4_call_rele(cp);

		if (e.error)
			goto out;
		mutex_enter(&rp->r_statelock);
		/*
		 * Is it possible that another write could have
		 * occurred that extended the last byte written
		 * beyond lastwriteoffset?  If so we do not want
		 * to clear the R4LASTBYTE.
		 */
		if (lastwriteoff == rp->r_last_write_offset)
			rp->r_flags &= ~ R4LASTBYTE;
		mutex_exit(&rp->r_statelock);
	}


out:
	pnfs_release_layouts(np, rp, lom, LOM_COMMIT);

	kmem_free(exts, exts_size);

	mutex_enter(&np->s_lock);
	nfs4_server_rele_lockt(np);

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_commit_free, job, 0);

	return (error);
}
