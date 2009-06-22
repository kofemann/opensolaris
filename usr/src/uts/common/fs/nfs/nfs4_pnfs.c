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
	mi->mi_pnfs_io_taskq = taskq_create("pnfs_io_taskq",
	    nfs4_pnfs_io_nthreads,
	    minclsyspri, 1, nfs4_pnfs_io_maxalloc, TASKQ_PERZONE);
	mi->mi_pnfs_other_taskq = taskq_create("pnfs_other_taskq",
	    nfs4_pnfs_other_nthreads,
	    minclsyspri, 1, nfs4_pnfs_other_maxalloc,
	    TASKQ_PERZONE);
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
pnfs_trash_devtree(nfs4_server_t *n4sp)
{
	devnode_t *dp;
	void *cookie = NULL;
	int ns;
#ifdef	NOTYET
	int i;
	servinfo4_t *dssp;	/* for the data servers */
#endif

	/* The server structure is being decommissioned, no locking needed. */

	while ((dp = avl_destroy_nodes(&n4sp->s_devid_tree, &cookie)) != NULL) {
		if (dp->dn_count > 0)
			cmn_err(CE_WARN, "devnode count > 0");
		else {
			ns = dp->dn_ds_addrs.mpl_len;
			xdr_free(xdr_nfsv4_1_file_layout_ds_addr4,
			    (char *)&dp->dn_ds_addrs);
			/*
			 * Free the servinfo4 from the device.  This will
			 * need to change when multiple servers are present
			 * in the list.
			 */
#ifdef	NOTYET
			/*
			 * XXX - The servinfo4 cannot be freed yet because
			 * it is in use by the heartbeat thread.
			 */
			for (i = 0; i < ns; i++)
				if ((dssp = dp->dn_server_list[i].ds_curr_serv)
				    != NULL) {
					sv4_free(dssp);
				}
#endif

			kmem_free(dp->dn_server_list, ns * sizeof (ds_info_t));
			kmem_free(dp, sizeof (devnode_t));
		}
	}
	avl_destroy(&n4sp->s_devid_tree);
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

static int
pnfs_use_layout(rnode4_t *rp)
{
	ASSERT(MUTEX_HELD(&rp->r_statelock));
	if (! (rp->r_flags & R4LAYOUTVALID))
		return (0);

	/*
	 * check i/o mode
	 * check layout segments, not just all-or-nothing
	 */
	return (1);
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
 * Build a servinfo4 structure for the server described by IP address
 * in netbuf.  If necessary, make a new nfs4_server_t/servinfo4_t and
 * perform an Exchange ID and Create Session if needed.  On success,
 * return 0 and set *svpp to point to the servinfo4 we found or created.
 * Otherwise, return an error.
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
	nfs4_server_t *np;
	nfs4_error_t e = {0, 0, 0};
	int ri;
	int error = 0;

	if (nap == NULL || mi == NULL) {
		return (EINVAL);
	}

	if (netaddr2netbuf(nap, &nb, &knc)) {
		return (EINVAL);
	}

retry:
	mutex_enter(&nfs4_server_lst_lock);
	if ((np = find_nfs4_server_by_addr(&nb, &knc)) != NULL) {
		/*
		 * N.B., find_nfs4_server_by_addr() drops the
		 * nfs4_server_lst_lock when it returns a match
		 */
		if (np->s_flags & N4S_EXID_FAILED) {
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			kmem_free(nb.buf, nb.maxlen);
			return (EIO);
		}

		if (!(np->s_flags & (N4S_CLIENTID_SET|N4S_SESSION_CREATED))) {
			/* Not ready for prime time */
			cv_wait(&np->s_clientid_pend, &np->s_lock);
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			goto retry;
		}

		/*
		 * XXXrsb - This will likely go away when ds_info_t
		 * is implemented.
		 */
		if (np->s_ds_svp == NULL) {
			svp = new_servinfo4(mi, nap->na_r_addr,
			    &knc, &nb, SV4_ISA_DS);
			np->s_ds_svp = svp;
		} else
			svp = np->s_ds_svp;

		mutex_exit(&np->s_lock);
		kmem_free(nb.buf, nb.maxlen);

		*svpp = svp;
		return (0);
	}

	svp = new_servinfo4(mi, nap->na_r_addr, &knc, &nb, SV4_ISA_DS);
	np = add_new_nfs4_server(svp, kcred);
	np->s_ds_svp = svp;

	mutex_exit(&np->s_lock);
	mutex_exit(&nfs4_server_lst_lock);

	/*
	 * XXXrsb - Either we should use start_op/end_op or
	 * nfs4exchange_id_otw() should use start_op/end_op
	 * before it calls (some form of) rfs4call()
	 */
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);

	nfs4exchange_id_otw(mi, svp, kcred, np, &e, &ri);

	nfs_rw_exit(&mi->mi_recovlock);

	/*
	 * Drop the initial reference on the nfs4_server.  The
	 * list still maintains a ref as well as the heartbeat
	 * thread, started by nfs4exchange_id_otw et al.
	 */
	nfs4_server_rele(np);

	if (e.error || e.stat) {
		mutex_enter(&np->s_lock);
		np->s_flags |= N4S_EXID_FAILED;
		cv_broadcast(&np->s_clientid_pend);
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		cmn_err(CE_WARN,
		    "netaddr4_to_servinfo4: exchange_id failed %d, %d",
		    e.error, e.stat);
		error = e.error;
	} else {
		/* All good, let's go home */
		*svpp = svp;
	}

	kmem_free(nb.buf, nb.maxlen);
	return (error);
}

static void
pnfs_rele_device(nfs4_server_t *np, devnode_t *dp)
{
	ASSERT(MUTEX_HELD(&np->s_lock));
	ASSERT(dp->dn_count > 0);
	dp->dn_count--;
	/*
	 * No point in caching a failed getdeviceinfo.  Throw away
	 * the devnode.  The devnode cannot have a server list or
	 * xdr data since getdeviceinfo failed.
	 */
	if (dp->dn_flags & DN_GDI_FAILED && dp->dn_count == 0) {
		avl_remove(&np->s_devid_tree, dp);
		kmem_free(dp, sizeof (*dp));
	}
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
	servinfo4_t *svp;	/* servinfo4 for the target DS */
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
		/*
		 * Drop these locks since netaddr4_to_servinfo4()
		 * may go OTW to do EXID/CR_SESS.
		 */
		mutex_exit(&mdsp->s_lock);
		error = netaddr4_to_servinfo4(nap, mi, &svp);
		mutex_enter(&mdsp->s_lock);

		if (error) {
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

/*ARGSUSED*/
static devnode_t *
pnfs_create_device(nfs4_server_t *n4sp, deviceid4 devid, avl_index_t where)
{
	devnode_t *new;

	new = kmem_zalloc(sizeof (devnode_t), KM_SLEEP);
	DEV_ASSIGN(new->dn_devid, devid);
	new->dn_count = 1;
	cv_init(new->dn_cv, NULL, CV_DEFAULT, NULL);

	/* insert the new devid into the tree */
	avl_insert(&n4sp->s_devid_tree, new, where);
	return (new);
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

void
layoutget_to_layout(LAYOUTGET4res *res, rnode4_t *rp, mntinfo4_t *mi)
{
	pnfs_layout_t *layout = NULL;
	layout4 *l4;
	nfsv4_1_file_layout4	*file_layout4;
	XDR xdr;
	int i;
	timespec_t now;

	if ((res == NULL) || (res->logr_status != NFS4_OK))
		return;

	if (res->LAYOUTGET4res_u.logr_resok4.logr_layout.logr_layout_len > 1) {
		cmn_err(CE_WARN, "too many entries in layout; dropping");
		return;
	}

	l4 = res->LAYOUTGET4res_u.logr_resok4.logr_layout.logr_layout_val;

	if (l4->lo_content.loc_type != LAYOUT4_NFSV4_1_FILES) {
		cmn_err(CE_WARN, "non-file layout; dropping");
		return;
	}

	/* XXX deal with byte ranges and i/o modes */

	/* XXX decode opaque layout */

	xdrmem_create(&xdr,
	    l4->lo_content.loc_body.loc_body_val,
	    l4->lo_content.loc_body.loc_body_len,
	    XDR_DECODE);
	file_layout4 = kmem_zalloc(sizeof (*file_layout4), KM_SLEEP);
	if (!xdr_nfsv4_1_file_layout4(&xdr, file_layout4)) {
		cmn_err(CE_WARN, "could not decode file_layouttype4");
		return;
	}

	layout = kmem_cache_alloc(pnfs_layout_cache, KM_SLEEP);
	layout->plo_iomode = l4->lo_iomode;
	layout->plo_flags = 0;
	layout->plo_offset = l4->lo_offset;
	layout->plo_length = l4->lo_length;
	layout->plo_inusecnt = 0;

	if (res->LAYOUTGET4res_u.logr_resok4.logr_return_on_close)
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
#ifdef	WEBXXX
	if (file_layout4->N_LEN > 0) {
		cmn_err(CE_WARN,
		    "dropping layout due to complex devices %p len %d lenny %d",
		    (void *)l4->lo_content.loc_body.loc_body_val,
		    l4->lo_content.loc_body.loc_body_len, file_layout4->N_LEN);
		/* XXX free memory and stuff */
		return;
	}
#endif
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
	/* XXX free memory and stuff */
	layout->plo_refcount = 1;

	rp->r_lostateid = res->LAYOUTGET4res_u.logr_resok4.logr_stateid;
	rp->r_flags |= R4LAYOUTVALID;
	/*
	 * Insert pnfs_layout_t into list, just add at head for now since we
	 * are only dealing with single layouts.
	 */
	gethrestime(&now);
	layout->plo_creation_sec = now.tv_sec;
	layout->plo_creation_musec = now.tv_nsec / (NANOSEC / MICROSEC);
	list_insert_head(&rp->r_layout, layout);
}

void
pnfs_layout_discard(rnode4_t *rp, nfs4_fsidlt_t *ltp, nfs4_server_t *np)
{
	ASSERT(MUTEX_HELD(&ltp->lt_rlt_lock));
	mutex_enter(&rp->r_statelock);
	if (!(rp->r_flags & R4LAYOUTVALID)) {
		mutex_exit(&rp->r_statelock);
		return;
	}
	pnfs_layout_rele(rp);
	if (list_head(&rp->r_layout)) {
		/*
		 * There are still layouts present.  This will
		 * need to be handled by synchronizing layout
		 * usage with recalls, but this is good enough
		 * for now.
		 */
		mutex_exit(&rp->r_statelock);
		cmn_err(CE_WARN, "pnfs_layout_discard: dangling layout");
		return;
	}
	rp->r_flags &= ~ R4LAYOUTVALID;
	mutex_exit(&rp->r_statelock);
	avl_remove(&ltp->lt_rlayout_tree, rp);
	nfs4_server_rele(np);
}

static void
pnfs_task_layoutreturn(void *v)
{
	task_layoutreturn_t *task = v;
	mntinfo4_t *mi = task->tlr_mi;
	nfs4_server_t *np;
	nfs4_fsidlt_t *ltp, lt;
	rnode4_t *found, *rp;
	nfs4_call_t *cp;
	LAYOUTRETURN4args *arg;
	LAYOUTRETURN4res *lrres;
	layoutreturn_file4 *lrf;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	nfs4_recov_state_t recov_state;
	avl_index_t where;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	cp = nfs4_call_init(TAG_PNFS_LAYOUTRETURN, OP_LAYOUTRETURN, OH_OTHER,
	    FALSE, mi, NULL, NULL, task->tlr_cr);

	/*
	 * XXX - todo need to pass vp for LAYOUTRETURN4_FILE
	 * XXX - if start_op fails, should we remove the layout from the tree?
	 */
	if (nfs4_start_op(cp, &recov_state))
		goto out;

	if (task->tlr_return_type == LAYOUTRETURN4_FILE) {
		rp = VTOR4(task->tlr_vp);
		(void) nfs4_op_cputfh(cp, rp->r_fh);
	} else if (task->tlr_return_type == LAYOUTRETURN4_FSID) {
		(void) nfs4_op_cputfh(cp, mi->mi_rootfh);
	} else {
		ASSERT(task->tlr_return_type == LAYOUTRETURN4_ALL);
	}

	lrres = nfs4_op_layoutreturn(cp, &arg);
	arg->lora_layoutreturn.lr_returntype = task->tlr_return_type;
	lrf = &arg->lora_layoutreturn.layoutreturn4_u.lr_layout;
	lrf->lrf_offset = task->tlr_offset;
	lrf->lrf_length = task->tlr_length;
	lrf->lrf_stateid = task->tlr_stateid;
	lrf->lrf_body.lrf_body_len = 0;
	arg->lora_reclaim = task->tlr_reclaim;
	arg->lora_iomode = task->tlr_iomode;
	arg->lora_layout_type = task->tlr_layout_type;

	rfs4call(cp, &e);

	/* XXX need needs_recovery/start_recovery logic here */

	if (task->tlr_return_type == LAYOUTRETURN4_FSID ||
	    task->tlr_return_type == LAYOUTRETURN4_ALL)
		goto done;

	if (e.error == 0 && e.stat == NFS4_OK) {
		if (lrres->lorr_status == NFS4_OK) {
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
				 * only ever tries to hold one layout
				 * on a file at one time.  However
				 * because we have released the
				 * r_statelock, it is possible that
				 * another layoutget could have occurred
				 * after the pnfs_layout_rele() from
				 * pnfs_layoutreturn(), but before we
				 * have returned this layout, and thus
				 * I can see that this would result in
				 * this layoutreturn getting a new
				 * layoutstateid.  Issue a warning for
				 * now incase other things then look
				 * strange, but this is in the process of
				 * being fixed.
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
	np = find_nfs4_server(mi);
	ASSERT(np != NULL);
	mutex_exit(&np->s_lock);
	mutex_enter(&np->s_lt_lock);

	lt.lt_fsid.major = rp->r_srv_fsid.major;
	lt.lt_fsid.minor = rp->r_srv_fsid.minor;

	ltp = avl_find(&np->s_fsidlt, &lt, &where);
	ASSERT(ltp != NULL);
	if (ltp) {
		mutex_enter(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
		found = avl_find(&ltp->lt_rlayout_tree, rp, &where);
		if (found) {
			/*
			 * Remove from rnode by file handle avl tree, and also
			 * from the rnode by fsid avl tree.  And decrement
			 * refcnt of nfs4_server_t that occurred when an
			 * rnode was put onto an fsid's tree.
			 */
			avl_remove(&ltp->lt_rlayout_tree, rp);
			nfs4_server_rele(np);
		}
		mutex_exit(&ltp->lt_rlt_lock);
	} else {
		mutex_exit(&np->s_lt_lock);
	}

	nfs4_server_rele(np);
done:
	nfs4_end_op(cp, &recov_state);
	/*
	 * At this point, we don't worry about failure.  We will either
	 * be asked to return the layout again, or the servers will stop
	 * honoring the layout.  Either way, we (the client) are through
	 * with the layout, and have tried to return it.
	 */

out:
	nfs4_call_rele(cp);
	task_layoutreturn_free(task);
}

int pnfs_no_layoutget;

static void
pnfs_task_layoutget(void *v)
{
	task_layoutget_t *task = v;
	mntinfo4_t *mi = task->tlg_mi;
	nfs4_server_t *np;
	rnode4_t *rp = VTOR4(task->tlg_vp);
	nfs4_call_t *cp;
	LAYOUTGET4args *arg;
	LAYOUTGET4res *resp;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int trynext_sid = 0;
	rnode4_t	*found;
	avl_index_t	where;
	nfs4_fsidlt_t lt, *ltp;
	cred_t *cr = task->tlg_cred;
	nfs4_recov_state_t recov_state;
	nfs4_stateid_types_t sid_types;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/*
	 * This code assumes we don't already have a layout and
	 * therefore, just use the delegation, lock or open stateID.
	 * If this function is used to get more layouts when we already
	 * have one, then it will need to be changed to grab the current
	 * layout stateid.
	 */
	nfs4_init_stateid_types(&sid_types);

recov_retry:
	cp = nfs4_call_init(TAG_PNFS_LAYOUTGET, OP_LAYOUTGET, OH_OTHER, FALSE,
	    mi, NULL, NULL, cr);

	if (pnfs_no_layoutget)
		goto out;

	(void) nfs4_op_cputfh(cp, rp->r_fh);
	resp = nfs4_op_layoutget(cp, &arg);

	arg->loga_layout_type = LAYOUT4_NFSV4_1_FILES;
	arg->loga_iomode = task->tlg_iomode;
	arg->loga_offset = 0;
	arg->loga_length = ~0;
	arg->loga_minlength = 8192; /* XXX */
	arg->loga_maxcount = mi->mi_tsize;
	arg->loga_stateid = nfs4_get_stateid(cr, rp, -1, mi, OP_READ,
	    &sid_types, (GETSID_LAYOUT | trynext_sid));

	/*
	 * If we ended up with the special stateid, this means the
	 * file isn't opened and does not have a delegation stateid to use
	 * either.  At this point we can not get a layout.
	 */
	if (sid_types.cur_sid_type == SPEC_SID)
		goto out;

	if (nfs4_start_op(cp, &recov_state))
		goto out;

	rfs4call(cp, &e);

	if ((e.error == 0) && (e.stat == NFS4_OK)) {
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4LAYOUTVALID) {
			pnfs_layout_return(task->tlg_vp, cr, rp->r_lostateid,
			    LR_ASYNC);
		}
		layoutget_to_layout(resp, rp, mi);
		mutex_exit(&rp->r_statelock);

		/*
		 * Create fsid layout tree if one doesn't exist
		 * and add the rnode to its rnode layout tree.
		 */
		lt.lt_fsid.major = rp->r_srv_fsid.major;
		lt.lt_fsid.minor = rp->r_srv_fsid.minor;
		np = find_nfs4_server(mi);
		ASSERT(np != NULL);
		mutex_exit(&np->s_lock);

		mutex_enter(&np->s_lt_lock);
		/*
		 * Find the fsid layout node for the fsid of this rnode.
		 * If none found, no layouts have occurred for this fsid,
		 * so create a new fsid layout tree node and insert it
		 * into the tree.
		 *
		 * Insert the rnode into the rnode layout tree in the fsid
		 * node.
		 */
		ltp = avl_find(&np->s_fsidlt, &lt, &where);
		if (ltp == NULL) {
			ltp = kmem_alloc(sizeof (*ltp), KM_SLEEP);
			ltp->lt_fsid.major = lt.lt_fsid.major;
			ltp->lt_fsid.minor = lt.lt_fsid.minor;
			mutex_init(&ltp->lt_rlt_lock, NULL,
			    MUTEX_DEFAULT, NULL);
			avl_create(&ltp->lt_rlayout_tree, layoutcmp,
			    sizeof (rnode4_t), offsetof(rnode4_t, r_avl));
			avl_insert(&np->s_fsidlt, ltp, where);
		}
		mutex_enter(&ltp->lt_rlt_lock);
		mutex_exit(&np->s_lt_lock);
		found = avl_find(&ltp->lt_rlayout_tree, rp, &where);
		if (found == NULL) {
			/*
			 * When adding an rnode to the fsid layout tree,
			 * increment the nfs4_server_t's refcnt.  This is done
			 * here instead of when the nfs4_fsid is added to the
			 * nfs4_server_t's fsid layout tree, because, the
			 * nfs4_fsidlt_t's on the nfs4_server_t structure
			 * will exist until the nfs4_server_t is destroyed,
			 * even if there are no rnodes the nfs4_fsid's
			 * rnode layout tree.
			 */
			avl_insert(&ltp->lt_rlayout_tree, rp, where);
			nfs4_server_hold(np);
		}
		mutex_exit(&ltp->lt_rlt_lock);
		nfs4_server_rele(np);
	} else if (e.error == 0 && cp->nc_res.status == NFS4ERR_BAD_STATEID &&
	    sid_types.cur_sid_type != OPEN_SID) {
		nfs4_save_stateid(&arg->loga_stateid, &sid_types);
		trynext_sid = GETSID_TRYNEXT;
		nfs4_end_op(cp, &recov_state);
		nfs4_call_rele(cp);
		goto recov_retry;
	} else if (e.error == 0 &&
	    cp->nc_res.status == NFS4ERR_LAYOUTUNAVAILABLE) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4LAYOUTUNAVAIL;
		mutex_exit(&rp->r_statelock);
	}

	nfs4_end_op(cp, &recov_state);

out:
	nfs4_call_rele(cp);
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4LOGET;
	cv_broadcast(&rp->r_lowait);
	mutex_exit(&rp->r_statelock);

	if (! (task->tlg_flags & TLG_NOFREE))
		task_layoutget_free(task);
}


void
pnfs_sync_layoutget(vnode_t *vp, cred_t *cr, layoutiomode4 mode)
{
	task_layoutget_t task;
	mntinfo4_t *mi = VTOMI4(vp);

	task.tlg_flags = TLG_NOFREE;
	task.tlg_cred = cr;
	task.tlg_mi = mi;
	task.tlg_vp = vp;
	task.tlg_iomode = mode;

	pnfs_task_layoutget(&task);
}

void
pnfs_layoutget(vnode_t *vp, cred_t *cr, layoutiomode4 mode)
{
	task_layoutget_t *task;
	mntinfo4_t *mi = VTOMI4(vp);
	rnode4_t *rp = VTOR4(vp);

	/*
	 * If we don't have an fsid on this rnode, don't bother trying
	 * to get a layout, cause if server does layoutrecall by fsid
	 * we won't know the fsid of this rnode.
	 */
#if 0
	/* this check is not correct, fsid == 0 is perfectly valid */
	if (rp->r_srv_fsid.major == 0 && rp->r_srv_fsid.minor == 0)
		return;
#endif

	mutex_enter(&rp->r_statelock);

	/*
	 * If a Layoutget is in progress, simply wait
	 * for it to finish and return.  It is still up
	 * to the caller to determine if a layout exists.
	 */
	if (rp->r_flags & R4LOGET) {
		(void) cv_wait_sig(&rp->r_lowait, &rp->r_statelock);
		mutex_exit(&rp->r_statelock);
		return;
	}

	rp->r_flags |= R4LOGET;
	rp->r_last_layoutget = lbolt;
	mutex_exit(&rp->r_statelock);

	task = kmem_cache_alloc(task_layoutget_cache, KM_SLEEP);
	task->tlg_flags = 0;
	crhold(cr);
	task->tlg_cred = cr;
	MI4_HOLD(mi);
	task->tlg_mi = mi;
	VN_HOLD(vp);
	task->tlg_vp = vp;
	task->tlg_iomode = mode;

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
pnfs_layout_return(vnode_t *vp, cred_t *cr, stateid4 losid, int aflag)
{
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);
	task_layoutreturn_t *task;
	pnfs_layout_t *layout;
	layoutiomode4 iomode;

	if (! (rp->r_flags & R4LAYOUTVALID))
		return;

	if ((aflag == LR_SYNC) &&
	    (nfs_zone() != mi->mi_zone)) {
		return;
	}

	ASSERT(MUTEX_HELD(&rp->r_statelock));

	layout = list_head(&rp->r_layout);

	if (layout == NULL)
		return;

	iomode = layout->plo_iomode;

	rp->r_flags &= ~R4LAYOUTVALID;
	pnfs_layout_rele(rp);

	task = kmem_cache_alloc(task_layoutreturn_cache, KM_SLEEP);
	VN_HOLD(vp);
	task->tlr_vp = vp;
	task->tlr_mi = mi;
	MI4_HOLD(mi);
	task->tlr_cr = cr;
	crhold(cr);

	task->tlr_offset = 0;
	task->tlr_length = ~0;
	task->tlr_reclaim = 0; /* XXX */
	task->tlr_iomode = iomode;
	task->tlr_layout_type = LAYOUT4_NFSV4_1_FILES;
	task->tlr_stateid = losid;
	task->tlr_return_type = LAYOUTRETURN4_FILE;

	if (aflag == LR_ASYNC)
		(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
		    pnfs_task_layoutreturn, task, 0);
	else {
		/* drop the mutex for the otw call */
		mutex_exit(&rp->r_statelock);
		pnfs_task_layoutreturn(task);
		mutex_enter(&rp->r_statelock);
	}
}

void
pnfs_layoutreturn_bulk(mntinfo4_t *mi, cred_t *cr, int how)
{
	task_layoutreturn_t *task;

	task = kmem_cache_alloc(task_layoutreturn_cache, KM_SLEEP);
	task->tlr_vp = NULL;
	task->tlr_mi = mi;
	MI4_HOLD(mi);
	task->tlr_cr = cr;
	crhold(cr);

	task->tlr_offset = 0;
	task->tlr_length = ~0;
	/* the spec says reclaim is always false for FSID or ALL */
	task->tlr_reclaim = 0;
	task->tlr_iomode = LAYOUTIOMODE4_ANY;
	task->tlr_layout_type = LAYOUT4_NFSV4_1_FILES;
	task->tlr_stateid = clnt_special0;
	task->tlr_return_type = how;

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_layoutreturn, task, 0);
}

void
pnfs_layout_hold(rnode4_t *rp, pnfs_layout_t *layout)
{
	ASSERT(MUTEX_HELD(&rp->r_statelock));
	layout->plo_refcount++;
}

void
pnfs_layout_rele(rnode4_t *rp)
{
	pnfs_layout_t	*layout = NULL;
	int i;

	ASSERT(MUTEX_HELD(&rp->r_statelock));

	/*
	 * Only 1 layout for now.
	 */
	layout = list_head(&rp->r_layout);
	if (layout == NULL)
		return;
	layout->plo_refcount--;
	if (layout->plo_refcount > 0)
		return;
	ASSERT((layout->plo_flags & (PLO_RETURN|PLO_GET|PLO_RECALL)) == 0);
	ASSERT(layout->plo_inusecnt == 0);

	list_remove(&rp->r_layout, layout);

	for (i = 0; i < layout->plo_stripe_count; i++)
		stripe_dev_rele(layout->plo_stripe_dev + i);

	kmem_free(layout->plo_stripe_dev,
	    layout->plo_stripe_count * sizeof (stripe_dev_t *));

	kmem_cache_free(pnfs_layout_cache, layout);
}

void
pnfs_start_read(read_task_t *task)
{
	nfs4_call_t *cp = task->rt_call;
	/*
	 * Synchronize with recovery actions.  If either the MDS or
	 * the target DS are in recovery, or need recovery, then
	 * start_op will block.
	 * end_op is called before starting task to avoid possible race.
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
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);
	int i, error = 0;
	int remaining = 0;
	file_io_read_t *job;
	read_task_t *task, *next;
	pnfs_layout_t *layout = NULL;
	uint32_t stripenum, stripeoff;
	length4 stripewidth;
	nfs4_stateid_types_t sid_types;
	offset_t orig_off = off;
	int orig_count = count;
	uio_t *uio_sav = NULL;
	caddr_t xbase;
	int nosig;
	int more_work, too_much;

	mutex_enter(&rp->r_statelock);
	layout = list_head(&rp->r_layout);
	if ((!(rp->r_flags & (R4LAYOUTVALID|R4LAYOUTUNAVAIL)) ||
	    layout == NULL)) {
		mutex_exit(&rp->r_statelock);
		pnfs_layoutget(vp, cr, LAYOUTIOMODE4_RW);
		mutex_enter(&rp->r_statelock);
		layout = list_head(&rp->r_layout);
	}


	if (layout == NULL || !(rp->r_flags & R4LAYOUTVALID)) {
		/*
		 * Now we will do proxy I/O
		 */
		VTOR4(vp)->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		return (EAGAIN);
	}
	pnfs_layout_hold(rp, layout);
	mutex_exit(&rp->r_statelock);

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

	for (i = 0; i < layout->plo_stripe_count; i++) {
		error = stripe_dev_prepare(mi, layout->plo_stripe_dev[i],
		    layout->plo_first_stripe_index, i, cr);
		if (error) {
			mutex_enter(&rp->r_statelock);
			pnfs_layout_rele(rp);
			mutex_exit(&rp->r_statelock);
			return (error);
		}
	}

	job = file_io_read_alloc();
	job->fir_count = count;
	nfs4_init_stateid_types(&sid_types);
	job->fir_stateid = nfs4_get_stateid(cr, rp, curproc->p_pidp->pid_id,
	    mi, OP_READ, &sid_types, (async ? GETSID_TRYNEXT : 0));

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

		task->rt_offset = off;
		if (layout->plo_stripe_type == STRIPE4_DENSE)
			task->rt_offset = (off / stripewidth)
			    * layout->plo_stripe_unit
			    + stripeoff;
		task->rt_count = MIN(layout->plo_stripe_unit - stripeoff,
		    count);
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
		task->rt_call->nc_ds_servinfo = task->rt_dev->std_svp;
		task->rt_recov_state.rs_flags = 0;
		task->rt_recov_state.rs_num_retry_despite_err = 0;

		off += task->rt_count;
		if (base)
			base += task->rt_count;
		count -= task->rt_count;

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
			error = uiomove(xbase, (orig_count - *residp), UIO_READ,
			    uio_sav);
		kmem_free(xbase, orig_count);
	}

	mutex_enter(&rp->r_statelock);
	pnfs_layout_rele(rp);
	mutex_exit(&rp->r_statelock);

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
	 * end_op is called before starting task to avoid possible race.
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
	int i, error = 0;
	file_io_write_t *job;
	write_task_t *task, *next;
	rnode4_t *rp = VTOR4(vp);
	pnfs_layout_t *layout;
	uint32_t stripenum, stripeoff;
	length4 stripewidth;
	mntinfo4_t *mi = VTOMI4(vp);
	int remaining = 0;
	nfs4_stateid_types_t sid_types;
	int nosig;
	int more_work, too_much;

	mutex_enter(&rp->r_statelock);
	layout = list_head(&rp->r_layout);
	if ((layout == NULL || !(rp->r_flags &
	    (R4LAYOUTUNAVAIL|R4LAYOUTVALID)))) {
		mutex_exit(&rp->r_statelock);
		pnfs_layoutget(vp, cr, LAYOUTIOMODE4_RW);
		mutex_enter(&rp->r_statelock);
		layout = list_head(&rp->r_layout);
	}

	/* XXX refactor needed with pnfs_read() above */
	if (layout == NULL || !(rp->r_flags & R4LAYOUTVALID)) {
		/*
		 * We will now resort to proxy I/O.
		 */
		VTOR4(vp)->r_proxyio_count++;
		mutex_exit(&rp->r_statelock);
		return (EAGAIN);
	}

	pnfs_layout_hold(rp, layout);
	mutex_exit(&rp->r_statelock);

	for (i = 0; i < layout->plo_stripe_count; i++) {
		error = stripe_dev_prepare(mi, layout->plo_stripe_dev[i],
		    layout->plo_first_stripe_index, i, cr);
		if (error) {
			mutex_enter(&rp->r_statelock);
			pnfs_layout_rele(rp);
			mutex_exit(&rp->r_statelock);
			return (error);
		}
	}

	job = file_io_write_alloc();
	nfs4_init_stateid_types(&sid_types);
	job->fiw_stateid = nfs4_get_w_stateid(cr, rp, curproc->p_pidp->pid_id,
	    mi, OP_WRITE, &sid_types, NFS4_WSID_PNFS);
	job->fiw_vp = vp;
	job->fiw_stable_how = *stab_comm;
	job->fiw_stable_result = FILE_SYNC4;
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
		task->wt_offset = off;
		task->wt_voff = off;
		if (layout->plo_stripe_type == STRIPE4_DENSE)
			task->wt_offset = (off / stripewidth)
			    * layout->plo_stripe_unit
			    + stripeoff;
		task->wt_sui = stripenum % layout->plo_stripe_count;
		task->wt_dev = layout->plo_stripe_dev[task->wt_sui];
		stripe_dev_hold(task->wt_dev);

		task->wt_base = base;
		/* XXX do we need a more conservative calculation? */
		task->wt_count = MIN(layout->plo_stripe_unit - stripeoff,
		    count);
		task->wt_call = nfs4_call_init(TAG_PNFS_WRITE, OP_WRITE,
		    OH_WRITE, FALSE, mi, vp, NULL, cr);
		task->wt_call->nc_ds_servinfo = task->wt_dev->std_svp;
		task->wt_recov_state.rs_flags = 0;
		task->wt_recov_state.rs_num_retry_despite_err = 0;

		off += task->wt_count;
		base += task->wt_count;
		count -= task->wt_count;
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
			task->wt_call = nfs4_call_init(TAG_PNFS_WRITE, OP_WRITE,
			    OH_WRITE, FALSE, mi, vp, NULL, cr);
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

	mutex_enter(&rp->r_statelock);
	pnfs_layout_rele(rp);
	mutex_exit(&rp->r_statelock);

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_write_free, job, 0);

	return (error);
}

/*
 * Gather layout statistics, XDR encode them, and copy them to the user space.
 */
int pnfs_collect_layoutstats(struct pnfs_getflo_args *args,
    model_t model, cred_t *cr)
{
	char *user_filename; /* Filename from the user space */
	char *data_buffer; /* Hold the XDR encoded stream */
	char *user_data_buffer; /* User space buffer */
	uint_t xdr_len;
	uint32_t *kernel_bufsize; /* Buffer size for the user space */
	uint32_t user_bufsize;
	uint32_t stp_ndx, mpl_index, num_servers;
	int stripe_num, error;
	vnode_t *vp;
	rnode4_t *rp;
	mntinfo4_t *mi;
	XDR xdrarg;
	layoutstats_t lostats;
	pnfs_layout_t *flayout;
	multipath_list4 *mpl_item;
	devnode_t *dip = NULL;
	stripe_info_t *si_node = NULL;
	nfsstat_lo_errcodes_t ec;
	nfs4_server_t *np;
	deviceid4 deviceid;
	uint_t plo_first_stripe_index;
	bool_t encode_failed;

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
	flayout = list_head(&rp->r_layout);
	if (((flayout == NULL) && (lostats.proxy_iocount == 0)) ||
	    !(rp->r_flags & R4LAYOUTVALID)) {
		mutex_exit(&rp->r_statelock);
		VN_RELE(vp);
		ec = ENOLAYOUT;
		return (ec);
	}

	lostats.plo_num_layouts = 0;
	lostats.plo_stripe_info_list.plo_stripe_info_list_val = NULL;
	lostats.plo_stripe_info_list.plo_stripe_info_list_len = 0;
	lostats.plo_stripe_count = 0;

	/*
	 * Now pluck the fields off the layout.
	 */
	if (flayout != NULL) {
		/* XXX: No multi-segment layouts */
		lostats.plo_num_layouts = 1;
		lostats.plo_stripe_count = flayout->plo_stripe_count;
		lostats.plo_status = flayout->plo_flags;
		lostats.plo_stripe_unit = flayout->plo_stripe_unit;
		lostats.iomode = flayout->plo_iomode;
		lostats.plo_offset = flayout->plo_offset;
		lostats.plo_length = flayout->plo_length;
		lostats.plo_creation_sec = flayout->plo_creation_sec;
		lostats.plo_creation_musec = flayout->plo_creation_musec;
		DEV_ASSIGN(deviceid, flayout->plo_deviceid);
		plo_first_stripe_index = flayout->plo_first_stripe_index;
		flayout = NULL;
		mutex_exit(&rp->r_statelock);

		dip = NULL;
		np = find_nfs4_server_nolock(mi);
		if (np) {
			error = pnfs_get_device(mi, np, deviceid, cr, &dip,
			    PGD_NO_OTW);
			mutex_exit(&np->s_lock);
		}

		if ((dip != NULL) && (error != EINPROGRESS) &&
		    (error != ENODEV)) {
			lostats.plo_stripe_info_list.plo_stripe_info_list_len =
			    lostats.plo_stripe_count;
			lostats.plo_stripe_info_list.plo_stripe_info_list_val =
			    kmem_zalloc(lostats.plo_stripe_count *
			    sizeof (stripe_info_t), KM_SLEEP);

			/*
			 * The reference count on *dip is sufficient for
			 * accessing these fields.
			 */
			for (stripe_num = 0; stripe_num <
			    lostats.plo_stripe_count; stripe_num++) {
				si_node = &lostats.plo_stripe_info_list.
				    plo_stripe_info_list_val[stripe_num];
				si_node->stripe_index = stripe_num;
				stp_ndx = (stripe_num +
				    plo_first_stripe_index) %
				    dip->dn_ds_addrs.stripe_indices_len;
				mpl_index = dip->dn_ds_addrs.
				    stripe_indices[stp_ndx];
				mpl_item = &dip->dn_ds_addrs.mpl_val[mpl_index];
				num_servers = mpl_item->multipath_list4_len;
				si_node->multipath_list.
				    multipath_list_len = num_servers;
				si_node->multipath_list.multipath_list_val =
				    mpl_item->multipath_list4_val;
			}
		}
	} else {
		mutex_exit(&rp->r_statelock);
	}

	/*
	 * Get the user buffer and fill it with XDR encoded stream.
	 */
	xdr_len = xdr_sizeof(xdr_layoutstats_t, &lostats);
	data_buffer = kmem_zalloc(xdr_len, KM_SLEEP);
	xdrmem_create(&xdrarg, data_buffer,  xdr_len, XDR_ENCODE);

	encode_failed = !xdr_layoutstats_t(&xdrarg, &lostats);

	/*
	 * The layout details been safely copied into another buffer,
	 * release locks and free kmem allocated memory. DO NOT USE
	 * xdr_free. It will free up kernel data structures, since we
	 * are using those pointers in the layoutstats data structure.
	 */
	if (np) {
		mutex_enter(&np->s_lock);
		if (dip) {
			pnfs_rele_device(np, dip);
			dip = NULL;
		}
		nfs4_server_rele_lockt(np);
		np = NULL;
	}
	VN_RELE(vp);

	if (lostats.plo_stripe_info_list.plo_stripe_info_list_val)
		kmem_free(lostats.plo_stripe_info_list.plo_stripe_info_list_val,
		    lostats.plo_stripe_count * sizeof (stripe_info_t));

	if (encode_failed) {
		kmem_free(data_buffer, xdr_len);
		DTRACE_PROBE(nfsstat__e__xdr_layoutstats_t_failed);
		ec = ESYSCALL;
		return (ec);
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
	mi->mi_last_getdevicelist = lbolt;
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
	int i, error = 0;
	file_io_commit_t *job = NULL;
	commit_task_t *task;
	rnode4_t *rp = VTOR4(vp);
	pnfs_layout_t *layout;
	length4 stripewidth;
	mntinfo4_t *mi = VTOMI4(vp);
	int remaining = 0;
	nfs4_stateid_types_t sid_types;
	int nosig;
	page_t *pp;
	offset4 off, ps, pe;
	commit_extent_t *exts, *ext;
	int exts_size;
	uint32_t sui;

	mutex_enter(&rp->r_statelock);
	layout = list_head(&rp->r_layout);
	if ((layout == NULL || !(rp->r_flags &
	    (R4LAYOUTUNAVAIL|R4LAYOUTVALID)))) {
		mutex_exit(&rp->r_statelock);
		pnfs_layoutget(vp, cr, LAYOUTIOMODE4_RW);
		mutex_enter(&rp->r_statelock);
		layout = list_head(&rp->r_layout);
	}

	if (layout == NULL || !(rp->r_flags & R4LAYOUTVALID)) {
		mutex_exit(&rp->r_statelock);
		return (EAGAIN);
	}

	pnfs_layout_hold(rp, layout);
	mutex_exit(&rp->r_statelock);

	for (i = 0; i < layout->plo_stripe_count; i++) {
		error = stripe_dev_prepare(mi, layout->plo_stripe_dev[i],
		    layout->plo_first_stripe_index, i, cr);
		if (error) {
			nfs4_set_pageerror(plist);
			mutex_enter(&rp->r_statelock);
			pnfs_layout_rele(rp);
			mutex_exit(&rp->r_statelock);
			return (error);
		}
	}

	/*
	 * Allocate an array of extents (offset, length).
	 * One extent for each stripe device.
	 */
	exts_size = sizeof (commit_extent_t) * layout->plo_stripe_count;
	exts = kmem_zalloc(exts_size, KM_SLEEP);

	/*
	 * Walk the list of pages and update the extents array.
	 * When finished, the extents array will contain the
	 * offset and length that needs to be committed for each device.
	 */
	pp = plist;
	do {
		ps = pp->p_offset;
		pe = ps + PAGESIZE - 1;

		/*
		 * Step through the page by stripe unit width
		 * and update the appropriate extent for the offset.
		 */
		do {
			sui = (ps / layout->plo_stripe_unit) %
			    layout->plo_stripe_count;
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

	if (layout->plo_flags & PLO_COMMIT_MDS) {
		error = pnfs_commit_mds(vp, plist, layout, exts,
		    offset, count, cr);
	} else {
		job = file_io_commit_alloc();
		nfs4_init_stateid_types(&sid_types);
		job->fic_vp = vp;
		job->fic_plist = plist;
		stripewidth = layout->plo_stripe_unit *
		    layout->plo_stripe_count;
		for (i = 0; i < layout->plo_stripe_count; i++) {
			ext = &exts[i];
			/* skip data servers that do not need commit */
			if (ext->ce_length == 0)
				continue;
			task = kmem_cache_alloc(commit_task_cache, KM_SLEEP);
			task->cm_job = job;
			task->cm_cred = cr;
			crhold(task->cm_cred);
			task->cm_layout = layout;
			off = ext->ce_offset;
			if (layout->plo_stripe_type == STRIPE4_DENSE)
				task->cm_offset = (off / stripewidth)
				    * layout->plo_stripe_unit
				    + (off % layout->plo_stripe_unit);
			else
				task->cm_offset = off;
			task->cm_sui = i;
			task->cm_dev = layout->plo_stripe_dev[i];
			stripe_dev_hold(task->cm_dev);
			task->cm_count = ext->ce_length;
			task->cm_call = nfs4_call_init(TAG_PNFS_COMMIT,
			    OP_COMMIT, OH_COMMIT, FALSE, mi, vp, NULL, cr);
			task->cm_call->nc_ds_servinfo = task->cm_dev->std_svp;
			task->cm_recov_state.rs_flags = 0;
			task->cm_recov_state.rs_num_retry_despite_err = 0;
	/*
	 * XXXcommit - Add the task to the job list here.
	 * Convert task dispatching to pnfs_commit_start()
	 * which will coordinate with recovery.
	 */
			++remaining;

			(void) taskq_dispatch(mi->mi_pnfs_io_taskq,
			    pnfs_task_commit, task, 0);
		}

		mutex_enter(&job->fic_lock);
		job->fic_remaining += remaining;
		while (job->fic_remaining > 0) {
			nosig = cv_wait_sig(&job->fic_cv, &job->fic_lock);
			if ((nosig == 0) && (job->fic_error == 0))
				job->fic_error = EINTR;
		}
	/*
	 * XXXcommit - loop through the task list to see if the task
	 * needs to be redispatched or if recovery needs to be initiated.
	 */
		error = job->fic_error;
		mutex_exit(&job->fic_lock);
	}

	mutex_enter(&rp->r_statelock);
	pnfs_layout_rele(rp);
	mutex_exit(&rp->r_statelock);

	kmem_free(exts, exts_size);

	if (job)
		(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
		    pnfs_task_commit_free, job, 0);

	return (error);
}
