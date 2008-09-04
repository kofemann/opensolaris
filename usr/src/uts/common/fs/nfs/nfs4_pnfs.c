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

#include <nfs/nfs4_pnfs.h>
#include <sys/cmn_err.h>

static kmem_cache_t *file_io_read_cache;
static kmem_cache_t *read_task_cache;
static kmem_cache_t *stripe_dev_cache;
static kmem_cache_t *pnfs_read_compound_cache;
static kmem_cache_t *pnfs_layout_cache;
static kmem_cache_t *file_io_write_cache;
static kmem_cache_t *write_task_cache;
static kmem_cache_t *task_get_devicelist_cache;
static kmem_cache_t *task_layoutget_cache;
static kmem_cache_t *task_layoutreturn_cache;

int nfs4_pnfs_io_nthreads = 32;
int nfs4_pnfs_io_maxalloc = 32;
int nfs4_pnfs_other_nthreads = 8;
int nfs4_pnfs_other_maxalloc = 8;

int nfs4_pnfs_stripe_unit = 16384;

#define	stripe_indices_len	nflda_stripe_indices.nflda_stripe_indices_len
#define	stripe_indices		nflda_stripe_indices.nflda_stripe_indices_val
#define	mpl_len		nflda_multipath_ds_list.nflda_multipath_ds_list_len
#define	mpl_val		nflda_multipath_ds_list.nflda_multipath_ds_list_val

#define	gdlr_dll	gdlr_devinfo_list.gdlr_devinfo_list_len
#define	gdlr_dlv	gdlr_devinfo_list.gdlr_devinfo_list_val

#define	dab_len		da_addr_body.da_addr_body_len
#define	dab_val		da_addr_body.da_addr_body_val

#define	DEV_ASSIGN(x, y)	bcopy((y), (x), sizeof (deviceid4))

static int pnfs_getdeviceinfo(mntinfo4_t *, devnode_t *, cred_t *);
static devnode_t *pnfs_create_device(mntinfo4_t *, deviceid4, avl_index_t);

static int
nfs4_devid_compare(const void *va, const void *vb)
{
	const devnode_t *a = va;
	const devnode_t *b = vb;
	int m;

	m = memcmp(a->devid, b->devid, sizeof (deviceid4));
	return (m == 0 ? 0 : m < 0 ? -1 : 1);
}

static stripe_dev_t *
stripe_dev_alloc()
{
	stripe_dev_t *rc;

	rc = kmem_cache_alloc(stripe_dev_cache, KM_SLEEP);
	rc->refcount = 1;
	rc->flags = 0;

	rc->std_n4sp = NULL;
	rc->std_svp = NULL;

	return (rc);
}

static void
stripe_dev_hold(stripe_dev_t *stripe)
{
	mutex_enter(&stripe->lock);
	stripe->refcount++;
	mutex_exit(&stripe->lock);
}

static void
stripe_dev_rele(stripe_dev_t **handle)
{
	stripe_dev_t *stripe = *handle;

	*handle = NULL;

	mutex_enter(&stripe->lock);
	stripe->refcount--;
	if (stripe->refcount > 0) {
		mutex_exit(&stripe->lock);
		return;
	}
	mutex_exit(&stripe->lock);

	if (stripe->std_n4sp) {
		/*
		 * Don't free stripe->std_svp since it's owned by the netaddr4.
		 * We simply need to release our hold on the nfs4_server_t.
		 */
		nfs4_server_rele(stripe->std_n4sp);
	}

	sfh4_rele(&stripe->fh);
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

	mutex_init(&stripe->lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
stripe_dev_destroy(void *vstripe, void *foo)
{
	stripe_dev_t *stripe = vstripe;

	mutex_destroy(&stripe->lock);
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
pnfs_read_compound_construct(void *vc, void *foo, int bar)
{
	pnfs_read_compound_t *r = vc;

	r->args.array = r->argop;
	r->read = &r->argop[2].nfs_argop4_u.opread;
	r->fh = &r->argop[1].nfs_argop4_u.opcputfh.sfh;

	r->args.ctag = TAG_PNFS_READ;
	r->args.array_len = 3;

	r->argop[0].argop = OP_SEQUENCE;
	r->argop[1].argop = OP_CPUTFH;
	r->argop[2].argop = OP_READ;
	return (0);
}

/*ARGSUSED*/
static int
file_io_read_construct(void *vrw, void *b, int c)
{
	file_io_read_t *rw = vrw;

	mutex_init(&rw->fir_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&rw->fir_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
file_io_read_destroy(void *vrw, void *b)
{
	file_io_read_t *rw = vrw;

	mutex_destroy(&rw->fir_lock);
	cv_destroy(&rw->fir_cv);
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
	crfree(iowork->rt_cred);
	stripe_dev_rele(&iowork->rt_dev);
	if (iowork->rt_free_uio)
		kmem_free(iowork->rt_uio.uio_iov, iowork->rt_free_uio);
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

	return (0);
}

/*ARGSUSED*/
static void
file_io_write_destroy(void *vwrite, void *foo)
{
	file_io_write_t *write = vwrite;

	mutex_destroy(&write->fiw_lock);
	cv_destroy(&write->fiw_cv);
}

static void
write_task_free(write_task_t *w)
{
	stripe_dev_rele(&w->wt_dev);
	crfree(w->wt_cred);
	kmem_cache_free(write_task_cache, w);
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
	mutex_init(&mi->mi_pnfs_lock, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&mi->mi_devid_tree, nfs4_devid_compare,
	    sizeof (devnode_t), offsetof(devnode_t, avl));
	mi->mi_pnfs_io_taskq = taskq_create("pnfs_io_taskq",
	    nfs4_pnfs_io_nthreads,
	    minclsyspri, 1, nfs4_pnfs_io_maxalloc, TASKQ_PERZONE);
	mi->mi_pnfs_other_taskq = taskq_create("pnfs_other_taskq",
	    nfs4_pnfs_other_nthreads,
	    minclsyspri, 1, nfs4_pnfs_other_maxalloc,
	    TASKQ_PERZONE);
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
	stripe_dev_cache = kmem_cache_create("stripe_dev_cache",
	    sizeof (stripe_dev_t), 0,
	    stripe_dev_construct, stripe_dev_destroy, NULL,
	    NULL, NULL, 0);
	pnfs_read_compound_cache = kmem_cache_create("pnfs_read_compound_cache",
	    sizeof (pnfs_read_compound_t), 0,
	    pnfs_read_compound_construct, NULL, NULL,
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
pnfs_trash_devtree(mntinfo4_t *mi)
{
	devnode_t *dp;
	void *cookie = NULL;
	int i, ns;

	mutex_enter(&mi->mi_pnfs_lock);
	while ((dp = avl_destroy_nodes(&mi->mi_devid_tree, &cookie)) != NULL) {
		if (dp->count > 0)
			cmn_err(CE_WARN, "devnode count > 0");
		else {
			ns = dp->ds_addrs.mpl_len;
			xdr_free(xdr_nfsv4_1_file_layout_ds_addr4,
			    (char *)&dp->ds_addrs);
			for (i = 0; i < ns; i++)
				if (dp->server_list[i])
					nfs4_server_rele(dp->server_list[i]);
			kmem_free(dp, sizeof (devnode_t));
		}
	}
	avl_destroy(&mi->mi_devid_tree);
	mutex_exit(&mi->mi_pnfs_lock);
}

void
nfs4_pnfs_fini_mi(mntinfo4_t *mi)
{
	pnfs_trash_devtree(mi);
	mutex_destroy(&mi->mi_pnfs_lock);
}

void
nfs4_pnfs_fini()
{
	kmem_cache_destroy(file_io_read_cache);
	kmem_cache_destroy(read_task_cache);
	kmem_cache_destroy(file_io_write_cache);
	kmem_cache_destroy(write_task_cache);
	kmem_cache_destroy(stripe_dev_cache);
	kmem_cache_destroy(pnfs_read_compound_cache);
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

	return (error);
}

/*
 * Find the nfs4_server structure for the server described by IP address
 * in netbuf.  If necessary, make a new nfs4_server_t/servinfo4_t and
 * perform an Exchange ID and Create Session if needed.  On success,
 * return 0 and set *npp to point to the twice-HELD nfs4_server_t that
 * we found/created.  Otherwise, return an error.
 *
 * Users of *npp are responsible for doing the nfs4_server_rele().
 * The two holds are the one from svp->sv_ds_n4sp and the other
 * is done for the benefit of the caller.
 */
static int
find_nfs4_server_by_netaddr4(
	netaddr4 *nap,		/* netaddr4 from the mi_devid_tree */
	mntinfo4_t *mi,		/* mntinfo4 from MDS */
	nfs4_server_t **npp)	/* returned nfs4_server */
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
			return (EIO);
		}

		if (!(np->s_flags & (N4S_CLIENTID_SET|N4S_SESSION_CREATED))) {
			/* Not ready for prime time */
			cv_wait(&np->s_clientid_pend, &np->s_lock);
			mutex_exit(&np->s_lock);
			nfs4_server_rele(np);
			goto retry;
		}

		if (np->s_ds_svp == NULL)
			np->s_ds_svp = mi->mi_curr_serv;
		mutex_exit(&np->s_lock);

		*npp = np;
		return (0);
	}

	svp = new_servinfo4(&knc, &nb, SV4_ISA_DS);
	np = add_new_nfs4_server(svp, kcred);
	np->s_ds_svp = svp;
	svp->sv_ds_n4sp = np;	/* Use the hold from add_new_nfs4_server() */

	mutex_exit(&np->s_lock);
	mutex_exit(&nfs4_server_lst_lock);

	nfs4_server_hold(np);	/* This hold is for the caller's benefit */

	/* XXX - this should probably be nfs4_start_fop */
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);

	/*
	 * XXXrsb - Should the nfs4_start_op()/nfs4_end_op() be
	 * here or should nfs4exchange_id_otw() deal with it as
	 * it calls some form of rfs4call()?
	 */
	nfs4exchange_id_otw(mi, svp, kcred, np, &e, &ri);

	nfs_rw_exit(&mi->mi_recovlock);

	if (e.error || e.stat) {
		mutex_enter(&np->s_lock);
		np->s_flags |= N4S_EXID_FAILED;
		cv_broadcast(&np->s_clientid_pend);
		mutex_exit(&np->s_lock);
		nfs4_server_rele(np);
		cmn_err(CE_WARN,
		    "find_nfs4_server_by_netaddr4: exchange_id failed");
		error = e.error;
	} else {
		/* All good, let's go home */
		*npp = np;
	}

	return (error);
}

static void
pnfs_rele_device(mntinfo4_t *mi, devnode_t *dp)
{
	ASSERT(MUTEX_HELD(&mi->mi_pnfs_lock));
	ASSERT(dp->count > 0);
	dp->count--;
	/*
	 * No point in caching a failed getdeviceinfo.  Throw away
	 * the devnode.  The devnode cannot have a server list or
	 * xdr data since getdeviceinfo failed.
	 */
	if (dp->flags & DN_GDI_FAILED && dp->count == 0) {
		avl_remove(&mi->mi_devid_tree, dp);
		kmem_free(dp, sizeof (*dp));
	}
}

static int
pnfs_get_device(mntinfo4_t *mi, deviceid4 did, cred_t *cr, devnode_t **dpp)
{
	devnode_t *dp = NULL;
	devnode_t key;	/* Dummy, only used as key for avl_find() */
	avl_index_t where;
	int error;

	DEV_ASSIGN(key.devid, did);
	if ((dp = avl_find(&mi->mi_devid_tree, &key, &where)) == NULL) {
		/*
		 * The devid is not in the tree, go get the device info.
		 * Create a placeholder devnode and stick it in the tree.
		 */
		dp = pnfs_create_device(mi, did, where);
		dp->flags |= DN_GDI_INFLIGHT;
		mutex_exit(&mi->mi_pnfs_lock);

		error = pnfs_getdeviceinfo(mi, dp, cr);

		mutex_enter(&mi->mi_pnfs_lock);
		dp->flags &= ~DN_GDI_INFLIGHT;
		if (dp->count > 1)
			cv_broadcast(dp->cv);
		if (error) {
			dp->flags |= DN_GDI_FAILED;
			pnfs_rele_device(mi, dp);
		}
		else
			*dpp = dp;
		return (error);
	}
	dp->count++;

	while (dp->flags & DN_GDI_INFLIGHT)
		cv_wait(dp->cv, &mi->mi_pnfs_lock);

	if (dp->flags & DN_GDI_FAILED) {
		pnfs_rele_device(mi, dp);
		error = EIO;
	} else {
		error = 0;
		*dpp = dp;
	}
	return (error);
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
	nfs4_server_t *np;
	int error = 0;
	deviceid4 did;

	/*
	 * Check to see if the stripe dev is already initialized,
	 * if so, just return
	 */
	mutex_enter(&dev->lock);
	if (dev->std_n4sp != NULL) {
		ASSERT(dev->std_svp != NULL);
		mutex_exit(&dev->lock);
		return (0);
	}

	DEV_ASSIGN(did, dev->sd_devid);
	mutex_exit(&dev->lock);

	mutex_enter(&mi->mi_pnfs_lock);
	if ((error = pnfs_get_device(mi, did, cr, &dip)) != 0) {
		mutex_exit(&mi->mi_pnfs_lock);
		return (error);
	}
	ASSERT(dip != NULL);

	/*
	 * Range check stripe_num and first_stripe_index against
	 * the length of the indices array.
	 */
	if (stripe_num >= dip->ds_addrs.stripe_indices_len ||
	    first_stripe_index >= dip->ds_addrs.stripe_indices_len) {
		pnfs_rele_device(mi, dip);
		mutex_exit(&mi->mi_pnfs_lock);
		cmn_err(CE_WARN, "stripe_dev_prepare: stripe_num or "
		    "first_stripe_index out of range: %d, %d, %d",
		    stripe_num, first_stripe_index,
		    dip->ds_addrs.stripe_indices_len);
		return (EIO);
	}
	ndx = (stripe_num+first_stripe_index) %
	    dip->ds_addrs.stripe_indices_len;
	mpl_index = dip->ds_addrs.stripe_indices[ndx];
	/*
	 * Range check the index from the indices
	 */
	if (mpl_index >= dip->ds_addrs.mpl_len) {
		pnfs_rele_device(mi, dip);
		mutex_exit(&mi->mi_pnfs_lock);
		cmn_err(CE_WARN, "strip_dev_prepare: mpl_index out "
		    "of range: %d, %d", mpl_index, dip->ds_addrs.mpl_len);
		return (EIO);
	}
	mpl_item = &dip->ds_addrs.mpl_val[mpl_index];
	/* XXX - always choose multipath item 0 */
	nap = &mpl_item->multipath_list4_val[0];

	if ((np = dip->server_list[mpl_index]) == NULL) {
		/*
		 * Drop these locks since find_nfs4_server_by_netaddr4()
		 * may go OTW to do EXID/CR_SESS.
		 */
		mutex_exit(&mi->mi_pnfs_lock);
		error = find_nfs4_server_by_netaddr4(nap, mi, &np);
		mutex_enter(&mi->mi_pnfs_lock);

		if (error) {
			pnfs_rele_device(mi, dip);
			mutex_exit(&mi->mi_pnfs_lock);
			return (error);
		}

		ASSERT(np->s_ds_svp != NULL);	/* 1 of 2 */


		/* Initialize the server list, if needed */

		if (dip->server_list[mpl_index] == NULL) {
			dip->server_list[mpl_index] = np;
		} else {
			/*
			 * Someone else got here first.  Drop the hold
			 * and use whatever is in the tree (below)
			 */
			nfs4_server_rele(np);
			np = dip->server_list[mpl_index];
		}
	}
	pnfs_rele_device(mi, dip);
	dip = NULL;
	mutex_exit(&mi->mi_pnfs_lock);

	mutex_enter(&dev->lock);
	/* std_n4sp & std_svp must be done as a set */
	if (dev->std_n4sp == NULL) {
		dev->std_n4sp = np;
		nfs4_server_hold(np);
		dev->std_svp = np->s_ds_svp;
		ASSERT(np->s_ds_svp != NULL);	/* 2 of 2 */
	}

	ASSERT(dev->std_svp != NULL);
	ASSERT(dev->std_n4sp != NULL);
	mutex_exit(&dev->lock);
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
pnfs_call(
	vnode_t			*vp,
	servinfo4_t		*svp,
	nfs_opnum4		op,
	COMPOUND4args_clnt	*argsp,
	COMPOUND4res_clnt	*resp,
	nfs4_error_t		*ep,
	cred_t			*cr)
{
	mntinfo4_t	*mi = VTOMI4(vp);
	nfs4_recov_state_t	recov_state = {NULL, 0, 0};
	int		doqueue = 1;
	int		error;

	ASSERT(vp != NULL);
	ASSERT(svp != NULL);

	/*
	 * XXxrsb - The recovery code below is mostly a placeholder.
	 * This will all change with the new data server recovery design.
	 */
	if ((error = nfs4_start_op(mi, vp, NULL, &recov_state)) != 0) {
		/*
		 * We're in recovery so fail this call and let the
		 * enqueueing thread try again.
		 */
		VN_RELE(vp);
		/*
		 * XXXrsb - This error will be changed to EAGAIN when the
		 * enqueueing learns how to re-enqueue I/O tasks.
		 */
		nfs4_error_init(ep, error);
		return;
	}

	resp->argsp = argsp;
	resp->array = NULL;
	resp->status = 0;
	resp->decode_len = 0;

	rfs4call(mi, svp, argsp, resp, cr, &doqueue, 0, ep);

	/*
	 * Don't call start_recovery, it don't have enough mojo to deal
	 * with DS failures (yet).  Just return the error.
	 */

	nfs4_end_op(mi, vp, NULL, &recov_state, 0);
	VN_RELE(vp);
}

static void
pnfs_task_read(void *v)
{
	read_task_t *task = v;
	file_io_read_t *job = task->rt_job;
	stripe_dev_t *stripe = task->rt_dev;
	pnfs_read_compound_t *readargs;
	COMPOUND4res_clnt res;
	READ4res *rres;
	struct timeval wait;
	int error = 0;
	int eof = 0;
	length4 eof_offset;
	int data_len = 0;

	mutex_enter(&job->fir_lock);
	if ((job->fir_error) ||
	    ((job->fir_eof) &&
	    (task->rt_offset + task->rt_count > job->fir_eof_offset))) {
		job->fir_remaining--;
		if (job->fir_remaining == 0)
			cv_broadcast(&job->fir_cv);
		mutex_exit(&job->fir_lock);
		read_task_free(task);
		return;
	}
	mutex_exit(&job->fir_lock);

	TICK_TO_TIMEVAL(30 * hz / 10, &wait); /* XXX 30?  SHORTWAIT? */
	readargs = kmem_cache_alloc(pnfs_read_compound_cache, KM_SLEEP);
	readargs->args.minor_vers = VTOMI4(task->rt_vp)->mi_minorversion;
	readargs->read->stateid = job->fir_stateid;
	*(readargs->fh) = task->rt_dev->fh;
	readargs->read->offset = task->rt_offset;
	readargs->read->count = task->rt_count;
	readargs->read->res_data_val_alt = NULL;
	readargs->read->res_mblk = NULL;
	readargs->read->res_uiop = NULL;
	readargs->read->res_maxsize = 0;
	if (task->rt_have_uio)
		readargs->read->res_uiop = &task->rt_uio;
	else
		readargs->read->res_data_val_alt = task->rt_base;
	readargs->read->res_maxsize = task->rt_count;

	pnfs_call(task->rt_vp, stripe->std_svp, OP_READ,
	    &readargs->args, &res, &task->rt_err, task->rt_cred);

	/*
	 * XXXrsb - rt_err will be available to the caller once we get
	 * the I/O threads fully synchronized with the enqueuing thread.
	 * For now, our error communication is solely at the "job" level.
	 */

	error = task->rt_err.error;
	if (error == 0) {
		rres = &res.array[2].nfs_resop4_u.opread;
		if ((res.status == NFS4_OK) && (rres->status == NFS4_OK)) {
			data_len = rres->data_len;
			if (rres->eof) {
				eof = 1;
				/*
				 * offset may have been modified if we are
				 * using dense stripes, use the offset in
				 * the uio.
				 */
				eof_offset =
				    task->rt_uio.uio_loffset + data_len;
			}
		} else {
			error = geterrno4(res.status);
		}

		ASSERT(task->rt_err.rpc_status == 0);
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	}

	mutex_enter(&job->fir_lock);
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

	kmem_cache_free(pnfs_read_compound_cache, readargs);
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
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[3];
	int error;
	WRITE4res *wres;
	rnode4_t *rp;

	mutex_enter(&job->fiw_lock);
	if (job->fiw_error) {
		job->fiw_remaining--;
		if (job->fiw_remaining == 0)
			cv_broadcast(&job->fiw_cv);
		mutex_exit(&job->fiw_lock);
		write_task_free(task);
		return;
	}
	mutex_exit(&job->fiw_lock);

	args.ctag = TAG_PNFS_WRITE;
	args.minor_vers = VTOMI4(task->wt_vp)->mi_minorversion;
	args.array_len = 3;
	args.array = argop;

	argop[0].argop = OP_SEQUENCE;
	/* the args for OP_SEQUENCE are filled out later */

	argop[1].argop = OP_CPUTFH;
	argop[1].nfs_argop4_u.opcputfh.sfh = dev->fh;

	argop[2].argop = OP_WRITE;
	argop[2].nfs_argop4_u.opwrite.stable = FILE_SYNC4; /* XXX */
	argop[2].nfs_argop4_u.opwrite.stateid = job->fiw_stateid;
	argop[2].nfs_argop4_u.opwrite.mblk = NULL;

	argop[2].nfs_argop4_u.opwrite.offset = task->wt_offset;
	argop[2].nfs_argop4_u.opwrite.data_len = task->wt_count;
	argop[2].nfs_argop4_u.opwrite.data_val = task->wt_base;

	pnfs_call(task->wt_vp, dev->std_svp, OP_WRITE, &args, &res,
	    &task->wt_err, task->wt_cred);

	/*
	 * XXXrsb - wt_err will be available to the caller once we get
	 * the I/O threads fully synchronized with the enqueuing thread.
	 * For now, our error communication is solely at the "job" level.
	 */

	error = task->wt_err.error;
	if (error == 0) {
		wres = &res.array[2].nfs_resop4_u.opwrite;
		if ((res.status == NFS4_OK) && (wres->status == NFS4_OK)) {
			mutex_enter(&dev->lock);
			if ((dev->flags & STRIPE_DEV_HAVE_VERIFIER) &&
			    (wres->writeverf != dev->writeverf))
				nfs4_set_mod(job->fiw_vp);
			dev->flags |= STRIPE_DEV_HAVE_VERIFIER;
			dev->writeverf = wres->writeverf;
			mutex_exit(&dev->lock);

			rp = VTOR4(job->fiw_vp);
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
			mutex_exit(&rp->r_statelock);
		} else {
			error = geterrno4(res.status);
		}

		ASSERT(task->wt_err.rpc_status == 0);
		xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	}

	mutex_enter(&job->fiw_lock);
	if (error && job->fiw_error == 0)
		job->fiw_error = error;
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

static int
pnfs_populate_device(devnode_t *dp, device_addr4 *da)
{
	XDR xdr;

	/* decode the da_addr_body */

	xdrmem_create(&xdr, da->da_addr_body.da_addr_body_val,
	    da->da_addr_body.da_addr_body_len, XDR_DECODE);

	if (!xdr_nfsv4_1_file_layout_ds_addr4(&xdr, &dp->ds_addrs)) {
		cmn_err(CE_WARN, "pnfs_populate_device: XDR_DECODE failed\n");
		return (EAGAIN);
	}

	/* Allocate the server array, it will be initialized later */
	dp->server_list = kmem_zalloc(dp->ds_addrs.mpl_len *
	    sizeof (nfs4_server_t *), KM_SLEEP);

	return (0);
}

/*ARGSUSED*/
static devnode_t *
pnfs_create_device(mntinfo4_t *mi, deviceid4 devid, avl_index_t where)
{
	devnode_t *new;

	new = kmem_zalloc(sizeof (devnode_t), KM_SLEEP);
	DEV_ASSIGN(new->devid, devid);
	new->count = 1;
	cv_init(new->cv, NULL, CV_DEFAULT, NULL);

	/* insert the new devid into the tree */
	avl_insert(&mi->mi_devid_tree, new, where);
	return (new);
}

#define	GDIres		nfs_resop4_u.opgetdeviceinfo
#define	GDIresok	GETDEVICEINFO4res_u.gdir_resok4

/* set this to 1 to preface GETDEVICEINFO with PUTFH */
int pnfs_gdi_hack = 0;

static int
pnfs_getdeviceinfo(mntinfo4_t *mi, devnode_t *dip, cred_t *cr)
{
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	GETDEVICEINFO4args *gdi_args;
	GETDEVICEINFO4res *gdi_res;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int doqueue = 1;
	int nr, abort;
	nfs4_recov_state_t recov_state;
	int gdi_ndx;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

retry:
	if (nfs4_start_op(mi, NULL, NULL, &recov_state))
		goto out;

	args.ctag = TAG_PNFS_GETDEVINFO;
	args.array = argop;
	args.array_len = 1;
	gdi_ndx = 0;

	if (pnfs_gdi_hack) {
		argop[0].argop = OP_CPUTFH;
		argop[0].nfs_argop4_u.opcputfh.sfh = mi->mi_rootfh;
		args.array_len = 2;
		gdi_ndx++;
	}
	argop[gdi_ndx].argop = OP_GETDEVICEINFO;
	gdi_args = &argop[gdi_ndx].nfs_argop4_u.opgetdeviceinfo;
	DEV_ASSIGN(gdi_args->gdia_device_id, dip->devid);
	gdi_args->gdia_layout_type = LAYOUT4_NFSV4_1_FILES;
	gdi_args->gdia_maxcount = 16384; /* XXX make abstraction */
	gdi_args->gdia_notify_types = 0;

	rfs4call(mi, NULL, &args, &res, cr, &doqueue, 0, &e);

	if ((nr = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp))) {

		abort = nfs4_start_recovery(&e, mi, NULL, NULL,
		    NULL, NULL, 0, NULL);

		nfs4_end_fop(mi, NULL, NULL, 0, &recov_state, nr);
		if (e.error == 0 && e.rpc_status == 0)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

		if (abort) {
			if (e.error)
				return (e.error);
			else
				return (geterrno4(e.stat));
		}
		goto  retry;
	}

	if ((e.error == 0) && (e.stat == NFS4_OK)) {

		gdi_res = &res.array[gdi_ndx].GDIres;
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

		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	} else if (e.error == 0 && e.stat != NFS4_OK)
		e.error = geterrno4(e.stat);

	nfs4_end_op(mi, NULL, NULL, &recov_state, 0);
out:
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
	bzero(&layout->plo_stateid, sizeof (layout->plo_stateid));
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
		sd->fh = sfh4_get(
		    &file_layout4->nfl_fh_list.nfl_fh_list_val[i], mi);
		DEV_ASSIGN(sd->sd_devid, file_layout4->nfl_deviceid);
	}
	/* XXX free memory and stuff */
	layout->plo_refcount = 1;

	rp->r_lostateid = res->LAYOUTGET4res_u.logr_resok4.logr_stateid;
	rp->r_flags |= R4LAYOUTVALID;
	/*
	 * Insert pnfs_layout_t into list, just add at head for now since we
	 * are only dealing with single layouts.
	 */
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
	nfs4_server_t	*np;
	nfs4_fsidlt_t *ltp, lt;
	rnode4_t *found, *rp;
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	LAYOUTRETURN4args *arg;
	layoutreturn_file4 *lrf;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int doqueue = 1, opx;
	nfs4_recov_state_t recov_state;
	avl_index_t	where;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	/*
	 * XXX - todo need to pass vp for LAYOUTRETURN4_FILE
	 * XXX - if start_op fails, should we remove the layout from the tree?
	 */
	if (nfs4_start_op(mi, NULL, NULL, &recov_state))
		goto out;

	args.ctag = TAG_PNFS_LAYOUTRETURN;
	args.array = argop;

	if (task->tlr_return_type == LAYOUTRETURN4_FILE) {
		rp = VTOR4(task->tlr_vp);
		argop[0].argop = OP_CPUTFH;
		argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;
		args.array_len = 2;
		opx = 1;
	} else if (task->tlr_return_type == LAYOUTRETURN4_FSID) {
		argop[0].argop = OP_CPUTFH;
		argop[0].nfs_argop4_u.opcputfh.sfh = mi->mi_rootfh;
		args.array_len = 2;
		opx = 1;
	} else {
		ASSERT(task->tlr_return_type == LAYOUTRETURN4_ALL);
		opx = 0;
		args.array_len = 1;
	}

	argop[opx].argop = OP_LAYOUTRETURN;
	arg = &argop[opx].nfs_argop4_u.oplayoutreturn;
	arg->lora_layoutreturn.lr_returntype = task->tlr_return_type;
	lrf = &arg->lora_layoutreturn.layoutreturn4_u.lr_layout;
	lrf->lrf_offset = task->tlr_offset;
	lrf->lrf_length = task->tlr_length;
	lrf->lrf_stateid = task->tlr_stateid;
	lrf->lrf_body.lrf_body_len = 0;
	arg->lora_reclaim = task->tlr_reclaim;
	arg->lora_iomode = task->tlr_iomode;
	arg->lora_layout_type = task->tlr_layout_type;

	rfs4call(mi, NULL, &args, &res, task->tlr_cr, &doqueue, 0, &e);

	/* XXX need needs_recovery/start_recovery logic here */

	if (task->tlr_return_type == LAYOUTRETURN4_FSID ||
	    task->tlr_return_type == LAYOUTRETURN4_ALL)
		goto done;

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
	if (e.error == 0 && e.rpc_status == RPC_SUCCESS)
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	nfs4_end_op(mi, NULL, NULL, &recov_state, 0);
	/*
	 * At this point, we don't worry about failure.  We will either
	 * be asked to return the layout again, or the servers will stop
	 * honoring the layout.  Either way, we (the client) are through
	 * with the layout, and have tried to return it.
	 */

out:
	task_layoutreturn_free(task);
}

static void
pnfs_task_layoutget(void *v)
{
	task_layoutget_t *task = v;
	mntinfo4_t *mi = task->tlg_mi;
	nfs4_server_t *np;
	rnode4_t *rp = VTOR4(task->tlg_vp);
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	LAYOUTGET4args *arg;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int doqueue = 1, trynext_sid = 0;
	rnode4_t	*found;
	avl_index_t	where;
	nfs4_fsidlt_t lt, *ltp;

	cred_t *cr = task->tlg_cred;
	nfs4_recov_state_t recov_state;
	nfs4_stateid_types_t sid_types;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	args.ctag = TAG_PNFS_LAYOUTGET;
	args.array_len = 2;
	args.array = argop;

	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = rp->r_fh;

	argop[1].argop = OP_LAYOUTGET;
	arg = &argop[1].nfs_argop4_u.oplayoutget;
	arg->loga_layout_type = LAYOUT4_NFSV4_1_FILES;
	arg->loga_iomode = task->tlg_iomode;
	arg->loga_offset = 0;
	arg->loga_length = ~0;
	arg->loga_minlength = 8192; /* XXX */
	arg->loga_maxcount = mi->mi_tsize;

	/*
	 * This code assumes we don't already have a layout and
	 * therefore, just use the delegation, lock or open stateID.
	 * If this function is used to get more layouts when we already
	 * have one, then it will need to be changed to grab the current
	 * layout stateid.
	 */
	nfs4_init_stateid_types(&sid_types);

recov_retry:

	arg->loga_stateid = nfs4_get_stateid(cr, rp, -1, mi, OP_READ,
	    &sid_types, (GETSID_LAYOUT | trynext_sid));

	/*
	 * If we ended up with the special stateid, this means the
	 * file isn't opened and does not have a delegation stateid to use
	 * either.  At this point we can not get a layout.
	 */
	if (sid_types.cur_sid_type == SPEC_SID)
		goto out;

	if (nfs4_start_op(mi, NULL, NULL, &recov_state))
		goto out;

	rfs4call(mi, NULL, &args, &res, cr, &doqueue, 0, &e);

	if ((e.error == 0) && (e.stat == NFS4_OK)) {
		LAYOUTGET4res *resp = &res.array[1].nfs_resop4_u.oplayoutget;
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4LAYOUTVALID) {
			pnfs_layout_return(task->tlg_vp, cr, LR_ASYNC);
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
	} else if (e.error == 0 && res.status == NFS4ERR_BAD_STATEID &&
	    sid_types.cur_sid_type != OPEN_SID) {
		nfs4_save_stateid(&arg->loga_stateid, &sid_types);
		trynext_sid = GETSID_TRYNEXT;
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
		nfs4_end_op(mi, NULL, NULL, &recov_state, 0);
		goto recov_retry;
	} else if (e.error == 0 && res.status == NFS4ERR_LAYOUTUNAVAILABLE) {
		mutex_enter(&rp->r_statelock);
		rp->r_flags |= R4LAYOUTUNAVAIL;
		mutex_exit(&rp->r_statelock);
	}

	if (e.error == 0 && e.rpc_status == RPC_SUCCESS) {
		(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);
	}

	nfs4_end_op(mi, NULL, NULL, &recov_state, 0);

out:
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
pnfs_layout_return(vnode_t *vp, cred_t *cr, int aflag)
{
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);
	task_layoutreturn_t *task;
	pnfs_layout_t *layout;
	layoutiomode4 iomode;
	stateid4 losid;

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
	losid = layout->plo_stateid;
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

int
pnfs_read(vnode_t *vp, caddr_t base, offset_t off, int count, size_t *residp,
    cred_t *cr, bool_t async, struct uio *uiop)
{
	rnode4_t *rp = VTOR4(vp);
	mntinfo4_t *mi = VTOMI4(vp);
	int i, error = 0;
	int remaining = 0;
	file_io_read_t *job;
	read_task_t *task;
	pnfs_layout_t *layout = NULL;
	uint32_t stripenum, stripeoff;
	length4 stripewidth;
	nfs4_stateid_types_t sid_types;
	offset_t orig_off = off;
	int orig_count = count;
	uio_t *uio_sav = NULL;
	caddr_t xbase;

	mutex_enter(&rp->r_statelock);
	layout = list_head(&rp->r_layout);
	if ((mi->mi_flags & MI4_PNFS) &&
	    (!(rp->r_flags & (R4LAYOUTVALID|R4LAYOUTUNAVAIL)) ||
	    layout == NULL)) {
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
		VN_HOLD(vp);	/* VN_RELE() in pnfs_call() */
		task->rt_vp = vp;
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
		nfs4_error_zinit(&task->rt_err);
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

		off += task->rt_count;
		if (base)
			base += task->rt_count;
		count -= task->rt_count;

		(void) taskq_dispatch(mi->mi_pnfs_io_taskq,
		    pnfs_task_read, task, 0);
		++remaining;
	}

	mutex_enter(&job->fir_lock);
	job->fir_remaining += remaining;
	while (job->fir_remaining > 0)
		if ((! cv_wait_sig(&job->fir_cv, &job->fir_lock)) &&
		    (job->fir_error == 0))
			job->fir_error = EINTR;
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

#if 1
	return (error);
#else
	return (0);
#endif
}

int
pnfs_write(vnode_t *vp, caddr_t base, u_offset_t off, int count,
    cred_t *cr, stable_how4 *stab)
{
	int i, error = 0;
	file_io_write_t *job;
	write_task_t *task;
	rnode4_t *rp = VTOR4(vp);
	pnfs_layout_t *layout;
	uint32_t stripenum, stripeoff;
	length4 stripewidth;
	mntinfo4_t *mi = VTOMI4(vp);
	int remaining = 0;
	nfs4_stateid_types_t sid_types;
	int nosig;

	mutex_enter(&rp->r_statelock);
	layout = list_head(&rp->r_layout);
	if ((mi->mi_flags & MI4_PNFS) &&
	    (layout == NULL || !(rp->r_flags &
	    (R4LAYOUTUNAVAIL|R4LAYOUTVALID)))) {
		mutex_exit(&rp->r_statelock);
		pnfs_layoutget(vp, cr, LAYOUTIOMODE4_RW);
		mutex_enter(&rp->r_statelock);
		layout = list_head(&rp->r_layout);
	}

	/* iXX refactor needed with pnfs_read() above */
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
	while (count > 0) {
		stripenum = off / layout->plo_stripe_unit;
		stripeoff = off % layout->plo_stripe_unit;
		stripewidth = layout->plo_stripe_unit *
		    layout->plo_stripe_count;

		task = kmem_cache_alloc(write_task_cache, KM_SLEEP);
		task->wt_job = job;
		VN_HOLD(vp);	/* VN_RELE() in pnfs_call() */
		task->wt_vp = vp;
		task->wt_cred = cr;
		crhold(task->wt_cred);
		nfs4_error_zinit(&task->wt_err);
		task->wt_offset = off;
		task->wt_voff = off;
		if (layout->plo_stripe_type == STRIPE4_DENSE)
			task->wt_offset = (off / stripewidth)
			    * layout->plo_stripe_unit
			    + stripeoff;
		task->wt_dev =
		    layout->plo_stripe_dev[stripenum %
		    layout->plo_stripe_count];
		stripe_dev_hold(task->wt_dev);

		task->wt_base = base;
		/* XXX do we need a more conservative calculation? */
		task->wt_count = MIN(layout->plo_stripe_unit - stripeoff,
		    count);

		off += task->wt_count;
		base += task->wt_count;
		count -= task->wt_count;
		++remaining;

		(void) taskq_dispatch(mi->mi_pnfs_io_taskq,
		    pnfs_task_write, task, 0);
	}

	mutex_enter(&job->fiw_lock);
	job->fiw_remaining += remaining;
	while (job->fiw_remaining > 0) {
		nosig = cv_wait_sig(&job->fiw_cv, &job->fiw_lock);
		if ((nosig == 0) && (job->fiw_error == 0))
			job->fiw_error = EINTR;
	}

	error = job->fiw_error;
	mutex_exit(&job->fiw_lock);

	mutex_enter(&rp->r_statelock);
	pnfs_layout_rele(rp);
	mutex_exit(&rp->r_statelock);

	*stab = FILE_SYNC4; /* XXX */

	(void) taskq_dispatch(mi->mi_pnfs_other_taskq,
	    pnfs_task_write_free, job, 0);

	return (error);
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
	COMPOUND4args_clnt args;
	COMPOUND4res_clnt res;
	nfs_argop4 argop[2];
	GETDEVICELIST4args *gdargs;
	nfs4_error_t e = {0, NFS4_OK, RPC_SUCCESS};
	int doqueue = 1;
	GETDEVICELIST4resok *gdres;
	int i, eof;
	nfs4_recov_state_t recov_state;

	recov_state.rs_flags = 0;
	recov_state.rs_num_retry_despite_err = 0;

	if (nfs4_start_op(mi, NULL, NULL, &recov_state))
		goto out;

	args.ctag = TAG_PNFS_GETDEVLIST;
	args.array_len = 2;
	args.array = argop;

	argop[0].argop = OP_CPUTFH;
	argop[0].nfs_argop4_u.opcputfh.sfh = mi->mi_rootfh;

	argop[1].argop = OP_GETDEVICELIST;
	gdargs = &argop[1].nfs_argop4_u.opgetdevicelist;
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

		rfs4call(mi, NULL, &args, &res, task->tgd_cred,
		    &doqueue, 0, &e);
		if ((e.error == 0) && (e.stat == NFS4_OK)) {
			gdres =
			    &res.array[1].nfs_resop4_u.opgetdevicelist.\
			    GETDEVICELIST4res_u.gdlr_resok4;
			for (i = 0; i < gdres->GDL_ADDRL; i++)
				pnfs_intern_devlist_item(mi,
				    gdres->GDL_ADDRV + i,
				    LAYOUT4_NFSV4_1_FILES);
			gdargs->gdla_cookie = gdres->gdlr_cookie;
			gdargs->gdla_cookieverf = gdres->gdlr_cookieverf;
			eof = gdres->gdlr_eof;

			/* XXX */
			if (eof == 0) {
				printf("missing eof = %d", eof);
				eof = 1; /* XXX */
			}
		}
		else
			/* exit loop gracefully on error */
			eof = 1;

		if (e.error == 0 && e.rpc_status == RPC_SUCCESS)
			(void) xdr_free(xdr_COMPOUND4res_clnt, (caddr_t)&res);

	} while (! eof);

	nfs4_end_op(mi, NULL, NULL, &recov_state, 0);
out:
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
