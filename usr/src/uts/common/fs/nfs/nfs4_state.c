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
#include <sys/systeminfo.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/atomic.h>
#include <sys/clconf.h>
#include <sys/cladm.h>
#include <sys/flock.h>
#include <nfs/export.h>
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

#include <nfs/nfs_sstor_impl.h>
#include <nfs/mds_state.h>

#include <nfs/spe_impl.h>

extern int nfs_doorfd;


stateid4 special0 = {
	0,
	{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};

stateid4 special1 = {
	0xffffffff,
	{
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff,
		(char)0xff, (char)0xff, (char)0xff, (char)0xff
	}
};


#define	ISSPECIAL(id)  (stateid4_cmp(id, &special0) || \
			stateid4_cmp(id, &special1))

/* For embedding the cluster nodeid into our clientid */
#define	CLUSTER_NODEID_SHIFT	24
#define	CLUSTER_MAX_NODEID	255

#ifdef DEBUG
int rfs4_debug;
#endif

static const fs_operation_def_t nfs4_rd_deleg_tmpl[] = {
	VOPNAME_OPEN,		{ .femop_open = deleg_rd_open },
	VOPNAME_WRITE,		{ .femop_write = deleg_rd_write },
	VOPNAME_SETATTR,	{ .femop_setattr = deleg_rd_setattr },
	VOPNAME_RWLOCK,		{ .femop_rwlock = deleg_rd_rwlock },
	VOPNAME_SPACE,		{ .femop_space = deleg_rd_space },
	VOPNAME_SETSECATTR,	{ .femop_setsecattr = deleg_rd_setsecattr },
	VOPNAME_VNEVENT,	{ .femop_vnevent = deleg_rd_vnevent },
	NULL,			NULL
};
static const fs_operation_def_t nfs4_wr_deleg_tmpl[] = {
	VOPNAME_OPEN,		{ .femop_open = deleg_wr_open },
	VOPNAME_READ,		{ .femop_read = deleg_wr_read },
	VOPNAME_WRITE,		{ .femop_write = deleg_wr_write },
	VOPNAME_SETATTR,	{ .femop_setattr = deleg_wr_setattr },
	VOPNAME_RWLOCK,		{ .femop_rwlock = deleg_wr_rwlock },
	VOPNAME_SPACE,		{ .femop_space = deleg_wr_space },
	VOPNAME_SETSECATTR,	{ .femop_setsecattr = deleg_wr_setsecattr },
	VOPNAME_VNEVENT,	{ .femop_vnevent = deleg_wr_vnevent },
	NULL,			NULL
};

static void rfs4_ss_chkclid_sip(rfs4_client_t *cp, nfs_server_instance_t *sip);
static void rfs4_ss_write(nfs_server_instance_t *, rfs4_client_t *, char *);
static void rfs4_ss_delete_client(nfs_server_instance_t *, char *);
static void rfs4_ss_delete_oldstate(nfs_server_instance_t *);
static void rfs4_clean_reclaim_list(nfs_server_instance_t *);
void rfs4_ss_retrieve_state(nfs_server_instance_t *);

/*
 * Module load initialization
 */
int
rfs4_srvrinit(void)
{
	extern void nsi_cache_init();
	extern void mds_srvrinit();
	extern void (*rfs4_client_clrst)(struct nfs4clrst_args *);
	extern void rfs4_ntov_init(void);

	rw_init(&nsi_lock, NULL, RW_DEFAULT, NULL);

	list_create(&nsi_head, sizeof (nfs_server_instance_t),
	    offsetof(nfs_server_instance_t, nsi_list));

	/* create the nfs_server_instance keme cache */
	nsi_cache_init();

	rfs4_client_clrst = rfs4_clear_client_state;

	rfs4_ntov_init();

	mds_srvrinit();

	return (0);
}

/*
 * Couple of simple init/destroy functions for a general waiter
 */
void
rfs4_sw_init(rfs4_state_wait_t *swp)
{
	mutex_init(swp->sw_cv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(swp->sw_cv, NULL, CV_DEFAULT, NULL);
	swp->sw_active = FALSE;
	swp->sw_wait_count = 0;
}

void
rfs4_sw_destroy(rfs4_state_wait_t *swp)
{
	mutex_destroy(swp->sw_cv_lock);
	cv_destroy(swp->sw_cv);
}

void
rfs4_sw_enter(rfs4_state_wait_t *swp)
{
	mutex_enter(swp->sw_cv_lock);
	while (swp->sw_active) {
		swp->sw_wait_count++;
		cv_wait(swp->sw_cv, swp->sw_cv_lock);
		swp->sw_wait_count--;
	}
	ASSERT(swp->sw_active == FALSE);
	swp->sw_active = TRUE;
	mutex_exit(swp->sw_cv_lock);
}

void
rfs4_sw_exit(rfs4_state_wait_t *swp)
{
	mutex_enter(swp->sw_cv_lock);
	ASSERT(swp->sw_active == TRUE);
	swp->sw_active = FALSE;
	if (swp->sw_wait_count != 0)
		cv_broadcast(swp->sw_cv);
	mutex_exit(swp->sw_cv_lock);
}

static void
deep_lock_copy(LOCK4res *dres, LOCK4res *sres)
{
	lock_owner4 *slo = &sres->LOCK4res_u.denied.owner;
	lock_owner4 *dlo = &dres->LOCK4res_u.denied.owner;

	if (sres->status == NFS4ERR_DENIED) {
		dlo->owner_val = kmem_alloc(slo->owner_len, KM_SLEEP);
		bcopy(slo->owner_val, dlo->owner_val, slo->owner_len);
	}
}

static void
deep_lock_free(LOCK4res *res)
{
	lock_owner4 *lo = &res->LOCK4res_u.denied.owner;

	if (res->status == NFS4ERR_DENIED)
		kmem_free(lo->owner_val, lo->owner_len);
}

static void
deep_open_copy(OPEN4res *dres, OPEN4res *sres)
{
	nfsace4 *sacep, *dacep;

	if (sres->status != NFS4_OK) {
		return;
	}

	dres->attrset = sres->attrset;

	switch (sres->delegation.delegation_type) {
	case OPEN_DELEGATE_NONE:
		return;
	case OPEN_DELEGATE_READ:
		sacep = &sres->delegation.open_delegation4_u.read.permissions;
		dacep = &dres->delegation.open_delegation4_u.read.permissions;
		break;
	case OPEN_DELEGATE_WRITE:
		sacep = &sres->delegation.open_delegation4_u.write.permissions;
		dacep = &dres->delegation.open_delegation4_u.write.permissions;
		break;
	}
	dacep->who.utf8string_val =
	    kmem_alloc(sacep->who.utf8string_len, KM_SLEEP);
	bcopy(sacep->who.utf8string_val, dacep->who.utf8string_val,
	    sacep->who.utf8string_len);
}

static void
deep_open_free(OPEN4res *res)
{
	nfsace4 *acep;
	if (res->status != NFS4_OK)
		return;

	switch (res->delegation.delegation_type) {
	case OPEN_DELEGATE_NONE:
		return;
	case OPEN_DELEGATE_READ:
		acep = &res->delegation.open_delegation4_u.read.permissions;
		break;
	case OPEN_DELEGATE_WRITE:
		acep = &res->delegation.open_delegation4_u.write.permissions;
		break;
	}

	if (acep->who.utf8string_val) {
		kmem_free(acep->who.utf8string_val, acep->who.utf8string_len);
		acep->who.utf8string_val = NULL;
	}
}

void
rfs4_free_reply(nfs_resop4 *rp)
{
	switch (rp->resop) {
	case OP_LOCK:
		deep_lock_free(&rp->nfs_resop4_u.oplock);
		break;
	case OP_OPEN:
		deep_open_free(&rp->nfs_resop4_u.opopen);
	default:
		break;
	}
}

void
rfs4_copy_reply(nfs_resop4 *dst, nfs_resop4 *src)
{
	*dst = *src;

	/* Handle responses that need deep copy */
	switch (src->resop) {
	case OP_LOCK:
		deep_lock_copy(&dst->nfs_resop4_u.oplock,
		    &src->nfs_resop4_u.oplock);
		break;
	case OP_OPEN:
		deep_open_copy(&dst->nfs_resop4_u.opopen,
		    &src->nfs_resop4_u.opopen);
		break;
	default:
		break;
	};
}

/*
 * This is the implementation of the underlying state engine. The
 * public interface to this engine is described by
 * nfs4_state.h. Callers to the engine should hold no state engine
 * locks when they call in to it. If the protocol needs to lock data
 * structures it should do so after acquiring all references to them
 * first and then follow the following lock order:
 *
 *	client > openowner > state > lo_state > lockowner > file.
 *
 * Internally we only allow a thread to hold one hash bucket lock at a
 * time and the lock is higher in the lock order (must be acquired
 * first) than the data structure that is on that hash list.
 *
 * If a new reference was acquired by the caller, that reference needs
 * to be released after releasing all acquired locks with the
 * corresponding rfs4_*_rele routine.
 */

/*
 * This code is some what prototypical for now. Its purpose currently is to
 * implement the interfaces sufficiently to finish the higher protocol
 * elements. This will be replaced by a dynamically resizeable tables
 * backed by kmem_cache allocator. However synchronization is handled
 * correctly (I hope) and will not change by much.  The mutexes for
 * the hash buckets that can be used to create new instances of data
 * structures  might be good candidates to evolve into reader writer
 * locks. If it has to do a creation, it would be holding the
 * mutex across a kmem_alloc with KM_SLEEP specified.
 */



void
rfs4_ss_pnfree(rfs4_ss_pn_t *ss_pn)
{
	kmem_free(ss_pn, sizeof (rfs4_ss_pn_t));
}

static rfs4_ss_pn_t *
rfs4_ss_pnalloc(char *dir, char *leaf)
{
	rfs4_ss_pn_t *ss_pn;
	int 	dir_len, leaf_len;

	/*
	 * validate we have a resonable path
	 * (account for the '/' and trailing null)
	 */
	if ((dir_len = strlen(dir)) > MAXPATHLEN ||
	    (leaf_len = strlen(leaf)) > MAXNAMELEN ||
	    (dir_len + leaf_len + 2) > MAXPATHLEN) {
		return (NULL);
	}

	ss_pn = kmem_alloc(sizeof (rfs4_ss_pn_t), KM_SLEEP);

	(void) snprintf(ss_pn->pn, MAXPATHLEN, "%s/%s", dir, leaf);
	/* Handy pointer to just the leaf name */
	ss_pn->leaf = ss_pn->pn + dir_len + 1;
	return (ss_pn);
}


static void
rfs4_ss_fini(nfs_server_instance_t *instp)
{
	rfs4_clean_reclaim_list(instp);
}

void
rfs4_ss_build_reclaim_list(nfs_server_instance_t *instp, char *resbuf)
{
	rfs4_reclaim_t *oldp;
	struct ss_res *resp = (struct ss_res *)resbuf;
	struct ss_rd_state *clp;
	int c, len;

	clp = resp->rec;
	for (c = resp->nsize; c > 0; c--) {
		oldp = kmem_alloc(sizeof (rfs4_reclaim_t), KM_SLEEP);
		oldp->ss_pn = NULL;
		len = (int)clp->ssr_len;
		oldp->cl_id4.id_val = kmem_alloc(len, KM_SLEEP);
		oldp->cl_id4.verifier = clp->ssr_veri;
		oldp->cl_id4.id_len = len;
		bcopy(clp->ssr_val, oldp->cl_id4.id_val, len);
		list_insert_head(&instp->reclaim_head, oldp);
		len += (sizeof (uint64_t) + sizeof (uint64_t));
		len = P2ROUNDUP(len, 8);
		clp = (struct ss_rd_state *)((char *)clp + len);
	}
	instp->reclaim_cnt = resp->nsize;
}

int
rfs4_ss_read_state(nfs_server_instance_t *instp, char **buf, int *sz)
{
	struct ss_arg ss_data;
	struct ss_res *ss_res;
	door_arg_t dargs;
	int err;

	ss_data.cmd = NFS4_SS_READ;
	ss_data.rsz = *sz;	/* size of return buffer */
	(void) snprintf(ss_data.path, MAXPATHLEN, "%s", instp->inst_name);

	dargs.data_ptr = (char *)&ss_data;
	dargs.data_size = sizeof (struct ss_arg);
	dargs.desc_ptr = NULL;
	dargs.desc_num = 0;
	dargs.rbuf = *buf;
	dargs.rsize = *sz;

	err = door_ki_upcall(instp->dh, &dargs);
	if (err) {
/*
 * XXX - When this happens, we are screwed.  nfsd has gone away and there
 * is nothing we can do about it here.  We probably need to just shutdown
 * the NFS server until nfsd is fixed.
 */
		printf("CRAP!  The door upcall failed\n");
		return (err);
	}

	ss_res = (struct ss_res *)dargs.rbuf;

	if (ss_res->status != NFS_DR_SUCCESS) {
		/* special handling for buffer too small */
		if (ss_res->status == NFS_DR_OVERFLOW) {
			*sz = ss_res->nsize;
			return (-1);
		}
		return (ss_res->status);
	}

	/* if buf too small, but door provided buf */
	if (dargs.rbuf != *buf) {
		kmem_free(*buf, *sz);
		*sz = dargs.rsize;
		*buf = dargs.rbuf;
	}
	return (0);
}

/*
 * retrieve the oldstate from stable storage.
 */
void
rfs4_ss_retrieve_state(nfs_server_instance_t *instp)
{
	int ret, notdone;
	int sz, osz;
	char *resbuf;

	osz = sz = 512 * 1024;
	do {
		notdone = 0;
		resbuf = kmem_alloc(sz, KM_SLEEP);

		ret = rfs4_ss_read_state(instp, &resbuf, &sz);
		if (ret == -1) {
			kmem_free(resbuf, osz);
			osz = sz;
			notdone = 1;
		}
	} while (notdone);

	if (ret == 0)
		rfs4_ss_build_reclaim_list(instp, resbuf);

	kmem_free(resbuf, sz);

	/* for now assume it's all good!  */
	instp->inst_flags |= NFS_INST_SS_ENABLED;
}

/*
 * Check if we are still in grace and if the client can be
 * granted permission to perform reclaims.
 *
 * XXX Only called from  setclientid_confirm, if MDS need
 * XXX this then we need alterations!
 */
void
rfs4_ss_chkclid(struct compound_state *cs, rfs4_client_t *cp)
{
	/*
	 * It should be sufficient to check the oldstate data for just
	 * this client's instance. However, since our per-instance
	 * client grouping is solely temporal, HA-NFSv4 RG failover
	 * might result in clients of the same RG being partitioned into
	 * separate instances.
	 *
	 * Until the client grouping is improved, we must check the
	 * oldstate data for all instances with an active grace period.
	 *
	 * This also serves as the mechanism to remove stale oldstate data.
	 * The first time we check an instance after its grace period has
	 * expired, the oldstate data should be cleared.
	 *
	 * Start at the current instance, and walk the list backwards
	 * to the first.
	 */
	rfs4_ss_chkclid_sip(cp, cs->instp);
}

static void
rfs4_ss_chkclid_sip(rfs4_client_t *cp, nfs_server_instance_t *sip)
{
	rfs4_reclaim_t *osp, *os_head;

	/* short circuit everything if this server instance has no oldstate */
	rw_enter(&sip->reclaimlst_lock, RW_READER);
	os_head = list_head(&sip->reclaim_head);
	rw_exit(&sip->reclaimlst_lock);
	if (os_head == NULL)
		return;

	/*
	 * If this server instance is no longer in a grace period then
	 * the client won't be able to reclaim. No further need for this
	 * instance's oldstate data, so it can be cleared.
	 */
	if (!rfs4_in_grace(sip)) {
		rfs4_ss_delete_oldstate(sip);
		return;
	}

	/* this instance is still in grace; search for the clientid */

	rw_enter(&sip->reclaimlst_lock, RW_READER);

	osp = list_head(&sip->reclaim_head);
	while (osp) {
		if (osp->cl_id4.id_len == cp->rc_nfs_client.id_len) {
			if (bcmp(osp->cl_id4.id_val, cp->rc_nfs_client.id_val,
			    osp->cl_id4.id_len) == 0) {
				cp->rc_can_reclaim = 1;
				break;
			}
		}
		osp = list_next(&sip->reclaim_head, osp);
	}

	rw_exit(&sip->reclaimlst_lock);
}

static void
rfs4_ss_write(nfs_server_instance_t *instp, rfs4_client_t *cp, char *leaf)
{
	struct ss_arg *ss_datap;
	struct ss_res res_buf;
	struct ss_res *resp;
	nfs_client_id4 *clp = &(cp->rc_nfs_client);
	door_arg_t dargs;
	rfs4_ss_pn_t *ss_pn;
	int size, error;

	size = sizeof (struct ss_arg) + clp->id_len;
	ss_datap = kmem_alloc(size, KM_SLEEP);

	ss_pn = rfs4_ss_pnalloc(instp->inst_name, leaf);
	if (ss_pn == NULL) {
		kmem_free(ss_datap, size);
		return;
	}
	(void) snprintf(ss_datap->path, MAXPATHLEN, "%s/%s",
	    instp->inst_name, leaf);

	ss_datap->cmd = NFS4_SS_WRITE;
	ss_datap->rec.ss_fvers = NFS4_SS_VERSION;
	ss_datap->rec.ss_veri = clp->verifier;
	ss_datap->rec.ss_len = clp->id_len;
	bcopy(clp->id_val, ss_datap->rec.ss_val, clp->id_len);

	dargs.data_ptr = (char *)ss_datap;
	dargs.data_size = size;
	dargs.desc_ptr = NULL;
	dargs.desc_num = 0;
	dargs.rbuf = (char *)&res_buf;
	dargs.rsize = sizeof (struct ss_res);

	error = door_ki_upcall(instp->dh, &dargs);

	kmem_free(ss_datap, size);

	if (error) {
		rfs4_ss_pnfree(ss_pn);
		return;
	}
	resp = (struct ss_res *)dargs.rbuf;
	if (resp->status != 0) {
		rfs4_ss_pnfree(ss_pn);
		goto out;
	}

	if (cp->rc_ss_pn == NULL) {
		cp->rc_ss_pn = ss_pn;
	} else {
		if (strcmp(cp->rc_ss_pn->leaf, leaf) == 0) {
			/* we've already recorded *this* leaf */
			rfs4_ss_pnfree(ss_pn);
		} else {
			/* replace with this leaf */
			rfs4_ss_pnfree(cp->rc_ss_pn);
			cp->rc_ss_pn = ss_pn;
		}
	}

out:
	/* this should never happen */
	if (resp != &res_buf) {
		kmem_free(resp, dargs.rsize);
	}
}

/*
 * Place client information into stable storage.
 * First, generate the leaf filename, from the client's IP address and
 * the server-generated short-hand clientid.
 */
void
rfs4_ss_clid(struct compound_state *cs, rfs4_client_t *cp, struct svc_req *req)
{
	const char *kinet_ntop6(uchar_t *, char *, size_t);
	char leaf[MAXNAMELEN], buf[INET6_ADDRSTRLEN];
	struct sockaddr *ca;
	uchar_t *b;

	if (!(cs->instp->inst_flags & NFS_INST_SS_ENABLED)) {
		return;
	}

	buf[0] = 0;


	ca = (struct sockaddr *)svc_getrpccaller(req->rq_xprt)->buf;
	if (ca == NULL) {
		return;
	}

	/*
	 * Convert the caller's IP address to a dotted string
	 */
	if (ca->sa_family == AF_INET) {

		bcopy(svc_getrpccaller(req->rq_xprt)->buf, &cp->rc_cl_addr,
		    sizeof (struct sockaddr_in));
		b = (uchar_t *)&((struct sockaddr_in *)ca)->sin_addr;
		(void) sprintf(buf, "%03d.%03d.%03d.%03d", b[0] & 0xFF,
		    b[1] & 0xFF, b[2] & 0xFF, b[3] & 0xFF);
	} else if (ca->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)ca;
		bcopy(svc_getrpccaller(req->rq_xprt)->buf, &cp->rc_cl_addr,
		    sizeof (struct sockaddr_in6));
		(void) kinet_ntop6((uchar_t *)&sin6->sin6_addr,
		    buf, INET6_ADDRSTRLEN);
	}

	(void) snprintf(leaf, MAXNAMELEN, "%s-%llx", buf,
	    (longlong_t)cp->rc_clientid);

	rfs4_ss_write(cs->instp, cp, leaf);
}



/*
 * DSS: distributed stable storage.
 * Unpack the list of paths passed by nfsd.
 * Use nvlist_alloc(9F) to manage the data.
 * The caller is responsible for allocating and freeing the buffer.
 */
int
rfs4_dss_setpaths(char *buf, size_t buflen)
{
	int error;

	/*
	 * If this is a "warm start", i.e. we previously had DSS paths,
	 * preserve the old paths.
	 */
	if (rfs4_dss_paths != NULL) {
		/*
		 * Before we lose the ptr, destroy the nvlist and pathnames
		 * array from the warm start before this one.
		 */
		if (rfs4_dss_oldpaths)
			nvlist_free(rfs4_dss_oldpaths);
		rfs4_dss_oldpaths = rfs4_dss_paths;
	}

	/* unpack the buffer into a searchable nvlist */
	error = nvlist_unpack(buf, buflen, &rfs4_dss_paths, KM_SLEEP);
	if (error)
		return (error);

	/*
	 * Search the nvlist for the pathnames nvpair (which is the only nvpair
	 * in the list, and record its location.
	 */
	error = nvlist_lookup_string_array(rfs4_dss_paths, NFS4_DSS_NVPAIR_NAME,
	    &rfs4_dss_newpaths, &rfs4_dss_numnewpaths);
	return (error);
}

/*
 * Ultimately the nfssys() call NFS4_CLR_STATE endsup here
 * to find and call the protocol specific clean_up/expire
 * function;
 */
static void
rfs4_client_scrub(rfs4_entry_t ent, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)ent;
	struct nfs4clrst_args *clr = arg;
	struct sockaddr_in6 *ent_sin6;
	struct in6_addr  clr_in6;
	struct sockaddr_in  *ent_sin;
	struct in_addr   clr_in;
	nfs_server_instance_t *instp;

	if (clr->addr_type != cp->rc_cl_addr.ss_family) {
		return;
	}

	instp = dbe_to_instp(cp->rc_dbe);

	switch (clr->addr_type) {

	case AF_INET6:
		/* copyin the address from user space */
		if (copyin(clr->ap, &clr_in6, sizeof (clr_in6))) {
			break;
		}

		ent_sin6 = (struct sockaddr_in6 *)&cp->rc_cl_addr;

		/*
		 * now compare, and if equivalent mark entry
		 * for forced expiration
		 */
		if (IN6_ARE_ADDR_EQUAL(&ent_sin6->sin6_addr, &clr_in6)) {
			(*instp->clnt_clear)(cp);
		}
		break;

	case AF_INET:
		/* copyin the address from user space */
		if (copyin(clr->ap, &clr_in, sizeof (clr_in))) {
			break;
		}

		ent_sin = (struct sockaddr_in *)&cp->rc_cl_addr;

		/*
		 * now compare, and if equivalent mark entry
		 * for forced expiration
		 */
		if (ent_sin->sin_addr.s_addr == clr_in.s_addr) {
			(*instp->clnt_clear)(cp);
		}
		break;

	default:
		/* force this assert to fail */
		ASSERT(clr->addr_type != clr->addr_type);
	}
}

static void
sstor_client_scrub(nfs_server_instance_t *instp, void *data)
{
	struct nfs4clrst_args *arg = (struct nfs4clrst_args *)data;

	if (instp->client_tab != NULL)
		rfs4_dbe_walk(instp->client_tab, rfs4_client_scrub, arg);
}

/*
 * This is called from nfssys() in order to clear server state
 * for the specified client IP Address.
 */
void
rfs4_clear_client_state(struct nfs4clrst_args *clr)
{
	nsi_walk(sstor_client_scrub, clr);
}

/* this need to be cleaned up robert.. hello.. */
typedef union {
	struct {
		uint32_t start_time;
		uint32_t c_id;
	} impl_id;
	clientid4 id4;
} cid;

static int foreign_stateid(stateid_t *id);
static int foreign_clientid(cid *cidp);
static void embed_nodeid(cid *cidp);

typedef union {
	struct {
		uint32_t c_id;
		uint32_t gen_num;
	} cv_impl;
	verifier4	confirm_verf;
} scid_confirm_verf;

uint32_t
clientid_hash(void *key)
{
	cid *idp = key;

	return (idp->impl_id.c_id);
}

bool_t
clientid_compare(rfs4_entry_t entry, void *key)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;
	clientid4 *idp = key;

	return (*idp == cp->rc_clientid);
}

void *
clientid_mkkey(rfs4_entry_t entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;

	return (&cp->rc_clientid);
}

uint32_t
nfsclnt_hash(void *key)
{
	nfs_client_id4 *client = key;
	int i;
	uint32_t hash = 0;

	for (i = 0; i < client->id_len; i++) {
		hash <<= 1;
		hash += (uint_t)client->id_val[i];
	}
	return (hash);
}


bool_t
nfsclnt_compare(rfs4_entry_t entry, void *key)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;
	nfs_client_id4 *nfs_client = key;

	if (cp->rc_nfs_client.id_len != nfs_client->id_len)
		return (FALSE);

	return (bcmp(cp->rc_nfs_client.id_val, nfs_client->id_val,
	    nfs_client->id_len) == 0);
}

void *
nfsclnt_mkkey(rfs4_entry_t entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)entry;

	return (&cp->rc_nfs_client);
}

bool_t
rfs4_client_expiry(rfs4_entry_t u_entry)
{
	nfs_server_instance_t *instp;
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;
	bool_t cp_expired;

	if (rfs4_dbe_is_invalid(cp->rc_dbe)) {
		cp->rc_ss_remove = 1;
		return (TRUE);
	}

	if (cp->rc_clid_scope)
		return (FALSE);

	instp = dbe_to_instp(cp->rc_dbe);
	/*
	 * If the sysadmin has used clear_locks for this
	 * entry then forced_expire will be set and we
	 * want this entry to be reaped. Or the entry
	 * has exceeded its lease period.
	 */
	cp_expired = (cp->rc_forced_expire ||
	    (gethrestime_sec() - cp->rc_last_access
	    > instp->lease_period));

	if (!cp->rc_ss_remove && cp_expired)
		cp->rc_ss_remove = 1;
	return (cp_expired);
}

static void
rfs4_ss_delete_client(nfs_server_instance_t *instp, char *leaf)
{
	struct ss_arg ss_data;
	struct ss_res res_buf;
	door_arg_t dargs;
	int error;

	ss_data.cmd = NFS4_SS_DELETE_CLNT;
	(void) snprintf(ss_data.path, MAXPATHLEN, "%s/%s",
	    instp->inst_name, leaf);

	dargs.data_ptr = (char *)&ss_data;
	dargs.data_size = sizeof (struct ss_arg);
	dargs.desc_ptr = NULL;
	dargs.desc_num = 0;
	dargs.rbuf = (char *)&res_buf;
	dargs.rsize = sizeof (struct ss_res);

	error = door_ki_upcall(instp->dh, &dargs);

#ifdef DEBUG
	/* XXX - jw - what do we do here? */
	if (error)
		printf("ss_delete_client: door upcall failed! (%d)\n", error);
#endif
}

static void
rfs4_ss_delete_oldstate(nfs_server_instance_t *instp)
{
	struct ss_arg ss_data;
	struct ss_res res_buf;
	door_arg_t dargs;
	int error;

	ss_data.cmd = NFS4_SS_DELETE_OLD;
	(void) snprintf(ss_data.path, MAXPATHLEN, "%s", instp->inst_name);

	dargs.data_ptr = (char *)&ss_data;
	dargs.data_size = sizeof (struct ss_arg);
	dargs.desc_ptr = NULL;
	dargs.desc_num = 0;
	dargs.rbuf = (char *)&res_buf;
	dargs.rsize = sizeof (struct ss_res);

	error = door_ki_upcall(instp->dh, &dargs);

#ifdef DEBUG
	/* XXX - jw - what do we do here? */
	if (error)
		printf("delete_oldstate: door upcall failed! (%d)\n", error);
#endif

	rfs4_clean_reclaim_list(instp);
}

static void
rfs4_clean_reclaim_list(nfs_server_instance_t *instp)
{
	rfs4_reclaim_t *op;

	rw_enter(&instp->reclaimlst_lock, RW_WRITER);

	while (op = list_head(&instp->reclaim_head)) {
		list_remove(&instp->reclaim_head, op);
		if (op->cl_id4.id_val)
			kmem_free(op->cl_id4.id_val, op->cl_id4.id_len);
		if (op->ss_pn)
			kmem_free(op->ss_pn, sizeof (rfs4_ss_pn_t));
		kmem_free(op, sizeof (rfs4_reclaim_t));
	}

	rw_exit(&instp->reclaimlst_lock);
}

void
rfs4_client_destroy(rfs4_entry_t u_entry)
{
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(cp->rc_dbe);

	mutex_destroy(cp->rc_cbinfo.cb_lock);
	cv_destroy(cp->rc_cbinfo.cb_cv);
	cv_destroy(cp->rc_cbinfo.cb_cv_nullcaller);

	/* free callback info */
	rfs4_cbinfo_free(&cp->rc_cbinfo);

	if (cp->rc_cp_confirmed)
		rfs4_client_rele(cp->rc_cp_confirmed);

	if (cp->rc_ss_pn) {
		/* check if the stable storage files need to be removed */
		if (cp->rc_ss_remove) {
			rfs4_ss_delete_client(instp, cp->rc_ss_pn->leaf);
		}
		rfs4_ss_pnfree(cp->rc_ss_pn);
	}

	/* if this is a 4.1 client, clean up it's sessions */
	if (instp->inst_flags & NFS_INST_v41) {
		mds_clean_up_sessions(cp);
		mds_clean_up_grants(cp);
		mds_clean_up_trunkinfo(cp);
	}

	/* Free the client supplied client id */
	kmem_free(cp->rc_nfs_client.id_val, cp->rc_nfs_client.id_len);

	if (cp->rc_sysidt != LM_NOSYSID)
		lm_free_sysidt(cp->rc_sysidt);
}

bool_t
rfs4_client_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_client_t *cp = (rfs4_client_t *)u_entry;
	nfs_client_id4 *client = (nfs_client_id4 *)arg;
	cid *cidp;
	scid_confirm_verf *scvp;
	int	i;

	/* Get a clientid to give to the client */
	cidp = (cid *)&cp->rc_clientid;
	cidp->impl_id.start_time = cp->rc_dbe->dbe_table->dbt_instp->start_time;
	cidp->impl_id.c_id = (uint32_t)rfs4_dbe_getid(cp->rc_dbe);

	/* If we are booted as a cluster node, embed our nodeid */
	if (cluster_bootflags & CLUSTER_BOOTED)
		embed_nodeid(cidp);

	/* Allocate and copy client's client id value */
	cp->rc_nfs_client.id_val = kmem_alloc(client->id_len, KM_SLEEP);
	cp->rc_nfs_client.id_len = client->id_len;
	bcopy(client->id_val, cp->rc_nfs_client.id_val, client->id_len);
	cp->rc_nfs_client.verifier = client->verifier;

	/* Init the value for the verifier */
	scvp = (scid_confirm_verf *)&cp->rc_confirm_verf;
	scvp->cv_impl.c_id = cidp->impl_id.c_id;
	scvp->cv_impl.gen_num = 0;

	/* An F_UNLKSYS has been done for this client */
	cp->rc_unlksys_completed = FALSE;

	/* We need the client to ack us */
	cp->rc_need_confirm = TRUE;
	cp->rc_cp_confirmed = NULL;

	/* TRUE all the time until the callback path actually fails */
	cp->rc_cbinfo.cb_notified_of_cb_path_down = TRUE;

	/* Initialize the access time to now */
	cp->rc_last_access = gethrestime_sec();

	cp->rc_cr_set = NULL;

	cp->rc_sysidt = LM_NOSYSID;

	list_create(&cp->rc_openownerlist, sizeof (rfs4_openowner_t),
	    offsetof(rfs4_openowner_t, ro_node));

	/* Init client grant list for remque/insque */
	cp->rc_clientgrantlist.next = cp->rc_clientgrantlist.prev =
	    &cp->rc_clientgrantlist;
	cp->rc_clientgrantlist.lg = NULL;

	cp->rc_bulk_recall = 0;

	/* set up the callback control structure */
	cp->rc_cbinfo.cb_state = CB_UNINIT;
	mutex_init(cp->rc_cbinfo.cb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(cp->rc_cbinfo.cb_cv, NULL, CV_DEFAULT, NULL);
	cv_init(cp->rc_cbinfo.cb_cv_nullcaller, NULL, CV_DEFAULT, NULL);

	/*
	 * NFSv4.1: See draft-07, Section 16.36.5
	 */
	cp->rc_contrived.xi_sid = 1;
	cp->rc_contrived.cs_slot.seqid = 0;
	cp->rc_contrived.cs_slot.status = NFS4ERR_SEQ_MISORDERED;

	/* only initialize bits relevant to client scope */
	bzero(&cp->rc_seq4, sizeof (bit_attr_t) * BITS_PER_WORD);
	for (i = 1; i <= SEQ4_HIGH_BIT && i != 0; i <<= 1) {
		uint32_t idx = log2(i);

		switch (i) {
		case SEQ4_STATUS_CB_PATH_DOWN:
		case SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED:
		case SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED:
		case SEQ4_STATUS_ADMIN_STATE_REVOKED:
		case SEQ4_STATUS_RECALLABLE_STATE_REVOKED:
		case SEQ4_STATUS_LEASE_MOVED:
		case SEQ4_STATUS_RESTART_RECLAIM_NEEDED:
		case SEQ4_STATUS_DEVID_CHANGED:
		case SEQ4_STATUS_DEVID_DELETED:
			cp->rc_seq4[idx].ba_bit = i;
			break;
		default:
			/* already bzero'ed */
			break;
		}
	}

	list_create(&cp->rc_trunkinfo, sizeof (rfs41_tie_t),
	    offsetof(rfs41_tie_t, t_link));
	return (TRUE);
}

/*
 * Caller wants to generate/update the setclientid_confirm verifier
 * associated with a client.  This is done during the SETCLIENTID
 * processing.
 */
void
rfs4_client_scv_next(rfs4_client_t *cp)
{
	scid_confirm_verf *scvp;

	/* Init the value for the SETCLIENTID_CONFIRM verifier */
	scvp = (scid_confirm_verf *)&cp->rc_confirm_verf;
	scvp->cv_impl.gen_num++;
}

void
rfs4_client_rele(rfs4_client_t *cp)
{
	rfs4_dbe_rele(cp->rc_dbe);
}

/*
 *  Find an rfs4_client
 */
rfs4_client_t *
findclient(nfs_server_instance_t *instp,
	nfs_client_id4 *client,
	bool_t *create,
	rfs4_client_t *oldcp)
{
	rfs4_client_t *cp;

	if (oldcp) {
		rw_enter(&instp->findclient_lock, RW_WRITER);
		rfs4_dbe_hide(oldcp->rc_dbe);
	} else {
		rw_enter(&instp->findclient_lock, RW_READER);
	}

	cp = (rfs4_client_t *)rfs4_dbsearch(instp->nfsclnt_idx, client,
	    create, (void *)client, RFS4_DBS_VALID);

	if (oldcp)
		rfs4_dbe_unhide(oldcp->rc_dbe);

	rw_exit(&instp->findclient_lock);

	return (cp);
}

/*
 * Find an rfs4_client via the ID.
 */
rfs4_client_t *
findclient_by_id(nfs_server_instance_t *instp, clientid4 clientid)
{
	rfs4_client_t *cp;
	bool_t create = FALSE;

	rw_enter(&instp->findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(instp->clientid_idx, &clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&instp->findclient_lock);

	return (cp);
}

rfs4_client_t *
rfs4_findclient_by_id(nfs_server_instance_t *instp, clientid4 clientid,
    bool_t find_unconfirmed)
{
	rfs4_client_t *cp;
	cid *cidp = (cid *)&clientid;

	/* If we're a cluster and the nodeid isn't right, short-circuit */
	if (cluster_bootflags & CLUSTER_BOOTED && foreign_clientid(cidp))
		return (NULL);

	cp = findclient_by_id(instp, clientid);

	if (cp && cp->rc_need_confirm && find_unconfirmed == FALSE) {
		rfs4_client_rele(cp);
		return (NULL);
	}
	return (cp);
}

/*
 * Evaluate if the lease for this client has expired.
 */
bool_t
rfs4_lease_expired(rfs4_client_t *cp)
{
	bool_t rc;

	rfs4_dbe_lock(cp->rc_dbe);

	/*
	 * If the admin has executed clear_locks for this
	 * client id, force expire will be set, so no need
	 * to calculate anything because it's "outa here".
	 */
	if (cp->rc_forced_expire) {
		rc = TRUE;
	} else {
		if (cp->rc_clid_scope) {
			rc = FALSE;
		} else {
			rc = (gethrestime_sec() - cp->rc_last_access >
			    dbe_to_instp(cp->rc_dbe)->lease_period);
		}
	}

	/*
	 * If the lease has expired we will also want
	 * to remove any stable storage state data. So
	 * mark the client id accordingly.
	 */
	if (!cp->rc_ss_remove)
		cp->rc_ss_remove = (rc == TRUE);

	rfs4_dbe_unlock(cp->rc_dbe);

	return (rc);
}

void
rfs4_update_lease(rfs4_client_t *cp)
{
	rfs4_dbe_lock(cp->rc_dbe);
	if (!cp->rc_forced_expire)
		cp->rc_last_access = gethrestime_sec();
	rfs4_dbe_unlock(cp->rc_dbe);
}

void
rfs4_state_rele_nounlock(rfs4_state_t *sp)
{
	rfs4_dbe_rele(sp->rs_dbe);
}

void
rfs4_state_rele(rfs4_state_t *sp)
{
	rw_exit(&sp->rs_finfo->rf_file_rwlock);
	rfs4_dbe_rele(sp->rs_dbe);
}

/*
 * Open Owners:
 */
uint_t
openowner_hash(void *key)
{
	int i;
	open_owner4 *openowner = key;
	uint_t hash = 0;

	for (i = 0; i < openowner->owner_len; i++) {
		hash <<= 4;
		hash += (uint_t)openowner->owner_val[i];
	}
	hash += (uint_t)openowner->clientid;
	hash |= (openowner->clientid >> 32);

	return (hash);
}

bool_t
openowner_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;
	open_owner4 *arg = key;
	bool_t rc;

	if (oo->ro_owner.clientid != arg->clientid)
		return (FALSE);

	if (oo->ro_owner.owner_len != arg->owner_len)
		return (FALSE);

	rc = (bcmp(oo->ro_owner.owner_val,
	    arg->owner_val, arg->owner_len) == 0);

	return (rc);
}

void *
openowner_mkkey(rfs4_entry_t u_entry)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;

	return (&oo->ro_owner);
}

bool_t
rfs4_openowner_expiry(rfs4_entry_t u_entry)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;

	if (rfs4_dbe_is_invalid(oo->ro_dbe))
		return (TRUE);
	return ((gethrestime_sec() - oo->ro_client->rc_last_access
	    > dbe_to_instp(oo->ro_dbe)->lease_period));
}

void
openowner_destroy(rfs4_entry_t u_entry)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;

	/* Remove open owner from client's lists of open owners */
	rfs4_dbe_lock(oo->ro_client->rc_dbe);
	list_remove(&oo->ro_client->rc_openownerlist, oo);
	rfs4_dbe_unlock(oo->ro_client->rc_dbe);

	/* One less reference to the client */
	rfs4_client_rele(oo->ro_client);
	oo->ro_client = NULL;

	/* Free the last reply for this lock owner */
	rfs4_free_reply(oo->ro_reply);

	if (oo->ro_reply_fh.nfs_fh4_val) {
		kmem_free(oo->ro_reply_fh.nfs_fh4_val,
		    oo->ro_reply_fh.nfs_fh4_len);
		oo->ro_reply_fh.nfs_fh4_val = NULL;
		oo->ro_reply_fh.nfs_fh4_len = 0;
	}

	rfs4_sw_destroy(&oo->ro_sw);
	list_destroy(&oo->ro_statelist);

	/* Free the lock owner id */
	kmem_free(oo->ro_owner.owner_val, oo->ro_owner.owner_len);
}

void
rfs4_openowner_rele(rfs4_openowner_t *oo)
{
	rfs4_dbe_rele(oo->ro_dbe);
}

bool_t
openowner_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_openowner_t *oo = (rfs4_openowner_t *)u_entry;
	rfs4_openowner_t *argp = (rfs4_openowner_t *)arg;
	open_owner4 *openowner = &argp->ro_owner;
	seqid4 seqid = argp->ro_open_seqid;
	rfs4_client_t *cp;
	bool_t create = FALSE;
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(oo->ro_dbe);

	rw_enter(&instp->findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(instp->clientid_idx,
	    &openowner->clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&instp->findclient_lock);

	if (cp == NULL)
		return (FALSE);

	oo->ro_reply_fh.nfs_fh4_len = 0;
	oo->ro_reply_fh.nfs_fh4_val = NULL;

	oo->ro_owner.clientid = openowner->clientid;
	oo->ro_owner.owner_val =
	    kmem_alloc(openowner->owner_len, KM_SLEEP);

	bcopy(openowner->owner_val,
	    oo->ro_owner.owner_val, openowner->owner_len);

	oo->ro_owner.owner_len = openowner->owner_len;

	oo->ro_need_confirm = TRUE;

	rfs4_sw_init(&oo->ro_sw);

	oo->ro_open_seqid = seqid;
	bzero(&oo->ro_reply, sizeof (nfs_resop4));
	oo->ro_client = cp;
	oo->ro_cr_set = NULL;

	list_create(&oo->ro_statelist, sizeof (rfs4_state_t),
	    offsetof(rfs4_state_t, rs_node));

	/* Insert openowner into client's open owner list */
	rfs4_dbe_lock(cp->rc_dbe);
	list_insert_tail(&cp->rc_openownerlist, oo);
	rfs4_dbe_unlock(cp->rc_dbe);

	return (TRUE);
}

rfs4_openowner_t *
rfs4_findopenowner(nfs_server_instance_t *instp,
    open_owner4 *openowner, bool_t *create, seqid4 seqid)
{
	rfs4_openowner_t *oo;
	rfs4_openowner_t arg;

	arg.ro_owner = *openowner;
	arg.ro_open_seqid = seqid;
	oo = (rfs4_openowner_t *)rfs4_dbsearch(instp->openowner_idx,
	    openowner, create, &arg, RFS4_DBS_VALID);

	return (oo);
}

/* !!! NFSv4.0 ONLY !!! */
void
rfs4_update_open_sequence(rfs4_openowner_t *oo)
{

	ASSERT(!(dbe_to_instp(oo->ro_dbe)->inst_flags & NFS_INST_v41));

	rfs4_dbe_lock(oo->ro_dbe);

	oo->ro_open_seqid++;

	rfs4_dbe_unlock(oo->ro_dbe);
}

void
rfs4_update_open_resp(rfs4_openowner_t *oo, nfs_resop4 *resp, nfs_fh4 *fh)
{
	ASSERT(!(dbe_to_instp(oo->ro_dbe)->inst_flags & NFS_INST_v41));

	rfs4_dbe_lock(oo->ro_dbe);

	rfs4_free_reply(oo->ro_reply);

	rfs4_copy_reply(oo->ro_reply, resp);

	/* Save the filehandle if provided and free if not used */
	if (resp->nfs_resop4_u.opopen.status == NFS4_OK &&
	    fh && fh->nfs_fh4_len) {
		if (oo->ro_reply_fh.nfs_fh4_val == NULL)
			oo->ro_reply_fh.nfs_fh4_val =
			    kmem_alloc(fh->nfs_fh4_len, KM_SLEEP);
		nfs_fh4_copy(fh, &oo->ro_reply_fh);
	} else {
		if (oo->ro_reply_fh.nfs_fh4_val) {
			kmem_free(oo->ro_reply_fh.nfs_fh4_val,
			    oo->ro_reply_fh.nfs_fh4_len);
			oo->ro_reply_fh.nfs_fh4_val = NULL;
			oo->ro_reply_fh.nfs_fh4_len = 0;
		}
	}

	rfs4_dbe_unlock(oo->ro_dbe);
}

/*
 * Lock Owner:
 */
bool_t
lockowner_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;
	lock_owner4 *b = (lock_owner4 *)key;

	if (lo->rl_owner.clientid != b->clientid)
		return (FALSE);

	if (lo->rl_owner.owner_len != b->owner_len)
		return (FALSE);

	return (bcmp(lo->rl_owner.owner_val, b->owner_val,
	    lo->rl_owner.owner_len) == 0);
}

void *
lockowner_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return (&lo->rl_owner);
}

uint32_t
lockowner_hash(void *key)
{
	int i;
	lock_owner4 *lockowner = key;
	uint_t hash = 0;

	for (i = 0; i < lockowner->owner_len; i++) {
		hash <<= 4;
		hash += (uint_t)lockowner->owner_val[i];
	}
	hash += (uint_t)lockowner->clientid;
	hash |= (lockowner->clientid >> 32);

	return (hash);
}

uint32_t
pid_hash(void *key)
{
	return ((uint32_t)(uintptr_t)key);
}

void *
pid_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return ((void *)(uintptr_t)lo->rl_pid);
}

bool_t
pid_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	return (lo->rl_pid == (pid_t)(uintptr_t)key);
}

void
rfs4_lockowner_destroy(rfs4_entry_t u_entry)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;

	/* Free the lock owner id */
	kmem_free(lo->rl_owner.owner_val, lo->rl_owner.owner_len);
	rfs4_client_rele(lo->rl_client);
}

void
rfs4_lockowner_rele(rfs4_lockowner_t *lo)
{
	rfs4_dbe_rele(lo->rl_dbe);
}

/* ARGSUSED */
bool_t
rfs4_lockowner_expiry(rfs4_entry_t u_entry)
{
	/*
	 * Since expiry is called with no other references on
	 * this struct, go ahead and have it removed.
	 */
	return (TRUE);
}

bool_t
rfs4_lockowner_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_lockowner_t *lo = (rfs4_lockowner_t *)u_entry;
	lock_owner4 *lockowner = (lock_owner4 *)arg;
	rfs4_client_t *cp;
	bool_t create = FALSE;
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(lo->rl_dbe);

	rw_enter(&instp->findclient_lock, RW_READER);

	cp = (rfs4_client_t *)rfs4_dbsearch(instp->clientid_idx,
	    &lockowner->clientid,
	    &create, NULL, RFS4_DBS_VALID);

	rw_exit(&instp->findclient_lock);

	if (cp == NULL)
		return (FALSE);

	/* Reference client */
	lo->rl_client = cp;
	lo->rl_owner.clientid = lockowner->clientid;
	lo->rl_owner.owner_val = kmem_alloc(lockowner->owner_len, KM_SLEEP);
	bcopy(lockowner->owner_val, lo->rl_owner.owner_val,
	    lockowner->owner_len);
	lo->rl_owner.owner_len = lockowner->owner_len;
	lo->rl_pid = rfs4_dbe_getid(lo->rl_dbe);

	return (TRUE);
}


rfs4_lockowner_t *
findlockowner(nfs_server_instance_t *instp, lock_owner4 *lockowner,
	    bool_t *create)
{
	rfs4_lockowner_t *lo;

	lo = (rfs4_lockowner_t *)rfs4_dbsearch(instp->lockowner_idx,
	    lockowner, create, lockowner,
	    RFS4_DBS_VALID);

	return (lo);
}


rfs4_lockowner_t *
findlockowner_by_pid(nfs_server_instance_t *instp, pid_t pid)
{
	rfs4_lockowner_t *lo;
	bool_t create = FALSE;

	lo = (rfs4_lockowner_t *)rfs4_dbsearch(instp->lockowner_pid_idx,
	    (void *)(uintptr_t)pid, &create, NULL, RFS4_DBS_VALID);

	return (lo);
}

/*
 * rfs4_file:
 */
uint32_t
file_hash(void *key)
{
	return (ADDRHASH(key));
}

void *
file_mkkey(rfs4_entry_t u_entry)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	return (fp->rf_vp);
}

bool_t
file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	return (fp->rf_vp == (vnode_t *)key);
}

void
rfs4_file_destroy(rfs4_entry_t u_entry)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;

	if (fp->rf_mlo) {
		rfs4_dbe_rele(fp->rf_mlo->mlo_dbe);
		fp->rf_mlo = NULL;
	}

	list_destroy(&fp->rf_delegstatelist);

	if (fp->rf_filehandle.nfs_fh4_val)
		kmem_free(fp->rf_filehandle.nfs_fh4_val,
		    fp->rf_filehandle.nfs_fh4_len);
	cv_destroy(fp->rf_dinfo->rd_recall_cv);
	if (fp->rf_vp) {
		vnode_t *vp = fp->rf_vp;
		nfs_server_instance_t *instp;

		instp = dbe_to_instp(fp->rf_dbe);
		mutex_enter(&vp->v_vsd_lock);
		(void) vsd_set(vp, instp->vkey, NULL);
		mutex_exit(&vp->v_vsd_lock);
		VN_RELE(vp);
		fp->rf_vp = NULL;
	}
	rw_destroy(&fp->rf_file_rwlock);
}

/*
 * Used to unlock the underlying dbe struct only
 */
void
rfs4_file_rele(rfs4_file_t *fp)
{
	rfs4_dbe_rele(fp->rf_dbe);
}

/*
 * Used to unlock the file rw lock and the file's dbe entry
 * Only used to pair with rfs4_findfile_withlock()
 */
void
rfs4_file_rele_withunlock(rfs4_file_t *fp)
{
	rw_exit(&fp->rf_file_rwlock);
	rfs4_dbe_rele(fp->rf_dbe);
}

typedef struct {
    vnode_t *vp;
    nfs_fh4 *fh;
} rfs4_fcreate_arg;

/* ARGSUSED */
bool_t
rfs4_file_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;
	rfs4_fcreate_arg *ap = (rfs4_fcreate_arg *)arg;
	vnode_t *vp = ap->vp;
	nfs_fh4 *fh = ap->fh;
	nfs_server_instance_t *instp;

	instp = dbe_to_instp(fp->rf_dbe);

	VN_HOLD(vp);

	fp->rf_filehandle.nfs_fh4_len = 0;
	fp->rf_filehandle.nfs_fh4_val = NULL;
	ASSERT(fh && fh->nfs_fh4_len);
	if (fh && fh->nfs_fh4_len) {
		fp->rf_filehandle.nfs_fh4_val =
		    kmem_alloc(fh->nfs_fh4_len, KM_SLEEP);
		nfs_fh4_copy(fh, &fp->rf_filehandle);
	}
	fp->rf_vp = vp;

	list_create(&fp->rf_delegstatelist, sizeof (rfs4_deleg_state_t),
	    offsetof(rfs4_deleg_state_t, rds_node));

	/* Init layout grant list for remque/insque */
	fp->rf_lo_grant_list.next = fp->rf_lo_grant_list.prev =
	    &fp->rf_lo_grant_list;
	fp->rf_lo_grant_list.lg = NULL;

	fp->rf_share_deny = fp->rf_share_access = fp->rf_access_read = 0;
	fp->rf_access_write = fp->rf_deny_read = fp->rf_deny_write = 0;

	mutex_init(fp->rf_dinfo->rd_recall_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(fp->rf_dinfo->rd_recall_cv, NULL, CV_DEFAULT, NULL);

	fp->rf_dinfo->rd_dtype = OPEN_DELEGATE_NONE;

	rw_init(&fp->rf_file_rwlock, NULL, RW_DEFAULT, NULL);

	mutex_enter(&vp->v_vsd_lock);
	VERIFY(vsd_set(vp, instp->vkey, (void *)fp) == 0);
	mutex_exit(&vp->v_vsd_lock);

	return (TRUE);
}

rfs4_file_t *
rfs4_findfile(nfs_server_instance_t *instp, vnode_t *vp, nfs_fh4 *fh,
	    bool_t *create)
{
	rfs4_file_t *fp;
	rfs4_fcreate_arg arg;

	arg.vp = vp;
	arg.fh = fh;

	if (*create == TRUE)
		fp = (rfs4_file_t *)rfs4_dbsearch(instp->file_idx, vp,
		    create, &arg, RFS4_DBS_VALID);
	else {
		mutex_enter(&vp->v_vsd_lock);
		fp = (rfs4_file_t *)vsd_get(vp, instp->vkey);
		if (fp) {
			rfs4_dbe_lock(fp->rf_dbe);
			if (rfs4_dbe_is_invalid(fp->rf_dbe) ||
			    (rfs4_dbe_refcnt(fp->rf_dbe) == 0)) {
				rfs4_dbe_unlock(fp->rf_dbe);
				fp = NULL;
			} else {
				rfs4_dbe_hold(fp->rf_dbe);
				rfs4_dbe_unlock(fp->rf_dbe);
			}
		}
		mutex_exit(&vp->v_vsd_lock);
	}
	return (fp);
}

/*
 * Find a file in the db and once it is located, take the rw lock.
 * Need to check the vnode pointer and if it does not exist (it was
 * removed between the db location and check) redo the find.  This
 * assumes that a file struct that has a NULL vnode pointer is marked
 * at 'invalid' and will not be found in the db the second time
 * around.
 */
rfs4_file_t *
rfs4_findfile_withlock(nfs_server_instance_t *instp, vnode_t *vp, nfs_fh4 *fh,
	    bool_t *create)
{
	rfs4_file_t *fp;
	rfs4_fcreate_arg arg;
	bool_t screate = *create;

	if (screate == FALSE) {
		mutex_enter(&vp->v_vsd_lock);
		fp = (rfs4_file_t *)vsd_get(vp, instp->vkey);
		if (fp) {
			rfs4_dbe_lock(fp->rf_dbe);
			if (rfs4_dbe_is_invalid(fp->rf_dbe) ||
			    (rfs4_dbe_refcnt(fp->rf_dbe) == 0)) {
				rfs4_dbe_unlock(fp->rf_dbe);
				mutex_exit(&vp->v_vsd_lock);
				fp = NULL;
			} else {
				rfs4_dbe_hold(fp->rf_dbe);
				rfs4_dbe_unlock(fp->rf_dbe);
				mutex_exit(&vp->v_vsd_lock);
				rw_enter(&fp->rf_file_rwlock, RW_WRITER);
				if (fp->rf_vp == NULL) {
					rw_exit(&fp->rf_file_rwlock);
					rfs4_file_rele(fp);
					fp = NULL;
				}
			}
		} else {
			mutex_exit(&vp->v_vsd_lock);
		}
	} else {
retry:
		arg.vp = vp;
		arg.fh = fh;

		fp = (rfs4_file_t *)rfs4_dbsearch(instp->file_idx, vp,
		    create, &arg, RFS4_DBS_VALID);
		if (fp != NULL) {
			rw_enter(&fp->rf_file_rwlock, RW_WRITER);
			if (fp->rf_vp == NULL) {
				rw_exit(&fp->rf_file_rwlock);
				rfs4_file_rele(fp);
				*create = screate;
				goto retry;
			}
		}
	}

	return (fp);
}

uint32_t
lo_state_hash(void *key)
{
	stateid_t *id = key;

	return (id->v4_bits.state_ident+id->v4_bits.pid);
}

bool_t
lo_state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	stateid_t *id = key;
	bool_t rc;

	rc = (lsp->rls_lockid.v4_bits.boottime == id->v4_bits.boottime &&
	    lsp->rls_lockid.v4_bits.type == id->v4_bits.type &&
	    lsp->rls_lockid.v4_bits.state_ident == id->v4_bits.state_ident &&
	    lsp->rls_lockid.v4_bits.pid == id->v4_bits.pid);

	return (rc);
}

void *
lo_state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	return (&lsp->rls_lockid);
}

bool_t
rfs4_lo_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	if (rfs4_dbe_is_invalid(lsp->rls_dbe))
		return (TRUE);
	if (lsp->rls_state->rs_closed)
		return (TRUE);
	return ((gethrestime_sec() -
	    lsp->rls_state->rs_owner->ro_client->rc_last_access
	    > dbe_to_instp(lsp->rls_dbe)->lease_period));
}

void
rfs4_lo_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;

	rfs4_dbe_lock(lsp->rls_state->rs_dbe);
	list_remove(&lsp->rls_state->rs_lostatelist, lsp);
	rfs4_dbe_unlock(lsp->rls_state->rs_dbe);

	rfs4_sw_destroy(&lsp->rls_sw);

	/* Make sure to release the file locks */
	if (lsp->rls_locks_cleaned == FALSE) {
		lsp->rls_locks_cleaned = TRUE;
		if (lsp->rls_locker->rl_client->rc_sysidt != LM_NOSYSID) {
			/* Is the PxFS kernel module loaded? */
			if (lm_remove_file_locks != NULL) {
				int new_sysid;

				/* Encode the cluster nodeid in new sysid */
				new_sysid =
				    lsp->rls_locker->rl_client->rc_sysidt;
				lm_set_nlmid_flk(&new_sysid);

				/*
				 * This PxFS routine removes file locks for a
				 * client over all nodes of a cluster.
				 */
				DTRACE_PROBE1(nfss_i_clust_rm_lck,
				    int, new_sysid);
				(*lm_remove_file_locks)(new_sysid);
			} else {
				(void) cleanlocks(
				    lsp->rls_state->rs_finfo->rf_vp,
				    lsp->rls_locker->rl_pid,
				    lsp->rls_locker->rl_client->rc_sysidt);
			}
		}
	}

	/* Free the last reply for this state */
	rfs4_free_reply(&lsp->rls_reply);

	rfs4_lockowner_rele(lsp->rls_locker);
	lsp->rls_locker = NULL;

	rfs4_state_rele_nounlock(lsp->rls_state);
	lsp->rls_state = NULL;
}

/* ARGSUSED */
bool_t
rfs4_lo_state_create(rfs4_entry_t u_entry, void *arg)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	rfs4_lo_state_t *argp = (rfs4_lo_state_t *)arg;
	rfs4_lockowner_t *lo = argp->rls_locker;
	rfs4_state_t *sp = argp->rls_state;

	lsp->rls_state = sp;

	lsp->rls_lockid = sp->rs_stateid;
	lsp->rls_lockid.v4_bits.type = LOCKID;
	lsp->rls_lockid.v4_bits.chgseq = 0;
	lsp->rls_lockid.v4_bits.pid = lo->rl_pid;

	lsp->rls_locks_cleaned = FALSE;
	lsp->rls_lock_completed = FALSE;

	rfs4_sw_init(&lsp->rls_sw);

	/* Attached the supplied lock owner */
	rfs4_dbe_hold(lo->rl_dbe);
	lsp->rls_locker = lo;

	rfs4_dbe_lock(sp->rs_dbe);
	list_insert_tail(&sp->rs_lostatelist, lsp);
	rfs4_dbe_hold(sp->rs_dbe);
	rfs4_dbe_unlock(sp->rs_dbe);

	return (TRUE);
}

void
rfs4_lo_state_rele(rfs4_lo_state_t *lsp, bool_t unlock_fp)
{
	if (unlock_fp == TRUE)
		rw_exit(&lsp->rls_state->rs_finfo->rf_file_rwlock);
	rfs4_dbe_rele(lsp->rls_dbe);
}

rfs4_lo_state_t *
rfs4_findlo_state(struct compound_state *cs,
		stateid_t *id, bool_t lock_fp)
{
	rfs4_lo_state_t *lsp;
	bool_t create = FALSE;

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(cs->instp->lo_state_idx, id,
	    &create, NULL, RFS4_DBS_VALID);
	if (lock_fp == TRUE && lsp != NULL)
		rw_enter(&lsp->rls_state->rs_finfo->rf_file_rwlock, RW_READER);

	return (lsp);
}

uint32_t
lo_state_lo_hash(void *key)
{
	rfs4_lo_state_t *lsp = key;

	return (ADDRHASH(lsp->rls_locker) ^ ADDRHASH(lsp->rls_state));
}

bool_t
lo_state_lo_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	rfs4_lo_state_t *keyp = key;

	return (keyp->rls_locker == lsp->rls_locker &&
	    keyp->rls_state == lsp->rls_state);
}

void *
lo_state_lo_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

rfs4_lo_state_t *
rfs4_findlo_state_by_owner(nfs_server_instance_t *instp,
    rfs4_lockowner_t *lo, rfs4_state_t *sp, bool_t *create)
{
	rfs4_lo_state_t *lsp;
	rfs4_lo_state_t arg;

	arg.rls_locker = lo;
	arg.rls_state = sp;

	lsp = (rfs4_lo_state_t *)rfs4_dbsearch(instp->lo_state_owner_idx,
	    &arg, create, &arg, RFS4_DBS_VALID);

	return (lsp);
}

rfs4_lo_state_t *
findlo_state_by_owner(rfs4_lockowner_t *lo,
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

static stateid_t
get_stateid(nfs_server_instance_t *instp, id_t eid, stateid_type_t id_type)
{
	stateid_t id;

	id.v4_bits.boottime = instp->start_time;
	id.v4_bits.state_ident = eid;
	id.v4_bits.chgseq = 0;
	id.v4_bits.type = id_type;
	id.v4_bits.pid = 0;

	/*
	 * If we are booted as a cluster node, embed our nodeid.
	 * We've already done sanity checks in rfs4_client_create() so no
	 * need to repeat them here.
	 */
	id.v4_bits.clnodeid = (cluster_bootflags & CLUSTER_BOOTED) ?
	    clconf_get_nodeid() : 0;

	return (id);
}

/*
 * For use only when booted as a cluster node.
 * Returns TRUE if the embedded nodeid indicates that this stateid was
 * generated on another node.
 */
static int
foreign_stateid(stateid_t *id)
{
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	return (id->v4_bits.clnodeid != (uint32_t)clconf_get_nodeid());
}

/*
 * For use only when booted as a cluster node.
 * Returns TRUE if the embedded nodeid indicates that this clientid was
 * generated on another node.
 */
static int
foreign_clientid(cid *cidp)
{
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	return (cidp->impl_id.c_id >> CLUSTER_NODEID_SHIFT !=
	    (uint32_t)clconf_get_nodeid());
}

/*
 * For use only when booted as a cluster node.
 * Embed our cluster nodeid into the clientid.
 */
static void
embed_nodeid(cid *cidp)
{
	int clnodeid;
	/*
	 * Currently, our state tables are small enough that their
	 * ids will leave enough bits free for the nodeid. If the
	 * tables become larger, we mustn't overwrite the id.
	 * Equally, we only have room for so many bits of nodeid, so
	 * must check that too.
	 */
	ASSERT(cluster_bootflags & CLUSTER_BOOTED);
	ASSERT(cidp->impl_id.c_id >> CLUSTER_NODEID_SHIFT == 0);
	clnodeid = clconf_get_nodeid();
	ASSERT(clnodeid <= CLUSTER_MAX_NODEID);
	ASSERT(clnodeid != NODEID_UNKNOWN);
	cidp->impl_id.c_id |= (clnodeid << CLUSTER_NODEID_SHIFT);
}

uint32_t
state_hash(void *key)
{
	stateid_t *ip = (stateid_t *)key;

	return (ip->v4_bits.state_ident);
}

bool_t
state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	rc = (sp->rs_stateid.v4_bits.boottime == id->v4_bits.boottime &&
	    sp->rs_stateid.v4_bits.state_ident == id->v4_bits.state_ident);

	return (rc);
}

void *
state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	return (&sp->rs_stateid);
}

void
rfs4_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	/* remove from openowner list */
	rfs4_dbe_lock(sp->rs_owner->ro_dbe);
	list_remove(&sp->rs_owner->ro_statelist, sp);
	rfs4_dbe_unlock(sp->rs_owner->ro_dbe);

	list_destroy(&sp->rs_lostatelist);

	/* release any share locks for this stateid if it's still open */
	if (!sp->rs_closed) {
		rfs4_dbe_lock(sp->rs_dbe);
		(void) rfs4_unshare(sp);
		rfs4_dbe_unlock(sp->rs_dbe);
	}

	/* We are done with the file */
	rfs4_file_rele(sp->rs_finfo);
	sp->rs_finfo = NULL;

	/* And now with the openowner */
	rfs4_openowner_rele(sp->rs_owner);
	sp->rs_owner = NULL;
}


uint32_t
deleg_hash(void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)key;

	return (ADDRHASH(dsp->rds_client) ^ ADDRHASH(dsp->rds_finfo));
}

bool_t
deleg_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	rfs4_deleg_state_t *kdsp = (rfs4_deleg_state_t *)key;

	return (dsp->rds_client == kdsp->rds_client &&
	    dsp->rds_finfo == kdsp->rds_finfo);
}

void *
deleg_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

uint32_t
deleg_state_hash(void *key)
{
	stateid_t *ip = (stateid_t *)key;

	return (ip->v4_bits.state_ident);
}

bool_t
deleg_state_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	stateid_t *id = (stateid_t *)key;
	bool_t rc;

	if (id->v4_bits.type != DELEGID)
		return (FALSE);

	rc = (dsp->rds_delegid.v4_bits.boottime == id->v4_bits.boottime &&
	    dsp->rds_delegid.v4_bits.state_ident == id->v4_bits.state_ident);

	return (rc);
}

void *
deleg_state_mkkey(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	return (&dsp->rds_delegid);
}

bool_t
rfs4_deleg_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	if (rfs4_dbe_is_invalid(dsp->rds_dbe))
		return (TRUE);

	if ((gethrestime_sec() - dsp->rds_client->rc_last_access
	    > dbe_to_instp(dsp->rds_dbe)->lease_period)) {
		rfs4_dbe_invalidate(dsp->rds_dbe);
		return (TRUE);
	}

	return (FALSE);
}

bool_t
rfs4_deleg_state_create(rfs4_entry_t u_entry,
			void *argp)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	rfs4_file_t *fp = ((rfs4_deleg_state_t *)argp)->rds_finfo;
	rfs4_client_t *cp = ((rfs4_deleg_state_t *)argp)->rds_client;

	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_hold(cp->rc_dbe);

	dsp->rds_delegid = get_stateid(dbe_to_instp(dsp->rds_dbe),
	    rfs4_dbe_getid(dsp->rds_dbe), DELEGID);
	dsp->rds_finfo = fp;
	dsp->rds_client = cp;
	dsp->rds_dtype = OPEN_DELEGATE_NONE;

	dsp->rds_time_granted = gethrestime_sec();	/* observability */
	dsp->rds_time_revoked = 0;

	list_link_init(&dsp->rds_node);

	/* cb race-detection support */
	dsp->rds_rs.refcnt = dsp->rds_rs.seqid = dsp->rds_rs.slotno = 0;
	bzero(&dsp->rds_rs.sessid, sizeof (sessionid4));

	return (TRUE);
}

void
rfs4_deleg_state_destroy(rfs4_entry_t u_entry)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;

	/* return delegation if necessary */
	rfs4_return_deleg(dsp, FALSE);

	/* Were done with the file */
	rfs4_file_rele(dsp->rds_finfo);
	dsp->rds_finfo = NULL;

	/* And now with the openowner */
	rfs4_client_rele(dsp->rds_client);
	dsp->rds_client = NULL;
}

rfs4_deleg_state_t *
rfs4_finddeleg(struct compound_state *cs,
	rfs4_state_t *sp, bool_t *create)
{
	rfs4_deleg_state_t ds, *dsp;

	ds.rds_client = sp->rs_owner->ro_client;
	ds.rds_finfo = sp->rs_finfo;

	dsp = (rfs4_deleg_state_t *)rfs4_dbsearch(cs->instp->deleg_idx, &ds,
	    create, &ds, RFS4_DBS_VALID);

	return (dsp);
}

rfs4_deleg_state_t *
rfs4_finddelegstate(struct compound_state *cs,
		    stateid_t *id)
{
	rfs4_deleg_state_t *dsp;
	bool_t create = FALSE;

	dsp = (rfs4_deleg_state_t *)rfs4_dbsearch(cs->instp->deleg_state_idx,
	    id, &create, NULL, RFS4_DBS_VALID);

	return (dsp);
}

void
rfs4_deleg_state_rele(rfs4_deleg_state_t *dsp)
{
	rfs4_dbe_rele(dsp->rds_dbe);
}

/*
 * XXX NFSv4.0 ONLY !!
 */
void
rfs4_update_lock_sequence(rfs4_lo_state_t *lsp)
{

	rfs4_dbe_lock(lsp->rls_dbe);

	/*
	 * If we are skipping sequence id checking, this means that
	 * this is the first lock request and therefore the sequence
	 * id does not need to be updated.  This only happens on the
	 * first lock request for a lockowner
	 */
	if (!lsp->rls_skip_seqid_check)
		lsp->rls_seqid++;

	rfs4_dbe_unlock(lsp->rls_dbe);
}

/*
 * XXX NFSv4.0 ONLY !!
 */
void
rfs4_update_lock_resp(rfs4_lo_state_t *lsp, nfs_resop4 *resp)
{
	ASSERT(!(dbe_to_instp(lsp->rls_dbe)->inst_flags & NFS_INST_v41));

	rfs4_dbe_lock(lsp->rls_dbe);

	rfs4_free_reply(&lsp->rls_reply);

	rfs4_copy_reply(&lsp->rls_reply, resp);

	rfs4_dbe_unlock(lsp->rls_dbe);
}

void
rfs4_free_opens(rfs4_openowner_t *oo, bool_t invalidate,
    bool_t close_of_client)
{
	rfs4_state_t *sp;

	rfs4_dbe_lock(oo->ro_dbe);

	for (sp = list_head(&oo->ro_statelist); sp != NULL;
	    sp = list_next(&oo->ro_statelist, sp)) {
		rfs4_state_close(sp, FALSE, close_of_client, CRED());
		if (invalidate == TRUE)
			rfs4_dbe_invalidate(sp->rs_dbe);
	}

	rfs4_dbe_invalidate(oo->ro_dbe);
	rfs4_dbe_unlock(oo->ro_dbe);
}

uint32_t
state_owner_file_hash(void *key)
{
	rfs4_state_t *sp = key;

	return (ADDRHASH(sp->rs_owner) ^ ADDRHASH(sp->rs_finfo));
}

bool_t
state_owner_file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_state_t *arg = key;

	if (sp->rs_closed == TRUE)
		return (FALSE);

	return (arg->rs_owner == sp->rs_owner && arg->rs_finfo == sp->rs_finfo);
}

void *
state_owner_file_mkkey(rfs4_entry_t u_entry)
{
	return (u_entry);
}

uint32_t
state_file_hash(void *key)
{
	return (ADDRHASH(key));
}

bool_t
state_file_compare(rfs4_entry_t u_entry, void *key)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_file_t *fp = key;

	if (sp->rs_closed == TRUE)
		return (FALSE);

	return (fp == sp->rs_finfo);
}

void *
state_file_mkkey(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;

	return (sp->rs_finfo);
}

rfs4_state_t *
rfs4_findstate_by_owner_file(struct compound_state *cs,
    rfs4_openowner_t *oo, rfs4_file_t *fp, bool_t *create)
{
	rfs4_state_t *sp;
	rfs4_state_t key;

	key.rs_owner = oo;
	key.rs_finfo = fp;

	sp = (rfs4_state_t *)rfs4_dbsearch(cs->instp->state_owner_file_idx,
	    &key, create, &key, RFS4_DBS_VALID);

	return (sp);
}

/*
 * This returns ANY state struct that refers
 * to this file.
 */
static rfs4_state_t *
findstate_by_file(nfs_server_instance_t *instp, rfs4_file_t *fp)
{
	bool_t create = FALSE;

	return ((rfs4_state_t *)rfs4_dbsearch(instp->state_file_idx, fp,
	    &create, fp, RFS4_DBS_VALID));
}

bool_t
rfs4_state_expiry(rfs4_entry_t u_entry)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	time_t lease;

	if (rfs4_dbe_is_invalid(sp->rs_dbe))
		return (TRUE);

	lease = dbe_to_instp(sp->rs_dbe)->lease_period;

	if (sp->rs_closed == TRUE &&
	    ((gethrestime_sec() - rfs4_dbe_get_timerele(sp->rs_dbe))
	    > lease))
		return (TRUE);

	return ((gethrestime_sec() - sp->rs_owner->ro_client->rc_last_access
	    > lease));
}

bool_t
rfs4_state_create(rfs4_entry_t u_entry, void *argp)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	rfs4_file_t *fp = ((rfs4_state_t *)argp)->rs_finfo;
	rfs4_openowner_t *oo = ((rfs4_state_t *)argp)->rs_owner;

	rfs4_dbe_hold(fp->rf_dbe);
	rfs4_dbe_hold(oo->ro_dbe);
	sp->rs_stateid = get_stateid(dbe_to_instp(sp->rs_dbe),
	    rfs4_dbe_getid(sp->rs_dbe), OPENID);
	sp->rs_owner = oo;
	sp->rs_finfo = fp;

	list_create(&sp->rs_lostatelist, sizeof (rfs4_lo_state_t),
	    offsetof(rfs4_lo_state_t, rls_node));

	/* Insert state on per open owner's list */
	rfs4_dbe_lock(oo->ro_dbe);
	list_insert_tail(&oo->ro_statelist, sp);
	rfs4_dbe_unlock(oo->ro_dbe);

	return (TRUE);
}

rfs4_state_t *
rfs4_findstate(struct compound_state *cs, stateid_t *id,
    rfs4_dbsearch_type_t find_invalid, bool_t lock_fp)
{
	rfs4_state_t *sp;
	bool_t create = FALSE;

	sp = (rfs4_state_t *)rfs4_dbsearch(cs->instp->state_idx, id,
	    &create, NULL, find_invalid);
	if (lock_fp == TRUE && sp != NULL)
		rw_enter(&sp->rs_finfo->rf_file_rwlock, RW_READER);

	return (sp);
}

void
rfs4_state_close(rfs4_state_t *sp, bool_t lock_held, bool_t close_of_client,
    cred_t *cr)
{
	/* Remove the associated lo_state owners */
	if (!lock_held)
		rfs4_dbe_lock(sp->rs_dbe);

	/*
	 * If refcnt == 0, the dbe is about to be destroyed.
	 * lock state will be released by the reaper thread.
	 */

	if (rfs4_dbe_refcnt(sp->rs_dbe) > 0) {
		if (sp->rs_closed == FALSE) {
			rfs4_release_share_lock_state(sp, cr, close_of_client);
			sp->rs_closed = TRUE;
		}
	}

	if (!lock_held)
		rfs4_dbe_unlock(sp->rs_dbe);
}

/*
 * Remove all state associated with the given client.
 */
void
rfs4_client_state_remove(rfs4_client_t *cp)
{
	rfs4_openowner_t *oo;

	rfs4_dbe_lock(cp->rc_dbe);

	for (oo = list_head(&cp->rc_openownerlist); oo != NULL;
	    oo = list_next(&cp->rc_openownerlist, oo)) {
		rfs4_free_opens(oo, TRUE, TRUE);
	}

	rfs4_dbe_unlock(cp->rc_dbe);
}

void
rfs4_client_close(rfs4_client_t *cp)
{
	/* Mark client as going away. */
	rfs4_dbe_lock(cp->rc_dbe);
	rfs4_dbe_invalidate(cp->rc_dbe);
	rfs4_dbe_unlock(cp->rc_dbe);

	rfs4_free_cred_princ(cp);
	rfs4_client_state_remove(cp);

	/* Release the client */
	rfs4_client_rele(cp);
}

nfsstat4
get_clientid_err(nfs_server_instance_t *instp,
		clientid4 *cp, int setclid_confirm)
{
	cid *cidp = (cid *) cp;

	/*
	 * If we are booted as a cluster node, check the embedded nodeid.
	 * If it indicates that this clientid was generated on another node,
	 * inform the client accordingly.
	 */
	if (cluster_bootflags & CLUSTER_BOOTED && foreign_clientid(cidp))
		return (NFS4ERR_STALE_CLIENTID);

	/*
	 * If the server start time matches the time provided
	 * by the client (via the clientid) and this is NOT a
	 * setclientid_confirm then return EXPIRED.
	 */
	if (!setclid_confirm && cidp->impl_id.start_time == instp->start_time)
		return (NFS4ERR_EXPIRED);

	return (NFS4ERR_STALE_CLIENTID);
}


nfsstat4
rfs4_check_clientid(nfs_server_instance_t *instp, clientid4 *cp)
{
	cid *cidp = (cid *) cp;

	/*
	 * If we are booted as a cluster node, check the embedded nodeid.
	 * If it indicates that this clientid was generated on another node,
	 * inform the client accordingly.
	 */
	if (cluster_bootflags & CLUSTER_BOOTED && foreign_clientid(cidp))
		return (NFS4ERR_STALE_CLIENTID);

	/*
	 * If the server start time matches the time provided
	 * by the client (via the clientid) and this is NOT a
	 * setclientid_confirm then return EXPIRED.
	 */
	if (cidp->impl_id.start_time == instp->start_time)
		return (NFS4ERR_EXPIRED);

	return (NFS4ERR_STALE_CLIENTID);
}


/*
 * This is used when a stateid has not been found amongst the
 * current server's state.  Check the stateid to see if it
 * was from this server instantiation or not.
 */
static nfsstat4
what_stateid_error(struct compound_state *cs,
		stateid_t *id, stateid_type_t type)
{
	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	/* If types don't match then no use checking further */
	if (type != id->v4_bits.type)
		return (NFS4ERR_BAD_STATEID);

	/* From a previous server instantiation, return STALE */
	if (id->v4_bits.boottime < cs->instp->start_time)
		return (NFS4ERR_STALE_STATEID);

	/*
	 * From this server but the state is most likely beyond lease
	 * timeout: return NFS4ERR_EXPIRED.  However, there is the
	 * case of a delegation stateid.  For delegations, there is a
	 * case where the state can be removed without the client's
	 * knowledge/consent: revocation.  In the case of delegation
	 * revocation, the delegation state will be removed and will
	 * not be found.  If the client does something like a
	 * DELEGRETURN or even a READ/WRITE with a delegatoin stateid
	 * that has been revoked, the server should return BAD_STATEID
	 * instead of the more common EXPIRED error.
	 */
	if (id->v4_bits.boottime == cs->instp->start_time) {
		if (type == DELEGID)
			return (NFS4ERR_BAD_STATEID);
		else
			return (NFS4ERR_EXPIRED);
	}

	return (NFS4ERR_BAD_STATEID);
}

/*
 * Used later on to find the various state structs.  When called from
 * check_stateid()->rfs4_get_all_state(), no file struct lock is
 * taken (it is not needed) and helps on the read/write path with
 * respect to performance.
 */
static nfsstat4
rfs4_get_state_lockit(struct compound_state *cs, stateid4 *stateid,
    rfs4_state_t **spp, rfs4_dbsearch_type_t find_invalid, bool_t lock_fp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_state_t *sp;

	*spp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	sp = rfs4_findstate(cs, id, find_invalid, lock_fp);
	if (sp == NULL) {
		return (what_stateid_error(cs, id, OPENID));
	}

	if (rfs4_lease_expired(sp->rs_owner->ro_client)) {
		if (lock_fp == TRUE)
			rfs4_state_rele(sp);
		else
			rfs4_state_rele_nounlock(sp);
		return (NFS4ERR_EXPIRED);
	}

	*spp = sp;

	return (NFS4_OK);
}

nfsstat4
rfs4_get_state(struct compound_state *cs, stateid4 *stateid,
    rfs4_state_t **spp, rfs4_dbsearch_type_t find_invalid)
{
	return (rfs4_get_state_lockit(cs, stateid, spp, find_invalid, TRUE));
}

int
rfs4_check_stateid_seqid(rfs4_state_t *sp, stateid4 *stateid)
{
	stateid_t *id = (stateid_t *)stateid;

	if (rfs4_lease_expired(sp->rs_owner->ro_client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (sp->rs_stateid.v4_bits.chgseq < id->v4_bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (sp->rs_stateid.v4_bits.chgseq == id->v4_bits.chgseq + 1)
		return (NFS4_CHECK_STATEID_REPLAY);

	/* Stateid is some time in the past - that's old */
	if (sp->rs_stateid.v4_bits.chgseq > id->v4_bits.chgseq)
		return (NFS4_CHECK_STATEID_OLD);

	/* Caller needs to know about confirmation before closure */
	if (sp->rs_owner->ro_need_confirm)
		return (NFS4_CHECK_STATEID_UNCONFIRMED);

	if (sp->rs_closed == TRUE)
		return (NFS4_CHECK_STATEID_CLOSED);

	return (NFS4_CHECK_STATEID_OKAY);
}

int
rfs4_check_lo_stateid_seqid(rfs4_lo_state_t *lsp, stateid4 *stateid)
{
	stateid_t *id = (stateid_t *)stateid;

	if (rfs4_lease_expired(lsp->rls_state->rs_owner->ro_client))
		return (NFS4_CHECK_STATEID_EXPIRED);

	/* Stateid is some time in the future - that's bad */
	if (lsp->rls_lockid.v4_bits.chgseq < id->v4_bits.chgseq)
		return (NFS4_CHECK_STATEID_BAD);

	if (lsp->rls_lockid.v4_bits.chgseq == id->v4_bits.chgseq + 1)
		return (NFS4_CHECK_STATEID_REPLAY);

	/* Stateid is some time in the past - that's old */
	if (lsp->rls_lockid.v4_bits.chgseq > id->v4_bits.chgseq)
		return (NFS4_CHECK_STATEID_OLD);

	if (lsp->rls_state->rs_closed == TRUE)
		return (NFS4_CHECK_STATEID_CLOSED);

	return (NFS4_CHECK_STATEID_OKAY);
}

nfsstat4
rfs4_get_deleg_state(struct compound_state *cs,
		stateid4 *stateid, rfs4_deleg_state_t **dspp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_deleg_state_t *dsp;

	*dspp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	dsp = rfs4_finddelegstate(cs, id);
	if (dsp == NULL) {
		return (what_stateid_error(cs, id, DELEGID));
	}

	if (rfs4_lease_expired(dsp->rds_client)) {
		rfs4_deleg_state_rele(dsp);
		return (NFS4ERR_EXPIRED);
	}

	*dspp = dsp;

	return (NFS4_OK);
}

nfsstat4
rfs4_get_lo_state(struct compound_state *cs,
		stateid4 *stateid, rfs4_lo_state_t **lspp, bool_t lock_fp)
{
	stateid_t *id = (stateid_t *)stateid;
	rfs4_lo_state_t *lsp;

	*lspp = NULL;

	/* If we are booted as a cluster node, was stateid locally generated? */
	if ((cluster_bootflags & CLUSTER_BOOTED) && foreign_stateid(id))
		return (NFS4ERR_STALE_STATEID);

	lsp = rfs4_findlo_state(cs, id, lock_fp);
	if (lsp == NULL) {
		return (what_stateid_error(cs, id, LOCKID));
	}

	if (rfs4_lease_expired(lsp->rls_state->rs_owner->ro_client)) {
		rfs4_lo_state_rele(lsp, lock_fp);
		return (NFS4ERR_EXPIRED);
	}

	*lspp = lsp;

	return (NFS4_OK);
}

/* v4.0 only */
nfsstat4
rfs4_get_all_state(struct compound_state *cs, stateid4 *sid,
    rfs4_state_t **spp, rfs4_deleg_state_t **dspp,
    rfs4_lo_state_t **lospp)
{
	rfs4_state_t *sp = NULL;
	rfs4_deleg_state_t *dsp = NULL;
	rfs4_lo_state_t *lsp = NULL;
	stateid_t *id;
	nfsstat4 status;

	*spp = NULL; *dspp = NULL; *lospp = NULL;

	id = (stateid_t *)sid;
	switch (id->v4_bits.type) {
	case OPENID:
		status = rfs4_get_state_lockit(cs, sid,
		    &sp, RFS4_DBS_VALID, FALSE);
		break;
	case DELEGID:
		status = rfs4_get_deleg_state(cs, sid, &dsp);
		break;
	case LOCKID:
		/*
		 * NB: If this was a lock stateid we return to the caller
		 * the lock state via lospp and the associated open stateid
		 * that established the lock state in spp.
		 */
		status = rfs4_get_lo_state(cs, sid, &lsp, FALSE);
		if (status == NFS4_OK) {
			sp = lsp->rls_state;
			rfs4_dbe_hold(sp->rs_dbe);
		}
		break;
	default:
		status = NFS4ERR_BAD_STATEID;
	}

	if (status == NFS4_OK) {
		*spp = sp;
		*dspp = dsp;
		*lospp = lsp;
	}

	return (status);
}

/* ARGSUSED */
nfsstat4
mds_validate_logstateid(struct compound_state *cs, stateid_t *sid)
{
	nfsstat4 status;
	stateid4 *id = (stateid4 *)sid;
	rfs4_deleg_state_t *dsp;
	rfs4_state_t *sp;
	rfs4_lo_state_t *lsp;

	switch (sid->v4_bits.type) {
	case DELEGID:
		status = rfs4_get_deleg_state(cs, id, &dsp);
		if (status != NFS4_OK)
			break;

		/* Is associated server instance in its grace period? */
		if (rfs4_clnt_in_grace(dsp->rds_client)) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_GRACE);
		}
		if (dsp->rds_delegid.v4_bits.chgseq != sid->v4_bits.chgseq) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_BAD_STATEID);
		}
		/* Ensure specified filehandle matches */
		if (dsp->rds_finfo->rf_vp != cs->vp) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_BAD_STATEID);
		}

		rfs4_deleg_state_rele(dsp);
		break;
	case OPENID:
		status = rfs4_get_state_lockit(cs, id,
		    &sp, RFS4_DBS_VALID, FALSE);
		if (status != NFS4_OK)
			return (status);

		/* Is associated server instance in its grace period? */
		if (rfs4_clnt_in_grace(sp->rs_owner->ro_client)) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_GRACE);
		}
		/* Seqid in the future? - that's bad */
		if (sp->rs_stateid.v4_bits.chgseq < sid->v4_bits.chgseq) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}
		/* Seqid in the past - that's old */
		if (sp->rs_stateid.v4_bits.chgseq > sid->v4_bits.chgseq) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_OLD_STATEID);
		}
		/* Ensure specified filehandle matches */
		if (sp->rs_finfo->rf_vp != cs->vp) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}
		if (sp->rs_owner->ro_need_confirm) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}
		if (sp->rs_closed == TRUE) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_OLD_STATEID);
		}

		rfs4_state_rele_nounlock(sp);
		break;
	case LOCKID:
		status = rfs4_get_lo_state(cs, id, &lsp, FALSE);
		if (status != NFS4_OK)
			return (status);

		/* Is associated server instance in its grace period? */
		if (rfs4_clnt_in_grace(lsp->rls_locker->rl_client)) {
			rfs4_lo_state_rele(lsp, FALSE);
			return (NFS4ERR_GRACE);
		}
		/* Seqid in the future? - that's bad */
		if (lsp->rls_lockid.v4_bits.chgseq < sid->v4_bits.chgseq) {
			rfs4_lo_state_rele(lsp, FALSE);
			return (NFS4ERR_BAD_STATEID);
		}
		/* Seqid in the past? - that's old */
		if (lsp->rls_lockid.v4_bits.chgseq > sid->v4_bits.chgseq) {
			rfs4_lo_state_rele(lsp, FALSE);
			return (NFS4ERR_OLD_STATEID);
		}
		/* Ensure specified filehandle matches */
		if (lsp->rls_state->rs_finfo->rf_vp != cs->vp) {
			rfs4_lo_state_rele(lsp, FALSE);
			return (NFS4ERR_BAD_STATEID);
		}
		rfs4_lo_state_rele(lsp, FALSE);
		break;
	default:
		status = NFS4ERR_BAD_STATEID;
	}

	return (status);
}

/*
 * Given the I/O mode (FREAD or FWRITE), this checks whether the
 * rfs4_state_t struct has access to do this operation and if so
 * return NFS4_OK; otherwise the proper NFSv4 error is returned.
 */
nfsstat4
rfs4_state_has_access(rfs4_state_t *sp, int mode, vnode_t *vp)
{
	nfsstat4 stat = NFS4_OK;
	rfs4_file_t *fp;
	bool_t create = FALSE;

	rfs4_dbe_lock(sp->rs_dbe);
	if (mode == FWRITE) {
		if (!(sp->rs_share_access & OPEN4_SHARE_ACCESS_WRITE)) {
			stat = NFS4ERR_OPENMODE;
		}
	} else if (mode == FREAD) {
		if (!(sp->rs_share_access & OPEN4_SHARE_ACCESS_READ)) {
			/*
			 * If we have OPENed the file with DENYing access
			 * to both READ and WRITE then no one else could
			 * have OPENed the file, hence no conflicting READ
			 * deny.  This check is merely an optimization.
			 */
			if (sp->rs_share_deny == OPEN4_SHARE_DENY_BOTH)
				goto out;

			/* Check against file struct's DENY mode */
			fp = rfs4_findfile(dbe_to_instp(sp->rs_dbe),
			    vp, NULL, &create);
			if (fp != NULL) {
				int deny_read = 0;
				rfs4_dbe_lock(fp->rf_dbe);
				/*
				 * Check if any other open owner has the file
				 * OPENed with deny READ.
				 */
				if (sp->rs_share_deny & OPEN4_SHARE_DENY_READ)
					deny_read = 1;
				ASSERT(fp->rf_deny_read - deny_read >= 0);
				if (fp->rf_deny_read - deny_read > 0)
					stat = NFS4ERR_OPENMODE;
				rfs4_dbe_unlock(fp->rf_dbe);
				rfs4_file_rele(fp);
			}
		}
	} else {
		/* Illegal I/O mode */
		stat = NFS4ERR_INVAL;
	}
out:
	rfs4_dbe_unlock(sp->rs_dbe);
	return (stat);
}

/*
 * Given the I/O mode (FREAD or FWRITE), the vnode, the stateid and whether
 * the file is being truncated, return NFS4_OK if allowed or appropriate
 * V4 error if not. Note NFS4ERR_DELAY will be returned and a recall on
 * the associated file will be done if the I/O is not consistent with any
 * delegation in effect on the file. Should be holding VOP_RWLOCK, either
 * as reader or writer as appropriate. rfs4_op_open will acquire the
 * VOP_RWLOCK as writer when setting up delegation. If the stateid is bad
 * this routine will return NFS4ERR_BAD_STATEID. In addition, through the
 * deleg parameter, we will return whether a write delegation is held by
 * the client associated with this stateid.
 * If the server instance associated with the relevant client is in its
 * grace period, return NFS4ERR_GRACE.
 */

nfsstat4
check_stateid(int mode, struct compound_state *cs, vnode_t *vp,
    stateid4 *stateid, bool_t trunc, bool_t *deleg, bool_t do_access,
    caller_context_t *ct, clientid4 *cid)
{
	rfs4_file_t *fp;
	bool_t create = FALSE;
	rfs4_state_t *sp;
	rfs4_deleg_state_t *dsp;
	rfs4_lo_state_t *lsp;
	stateid_t *id = (stateid_t *)stateid;
	nfsstat4 stat = NFS4_OK;

	if (ct != NULL) {
		ct->cc_sysid = 0;
		ct->cc_pid = 0;
		ct->cc_caller_id = cs->instp->caller_id;
		ct->cc_flags = CC_DONTBLOCK;
	}

	if (ISSPECIAL(stateid)) {
		fp = rfs4_findfile(cs->instp, vp, NULL, &create);
		if (fp == NULL)
			return (NFS4_OK);
		if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_NONE) {
			rfs4_file_rele(fp);
			return (NFS4_OK);
		}
		if (mode == FWRITE ||
		    fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_WRITE) {
			rfs4_recall_deleg(fp, trunc, NULL);
			rfs4_file_rele(fp);
			return (NFS4ERR_DELAY);
		}
		rfs4_file_rele(fp);
		return (NFS4_OK);
	}

	stat = rfs4_get_all_state(cs, stateid, &sp, &dsp, &lsp);
	if (stat != NFS4_OK)
		return (stat);

	/*
	 * Ordering of the following 'if' statements is specific
	 * since rfs4_get_all_state() may return a value for sp and
	 * lsp. First we check lsp, then 'fall' through to sp.
	 */
	if (lsp != NULL) {
		if (cid) {
			*cid = lsp->rls_locker->rl_client->rc_clientid;
		}
		/* Is associated server instance in its grace period? */
		if (rfs4_clnt_in_grace(lsp->rls_locker->rl_client)) {
			if (ct != NULL) {
				ct->cc_sysid =
				    lsp->rls_locker->rl_client->rc_sysidt;
				ct->cc_pid = lsp->rls_locker->rl_pid;
			}
			rfs4_lo_state_rele(lsp, FALSE);
			if (sp != NULL)
				rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_GRACE);
		}
		/* Seqid in the future? - that's bad */
		if (lsp->rls_lockid.v4_bits.chgseq <
		    id->v4_bits.chgseq) {
			rfs4_lo_state_rele(lsp, FALSE);
			if (sp != NULL)
				rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}
		/* Seqid in the past? - that's old */
		if (lsp->rls_lockid.v4_bits.chgseq >
		    id->v4_bits.chgseq) {
			rfs4_lo_state_rele(lsp, FALSE);
			if (sp != NULL)
				rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_OLD_STATEID);
		}
		/* Ensure specified filehandle matches */
		if (lsp->rls_state->rs_finfo->rf_vp != vp) {
			rfs4_lo_state_rele(lsp, FALSE);
			if (sp != NULL)
				rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}
		rfs4_lo_state_rele(lsp, FALSE);
	}

	/*
	 * Stateid provided was an "open" or via the lock stateid
	 */
	if (sp != NULL) {
		/*
		 * only check if the passed in stateid was an OPENID,
		 * ie. Skip if we got here via the LOCKID.
		 */
		if (id->v4_bits.type == OPENID) {
			if (cid) {
				rfs4_dbe_lock(sp->rs_owner->ro_client->rc_dbe);
				*cid = sp->rs_owner->ro_client->rc_clientid;
				rfs4_dbe_unlock(sp->rs_owner->
				    ro_client->rc_dbe);
			}
			/* Is associated server instance in its grace period? */
			if (rfs4_clnt_in_grace(sp->rs_owner->ro_client)) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_GRACE);
			}
			/* Seqid in the future? - that's bad */
			if (sp->rs_stateid.v4_bits.chgseq <
			    id->v4_bits.chgseq) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_BAD_STATEID);
			}
			/* Seqid in the past - that's old */
			if (sp->rs_stateid.v4_bits.chgseq >
			    id->v4_bits.chgseq) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_OLD_STATEID);
			}
			/* Ensure specified filehandle matches */
			if (sp->rs_finfo->rf_vp != vp) {
				rfs4_state_rele_nounlock(sp);
				return (NFS4ERR_BAD_STATEID);
			}
		}
		if (sp->rs_owner->ro_need_confirm) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_BAD_STATEID);
		}

		if (sp->rs_closed == TRUE) {
			rfs4_state_rele_nounlock(sp);
			return (NFS4ERR_OLD_STATEID);
		}

		if (do_access)
			stat = rfs4_state_has_access(sp, mode, vp);
		else
			stat = NFS4_OK;

		/*
		 * Return whether this state has write
		 * delegation if desired
		 */
		if (deleg &&
		    (sp->rs_finfo->rf_dinfo->rd_dtype == OPEN_DELEGATE_WRITE))
			*deleg = TRUE;

		/*
		 * We got a valid stateid, so we update the
		 * lease on the client. Ideally we would like
		 * to do this after the calling op succeeds,
		 * but for now this will be good
		 * enough. Callers of this routine are
		 * currently insulated from the state stuff.
		 */
		rfs4_update_lease(sp->rs_owner->ro_client);

		/*
		 * If a delegation is present on this file and
		 * this is a WRITE, then update the lastwrite
		 * time to indicate that activity is present.
		 */
		if (sp->rs_finfo->rf_dinfo->rd_dtype ==
		    OPEN_DELEGATE_WRITE && mode == FWRITE) {
			sp->rs_finfo->rf_dinfo->rd_time_lastwrite =
			    gethrestime_sec();
		}

		rfs4_state_rele_nounlock(sp);
		return (stat);
	}

	if (dsp != NULL) {
		if (cid) {
			rfs4_dbe_lock(dsp->rds_client->rc_dbe);
			*cid = dsp->rds_client->rc_clientid;
			rfs4_dbe_unlock(dsp->rds_client->rc_dbe);
		}
		/* Is associated server instance in its grace period? */
		if (rfs4_clnt_in_grace(dsp->rds_client)) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_GRACE);
		}
		if (dsp->rds_delegid.v4_bits.chgseq != id->v4_bits.chgseq) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_BAD_STATEID);
		}

		/* Ensure specified filehandle matches */
		if (dsp->rds_finfo->rf_vp != vp) {
			rfs4_deleg_state_rele(dsp);
			return (NFS4ERR_BAD_STATEID);
		}
		/*
		 * Return whether this state has write
		 * delegation if desired
		 */
		if (deleg && (dsp->rds_finfo->rf_dinfo->rd_dtype ==
		    OPEN_DELEGATE_WRITE))
			*deleg = TRUE;

		rfs4_update_lease(dsp->rds_client);

		/*
		 * If a delegation is present on this file and
		 * this is a WRITE, then update the lastwrite
		 * time to indicate that activity is present.
		 */
		if (dsp->rds_finfo->rf_dinfo->rd_dtype ==
		    OPEN_DELEGATE_WRITE && mode == FWRITE) {
			dsp->rds_finfo->rf_dinfo->rd_time_lastwrite =
			    gethrestime_sec();
		}

		/*
		 * XXX - what happens if this is a WRITE and the
		 * delegation type of for READ.
		 */
		rfs4_deleg_state_rele(dsp);

		return (stat);
	}
	/*
	 * If we got this far, something bad happened
	 */
	return (NFS4ERR_BAD_STATEID);
}


/*
 * This is a special function in that for the file struct provided the
 * server wants to remove/close all current state associated with the
 * file.  The prime use of this would be with OP_REMOVE to force the
 * release of state and particularly of file locks.
 *
 * There is an assumption that there is no delegations outstanding on
 * this file at this point.  The caller should have waited for those
 * to be returned or revoked.
 */
void
rfs4_close_all_state(rfs4_file_t *fp)
{
	nfs_server_instance_t *instp;
	rfs4_state_t *sp;

	rfs4_dbe_lock(fp->rf_dbe);

	/* No delegations for this file */
	ASSERT(list_is_empty(&fp->rf_delegstatelist));

	/* Make sure that it can not be found */
	rfs4_dbe_invalidate(fp->rf_dbe);

	if (fp->rf_vp == NULL) {
		rfs4_dbe_unlock(fp->rf_dbe);
		return;
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	instp = dbe_to_instp(fp->rf_dbe);

	/*
	 * Hold as writer to prevent other server threads from
	 * processing requests related to the file while all state is
	 * being removed.
	 */
	rw_enter(&fp->rf_file_rwlock, RW_WRITER);

	/* Remove ALL state from the file */
	while (sp = findstate_by_file(instp, fp)) {
		rfs4_state_close(sp, FALSE, FALSE, CRED());
		rfs4_state_rele_nounlock(sp);
	}

	/*
	 * This is only safe since there are no further references to
	 * the file.
	 */
	rfs4_dbe_lock(fp->rf_dbe);
	if (fp->rf_vp) {
		vnode_t *vp = fp->rf_vp;
		nfs_server_instance_t *instp; /* XXX: shadows above */

		instp = dbe_to_instp(fp->rf_dbe);
		mutex_enter(&vp->v_vsd_lock);
		(void) vsd_set(vp, instp->vkey, NULL);
		mutex_exit(&vp->v_vsd_lock);
		VN_RELE(vp);
		fp->rf_vp = NULL;
	}
	rfs4_dbe_unlock(fp->rf_dbe);

	/* Finally let other references to proceed */
	rw_exit(&fp->rf_file_rwlock);
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
static void
rfs4_lo_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_lo_state_t *lsp = (rfs4_lo_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp = (nfs_fh4_fmt_t *)lsp->rls_state->rs_finfo->
	    rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
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
static void
rfs4_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_state_t *sp = (rfs4_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp =
	    (nfs_fh4_fmt_t *)sp->rs_finfo->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
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
static void
rfs4_deleg_state_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_deleg_state_t *dsp = (rfs4_deleg_state_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp =
	    (nfs_fh4_fmt_t *)dsp->rds_finfo->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
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
static void
rfs4_file_walk_callout(rfs4_entry_t u_entry, void *e)
{
	rfs4_file_t *fp = (rfs4_file_t *)u_entry;
	struct exportinfo *exi = (struct exportinfo *)e;
	nfs_fh4_fmt_t   fhfmt4, *exi_fhp, *finfo_fhp;
	fhandle_t *efhp;
	nfs_server_instance_t *instp;

	efhp = (fhandle_t *)&exi->exi_fh;
	exi_fhp = (nfs_fh4_fmt_t *)&fhfmt4;

	FH_TO_FMT4(efhp, exi_fhp);

	finfo_fhp = (nfs_fh4_fmt_t *)fp->rf_filehandle.nfs_fh4_val;

	if (EQFSID(&finfo_fhp->fh4_fsid, &exi_fhp->fh4_fsid) &&
	    bcmp(&finfo_fhp->fh4_xdata, &exi_fhp->fh4_xdata,
	    exi_fhp->fh4_xlen) == 0) {
		if (fp->rf_vp) {
			vnode_t *vp = fp->rf_vp;

			instp = dbe_to_instp(fp->rf_dbe);
			ASSERT(instp);
			/* don't leak monitors */
			if (fp->rf_dinfo->rd_dtype == OPEN_DELEGATE_READ) {
				(void) fem_uninstall(vp, instp->deleg_rdops,
				    (void *)fp);
				vn_open_downgrade(vp, FREAD);
			} else if (fp->rf_dinfo->rd_dtype ==
			    OPEN_DELEGATE_WRITE) {
				(void) fem_uninstall(vp, instp->deleg_wrops,
				    (void *)fp);
				vn_open_downgrade(vp, FREAD|FWRITE);
			}
			mutex_enter(&vp->v_vsd_lock);
			(void) vsd_set(vp, instp->vkey, NULL);
			mutex_exit(&vp->v_vsd_lock);
			VN_RELE(vp);
			fp->rf_vp = NULL;
		}
		rfs4_dbe_invalidate(fp->rf_dbe);
	}
}

/*
 * v4 state cleaner
 */
void
rfs4_clean_state_exi(nfs_server_instance_t *instp, struct exportinfo *exi)
{
	rfs4_dbe_walk(instp->lo_state_tab, rfs4_lo_state_walk_callout, exi);
	rfs4_dbe_walk(instp->state_tab, rfs4_state_walk_callout, exi);
	rfs4_dbe_walk(instp->deleg_state_tab, rfs4_deleg_state_walk_callout,
	    exi);
	rfs4_dbe_walk(instp->file_tab, rfs4_file_walk_callout, exi);
}

/*
 * Given a directory that is being unexported, cleanup/release
 * state for all stateStore occurrences with refering objects.
 */
void
sstor_clean_state_exi(struct exportinfo *exi)
{
	nfs_server_instance_t *nsip = list_head(&nsi_head);

	while (nsip) {
		mutex_enter(&nsip->state_lock);
		if (nsip->inst_flags & NFS_INST_STORE_INIT) {
			if (nsip->exi_clean_func != NULL)
				(*nsip->exi_clean_func)(nsip, exi);
		}
		mutex_exit(&nsip->state_lock);

		nsip = list_next(&nsi_head, &nsip->nsi_list);
	}
}

/*
 * v4 protocol Table Initialzation (common between 4.0 and 4.1)
 */
void
v4prot_sstor_init(nfs_server_instance_t *instp)
{
	timespec32_t verf;
	int error;

	/*
	 * Init the grace timers and reclaim list.
	 */
	instp->gstart_time = (time_t)0;
	instp->grace_period = (time_t)0;
	instp->lease_period = rfs4_lease_time;

	rw_init(&instp->reclaimlst_lock, NULL, RW_DEFAULT, NULL);

	list_create(&instp->reclaim_head, sizeof (rfs4_reclaim_t),
	    offsetof(rfs4_reclaim_t, reclaim_list));

	/*
	 * set the various cache timers for table creation
	 */
	SSTOR_CT_INIT(instp, client_cache_time, CLIENT_CACHE_TIME);
	SSTOR_CT_INIT(instp, openowner_cache_time, OPENOWNER_CACHE_TIME);
	SSTOR_CT_INIT(instp, state_cache_time, STATE_CACHE_TIME);
	SSTOR_CT_INIT(instp, lo_state_cache_time, LO_STATE_CACHE_TIME);
	SSTOR_CT_INIT(instp, lockowner_cache_time, LOCKOWNER_CACHE_TIME);
	SSTOR_CT_INIT(instp, file_cache_time, FILE_CACHE_TIME);
	SSTOR_CT_INIT(instp, deleg_state_cache_time, DELEG_STATE_CACHE_TIME);

	/*
	 * Get the door handle for stable storage upcalls.
	 */
	instp->dh = door_ki_lookup(nfs_doorfd);
	door_ki_hold(instp->dh);

	/*
	 * Init the stable storage.
	 */
	rfs4_ss_retrieve_state(instp);

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
	 * File table.
	 */
	instp->file_tab = rfs4_table_create(instp,
	    "File", instp->file_cache_time, 1, rfs4_file_create,
	    rfs4_file_destroy, NULL, sizeof (rfs4_file_t),
	    TABSIZE, MAXTABSZ, -1);

	instp->file_idx = rfs4_index_create(instp->file_tab,
	    "Filehandle", file_hash, file_compare, file_mkkey, TRUE);

	/*
	 * Open Owner table.
	 */
	instp->openowner_tab = rfs4_table_create(
	    instp, "OpenOwner", instp->openowner_cache_time, 1,
	    openowner_create, openowner_destroy, rfs4_openowner_expiry,
	    sizeof (rfs4_openowner_t), TABSIZE, MAXTABSZ, 100);

	instp->openowner_idx = rfs4_index_create(instp->openowner_tab,
	    "open_owner4", openowner_hash, openowner_compare, openowner_mkkey,
	    TRUE);

	/*
	 * State table.
	 */
	instp->state_tab = rfs4_table_create(
	    instp, "OpenStateID", instp->state_cache_time, 3,
	    rfs4_state_create, rfs4_state_destroy, rfs4_state_expiry,
	    sizeof (rfs4_state_t), TABSIZE, MAXTABSZ, 100);

	instp->state_owner_file_idx = rfs4_index_create(instp->state_tab,
	    "Openowner-File", state_owner_file_hash, state_owner_file_compare,
	    state_owner_file_mkkey, TRUE);

	instp->state_idx = rfs4_index_create(instp->state_tab,
	    "State-id", state_hash, state_compare, state_mkkey, FALSE);

	instp->state_file_idx = rfs4_index_create(instp->state_tab, "File",
	    state_file_hash, state_file_compare, state_file_mkkey, FALSE);

	/*
	 * Lock Owner tables.
	 */
	instp->lo_state_tab = rfs4_table_create(
	    instp, "LockStateID", instp->lo_state_cache_time, 2,
	    rfs4_lo_state_create, rfs4_lo_state_destroy, rfs4_lo_state_expiry,
	    sizeof (rfs4_lo_state_t), TABSIZE, MAXTABSZ, 100);

	instp->lo_state_owner_idx = rfs4_index_create(instp->lo_state_tab,
	    "lockowner_state", lo_state_lo_hash, lo_state_lo_compare,
	    lo_state_lo_mkkey, TRUE);

	instp->lo_state_idx = rfs4_index_create(instp->lo_state_tab,
	    "State-id", lo_state_hash, lo_state_compare, lo_state_mkkey,
	    FALSE);

	instp->lockowner_tab = rfs4_table_create(
	    instp, "Lockowner", instp->lockowner_cache_time, 2,
	    rfs4_lockowner_create, rfs4_lockowner_destroy,
	    rfs4_lockowner_expiry, sizeof (rfs4_lockowner_t), TABSIZE,
	    MAXTABSZ, 100);

	instp->lockowner_idx = rfs4_index_create(instp->lockowner_tab,
	    "lock_owner4", lockowner_hash, lockowner_compare,
	    lockowner_mkkey, TRUE);

	instp->lockowner_pid_idx = rfs4_index_create(instp->lockowner_tab,
	    "pid", pid_hash, pid_compare, pid_mkkey, FALSE);

	/*
	 * Delegation state table
	 */
	instp->deleg_state_tab = rfs4_table_create(
	    instp, "DelegStateID", instp->deleg_state_cache_time, 2,
	    rfs4_deleg_state_create, rfs4_deleg_state_destroy,
	    rfs4_deleg_state_expiry, sizeof (rfs4_deleg_state_t),
	    TABSIZE, MAXTABSZ, 100);

	instp->deleg_idx = rfs4_index_create(instp->deleg_state_tab,
	    "DelegByFileClient", deleg_hash, deleg_compare, deleg_mkkey,
	    TRUE);

	instp->deleg_state_idx = rfs4_index_create(instp->deleg_state_tab,
	    "DelegState", deleg_state_hash, deleg_state_compare,
	    deleg_state_mkkey, FALSE);

	mutex_init(&instp->deleg_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Used to manage access to rfs4_deleg_policy */
	rw_init(&instp->deleg_policy_lock, NULL, RW_DEFAULT, NULL);

	instp->vkey = 0;
	vsd_create(&instp->vkey, NULL);

	instp->lockt_sysid = lm_alloc_sysidt();
	instp->caller_id = fs_new_caller_id();

	/*
	 * The following algorithm attempts to find a unique verifier
	 * to be used as the write verifier returned from the server
	 * to the client.  It is important that this verifier change
	 * whenever the server reboots.  Of secondary importance, it
	 * is important for the verifier to be unique between two
	 * different servers.
	 *
	 * Thus, an attempt is made to use the system hostid and the
	 * current time in seconds when the nfssrv kernel module is
	 * loaded.  It is assumed that an NFS server will not be able
	 * to boot and then to reboot in less than a second.  If the
	 * hostid has not been set, then the current high resolution
	 * time is used.  This will ensure different verifiers each
	 * time the server reboots and minimize the chances that two
	 * different servers will have the same verifier.
	 * XXX - this is broken on LP64 kernels.
	 */
	verf.tv_sec = (time_t)nfs_atoi(hw_serial);
	if (verf.tv_sec != 0) {
		verf.tv_nsec = gethrestime_sec();
	} else {
		timespec_t tverf;

		gethrestime(&tverf);
		verf.tv_sec = (time_t)tverf.tv_sec;
		verf.tv_nsec = tverf.tv_nsec;
	}

	instp->Write4verf = *(uint64_t *)&verf;

	error = fem_create("deleg_rdops", nfs4_rd_deleg_tmpl,
	    &instp->deleg_rdops);

	if (error == 0) {
		error = fem_create("deleg_wrops", nfs4_wr_deleg_tmpl,
		    &instp->deleg_wrops);
		if (error)
			fem_free(instp->deleg_rdops);
	}

	if (error)
		rfs4_disable_delegation(instp);
}

/*
 * Used to initialize NFSv4.0 server's state.  All of the tables are
 * created and timers are set. Only called when an occurrence
 * of NFSv4.0 is needed.
 */
void
rfs4_sstor_init(nfs_server_instance_t *instp)
{
	extern boolean_t rfs4_cpr_callb(void *, int);
	extern void rfs4_do_cb_recall(rfs4_deleg_state_t *, bool_t);
	extern rfs4_cbstate_t rfs4_cbcheck(rfs4_state_t *);

	int  need_sstor_init;

	/*
	 * Create the state store and set the
	 * start-up time.
	 */
	need_sstor_init = sstor_init(instp, 60);

	if (need_sstor_init == 0)
		return;

	instp->deleg_cbrecall = rfs4_do_cb_recall;
	instp->deleg_cbcheck =  rfs4_cbcheck;

	/*
	 * Add a CPR callback so that we can update client
	 * access times to extend the lease after a suspend
	 * and resume (we use same class as rpcmod/connmgr)
	 */
	instp->cpr_id = callb_add(rfs4_cpr_callb, instp, CB_CL_CPR_RPC,
	    instp->inst_name);

	/*
	 * Make the NFSv4.0 protocol tables and indexes.
	 */
	v4prot_sstor_init(instp);

	instp->attrvers = 0;

	/*
	 * Mark it as fully initialized
	 */
	instp->inst_flags |= NFS_INST_STORE_INIT | NFS_INST_v40;

	/*
	 * Clear out any old init state.
	 */
	instp->inst_flags &= ~NFS_INST_TERMINUS;

	mutex_exit(&instp->state_lock);
}

/*
 * Used at server occurrence shutdown to cleanup all of the NFSv4.0
 * structures and other state.
 */
void
rfs4_sstor_fini(nfs_server_instance_t *instp)
{
	rfs4_database_t *dbp;

	mutex_enter(&instp->state_lock);

	if (instp->state_store == NULL) {
		mutex_exit(&instp->state_lock);
		return;
	}

	/*
	 * Mark it as being terminated.
	 */
	instp->inst_flags |= NFS_INST_TERMINUS;

	rfs4_set_deleg_policy(instp, SRV_NEVER_DELEGATE);
	dbp = instp->state_store;

	/*
	 * Cleanup the kspe policies.
	 */
	nfs41_spe_fini();

	/*
	 * Cleanup the CPR callback.
	 */
	if (instp->cpr_id)
		(void) callb_delete(instp->cpr_id);

	rw_destroy(&instp->findclient_lock);

	/* First stop all of the reaper threads in the database */
	rfs4_database_shutdown(dbp);

	instp->state_store = NULL;

	/* clean up any dangling stable storage structures */
	rfs4_ss_fini(instp);

	/* Now actually destroy/release the database and its tables */
	rfs4_database_destroy(dbp);

	/* If the mds, then cleanup the id_space for mds_mpd */
	if (instp->mds_mpd_id_space) {
		id_space_destroy(instp->mds_mpd_id_space);
	}

	mutex_exit(&instp->state_lock);

	rw_destroy(&instp->reclaimlst_lock);
	list_destroy(&instp->reclaim_head);

	/* reset the "first NFSv4 request" status */
	instp->seen_first_compound = 0;

	/* DSS: distributed stable storage */
	if (rfs4_dss_oldpaths)
		nvlist_free(rfs4_dss_oldpaths);
	if (rfs4_dss_paths)
		nvlist_free(rfs4_dss_paths);
	rfs4_dss_paths = rfs4_dss_oldpaths = NULL;

	/*
	 * Clear out that it was initialized.
	 */
	instp->inst_flags &= ~(NFS_INST_STORE_INIT|NFS_INST_v40|
	    NFS_INST_v41|NFS_INST_DS);
}
