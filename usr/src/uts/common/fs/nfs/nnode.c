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

#include <nfs/nnode_impl.h>

#include <nfs/nfs41_filehandle.h>

#include <nfs/nfs4.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/crc32.h>
#include <sys/sdt.h>

static int nnode_compare(const void *, const void *);
static nnode_bucket_t *nnode_bucket_alloc(void);
static pid_t nnode_get_my_instance(void);
static void nnode_bucket_free_by_instance(nnode_bucket_t *, pid_t);
static void nnode_free(nnode_t *);

static uint32_t nnode_hash_size = NNODE_HASH_SIZE;
static nnode_bucket_t **nnode_hash;

static kmem_cache_t *nnode_kmem_cache;
static kmem_cache_t *nnode_bucket_cache;
static kmem_cache_t *nfs_mds_nnode_cache;

/*ARGSUSED*/
static int
nnode_construct(void *vnp, void *foo, int bar)
{
	nnode_t *np = (nnode_t *)vnp;

	mutex_init(&np->nn_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&np->nn_refcount_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
nnode_destroy(void *vnp, void *foo)
{
	nnode_t *np = vnp;

	mutex_destroy(&np->nn_lock);
	cv_destroy(&np->nn_refcount_cv);
}

/*ARGSUSED*/
static void
nnode_reclaim(void *foo)
{
	/* oh noes!  we are short on memory! */
}

static int
nnode_bucket_teardown_by_instance(nnode_bucket_t *bucket, pid_t inst_id)
{
	nnode_t *np, *tmp_np;

	/*
	 * Take the bucket lock as writer because we intend to remove
	 * nnodes from it.
	 */
again:
	rw_enter(&bucket->nb_lock, RW_WRITER);

	/*
	 * Traverse the avl tree and free all nnodes meeting
	 * the following criteria:
	 * 1. nn_instance_id equal to inst_id
	 * nn_refcount equal to zero
	 *
	 * nnodes matching the critera will have the nn_refcount checked.
	 * If if refcount == zero, the nnode will be will be freed.
	 * If refcount > 0 we will sleep waiting for the refcount to go
	 * to zero.
	 */
	np = avl_first(&bucket->nb_tree);
	while (np != NULL) {
		tmp_np = AVL_NEXT(&bucket->nb_tree, np);
		if (np->nn_instance_id == inst_id) {
			/*
			 * We have the WRITE lock on the bucket so
			 * we are the only ones accessing this tree
			 * and therefore the only ones accessing this
			 * nnode.
			 */
			if (np->nn_refcount == 0) {
				avl_remove(&bucket->nb_tree, np);
				nnode_free(np);
			} else {
				mutex_enter(&np->nn_lock);
				/*
				 * Release bucket lock so other threads
				 * trying to create new nnodes or delete
				 * existing nnodes from this bucket can.
				 */
				rw_exit(&bucket->nb_lock);
				/*
				 * We will get woken up when the nn_refcount
				 * has gone to zero.  Then we can go up to
				 * the top and start freeing again.
				 */
				if (!cv_wait_sig(&np->nn_refcount_cv,
				    &np->nn_lock)) {
					mutex_exit(&np->nn_lock);
					return (EINTR);
				}

				mutex_exit(&np->nn_lock);
				goto again;
			}
		}
		np = tmp_np;
	}
	rw_exit(&bucket->nb_lock);
	return (0);
}

/*ARGSUSED*/
static int
nnode_bucket_construct(void *vnp, void *foo, int bar)
{
	nnode_bucket_t *bucket = vnp;

	rw_init(&bucket->nb_lock, NULL, RW_DEFAULT, NULL);
	avl_create(&bucket->nb_tree, nnode_compare, sizeof (nnode_t),
	    offsetof(nnode_t, nn_avl));

	return (0);
}

/*ARGSUSED*/
static void
nnode_bucket_destroy(void *nvp, void *foo)
{
	nnode_bucket_t *bucket = nvp;

	avl_destroy(&bucket->nb_tree);
	rw_destroy(&bucket->nb_lock);
}

/*ARGSUSED*/
static int
nfs_mds_nnode_construct(void *vnmn, void *foo, int bar)
{
	return (0);
}

/*ARGSUSED*/
static void
nfs_mds_nnode_destroy(void *vnmn, void *foo)
{
}

void
nnode_mod_init(void)
{
	nnode_hash = kmem_zalloc(nnode_hash_size * sizeof (nnode_bucket_t *),
	    KM_SLEEP);
	nnode_kmem_cache = kmem_cache_create("nnode_kmem_cache",
	    sizeof (nnode_t), 0,
	    nnode_construct, nnode_destroy, nnode_reclaim,
	    NULL, NULL, 0);
	nnode_bucket_cache = kmem_cache_create("nnode_bucket_cache",
	    sizeof (nnode_bucket_t), 0,
	    nnode_bucket_construct, nnode_bucket_destroy, NULL,
	    NULL, NULL, 0);
	nfs_mds_nnode_cache = kmem_cache_create("nfs_mds_nnode_cache",
	    sizeof (nfs_mds_nnode_t), 0,
	    nfs_mds_nnode_construct, nfs_mds_nnode_destroy, NULL,
	    NULL, NULL, 0);

	for (int i = 0; i < nnode_hash_size; i++)
		nnode_hash[i] = nnode_bucket_alloc();
}

void
nnode_mod_fini(void)
{
	/* XXX sweep all caches */
	kmem_free(nnode_hash, nnode_hash_size * sizeof (nnode_bucket_t *));
	kmem_cache_destroy(nnode_bucket_cache);
	kmem_cache_destroy(nfs_mds_nnode_cache);
	kmem_cache_destroy(nnode_kmem_cache);
}

/*
 * This function implements an aggressive purging of all of the nnodes
 * in the cache for an instance that is being shutdown.
 */
int
nnode_teardown_by_instance()
{
	pid_t inst;
	int error = 0;
	int i;

	inst = nnode_get_my_instance();
	if (inst == NULL) {
		DTRACE_PROBE(nfssrv__e__nnode_instance_is_null);
		return (ESRCH);
	}

	for (i = 0; i < nnode_hash_size; i++) {
		error = nnode_bucket_teardown_by_instance(nnode_hash[i], inst);
		if (error)
			return (error);
	}

	return (0);
}

nnop_error_t
nnop_read(nnode_t *np, void *buf, uint64_t off, uint32_t len)
{
	if ((np->nn_data_ops == NULL) || (np->nn_data_ops->ndo_read == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_data_ops->ndo_read)(np->nn_data_ops_data,
	    buf, off, len);
}

nnop_error_t
nnop_write(nnode_t *np, void *buf, uint64_t off, uint32_t len)
{
	if ((np->nn_data_ops == NULL) || (np->nn_data_ops->ndo_write == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_data_ops->ndo_write)(np->nn_data_ops_data,
	    buf, off, len);
}

nnop_error_t
nnop_commit(nnode_t *np, uint64_t off, uint32_t len)
{
	if ((np->nn_data_ops == NULL) || (np->nn_data_ops->ndo_commit == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_data_ops->ndo_commit)(np->nn_data_ops_data,
	    off, len);
}

nnop_error_t
nnop_truncate(nnode_t *np, uint64_t len)
{
	if ((np->nn_data_ops == NULL) ||
	    (np->nn_data_ops->ndo_truncate == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_data_ops->ndo_truncate)(np->nn_data_ops_data, len);
}

nnop_error_t
nnop_access(nnode_t *np, uint32_t flags)
{
	if ((np->nn_metadata_ops == NULL) ||
	    (np->nn_metadata_ops->nmo_access == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_metadata_ops->nmo_access)(np->nn_metadata_ops_data,
	    flags);
}

nnop_error_t
nnop_checkstate(nnode_t *np, stateid4 *statep, enum nfsstat4 *statusp)
{
	if ((np->nn_state_ops == NULL) ||
	    (np->nn_state_ops->nso_checkstate == NULL))
		return (NNOP_ERR_NOT_IMPL);

	return (*(np)->nn_state_ops->nso_checkstate)(np->nn_state_ops_data,
	    statep, statusp);
}

static int
nnode_compare(const void *va, const void *vb)
{
	const nnode_t *a = (nnode_t *)va;
	const nnode_t *b = (nnode_t *)vb;
	int rc;

	rc = a->nn_fh_len - b->nn_fh_len;
	NFS_AVL_RETURN(rc);

	rc = memcmp(a->nn_fh_value, b->nn_fh_value, a->nn_fh_len);
	NFS_AVL_RETURN(rc);

	rc = a->nn_instance_id - b->nn_instance_id;
	NFS_AVL_RETURN(rc);

	return (0);
}

static nnode_t *
nnode_alloc(nnode_seed_t *seed)
{
	nnode_t *nn;

	nn = kmem_cache_alloc(nnode_kmem_cache, KM_SLEEP);

	nn->nn_fh_value = seed->ns_fh_value;
	nn->nn_fh_len = seed->ns_fh_len;
	nn->nn_instance_id = nnode_get_my_instance();

	nn->nn_flags = 0;
	nn->nn_refcount = 1;

	nn->nn_data_ops_data = seed->ns_data;
	nn->nn_data_ops = seed->ns_data_ops;
	nn->nn_metadata_ops_data = seed->ns_metadata;
	nn->nn_metadata_ops = seed->ns_metadata_ops;
	nn->nn_state_ops_data = seed->ns_state;
	nn->nn_state_ops = seed->ns_state_ops;

	return (nn);
}

static void
nnode_free(nnode_t *nn)
{
	if ((nn->nn_data_ops != NULL) && (nn->nn_data_ops->ndo_free != NULL))
		(nn->nn_data_ops->ndo_free)(nn->nn_data_ops_data);
	if ((nn->nn_metadata_ops != NULL) &&
	    (nn->nn_metadata_ops->nmo_free != NULL))
		(nn->nn_metadata_ops->nmo_free)(nn->nn_metadata_ops_data);
	if ((nn->nn_state_ops != NULL) &&
	    (nn->nn_state_ops->nso_free != NULL))
		(nn->nn_state_ops->nso_free)(nn->nn_state_ops_data);
	kmem_free(nn->nn_fh_value, nn->nn_fh_len);
	kmem_cache_free(nnode_kmem_cache, nn);
}

static nnode_from_fh_res_t
nnode_build_v41(nnode_seed_t *seed)
{
	nfs41_fh_fmt_t *fhp;

	/*
	 * sanity check the otw filehandle
	 */
	if (seed->ns_fh_len != sizeof (*fhp))
		return (NNODE_FROM_FH_UNKNOWN);
	fhp = seed->ns_fh_value;

	if (fhp->type != FH41_TYPE_DMU_DS)
		return (NNODE_FROM_FH_UNKNOWN);

	return (NNODE_FROM_FH_OKAY);
}

nnode_from_fh_res_t (*nnode_build_dserv)(nnode_seed_t *);

/*
 * Find or build an nnode based upon a filehandle.  The flags field
 * says what kind or kinds of file handles are expected in the caller's
 * context.  Note that without the flags field, the algorithm for
 * determining the type of filehandle is not deterministic.
 *
 * If successful, NNODE_FROM_FH_OKAY is returned, and *npp is set to
 * point to an nnode.  When the caller is finished processing the
 * given request, nnode_rele() should be called to release the nnode.
 *
 * If unsuccessful, another value will be returned:
 *   NNODE_FROM_FH_UNKNOWN if the type of the filehandle cannot be
 *   determined.
 *   NNODE_FROM_FH_BADFH if the filehandle looks legitimate, but
 *   cannot be useful, e.g. in a stale filehandle situation.
 */

static nnode_from_fh_res_t
nnode_build(nnode_t **npp, void *fhval, uint32_t fhlen,
    uint32_t context)
{
	nnode_from_fh_res_t status = NNODE_FROM_FH_UNKNOWN;
	nnode_seed_t seed;

	bzero(&seed, sizeof (seed));
	seed.ns_fh_value = kmem_alloc(fhlen, KM_SLEEP);
	seed.ns_fh_len = fhlen;
	bcopy(fhval, seed.ns_fh_value, fhlen);

	switch (context) {
	case NNODE_FROM_FH_DS:
		if (nnode_build_dserv == NULL) {
			status = NNODE_FROM_FH_UNKNOWN;
			break;
		}
		status = nnode_build_dserv(&seed);
		break;
	default:
		status = NNODE_FROM_FH_BADCONTEXT;
		break;
	}

	if (status == NNODE_FROM_FH_OKAY)
		*npp = nnode_alloc(&seed);
	else
		kmem_free(seed.ns_fh_value, fhlen);

	return (status);
}

static uint32_t
nnode_fh_hash32(void *fhval, uint32_t fhlen)
{
	uint32_t rc;

	CRC32(rc, fhval, fhlen, -1U, crc32_table);

	return (rc);
}

static nnode_bucket_t *
nnode_bucket_alloc(void)
{
	nnode_bucket_t *bucket;

	bucket = kmem_cache_alloc(nnode_bucket_cache, KM_SLEEP);

	return (bucket);
}

static pid_t
nnode_get_my_instance(void)
{
	proc_t *myproc = ttoproc(curthread);

	return (myproc->p_pid);
}

/*
 * Find or create an nnode, based upon a filehandle.
 *
 * context is a bitmap of which kinds of filehandles are acceptable.
 * For non-pNFS uses, only one bit is typically set.  For pNFS, any
 * nonempty combination of MDS and DS is allowed.  This function does
 * now allow arbitrary combinations of bits, e.g. NFSv3 and DS at the
 * same time.
 */

nnode_from_fh_res_t
nnode_from_fh(nnode_t **npp, void *fhval, uint32_t fhlen,
    uint32_t context)
{
	nnode_from_fh_res_t rc;
	nnode_bucket_t *bucket;
	krw_t rw = RW_READER;
	avl_index_t where;
	nnode_t key, *found;
	int i;

	/*
	 * Quickly rule out some duds
	 */

	if (fhlen == 0)
		return (NNODE_FROM_FH_BADFH);
	if (fhlen < NNODE_MIN_FH_LEN)
		return (NNODE_FROM_FH_UNKNOWN);
	if (fhlen > NNODE_MAX_FH_LEN)
		return (NNODE_FROM_FH_BADFH);

	/*
	 * Find or create the nnode.
	 */

	i = nnode_fh_hash32(fhval, fhlen) % nnode_hash_size;
	bucket = nnode_hash[i];

	key.nn_fh_value = fhval;
	key.nn_fh_len = fhlen;
	key.nn_instance_id = nnode_get_my_instance();

again:
	rw_enter(&bucket->nb_lock, rw);
	found = avl_find(&bucket->nb_tree, &key, &where);
	if (found) {
		/*
		 * Found it.  Since we're holding the bucket lock,
		 * we know that any garbage-collection thread cannot
		 * free the nnode.  Increment its refcount and we're
		 * done.
		 */
		mutex_enter(&found->nn_lock);
		found->nn_refcount++;
		*npp = found;
		mutex_exit(&found->nn_lock);
		rw_exit(&bucket->nb_lock);
		return (NNODE_FROM_FH_OKAY);
	}

	/*
	 * not found; try to upgrade the lock, or drop the lock and
	 * re-grab as a writer and re-search the tree, since another
	 * thread may have created it while we had the lock dropped.
	 */
	if ((rw != RW_WRITER) && (! rw_tryupgrade(&bucket->nb_lock))) {
		rw = RW_WRITER;
		rw_exit(&bucket->nb_lock);
		goto again;
	}

	/*
	 * At this point, we know that the nnode does not exist, and
	 * since we're holding the bucket lock as a writer, that
	 * no other thread is trying to create it.  Thus, we can
	 * create the nnode, as well as modify the AVL tree by
	 * inserting the nnode.
	 */

	rc = nnode_build(npp, fhval, fhlen, context);
	if (rc == NNODE_FROM_FH_OKAY)
		avl_insert(&bucket->nb_tree, *npp, where);

	rw_exit(&bucket->nb_lock);

	return (rc);
}

void
nnode_rele(nnode_t **npp)
{
	nnode_t *np = *npp;

	*npp = NULL;

	/* use the atomics? */
	mutex_enter(&np->nn_lock);
	np->nn_refcount--;
	if (np->nn_refcount == 0)
		cv_broadcast(&np->nn_refcount_cv);
	mutex_exit(&np->nn_lock);
}
