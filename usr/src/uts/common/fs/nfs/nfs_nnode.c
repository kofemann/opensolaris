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

#include <nfs/nnode_impl.h>
#include <nfs/nfs4.h>
#include <nfs/export.h>

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <sys/taskq.h>
#include <sys/cyclic.h>

static int nnode_compare(const void *, const void *);
static nnode_bucket_t *nnode_bucket_alloc(void);
static void nnode_bucket_free(nnode_bucket_t *);
static pid_t nnode_get_my_instance(void);
static void nnode_bucket_sweep_task(void *);
static void nnode_bucket_sweep_task_free(nnode_bucket_sweep_task_t *);
static void nnode_bucket_proc_reclaim(nnode_bucket_sweep_task_t *, nnode_t *);
static void nnode_free(nnode_t *);
static void nnode_async_free(nnode_t *);
static void nnode_periodic_gc(void *);
static void nnode_sweep(nnode_bucket_sweep_task_t *);

extern pri_t minclsyspri;

/* globals */

uint32_t nnode_hash_size = NNODE_HASH_SIZE;
int nnode_max_workers = NNODE_MAX_WORKERS;
int nnode_min_taskalloc = NNODE_MIN_TASKALLOC;
int nnode_max_taskalloc = NNODE_MAX_TASKALLOC;
hrtime_t nnode_gc_interval = NNODE_GC_INTERVAL;
hrtime_t nnode_gc_too_old = NNODE_GC_TOO_OLD;
static nnode_bucket_t **nnode_hash;

static kmem_cache_t *nnode_kmem_cache;
static kmem_cache_t *nnode_bucket_cache;
static kmem_cache_t *nnode_bucket_sweep_task_cache;
static taskq_t *nnode_taskq;
static cyclic_id_t nnode_gc_cyclic;

static nnode_bucket_sweep_task_t nnode_gc_task = {
	.nbst_flags = 0,
};
static cyc_handler_t nnode_gc_handler = {
	nnode_periodic_gc,
	NULL,
	CY_LOW_LEVEL
};
static cyc_time_t nnode_gc_time = {
	0,
	NNODE_GC_INTERVAL
};

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
	nnode_bucket_sweep_task_t task;

	task.nbst_flags = NNODE_BUCKET_SWEEP_TASK_SYNC;
	task.nbst_proc = nnode_bucket_proc_reclaim;

	nnode_sweep(&task);
}

static nnode_bucket_sweep_task_t *
nnode_bucket_sweep_task_alloc(nnode_bucket_sweep_task_t *proto, int how)
{
	nnode_bucket_sweep_task_t *rc;

	rc = kmem_cache_alloc(nnode_bucket_sweep_task_cache, how);
	if (rc == NULL)
		return (NULL);
	bcopy(proto, rc, sizeof (*rc));
	rc->nbst_flags |= NNODE_BUCKET_SWEEP_TASK_FREEME;

	return (rc);
}

/*
 * Sweep through all nnodes.  If NNODE_BUCKET_SWEEP_TASK_SYNC is not set,
 * then we try to spawn tasks, to gain parallelism.  However, since
 * nnode_sweep() may be called to free memory in a low-memory situation,
 * we fall back to synchronously sweeping the nodes in the case where we
 * fail to allocate memory.
 */

static void
nnode_sweep(nnode_bucket_sweep_task_t *task)
{
	nnode_bucket_sweep_task_t *atask;

	for (int i = 0; i < nnode_hash_size; i++) {
		task->nbst_bucket = nnode_hash[i];
		if (task->nbst_flags & NNODE_BUCKET_SWEEP_TASK_SYNC) {
			nnode_bucket_sweep_task(task);
			continue;
		}
		atask = nnode_bucket_sweep_task_alloc(task, KM_NOSLEEP);
		if ((atask != NULL) &&
		    (taskq_dispatch(nnode_taskq, nnode_bucket_sweep_task,
		    atask, TQ_NOSLEEP) == (taskqid_t)0))
			nnode_bucket_sweep_task_free(atask);
	}
}

static void
nnode_bucket_sweep_task_free(nnode_bucket_sweep_task_t *task)
{
	kmem_cache_free(nnode_bucket_sweep_task_cache, task);
}

/*
 * Synchronously free all nnodes under a given exportinfo.
 */

static void
nnode_bucket_proc_export(nnode_bucket_sweep_task_t *task, nnode_t *nn)
{
	nnode_bucket_t *bucket = task->nbst_bucket;

	ASSERT(RW_ISWRITER(&task->nbst_bucket->nb_lock));

	/* XXX in the future, match exportinfo; for now, nuke everything */

	avl_remove(&bucket->nb_tree, nn);

	mutex_enter(&nn->nn_lock);
	while (nn->nn_refcount > 0)
		cv_wait(&nn->nn_refcount_cv, &nn->nn_lock);
	mutex_exit(&nn->nn_lock);

	nnode_free(nn);
}

/*
 * Synchronously free all nnodes with a matching instance.
 */

static void
nnode_bucket_proc_instance(nnode_bucket_sweep_task_t *task, nnode_t *nn)
{
	nnode_bucket_t *bucket = task->nbst_bucket;

	ASSERT(RW_ISWRITER(&task->nbst_bucket->nb_lock));

	if (nn->nn_instance_id != task->nbst_inst_id)
		return;

	avl_remove(&bucket->nb_tree, nn);

	mutex_enter(&nn->nn_lock);
	while (nn->nn_refcount > 0)
		cv_wait(&nn->nn_refcount_cv, &nn->nn_lock);
	mutex_exit(&nn->nn_lock);

	nnode_free(nn);
}

/*
 * Free all unreferenced nnodes that have not been found since "maxage".
 */

static void
nnode_bucket_proc_maxage(nnode_bucket_sweep_task_t *task, nnode_t *nn)
{
	nnode_bucket_t *bucket = task->nbst_bucket;

	ASSERT(RW_ISWRITER(&task->nbst_bucket->nb_lock));

	/*
	 * if we cannot get the lock, then some other thread is
	 * using the nnode now, so we can just bail out.
	 */
	if (!mutex_tryenter(&nn->nn_lock))
		return;

	/*
	 * Bail out if it's in use, or if it's recently accessed.
	 */
	if ((nn->nn_refcount > 0) ||
	    (nn->nn_last_access >= task->nbst_maxage)) {
		mutex_exit(&nn->nn_lock);
		return;
	}

	/*
	 * A victim.  Since we're holding the bucket lock as a writer,
	 * we can remove the nnode from the tree, and thus it will not
	 * be found by another thread.  Since its refcount is zero,
	 * we can safely free it.
	 */
	avl_remove(&bucket->nb_tree, nn);
	mutex_exit(&nn->nn_lock);
	nnode_free(nn);
}

/*
 * Reclaim (i.e. free) all nnodes, as quickly as possible.  This is called
 * in a low memory situation.  If an nnode cannot be freed immediately,
 * skip it.
 */

static void
nnode_bucket_proc_reclaim(nnode_bucket_sweep_task_t *task, nnode_t *nn)
{
	nnode_bucket_t *bucket = task->nbst_bucket;
	int count;

	ASSERT(RW_ISWRITER(&task->nbst_bucket->nb_lock));

	if (!mutex_tryenter(&nn->nn_lock))
		return;
	count = nn->nn_refcount;
	mutex_exit(&nn->nn_lock);

	if (count > 0)
		return;

	avl_remove(&bucket->nb_tree, nn);
	nnode_free(nn);
}

static void
nnode_bucket_sweep_task(void *vtask)
{
	nnode_bucket_sweep_task_t *task = vtask;
	nnode_bucket_t *bucket;
	nnode_t *np, *tmp_np;

	bucket = task->nbst_bucket;

	/*
	 * Take the bucket lock as writer because we intend to remove
	 * nnodes from it.
	 */
	rw_enter(&bucket->nb_lock, RW_WRITER);

	/*
	 * Traverse the avl tree, calling nbst_proc on each node.
	 */
	np = avl_first(&bucket->nb_tree);
	while (np != NULL) {
		tmp_np = AVL_NEXT(&bucket->nb_tree, np);
		(task->nbst_proc)(task, np);
		np = tmp_np;
	}
	rw_exit(&bucket->nb_lock);
	if (task->nbst_flags & NNODE_BUCKET_SWEEP_TASK_FREEME)
		nnode_bucket_sweep_task_free(task);
}

static void
nnode_sweep_call(void *vtask)
{
	nnode_bucket_sweep_task_t *task = vtask;

	nnode_sweep(task);
}

/*ARGSUSED*/
static void
nnode_periodic_gc(void *vtask)
{
	nnode_bucket_sweep_task_t *task = vtask;

	task->nbst_maxage = gethrtime() - nnode_gc_too_old;

	(void) taskq_dispatch(nnode_taskq, nnode_sweep_call, task,
	    TQ_NOSLEEP | TQ_NOQUEUE);
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
	nnode_bucket_sweep_task_cache = kmem_cache_create(
	    "nnode_bucket_sweep_task_cache",
	    sizeof (nnode_bucket_sweep_task_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	nnode_vn_init();
	nnode_proxy_init();

	for (int i = 0; i < nnode_hash_size; i++)
		nnode_hash[i] = nnode_bucket_alloc();

	nnode_taskq = taskq_create("nnode_taskq", nnode_max_workers,
	    minclsyspri, nnode_min_taskalloc, nnode_max_taskalloc,
	    TASKQ_DYNAMIC);

	nnode_gc_time.cyt_interval = nnode_gc_interval;
	nnode_gc_handler.cyh_arg = &nnode_gc_task;
	nnode_gc_task.nbst_proc = nnode_bucket_proc_maxage;
	mutex_enter(&cpu_lock);
	nnode_gc_cyclic = cyclic_add(&nnode_gc_handler, &nnode_gc_time);
	mutex_exit(&cpu_lock);
}

int
nnode_mod_fini(void)
{
	mutex_enter(&cpu_lock);
	cyclic_remove(nnode_gc_cyclic); /* guaranteed gc is finished */
	mutex_exit(&cpu_lock);

	for (int i = 0; i < nnode_hash_size; i++)
		nnode_bucket_free(nnode_hash[i]); /* spawns tasks */

	taskq_destroy(nnode_taskq); /* guaranteed tasks are finished */

	kmem_free(nnode_hash, nnode_hash_size * sizeof (nnode_bucket_t *));

	kmem_cache_destroy(nnode_bucket_cache);
	kmem_cache_destroy(nnode_kmem_cache);
	kmem_cache_destroy(nnode_bucket_sweep_task_cache);
	nnode_proxy_fini();
	nnode_vn_fini();

	return (0);
}

/*
 * This function implements an aggressive purging of all of the nnodes
 * in the cache for an exportinfo that is being unshared.
 */
void
nnode_free_export(exportinfo_t *exi)
{
	nnode_bucket_sweep_task_t task;

	task.nbst_flags = NNODE_BUCKET_SWEEP_TASK_SYNC;
	task.nbst_proc = nnode_bucket_proc_export;
	task.nbst_export = exi;

	nnode_sweep(&task);
}

/*
 * This function implements an aggressive purging of all of the nnodes
 * in the cache for an instance that is being shutdown.
 */
int
nnode_teardown_by_instance(void)
{
	nnode_bucket_sweep_task_t task;

	task.nbst_flags = NNODE_BUCKET_SWEEP_TASK_SYNC;
	task.nbst_proc = nnode_bucket_proc_instance;

	task.nbst_inst_id = nnode_get_my_instance();
	if (task.nbst_inst_id == NULL) {
		DTRACE_PROBE(nfssrv__e__nnode_instance_is_null);
		return (ESRCH);
	}

	nnode_sweep(&task);

	return (0);
}

static int
nnode_compare(const void *va, const void *vb)
{
	const nnode_t *a = (nnode_t *)va;
	const nnode_t *b = (nnode_t *)vb;
	pid_t rc;

	/*
	 * NFS_AVL_RETURN() does nothing if rc is zero.
	 * If rc is not zero, it causes this function to return 1 or -1.
	 */
	rc = a->nn_instance_id - b->nn_instance_id;
	NFS_AVL_RETURN(rc);

	/*
	 * NFS_AVL_COMPARE() does nothing if the two arguments are equal.
	 * If they are not, it causes this function to return 1 or -1.
	 */
	NFS_AVL_COMPARE((uintptr_t)a->nn_key_compare,
	    (uintptr_t)b->nn_key_compare);

	return (a->nn_key_compare(a->nn_key, b->nn_key));
}

static nnode_t *
nnode_alloc(nnode_seed_t *seed)
{
	nnode_t *nn;

	nn = kmem_cache_alloc(nnode_kmem_cache, KM_SLEEP);

	nn->nn_key = seed->ns_key;
	nn->nn_key_compare = seed->ns_key_compare;
	nn->nn_key_free = seed->ns_key_free;

	nn->nn_instance_id = nnode_get_my_instance();

	nn->nn_flags = 0;
	nn->nn_refcount = 1;
	nn->nn_last_access = gethrtime();

	nn->nn_data_ops_data = seed->ns_data;
	nn->nn_data_ops = seed->ns_data_ops;
	nn->nn_metadata_ops_data = seed->ns_metadata;
	nn->nn_metadata_ops = seed->ns_metadata_ops;
	nn->nn_state_ops_data = seed->ns_state;
	nn->nn_state_ops = seed->ns_state_ops;

	return (nn);
}

static void
nnode_async_free_task(void *vnn)
{
	nnode_t *nn = vnn;

	mutex_enter(&nn->nn_lock);
	while (nn->nn_refcount > 0)
		cv_wait(&nn->nn_refcount_cv, &nn->nn_lock);
	mutex_exit(&nn->nn_lock);

	nnode_free(nn);
}

static void
nnode_async_free(nnode_t *nn)
{
	(void) taskq_dispatch(nnode_taskq, nnode_async_free_task, nn,
	    TQ_SLEEP);
}

static void
nnode_free(nnode_t *nn)
{
	ASSERT(nn->nn_refcount == 0);

	if ((nn->nn_data_ops != NULL) && (nn->nn_data_ops->ndo_free != NULL))
		(nn->nn_data_ops->ndo_free)(nn->nn_data_ops_data);
	if ((nn->nn_metadata_ops != NULL) &&
	    (nn->nn_metadata_ops->nmo_free != NULL))
		(nn->nn_metadata_ops->nmo_free)(nn->nn_metadata_ops_data);
	if ((nn->nn_state_ops != NULL) &&
	    (nn->nn_state_ops->nso_free != NULL))
		(nn->nn_state_ops->nso_free)(nn->nn_state_ops_data);
	if (nn->nn_key_free != NULL)
		(nn->nn_key_free)(nn->nn_key);
	kmem_cache_free(nnode_kmem_cache, nn);
}

static int
nnode_build(nnode_t **npp, void *fhdata, nnode_init_function_t nninit)
{
	int status = ESTALE;
	nnode_seed_t seed;

	bzero(&seed, sizeof (seed));

	status = nninit(&seed, fhdata);

	if (status == 0)
		*npp = nnode_alloc(&seed);

	return (status);
}

static nnode_bucket_t *
nnode_bucket_alloc(void)
{
	nnode_bucket_t *bucket;

	bucket = kmem_cache_alloc(nnode_bucket_cache, KM_SLEEP);

	return (bucket);
}

static void
nnode_bucket_free(nnode_bucket_t *bucket)
{
	void *cookie = NULL;
	nnode_t *nn;

	ASSERT(! RW_LOCK_HELD(&bucket->nb_lock));

	while ((nn = avl_destroy_nodes(&bucket->nb_tree, &cookie)) != NULL)
		nnode_async_free(nn);

	kmem_cache_free(nnode_bucket_cache, bucket);
}

static pid_t
nnode_get_my_instance(void)
{
	proc_t *myproc = ttoproc(curthread);

	return (myproc->p_pid);
}

/*
 * Function to set nnode flag.
 * Returns 0 upon failure, 1 on success
 */
int
nnode_set_flag(nnode_t *np, uint32_t flag)
{
	if (!(flag & NNODE_VALID_FLAG_BITS))
		return (0);

	mutex_enter(&np->nn_lock);
	np->nn_flags |= flag;
	mutex_exit(&np->nn_lock);

	return (1);
}

/*
 * Function to clear nnode flag.
 * Returns 0 upon failure, 1 on success
 */
int
nnode_clear_flag(nnode_t *np, uint32_t flag)
{
	if ((!flag & NNODE_VALID_FLAG_BITS))
		return (0);

	mutex_enter(&np->nn_lock);
	np->nn_flags &= ~flag;
	mutex_exit(&np->nn_lock);

	return (1);
}


int
nnode_find_or_create(nnode_t **npp, nnode_key_t *nkey, uint32_t hash,
    void *data, nnode_init_function_t nnbuild)
{
	nnode_bucket_t *bucket;
	krw_t rw = RW_READER;
	avl_index_t where;
	nnode_t key, *found;
	int rc;

	/*
	 * Find or create the nnode.
	 */

	key.nn_key = nkey->nk_keydata;
	key.nn_key_compare = nkey->nk_compare;
	key.nn_instance_id = nnode_get_my_instance();

	hash %= nnode_hash_size;
	bucket = nnode_hash[hash];

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
		ASSERT(found->nn_refcount != 0);
		found->nn_last_access = gethrtime();
		*npp = found;
		mutex_exit(&found->nn_lock);
		rw_exit(&bucket->nb_lock);
		return (0);
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
	rc = nnode_build(npp, data, nnbuild);
	if (rc == 0)
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
	ASSERT(np->nn_refcount != 0);

	/*
	 * There should not be any other thread accessing
	 * the nnode if the object has been removed.  If
	 * the refcount on the nnode != 1 and NNODE_OBJ_REMOVED
	 * is set, this is an error condition.  The object
	 * should only be removed by the metadata server when
	 * the last close is done.  We are only firing a DTrace
	 * probe if this condition is met because it is possible
	 * for a misbehaving client to access the data server
	 * after a file has been closed.  We do not want a
	 * a misbehaving client to crater the server.
	 */
	if ((np->nn_flags & NNODE_OBJ_REMOVED) && np->nn_refcount != 1)
		DTRACE_PROBE1(nfssrv__e__unexpected_refcount, int,
		    np->nn_refcount);

	np->nn_refcount--;
	np->nn_last_access = gethrtime();
	if (np->nn_refcount == 0)
		cv_broadcast(&np->nn_refcount_cv);
	mutex_exit(&np->nn_lock);
}
