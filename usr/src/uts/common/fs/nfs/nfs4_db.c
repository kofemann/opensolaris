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
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/id_space.h>
#include <sys/atomic.h>
#include <rpc/rpc.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_db_impl.h>

static int rfs4_reap_interval = RFS4_REAP_INTERVAL;

static void rfs4_dbe_reap(rfs4_table_t *, time_t, uint32_t);
static void rfs4_dbe_destroy(rfs4_dbe_t *);
static rfs4_dbe_t *rfs4_dbe_create(rfs4_table_t *, id_t, rfs4_entry_t);
static void rfs4_start_reaper(rfs4_table_t *);

krwlock_t nsi_lock;

id_t
rfs4_dbe_getid(rfs4_dbe_t *entry)
{
	return (entry->dbe_id);
}

void
rfs4_dbe_hold(rfs4_dbe_t *entry)
{
	atomic_add_32(&entry->dbe_refcnt, 1);
}

/*
 * rfs4_dbe_rele_nolock only decrements the reference count of the entry.
 */
void
rfs4_dbe_rele_nolock(rfs4_dbe_t *entry)
{
	atomic_add_32(&entry->dbe_refcnt, -1);
}


uint32_t
rfs4_dbe_refcnt(rfs4_dbe_t *entry)
{
	return (entry->dbe_refcnt);
}

/*
 * Mark an entry such that the dbsearch will skip it.
 * Caller does not want this entry to be found any longer
 */
void
rfs4_dbe_invalidate(rfs4_dbe_t *entry)
{
	entry->dbe_invalid = TRUE;
	entry->dbe_skipsearch = TRUE;
	entry->inval_hint = caller();
}

/*
 * Is this entry invalid?
 */
bool_t
rfs4_dbe_is_invalid(rfs4_dbe_t *entry)
{
	return (entry->dbe_invalid);
}

/*
 * Is the entry marked to SKIP or INVALID ?
 */
bool_t
rfs4_dbe_skip_or_invalid(rfs4_dbe_t *e)
{
	return (e->invalid | e->skipsearch);
}

time_t
rfs4_dbe_get_timerele(rfs4_dbe_t *entry)
{
	return (entry->dbe_time_rele);
}

/*
 * Use these to temporarily hide/unhide a db entry.
 */
void
rfs4_dbe_hide(rfs4_dbe_t *entry)
{
	rfs4_dbe_lock(entry);
	entry->dbe_skipsearch = TRUE;
	rfs4_dbe_unlock(entry);
}

void
rfs4_dbe_unhide(rfs4_dbe_t *entry)
{
	rfs4_dbe_lock(entry);
	entry->dbe_skipsearch = FALSE;
	rfs4_dbe_unlock(entry);
}

void
rfs4_dbe_rele(rfs4_dbe_t *entry)
{
	mutex_enter(entry->dbe_lock);
	ASSERT(entry->dbe_refcnt > 1);
	atomic_add_32(&entry->dbe_refcnt, -1);
	entry->dbe_time_rele = gethrestime_sec();
	mutex_exit(entry->dbe_lock);
}

void
rfs4_dbe_lock(rfs4_dbe_t *entry)
{
	mutex_enter(entry->dbe_lock);
}

void
rfs4_dbe_unlock(rfs4_dbe_t *entry)
{
	mutex_exit(entry->dbe_lock);
}

bool_t
rfs4_dbe_islocked(rfs4_dbe_t *entry)
{
	return (mutex_owned(entry->dbe_lock));
}

clock_t
rfs4_dbe_twait(rfs4_dbe_t *entry, clock_t timeout)
{
	return (cv_timedwait(entry->dbe_cv, entry->dbe_lock, timeout));
}

void
rfs4_dbe_cv_broadcast(rfs4_dbe_t *entry)
{
	cv_broadcast(entry->dbe_cv);
}

/* ARGSUSED */
static int
rfs4_dbe_kmem_constructor(void *obj, void *private, int kmflag)
{
	rfs4_dbe_t *entry = obj;

	mutex_init(entry->dbe_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(entry->dbe_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

static void
rfs4_dbe_kmem_destructor(void *obj, void *private)
{
	rfs4_dbe_t *entry = obj;
	/*LINTED*/
	rfs4_table_t *table = private;

	mutex_destroy(entry->dbe_lock);
	cv_destroy(entry->dbe_cv);
}

rfs4_database_t *
rfs4_database_create()
{
	rfs4_database_t *db;

	db = kmem_alloc(sizeof (rfs4_database_t), KM_SLEEP);
	mutex_init(db->db_lock, NULL, MUTEX_DEFAULT, NULL);
	db->db_tables = NULL;
	db->db_shutdown_count = 0;
	cv_init(&db->db_shutdown_wait, NULL, CV_DEFAULT, NULL);
	return (db);
}


/*
 * The reaper threads that have been created for the tables in this
 * database must be stopped and the entries in the tables released.
 * Each table will be marked as "shutdown" and the reaper threads
 * poked and they will see that a shutdown is in progress and cleanup
 * and exit.  This function waits for all reaper threads to stop
 * before returning to the caller.
 */
void
rfs4_database_shutdown(rfs4_database_t *db)
{
	rfs4_table_t *table;

	mutex_enter(db->db_lock);
	for (table = db->db_tables; table; table = table->dbt_tnext) {
		table->dbt_reaper_shutdown = TRUE;
		mutex_enter(&table->dbt_reaper_cv_lock);
		cv_broadcast(&table->dbt_reaper_wait);
		db->db_shutdown_count++;
		mutex_exit(&table->dbt_reaper_cv_lock);
	}
	while (db->db_shutdown_count > 0) {
		cv_wait(&db->db_shutdown_wait, db->db_lock);
	}
	mutex_exit(db->db_lock);
}

/*
 * Given a database that has been "shutdown" by the function above all
 * of the table tables are destroyed and then the database itself
 * freed.
 */
void
rfs4_database_destroy(rfs4_database_t *db)
{
	rfs4_table_t *next, *tmp;

	for (next = db->db_tables; next; ) {
		tmp = next;
		next = tmp->dbt_tnext;
		rfs4_table_destroy(db, tmp);
	}

	mutex_destroy(db->db_lock);
	kmem_free(db, sizeof (rfs4_database_t));
}

rfs4_table_t *
rfs4_table_create(nfs_server_instance_t *instp, char *tabname,
    time_t max_cache_time,
    uint32_t idxcnt, bool_t (*create)(rfs4_entry_t, void *),
    void (*destroy)(rfs4_entry_t),
    bool_t (*expiry)(rfs4_entry_t),
    uint32_t size, uint32_t hashsize,
    uint32_t maxentries, id_t start)
{
	rfs4_database_t *db;
	rfs4_table_t *table;

	int len;
	char *tbl_inst_name = "";
	char *cache_name;
	char *id_name;

	table = kmem_alloc(sizeof (rfs4_table_t), KM_SLEEP);
	table->dbt_instp = instp;
	db = instp->state_store;

	rw_init(table->dbt_t_lock, NULL, RW_DEFAULT, NULL);
	mutex_init(table->dbt_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&table->dbt_reaper_cv_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&table->dbt_reaper_wait, NULL, CV_DEFAULT, NULL);

	ASSERT(instp);

	if (instp != NULL)
		tbl_inst_name = instp->inst_name;

	len = strlen(tabname) + strlen(tbl_inst_name);
	/* alloc plus one for the Nul */
	table->dbt_name = kmem_alloc(len+1, KM_SLEEP);
	cache_name = kmem_alloc(len + 12 /* "_entry_cache" */ + 1, KM_SLEEP);
	(void) sprintf(table->dbt_name, "%s%s", tbl_inst_name, tabname);
	(void) sprintf(cache_name, "%s_entry_cache", table->dbt_name);

	table->dbt_max_cache_time = max_cache_time;
	table->dbt_usize = size;
	table->dbt_len = hashsize;
	table->dbt_count = 0;
	table->dbt_idxcnt = 0;
	table->dbt_ccnt = 0;
	table->dbt_maxcnt = idxcnt;
	table->dbt_indices = NULL;
	table->dbt_id_space = NULL;
	table->dbt_reaper_shutdown = FALSE;

	/*
	 * If a start value was specified then we
	 * wish to allocate identifiers from the
	 * id_space.
	 */
	if (start >= 0) {
		if (maxentries + (uint32_t)start > (uint32_t)INT32_MAX)
			maxentries = INT32_MAX - start;
		id_name = kmem_alloc(len + 9 /* "_id_space" */ + 1, KM_SLEEP);
		(void) sprintf(id_name, "%s_id_space", table->dbt_name);
		table->dbt_id_space = id_space_create(id_name, start,
		    maxentries + start);
		kmem_free(id_name, len + 10);
	}
	table->dbt_maxentries = maxentries;
	table->dbt_create = create;
	table->dbt_destroy = destroy;
	table->dbt_expiry = expiry;

	table->dbt_mem_cache = kmem_cache_create(cache_name,
	    sizeof (rfs4_dbe_t) + idxcnt * sizeof (rfs4_link_t) + size,
	    0,
	    rfs4_dbe_kmem_constructor,
	    rfs4_dbe_kmem_destructor,
	    NULL,
	    table,
	    NULL,
	    0);
	kmem_free(cache_name, len+13);

	mutex_enter(db->db_lock);
	table->dbt_tnext = db->db_tables;
	db->db_tables = table;
	mutex_exit(db->db_lock);

	rfs4_start_reaper(table);

	return (table);
}

void
rfs4_table_destroy(rfs4_database_t *db, rfs4_table_t *table)
{
	rfs4_table_t *p;
	rfs4_index_t *idx;

	ASSERT(table->dbt_count == 0);

	mutex_enter(db->db_lock);
	if (table == db->db_tables)
		db->db_tables = table->dbt_tnext;
	else {
		for (p = db->db_tables; p; p = p->dbt_tnext)
			if (p->dbt_tnext == table) {
				p->dbt_tnext = table->dbt_tnext;
				table->dbt_tnext = NULL;
				break;
			}
		ASSERT(p != NULL);
	}
	mutex_exit(db->db_lock);

	/* Destroy indices */
	while (table->dbt_indices) {
		idx = table->dbt_indices;
		table->dbt_indices = idx->dbi_inext;
		rfs4_index_destroy(idx);
	}

	rw_destroy(table->dbt_t_lock);
	mutex_destroy(table->dbt_lock);
	mutex_destroy(&table->dbt_reaper_cv_lock);
	cv_destroy(&table->dbt_reaper_wait);

	kmem_free(table->dbt_name, strlen(table->dbt_name) + 1);

	if (table->dbt_id_space)
		id_space_destroy(table->dbt_id_space);
	kmem_cache_destroy(table->dbt_mem_cache);
	kmem_free(table, sizeof (rfs4_table_t));
}

rfs4_index_t *
rfs4_index_create(rfs4_table_t *table,
	char *keyname,
	uint32_t (*hash)(void *),
	bool_t (compare)(rfs4_entry_t, void *),
	void *(*mkkey)(rfs4_entry_t),
	bool_t createable)
{
	rfs4_index_t *idx;
	char *tbl_inst_name = "";

	ASSERT(table->dbt_idxcnt < table->dbt_maxcnt);

	idx = kmem_alloc(sizeof (rfs4_index_t), KM_SLEEP);

	if (table->dbt_instp)
		tbl_inst_name = table->dbt_instp->inst_name;

	idx->dbi_table = table;
	idx->dbi_keyname = kmem_alloc(strlen(tbl_inst_name)
	    + strlen(keyname) + 2, KM_SLEEP);
	(void) sprintf(idx->dbi_keyname, "%s_%s", tbl_inst_name, keyname);
	idx->dbi_hash = hash;
	idx->dbi_compare = compare;
	idx->dbi_mkkey = mkkey;
	idx->dbi_tblidx = table->dbt_idxcnt;
	table->dbt_idxcnt++;
	if (createable) {
		table->dbt_ccnt++;
		if (table->dbt_ccnt > 1)
			panic("Table %s currently can have only have one "
			    "index that will allow creation of entries",
			    table->dbt_name);
		idx->dbi_createable = TRUE;
	} else {
		idx->dbi_createable = FALSE;
	}

	idx->dbi_inext = table->dbt_indices;
	table->dbt_indices = idx;
	idx->dbi_buckets = kmem_zalloc(sizeof (rfs4_bucket_t) * table->dbt_len,
	    KM_SLEEP);

	return (idx);
}

void
rfs4_index_destroy(rfs4_index_t *idx)
{
	kmem_free(idx->dbi_keyname, strlen(idx->dbi_keyname) + 1);
	kmem_free(idx->dbi_buckets,
	    sizeof (rfs4_bucket_t) * idx->dbi_table->dbt_len);
	kmem_free(idx, sizeof (rfs4_index_t));
}

static void
rfs4_dbe_destroy(rfs4_dbe_t *entry)
{
	rfs4_index_t *idx;
	void *key;
	int i;
	rfs4_bucket_t *bp;
	rfs4_table_t *table = entry->dbe_table;
	rfs4_link_t *l;

#ifdef	DEBUG
	mutex_enter(entry->dbe_lock);
	ASSERT(entry->dbe_refcnt == 0);
	mutex_exit(entry->dbe_lock);
#endif

	/* Unlink from all indices */
	for (idx = table->dbt_indices; idx; idx = idx->dbi_inext) {
		l = &entry->dbe_indices[idx->dbi_tblidx];
		/* check and see if we were ever linked in to the index */
		if (INVALID_LINK(l)) {
			ASSERT(l->next == NULL && l->prev == NULL);
			continue;
		}
		key = idx->dbi_mkkey(entry->dbe_data);
		i = HASH(idx, key);
		bp = &idx->dbi_buckets[i];
		ASSERT(bp->dbk_head != NULL);
		DEQUEUE_IDX(bp, &entry->dbe_indices[idx->dbi_tblidx]);
	}

	/* Destroy user data */
	if (table->dbt_destroy)
		(*table->dbt_destroy)(entry->dbe_data);

	if (table->dbt_id_space)
		id_free(table->dbt_id_space, entry->dbe_id);

	mutex_enter(table->dbt_lock);
	table->dbt_count--;
	mutex_exit(table->dbt_lock);

	/* Destroy the entry itself */
	kmem_cache_free(table->dbt_mem_cache, entry);
}

/*
 * If a valid entry is created, then the refcnt will be 1.
 */
static rfs4_dbe_t *
rfs4_dbe_create(rfs4_table_t *table, id_t id, rfs4_entry_t data)
{
	rfs4_dbe_t *entry;
	int i;

	entry = kmem_cache_alloc(table->dbt_mem_cache, KM_SLEEP);
	entry->dbe_refcnt = 1;
	entry->dbe_invalid = FALSE;
	entry->dbe_skipsearch = FALSE;
	entry->dbe_time_rele = 0;
	entry->dbe_id = 0;

	if (table->dbt_id_space)
		entry->dbe_id = id;
	entry->dbe_table = table;

	for (i = 0; i < table->dbt_maxcnt; i++) {
		entry->dbe_indices[i].next = entry->dbe_indices[i].prev = NULL;
		entry->dbe_indices[i].entry = entry;
		/*
		 * We mark the entry as not indexed by setting the low
		 * order bit, since address are word aligned. This has
		 * the advantage of causing a trap if the address is
		 * used. After the entry is linked in to the
		 * corresponding index the bit will be cleared.
		 */
		INVALIDATE_ADDR(entry->dbe_indices[i].entry);
	}

	entry->dbe_data = (rfs4_entry_t)&entry->dbe_indices[table->dbt_maxcnt];
	bzero(entry->dbe_data, table->dbt_usize);
	entry->dbe_data->dbe = entry;

	if (!(*table->dbt_create)(entry->dbe_data, data)) {
		if (table->dbt_id_space)
			id_free(table->idbt_d_space, entry->dbe_id);
		kmem_cache_free(table->dbt_mem_cache, entry);

		return (NULL);
	}

	mutex_enter(table->dbt_lock);
	table->dbt_count++;
	mutex_exit(table->dbt_lock);

	return (entry);
}

/*
 * If *create is TRUE and we end up creating an entry, then the entry will
 * have a refcnt of 2. The entry may not be reaped until the hold done here
 * has been released.
 *
 * If the entry was not created here and is returned, then this function
 * will bump the refcnt. It will also need to be released when appropriate.
 */
rfs4_entry_t
rfs4_dbsearch(rfs4_index_t *idx, void *key, bool_t *create, void *arg,
    rfs4_dbsearch_type_t dbsearch_type)
{
	int already_done;
	uint32_t i;
	rfs4_table_t *table = idx->dbi_table;
	rfs4_index_t *ip;
	rfs4_bucket_t *bp;
	rfs4_link_t *l;
	rfs4_dbe_t *entry;
	id_t id = -1;

	/*
	 * figure out the bucket in idx based on the passed in key value
	 * and the abstracted key hashing function for the index
	 */
	i = HASH(idx, key);
	bp = &idx->dbi_buckets[i];

	rw_enter(bp->dbk_lock, RW_READER);

	/*
	 * Now search the bucket for a match.
	 *
	 * Based on each entry in the bucket check:
	 *   passed in key value using idx abstracted compare function;
	 *   validity of the entry using the refcnt,
	 *   	the entries skipsearch and dbsearch_type.
	 */
retry:
	for (l = bp->dbk_head; l; l = l->next) {
		if (l->entry->dbe_refcnt > 0 &&
		    (l->entry->dbe_skipsearch == FALSE ||
		    (l->entry->dbe_skipsearch == TRUE &&
		    dbsearch_type == RFS4_DBS_INVALID)) &&
		    (*idx->dbi_compare)(l->entry->dbe_data, key)) {
			mutex_enter(l->entry->dbe_lock);

			/* recheck the refcnt after acquiring the lock */
			if (l->entry->dbe_refcnt == 0) {
				mutex_exit(l->entry->dbe_lock);
				continue;
			}

			/* place an additional hold since we are returning */
			rfs4_dbe_hold(l->entry);

			mutex_exit(l->entry->dbe_lock);
			rw_exit(bp->dbk_lock);


			/* inform caller we did not create this entry */
			*create = FALSE;

			if (id != -1)
				id_free(table->dbt_id_space, id);
			return (l->entry->dbe_data);
		}
	}

	/*
	 * Here we have not found the entry in the table:
	 *
	 * If creation was not requested, or the table does not have
	 * a create function, or the index is not 'allowed' to automatically
	 * create entries, or the table is FULL!! return NULL to the caller.
	 */
	if (!*create || table->dbt_create == NULL || !idx->dbi_createable ||
	    table->dbt_maxentries == table->dbt_count) {
		rw_exit(bp->dbk_lock);
		if (id != -1)
			id_free(table->dbt_id_space, id);
		return (NULL);
	}

	if (table->dbt_id_space && id == -1) {
		/* get an id but don't sleep for it */
		id = id_alloc_nosleep(table->dbt_id_space);
		if (id == -1) {
			rw_exit(bp->dbk_lock);

			/* get an id, ok to sleep for it here */
			id = id_alloc(table->dbt_id_space);

			rw_enter(bp->dbk_lock, RW_WRITER);
			goto retry;
		}
	}

	/* get an exclusive lock on the bucket */
	if (rw_read_locked(bp->dbk_lock) && !rw_tryupgrade(bp->dbk_lock)) {
		rw_exit(bp->dbk_lock);
		rw_enter(bp->dbk_lock, RW_WRITER);
		goto retry;
	}

	/* create entry */
	entry = rfs4_dbe_create(table, id, arg);
	if (entry == NULL) {
		rw_exit(bp->dbk_lock);
		if (id != -1)
			id_free(table->dbt_id_space, id);

		return (NULL);
	}

	/*
	 * Add one ref for entry into table's hash - only one
	 * reference added even though there may be multiple indices
	 */
	rfs4_dbe_hold(entry);
	ENQUEUE(bp->dbk_head, &entry->dbe_indices[idx->dbi_tblidx]);
	VALIDATE_ADDR(entry->dbe_indices[idx->dbi_tblidx].entry);

	already_done = idx->dbi_tblidx;
	rw_exit(bp->dbk_lock);

	for (ip = table->dbt_indices; ip; ip = ip->dbi_inext) {
		if (ip->dbi_tblidx == already_done)
			continue;
		l = &entry->dbe_indices[ip->dbi_tblidx];
		i = HASH(ip, ip->dbi_mkkey(entry->dbe_data));
		ASSERT(i < ip->dbi_table->dbt_len);
		bp = &ip->dbi_buckets[i];
		ENQUEUE_IDX(bp, l);
	}

	return (entry->dbe_data);
}

boolean_t
rfs4_cpr_callb(void *arg, int code)
{
	nfs_server_instance_t *instp;
	rfs4_table_t *table;
	rfs4_bucket_t *buckets, *bp;
	rfs4_link_t *l;
	rfs4_client_t *cp;
	int i;

	if (arg == NULL)
		return (B_TRUE);

	instp = (nfs_server_instance_t *)arg;
	tbl = instp->client_tab;

	/*
	 * We get called for Suspend and Resume events.
	 * For the suspend case we simply don't care!  Nor do we care if
	 * there are no clients.
	 */
	if (code == CB_CODE_CPR_CHKPT || table == NULL) {
		return (B_TRUE);
	}

	buckets = table->dbt_indices->dbi_buckets;

	/*
	 * When we get this far we are in the process of
	 * resuming the system from a previous suspend.
	 *
	 * We are going to blast through and update the
	 * last_access time for all the clients and in
	 * doing so extend them by one lease period.
	 */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		for (l = bp->dbk_head; l; l = l->next) {
			cp = (rfs4_client_t *)l->entry->dbe_data;
			cp->rc_last_access = gethrestime_sec();
		}
	}

	return (B_TRUE);
}

/*
 * Given a table, lock each of the buckets and walk all entries (in
 * turn locking those) and calling the provided "callout" function
 * with the provided parameter.  Obviously used to iterate across all
 * entries in a particular table via the database locking hierarchy.
 * Obviously the caller must not hold locks on any of the entries in
 * the specified table.
 */
void
rfs4_dbe_walk(rfs4_table_t *table,
    void (*callout)(rfs4_entry_t, void *),
    void *data)
{
	rfs4_bucket_t *buckets = table->dbt_indices->dbi_buckets, *bp;
	rfs4_link_t *l;
	rfs4_dbe_t *entry;
	int i;

	/* Walk the buckets looking for entries to release/destroy */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		rw_enter(bp->dbk_lock, RW_READER);
		for (l = bp->dbk_head; l; l = l->next) {
			entry = l->entry;
			mutex_enter(entry->dbe_lock);
			(*callout)(entry->dbe_data, data);
			mutex_exit(entry->dbe_lock);
		}
		rw_exit(bp->dbk_lock);
	}
}

/* ARGSUSED */
static void
rfs4_dbe_reap(rfs4_table_t *table, time_t cache_time, uint32_t desired)
{
	rfs4_index_t *idx = table->dbt_indices;
	rfs4_bucket_t *buckets = idx->dbi_buckets, *bp;
	rfs4_link_t *l, *t;
	rfs4_dbe_t *entry;
	bool_t found;
	int i;
	int count = 0;


	/*
	 * Walk the buckets looking for entries to release/destroy.
	 * Note that we do not need to grab the entry's lock because
	 * the refcnt can only be 0 or 1 if nothing else has a
	 * reference. Once the refcnt transistions to one of these
	 * states (and the entry has been fully created), it is not
	 * allowed to be incremented.
	 */
	for (i = 0; i < table->dbt_len; i++) {
		bp = &buckets[i];
		do {
			/*
			 * First pass is to look for unreferenced entries.
			 */
			found = FALSE;
			rw_enter(bp->dbk_lock, RW_READER);
			for (l = bp->dbk_head; l; l = l->next) {
				entry = l->entry;
				/*
				 * Examine an entry.  Ref count of 1 means
				 * that the only reference is for the hash
				 * table reference.
				 */
				if (entry->dbe_refcnt != 1)
					continue;
				mutex_enter(entry->dbe_lock);
				if ((entry->dbe_refcnt == 1) &&
				    (table->dbt_reaper_shutdown ||
				    table->dbt_expiry == NULL ||
				    (*table->dbt_expiry)(entry->dbe_data))) {
					entry->dbe_refcnt--;
					count++;
					found = TRUE;
				}
				mutex_exit(entry->dbe_lock);
			}

			/*
			 * Second pass is to destroy them.
			 */
			if (found) {
				if (!rw_tryupgrade(bp->dbk_lock)) {
					rw_exit(bp->dbk_lock);
					rw_enter(bp->dbk_lock, RW_WRITER);
				}

				l = bp->dbk_head;
				while (l) {
					t = l;
					entry = t->entry;
					l = l->next;
					if (entry->dbe_refcnt == 0) {
						DEQUEUE(bp->dbk_head, t);
						t->next = NULL;
						t->prev = NULL;
						INVALIDATE_ADDR(t->entry);
						rfs4_dbe_destroy(entry);
					}
				}
			}
			rw_exit(bp->dbk_lock);

			/*
			 * Delay slightly if there is more work to do
			 * with the expectation that other reaper
			 * threads are freeing data structures as well
			 * and in turn will reduce ref counts on
			 * entries in this table allowing them to be
			 * released.  This is only done in the
			 * instance that the tables are being shut down.
			 */
			if (table->dbt_reaper_shutdown && bp->dbk_head != NULL)
				delay(hz/100);
		/*
		 * If this is a table shutdown, keep going until
		 * everything is gone
		 */
		} while (table->dbt_reaper_shutdown && bp->dbk_head != NULL);

		/*
		 * XXX - Is the second clause redundant?
		 */
		if (!table->dbt_reaper_shutdown && desired && count >= desired)
			break;
	}
}


static void
reaper_thread(caddr_t *arg)
{
	rfs4_table_t *table = (rfs4_table_t *)arg;
	clock_t rc, time;

	CALLB_CPR_INIT(&table->dbt_reaper_cpr_info, &table->dbt_reaper_cv_lock,
	    callb_generic_cpr, "nfsv4Reaper");

	time = MIN(rfs4_reap_interval, table->dbt_max_cache_time);
	mutex_enter(&table->dbt_reaper_cv_lock);
	do {
		CALLB_CPR_SAFE_BEGIN(&table->dbt_reaper_cpr_info);
		rc = cv_timedwait_sig(&table->dbt_reaper_wait,
		    &table->dbt_reaper_cv_lock,
		    lbolt + SEC_TO_TICK(time));
		CALLB_CPR_SAFE_END(&table->dbt_reaper_cpr_info,
		    &table->dbt_reaper_cv_lock);
		rfs4_dbe_reap(table, table->dbt_max_cache_time, 0);
	} while (rc != 0 && table->dbt_reaper_shutdown == FALSE);

	CALLB_CPR_EXIT(&table->dbt_reaper_cpr_info);

	/* Notify the database shutdown processing that the table is shutdown */
	mutex_enter(table->dbt_instp->state_store->lock);
	table->dbt_instp->state_store->shutdown_count--;
	cv_signal(&table->dbt_instp->state_store->shutdown_wait);
	mutex_exit(table->dbt_instp->state_store->lock);
}

static void
rfs4_start_reaper(rfs4_table_t *table)
{
	(void) thread_create(NULL, 0, reaper_thread, table, 0, &p0, TS_RUN,
	    minclsyspri);
}

rfs4_entry_t
rfs4_dbcreate(rfs4_index_t *idx, void *ap)
{
	rfs4_index_t	*ip;
	rfs4_table_t	*table;
	rfs4_bucket_t	*bp;
	rfs4_dbe_t	*entry = NULL;
	int		 already_done;
	uint32_t	 i;
	void		*key;

	ASSERT(ap != NULL);
	ASSERT(idx != NULL);
	ASSERT(idx->dbi_table != NULL);
	if (ap == NULL || idx == NULL || idx->dbi_table == NULL)
		return (NULL);
	table = idx->dbi_table;

	/*
	 * Create the desired object
	 */
	if ((entry = rfs4_dbe_create(table, ap)) == NULL)
		return (NULL);
	key = idx->dbi_mkkey(entry->dbe_data);
	i = HASH(idx, key);
	bp = &idx->dbi_buckets[i];

	/*
	 * Add one ref for entry into table's hash - only one
	 * reference added even though there may be multiple indices
	 */
	rw_enter(bp->dbk_lock, RW_WRITER);
	rfs4_dbe_hold(entry);
	ENQUEUE(bp->dbk_head, &entry->dbe_indices[idx->dbi_tblidx]);
	VALIDATE_ADDR(entry->dbe_indices[idx->dbi_tblidx].entry);
	already_done = idx->dbi_tblidx;
	rw_exit(bp->lock);

	/*
	 * Initialize any additional indices to the table,
	 * remembering to skip the primary index (already_done)
	 */
	for (ip = table->dbt_indices; ip; ip = ip->dbi_inext) {
		rfs4_link_t	*l;

		if (ip->dbi_tblidx == already_done)
			continue;
		l = &entry->dbe_indices[ip->dbi_tblidx];
		i = HASH(ip, ip->dbi_mkkey(entry->dbe_data));
		ASSERT(i < ip->dbi_table->len);
		bp = &ip->dbi_buckets[i];
		ENQUEUE_IDX(bp, l);
	}
	return (entry->dbe_data);
}

/*
 * Return the instance pointer from the rfs4_dbe_t
 */
nfs_server_instance_t *
dbe_to_instp(rfs4_dbe_t *dbp)
{
	return (dbp->table->dbt_instp);
}
