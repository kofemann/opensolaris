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

#include <nfs/range_impl.h>

#include <nfs/nfs.h>

#include <sys/debug.h>

static kmem_cache_t *nfs_range_cache;
static kmem_cache_t *nfs_subrange_cache;

static nfs_subrange_t *nfs_subrange_create(uint64_t, uint64_t);
static void nfs_subrange_destroy(nfs_subrange_t *);
static void nfs_range_clearall(nfs_range_t *);

typedef int (*nfs_subrange_criteria_t)(nfs_subrange_t *, uint64_t);

/*
 * Returns true if the given offset is within the subrange, or if it's the
 * very next byte above (and thus could be "subsumed" into the subrange).
 */

static int
nfs_subrange_subsumes(nfs_subrange_t *sub, uint64_t off)
{
	if (sub == NULL)
		return (B_FALSE);

	ASSERT(sub->ns_off + sub->ns_len == sub->ns_end);

	if (off < sub->ns_off)
		return (B_FALSE);

	if (sub->ns_end >= off)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Returns true if the given offset is within the subrange.
 */

static int
nfs_subrange_contains(nfs_subrange_t *sub, uint64_t off)
{
	if (sub == NULL)
		return (B_FALSE);

	ASSERT(sub->ns_off + sub->ns_len == sub->ns_end);

	if (off < sub->ns_off)
		return (B_FALSE);

	if (sub->ns_end > off)
		return (B_TRUE);

	return (B_FALSE);
}

/*
 * Grow the subrange to end at the given offset.  The given offset
 * must be greater than the subrange's starting offset.  No effect
 * if the subrange would not grow.
 */

static void
nfs_subrange_growto(nfs_subrange_t *sub, uint64_t off)
{
	ASSERT(off > sub->ns_off);
	ASSERT(sub->ns_off + sub->ns_len == sub->ns_end);

	if (off > sub->ns_end) {
		sub->ns_end = off;
		sub->ns_len = sub->ns_end - sub->ns_off;
	}
}

/*
 * Shrink the subrange to end at the given offset.  The given offset
 * must be greater than the subrange's starting offset.  No effect if
 * the subrange would not shrink.
 */

static void
nfs_subrange_shrinkto(nfs_subrange_t *sub, uint64_t off)
{
	ASSERT(off > sub->ns_off);
	ASSERT(sub->ns_off + sub->ns_len == sub->ns_end);

	if (sub->ns_end > off) {
		sub->ns_end = off;
		sub->ns_len = sub->ns_end - sub->ns_off;
	}
}

/*
 * Shrink the subrange by moving its starting offset forward.  The given
 * starting offset must be within the subrange; the given offset may be
 * equal to the subrange's starting offset, in which case it will have
 * no effect.
 */

static void
nfs_subrange_shrinkfront(nfs_subrange_t *sub, uint64_t off)
{
	ASSERT(nfs_subrange_contains(sub, off));
	ASSERT(sub->ns_off + sub->ns_len == sub->ns_end);

	sub->ns_off = off;
	sub->ns_len = sub->ns_end - sub->ns_off;
}

/*
 * Find a subrange that is at or below the given offset.  The criteria
 * function is used to tell whether a subrange starting below a given
 * offset may be used; typically, "contains" is used to find a subrange
 * containing the given offset, and "subsumes" is used when trying to
 * find a subrange below that may subsume the given offset.
 */

static nfs_subrange_t *
nfs_subrange_find(nfs_range_t *range, uint64_t off, avl_index_t *where,
    nfs_subrange_criteria_t criteria)
{
	nfs_subrange_t key, *found;

	ASSERT(RW_LOCK_HELD(&range->nr_lock));

	key.ns_off = off;
	found = avl_find(&range->nr_tree, &key, where);
	if (found != NULL)
		return (found);

	found = avl_nearest(&range->nr_tree, *where, AVL_BEFORE);
	if (criteria(found, off))
		return (found);

	return (NULL);
}

/*
 * Set a given offset and length within a range.  offset + length must be
 * a valid 64-bit unsigned integer.
 */

nfs_range_query_t
nfs_range_set(nfs_range_t *range, uint64_t offset, uint64_t length)
{
	nfs_subrange_t *set = NULL;
	nfs_subrange_t *anchor, *victim;
	avl_index_t where;

	/*
	 * Optimize out the case where every possible subrange is
	 * already set, and the dumb case that we're being requested
	 * to set an empty subrange.
	 */
	if ((range->nr_status == NFS_RANGE_ALL) || (length == 0))
		return (range->nr_status);

	/*
	 * Create a subrange representing the requested offset/length.
	 * This may be inserted into nr_tree, and set->ns_end will be
	 * used regardless.
	 */
	set = nfs_subrange_create(offset, length);

	rw_enter(&range->nr_lock, RW_WRITER);

	/*
	 * Two more cases can be optimized: setting offset 0, length
	 * NFS_RANGE_MAX, or setting anything when the current
	 * status is NFS_RANGE_NONE.  In either case, the subrange
	 * to be set will comprise the entire nr_tree.
	 */
	if ((range->nr_status == NFS_RANGE_NONE) ||
	    ((offset == 0) && (length == NFS_RANGE_MAX))) {
		nfs_subrange_t *v;

		if (range->nr_status != NFS_RANGE_NONE)
			nfs_range_clearall(range);
		v = avl_find(&range->nr_tree, set, &where);
		ASSERT(v == NULL);
		avl_insert(&range->nr_tree, set, where);
		set = NULL;
		goto done;
	}

	/*
	 * Deal with the "front end" of the requested subrange first.
	 * anchor will be any existing subrange that overlaps or touches
	 * the beginning offset of the subrange we're setting.
	 */
	anchor = nfs_subrange_find(range, set->ns_off, &where,
	    nfs_subrange_subsumes);

	/*
	 * If the subrange we found extends to the end of what we have
	 * been requested to set, then we're done!  I.e. everything is
	 * already set; bail out.
	 */
	if (nfs_subrange_subsumes(anchor, set->ns_end))
		goto done;

	/*
	 * If we found an existing subrange that overlaps with the front
	 * of what we're setting, grow that subrange to envelop the
	 * newly requested subrange.
	 */
	if (anchor != NULL) {
		nfs_subrange_growto(anchor, set->ns_end);
	/*
	 * If we did not find an existing subrange that overlapped the
	 * front of the subrange we're setting, then we add our subrange
	 * to the tree of set subranges.  We set "anchor" to the value
	 * of our new subrange, so that the rest of the code below will
	 * work.  We set "set" to NULL, so that it doesn't get destroyed
	 * at the end of this function.
	 */
	} else {
		anchor = set;
		set = NULL;
		avl_insert(&range->nr_tree, anchor, where);
	}

	/*
	 * At this point, we have successfuly set the requested subrange
	 * within our range.  The only remaining problem is that the
	 * subrange containing the requested subrange, "anchor", may be
	 * overlapping other subranges within the overall tree.  We
	 * must walk forward and deal with any other subranges that are
	 * touching "anchor".
	 */
	for (victim = avl_walk(&range->nr_tree, anchor, AVL_AFTER);
	    victim != NULL;
	    victim = avl_walk(&range->nr_tree, anchor, AVL_AFTER)) {
		if (victim->ns_off > anchor->ns_end)
			break;

		/*
		 * We now have "victim", which is a subrange that
		 * touches "anchor".  There are two possibilities:
		 * victim is entirely contained within anchor, or
		 * victim extends beyond anchor.  Fortunately,
		 * nfs_subrange_growto() does exactly what we want.
		 * If victim extends beyond anchor, then anchor
		 * will grow to envelop victim.  If not, then
		 * nfs_subrange_growto() will have no effect.
		 */
		nfs_subrange_growto(anchor, victim->ns_end);
		/*
		 * anchor now fully contains victim, so there is
		 * no need for victim.  Purge!
		 */
		avl_remove(&range->nr_tree, victim);
		nfs_subrange_destroy(victim);
	}

done:
	/*
	 * nr_tree now fully represents the range, updated to set
	 * the requested subrange.  The only thing left to do is to
	 * set nr_status correctly.
	 */
	if (avl_numnodes(&range->nr_tree) == 1) {
		nfs_subrange_t *all;

		all = avl_first(&range->nr_tree);
		if ((all->ns_off == 0) && (all->ns_len == NFS_RANGE_MAX))
			range->nr_status = NFS_RANGE_ALL;
		else
			range->nr_status = NFS_RANGE_SOME;
	} else
		range->nr_status = NFS_RANGE_SOME;

	rw_exit(&range->nr_lock);

	if (set != NULL)
		nfs_subrange_destroy(set);

	return (range->nr_status);
}

/*
 * Clear an offset and length within a range.  offset + length must be a
 * valid unsigned 64-bit integer.
 */

nfs_range_query_t
nfs_range_clear(nfs_range_t *range, uint64_t offset, uint64_t length)
{
	nfs_subrange_t *clear, *next, *victim;
	avl_index_t where;

	/*
	 * Optimize out the silly cases of clearing when everything is
	 * already clear, and clearing an empty subrange.
	 */
	if ((range->nr_status == NFS_RANGE_NONE) || (length == 0))
		return (range->nr_status);

	/*
	 * Create a subrange representing the subrange we're requesting
	 * to clear.  Even though this will never be inserted into
	 * nr_tree, it will allow us to use the nfs_subrange_*() functions
	 * for testing whether things fall into the subrange to be
	 * cleared.
	 */
	clear = nfs_subrange_create(offset, length);

	rw_enter(&range->nr_lock, RW_WRITER);

	/*
	 * Optimize the case where the entire possible range is being
	 * cleared.
	 */
	if ((clear->ns_off == 0) && (clear->ns_len == NFS_RANGE_MAX)) {
		nfs_range_clearall(range);
		goto done;
	}

	/*
	 * Deal with the front first.  Find any subrange that contains
	 * the starting offset of the range to be cleared.
	 */
	victim = nfs_subrange_find(range, clear->ns_off, &where,
	    nfs_subrange_contains);

	/*
	 * If nothing was found, then set "victim" to be the next higher
	 * subrange.  It will be used in the code below.
	 */
	if (victim == NULL) {
		next = avl_nearest(&range->nr_tree, where, AVL_AFTER);
	/*
	 * If "victim" begins before the beginning of "clear", then
	 * We have to shorten victim to only include offsets below
	 * the starting offset of clear.  This will be done in the
	 * call to nfs_subrange_shrinkto() below.
	 */
	} else if (victim->ns_off < clear->ns_off) {
		/*
		 * Additionally, if victim extends beyond the end
		 * of clear, we have split victim into two subranges.
		 * We need to create a new subrange to represent the
		 * second part.
		 */
		if (nfs_subrange_contains(victim, clear->ns_end)) {
			nfs_subrange_t *new;

			new = nfs_subrange_create(clear->ns_end,
			    victim->ns_end - clear->ns_end);
			avl_insert_here(&range->nr_tree, new, victim,
			    AVL_AFTER);
		}
		nfs_subrange_shrinkto(victim, clear->ns_off);
		next = avl_walk(&range->nr_tree, victim, AVL_AFTER);
	}

	/*
	 * At this point, "clear" still represents the subrange to be
	 * cleared, and "next" represents the next subrange after the
	 * starting offset of "clear".  We iterate through any more
	 * subranges that may contain offsets contained within
	 * "clear".
	 */
	while (next != NULL) {
		if (next->ns_off >= clear->ns_end)
			break;
		victim = next;

		/*
		 * If "victim" contains the end of our subrange to be
		 * cleared, then we need to shrink victim from the
		 * front.  Note that the length of victim will not be
		 * zero after this point, because victim contains
		 * the offset clear->ns_end.
		 */
		if (nfs_subrange_contains(victim, clear->ns_end)) {
			nfs_subrange_shrinkfront(victim, clear->ns_end);
			break;
		}

		/*
		 * If we get to this point, then we know that "clear"
		 * extends beyond the end of "victim".  Thus, the entire
		 * subrange "victim" is to be cleared, and thus we simply
		 * remove it from nr_tree.
		 */
		next = avl_walk(&range->nr_tree, victim, AVL_AFTER);
		avl_remove(&range->nr_tree, victim);
		nfs_subrange_destroy(victim);
	}

done:
	/*
	 * At this point, nr_tree is up to date, and nr_status must be
	 * adjusted.  Since we just cleared something, we know that the
	 * status cannot be NFS_RANGE_ALL.  We just need to check whether
	 * it is NFS_RANGE_NONE or not.
	 */
	if (avl_numnodes(&range->nr_tree) == 0)
		range->nr_status = NFS_RANGE_NONE;
	else
		range->nr_status = NFS_RANGE_SOME;
	rw_exit(&range->nr_lock);
	nfs_subrange_destroy(clear);

	return (range->nr_status);
}

/*
 * Query whether the subrange specified by *offp and *lenp is set.  Returns
 * NFS_RANGE_NONE if the offset is not set, even if other bytes within the
 * subrange are set.  If the offset is set, returns NFS_RANGE_ALL if the
 * entire subrange is set, and NFS_RANGE_SOME otherwise.  If the result
 * is NFS_RANGE_SOME, the length (*lenp) is lowered such that the new value
 * specifies a subrange that is entirely set.
 */

/*ARGSUSED*/
nfs_range_query_t
nfs_range_is_set(nfs_range_t *range, uint64_t *offp, uint64_t *lenp,
    uint32_t flags)
{
	nfs_range_query_t rc;
	nfs_subrange_t *sub;
	avl_index_t where;

	if (range->nr_status == NFS_RANGE_ALL)
		return (NFS_RANGE_ALL);

	rw_enter(&range->nr_lock, RW_READER);

	sub = nfs_subrange_find(range, *offp, &where, nfs_subrange_contains);
	if (sub == NULL) {
		rc = NFS_RANGE_NONE;
	} else if (nfs_subrange_subsumes(sub, *offp + *lenp)) {
		rc = NFS_RANGE_ALL;
	} else {
		rc = NFS_RANGE_SOME;
		*lenp = sub->ns_end - *offp;
	}

	rw_exit(&range->nr_lock);

	return (rc);
}

/*
 * Query whether the subrange specified by *offp and *lenp is clear.
 * Returns NFS_RANGE_NONE if the starting offset is not clear, even if
 * other bytes within the subrange are clear.
 *
 * Returns NFS_RANGE_ALL if the entire requested subrange is clear,
 * NFS_RANGE_SOME if the initial offset is clear but not the entire
 * subrange, and NFS_RANGE_NONE otherwise.
 *
 * If NFS_RANGE_SOME is returned, *lenp is adjusted such that the
 * entire length will be clear.
 */

/*ARGSUSED*/
nfs_range_query_t
nfs_range_is_clear(nfs_range_t *range, uint64_t *offp, uint64_t *lenp,
    uint32_t flags)
{
	nfs_range_query_t rc;
	nfs_subrange_t *sub;
	avl_index_t where;

	if (range->nr_status == NFS_RANGE_NONE)
		return (NFS_RANGE_ALL);

	rw_enter(&range->nr_lock, RW_READER);
	sub = nfs_subrange_find(range, *offp, &where, nfs_subrange_contains);
	if (sub != NULL) {
		rc = NFS_RANGE_NONE;
		goto done;
	}
	sub = avl_nearest(&range->nr_tree, where, AVL_AFTER);
	if ((sub != NULL) && (sub->ns_off < *offp + *lenp)) {
		rc = NFS_RANGE_SOME;
		*lenp = sub->ns_off - *offp;
	} else {
		rc = NFS_RANGE_ALL;
	}

done:
	rw_exit(&range->nr_lock);

	return (rc);
}

static nfs_subrange_t *
nfs_subrange_create(uint64_t off, uint64_t len)
{
	nfs_subrange_t *sub;

	sub = kmem_cache_alloc(nfs_subrange_cache, KM_SLEEP);
	sub->ns_off = off;
	sub->ns_len = len;
	sub->ns_end = off + len;

	return (sub);
}

static void
nfs_subrange_destroy(nfs_subrange_t *sub)
{
	kmem_cache_free(nfs_subrange_cache, sub);
}

nfs_range_t *
nfs_range_create(void)
{
	nfs_range_t *rc;

	rc = kmem_cache_alloc(nfs_range_cache, KM_SLEEP);
	rc->nr_status = NFS_RANGE_NONE;

	return (rc);
}

static void
nfs_range_clearall(nfs_range_t *range)
{
	void *cookie = NULL;
	nfs_subrange_t *sub;

	while ((sub = avl_destroy_nodes(&range->nr_tree, &cookie)) != NULL)
		nfs_subrange_destroy(sub);
	range->nr_status = NFS_RANGE_NONE;
}

void
nfs_range_destroy(nfs_range_t *range)
{
	nfs_range_clearall(range);

	kmem_cache_free(nfs_range_cache, range);
}

static int
nfs_subrange_compare(const void *va, const void *vb)
{
	const nfs_subrange_t *a = va;
	const nfs_subrange_t *b = vb;

	NFS_AVL_COMPARE(a->ns_off, b->ns_off);

	return (0);
}

/*ARGSUSED*/
static int
nfs_range_construct(void *vrange, void *foo, int bar)
{
	nfs_range_t *range = vrange;

	avl_create(&range->nr_tree, nfs_subrange_compare,
	    sizeof (nfs_subrange_t), offsetof(nfs_subrange_t, ns_avl));
	rw_init(&range->nr_lock, NULL, RW_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
nfs_range_destruct(void *vrange, void *foo)
{
	nfs_range_t *range = vrange;

	rw_destroy(&range->nr_lock);
	avl_destroy(&range->nr_tree);
}

#ifdef NFS_RANGE_TEST
void
nfs_range_test(void)
{
	nfs_range_query_t q;
	nfs_range_t *range;
	uint64_t off, len;

	printf("nfs_range_test begins");

	range = nfs_range_create();
	printf("range is %p", range);
	q = nfs_range_set(range, 0, 0);
	ASSERT(q == NFS_RANGE_NONE);

	off = 0;
	len = ~0;
	q = nfs_range_is_clear(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_NONE);

	q = nfs_range_set(range, 0, ~0);
	ASSERT(q == NFS_RANGE_ALL);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	ASSERT(len == ~0);

	q = nfs_range_set(range, 1, 1);
	ASSERT(q == NFS_RANGE_ALL);

	q = nfs_range_clear(range, 0, 1);
	ASSERT(q == NFS_RANGE_SOME);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_NONE);
	len = 1;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_NONE);
	q = nfs_range_is_clear(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	len = 1024;
	q = nfs_range_is_clear(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(len == 1);

	q = nfs_range_clear(range, 2, 2);
	ASSERT(q == NFS_RANGE_SOME);
	off = 1;
	len = 30;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(len == 1);
	off = 3;
	len = 1024;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_NONE);
	off = 4;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	ASSERT(len == 1024);
	q = nfs_range_set(range, 3, 1);
	ASSERT(q == NFS_RANGE_SOME);
	q = nfs_range_set(range, 2, 1024);
	ASSERT(q == NFS_RANGE_SOME);

	q = nfs_range_clear(range, 1, ~0 - 1);
	ASSERT(q == NFS_RANGE_NONE);

	q = nfs_range_set(range, 0, 10);
	ASSERT(q == NFS_RANGE_SOME);
	off = 0;
	len = 11;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(off == 0);
	ASSERT(len == 10);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	ASSERT(off == 0);
	ASSERT(len == 10);
	q = nfs_range_clear(range, 10, 100);
	ASSERT(q == NFS_RANGE_SOME);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_ALL);
	ASSERT(off == 0);
	ASSERT(len == 10);
	q = nfs_range_clear(range, 1, 1);
	ASSERT(q == NFS_RANGE_SOME);
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(off == 0);
	ASSERT(len == 1);
	off += len;
	len = 1024;
	q = nfs_range_is_clear(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(off == 1);
	ASSERT(len == 1);
	off += len;
	len = 1024;
	q = nfs_range_is_set(range, &off, &len, 0);
	ASSERT(q == NFS_RANGE_SOME);
	ASSERT(off == 2);
	ASSERT(len == 8);
	for (off = 0; off < 9; off++) {
		q = nfs_range_clear(range, off, 1);
		ASSERT(q == NFS_RANGE_SOME);
	}
	ASSERT(off == 9);
	q = nfs_range_clear(range, off, 1);
	ASSERT(q == NFS_RANGE_NONE);

	q = nfs_range_set(range, 1024, 1024);
	ASSERT(q == NFS_RANGE_SOME);
	q = nfs_range_clear(range, 0, ~0);
	ASSERT(q == NFS_RANGE_NONE);

	nfs_range_destroy(range);

	printf("nfs_range_test passed");
}
#endif /* NFS_RANGE_TEST */

void
nfs_range_init(void)
{
	nfs_subrange_cache = kmem_cache_create("nfs_subrange_cache",
	    sizeof (nfs_subrange_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	nfs_range_cache = kmem_cache_create("nfs_range_cache",
	    sizeof (nfs_range_t), 0,
	    nfs_range_construct, nfs_range_destruct, NULL,
	    NULL, NULL, 0);
}

void
nfs_range_fini(void)
{
	kmem_cache_destroy(nfs_subrange_cache);
	kmem_cache_destroy(nfs_range_cache);
}
