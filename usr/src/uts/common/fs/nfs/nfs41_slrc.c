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
#include <sys/atomic.h>
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

/*
 * Slot Table and Slot Cache Management Support
 */

/*
 *  session
 * .- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -.
 * |     sltab                                                                |
 * |    +---------------------------------------------------------+           |
 * |sl0 | se_state  se_lock  se_wait  se_sltno  se_seqid  se_clnt | slot_ent_t|
 * |    +---------------------------------------------------------+           |
 * ` _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _ _'
 *
 *
 * Design Notes:
 *
 * 1) slot table token (stok), created via sltab_create(), is the token by
 *    which the interface consumer instantiates further calls to the API.
 *
 * 2) The stok contains metadata pertinent to _that_ slot table (current
 *    width, current free slots, caller ctxt, state). It also has an overall
 *    cache lock and cv for slot usage and synchronization along with cache
 *    wide manipulation (growth, shrink, etc).
 *
 *    Hence, locking order is as follows for the pertinent interfaces:
 *
 *	sltab_create:
 *			No locking required	<lock initialization>
 *	sltab_destroy:
 *	sltab_resize:
 *			st_lock			<resizing/destruction>
 *	slot_alloc:
 *	slot_free:
 *			st_lock -> se_lock	<slot acquisition/release>
 *
 * 3) sltab_resize will be used to grow/shrink the cache. This  will result
 *    in the entire cache being quiesced while a new array of pointers
 *    (reflecting the new "width") is allocated. These new ptrs will then
 *    be set to the values pointed to by stok->sltab[n]. At this point,
 *    the old slrc pointers will be freed and stok->sltab updated to point
 *    to the newly allocated array of slot pointers.
 *
 *    Bottom line: Consumers of the interface can continue to treat stok
 *		as an opaque token, since resizing (and reallocation) of
 *		the cache happens deep w/in the interfaces, so user remains
 *		happily oblivious.
 */

static int
sltab_slot_cmp(const void *a, const void *b)
{
	const slot_ent_t *ra = (slot_ent_t *)a;
	const slot_ent_t *rb = (slot_ent_t *)b;

	/*
	 * Comparision is with slot id.
	 */
	if (ra->se_sltno  < rb->se_sltno)
		return (-1);
	if (ra->se_sltno > rb->se_sltno)
		return (+1);
	return (0);
}


void
sltab_create(stok_t **handle, int max_slots)
{
	avl_tree_t *tree = NULL;
	stok_t *tok;

	tok  = kmem_alloc(sizeof (stok_t), KM_SLEEP);
	tree = kmem_alloc(sizeof (avl_tree_t), KM_SLEEP);
	avl_create(tree,
	    sltab_slot_cmp,
	    sizeof (slot_ent_t),
	    offsetof(slot_ent_t, se_node));
	mutex_init(&tok->st_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tok->st_wait,  NULL, CV_DEFAULT, NULL);
	tok->st_sltab = tree;
	tok->st_currw = max_slots;
	tok->st_fslots = max_slots;
	*handle = tok;
}

void
sltab_destroy(stok_t *handle)
{
	avl_tree_t *replaytree = handle->st_sltab;
	slot_ent_t *tmp, *next;

	mutex_enter(&handle->st_lock);
	for (tmp = avl_first(replaytree); tmp != NULL; tmp = next) {
		next = AVL_NEXT(replaytree, tmp);
		slot_delete(handle, tmp);
	}
	mutex_exit(&handle->st_lock);
	avl_destroy(replaytree);
	kmem_free(replaytree, sizeof (avl_tree_t));
	cv_destroy(&handle->st_wait);
	mutex_destroy(&handle->st_lock);
	kmem_free(handle, sizeof (stok_t));
	handle = NULL;
}

/*
 * Resize the tree.
 * If the maxslots are decreased, remove the nodes.
 * Set the sc_maxslot entry to the new maxslots.
 */
int
sltab_resize(stok_t *handle, int maxslots)
{
	slot_ent_t *tmp, *phd;
	avl_tree_t *replaytree = handle->st_sltab;
	int more = 0;

	mutex_enter(&handle->st_lock);
	/* Max slots are reduced.. */
	if (handle->st_currw > maxslots) {
		for (tmp = avl_first(replaytree); tmp != NULL;
		    tmp = phd) {
			phd = AVL_NEXT(replaytree, tmp);
			if (tmp->se_sltno > maxslots) {
				slot_delete(handle, tmp);
			}
		}
	} else {
		more = maxslots - handle->st_currw;
		handle->st_fslots += more;
		handle->st_currw = maxslots;
	}
	mutex_exit(&handle->st_lock);
	return (0);
}

void
sltab_query(stok_t *handle, slt_query_t qf, void *res)
{
	ASSERT(handle != NULL);
	ASSERT(res != NULL);

	mutex_enter(&handle->st_lock);
	switch (qf) {
		case SLT_MAXSLOT:
		{
			uint_t *p = (uint_t *)res;
			*p = (slotid4)handle->st_currw;
			break;
		}
		default:
			break;
	}
	mutex_exit(&handle->st_lock);
}

int
slot_delete(stok_t *handle, slot_ent_t *node)
{
	avl_tree_t *replaytree = handle->st_sltab;

	ASSERT(MUTEX_HELD(&handle->st_lock));
	cv_destroy(&node->se_wait);
	mutex_destroy(&node->se_lock);
	avl_remove(replaytree, node);
	kmem_free(node, sizeof (*node));
	node = NULL;
	handle->st_fslots -= 1;
	return (0);
}

slot_ent_t *
sltab_get(stok_t *handle, slotid4 slot)
{
	slot_ent_t *node = NULL, tmp;
	avl_index_t where;
	avl_tree_t *replaytree = handle->st_sltab;

	tmp.se_sltno = slot;
	mutex_enter(&handle->st_lock);
	node = (slot_ent_t *)avl_find(replaytree, &tmp, &where);
	mutex_exit(&handle->st_lock);
	return (node);
}

/*
 * Check if an entry is present or not.
 * If the slot exists, find out if sequences are correct.
 * If its a new slot reply back wth SEQRES_NEWREQ.
 * If its NEWREQ/REPLAY, assign res to that node.
 */
uint_t
slrc_slot_alloc(stok_t *handle, slotid4 slot, sequenceid4 seq, slot_ent_t **res)
{
	slot_ent_t *phd = NULL;
	slot_ent_t *tnode;
	avl_tree_t *replaytree = handle->st_sltab;
	avl_index_t where;
	uint_t	ret;

	/* Check if the node falls within the range. */
	if (slot < 0 || (slot > handle->st_currw - 1)) {
		return (SEQRES_BADSESSION);
	}
	phd = slot_get(handle, slot);
	if (phd != NULL) {
		mutex_enter(&phd->se_lock);
find_again:
		if ((phd->se_state & SLRC_INPROG_NEWREQ) ||
		    (phd->se_state & SLRC_INPROG_REPLAY)) {
			/*
			 * Synchronization problem.
			 * Another process is tyring to update the node.
			 * Wait till its updated and try again.
			 */
			cv_wait(&phd->se_wait, &phd->se_lock);
			goto find_again;
		}
		if (seq == phd->se_seqid) {
			phd->se_state = SLRC_INPROG_REPLAY;
			*res = phd;
			mutex_exit(&phd->se_lock);
			return (SEQRES_REPLAY);
		}
		if (seq == phd->se_seqid + 1) {
			phd->se_state = SLRC_INPROG_NEWREQ;
			*res = phd;
			mutex_exit(&phd->se_lock);
			return (SEQRES_NEWREQ);
		}
		if (seq < phd->se_seqid) {
			mutex_exit(&phd->se_lock);
			return (SEQRES_MISORD_REPLAY);
		}
		if (seq >= phd->se_seqid + 2) {
			mutex_exit(&phd->se_lock);
			return (SEQRES_MISORD_NEWREQ);
		}
		mutex_exit(&phd->se_lock);
		return (SEQRES_BADSESSION);
	}
	/* Create a new slot node. */
	tnode = kmem_zalloc(sizeof (slot_ent_t), KM_SLEEP);
	tnode->se_seqid = 0;
	tnode->se_sltno = slot;
	tnode->se_state = SLRC_INPROG_NEWREQ;
	tnode->se_status = NFS4ERR_SEQ_MISORDERED;
	mutex_init(&tnode->se_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tnode->se_wait,  NULL, CV_DEFAULT, NULL);
	mutex_enter(&handle->st_lock);
	phd =  (slot_ent_t *)avl_find(replaytree, tnode, &where);
	if (phd == NULL) {
		avl_insert(replaytree, tnode, where);
		ret = SEQRES_NEWREQ;
		*res = tnode;
	} else {
		mutex_destroy(&tnode->se_lock);
		cv_destroy(&tnode->se_wait);
		kmem_free(tnode, sizeof (slot_ent_t));
		ret = SEQRES_MISORD_NEWREQ;
	}
	mutex_exit(&handle->st_lock);
	return (ret);
}


int
slot_alloc(stok_t  *handle, slt_wait_t f, slot_ent_t **res)
{
	avl_tree_t *replaytree = handle->st_sltab;
	slot_ent_t *tmp = NULL, *phd, *tnode = NULL;
	uint_t		i, ret = 0;
	avl_index_t where;

	ASSERT(handle != NULL);
	ASSERT(handle->st_sltab->avl_numnodes <= handle->st_currw);

retry:
	for (i = 0; i < handle->st_currw; i++) {
		tmp =  slot_get(handle, i);
		if (tmp == NULL) {
			tnode = kmem_zalloc(sizeof (slot_ent_t),
			    KM_SLEEP);
			mutex_enter(&handle->st_lock);
			tnode->se_seqid = 1;
			tnode->se_sltno = i;
			tnode->se_state = SLOT_INUSE;
			mutex_init(&tnode->se_lock, NULL, MUTEX_DEFAULT, NULL);
			cv_init(&tnode->se_wait,  NULL, CV_DEFAULT, NULL);
			phd =  (slot_ent_t *)avl_find(replaytree,
			    tnode, &where);
			if (phd == NULL) {
				avl_insert(replaytree, tnode, where);
				handle->st_fslots -= 1;
				*res = tnode;
				mutex_exit(&handle->st_lock);
				return (ret);
			} else {
				/*
				 * Somebody already snuck in a slot
				 * continue with the search
				 */
				cv_destroy(&tnode->se_wait);
				mutex_destroy(&tnode->se_lock);
				kmem_free(tnode, sizeof (slot_ent_t));
				mutex_exit(&handle->st_lock);
				continue;
			}
		} else {
			mutex_enter(&handle->st_lock);
			mutex_enter(&tmp->se_lock);
			if (tmp->se_state & SLOT_FREE) {
				tmp->se_state = SLOT_INUSE;
				handle->st_fslots -= 1;
				*res = tmp;
				mutex_exit(&tmp->se_lock);
				mutex_exit(&handle->st_lock);
				return (ret);
			}
			mutex_exit(&tmp->se_lock);
			mutex_exit(&handle->st_lock);
		}
	}
	if (f == SLT_NOSLEEP) {
		res = NULL;
		return (NULL);
	}

	ASSERT(f == SLT_SLEEP);

	/*
	 * wait for a free slot
	 */
	mutex_enter(&handle->st_lock);
	while (handle->st_fslots < 1)
		cv_wait(&handle->st_wait, &handle->st_lock);
	mutex_exit(&handle->st_lock);

	/*
	 * try for a free slot again
	 */
	goto retry;

}

void
slot_incr_seq(slot_ent_t *p, int incr)
{
	atomic_add_32(&p->se_seqid, incr);
}

void
slot_free(stok_t *handle, slot_ent_t *p)
{
	ASSERT(handle != NULL);

	mutex_enter(&handle->st_lock);
	mutex_enter(&p->se_lock);

	p->se_state = SLOT_FREE;
	handle->st_fslots += 1;
	ASSERT(handle->st_fslots <= handle->st_currw);
	mutex_exit(&p->se_lock);
	cv_signal(&handle->st_wait);
	mutex_exit(&handle->st_lock);
}


nfsstat4
slot_cb_status(stok_t *handle)
{
	avl_tree_t	*replaytree = handle->st_sltab;
	nfsstat4	status = NFS4_OK;
	slot_ent_t *tmp = NULL, *next;

	/*
	 * If there is even one CB call outstanding, error off;
	 * Slot is still in use, session cannot be destroyed.
	 */
	ASSERT(handle != NULL);

	mutex_enter(&handle->st_lock);
	for (tmp = avl_first(replaytree); tmp != NULL; tmp = next) {
		next = AVL_NEXT(replaytree, tmp);
		mutex_enter(&tmp->se_lock);
		if (tmp->se_state & SLOT_INUSE) {
			status = NFS4ERR_BACK_CHAN_BUSY;
			mutex_exit(&tmp->se_lock);
			break;
		}
		tmp->se_state = SLOT_FREE;
		handle->st_fslots += 1;
		mutex_exit(&tmp->se_lock);
	}
	mutex_exit(&handle->st_lock);
	return (status);
}

void
slot_set_state(slot_ent_t *slot, int state)
{
	mutex_enter(&slot->se_lock);	/* grab slot lock */
	slot->se_state |= state;
	mutex_exit(&slot->se_lock);
}

void
slot_error_to_inuse(slot_ent_t *slot)
{
	mutex_enter(&slot->se_lock);
	ASSERT(slot->se_state & SLOT_ERROR);
	ASSERT(slot->se_state & SLOT_INUSE);
	slot->se_state &= ~SLOT_ERROR;
	mutex_exit(&slot->se_lock);
}

int
slot_mark(stok_t *handle, slotid4 slid, sequenceid4 seqid)
{
	slot_ent_t *slot;

	ASSERT(handle != NULL);
	mutex_enter(&handle->st_lock);

	if (slid < 0 || slid >= handle->st_currw) {
		mutex_exit(&handle->st_lock);
		return (0);
	}

	mutex_exit(&handle->st_lock);
	slot = slot_get(handle, slid);
	mutex_enter(&slot->se_lock);	/* grab slot lock */

	/*
	 * no race. slot has already been used.
	 */
	if ((slot->se_state & SLOT_FREE) ||
	    (slot->se_state & SLOT_ERROR) ||
	    (slot->se_seqid != seqid)) {
		mutex_exit(&slot->se_lock);
		return (0);
	}

	slot->se_state |= SLOT_RECALLED;
	mutex_exit(&slot->se_lock);
	return (1);
}


/*
 * No particular place to put this, so might as well be here
 */
uint32_t
pow2(uint32_t x)		/* k = 2^x */
{
	uint32_t j;
	uint32_t k;

	if (x == 0)
		return (1);

	for (j = 1, k = 1; j <= x; j++)
		k *= 2;

	return (k);
}

uint32_t
log2(uint32_t x)		/* k = log2(x) */
{
	uint32_t k;

	for (k = 0; ; x >>= 1, k++)
		if (x & 1 || k == BITS_PER_WORD)
			break;
	return (k);
}

void
slrc_table_create(stok_t **handle, int max_slots)
{
	(void) sltab_create(handle, max_slots);
}

void
slrc_table_destroy(stok_t *handle)
{
	(void) sltab_destroy(handle);
}

void
slrc_table_resize(stok_t *handle, int max_slots)
{
	(void) sltab_resize(handle, max_slots);
}

void
slrc_table_query(stok_t *handle, slt_query_t q, void *res)
{
	(void) sltab_query(handle, q, res);
}

slot_ent_t *
slrc_slot_get(stok_t *handle, slotid4 slot)
{
	return (sltab_get(handle, slot));
}


void
slot_table_create(stok_t **handle, int max_slots)
{
	(void) sltab_create(handle, max_slots);
}

void
slot_table_destroy(stok_t *handle)
{
	(void) sltab_destroy(handle);
}

void
slot_table_resize(stok_t *handle, int max_slots)
{
	(void) sltab_resize(handle, max_slots);
}

void
slot_table_query(stok_t *handle, slt_query_t q, void *res)
{
	(void) sltab_query(handle, q, res);
}

slot_ent_t *
slot_get(stok_t *handle, slotid4 slot)
{
	return (sltab_get(handle, slot));
}
