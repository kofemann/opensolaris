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

/*
 * Create a slot table to use for 'client-side' sessions.
 */
void *
sltab_create(uint_t width)
{
	stok_t		 *tp;
	slot_ent_t	**t;
	uint_t		  i;

	if (width == 0)
		return (NULL);

	tp = (stok_t *)kmem_zalloc(sizeof (stok_t), KM_SLEEP);
	t = tp->st_sltab = kmem_zalloc(width * sizeof (slot_ent_t *), KM_SLEEP);
	mutex_init(&tp->st_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&tp->st_wait, NULL, CV_DEFAULT, NULL);
	for (i = 0; i < width; i++) {
		t[i] = (slot_ent_t *)kmem_zalloc(sizeof (slot_ent_t), KM_SLEEP);
		mutex_init(&t[i]->se_lock, NULL, MUTEX_DEFAULT, NULL);
		cv_init(&t[i]->se_wait, NULL, CV_DEFAULT, NULL);
		t[i]->se_seqid = 1;
		t[i]->se_sltno = i;
		t[i]->se_state = SLOT_FREE;
	}
	tp->st_fslots = tp->st_currw = width;
	return ((void *)tp);
}

/*
 * To grow or shrink the slot table, we won't be destroying the opaque
 * token. We'll merely resize the table accordingly and adjusting the
 * accounting, but new slot_XXX callers should remain oblivious as to
 * the new size of the slot table.
 */
/*ARGSUSED*/
uint_t
sltab_resize(void *stt, uint_t ns)
{
	return (0);
}

void
sltab_query(void *stt, slt_query_t qf, void *res)
{
	stok_t	*sttp = (stok_t *)stt;

	ASSERT(sttp != NULL);
	ASSERT(res != NULL);

	mutex_enter(&sttp->st_lock);
	switch (qf) {
		case SLT_MAXSLOT:
		{
			uint_t	*p = (uint_t *)res;
			*p = (slotid4)sttp->st_currw;
			break;
		}
		default:
			break;
	}
	mutex_exit(&sttp->st_lock);
}

/*
 * nuke slot table associated with 'stt' token
 */
void
sltab_destroy(void *stt)
{
	stok_t		 *sttp = (stok_t *)stt;
	slot_ent_t	**t;
	uint_t		  i;

	ASSERT(sttp != NULL);
	if (sttp == NULL)
		return;

	for (i = 0, t = sttp->st_sltab; i < sttp->st_currw; i++) {
		cv_destroy(&t[i]->se_wait);
		mutex_destroy(&t[i]->se_lock);
		kmem_free(t[i], sizeof (slot_ent_t));
	}
	cv_destroy(&sttp->st_wait);
	mutex_destroy(&sttp->st_lock);
	kmem_free(sttp->st_sltab, sttp->st_currw * sizeof (slot_ent_t *));
	kmem_free(sttp, sizeof (stok_t));
}

/*
 * NOTE: Callers of slot_alloc() interface are responsible for the
 *	 correct behavior in the SLT_SLEEP case, in which obviously
 *	 this interface blocks.
 *
 * slt_arg_t
 *      sltno			- alloc a 'specific' slot
 *	flags
 *		SA_SLOT_ANY	- 'any' slot will do
 *		SA_SLOT_SPEC	- only slot specified by 'sltno' will do
 * slt_wait_t
 *	SLT_NOSLEEP		- don't wait/block if all slots are used
 *	SLT_SLEEP		- wait/block until [spec/any] slot is avail
 *
 * lock order: st_lock -> se_lock
 */
slot_ent_t *
slot_alloc(void *stt, slt_wait_t f, slt_arg_t *argp)
{
	stok_t		*sttp = (stok_t *)stt;
	slot_ent_t	*p;
	uint_t		 i;

	ASSERT(sttp != NULL);
	mutex_enter(&sttp->st_lock);
	if (argp == NULL)
		goto retry;			/* no arg == SA_SLOT_ANY */

	if (argp->sa_flags & SA_SLOT_SPEC) {		/* fast path */
		slotid4	slid = argp->sa_sltno;

		if (slid < 0 || slid >= sttp->st_currw) {
			mutex_exit(&sttp->st_lock);
			return (NULL);
		}
		p = sttp->st_sltab[slid];
		mutex_enter(&p->se_lock);	/* grab slot lock */
		mutex_exit(&sttp->st_lock);	/* rele table lock */

		if (p->se_state == SLOT_INUSE && f == SLT_NOSLEEP) {
			/* don't wait for it if it's in use */
			mutex_exit(&p->se_lock);
			return (NULL);
		}

		/*
		 * NB - if we cv_wait, this thread will block and p->se_lock
		 * will be freed, obviously. However, if we encapsulate the
		 * slot's mutex with the table's mutex, we are sure to lock
		 * out any other threads from releasing their slots (since
		 * they cannot acquire the table's mutex) and hence, no
		 * progress would be made.
		 */
		while (p->se_state == SLOT_INUSE)
			cv_wait(&p->se_wait, &p->se_lock);
		ASSERT(p->se_state == SLOT_FREE);
		p->se_state = SLOT_INUSE;
		atomic_add_32(&sttp->st_fslots, -1);	/* see NB above */
		mutex_exit(&p->se_lock);
		return (p);
	}

retry:	/* SA_SLOT_ANY */
	for (i = 0; i < sttp->st_currw; i++) {
		p = sttp->st_sltab[i];

		mutex_enter(&p->se_lock);
		if (p->se_state == SLOT_FREE) {
			p->se_state = SLOT_INUSE;
			sttp->st_fslots -= 1;
			mutex_exit(&p->se_lock);
			mutex_exit(&sttp->st_lock);
			return (p);
		}
		mutex_exit(&p->se_lock);
	}

	if (f == SLT_NOSLEEP) {
		mutex_exit(&sttp->st_lock);
		return (NULL);
	}

	ASSERT(f == SLT_SLEEP);
	while (sttp->st_fslots < 1)
		cv_wait(&sttp->st_wait, &sttp->st_lock);
	goto retry;
	/* NOTREACHED */
}

/*
 * 1) change slot's state, update accounting
 * 2) cv_signal any 'specific' slot waiters
 * 3) cv_signal any 'generic' slot waiters
 * 4) release slot's and table's lock
 */
void
slot_free(void *stt, slot_ent_t *p)
{
	stok_t	*sttp = (stok_t *)stt;

	ASSERT(sttp != NULL);
	mutex_enter(&sttp->st_lock);
	mutex_enter(&p->se_lock);

	p->se_state = SLOT_FREE;
	sttp->st_fslots += 1;
	ASSERT(sttp->st_fslots <= sttp->st_currw);

	cv_signal(&p->se_wait);
	mutex_exit(&p->se_lock);
	cv_signal(&sttp->st_wait);
	mutex_exit(&sttp->st_lock);
}

nfsstat4
slot_cb_status(void *stt)
{
	stok_t		*sttp = (stok_t *)stt;
	nfsstat4	 status = NFS4_OK;
	slot_ent_t	*p;
	uint_t		 i;

	/*
	 * If there is even one CB call outstanding, error off;
	 * Slot is still in use, session cannot be destroyed.
	 */
	ASSERT(sttp != NULL);
	mutex_enter(&sttp->st_lock);
	for (i = 0; i < sttp->st_currw; i++) {

		p = sttp->st_sltab[i];
		mutex_enter(&p->se_lock);
		if (p->se_state == SLOT_INUSE) {
			status = NFS4ERR_BACK_CHAN_BUSY;
			mutex_exit(&p->se_lock);
			break;
		} else {
			/* slot not in use */
			if (p->se_clnt != NULL) {
				CLIENT  *ch = p->se_clnt;
				AUTH    *ap = ch->cl_auth;

				if (ap)
					AUTH_DESTROY(ap);
				CLNT_DESTROY(ch);
				p->se_clnt = NULL;
			}
			p->se_state = SLOT_FREE;
		}
		mutex_exit(&p->se_lock);
	}
	mutex_exit(&sttp->st_lock);
	return (status);
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
