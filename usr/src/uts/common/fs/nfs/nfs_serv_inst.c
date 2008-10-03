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
#include <nfs/nfs4.h>
#include <nfs/nfs_serv_inst.h>

/*
 * list of all occurrences of NFS Server stateStores.
 */
extern  list_t    nsi_head;
extern  krwlock_t nsi_lock;
kmem_cache_t *nsi_cache;

/*
 * walk all the server instances and call the callout function.
 *
 * ( This could spawn a thread to do the actual work, based on
 *    a flag passed in as an argument ?? )
 */
void
nsi_walk(void (*callout)(nfs_server_instance_t *, void *), void *data)
{
	nfs_server_instance_t *nsip;

	rw_enter(&nsi_lock, RW_READER);
	for (nsip = list_head(&nsi_head); nsip != NULL;
	    nsip = list_next(&nsi_head, &nsip->nsi_list)) {
		mutex_enter(&nsip->state_lock);
		if (nsip->inst_flags & NFS_INST_STORE_INIT) {
			(*callout)(nsip, data);
		}
		mutex_exit(&nsip->state_lock);
	}
	rw_exit(&nsi_lock);
}

static void
nsi_remove(nfs_server_instance_t *instp)
{
	rw_enter(&nsi_lock, RW_WRITER);
	list_remove(&nsi_head, instp);
	rw_exit(&nsi_lock);

}

int
nsi_create(char *inst_name, nfs_server_instance_t **instpp)
{
	nfs_server_instance_t *nsip, *instp;

	if (instpp == NULL)
		return (EINVAL);

	instp = kmem_cache_alloc(nsi_cache, KM_SLEEP);

	rw_enter(&nsi_lock, RW_WRITER);
	for (nsip = list_head(&nsi_head); nsip != NULL;
	    nsip = list_next(&nsi_head, &nsip->nsi_list)) {
		mutex_enter(&nsip->state_lock);
		if (strncmp(nsip->inst_name, inst_name, NFS_INST_NAMESZ) == 0) {
			kmem_cache_free(nsi_cache, instp);
			*instpp = nsip;
			mutex_exit(&nsip->state_lock);
			rw_exit(&nsi_lock);
			return (EEXIST);
		}
		mutex_exit(&nsip->state_lock);
	}
	/* insert a new occurrence */
	(void) strncpy(instp->inst_name, inst_name, NFS_INST_NAMESZ);
	list_insert_head(&nsi_head, instp);
	rw_exit(&nsi_lock);
	*instpp = instp;
	return (0);
}

void
nsi_destroy(nfs_server_instance_t *instp)
{
	nsi_remove(instp);
	kmem_cache_free(nsi_cache, instp);
}

/*ARGSUSED*/
static int
nsi_cache_construct(void *ptr, void *arg1, int arg2)
{
	nfs_server_instance_t *instp = (nfs_server_instance_t *)ptr;

	bzero(instp, sizeof (*instp));

	/* Used to manage create/destroy of server state */
	mutex_init(&instp->state_lock, NULL, MUTEX_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
nsi_cache_destroy(void *ptr, void *arg1)
{
	nfs_server_instance_t *instp = (nfs_server_instance_t *)ptr;

	mutex_destroy(&instp->state_lock);
}

void
nsi_cache_init()
{
	nsi_cache = kmem_cache_create("nfss_inst",
	    sizeof (nfs_server_instance_t), 0,
	    nsi_cache_construct, nsi_cache_destroy, NULL,
	    NULL, NULL, 0);
}

void
nsi_cache_fini(void)
{
	kmem_cache_destroy(nsi_cache);
}
