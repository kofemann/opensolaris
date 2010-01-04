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

#include <sys/list.h>
#include <sys/systeminfo.h>
#include <sys/sunddi.h>
#include <sys/avl.h>
#include <sys/atomic.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs_dispatch.h>
#include <nfs/nfssys.h>
#include <nfs/dserv_impl.h>
#include <sys/systm.h>
#include <sys/sdt.h>
#include <nfs/ds.h>
#include <sys/dmu.h>
#include <sys/spa.h>
#include <sys/zap.h>
#include <sys/txg.h>
#include <inet/ip.h>
#include <inet/ip6.h>

static avl_tree_t dserv_mds_instance_avl;
static krwlock_t dserv_mds_instance_tree_lock;
static kmem_cache_t *mds_sid_map_cache = NULL;
static kmem_cache_t *dserv_mds_instance_cache = NULL;
static kmem_cache_t *dserv_open_root_objset_cache = NULL;
static kmem_cache_t *dserv_uaddr_cache = NULL;
static kmem_cache_t *dserv_mds_handle_cache = NULL;

static enum nfsstat4 get_nfs_status(ds_status);
static nfsstat4 cp_ds_mds_checkstateid(mds_ds_fh *,
    compound_state_t *, stateid4 *, int);
extern time_t rfs4_ds_mds_hb_time;

static int
dserv_mds_instance_compare(const void *va, const void *vb)
{
	const dserv_mds_instance_t *a = va;
	const dserv_mds_instance_t *b = vb;
	int rc;

	rc = a->dmi_pid - b->dmi_pid;
	DSERV_AVL_RETURN(rc);
	return (rc);
}

/*ARGSUSED*/
static int
dserv_mds_instance_construct(void *vdmi, void *foo, int bar)
{
	dserv_mds_instance_t *dmi = vdmi;

	rw_init(&dmi->dmi_inst_lock, NULL, RW_DEFAULT, NULL);

	mutex_init(&dmi->dmi_content_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&dmi->dmi_zap_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&dmi->dmi_datasets,
	    sizeof (open_root_objset_t),
	    offsetof(open_root_objset_t, oro_open_root_objset_node));
	list_create(&dmi->dmi_mds_sids,
	    sizeof (mds_sid_map_t),
	    offsetof(mds_sid_map_t, msm_mds_sid_map_node));
	list_create(&dmi->dmi_uaddrs,
	    sizeof (dserv_uaddr_t),
	    offsetof(dserv_uaddr_t, du_list));
	list_create(&dmi->dmi_handles,
	    sizeof (dserv_mds_handle_t),
	    offsetof(dserv_mds_handle_t, dmh_list));

	return (0);
}

/*ARGSUSED*/
static void
dserv_mds_instance_destroy(void *vdmi, void *foo)
{
	dserv_mds_instance_t *dmi = vdmi;

	list_destroy(&dmi->dmi_handles);
	list_destroy(&dmi->dmi_datasets);
	list_destroy(&dmi->dmi_mds_sids);
	list_destroy(&dmi->dmi_uaddrs);

	mutex_destroy(&dmi->dmi_zap_lock);
	mutex_destroy(&dmi->dmi_content_lock);
	rw_destroy(&dmi->dmi_inst_lock);
}

static dserv_mds_instance_t *
dserv_mds_get_instance(pid_t keypid)
{
	dserv_mds_instance_t key, *rc;

	key.dmi_pid = keypid;
	rw_enter(&dserv_mds_instance_tree_lock, RW_READER);
	rc = avl_find(&dserv_mds_instance_avl, &key, NULL);
	rw_exit(&dserv_mds_instance_tree_lock);

	return (rc);
}

dserv_mds_instance_t *
dserv_mds_get_my_instance()
{
	proc_t *myproc = ttoproc(curthread);

	if (myproc == NULL)
		return (NULL);

	return (dserv_mds_get_instance(myproc->p_pid));
}

static int
dserv_atoi(char *cp)
{
	int n;

	n = 0;
	while (*cp != '\0') {
		n = n * 10 + (*cp - '0');
		cp++;
	}

	return (n);
}

static void
dserv_mds_instance_init(dserv_mds_instance_t *inst)
{
	timespec32_t verf;

	inst->dmi_ds_id = 0;
	inst->dmi_mds_addr = NULL;
	inst->dmi_mds_netid = NULL;

	verf.tv_sec = dserv_atoi(hw_serial);
	if (verf.tv_sec != 0) {
		verf.tv_nsec = gethrestime_sec();
	} else {
		timespec_t tverf;

		gethrestime(&tverf);
		verf.tv_sec = (time_t)tverf.tv_sec;
		verf.tv_nsec = tverf.tv_nsec;
	}

	inst->dmi_verifier = *(uint64_t *)&verf;
	inst->dmi_teardown_in_progress = B_FALSE;
	inst->dmi_recov_in_progress = B_FALSE;
}

static dserv_mds_instance_t *
dserv_mds_create_my_instance()
{
	dserv_mds_instance_t *rc, *existing;
	avl_index_t where;
	proc_t *proc;

	proc = ttoproc(curthread);
	if (proc == NULL)
		return (NULL);

	rc = kmem_cache_alloc(dserv_mds_instance_cache, KM_SLEEP);
	rc->dmi_start_time = gethrestime_sec();
	rc->dmi_pid = proc->p_pid;

	rw_enter(&dserv_mds_instance_tree_lock, RW_WRITER);
	existing = avl_find(&dserv_mds_instance_avl, rc, &where);
	if (existing != NULL) {
		rw_exit(&dserv_mds_instance_tree_lock);
		kmem_cache_free(dserv_mds_instance_cache, rc);
		return (existing);
	}

	dserv_mds_instance_init(rc);

	avl_insert(&dserv_mds_instance_avl, rc, where);
	rw_exit(&dserv_mds_instance_tree_lock);

	return (rc);
}

/*
 * Synchronizes the access of an instance with the shutdown of the instance.
 * The dmi_inst_lock must not be taken/released outside of these functions.
 * Upon executing any COMPOUND operation or sending a control protocol
 * message over the wire, this function must be called.
 */
int
dserv_instance_enter(krw_t lock_type, boolean_t create_instance,
	dserv_mds_instance_t **instpp, pid_t *pid)
{
	dserv_mds_instance_t *inst;
	bool_t grab_lock = FALSE;

	if (create_instance)
		inst = dserv_mds_create_my_instance();
	else {
		if (pid == NULL) {
			inst = dserv_mds_get_my_instance();
		} else {
			inst = dserv_mds_get_instance(*pid);
		}
	}

	if (inst == NULL)
		return (ESRCH);

	/*
	 * If dmi_teardown_in_progress is set, then we can't grab the
	 * lock. I.e., we are in the midst of either tearing it
	 * down or we have torn it down.
	 */
retry_with_lock:
	if (grab_lock) {
		/*
		 * Now we have to grab the lock and make sure that it is not
		 * true!
		 *
		 * Note that there is currently only one case were we
		 * are a WRITER and that is during tear-down. So if a
		 * READER has to block, it is because tear-down is
		 * pending.
		 */
		if (rw_tryenter(&inst->dmi_inst_lock, lock_type) == 0) {
			if (lock_type == RW_READER)
				return (EIO);
			rw_enter(&inst->dmi_inst_lock, lock_type);
		}
	}

	/*
	 * dmi_teardown_in_progress is only set in one place,
	 * dserv_mds_teardown_instance() and when doing so the dmi_inst_lock
	 * is held as a WRITER, therefore, it is safe to check it without
	 * holding the dmi_content_lock.
	 */
	if (inst->dmi_teardown_in_progress == B_TRUE) {
		if (grab_lock)
			rw_exit(&inst->dmi_inst_lock);

		if (lock_type == RW_READER)
			return (EIO);

		/*
		 * This will protect from receiving multiple teardown
		 * commands happening at once.
		 */
		return (EBUSY);
	} else if (!grab_lock) {
		grab_lock = TRUE;
		goto retry_with_lock;
	}

	*instpp = inst;
	return (0);
}

/*
 * This function frees any of the locks taken by dserv_instance_enter
 */
void
dserv_instance_exit(dserv_mds_instance_t *inst)
{
	rw_exit(&inst->dmi_inst_lock);
}

static int
dserv_mds_client_get(dserv_mds_instance_t *inst, CLIENT **clientp)
{
	static uint32_t zero = 0;
	int error = 0;
	dserv_mds_handle_t *handle;

	mutex_enter(&inst->dmi_content_lock);
	handle = list_head(&inst->dmi_handles);
	if (handle != NULL) {
		list_remove(&inst->dmi_handles, handle);
		mutex_exit(&inst->dmi_content_lock);
		*clientp = handle->dmh_client;
		CLNT_CONTROL(*clientp, CLSET_XID, (char *)&zero);
		kmem_cache_free(dserv_mds_handle_cache, handle);
		return (0);
	}
	if (! (inst->dmi_flags & DSERV_MDS_INSTANCE_NET_VALID))
		error = EINVAL;
	if (error)
		goto out;

	error = clnt_tli_kcreate(&inst->dmi_knc, &inst->dmi_nb, PNFSCTLDS,
	    PNFSCTLDS_V1, 0, 0, CRED(), clientp);

out:
	mutex_exit(&inst->dmi_content_lock);
	return (error);
}

static void
dserv_mds_client_return(dserv_mds_instance_t *inst, CLIENT *client)
{
	dserv_mds_handle_t *handle;

	/* XXX high-water mark someday; free it instead of cache it */

	handle = kmem_cache_alloc(dserv_mds_handle_cache, KM_SLEEP);
	handle->dmh_client = client;

	mutex_enter(&inst->dmi_content_lock);
	list_insert_head(&inst->dmi_handles, handle);
	mutex_exit(&inst->dmi_content_lock);
}

static int
dserv_mds_call(dserv_mds_instance_t *inst, rpcproc_t proc,
    caddr_t argp, xdrproc_t xdrarg,
    caddr_t resp, xdrproc_t xdrres)
{
	enum clnt_stat status;
	struct timeval wait;
	CLIENT *client;
	int again, error = 0, num_tries = 0;

	error = dserv_mds_client_get(inst, &client);
	if (error != 0)
		return (error);

	do {
		again = 0;
		wait.tv_sec = CTLDS_TIMEO;
		wait.tv_usec = 0;

		status = CLNT_CALL(client, proc,
		    xdrarg, argp,
		    xdrres, resp,
		    wait);

		/*
		 * Check the easy cases: The call succeeded or failed
		 * miserably and we can't recover
		 */
		if (status == RPC_SUCCESS)
			goto out;

		if (IS_UNRECOVERABLE_RPC(status)) {
			error = EIO;
			goto out;
		}

		/*
		 * Since the error is recoverable, retry the request.  If we
		 * are above our threshold of retries to send, set the error
		 * appropriately and return.
		 */
		if (num_tries < DS_TO_MDS_CTRL_PROTO_RETRIES) {
			num_tries++;
			again = 1;
		} else {
			switch (status) {
			case RPC_TIMEDOUT:
				error = ETIMEDOUT;
				break;
			case RPC_INTR:
				error = EINTR;
				break;
			default:
				error = EIO;
				break;
			}
		}
	} while (again);

	if (status != RPC_SUCCESS)
		DTRACE_PROBE1(dserv__e__ctlds_clnt_call_failed, int, status);

out:
	dserv_mds_client_return(inst, client);
	return (error);
}

/*ARGSUSED*/
static int
dserv_open_root_objset_construct(void *voro, void *foo, int bar)
{
	open_root_objset_t *oro = voro;

	list_create(&oro->oro_open_mdsfs_objsets,
	    sizeof (open_mdsfs_objset_t),
	    offsetof(open_mdsfs_objset_t, omo_open_mdsfs_objset_node));

	return (0);
}

/*ARGSUSED*/
static void
dserv_open_root_objset_destroy(void *voro, void *foo)
{
	open_root_objset_t *oro = voro;

	list_destroy(&oro->oro_open_mdsfs_objsets);
}

u_longlong_t dserv_caller_id;

void
dserv_mds_setup()
{
	avl_create(&dserv_mds_instance_avl, dserv_mds_instance_compare,
	    sizeof (dserv_mds_instance_t),
	    offsetof(dserv_mds_instance_t, dmi_avl));
	rw_init(&dserv_mds_instance_tree_lock, NULL, RW_DEFAULT, NULL);
	dserv_mds_handle_cache = kmem_cache_create("dserv_mds_handle_cache",
	    sizeof (dserv_mds_handle_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	dserv_open_root_objset_cache =
	    kmem_cache_create("dserv_open_root_objset_cache",
	    sizeof (open_root_objset_t), 0,
	    dserv_open_root_objset_construct, dserv_open_root_objset_destroy,
	    NULL,
	    NULL, NULL, 0);
	dserv_open_mdsfs_objset_cache =
	    kmem_cache_create("dserv_open_mdsfs_objset_cache",
	    sizeof (open_mdsfs_objset_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	mds_sid_map_cache =
	    kmem_cache_create("mds_sid_map_cache",
	    sizeof (mds_sid_map_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	dserv_uaddr_cache = kmem_cache_create("dserv_uaddr_cache",
	    sizeof (dserv_uaddr_t), 0,
	    NULL, NULL, NULL,
	    NULL, NULL, 0);
	dserv_mds_instance_cache = kmem_cache_create("dserv_mds_instance_cache",
	    sizeof (dserv_mds_instance_t), 0,
	    dserv_mds_instance_construct, dserv_mds_instance_destroy, NULL,
	    NULL, NULL, 0);
	dserv_caller_id = fs_new_caller_id();
}

int
dserv_mds_instance_teardown()
{
	dserv_mds_instance_t *inst;
	int error = 0;

	error = dserv_instance_enter(RW_WRITER, B_FALSE, &inst, NULL);
	if (error)
		return (error);

	/*
	 * The instance lock is taken as writer so set the teardown flag
	 * to TRUE.  Once this flag is set to TRUE all requests to the
	 * data server will fail with an I/O error.
	 */
	inst->dmi_teardown_in_progress = B_TRUE;
	dserv_instance_exit(inst);

	/*
	 * Free all of the nnodes that are associated with this instance
	 */
	error = nnode_teardown_by_instance();
	if (error)
		return (error);

	/*
	 * Remove the instance from the AVL tree.
	 */
	rw_enter(&dserv_mds_instance_tree_lock, RW_WRITER);
	avl_remove(&dserv_mds_instance_avl, inst);
	rw_exit(&dserv_mds_instance_tree_lock);

	/*
	 * Destroy the instance's data
	 */
	if (!list_is_empty(&inst->dmi_datasets)) {
		open_root_objset_t *tmp;
		open_mdsfs_objset_t *tmp_mdsfs;

		/*
		 * Traverse the list of open object sets and close them.
		 * While doing that, remove each entry from the list
		 * and free memory allocated to it.  Outer loop frees
		 * root object sets.  Inner loop frees per-MDS_FS
		 * object sets.
		 */
		for (tmp = list_head(&inst->dmi_datasets); tmp != NULL;
		    tmp = list_head(&inst->dmi_datasets)) {

			for (tmp_mdsfs =
			    list_head(&tmp->oro_open_mdsfs_objsets);
			    tmp_mdsfs != NULL; tmp_mdsfs =
			    list_head(&tmp->oro_open_mdsfs_objsets)) {
				dmu_objset_disown(tmp_mdsfs->omo_osp,
				    pnfs_dmu_tag);
				list_remove(&tmp->oro_open_mdsfs_objsets,
				    tmp_mdsfs);
				kmem_cache_free(
				    dserv_open_mdsfs_objset_cache,
				    tmp_mdsfs);
			}

			dmu_objset_disown(tmp->oro_osp, pnfs_dmu_tag);
			list_remove(&inst->dmi_datasets, tmp);
			kmem_cache_free(dserv_open_root_objset_cache,
			    tmp);
		}
	}

	if (!list_is_empty(&inst->dmi_mds_sids)) {
		mds_sid_map_t *sid_map;

		for (sid_map = list_head(&inst->dmi_mds_sids);
		    sid_map != NULL;
		    sid_map = list_head(&inst->dmi_mds_sids)) {
			list_remove(&inst->dmi_mds_sids, sid_map);

			if (sid_map->msm_mds_storid.len)
				kmem_free(sid_map->msm_mds_storid.val,
				    sid_map->msm_mds_storid.len);

			kmem_cache_free(mds_sid_map_cache, sid_map);
		}
	}

	if (!list_is_empty(&inst->dmi_uaddrs)) {
		dserv_uaddr_t *tmp;

		for (tmp = list_head(&inst->dmi_uaddrs); tmp != NULL;
		    tmp = list_head(&inst->dmi_uaddrs)) {
			list_remove(&inst->dmi_uaddrs, tmp);
			kmem_cache_free(dserv_uaddr_cache, tmp);
		}
	}

	if (!list_is_empty(&inst->dmi_handles)) {
		dserv_mds_handle_t *tmp;

		for (tmp = list_head(&inst->dmi_handles); tmp != NULL;
		    tmp = list_head(&inst->dmi_handles)) {
			list_remove(&inst->dmi_handles, tmp);
			CLNT_DESTROY(tmp->dmh_client);
			kmem_cache_free(dserv_mds_handle_cache, tmp);
		}
	}

	if (inst->dmi_mds_addr != NULL)
		dserv_strfree(inst->dmi_mds_addr);
	if (inst->dmi_mds_netid != NULL)
		dserv_strfree(inst->dmi_mds_netid);

	kmem_cache_free(dserv_mds_instance_cache, inst);
	return (0);
}

/*
 * This function gets called when the data server kernel module is being
 * unloaded.  It is called from dserv_detach().
 */
void
dserv_mds_teardown()
{
	/*
	 * By the time this function gets called, all of the data server
	 * instances have been torn down.  Therefore, all we need to do
	 * is destroy some of the kmem caches, locks and avl trees that
	 * we were using to store all of the data server's per instance
	 * information.
	 */
	kmem_cache_destroy(dserv_mds_instance_cache);
	kmem_cache_destroy(dserv_open_root_objset_cache);
	kmem_cache_destroy(dserv_open_mdsfs_objset_cache);
	kmem_cache_destroy(mds_sid_map_cache);
	kmem_cache_destroy(dserv_uaddr_cache);
	kmem_cache_destroy(dserv_mds_handle_cache);
	rw_destroy(&dserv_mds_instance_tree_lock);
	avl_destroy(&dserv_mds_instance_avl);
}

/* stolen from nfs4_srv_deleg.c */
static int
dserv_uaddr2sockaddr(int af, char *ua, void *ap, in_port_t *pp)
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

/*
 * dserv_mds_setmds builds a knetconfig structure for the
 * dserv instance, netid, address and port.
 */
int
dserv_mds_setmds(char *netid, char *uaddr)
{
	dserv_mds_instance_t *inst;
	struct sockaddr_in *addr4;
	struct sockaddr_in6 *addr6;
	char *devname;
	vnode_t *vp;
	int error;
	int af;

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst, NULL);
	if (error)
		return (error);

	mutex_enter(&inst->dmi_content_lock);
	inst->dmi_mds_netid = dserv_strdup(netid);
	inst->dmi_mds_addr = dserv_strdup(uaddr);

	inst->dmi_knc.knc_semantics = NC_TPI_COTS;
	if (strcmp(netid, "tcp") == 0) {
		inst->dmi_knc.knc_protofmly = "inet";
		inst->dmi_knc.knc_proto = "tcp";
		devname = "/dev/tcp";
		af = AF_INET;
	} else if (strcmp(netid, "tcp6") == 0) {
		inst->dmi_knc.knc_protofmly = "inet6";
		inst->dmi_knc.knc_proto = "tcp"; /* why not tcp6? */
		devname = "/dev/tcp6";
		af = AF_INET6;
	} else {
		error = EINVAL;
		goto out;
	}

	error = lookupname(devname, UIO_SYSSPACE, FOLLOW, NULLVPP, &vp);
	if (error)
		goto out;
	if (vp->v_type != VCHR) {
		error = EINVAL;
		goto out;
	}
	inst->dmi_knc.knc_rdev = vp->v_rdev;
	VN_RELE(vp);

	if (af == AF_INET) {
		inst->dmi_nb.maxlen = inst->dmi_nb.len =
		    sizeof (struct sockaddr_in);
		inst->dmi_nb.buf = kmem_zalloc(inst->dmi_nb.maxlen, KM_SLEEP);
		addr4 = (struct sockaddr_in *)inst->dmi_nb.buf;
		addr4->sin_family = af;
		error = dserv_uaddr2sockaddr(af, uaddr,
		    &addr4->sin_addr, &addr4->sin_port);
	} else { /* AF_INET6 */
		inst->dmi_nb.maxlen = inst->dmi_nb.len =
		    sizeof (struct sockaddr_in6);
		inst->dmi_nb.buf = kmem_zalloc(inst->dmi_nb.maxlen, KM_SLEEP);
		addr6 = (struct sockaddr_in6 *)inst->dmi_nb.buf;
		addr6->sin6_family = af;
		error = dserv_uaddr2sockaddr(af, uaddr,
		    &addr6->sin6_addr, &addr6->sin6_port);
	}

	if (error == 0)
		inst->dmi_flags |= DSERV_MDS_INSTANCE_NET_VALID;

out:
	mutex_exit(&inst->dmi_content_lock);
	dserv_instance_exit(inst);
	return (error);
}

/*
 * XXX Please Note: This function is not yet finished.  If you are confused
 * by this function... Don't worry it will be come more clear.
 *
 * populate_mds_sid_cache - Reads the on-disk MDS SID information and
 * populates the in-core representation of this.
 *
 * osp - The object set pointer of a root pNFS dataset.
 *       DMU_PNFS_METADATA_OBJECT represents the DMU Object ID of the
 *	 object where the MDS SID information resides.
 *	 The data is in the format of an xdr encoded array of MDS SIDs,
 *	 but that fact will be hidden from this layer by an abstract
 *	 interface (XXX yet to be implemented).
 *
 * inst - The caller's instance information.
 *
 * Other info:
 * Upon calling this function the inst->dmi_content_lock lock is held.
 */
/*ARGSUSED*/
int
populate_mds_sid_cache(objset_t *osp, dserv_mds_instance_t *inst)
{
	uint64_t size;
	dmu_object_info_t dmu_obj_info;
	char *buf = NULL;
	int error = 0;

	/*
	 * Determine the size of the object so we know how much to read.
	 */
	error = dmu_object_info(osp, DMU_PNFS_METADATA_OBJECT, &dmu_obj_info);
	if (error)
		return (error);

	/*
	 * dmu_obj_info.doi_physical_blks_512 is the number of 512-byte blocks
	 * allocated to this object.
	 */
	size = dmu_obj_info.doi_physical_blocks_512 * 512;
	buf = kmem_zalloc(size, KM_SLEEP);

	error = dmu_read(osp, DMU_PNFS_METADATA_OBJECT, 0, size,
	    buf, DMU_READ_PREFETCH);
	if (error) {
		kmem_free(buf, size);
		return (error);
	}
	/* To Do: Parse the data */

	/* To Do: Add entry to mds sid list */
	return (error);
}

int
dserv_mds_addobjset(const char *objsetname)
{
	dserv_mds_instance_t *inst;
	open_root_objset_t *new_objset;
	objset_t *osp = NULL;
	spa_t *spa = NULL;
	int error = 0;

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst, NULL);
	if (error)
		return (error);

	mutex_enter(&inst->dmi_content_lock);
	if (!list_is_empty(&inst->dmi_datasets)) {
		open_root_objset_t *tmp;

		/*
		 * Search through the open object sets and see if
		 * the object set is already open.
		 *
		 * If the object set is already open then we shouldn't
		 * open it again, just return success.
		 */
		for (tmp = list_head(&inst->dmi_datasets); tmp != NULL;
		    tmp = list_next(&inst->dmi_datasets, tmp)) {
			if (strncmp(objsetname, tmp->oro_objsetname,
			    MAXPATHLEN) == 0) {
#if 0
				/*
				 * Populate in-core MDS SID Map from
				 * on-disk info.  Note, this error does not
				 * have to be returned to the caller.
				 * If we fail to populate the cache, just
				 * do it at a later time...
				 */
				error = populate_mds_sid_cache(tmp->oro_osp,
				    inst);
#endif
				goto out;
			}
		}
	}

	error = dmu_objset_own(objsetname, DMU_OST_PNFS, B_FALSE,
	    pnfs_dmu_tag, &osp);
	if (error)
		goto out;

	spa = dmu_objset_spa(osp);

	new_objset = kmem_cache_alloc(dserv_open_root_objset_cache, KM_SLEEP);
	new_objset->oro_osp = osp;
	(void) strncpy(new_objset->oro_objsetname, objsetname, MAXPATHLEN);
	new_objset->oro_ds_guid.dg_zpool_guid = spa_guid(spa);
	new_objset->oro_ds_guid.dg_objset_guid = dmu_objset_id(osp);
	list_insert_tail(&inst->dmi_datasets, new_objset);
#if 0
	/*
	 * Populate in-core MDS SID map from on-disk info.
	 */
	error = populate_mds_sid_cache(osp, inst);
	if (error)
		goto out;
#endif
out:
	mutex_exit(&inst->dmi_content_lock);
	dserv_instance_exit(inst);
	return (error);
}

void
dserv_mds_heartbeat_thread(pid_t *pid)
{
	int 			error = 0;
	DS_RENEWargs 		args;
	DS_RENEWres  		res;
	dserv_mds_instance_t	*inst = NULL;
	callb_cpr_t		cpr_info;
	kmutex_t		cpr_lock;
	ds_status 		status = 0;


	ASSERT(pid != NULL);
	mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_info, &cpr_lock,
	    callb_generic_cpr, "pnfs_ds_mds_renew_hb");

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));

	for (;;) {
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_BEGIN(&cpr_info);
		mutex_exit(&cpr_lock);
		delay(SEC_TO_TICK(rfs4_ds_mds_hb_time));
		mutex_enter(&cpr_lock);
		CALLB_CPR_SAFE_END(&cpr_info, &cpr_lock);
		mutex_exit(&cpr_lock);

		error = dserv_instance_enter(RW_READER, B_FALSE, &inst, pid);
		if (error) {
			DTRACE_PROBE1(dserv__i__dserv_mds_hb_error, int, *pid);

			/*
			 * ESRCH implies that there is no instance. If there is
			 * no instance, then there is no point of having a
			 * heartbeat for that instance, so we exit.
			 */
			if (error == ESRCH) {
				DTRACE_PROBE(dserv__i__ds_mds_hb_ESRCH_error);
				break;
			}

			/*
			 * Some other error happened. Just keep retrying.
			 */
			continue;
		}

		/*
		 * Check if the instance is shutting down. If yes, then
		 * we exit the heartbeat thread.
		 */
		mutex_enter(&inst->dmi_content_lock);
		if (inst->dmi_teardown_in_progress == B_TRUE) {
			DTRACE_PROBE(dserv__i__dmi_teardown_in_progress);
			mutex_exit(&inst->dmi_content_lock);
			dserv_instance_exit(inst);
			break;
		}

		args.ds_id = inst->dmi_ds_id;
		args.ds_boottime = inst->dmi_verifier;
		mutex_exit(&inst->dmi_content_lock);

		/*
		 * Invoke DS_RENEW to the MDS
		 */
		error = dserv_mds_call(inst, DS_RENEW,
		    (caddr_t)&args, xdr_DS_RENEWargs,
		    (caddr_t)&res, xdr_DS_RENEWres);

		/*
		 * Detect reboot if the RPC succeeds.
		 */
		DTRACE_PROBE2(dserv__i__dserv_mds_call_resp_status,
		    int, res.status, int, error);
		if (error == 0) {

			/*
			 * error == 0 simply implies that the DS_RENEW RPC
			 * succeeded, not necessarily with DS_OK though.  Take
			 * recovery actions if MDS reboot is detected.
			 */
			mutex_enter(&inst->dmi_content_lock);
			if (res.status == DSERR_STALE_DSID ||
			    inst->dmi_recov_in_progress == B_TRUE ||
			    inst->dmi_mds_boot_verifier !=
			    res.DS_RENEWres_u.mds_boottime) {
				DTRACE_PROBE(dserv__i__dserv_recovery_starts);

				/*
				 * Spawning another thread to do recovery seems
				 * like an overkill here, so doing it inline.
				 * First do DS_EXIBI, and continue on to
				 * DS_REPORTAVAIL only if DS_EXIBI passes.
				 */
				inst->dmi_recov_in_progress = B_TRUE;
				mutex_exit(&inst->dmi_content_lock);

				error = dserv_mds_exibi(inst, &status);
				if (error || status != DS_OK) {
					DTRACE_PROBE(dserv__i__exibi_failed);
					dserv_instance_exit(inst);
					continue;
				}

				/* DS_EXIBI is done, now do DS_REPORTAVAIL. */
				error = dserv_mds_do_reportavail(inst, &status);
				if (error || status != DS_OK) {
					DTRACE_PROBE(
					    dserv__i__reportavail_failed);
					dserv_instance_exit(inst);
					continue;
				} else {
					/*
					 * Recovery is done. Mark all the
					 * appropriate flags so that we are
					 * ready for the next round of recovery
					 * actions.
					 */
					mutex_enter(&inst->dmi_content_lock);
					inst->dmi_recov_in_progress = B_FALSE;
					mutex_exit(&inst->dmi_content_lock);
				}
			} else {
				DTRACE_PROBE(dserv__i__dserv_no_recovery);
				mutex_exit(&inst->dmi_content_lock);
			}
		}
		dserv_instance_exit(inst);
	}

	DTRACE_PROBE(dserv__i__hb_thread_exiting);

	kmem_free(pid, sizeof (pid_t));

	mutex_enter(&cpr_lock);
	CALLB_CPR_EXIT(&cpr_info);
	mutex_destroy(&cpr_lock);

	zthread_exit();
	/* NOTREACHED */
}

int
dserv_mds_addport(const char *uaddr, const char *proto, const char *aname)
{
	dserv_mds_instance_t *inst;
	dserv_uaddr_t *keep;
	int error;
	char in[MAXPATHLEN];
	ds_status status = 0;

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst, NULL);
	if (error)
		return (error);

	keep = kmem_cache_alloc(dserv_uaddr_cache, KM_SLEEP);
	keep->du_addr = dserv_strdup(uaddr);
	keep->du_proto = dserv_strdup(proto);
	(void) sprintf(in, "%s: %s:", hw_serial, aname);

	mutex_enter(&inst->dmi_content_lock);
	list_insert_tail(&inst->dmi_uaddrs, keep);
	inst->dmi_name = dserv_strdup(in);
	mutex_exit(&inst->dmi_content_lock);

	error = dserv_mds_exibi(inst, &status);

	dserv_instance_exit(inst);
	return (error);
}

int
dserv_mds_exibi(dserv_mds_instance_t *inst, ds_status *status)
{
	DS_EXIBIargs args;
	DS_EXIBIres res;
	int error;

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));

	mutex_enter(&inst->dmi_content_lock);
	args.ds_ident.boot_verifier = inst->dmi_verifier;
	args.ds_ident.instance.instance_len = strlen(inst->dmi_name) + 1;
	args.ds_ident.instance.instance_val = inst->dmi_name;
	mutex_exit(&inst->dmi_content_lock);

	error = dserv_mds_call(inst, DS_EXIBI,
	    (caddr_t)&args, xdr_DS_EXIBIargs,
	    (caddr_t)&res, xdr_DS_EXIBIres);

	if (error == 0 && res.status == DS_OK) {
		mutex_enter(&inst->dmi_content_lock);
		inst->dmi_ds_id = res.DS_EXIBIres_u.res_ok.ds_id;
		inst->dmi_mds_boot_verifier =
		    res.DS_EXIBIres_u.res_ok.mds_boot_verifier;
		mutex_exit(&inst->dmi_content_lock);
	}

	*status = res.status;
	return (error);
}

/*
 * Ensure that we catch all the control protocol errors from the MDS and report
 * them to the client in the form of NFSv4.1 error.
 */
static enum nfsstat4
get_nfs_status(ds_status status)
{
	enum nfsstat4 nfs_status;
	switch (status) {
		case DS_OK:
			nfs_status = NFS4_OK;
			break;
		case DSERR_BADHANDLE:
			nfs_status = NFS4ERR_NOFILEHANDLE;
			break;
		case DSERR_STALE_STATEID:
			nfs_status = NFS4ERR_STALE;
			break;
		case DSERR_BAD_STATEID:
			nfs_status = NFS4ERR_BAD_STATEID;
			break;
		case DSERR_STALE_CLIENTID:
			nfs_status = NFS4ERR_STALE;
			break;
		default:
			nfs_status = NFS4ERR_SERVERFAULT;
	}
	return (nfs_status);
}

/*
 * Control Protocol (DS to MDS) checkstateid
 */
static nfsstat4
cp_ds_mds_checkstateid(mds_ds_fh *fh, struct compound_state *cs,
    stateid4 *stateid, int mode)
{
	dserv_mds_instance_t *inst;
	DS_CHECKSTATEargs args;
	DS_CHECKSTATEres res;
	int error;
	client_owner4 *co4;
	nfsstat4 status;

	/*
	 * The derivation of client_owner4 below assumes that the
	 * nfs_client_id4 and client_owner4 are comparable. The language in the
	 * SPEC suggests that it is indeed the case at the server. See Section
	 * 2.4.1 of NFS v4.1 proposed standard (Jan 29, 2009).
	 *
	 * The derivation is based on the sessions pointer, which is already
	 * cached in the compound_state_t. The hold and release on the database
	 * entry for the sessions pointer happens in the context of
	 * rfs41_dispatch, so we do not need to worry about that here.
	 */
	co4 = (client_owner4*)&cs->sp->sn_clnt->rc_nfs_client;

	error = dserv_instance_enter(RW_READER, B_FALSE, &inst, NULL);
	if (error) {
		status = NFS4ERR_SERVERFAULT;
		return (status);
	}

	/*
	 * Checkstate will be done on each I/O, it may or may not go OTW, but
	 * the state will be checked. Hence, it seems to be a good place for
	 * sychronizing with the DS heartbeat thread, where the heartbeat
	 * thread redrives DS_EXIBI and DS_REPORTAVAIL if the MDS reboots.
	 *
	 * Note that in the current implementation, if the recovery is in
	 * progress then we deny the I/O. This is inefficient, since the I/Os
	 * in flight from the client with valid state will get penalized
	 * unncessarily.  However, the I/Os are currently being denied only
	 * because we do not have state caching implemented. If we had state
	 * caching, we would first check if the state that comes along
	 * with the I/O operation is valid, and if so, we would allow the
	 * I/O even if the recovery is in progress.
	 */

	mutex_enter(&inst->dmi_content_lock);
	if (inst->dmi_recov_in_progress == B_TRUE) {
		mutex_exit(&inst->dmi_content_lock);
		status = NFS4ERR_DELAY;
		return (status);
	}
	mutex_exit(&inst->dmi_content_lock);

	/*
	 * XXX: check some sort of cache or something. The design for the
	 * caching infrastructure is still pending (Jan 29, 2009). Check the
	 * I/Os offset against the cached layout. Think through both dense and
	 * sparse cases. How do you detect the writes past a layout in the
	 * dense case?
	 */

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));

	/*
	 * Do some sanity checks and pack the arguments.
	 */
	if (fh == NULL || co4 == NULL) {
		status = NFS4ERR_SERVERFAULT;
		goto out;
	}
	if (!xdr_encode_ds_fh(fh, &args.fh)) {
		status = NFS4ERR_SERVERFAULT;
		goto out;
	}
	bcopy(stateid, &args.stateid, sizeof (args.stateid));
	bcopy(co4, &args.co_owner, sizeof (args.co_owner));
	args.mode = mode;

	error = dserv_mds_call(inst, DS_CHECKSTATE,
	    (caddr_t)&args, xdr_DS_CHECKSTATEargs,
	    (caddr_t)&res, xdr_DS_CHECKSTATEres);

	/*
	 * XXX:Process the response.  Store the layout, client id, open mode,
	 * access rights for the state caching infrastructure.
	 */
	if (!error) {
		DTRACE_PROBE1(dserv__i__checkstate_status, int, res.status);
		status = get_nfs_status(res.status);
		xdr_free(xdr_DS_CHECKSTATEres, (caddr_t)&res);
	} else {
		status = NFS4ERR_SERVERFAULT;
		DTRACE_PROBE1(dserv__i__checkstate_status,
		    int, NFS4ERR_SERVERFAULT);
	}
	xdr_free_ds_fh(&args.fh);

out:
	dserv_instance_exit(inst);
	return (status);
}

/*
 * DS_CHECKSTATE entry point. Accesses via nnop_checkstate interface for nnode,
 * which in turn calls nso_checkstate, which is mapped to dserv_mds_checkstate.
 * Most of the fields are not required for a control protocol checkstate, but
 * we nevertheless have them here because they exist in the nnode interface for
 * checkstate.
 */
/*ARGSUSED*/
nfsstat4
dserv_mds_checkstate(void *dnstate, compound_state_t *cs, int mode,
    stateid4 *stateid, bool_t trunc, bool_t *deleg, bool_t do_access,
    caller_context_t *ct, clientid4 *clientid)
{
	enum nfsstat4 status;

	dserv_nnode_state_t *dns = dnstate;
	status = cp_ds_mds_checkstateid(dns->fh, cs, stateid, mode);

	return (status);
}

int
dserv_mds_reportavail()
{
	dserv_mds_instance_t *inst = NULL;
	int error = 0;
	pid_t *pid = NULL;
	ds_status status = 0;

	error = dserv_instance_enter(RW_READER, B_FALSE, &inst, NULL);
	if (error) {
		return (error);
	}

	error = dserv_mds_do_reportavail(inst, &status);

	/*
	 * If the first DS_REPORTAVAIL (and the previous  DS_EXIBI)
	 * completes successfully, start a heartbeat thread from the DS
	 * to the MDS. Using the heartbeat thread, the DS will detect
	 * MDS reboot and the MDS will detect DS reboot. DS_RENEW is
	 * the control protocol operation that gets invoked in the
	 * heartbeat thread.
	 *
	 * There are two reasons for starting the heartbeat
	 * thread here:
	 *
	 * 1. No point starting the heartbeat if the initial set of
	 * exchanges between the DS and MDS return in an error.
	 *
	 * 2. We could start the heartbeat thread in the user space,
	 * and issue a system call for doing DS_RENEW, but that would
	 * be inefficient, since the DS_RENEW is a frequently executed
	 * operation.
	 *
	 * Note that each instance will have its own heartbeat thread,
	 * since: (a) each instance will invoke DS_REPORTAVAIL and DS_EXIBI;
	 * (b): each instance can be stopped and started independently; (c)
	 * instances can be serving a different pNFS communities and/or
	 * datasets.
	 */
	if (error == 0 && status == DS_OK) {
		DTRACE_PROBE1(dserv__i__dmi_pid, int, inst->dmi_pid);
		pid = kmem_zalloc(sizeof (pid_t), KM_NOSLEEP);
		mutex_enter(&inst->dmi_content_lock);
		*pid = inst->dmi_pid;
		mutex_exit(&inst->dmi_content_lock);

		DTRACE_PROBE(dserv__i__creating_heartbeat_thread);
		(void) zthread_create(NULL, 0, dserv_mds_heartbeat_thread,
		    pid, 0, minclsyspri);
	}

	dserv_instance_exit(inst);
	return (error);
}

int
dserv_mds_do_reportavail(dserv_mds_instance_t *inst, ds_status *status)
{
	DS_REPORTAVAILargs args;
	DS_REPORTAVAILres res;
	dserv_uaddr_t *ua;
	open_root_objset_t *root;
	ds_zfsguid *zfsguid = NULL;
	XDR xdr;
	int xdr_size = 0;
	char *xdr_buffer;
	int error = 0;
	int i, j;
	int acount, pcount;

	int acount_done = 0;
	int pcount_done = 0;

	ds_zfsinfo	*dz;

	char	path_buf[MAXPATHLEN];

	(void) memset(&args, '\0', sizeof (args));
	(void) memset(&res, '\0', sizeof (res));

	mutex_enter(&inst->dmi_content_lock);
	acount = 0;
	for (ua = list_head(&inst->dmi_uaddrs); ua != NULL;
	    ua = list_next(&inst->dmi_uaddrs, ua))
		++acount;

	pcount = 0;
	for (root = list_head(&inst->dmi_datasets); root != NULL;
	    root = list_next(&inst->dmi_datasets, root))
		++pcount;

	if ((acount == 0) || (pcount == 0)) {
		mutex_exit(&inst->dmi_content_lock);
		error = ESRCH;
		goto out;
	}

	/*
	 * The GUID Map will come back in the same order we
	 * create entries. So instead of decoding them, we
	 * just sock them away.
	 */
	zfsguid = kmem_zalloc(pcount * sizeof (ds_zfsguid),
	    KM_SLEEP);

	args.ds_id = inst->dmi_ds_id;
	args.ds_verifier = inst->dmi_verifier;

	args.ds_addrs.ds_addrs_len = acount;
	args.ds_addrs.ds_addrs_val = kmem_alloc(acount *
	    sizeof (struct ds_addr), KM_SLEEP);
	ua = list_head(&inst->dmi_uaddrs);
	for (i = 0; i < acount; i++) {
		args.ds_addrs.ds_addrs_val[i].validuse = NFS | DSERV;
		args.ds_addrs.ds_addrs_val[i].addr.na_r_netid =
		    dserv_strdup(ua->du_proto);
		args.ds_addrs.ds_addrs_val[i].addr.na_r_addr =
		    dserv_strdup(ua->du_addr);
		ua = list_next(&inst->dmi_uaddrs, ua);
	}

	acount_done = acount;

	args.ds_attrvers = DS_ATTR_v1;

	args.ds_storinfo.ds_storinfo_len = pcount;
	args.ds_storinfo.ds_storinfo_val = kmem_zalloc(pcount *
	    sizeof (struct ds_storinfo), KM_SLEEP);
	root = list_head(&inst->dmi_datasets);

	for (i = 0; i < pcount; i++) {
		args.ds_storinfo.ds_storinfo_val[i].type = ZFS;

		dz = &args.ds_storinfo.ds_storinfo_val[i].
		    ds_storinfo_u.zfs_info;

		/* Storage attributes */
		/*
		 * ToDo: We are sending over just some of
		 * the storage attributes now.
		 */
		dz->attrs.attrs_len = 1;
		dz->attrs.attrs_val =
		    kmem_zalloc(dz->attrs.attrs_len * sizeof (ds_zfsattr),
		    KM_SLEEP);

		(void) sprintf(path_buf, "%s:%s", uts_nodename(),
		    root->oro_objsetname);

		(void) str_to_utf8("dataset",
		    &dz->attrs.attrs_val[0].attrname);
		(void) str_to_utf8(path_buf,
		    (utf8string *)&dz->attrs.attrs_val[0].attrvalue);

		/*
		 * GUID Map
		 *
		 * XXX: A "GUID Map" seems to be used for both a
		 * mapping of guids and as a collection of such mappings.
		 */
		dz->guid_map.ds_guid.stor_type = ZFS;

		zfsguid[i].zpool_guid = root->oro_ds_guid.dg_zpool_guid;
		zfsguid[i].dataset_guid = root->oro_ds_guid.dg_objset_guid;

		/*
		 * We do this here because of a possible
		 * early termination of the loop.
		 */
		pcount_done++;

		xdr_size = xdr_sizeof(xdr_ds_zfsguid, &zfsguid[i]);
		ASSERT(xdr_size);
		xdr_buffer = kmem_alloc(xdr_size, KM_SLEEP);

		xdrmem_create(&xdr, xdr_buffer, xdr_size, XDR_ENCODE);

		if (xdr_ds_zfsguid(&xdr, &zfsguid[i]) == FALSE) {
			mutex_exit(&inst->dmi_content_lock);
			kmem_free(xdr_buffer, xdr_size);
			error = EIO;
			goto out;
		}

		dz->guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_len = xdr_size;
		dz->guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_val = xdr_buffer;

		/*
		 * ToDo: This should include the list of MDS SIDs
		 * that the data-server knows about. In case
		 * the MDS has lost it's way and needs a friend
		 * to help it out.
		 */
		root = list_next(&inst->dmi_datasets, root);
	}

	mutex_exit(&inst->dmi_content_lock);

	bzero(&res, sizeof (res));
	error = dserv_mds_call(inst, DS_REPORTAVAIL,
	    (caddr_t)&args, xdr_DS_REPORTAVAILargs,
	    (caddr_t)&res, xdr_DS_REPORTAVAILres);

	*status = res.status;

	/*
	 * XXX: Store MDS SIDs that we get back in the
	 * 1) on-disk storage and,
	 *	Need to do
	 * 2) in the in-memory MDS SID map.
	 *	Done below!
	 */
	if (error == 0 && res.status == DS_OK) {
		ASSERT(pcount ==
		    res.DS_REPORTAVAILres_u.res_ok.guid_map.guid_map_len);

		mutex_enter(&inst->dmi_content_lock);
		for (i = 0;
		    i < res.DS_REPORTAVAILres_u.res_ok.guid_map.guid_map_len;
		    i++) {
			ds_guid_map	*guid_map;
			mds_sid_map_t	*sid_map;

			guid_map = &res.DS_REPORTAVAILres_u.res_ok.guid_map.
			    guid_map_val[i];

			for (j = 0;
			    j < guid_map->mds_sid_array.mds_sid_array_len;
			    j++) {
				mds_sid	*sid =
				    &guid_map->mds_sid_array
				    .mds_sid_array_val[j];
				bool_t	bFound = FALSE;

				/*
				 * Can we find it first?
				 */
				for (sid_map = list_head(&inst->dmi_mds_sids);
				    sid_map != NULL;
				    sid_map = list_next(&inst->dmi_mds_sids,
				    sid_map)) {
					if ((sid->len ==
					    sid_map->msm_mds_storid.len) &&
					    (memcmp(sid->val,
					    sid_map->msm_mds_storid.val,
					    sid_map->msm_mds_storid.len)
					    == 0)) {
						bFound = TRUE;
						break;
					}
				}

				/*
				 * If we found it, then it can't have changed.
				 * So do nothing.
				 */
				if (bFound == FALSE) {
					sid_map = kmem_cache_alloc(
					    mds_sid_map_cache,
					    KM_SLEEP);
					sid_map->msm_mds_storid.len =
					    sid->len;
					sid_map->msm_mds_storid.val =
					    kmem_zalloc(
					    sid_map->msm_mds_storid.len,
					    KM_SLEEP);

					bcopy(sid->val,
					    sid_map->msm_mds_storid.val,
					    sid_map->msm_mds_storid.len);

					sid_map->msm_ds_guid.dg_zpool_guid =
					    zfsguid[i].zpool_guid;
					sid_map->msm_ds_guid.dg_objset_guid =
					    zfsguid[i].dataset_guid;

					list_insert_tail(&inst->dmi_mds_sids,
					    sid_map);
				}
			}
		}
		mutex_exit(&inst->dmi_content_lock);
	}

out:
	/* Free arguments and results */
	for (i = 0; i < pcount_done; i++) {
		dz = &args.ds_storinfo.ds_storinfo_val[i].
		    ds_storinfo_u.zfs_info;
		if (dz->guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_len) {
			kmem_free(dz->guid_map.ds_guid.ds_guid_u.
			    zfsguid.zfsguid_val,
			    dz->guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_len);
		}

		for (j = 0; j < dz->attrs.attrs_len; j++) {
			UTF8STRING_FREE(dz->attrs.attrs_val[j].attrname);
			if (dz->attrs.attrs_val[j].attrvalue.attrvalue_val) {
				kmem_free(dz->attrs.attrs_val[j].attrvalue.
				    attrvalue_val,
				    dz->attrs.attrs_val[j].attrvalue.
				    attrvalue_len);
			}
		}

		if (dz->attrs.attrs_len) {
			kmem_free(dz->attrs.attrs_val,
			    dz->attrs.attrs_len * sizeof (ds_zfsattr));
		}
	}

	for (i = 0; i < acount_done; i++) {
		dserv_strfree(args.ds_addrs.ds_addrs_val[i].addr.na_r_netid);
		dserv_strfree(args.ds_addrs.ds_addrs_val[i].addr.na_r_addr);
	}

	if (zfsguid)
		kmem_free(zfsguid, pcount * sizeof (ds_zfsguid));

	if (args.ds_addrs.ds_addrs_val)
		kmem_free(args.ds_addrs.ds_addrs_val,
		    args.ds_addrs.ds_addrs_len * sizeof (struct ds_addr));

	if (!error)
		xdr_free(xdr_DS_REPORTAVAILres, (caddr_t)&res);

	return (error);
}
