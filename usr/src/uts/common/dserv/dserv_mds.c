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

#include <sys/list.h>
#include <sys/utsname.h>
#include <sys/avl.h>
#include <nfs/nfs.h>
#include <nfs/nfs4.h>
#include <nfs/nfs4_kprot.h>
#include <nfs/nfs_dispatch.h>
#include <sys/dserv.h>
#include <sys/dserv_impl.h>
#include <sys/systm.h>
#include <sys/cmn_err.h>
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

static void
dserv_mds_instance_init(dserv_mds_instance_t *inst)
{
	inst->dmi_ds_id = 0;
	inst->dmi_mds_addr = NULL;
	inst->dmi_mds_netid = NULL;
	inst->dmi_verifier = (uintptr_t)curthread;
	inst->dmi_teardown_in_progress = B_FALSE;
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
	dserv_mds_instance_t **instpp)
{
	dserv_mds_instance_t *inst;

	if (create_instance)
		inst = dserv_mds_create_my_instance();
	else
		inst = dserv_mds_get_my_instance();

	if (inst == NULL)
		return (ESRCH);

	rw_enter(&inst->dmi_inst_lock, lock_type);
	/*
	 * dmi_teardown_in_progress is only set in one place,
	 * dserv_mds_teardown_instance() and when doing so the dmi_inst_lock
	 * is held as a WRITER, therefore, it is safe to check it without
	 * holding the dmi_content_lock.
	 */
	if (inst->dmi_teardown_in_progress == B_TRUE) {
		rw_exit(&inst->dmi_inst_lock);
		if (lock_type == RW_READER)
			return (EIO);
		else if (lock_type == RW_WRITER)
			/*
			 * This will protect from receiving multiple teardown
			 * commands happening at once.
			 */
			return (EBUSY);
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
	int error = 0;

	error = dserv_mds_client_get(inst, &client);
	if (error != 0)
		return (error);

	wait.tv_sec = 3;
	wait.tv_usec = 0;

	status = CLNT_CALL(client, proc,
	    xdrarg, argp,
	    xdrres, resp,
	    wait);
	dserv_mds_client_return(inst, client);
	if (status != RPC_SUCCESS) {
		cmn_err(CE_WARN, "CLNT_CALL() ds protocol to mds failed: %d",
		    status);
		error = EIO;
	}

	return (error);
}

/*ARGSUSED*/
static int
dserv_open_root_objset_construct(void *voro, void *foo, int bar)
{
	open_root_objset_t *oro = voro;

	list_create(&oro->oro_open_fsid_objsets,
	    sizeof (open_fsid_objset_t),
	    offsetof(open_fsid_objset_t, ofo_open_fsid_objset_node));

	return (0);
}

/*ARGSUSED*/
static void
dserv_open_root_objset_destroy(void *voro, void *foo)
{
	open_root_objset_t *oro = voro;

	list_destroy(&oro->oro_open_fsid_objsets);
}

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
	dserv_open_fsid_objset_cache =
	    kmem_cache_create("dserv_open_fsid_objset_cache",
	    sizeof (open_fsid_objset_t), 0,
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
}

int
dserv_mds_instance_teardown()
{
	dserv_mds_instance_t *inst;
	int error = 0;

	error = dserv_instance_enter(RW_WRITER, B_FALSE, &inst);
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
		open_fsid_objset_t *tmp_fsid;

		/*
		 * Traverse the list of open object sets and close them.
		 * While doing that, remove each entry from the list
		 * and free memory allocated to it.  Outer loop frees
		 * root object sets.  Inner loop frees per-FSID
		 * object sets.
		 */
		for (tmp = list_head(&inst->dmi_datasets); tmp != NULL;
		    tmp = list_head(&inst->dmi_datasets)) {

			for (tmp_fsid =
			    list_head(&tmp->oro_open_fsid_objsets);
			    tmp_fsid != NULL; tmp_fsid =
			    list_head(&tmp->oro_open_fsid_objsets)) {
				dmu_objset_close(tmp_fsid->ofo_osp);
				list_remove(&tmp->oro_open_fsid_objsets,
				    tmp_fsid);
				kmem_cache_free(
				    dserv_open_fsid_objset_cache,
				    tmp_fsid);
			}

			dmu_objset_close(tmp->oro_osp);
			list_remove(&inst->dmi_datasets, tmp);
			kmem_cache_free(dserv_open_root_objset_cache,
			    tmp);
		}
	}

	if (!list_is_empty(&inst->dmi_mds_sids)) {
		mds_sid_map_t *tmp_sid;

		for (tmp_sid = list_head(&inst->dmi_mds_sids);
		    tmp_sid != NULL;
		    tmp_sid = list_head(&inst->dmi_mds_sids)) {
			list_remove(&inst->dmi_mds_sids, tmp_sid);
			kmem_cache_free(mds_sid_map_cache, tmp_sid);
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
	kmem_cache_destroy(dserv_open_fsid_objset_cache);
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

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst);
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
 * populate_mds_sid_cache - Reads the on-disk MDS SID information and
 * populates the in-core representation of this.
 *
 * osp - The object set pointer of a root pNFS dataset.
 *       ObjectID 1 in this dataset is where the MDS SID information resides.
 *	 The data is in the format of an xdr encoded array of MDS SIDSs.
 *
 * inst - The caller's instance information.
 *
 * Other info:
 * Upon calling this function the inst->dmi_content_lock lock is held.
 *
 * Please note: This function is not yet finished.
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
	error = dmu_object_info(osp, 1, &dmu_obj_info);
	if (error)
		return (error);

	/*
	 * dmu_obj_info.doi_physical_blks is the number of 512-byte blocks
	 * allocated to this object.
	 */
	size = dmu_obj_info.doi_physical_blks * 512;
	buf = kmem_zalloc(size, KM_SLEEP);

	error = dmu_read(osp, 1, 0, size, buf);
	if (error) {
		kmem_free(buf, size);
		return (error);
	}
	/* Parse the data */

	/* Add entry to mds sid list */
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

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst);
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

	error = dmu_objset_open(objsetname, DMU_OST_PNFS,
	    DS_MODE_OWNER, &osp);
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

int
dserv_mds_addport(const char *uaddr, const char *proto, const char *aname)
{
	dserv_mds_instance_t *inst;
	dserv_uaddr_t *keep;
	DS_EXIBIargs args;
	DS_EXIBIres res;
	char in[MAXPATHLEN];
	int error;

	error = dserv_instance_enter(RW_READER, B_TRUE, &inst);
	if (error)
		return (error);

	keep = kmem_cache_alloc(dserv_uaddr_cache, KM_SLEEP);
	keep->du_addr = dserv_strdup(uaddr);
	keep->du_proto = dserv_strdup(proto);

	mutex_enter(&inst->dmi_content_lock);
	list_insert_tail(&inst->dmi_uaddrs, keep);
	mutex_exit(&inst->dmi_content_lock);

	(void) sprintf(in, "%s: %s:", uts_nodename(), aname);

	inst->dmi_name = dserv_strdup(in);
	bzero(&res, sizeof (res));

	args.ds_ident.boot_verifier = inst->dmi_verifier;
	args.ds_ident.instance.instance_len = strlen(inst->dmi_name) + 1;
	args.ds_ident.instance.instance_val = inst->dmi_name;

	error = dserv_mds_call(inst, DS_EXIBI,
	    (caddr_t)&args, xdr_DS_EXIBIargs,
	    (caddr_t)&res, xdr_DS_EXIBIres);

	if (error == 0 && res.status == DS_OK)
		inst->dmi_ds_id = res.DS_EXIBIres_u.res_ok.ds_id;

out:
	dserv_instance_exit(inst);
	return (error);
}

/*ARGSUSED*/
int
dserv_mds_checkstate(nfs_fh4 *fh, stateid4 *state, struct svc_req *req)
{
	dserv_mds_instance_t *inst;
	DS_CHECKSTATEargs args;
	DS_CHECKSTATEres res;
	int error;

	error = dserv_instance_enter(RW_READER, B_FALSE, &inst);
	if (error)
		return (error);

	/* XXX check some sort of cache or something */

	/* oopsie, a cache miss.  Gotta go OTW. */

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));


	if (xdr_encode_ds_fh((mds_ds_fh *)fh->nfs_fh4_val, &args.fh)) {
		error = EINVAL;
		goto out;
	}

	/*
	 * XXX need sessions API to get client owner
	 */
	/* args.client = 37; */

	bcopy(state, &args.stateid, sizeof (args.stateid));

	error = dserv_mds_call(inst, DS_CHECKSTATE,
	    (caddr_t)&args, xdr_DS_CHECKSTATEargs,
	    (caddr_t)&res, xdr_DS_CHECKSTATEres);

	if (error)
		cmn_err(CE_WARN, "checkstate rpc failed: %d", error);
	else
		DTRACE_PROBE1(dserv__i__checkstate_status, int, res.status);

	/*
	 * Free arguments and results
	 */
	if (!error)
		(void) xdr_free(xdr_DS_CHECKSTATEres, (caddr_t)&res);

out:
	dserv_instance_exit(inst);
	return (error);
}

int
dserv_mds_reportavail()
{
	dserv_mds_instance_t *inst;
	DS_REPORTAVAILargs args;
	DS_REPORTAVAILres res;
	dserv_uaddr_t *ua;
	open_root_objset_t *root;
	ds_zfsguid zfsguid;
	XDR xdr;
	int xdr_size = 0;
	char *xdr_buffer;
	int error = 0;
	int i, acount, pcount;

	int acount_done = 0;
	int pcount_done = 0;

	memset(&args, '\0', sizeof (args));
	memset(&res, '\0', sizeof (res));

	error = dserv_instance_enter(RW_READER, B_FALSE, &inst);
	if (error)
		return (error);

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

		/* Storage attributes */
		/*
		 * ToDo: We are not sending over storage attributes yet.
		 */

		/* GUID Map */
		args.ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.zfs_info.
		    guid_map.ds_guid.stor_type = ZFS;

		zfsguid.zpool_guid = root->oro_ds_guid.dg_zpool_guid;
		zfsguid.dataset_guid = root->oro_ds_guid.dg_objset_guid;

		pcount_done++;

		xdr_size = xdr_sizeof(xdr_ds_zfsguid, &zfsguid);
		ASSERT(xdr_size);
		xdr_buffer = kmem_alloc(xdr_size, KM_SLEEP);

		xdrmem_create(&xdr, xdr_buffer, xdr_size, XDR_ENCODE);

		if (xdr_ds_zfsguid(&xdr, &zfsguid) == FALSE) {
			mutex_exit(&inst->dmi_content_lock);
			kmem_free(xdr_buffer, xdr_size);
			error = EIO;
			goto out;
		}

		args.ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.zfs_info.
		    guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_len = xdr_size;
		args.ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.zfs_info.
		    guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_val = xdr_buffer;

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

	/*
	 * ToDo: Store MDS SIDs that we get back in the on-disk storage
	 * and in the in-memory MDS SID map.
	 */

out:
	/* Free arguments and results */
	for (i = 0; i < pcount_done; i++) {
		if (args.ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.zfs_info.
		    guid_map.ds_guid.ds_guid_u.zfsguid.zfsguid_len) {
			kmem_free(args.ds_storinfo.ds_storinfo_val[i].
			    ds_storinfo_u.zfs_info.guid_map.ds_guid.ds_guid_u.
			    zfsguid.zfsguid_val,
			    args.ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.
			    zfs_info.guid_map.ds_guid.ds_guid_u.
			    zfsguid.zfsguid_len);
		}
	}

	for (i = 0; i < acount_done; i++) {
		dserv_strfree(args.ds_addrs.ds_addrs_val[i].addr.na_r_netid);
		dserv_strfree(args.ds_addrs.ds_addrs_val[i].addr.na_r_addr);
	}

	kmem_free(args.ds_addrs.ds_addrs_val,
	    args.ds_addrs.ds_addrs_len * sizeof (struct ds_addr));

	if (!error)
		xdr_free(xdr_DS_REPORTAVAILres, (caddr_t)&res);

	dserv_instance_exit(inst);
	return (error);
}
