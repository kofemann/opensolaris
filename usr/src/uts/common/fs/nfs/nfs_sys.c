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
 *
 * Copyright (c) 1983,1984,1985,1986,1987,1988,1989  AT&T.
 * All rights reserved.
 */

#include <sys/types.h>
#include <rpc/types.h>
#include <sys/systm.h>
#include <sys/vfs.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/siginfo.h>
#include <sys/proc.h>		/* for exit() declaration */
#include <sys/kmem.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <sys/thread.h>
#include <rpc/auth.h>
#include <rpc/rpcsys.h>
#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <sys/cmn_err.h>
#include <sys/sdt.h>
#include <nfs/dserv_impl.h>

/*
 * This is filled in with an appropriate address for the
 * function that will traverse the rfs4_client_t table
 * and mark any matching IP Address as "forced_expire".
 *
 * It is the server module load init() function that plops the
 * function pointer.
 */
void (*rfs4_client_clrst)(struct nfs4clrst_args *) = NULL;

/* Temp: used by mdsadm */
int (*mds_recall_lo)(struct mds_reclo_args *, cred_t *) = NULL;
int (*mds_notify_device)(struct mds_notifydev_args *, cred_t *) = NULL;

/* This filled in by nfssrv:_init() */
void (*nfs_srv_quiesce_func)(void) = NULL;

extern void nfscmd_args(uint_t);

/*
 * Time period in seconds for DS_RENEW requests from the heartbeat thread
 * between DS and MDS
 */
#define	DS_MDS_HEARTBEAT_TIME 5
time_t rfs4_ds_mds_hb_time = DS_MDS_HEARTBEAT_TIME;

/*
 * These will be reset by klmmod:lm_svc(), when lockd starts NLM service,
 * based on values read by lockd from /etc/default/nfs. Since nfssrv depends on
 * klmmod, the declarations need to be here (in nfs, on which both depend) so
 * that nfssrv can see the klmmod changes.
 * When the dependency of NFSv4 on NLM/lockd is removed, this will need to
 * be adjusted.
 */
#define	RFS4_LEASETIME 90			/* seconds */
time_t rfs4_lease_time = RFS4_LEASETIME;
time_t rfs4_grace_period = RFS4_LEASETIME;

/* DSS: distributed stable storage */
size_t nfs4_dss_buflen = 0;

/* This filled in by nfssrv:_init() */
int (*nfs_srv_dss_func)(char *, size_t) = NULL;

int
nfs_export(void *arg)
{
	STRUCT_DECL(exportfs_args, ea);

	if (!INGLOBALZONE(curproc))
		return (set_errno(EPERM));
	STRUCT_INIT(ea, get_udatamodel());
	if (copyin(arg, STRUCT_BUF(ea), STRUCT_SIZE(ea)))
		return (set_errno(EFAULT));

	return (exportfs(STRUCT_BUF(ea), get_udatamodel(), CRED()));
}

int
nfssys(enum nfssys_op opcode, void *arg)
{
/* XXX - jw - need to create this routine. */
#ifdef NotDoneYet
	extern void rfs4_inst_init(struct nfs_state_init_args *);
#endif

	int error = 0;

	if (!(opcode == NFS_REVAUTH ||
	    opcode == NFS4_SVC ||
	    opcode == NFSSTAT_LAYOUT) &&
	    secpolicy_nfs(CRED()) != 0) {
		return (set_errno(EPERM));
	}

	switch (opcode) {
/* XXX - jw - need to finish this stuff */
#ifdef NotDoneYet
	case NFS_INIT_STATESTORE: {
		struct nfs_state_init_args nsi_args;
		STRUCT_DECL(nfs_state_init_args, ua);

		if (mds_recall_lo == NULL) {
			printf(":-P .. NFS server is not loaded\n");
			break;
		}

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));

		STRUCT_INIT(ua, get_udatamodel());

		nsi_args.inst_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		error = copyinstr(nsi_args.inst_name,
		    STRUCT_FGETP(ua, inst_name), MAXNAMELEN, NULL);

		if (error != 0) {
			kmem_free(nsi_args.inst_name, MAXNAMELEN);
			return (set_errno(EFAULT));
		}
		nsi_args.cap_flags = STRUCT_FGET(ua, cap_flags);

		rfs4_inst_init(&nsi_args);

		break;
	}

	case NFS_FINI_STATESTORE: {
		struct nfs_state_init_args nsi_args;
		STRUCT_DECL(nfs_state_init_args, ua);

		if (mds_recall_lo == NULL) {
			printf(":-P .. NFS server is not loaded\n");
			break;
		}

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));

		STRUCT_INIT(ua, get_udatamodel());

		nsi_args.inst_name = kmem_alloc(MAXNAMELEN, KM_SLEEP);

		error = copyinstr(nsi_args.inst_name,
		    STRUCT_FGETP(ua, inst_name), MAXNAMELEN, NULL);

		if (error != 0) {
			kmem_free(nsi_args.inst_name, MAXNAMELEN);
			return (set_errno(EFAULT));
		}
		rfs4_inst_finit(&nsi_args);

		break;
	}
#endif

	case MDS_RECALL_LAYOUT: {
		struct mds_reclo_args rargs;
		int plen = 0;
		int buf[2] = {0, 0};
		XDR xdrs;

		if (mds_recall_lo == NULL)
			return (set_errno(ENOTSUP));

		if (copyin(arg, (char *)buf, sizeof (buf)))
			return (set_errno(EFAULT));

		xdrmem_create(&xdrs, (char *)buf, sizeof (buf), XDR_DECODE);

		if (! xdr_int(&xdrs, &rargs.lo_type) ||
		    ! xdr_int(&xdrs, &plen) || (plen > MAXNAMELEN))
			return (set_errno(EINVAL));

		rargs.lo_fname = kmem_alloc(plen + 1, KM_SLEEP);
		rargs.lo_fname[plen] = '\0';
		error = copyin((char *)arg + BYTES_PER_XDR_UNIT * 2,
		    rargs.lo_fname, plen);

		if (error) {
			kmem_free(rargs.lo_fname, plen + 1);
			return (set_errno(EFAULT));
		}

		error = mds_recall_lo(&rargs, CRED());
		kmem_free(rargs.lo_fname, plen + 1);
		break;
	}

	case MDS_NOTIFY_DEVICE: {
		struct mds_notifydev_args dargs;

		if (mds_notify_device == NULL)
			return (set_errno(ENOTSUP));

		if (copyin(arg, (char *)&dargs, sizeof (dargs)))
			return (set_errno(EFAULT));

		error = mds_notify_device(&dargs, CRED());
		break;
	}

	case NFS4_CLR_STATE: { /* Clear NFS4 client state */
		struct nfs4clrst_args clr;
		STRUCT_DECL(nfs4clrst_args, u_clr);

		/*
		 * If the server is not loaded then no point in
		 * clearing nothing :-)
		 */
		if (rfs4_client_clrst == NULL) {
			break;
		}

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));

		STRUCT_INIT(u_clr, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(u_clr), STRUCT_SIZE(u_clr)))
			return (set_errno(EFAULT));

		clr.vers = STRUCT_FGET(u_clr, vers);

		if (clr.vers != NFS4_CLRST_VERSION)
			return (set_errno(EINVAL));

		clr.addr_type = STRUCT_FGET(u_clr, addr_type);
		clr.ap = STRUCT_FGETP(u_clr, ap);
		rfs4_client_clrst(&clr);
		break;
	}

	case SVCPOOL_CREATE: { /* setup an RPC server thread pool */
		struct svcpool_args p;

		if (copyin(arg, &p, sizeof (p)))
			return (set_errno(EFAULT));

		error = svc_pool_create(&p);

		if (copyout(&p, arg, sizeof (p)))
			return (set_errno(EFAULT));
		break;
	}

	case SVCPOOL_WAIT: { /* wait in kernel for threads to be needed */
		int id;

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_wait(id);
		break;
	}

	case SVCPOOL_RUN: { /* give work to a runnable thread */
		int id;

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_do_run(id);
		break;
	}

	case RDMA_SVC_INIT: {
		struct rdma_svc_args rsa;
		char netstore[20] = "tcp";

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		if (get_udatamodel() != DATAMODEL_NATIVE) {
			STRUCT_DECL(rdma_svc_args, ursa);

			STRUCT_INIT(ursa, get_udatamodel());
			if (copyin(arg, STRUCT_BUF(ursa), STRUCT_SIZE(ursa)))
				return (set_errno(EFAULT));

			rsa.poolid = STRUCT_FGET(ursa, poolid);
			rsa.nfs_versmin = STRUCT_FGET(ursa, nfs_versmin);
			rsa.nfs_versmax = STRUCT_FGET(ursa, nfs_versmax);
			rsa.delegation = STRUCT_FGET(ursa, delegation);
			rsa.dfd = STRUCT_FGET(ursa, dfd);
		} else {
			if (copyin(arg, &rsa, sizeof (rsa)))
				return (set_errno(EFAULT));
		}
		rsa.netid = netstore;

		error = rdma_start(&rsa);
		break;
	}

	case NFS_SVC: { /* NFS server daemon */
		STRUCT_DECL(nfs_svc_args, nsa);

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		STRUCT_INIT(nsa, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(nsa), STRUCT_SIZE(nsa)))
			return (set_errno(EFAULT));

		error = nfs_svc(STRUCT_BUF(nsa), get_udatamodel());
		break;
	}

	case EXPORTFS: { /* export a file system */
		error = nfs_export(arg);
		break;
	}

	case NFS_GETFH: { /* get a file handle */
		STRUCT_DECL(nfs_getfh_args, nga);

		if (!INGLOBALZONE(curproc))
			return (set_errno(EPERM));
		STRUCT_INIT(nga, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nga), STRUCT_SIZE(nga)))
			return (set_errno(EFAULT));

		error = nfs_getfh(STRUCT_BUF(nga), get_udatamodel(), CRED());
		break;
	}

	case NFSSTAT_LAYOUT: {
		STRUCT_DECL(pnfs_getflo_args, pla);

		STRUCT_INIT(pla, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(pla), STRUCT_SIZE(pla))) {
			error = EFAULT;
		} else {
			error = pnfs_collect_layoutstats(
			    STRUCT_BUF(pla), get_udatamodel(), CRED());
		}
		break;
	}



	case NFS_REVAUTH: { /* revoke the cached credentials for the uid */
		STRUCT_DECL(nfs_revauth_args, nra);

		STRUCT_INIT(nra, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nra), STRUCT_SIZE(nra)))
			return (set_errno(EFAULT));

		/* This call performs its own privilege checking */
		error = sec_clnt_revoke(STRUCT_FGET(nra, authtype),
		    STRUCT_FGET(nra, uid), CRED(), NULL, get_udatamodel());
		break;
	}

	case LM_SVC: { /* LM server daemon */
		struct lm_svc_args lsa;

		if (get_udatamodel() != DATAMODEL_NATIVE) {
			STRUCT_DECL(lm_svc_args, ulsa);

			STRUCT_INIT(ulsa, get_udatamodel());
			if (copyin(arg, STRUCT_BUF(ulsa), STRUCT_SIZE(ulsa)))
				return (set_errno(EFAULT));

			lsa.version = STRUCT_FGET(ulsa, version);
			lsa.fd = STRUCT_FGET(ulsa, fd);
			lsa.n_fmly = STRUCT_FGET(ulsa, n_fmly);
			lsa.n_proto = STRUCT_FGET(ulsa, n_proto);
			lsa.n_rdev = expldev(STRUCT_FGET(ulsa, n_rdev));
			lsa.debug = STRUCT_FGET(ulsa, debug);
			lsa.timout = STRUCT_FGET(ulsa, timout);
			lsa.grace = STRUCT_FGET(ulsa, grace);
			lsa.retransmittimeout = STRUCT_FGET(ulsa,
			    retransmittimeout);
		} else {
			if (copyin(arg, &lsa, sizeof (lsa)))
				return (set_errno(EFAULT));
		}

		error = lm_svc(&lsa);
		break;
	}

	case KILL_LOCKMGR: {
		error = lm_shutdown();
		break;
	}

	case LOG_FLUSH:	{	/* Flush log buffer and possibly rename */
		STRUCT_DECL(nfsl_flush_args, nfa);

		STRUCT_INIT(nfa, get_udatamodel());
		if (copyin(arg, STRUCT_BUF(nfa), STRUCT_SIZE(nfa)))
			return (set_errno(EFAULT));

		error = nfsl_flush(STRUCT_BUF(nfa), get_udatamodel());
		break;
	}

	case NFS4_SVC: { /* NFS client callback daemon */

		STRUCT_DECL(nfs4_svc_args, nsa);

		STRUCT_INIT(nsa, get_udatamodel());

		if (copyin(arg, STRUCT_BUF(nsa), STRUCT_SIZE(nsa)))
			return (set_errno(EFAULT));

		error = nfs4_svc(STRUCT_BUF(nsa), get_udatamodel());
		break;
	}

	/* Request that NFSv4 server quiesce on next shutdown */
	case NFS4_SVC_REQUEST_QUIESCE: {
		int id;

		/* check that nfssrv module is loaded */
		if (nfs_srv_quiesce_func == NULL)
			return (set_errno(ENOTSUP));

		if (copyin(arg, &id, sizeof (id)))
			return (set_errno(EFAULT));

		error = svc_pool_control(id, SVCPSET_SHUTDOWN_PROC,
		    (void *)nfs_srv_quiesce_func);
		break;
	}

	case NFS_IDMAP: {
		struct nfsidmap_args idm;

		if (copyin(arg, &idm, sizeof (idm)))
			return (set_errno(EFAULT));

		nfs_idmap_args(&idm);
		error = 0;
		break;
	}

	case NFS_SPE: {
		nfs41_spe_svc(arg);
		error = 0;
		break;
	}

	case NFS4_DSS_SETPATHS_SIZE: {
		/* crosses ILP32/LP64 boundary */
		uint32_t nfs4_dss_bufsize = 0;

		if (copyin(arg, &nfs4_dss_bufsize, sizeof (nfs4_dss_bufsize)))
			return (set_errno(EFAULT));
		nfs4_dss_buflen = (long)nfs4_dss_bufsize;
		error = 0;
		break;
	}

	case NFS4_DSS_SETPATHS: {
		char *nfs4_dss_bufp;

		/* check that nfssrv module is loaded */
		if (nfs_srv_dss_func == NULL)
			return (set_errno(ENOTSUP));

		/*
		 * NFS4_DSS_SETPATHS_SIZE must be called before
		 * NFS4_DSS_SETPATHS, to tell us how big a buffer we need
		 * to allocate.
		 */
		if (nfs4_dss_buflen == 0)
			return (set_errno(EINVAL));
		nfs4_dss_bufp = kmem_alloc(nfs4_dss_buflen, KM_SLEEP);
		if (nfs4_dss_bufp == NULL)
			return (set_errno(ENOMEM));

		if (copyin(arg, nfs4_dss_bufp, nfs4_dss_buflen)) {
			kmem_free(nfs4_dss_bufp, nfs4_dss_buflen);
			return (set_errno(EFAULT));
		}

		/* unpack the buffer and extract the pathnames */
		error = nfs_srv_dss_func(nfs4_dss_bufp, nfs4_dss_buflen);
		kmem_free(nfs4_dss_bufp, nfs4_dss_buflen);

		break;
	}

	case NFS4_EPHEMERAL_MOUNT_TO: {
		uint_t	mount_to;

		/*
		 * Not a very complicated call.
		 */
		if (copyin(arg, &mount_to, sizeof (mount_to)))
			return (set_errno(EFAULT));
		nfs4_ephemeral_set_mount_to(mount_to);
		error = 0;
		break;
	}

	case MOUNTD_ARGS: {
		uint_t	did;

		/*
		 * For now, only passing down the door fd; if we
		 * ever need to pass down more info, we can use
		 * a (properly aligned) struct.
		 */
		if (copyin(arg, &did, sizeof (did)))
			return (set_errno(EFAULT));
		mountd_args(did);
		error = 0;
		break;
	}

	case NFSCMD_ARGS: {
		uint_t	did;

		/*
		 * For now, only passing down the door fd; if we
		 * ever need to pass down more info, we can use
		 * a (properly aligned) struct.
		 */
		if (copyin(arg, &did, sizeof (did)))
			return (set_errno(EFAULT));
		nfscmd_args(did);
		error = 0;
		break;
	}

	case DSERV_DATASET_INFO: {
		dserv_dataset_info_t dinfo;

		error = copyin((void *)arg, &dinfo,
		    sizeof (dserv_dataset_info_t));
		if (error)
			return (EFAULT);

		error = dserv_mds_addobjset(dinfo.dataset_name);
		break;
	}

	case DSERV_DATASET_PROPS: {
		dserv_dataset_props_t dprops;

		error = copyin((void *)arg, &dprops,
		    sizeof (dserv_dataset_props_t));
		if (error)
			return (EFAULT);
		DTRACE_PROBE3(dserv__i__dataset_props,
		    char *, dprops.ddp_name,
		    char *, dprops.ddp_mds_netid,
		    char *, dprops.ddp_mds_uaddr);
		break;
	}

	case DSERV_INSTANCE_SHUTDOWN: {
		error = dserv_mds_instance_teardown();
		break;
	}

	case DSERV_REPORTAVAIL: {
		error = dserv_mds_reportavail();
		break;
	}

	case DSERV_SVC: {
		dserv_svc_args_t svcargs;

		error = copyin((void *)arg, &svcargs,
		    sizeof (dserv_svc_args_t));
		if (error)
			return (EFAULT);

		error =	dserv_svc(&svcargs);
		break;
	}

	case DSERV_SETMDS: {
		dserv_setmds_args_t smargs;

		error = copyin((void *)arg, &smargs,
		    sizeof (dserv_setmds_args_t));
		if (error)
			return (EFAULT);

		DTRACE_PROBE2(dserv__i__setmds,
		    char *, smargs.dsm_mds_uaddr, char *, smargs.dsm_mds_netid);

		error = dserv_mds_setmds(smargs.dsm_mds_netid,
		    smargs.dsm_mds_uaddr);
		break;
	}

	case DSERV_SETPORT: {
		dserv_setport_args_t spargs;

		error = copyin((void *)arg, &spargs,
		    sizeof (dserv_setport_args_t));
		if (error)
			return (EFAULT);

		DTRACE_PROBE2(dserv__i__setport, char *, spargs.dsa_uaddr,
		    char *, spargs.dsa_proto);

		error = dserv_mds_addport(spargs.dsa_uaddr, spargs.dsa_proto,
		    spargs.dsa_name);
		break;
	}

	default:
		error = EINVAL;
		break;
	}

	return ((error != 0) ? set_errno(error) : 0);
}
