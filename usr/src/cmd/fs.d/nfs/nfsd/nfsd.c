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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

/* LINTLIBRARY */
/* PROTOLIB1 */

/* NFS server */

#include <nfs/libnfs.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <tiuser.h>
#include <rpc/rpc.h>
#include <errno.h>
#include <thread.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/file.h>
#include <nfs/nfs.h>
#include <nfs/nfs_acl.h>
#include <nfs/nfssys.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <signal.h>
#include <netconfig.h>
#include <netdir.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/tihdr.h>
#include <sys/wait.h>
#include <poll.h>
#include <priv_utils.h>
#include <sys/tiuser.h>
#include <netinet/tcp.h>
#include <deflt.h>
#include <rpcsvc/daemon_utils.h>
#include <rpcsvc/nfs4_prot.h>
#include <libnvpair.h>
#include <door.h>
#include <dirent.h>
#include <libintl.h>
#include "nfs_tbind.h"
#include "thrpool.h"

/* quiesce requests will be ignored if nfs_server_vers_max < QUIESCE_VERSMIN */
#define	QUIESCE_VERSMIN	4
/* DSS: distributed stable storage */
#define	DSS_VERSMIN	4

#define	MAX_DR_BUF_SZ	(1024 * 1024)

static	int	nfssvc(int, struct netbuf, struct netconfig *);
static	int	nfssvcpool(int maxservers);
static	int	dss_init(uint_t npaths, char **pathnames);
static	void	dss_mkleafdirs(uint_t npaths, char **pathnames);
static	void	dss_mkleafdir(char *dir, char *leaf, char *path);
static	void	usage(void);
int		qstrcmp(const void *s1, const void *s2);
static	void 	clean_buf(void);
static	void	free_buf(char *);
static	void	*realloc_buf(char *, size_t);
static	void	*alloc_buf(size_t);
static	int	create_door(void);

extern	int	_nfssys(int, void *);

extern int	daemonize_init(void);
extern void	daemonize_fini(int fd);

/* signal handlers */
static void sigflush(int);
static void quiesce(int);

static	char	*MyName;
static	NETSELDECL(defaultproviders)[] = { "/dev/tcp6", "/dev/tcp", "/dev/udp",
					    "/dev/udp6", NULL };
/* static	NETSELDECL(defaultprotos)[] =	{ NC_UDP, NC_TCP, NULL }; */
/*
 * The following are all globals used by routines in nfs_tbind.c.
 */
size_t	end_listen_fds;		/* used by conn_close_oldest() */
size_t	num_fds = 0;		/* used by multiple routines */
int	listen_backlog = 32;	/* used by bind_to_{provider,proto}() */
int	num_servers;		/* used by cots_listen_event() */
int	(*Mysvc)(int, struct netbuf, struct netconfig *) = nfssvc;
				/* used by cots_listen_event() */
int	max_conns_allowed = -1;	/* used by cots_listen_event() */

/*
 * Keep track of min/max versions of NFS protocol to be started.
 * Start with the defaults (min == 2, max == 3).  We have the
 * capability of starting vers=4 but only if the user requests it.
 */
int	nfs_server_vers_min = NFS_VERSMIN_DEFAULT;
int	nfs_server_vers_max = NFS_VERSMAX_DEFAULT;

/*
 * Set the default for server delegation enablement and set per
 * /etc/default/nfs configuration (if present).
 */
int	nfs_server_delegation = NFS_SERVER_DELEGATION_DEFAULT;

static thread_key_t	nfsd_tsd_key;

int
main(int ac, char *av[])
{
	libnfs_handle_t *libhandle;
	char *dir = "/";
	int allflag = 0;
	int df_allflag = 0;
	int maxservers = 1;	/* zero allows inifinte number of threads */
	int pid;
	int i;
	int doorfd = -1;
	char *provider = (char *)NULL;
	char *df_provider = (char *)NULL;
	struct protob *protobp0, *protobp;
	NETSELDECL(proto) = NULL;
	NETSELDECL(df_proto) = NULL;
	NETSELPDECL(providerp);
	char *defval;
	boolean_t can_do_mlp;
	uint_t dss_npaths = 0;
	char **dss_pathnames = NULL;
	sigset_t sgset;

	int pipe_fd = -1;

	libhandle = libnfs_handle_create(LIBNFS_VERSION);
	libnfs_error_mode_set(libhandle, LIBNFS_ERRMODE_DIE);
	(void) libnfs_myinstance(libhandle);

	MyName = *av;

	/*
	 * Initializations that require more privileges than we need to run.
	 */
	(void) _create_daemon_lock(NFSD, DAEMON_UID, DAEMON_GID);
	svcsetprio();

	can_do_mlp = priv_ineffect(PRIV_NET_BINDMLP);
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS,
	    can_do_mlp ? PRIV_NET_BINDMLP : NULL, NULL) == -1) {
		(void) fprintf(stderr, "%s should be run with"
		    " sufficient privileges\n", av[0]);
		exit(1);
	}

	(void) enable_extended_FILE_stdio(-1, -1);

	/*
	 * Read in the values from config file first before we check
	 * commandline options so the options override the file.
	 */

	max_conns_allowed = libnfs_prop_num(libhandle,
	    LIBNFS_PROP_SERVER_MAX_CONNECTIONS);
	listen_backlog = libnfs_prop_num(libhandle,
	    LIBNFS_PROP_SERVER_LISTEN_BACKLOG);
	df_proto = libnfs_prop_string(libhandle,
	    LIBNFS_PROP_SERVER_PROTOCOL);
	if (strncasecmp("ALL", df_proto, 3) == 0) {
		libnfs_strfree(libhandle, df_proto);
		df_proto = NULL;
		df_allflag = 1;
	}
	df_provider = libnfs_prop_string(libhandle,
	    LIBNFS_PROP_SERVER_DEVICE);
	maxservers = libnfs_prop_num(libhandle,
	    LIBNFS_PROP_SERVER_SERVERS);
	nfs_server_vers_min = libnfs_prop_num(libhandle,
	    LIBNFS_PROP_SERVER_VERSMIN);
	nfs_server_vers_max = libnfs_prop_num(libhandle,
	    LIBNFS_PROP_SERVER_VERSMAX);
	libnfs_log(libhandle, LOG_DEBUG,
	    "vers min/max = %d/%d",
	    nfs_server_vers_min, nfs_server_vers_max);
	nfs_server_delegation = libnfs_prop_boolean(libhandle,
	    LIBNFS_PROP_SERVER_DELEGATION);

	while ((i = getopt(ac, av, "s:")) != EOF) {
		switch (i) {
		/*
		 * DSS: NFSv4 distributed stable storage.
		 *
		 * This is a Contracted Project Private interface, for
		 * the sole use of Sun Cluster HA-NFS. See PSARC/2006/313.
		 */
		case 's':
			if (strlen(optarg) < MAXPATHLEN) {
				/* first "-s" option encountered? */
				if (dss_pathnames == NULL) {
					/*
					 * Allocate maximum possible space
					 * required given cmdline arg count;
					 * "-s <path>" consumes two args.
					 */
					size_t sz = (ac / 2) * sizeof (char *);
					dss_pathnames = (char **)malloc(sz);
					if (dss_pathnames == NULL) {
						(void) fprintf(stderr, "%s: "
						    "dss paths malloc failed\n",
						    av[0]);
						exit(1);
					}
					(void) memset(dss_pathnames, 0, sz);
				}
				dss_pathnames[dss_npaths] = optarg;
				dss_npaths++;
			} else {
				(void) fprintf(stderr,
				    "%s: -s pathname too long.\n", av[0]);
			}
			break;

		case '?':
			usage();
			/* NOTREACHED */
		}
	}

	allflag = df_allflag;
	if (proto == NULL)
		proto = df_proto;
	if (provider == NULL)
		provider = df_provider;

	if (proto != NULL &&
	    strncasecmp(proto, NC_UDP, strlen(NC_UDP)) == 0) {
		if (nfs_server_vers_max == NFS_V4) {
			if (nfs_server_vers_min == NFS_V4) {
				fprintf(stderr,
				    "NFS version 4 is not supported "
				    "with the UDP protocol.  Exiting\n");
				exit(3);
			} else {
				fprintf(stderr,
				    "NFS version 4 is not supported "
				    "with the UDP protocol.\n");
			}
		}
	}

	if (optind < ac)
		usage();
	/*
	 * Check the ranges for min/max version specified
	 */
	if (nfs_server_vers_min > nfs_server_vers_max) {
		libnfs_log(libhandle, LOG_ERR,
		    gettext("minimum version > maximum "
		    "(%d > %d)"), nfs_server_vers_min, nfs_server_vers_max);
		abort();
	}
	if (nfs_server_vers_min < NFS_VERSMIN) {
		libnfs_log(libhandle, LOG_ERR,
		    gettext("minimum version too low "
		    "(%d)"), nfs_server_vers_min);
		abort();
	}
	if (nfs_server_vers_max > NFS_VERSMAX) {
		libnfs_log(libhandle, LOG_ERR,
		    gettext("maximum version too high "
		    "(%d)"), nfs_server_vers_max);
		abort();
	}

	/*
	 * handle pNFS data server stuff
	 */

	(void) libnfs_dserv_push_inst_datasets(libhandle);

	/*
	 * Set current dir to server root
	 */
	if (chdir(dir) < 0) {
		(void) fprintf(stderr, "%s:  ", MyName);
		perror(dir);
		exit(1);
	}

#ifndef DEBUG
	pipe_fd = daemonize_init();
#endif

	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/*
	 * If we've been given a list of paths to be used for distributed
	 * stable storage, and provided we're going to run a version
	 * that supports it, setup the DSS paths.
	 */
	if (dss_pathnames != NULL && nfs_server_vers_max >= DSS_VERSMIN) {
		if (dss_init(dss_npaths, dss_pathnames) != 0) {
			fprintf(stderr, "%s", "dss_init failed. Exiting.");
			exit(1);
		}
	}
	(void) thr_keycreate(&nfsd_tsd_key, NULL);

	/*
	 * Block all signals till we spawn other
	 * threads.
	 */
	(void) sigfillset(&sgset);
	(void) thr_sigsetmask(SIG_BLOCK, &sgset, NULL);

	/*
	 * Make sure to unregister any previous versions in case the
	 * user is reconfiguring the server in interesting ways.
	 */
	svc_unreg(NFS_PROGRAM, NFS_VERSION);
	svc_unreg(NFS_PROGRAM, NFS_V3);
	svc_unreg(NFS_PROGRAM, NFS_V4);
	svc_unreg(NFS_ACL_PROGRAM, NFS_ACL_V2);
	svc_unreg(NFS_ACL_PROGRAM, NFS_ACL_V3);

	/*
	 * Set up kernel RPC thread pool for the NFS server.
	 */
	if (nfssvcpool(maxservers)) {
		fprintf(stderr, "Can't set up kernel NFS service: %s. Exiting",
		    strerror(errno));
		exit(1);
	}

	/*
	 * Set up blocked thread to do LWP creation on behalf of the kernel.
	 */
	if (svcwait(NFS_SVCPOOL_ID)) {
		fprintf(stderr, "Can't set up NFS pool creator: %s. Exiting",
		    strerror(errno));
		exit(1);
	}

	doorfd = create_door();
	/*
	 * RDMA start and stop thread.
	 * Per pool RDMA listener creation and
	 * destructor thread.
	 *
	 * start rdma services and block in the kernel.
	 * (only if proto or provider is not set to TCP or UDP)
	 */
	if ((proto == NULL) && (provider == NULL)) {
		if (svcrdma(NFS_SVCPOOL_ID, nfs_server_vers_min,
		    nfs_server_vers_max, nfs_server_delegation,
		    doorfs)) {
			fprintf(stderr,
			    "Can't set up RDMA creator thread : %s",
			    strerror(errno));
		}
	}

	/*
	 * Now open up for signal delivery
	 */

	(void) thr_sigsetmask(SIG_UNBLOCK, &sgset, NULL);
	sigset(SIGTERM, sigflush);
	sigset(SIGUSR1, quiesce);

	/*
	 * Build a protocol block list for registration.
	 */
	protobp0 = protobp = (struct protob *)malloc(sizeof (struct protob));
	protobp->serv = "NFS";
	protobp->versmin = nfs_server_vers_min;
	protobp->versmax = nfs_server_vers_max;
	protobp->program = NFS_PROGRAM;
	protobp->flags = 0;

	protobp->next = (struct protob *)malloc(sizeof (struct protob));
	protobp = protobp->next;
	protobp->serv = "NFS_ACL";		/* not used */
	protobp->flags = 0;
	protobp->versmin = nfs_server_vers_min;
	/* XXX - this needs work to get the version just right */
	protobp->versmax = (nfs_server_vers_max > NFS_ACL_V3) ?
	    NFS_ACL_V3 : nfs_server_vers_max;
	protobp->program = NFS_ACL_PROGRAM;
	protobp->next = (struct protob *)NULL;

	if (allflag) {
		if (do_all(protobp0, nfssvc, 0) == -1) {
			fprintf(stderr, "setnetconfig failed : %s",
			    strerror(errno));
			exit(1);
		}
	} else if (proto) {
		/* there's more than one match for the same protocol */
		struct netconfig *nconf;
		NCONF_HANDLE *nc;
		bool_t	protoFound = FALSE;
		if ((nc = setnetconfig()) == (NCONF_HANDLE *) NULL) {
			fprintf(stderr, "setnetconfig failed : %s",
			    strerror(errno));
			goto done;
		}
		while (nconf = getnetconfig(nc)) {
			if (strcmp(nconf->nc_proto, proto) == 0) {
				protoFound = TRUE;
				do_one(nconf->nc_device, NULL,
				    protobp0, nfssvc, 0);
			}
		}
		(void) endnetconfig(nc);
		if (protoFound == FALSE) {
			fprintf(stderr,
			    "couldn't find netconfig entry for protocol %s",
			    proto);
		}
	} else if (provider)
		do_one(provider, proto, protobp0, nfssvc, 0);
	else {
		for (providerp = defaultproviders;
		    *providerp != NULL; providerp++) {
			provider = *providerp;
			do_one(provider, NULL, protobp0, nfssvc, 0);
		}
	}
done:

	free(protobp);
	free(protobp0);

	if (num_fds == 0) {
		fprintf(stderr, "Could not start NFS service for any protocol."
		    " Exiting");
		exit(1);
	}

	end_listen_fds = num_fds;

	/*
	 * nfsd is up and running as far as we are concerned.
	 */
	daemonize_fini(pipe_fd);

	/*
	 * Get rid of unneeded privileges.
	 */
	__fini_daemon_priv(PRIV_PROC_FORK, PRIV_PROC_EXEC, PRIV_PROC_SESSION,
	    PRIV_FILE_LINK_ANY, PRIV_PROC_INFO, (char *)NULL);

	/*
	 * Poll for non-data control events on the transport descriptors.
	 */
	poll_for_action();

	libnfs_handle_destroy(libhandle);

	/*
	 * If we get here, something failed in poll_for_action().
	 */
	return (1);
}

static int
nfssvcpool(int maxservers)
{
	struct svcpool_args npa;

	npa.id = NFS_SVCPOOL_ID;
	npa.maxthreads = maxservers;
	npa.redline = 0;
	npa.qsize = 0;
	npa.timeout = 0;
	npa.stksize = 0;
	npa.max_same_xprt = 0;
	return (_nfssys(SVCPOOL_CREATE, &npa));
}

/*
 * Establish NFS service thread.
 */
static int
nfssvc(int fd, struct netbuf addrmask, struct netconfig *nconf)
{
	struct nfs_svc_args nsa;

	nsa.fd = fd;
	nsa.netid = nconf->nc_netid;
	nsa.addrmask = addrmask;
#ifdef NOT_YET
	/* XXX - jw: this isn't where nfssrv is started. */
	nsa.dfd = create_door();
#endif
	if (strncasecmp(nconf->nc_proto, NC_UDP, strlen(NC_UDP)) == 0) {
		nsa.versmax = (nfs_server_vers_max > NFS_V3) ?
		    NFS_V3 : nfs_server_vers_max;
		nsa.versmin = nfs_server_vers_min;
		/*
		 * If no version left, silently do nothing, previous
		 * checks will have assured at least TCP is available.
		 */
		if (nsa.versmin > nsa.versmax)
			return (0);
	} else {
		nsa.versmax = nfs_server_vers_max;
		nsa.versmin = nfs_server_vers_min;
	}
	nsa.delegation = nfs_server_delegation;
	return (_nfssys(NFS_SVC, &nsa));
}

static void
usage(void)
{
	(void) fprintf(stderr,
	    "usage: %s ", MyName);
	(void) fprintf(stderr, "\n[ -l listen_backlog ] [ nservers ]\n");
	exit(1);
}

/*
 * Issue nfssys system call to flush all logging buffers asynchronously.
 *
 * NOTICE: It is extremely important to flush NFS logging buffers when
 *	   nfsd exits. When the system is halted or rebooted nfslogd
 *	   may not have an opportunity to flush the buffers.
 */
static void
nfsl_flush()
{
	struct nfsl_flush_args nfa;

	memset((void *)&nfa, 0, sizeof (nfa));
	nfa.version = NFSL_FLUSH_ARGS_VERS;
	nfa.directive = NFSL_ALL;	/* flush all asynchronously */

	if (_nfssys(LOG_FLUSH, &nfa) < 0)
		syslog(LOG_ERR, "_nfssys(LOG_FLUSH) failed: %s\n",
		    strerror(errno));
}

/*
 * SIGTERM handler.
 * Flush logging buffers and exit.
 */
static void
sigflush(int sig)
{
	nfsl_flush();
	_exit(0);
}

/*
 * SIGUSR1 handler.
 *
 * Request that server quiesce, then (nfsd) exit. For subsequent warm start.
 *
 * This is a Contracted Project Private interface, for the sole use
 * of Sun Cluster HA-NFS. See PSARC/2004/497.
 *
 * Equivalent to SIGTERM handler if nfs_server_vers_max < QUIESCE_VERSMIN.
 */
static void
quiesce(int sig)
{
	int error;
	int id = NFS_SVCPOOL_ID;

	if (nfs_server_vers_max >= QUIESCE_VERSMIN) {
		/* Request server quiesce at next shutdown */
		error = _nfssys(NFS4_SVC_REQUEST_QUIESCE, &id);

		/*
		 * ENOENT is returned if there is no matching SVC pool
		 * for the id. Possibly because the pool is not yet setup.
		 * In this case, just exit as if no error. For all other errors,
		 * just return and allow caller to retry.
		 */
		if (error && errno != ENOENT) {
			syslog(LOG_ERR,
			    "_nfssys(NFS4_SVC_REQUEST_QUIESCE) failed: %s",
			    strerror(errno));
			return;
		}
	}

	/* Flush logging buffers */
	nfsl_flush();

	_exit(0);
}

/*
 * DSS: distributed stable storage.
 * Create leaf directories as required, keeping an eye on path
 * lengths. Calls exit(1) on failure.
 * The pathnames passed in must already exist, and must be writeable by nfsd.
 * Note: the leaf directories under NFS4_VAR_DIR are not created here;
 * they're created at pkg install.
 */
static void
dss_mkleafdirs(uint_t npaths, char **pathnames)
{
	int i;
	char *tmppath = NULL;

	/*
	 * Create the temporary storage used by dss_mkleafdir() here,
	 * rather than in that function, so that it only needs to be
	 * done once, rather than once for each call. Too big to put
	 * on the function's stack.
	 */
	tmppath = (char *)malloc(MAXPATHLEN);
	if (tmppath == NULL) {
		syslog(LOG_ERR, "tmppath malloc failed. Exiting");
		exit(1);
	}

	for (i = 0; i < npaths; i++) {
		char *p = pathnames[i];

		dss_mkleafdir(p, NFS4_DSS_STATE_LEAF, tmppath);
		dss_mkleafdir(p, NFS4_DSS_OLDSTATE_LEAF, tmppath);
	}

	free(tmppath);
}

/*
 * Create "leaf" in "dir" (which must already exist).
 * leaf: should start with a '/'
 */
static void
dss_mkleafdir(char *dir, char *leaf, char *tmppath)
{
	/* MAXPATHLEN includes the terminating NUL */
	if (strlen(dir) + strlen(leaf) > MAXPATHLEN - 1) {
		fprintf(stderr, "stable storage path too long: %s%s. Exiting",
		    dir, leaf);
		exit(1);
	}

	(void) snprintf(tmppath, MAXPATHLEN, "%s/%s", dir, leaf);

	/* the directory may already exist: that's OK */
	if (mkdir(tmppath, NFS4_DSS_DIR_MODE) == -1 && errno != EEXIST) {
		fprintf(stderr, "error creating stable storage directory: "
		    "%s: %s. Exiting", strerror(errno), tmppath);
		exit(1);
	}
}

/*
 * Create the storage dirs, and pass the path list to the kernel.
 * This requires the nfssrv module to be loaded; the _nfssys() syscall
 * will fail ENOTSUP if it is not.
 * Use libnvpair(3LIB) to pass the data to the kernel.
 */
static int
dss_init(uint_t npaths, char **pathnames)
{
	int i, j, nskipped, error;
	char *bufp;
	uint32_t bufsize;
	size_t buflen;
	nvlist_t *nvl;

	if (npaths > 1) {
		/*
		 * We need to remove duplicate paths; this might be user error
		 * in the general case, but HA-NFSv4 can also cause this.
		 * Sort the pathnames array, and NULL out duplicates,
		 * then write the non-NULL entries to a new array.
		 * Sorting will also allow the kernel to optimise its searches.
		 */

		qsort(pathnames, npaths, sizeof (char *), qstrcmp);

		/* now NULL out any duplicates */
		i = 0; j = 1; nskipped = 0;
		while (j < npaths) {
			if (strcmp(pathnames[i], pathnames[j]) == NULL) {
				pathnames[j] = NULL;
				j++;
				nskipped++;
				continue;
			}

			/* skip i over any of its NULLed duplicates */
			i = j++;
		}

		/* finally, write the non-NULL entries to a new array */
		if (nskipped > 0) {
			int nreal;
			size_t sz;
			char **tmp_pathnames;

			nreal = npaths - nskipped;

			sz = nreal * sizeof (char *);
			tmp_pathnames = (char **)malloc(sz);
			if (tmp_pathnames == NULL) {
				fprintf(stderr, "tmp_pathnames malloc failed");
				exit(1);
			}

			for (i = 0, j = 0; i < npaths; i++)
				if (pathnames[i] != NULL)
					tmp_pathnames[j++] = pathnames[i];
			free(pathnames);
			pathnames = tmp_pathnames;
			npaths = nreal;
		}

	}

	/* Create directories to store the distributed state files */
	dss_mkleafdirs(npaths, pathnames);

	/* Create the name-value pair list */
	error = nvlist_alloc(&nvl, NV_UNIQUE_NAME, 0);
	if (error) {
		fprintf(stderr, "nvlist_alloc failed: %s.", strerror(errno));
		return (1);
	}

	/* Add the pathnames array as a single name-value pair */
	error = nvlist_add_string_array(nvl, NFS4_DSS_NVPAIR_NAME,
	    pathnames, npaths);
	if (error) {
		fprintf(stderr, "nvlist_add_string_array failed: %s.",
		    strerror(errno));
		nvlist_free(nvl);
		return (1);
	}

	/*
	 * Pack list into contiguous memory, for passing to kernel.
	 * nvlist_pack() will allocate the memory for the buffer,
	 * which we should free() when no longer needed.
	 * NV_ENCODE_XDR for safety across ILP32/LP64 kernel boundary.
	 */
	bufp = NULL;
	error = nvlist_pack(nvl, &bufp, &buflen, NV_ENCODE_XDR, 0);
	if (error) {
		fprintf(stderr, "nvlist_pack failed: %s.", strerror(errno));
		nvlist_free(nvl);
		return (1);
	}

	/* Now we have the packed buffer, we no longer need the list */
	nvlist_free(nvl);

	/*
	 * Let the kernel know in advance how big the buffer is.
	 * NOTE: we cannot just pass buflen, since size_t is a long, and
	 * thus a different size between ILP32 userland and LP64 kernel.
	 * Use an int for the transfer, since that should be big enough;
	 * this is a no-op at the moment, here, since nfsd is 32-bit, but
	 * that could change.
	 */
	bufsize = (uint32_t)buflen;
	error = _nfssys(NFS4_DSS_SETPATHS_SIZE, &bufsize);
	if (error) {
		fprintf(stderr,
		    "_nfssys(NFS4_DSS_SETPATHS_SIZE) failed: %s. ",
		    strerror(errno));
		free(bufp);
		return (1);
	}

	/* Pass the packed buffer to the kernel */
	error = _nfssys(NFS4_DSS_SETPATHS, bufp);
	if (error) {
		fprintf(stderr,
		    "_nfssys(NFS4_DSS_SETPATHS) failed: %s. ", strerror(errno));
		free(bufp);
		return (1);
	}

	/*
	 * The kernel has now unpacked the buffer and extracted the
	 * pathnames array, we no longer need the buffer.
	 */
	free(bufp);

	return (0);
}

/*
 * Quick sort string compare routine, for qsort.
 * Needed to make arg types correct.
 */
int
qstrcmp(const void *p1, const void *p2)
{
	char *s1 = *((char **)p1);
	char *s2 = *((char **)p2);

	return (strcmp(s1, s2));
}

/* struct used for stable storage */
struct ss_info {
	uint64_t filever;
	uint64_t verifier;
	uint64_t id_len;
};
#define	INFO_SZ	sizeof (struct ss_info)

/*
 * Create a file to hold the stable storage information for a client.
 * The id_val is variable length so the size of the write is calculated.
 * If the create or the write fails, there isn't much we can do.
 */
int
ss_write_client(char *path, struct ss_state_rec *statep)
{
	int fd, size, ret = 0, wbytes;

	if ((fd = open(path, O_WRONLY|O_CREAT, 0600)) == -1) {
		syslog(LOG_ERR, "open/create failed for %s", path);
		return (-1);
	}

	size = sizeof (struct ss_state_rec) + (int)statep->ss_len;
	if ((wbytes = write(fd, (void *)statep, size)) != size) {
		syslog(LOG_ERR,
		    "write failed for %s: write(%d) returned %d errno=%d\n",
		    path, size, wbytes, errno);
		ret = -1;
	}

	close(fd);

	/* if the write failed, don't keep the file around */
	if (ret == -1)
		remove(path);

	return (ret);
}

/*
 * This is the function that handles the door upcall command for writing out
 * stable storage for a client.  It creates the path name from the passed
 * in root of the path + "v4_state" + <instance/filename>.  Upon completion,
 * the status of the operation is returned via "door_return():
 */
void
ss_write_state(struct ss_arg *argp, char *dir)
{
	struct ss_state_rec *recp;
	struct ss_res res;
	char path[MAXPATHLEN];
	int error;

	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s", dir,
	    NFS4_DSS_STATE_LEAF, argp->path);

	recp = &argp->rec;

	error = ss_write_client(path, recp);

	if (error)
		res.status = NFS_DR_OPFAIL;
	else
		res.status = NFS_DR_SUCCESS;

	res.nsize = 0;
	(void) door_return((char *)&res, sizeof (struct ss_res), NULL, 0);
}

/*
 * Open a file and read in the stable storage info for a client.
 * Returns number of bytes used when successful.  Otherwise, returns
 * -2 for running out of buffer space and -1 for all other failures.
 */
int
read_client_state(char *path, char *statep, int remain)
{
	int fd, size, len = 0;
	int ret, killit;
	struct ss_info cl_info;
	struct ss_rd_state *sp = (struct ss_rd_state *)statep;
	struct ss_state_rec *recp;

	/*
	 * opening a directory for rdwr will fail, hence skipping entries
	 * that are not files, like '.' and '..'  Also, all the files
	 * that we created are 0600, if we can't open it now as rdwr,
	 * then we didn't create it.
	 */
	if ((fd = open(path, O_RDWR)) == -1)
		return (-1);

	ret = (read(fd, (void *)&cl_info, INFO_SZ) != INFO_SZ);

	len = (int)cl_info.id_len;
	killit = (cl_info.filever != NFS4_SS_VERSION || len < 1);
	if (ret || killit) {
		close(fd);
		(void) remove(path);
		syslog(LOG_ERR,
		    "Failed to retrieve stable storage for %s, file removed.",
		    path);
		return (-1);
	}

	/*
	 * Check if there are enough bytes left in the return buffer to put
	 * this client's info in.  If not return an error to indicate this.
	 */
	if (remain < (INFO_SZ + len)) {
		close(fd);
		return (-2); /* need to realloc */
	}

	size = sizeof (struct ss_state_rec) + len;
	recp = (struct ss_state_rec *)malloc(size);

	lseek(fd, 0, SEEK_SET);
	if (read(fd, (void *)recp, size) == size) {
		memcpy(sp->ssr_val, recp->ss_val, len);
		sp->ssr_veri = cl_info.verifier;
		sp->ssr_len = len;
		ret = len + sizeof (uint64_t) + sizeof (uint64_t);
	} else {
		ret = -1;
	}

	free(recp);
	close(fd);

	/* failed to read the info, get rid of the file */
	if (ret == -1)
		(void) remove(path);

	return (ret);
}

/*
 * Loop through all the files in a directory, which contains all the client's
 * stable storage for a given server instance.  When this is called with
 * both a path and an oldpath, the files are moved from one directory to
 * the other (ie from .../v4_state/... to .../v4_oldstate/...).
 * The routine returns the number of client state files that were read in, or
 * -1 if it ran out of room in the return buffer.
 * It will also update the number of bytes "used" as well as the "sz" of the
 * return buffer (if it is realloc'd).
 */
int
ss_read_clients(char *path, char *oldpath, char **resp, size_t *sz, int *used)
{
	DIR *dirp;
	int cnt = 0;
	struct dirent *dentp;
	char *p, *op;
	int plen, oplen, fd, done = 0;
	int ret, remain, rec_len;
	struct ss_res *resultp;
	char *statep;

	dirp = opendir(path);
	if (dirp == NULL) {
		if (errno == ENOENT) {
			if (mkdir(path, NFS4_DSS_DIR_MODE) == -1)
				syslog(LOG_ERR, "mkdir of %s failed", path);
		} else {
			syslog(LOG_ERR, "failed to open directory %s", path);
		}
		*used = 0;
		return (0);
	}

	plen = strlen(path);
	p = &path[plen];
	if (oldpath) {
		oplen = strlen(oldpath);
		op = &oldpath[oplen];
	}

	resultp = (struct ss_res *)*resp;
	statep = (char *)&resultp->rec;
	statep += *used;
	remain = *sz - *used;
	while (!done) {
		dentp = readdir(dirp);
		if (dentp == NULL) {
			done = 1;
			continue;
		}
		strlcpy(p, dentp->d_name, MAXPATHLEN - plen);
again:
		if ((ret = read_client_state(path, statep, remain)) < 0) {
			if (ret == -2) { /* out of buf space */
				char *ptr;
				/*
				 * If the size is already as big as the max
				 * buffer that doors will provide, then it
				 * can't be made bigger.  Return an error
				 * and let the caller try again with a
				 * bigger buffer.
				 */
				if (*sz >= MAX_DR_BUF_SZ) {
					*used = *sz * 2;
					return (-1);
				}

				ptr = *resp;
				*sz = MAX_DR_BUF_SZ;
				*resp = realloc_buf(ptr, *sz);
				if (*resp == NULL) {
					free(ptr);
					*used = MAX_DR_BUF_SZ;
					return (-1);
				}
				/*
				 * set all the pointers back to where we
				 * left off in filling this buffer.
				 */
				resultp = (struct ss_res *)*resp;
				statep = (char *)&resultp->rec;
				statep += *used;
				remain = *sz - *used;
				goto again;
			} else {	/* bad file */
				continue;
			}
		}

		/*
		 * round up the size of the record to be sure that we don't
		 * have any alignment problems when we move the pointers
		 * and cast it to the structure (both here and in kernel).
		 */
		rec_len = P2ROUNDUP(ret, 8);
		*used += rec_len;
		statep += rec_len;
		remain -= rec_len;
		cnt++; /* increment the number of clients */

		if (oldpath) {
			strlcpy(op, dentp->d_name, MAXPATHLEN - oplen);
			(void) rename(path, oldpath);
		}
	}
	*p = '\0';	/* put path back to the way it was */
	return (cnt);
}

void
ss_read_state(char *inst, char *dir, int rsize)
{
	char *path, *oldpath;
	char *resbuf;
	struct ss_res res;
	size_t sz;
	int used = 0;
	int cnt = 0;
	int ocnt;

	sz = rsize;	/* size of kernel return buffer */
	resbuf = (char *)alloc_buf(sz);
	if (resbuf == NULL) {
		syslog(LOG_ERR, "resbuf malloc failed. No stable storage");
		res.status = NFS_DR_NOMEM;
		res.nsize = 0;
		resbuf = (char *)&res;
		sz = sizeof (struct ss_res);
		goto dr_ret0;
	}
	path = (char *)malloc(MAXPATHLEN);
	if (path == NULL) {
		syslog(LOG_ERR, "path malloc failed. No stable storage");
		free_buf(resbuf);
		res.status = NFS_DR_NOMEM;
		res.nsize = 0;
		resbuf = (char *)&res;
		sz = sizeof (struct ss_res);
		goto dr_ret0;
	}
	oldpath = (char *)malloc(MAXPATHLEN);
	if (oldpath == NULL) {
		syslog(LOG_ERR, "oldpath malloc failed. No stable storage");
		free_buf(resbuf);
		res.status = NFS_DR_NOMEM;
		res.nsize = 0;
		resbuf = (char *)&res;
		sz = sizeof (struct ss_res);
		goto dr_ret1;
	}
	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s/", dir,
	    NFS4_DSS_STATE_LEAF, inst);
	(void) snprintf(oldpath, MAXPATHLEN, "%s/%s/%s/", dir,
	    NFS4_DSS_OLDSTATE_LEAF, inst);

	ocnt = ss_read_clients(oldpath, NULL, &resbuf, &sz, &used);
	if (ocnt != -1)
		cnt = ss_read_clients(path, oldpath, &resbuf, &sz, &used);

	if (ocnt == -1 || cnt == -1) {
		if (resbuf)
			free_buf(resbuf);
		sz = sizeof (struct ss_res);
		res.status = NFS_DR_OVERFLOW;
		res.nsize = used;
		resbuf = (char *)&res;
	} else {
		cnt += ocnt;
		((struct ss_res *)resbuf)->status = NFS_DR_SUCCESS;
		((struct ss_res *)resbuf)->nsize = cnt;
		if (used == 0)
			sz = sizeof (struct ss_res);
		else
			sz = used + (sizeof (int) * 2);
	}
	free(oldpath);
dr_ret1:
	free(path);
dr_ret0:
	(void) door_return(resbuf, sz, NULL, 0);
}

void
ss_delete_state(char *path, char *dir)
{
	struct ss_res res;
	char expired[MAXPATHLEN];

	/*
	 * path contains instance/file
	 */
	(void) snprintf(expired, MAXPATHLEN, "%s/%s/%s", dir,
	    NFS4_DSS_STATE_LEAF, path);

	(void) remove(expired);

	res.status = NFS_DR_SUCCESS;
	res.nsize = 0;
	(void) door_return((char *)&res, sizeof (struct ss_res), NULL, 0);
}

void
ss_delete_old(char *inst, char *dir)
{
	struct ss_res res;
	char path[MAXPATHLEN];
	DIR *dirp;
	struct dirent *dentp;
	char *p;
	int plen, done = 0;
	int len;

	(void) snprintf(path, MAXPATHLEN, "%s/%s/%s/", dir,
	    NFS4_DSS_OLDSTATE_LEAF, inst);

	dirp = opendir(path);
	if (dirp == NULL) {
		syslog(LOG_ERR, "ss_delete_old(): opendir of %s failed", path);
		res.status = NFS_DR_BADDIR;
		goto out;
	}

	plen = strlen(path);
	p = &path[plen];

	while (!done) {
		dentp = readdir(dirp);
		if (dentp == NULL) {
			done = 1;
			continue;
		}

		/*
		 * skip dot and dotdot.  No client name will be one or two
		 * characters long and start with a dot.
		 */
		len = strlen(dentp->d_name);
		if (len < 3 && dentp->d_name[0] == '.')
			continue;

		strlcpy(p, dentp->d_name, MAXPATHLEN - plen);
		(void) remove(path);
	}

	res.status = NFS_DR_SUCCESS;
out:
	res.nsize = 0;
	(void) door_return((char *)&res, sizeof (struct ss_res), NULL, 0);
}

void
ss_door_func(void *c, char *argp, size_t sz, door_desc_t *dp, uint_t cnt)
{
	struct ss_arg *ss_argp;
	struct ss_res res;

	/* validate the arg */
	if (sz < sizeof (struct ss_arg)) {
		syslog(LOG_ERR, "Bad arg passed to ss_door_func()");
		res.status = NFS_DR_BADARG;
		res.nsize = 0;
		(void) door_return((char *)&res, sizeof (struct ss_res),
		    NULL, 0);
	}

	ss_argp = (struct ss_arg *)argp;
	switch (ss_argp->cmd) {
	case NFS4_SS_READ:
		ss_read_state(ss_argp->path, NFS4_DSS_VAR_DIR, ss_argp->rsz);
	case NFS4_SS_WRITE:
		clean_buf();
		ss_write_state(ss_argp, NFS4_DSS_VAR_DIR);
	case NFS4_SS_DELETE_CLNT:
		clean_buf();
		ss_delete_state(ss_argp->path, NFS4_DSS_VAR_DIR);
	case NFS4_SS_DELETE_OLD:
		clean_buf();
		ss_delete_old(ss_argp->path, NFS4_DSS_VAR_DIR);
	default:
		syslog(LOG_ERR, "Bad command passed to ss_door_func()");
		break;
	}

	res.status = NFS_DR_BADCMD;
	res.nsize = 0;
	(void) door_return((char *)&res, sizeof (struct ss_res), NULL, 0);
}

static int
create_door(void)
{
	int dfd = -1;

	if ((dfd = door_create(ss_door_func, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL)) == -1)
		syslog(LOG_ERR, "Unable to create door, no stable storage\n");

	return (dfd);
}

struct nfsd_ss_tsd {
	int nfsd_len;
	char *nfsd_buf;
};
typedef struct nfsd_ss_tsd nfsd_ss_tsd_t;

static void *
alloc_buf(size_t size)
{
	nfsd_ss_tsd_t *tsd = NULL;

	(void) thr_getspecific(nfsd_tsd_key, (void **)&tsd);
	if (tsd == NULL) {
		tsd = (nfsd_ss_tsd_t *)malloc(sizeof (nfsd_ss_tsd_t));
		if (tsd == NULL) {
			return (NULL);
		}
		tsd->nfsd_buf = malloc(size);
		if (tsd->nfsd_buf != NULL)
			tsd->nfsd_len = size;
		else
			tsd->nfsd_len = 0;
		(void) thr_setspecific(nfsd_tsd_key, (void *)tsd);
	} else {
		if (tsd->nfsd_buf && (tsd->nfsd_len != size)) {
			free(tsd->nfsd_buf);
			tsd->nfsd_buf = malloc(size);
			if (tsd->nfsd_buf != NULL)
				tsd->nfsd_len = size;
			else {
				tsd->nfsd_len = 0;
			}
		}
	}
	return (tsd->nfsd_buf);
}

static void *
realloc_buf(char *bp, size_t size)
{
	nfsd_ss_tsd_t *tsd = NULL;

	(void) thr_getspecific(nfsd_tsd_key, (void **)&tsd);
	if (tsd == NULL)	/* something went horribly wrong */
		return (NULL);

	tsd->nfsd_buf = realloc(bp, size);
	if (tsd->nfsd_buf != NULL)
		tsd->nfsd_len = size;
	else
		tsd->nfsd_len = 0;

	return (tsd->nfsd_buf);
}


static void
free_buf(char *buf)
{
	nfsd_ss_tsd_t *tsd = NULL;

	(void) thr_getspecific(nfsd_tsd_key, (void **)&tsd);

	free(buf);
	free(tsd);

	(void) thr_setspecific(nfsd_tsd_key, (void *)NULL);
}

static void
clean_buf(void)
{
	nfsd_ss_tsd_t *tsd = NULL;

	(void) thr_getspecific(nfsd_tsd_key, (void **)&tsd);
	if (tsd == NULL)
		return;

	if (tsd->nfsd_buf)
		free(tsd->nfsd_buf);

	free(tsd);
	(void) thr_setspecific(nfsd_tsd_key, (void *)NULL);
}
