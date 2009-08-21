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

#include <stdio.h>
#include <stdlib.h>
#include <stropts.h>
#include <signal.h>
#include <fcntl.h>
#include <door.h>
#include <thread.h>
#include <priv_utils.h>
#include <locale.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <nfs/nfs4.h>
#include <nfs/spe.h>
#include <rpcsvc/daemon_utils.h>
#include <arpa/nameser.h>
#include <nfs/nfssys.h>
#include <sys/sdt.h>
#include <errno.h>

#include "spedaemon.h"

static char	*MyName;

thread_t	sig_thread;

extern int sped_daemon_load(char *server_policy_file,
	char *server_npool_file);

extern void spe_global_dump(void);

/*
 * Processing for daemonization
 */
static void
daemonize(void)
{
	switch (fork()) {
		case -1:
			perror("sped: can't fork");
			exit(2);
			/* NOTREACHED */
		case 0:		/* child */
			break;

		default:	/* parent */
			_exit(0);
	}

	if (chdir("/") < 0)
		syslog(LOG_ERR, gettext("chdir /: %m"));

	/*
	 * Close stdin, stdout, and stderr.
	 * Open again to redirect input+output
	 */
	(void) close(0);
	(void) close(1);
	(void) close(2);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();
}

static void
sped_load(void)
{
	const char	*whoami = "sped_load";
	static int	setup_done = 0;

	sped_daemon_load("/etc/policies.spe", "/etc/npools.spe");
	sped_populate_policies(Spe_policies);
	sped_populate_npools(Spe_npools);
}

/* ARGSUSED */
static void *
sig_handler(void *arg)
{
	sigset_t	sigset;
	siginfo_t	si;
	int		ret;

	(void) sigemptyset(&sigset);
	(void) sigaddset(&sigset, SIGHUP);
	(void) sigaddset(&sigset, SIGTERM);
	(void) sigaddset(&sigset, SIGINT);

	/*CONSTCOND*/
	while (1) {
		if ((ret = sigwaitinfo(&sigset, &si)) != 0) {
			switch (si.si_signo) {
				case SIGHUP:
					sped_load();
					break;
				case SIGINT:
					exit(0);
				case SIGTERM:
				default:
					exit(si.si_signo);
			}
		}
	}

	/*NOTREACHED*/
	return (NULL);
}

/*
 * Thread initialization. Mask out all signals we want our
 * signal handler to handle for us from any other threads.
 */
static void
thr_init(void)
{
	sigset_t sigset;
	long	 thr_flags = (THR_NEW_LWP|THR_DAEMON);

	/*
	 * Before we kick off any other threads, mask out desired
	 * signals from main thread so that any subsequent threads
	 * don't receive said signals.
	 */
	(void) thr_sigsetmask(NULL, NULL, &sigset);
	(void) sigaddset(&sigset, SIGHUP);
	(void) sigaddset(&sigset, SIGTERM);
	(void) sigaddset(&sigset, SIGINT);
	(void) thr_sigsetmask(SIG_SETMASK, &sigset, NULL);

	if (thr_create(NULL, 0, sig_handler, 0, thr_flags, &sig_thread)) {
		syslog(LOG_ERR,
		    gettext("Failed to create signal handling thread"));
		exit(4);
	}
}

static void
daemon_init(void)
{
	thr_init();

	sped_load();
}

static int
start_svcs(void)
{
	sped_load();

	/*
	 * Wait for incoming calls
	 */
	/*CONSTCOND*/
	while (1)
		(void) pause();

	syslog(LOG_ERR, gettext("Door server exited"));
	return (10);
}

/* ARGSUSED */
int
main(int argc, char **argv)
{
	MyName = argv[0];

	(void) setlocale(LC_ALL, "");
	(void) textdomain(TEXT_DOMAIN);

	(void) _create_daemon_lock(SPED, DAEMON_UID, DAEMON_GID);

	/*
	 * Initialize the daemon to basic + sys_nfs
	 */
	if (__init_daemon_priv(PU_RESETGROUPS|PU_CLEARLIMITSET,
	    DAEMON_UID, DAEMON_GID, PRIV_SYS_NFS, (char *)NULL) == -1) {
		(void) fprintf(stderr, gettext("%s PRIV_SYS_NFS privilege "
		    "missing\n"), MyName);
		exit(1);
	}

	daemonize();

	/* Basic privileges we don't need, remove from E/P. */
	__fini_daemon_priv(PRIV_PROC_EXEC, PRIV_PROC_FORK, PRIV_FILE_LINK_ANY,
	    PRIV_PROC_SESSION, PRIV_PROC_INFO, (char *)NULL);

	switch (_enter_daemon_lock(SPED)) {
		case 0:
			break;

		case -1:
			syslog(LOG_ERR, "error locking for %s: %s", SPED,
			    strerror(errno));
			exit(3);

		default:
			/* daemon was already running */
			exit(0);
	}
	openlog(MyName, LOG_PID | LOG_NDELAY, LOG_DAEMON);

	/* Initialize daemon subsystems */
	daemon_init();

	/* start services */
	return (start_svcs());
}
