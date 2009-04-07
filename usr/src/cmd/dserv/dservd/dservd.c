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

/*
 * dservd -- daemon for dserv
 */

#include <nfs/nfs4.h>
#include <libdserv.h>
#include <libintl.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>
#include <dservd.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

static void
daemonize()
{
	int frc;

	(void) chdir("/");
	closefrom(0);
	(void) open("/dev/null", O_RDONLY);
	(void) open("/dev/null", O_WRONLY);
	(void) dup(1);
	(void) setsid();

	frc = fork();
	if (frc < 0) {
		dserv_log(NULL, LOG_ERR,
		    gettext("fork() system call failed: %m\n"));
		exit(1);
	} else if (frc > 0) {
		exit(0);
	}
}

static void
instance_shutdown(void)
{
	dserv_handle_t *handle;
	int error = 0;

	handle = dserv_handle_create();
	if (handle == NULL) {
		dserv_log(NULL, LOG_ERR,
		    gettext("shutdown: cannot create libdserv handle: %m"));
		exit(1);
	}
	if (dserv_myinstance(handle) != 0) {
		dserv_log(handle, LOG_ERR, NULL);
		exit(1);
	}
	error = dserv_kmod_instance_shutdown(handle);
	if (error) {
		dserv_log(handle, LOG_ERR,
		    gettext("ERROR on dserv_kmod_instance_shutdown"));
	}

	dserv_handle_destroy(handle);
	exit(0);
}

int
main(int argc, char *argv[])
{
	dserv_setmds_args_t setmds;
	dserv_handle_t *handle;
	char *poolname, *mdsaddr;
	struct sigaction act;

	(void) sigfillset(&act.sa_mask);
	act.sa_handler = instance_shutdown;
	act.sa_flags = 0;

	(void) sigaction(SIGTERM, &act, NULL);

	daemonize();

	/* no need for _create_daemon_lock; we use SMF(5). */
	svcsetprio();

	handle = dserv_handle_create();
	if (handle == NULL)
		dserv_log(NULL, LOG_ERR,
		    gettext("cannot create libdserv handle: %m"));
	if (dserv_myinstance(handle) != 0) {
		dserv_log(handle, LOG_ERR, NULL);
		exit(1);
	}

	for (poolname = dserv_firstpool(handle);
	    poolname != NULL;
	    poolname = dserv_nextpool(handle)) {
		if (dserv_error(handle) != DSERV_ERR_NONE)
			break;

		dserv_log(handle, LOG_INFO, "dataset: %s\n", poolname);
		if (dserv_kmod_regpool(handle, poolname) != 0)
			break;
	}
	if (dserv_error(handle) != DSERV_ERR_NONE) {
		dserv_log(handle, LOG_ERR, NULL);
		exit(1);
	}

	mdsaddr = dserv_getmds(handle);
	if (mdsaddr == NULL) {
		if (dserv_error(handle) != DSERV_ERR_NONE)
			dserv_log(handle, LOG_ERR, NULL);
		else
			dserv_log(handle, LOG_ERR,
			    gettext("MDS not set; aborting"));
		exit(1);
	}
	if (strlcpy(setmds.dsm_mds_uaddr, mdsaddr,
	    sizeof (setmds.dsm_mds_uaddr)) >= sizeof (setmds.dsm_mds_uaddr)) {
		dserv_log(handle, LOG_ERR,
		    gettext("MDS address too long; aborting"));
		exit(1);
	}
	/* XXX need a way to have non-tcp addresses */
	(void) strcpy(setmds.dsm_mds_netid, "tcp");
	dserv_kmod_setmds(handle, &setmds);

	dserv_daemon(handle);

	dserv_handle_destroy(handle);

	return (0);
}
