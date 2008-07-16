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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * dservadm -- administrative CLI for dserv
 */

#include <stdio.h>
#include <libintl.h>
#include <libdserv.h>
#include <strings.h>

#ifndef TEXT_DOMAIN
#define	TEXT_DOMAIN	"SUNW_OST_OSCMD"
#endif /* TEXT_DOMAIN */

struct dservadm_cmd;
typedef int (*dservadm_func)(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);

static int dservadm_create(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_destroy(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_enable(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_disable(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_addstorage(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_dropstorage(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_liststorage(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_addmds(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_dropmds(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);
static int dservadm_listmds(dserv_handle_t *,
    int, char **, struct dservadm_cmd *);


typedef enum {
	USAGE_NONE,
	USAGE_CREATE,
	USAGE_DESTROY,
	USAGE_ENABLE,
	USAGE_DISABLE,
	USAGE_ADDSTORAGE,
	USAGE_ADDSTOR,
	USAGE_DROPSTORAGE,
	USAGE_DROPSTOR,
	USAGE_LISTSTORAGE,
	USAGE_LISTSTOR,
	USAGE_ADDMDS,
	USAGE_DROPMDS,
	USAGE_LISTMDS
} dservadm_usage_t;

typedef struct dservadm_cmd {
	char *name;
	dservadm_func func;
	dservadm_usage_t usage;
} dservadm_cmd_t;

static dservadm_cmd_t dservadm_cmd[] = {
	{"create", dservadm_create, USAGE_CREATE},
	{"destroy", dservadm_destroy, USAGE_DESTROY},
	{"enable", dservadm_enable, USAGE_ENABLE},
	{"disable", dservadm_disable, USAGE_DISABLE},

	{NULL},
	{"addstorage", dservadm_addstorage, USAGE_ADDSTORAGE},
	{"addstor", dservadm_addstorage, USAGE_ADDSTOR},
	{"dropstorage", dservadm_dropstorage, USAGE_DROPSTORAGE},
	{"dropstor", dservadm_dropstorage, USAGE_DROPSTOR},
	{"liststorage", dservadm_liststorage, USAGE_LISTSTORAGE},
	{"liststor", dservadm_liststorage, USAGE_LISTSTOR},

	{NULL},
	{"addmds", dservadm_addmds, USAGE_ADDMDS},
	{"dropmds", dservadm_dropmds, USAGE_DROPMDS},
	{"listmds", dservadm_listmds, USAGE_LISTMDS}
};

#define	NUM_CMDS (sizeof (dservadm_cmd) / sizeof (dservadm_cmd[0]))

static char *
usage_synopsis(dservadm_usage_t which)
{
	switch (which) {
	case USAGE_CREATE:
		return ("dservadm create <instance>");
	case USAGE_DESTROY:
		return ("dservadm destroy <instance>");

	case USAGE_ENABLE:
		return ("dservadm enable [ -i <instance> ]");
	case USAGE_DISABLE:
		return ("dservadm disable [ -i <instance> ]");

	case USAGE_ADDSTORAGE:
		return ("dservadm addstorage [ -i <instance> ] " \
		    "<pnfs-dataset-name>");
	case USAGE_ADDSTOR:
		return ("dservadm addstor [ -i <instance> ] " \
		    "<pnfs-dataset-name>");
	case USAGE_DROPSTORAGE:
		return ("dservadm dropstorage [ -i <instance> ] " \
		    "<pnfs-dataset-name>");
	case USAGE_DROPSTOR:
		return ("dservadm dropstor [ -i <instance> ] " \
		    "<pnfs-dataset-name>");
	case USAGE_LISTSTORAGE:
		return ("dservadm liststorage [ -i <instance> ]");
	case USAGE_LISTSTOR:
		return ("dservadm liststor [ -i <instance> ]");

	case USAGE_ADDMDS:
		return ("dservadm addmds [ -i <instance> ] "
		    "<universal-address>");
	case USAGE_DROPMDS:
		return ("dservadm dropmds [ -i <instance> ]");
	case USAGE_LISTMDS:
		return ("dservadm listmds [ -i <instance> ]");
	default:
		return ("dservadm <command> <arguments>");
	}
}

static char *
usage_desc(dservadm_usage_t which)
{
	switch (which) {
	case USAGE_CREATE:
		return ("    Creates a new dserv instance");
	case USAGE_DESTROY:
		return ("    Destroys a dserv instance");

	case USAGE_ENABLE:
		return ("    Enables dserv service");
	case USAGE_DISABLE:
		return ("    Disables dserv service");

	case USAGE_ADDSTOR:
	case USAGE_ADDSTORAGE:
		return ("    Add the dataset specified by <dataset-name>"
		    "\n    to the list of datasets dedicated to pNFS service."
		    "\n    Alias for addstorage is addstor.");
	case USAGE_DROPSTOR:
	case USAGE_DROPSTORAGE:
		return ("    Drop the dataset specified by <dataset-name>"
		    "\n    from the list of datasets dedicated to pNFS service."
		    "\n    Use with caution.  Alias for dropstorage is"
		    "\n    dropstor.");
	case USAGE_LISTSTOR:
	case USAGE_LISTSTORAGE:
		return ("    List datasets allocated to dserv.  Alias for"
		    "\n    liststorage is liststor.");

	case USAGE_ADDMDS:
		return ("   Add the metadata server specified by"
		    "\n   <universal-address>.  <universal-address> must be"
		    "\n   of the form [h1.h2.h3.h4.p1.p2].  Only one"
		    "\n   metadata server can be added per dserv instance.");
	case USAGE_DROPMDS:
		return ("   Drop the metadata server.");
	case USAGE_LISTMDS:
		return ("    List the metadata server for this dserv.");
	default:
		return ("dservadm <command> <arguments>");
	}
}

static void
usage(dservadm_usage_t which)
{
	int i;

	fprintf(stderr,
	    gettext("Usage: dservadm command [ options ] [ args ]\n"));

	if (which != USAGE_NONE) {
		fprintf(stderr, "%s\n%s\n\n",
		    usage_synopsis(which), usage_desc(which));
		exit(2);
	}

	for (i = 0; i < NUM_CMDS; i++) {
		if (dservadm_cmd[i].name == NULL)
			continue;
		fprintf(stderr, "%s\n\n",
		    usage_synopsis(dservadm_cmd[i].usage));
	}

	exit(2);
}

static int
optinstance(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_usage_t u)
{
	char *instance = DSERV_DEFAULT_INSTANCE;
	char c;

	opterr = 0;

	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			instance = strdup(optarg);
			break;
		case '?':
			usage(u);
			break;
		}
	}

	return (dserv_setinstance(handle, instance, 0));
}

static int
dservadm_create(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	if (argc != 2)
		usage(c->usage);

	return (dserv_create_instance(handle, argv[1]));
}

static int
dservadm_destroy(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	if (argc != 2)
		usage(c->usage);

	return (dserv_destroy_instance(handle, argv[1]));
}

static int
dservadm_enable(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	return (dserv_enable(handle));
}

static int
dservadm_disable(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	return (dserv_disable(handle));
}

static int
dservadm_addstorage(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(USAGE_ADDSTORAGE);


	rc = dserv_addprop(handle, DSERV_PROP_ZPOOLS, argv[0]);
	if (rc != 0)
		return (rc);

	return (dserv_refresh(handle));
}

static int
dservadm_dropstorage(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(USAGE_DROPSTORAGE);

	rc = dserv_dropprop(handle, DSERV_PROP_ZPOOLS, argv[0]);
	if (rc != 0)
		return (rc);

	return (dserv_refresh(handle));
}

static int
dservadm_liststorage(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc = 0;
	char *pool;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);

	printf(gettext("storage:\n"));

	for (pool = dserv_firstpool(handle);
	    pool != NULL; pool = dserv_nextpool(handle)) {
		if (dserv_error(handle) != DSERV_ERR_NONE) {
			fprintf(stderr, "%s\n", dserv_strerror(handle));
			rc = -1;
			break;
		}

		printf("    %s\n", pool);
	}

	return (rc);
}

static int
dservadm_addmds(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage(USAGE_ADDMDS);


	rc = dserv_addprop(handle, DSERV_PROP_MDS, argv[0]);
	if (rc != 0)
		return (rc);

	return (dserv_refresh(handle));
}

static int
dservadm_dropmds(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);
	argc -= optind;
	argv += optind;

	rc = dserv_dropprop(handle, DSERV_PROP_MDS, NULL);
	if (rc != 0)
		return (rc);

	return (dserv_refresh(handle));
}

static int
dservadm_listmds(dserv_handle_t *handle,
    int argc, char *argv[], dservadm_cmd_t *c)
{
	int rc = 0;
	char *mds;

	if (optinstance(handle, argc, argv, c->usage) != 0)
		return (1);

	printf(gettext("mds:\n"));

	mds = dserv_getmds(handle);
	if (dserv_error(handle) != DSERV_ERR_NONE) {
		fprintf(stderr, "%s\n", dserv_strerror(handle));
		rc = -1;
		return (rc);
	}
	if (mds != NULL)
		printf("    %s\n", mds);

	return (rc);
}

int
main(int argc, char *argv[])
{
	dservadm_cmd_t *cmd = NULL;
	dserv_handle_t *libhandle;
	int rc = 2;
	int i;

	if (argc < 2)
		usage(USAGE_NONE);

	for (i = 0; i < NUM_CMDS; i++) {
		cmd = dservadm_cmd + i;
		if ((cmd->name != NULL) && (strcmp(cmd->name, argv[1]) == 0))
			break;
	}

	if (i < NUM_CMDS) {
		libhandle = dserv_handle_create();
		rc = cmd->func(libhandle, argc - 1, argv + 1, cmd);
		if (rc != 0) {
			fprintf(stderr, "dservadm: %s\n",
			    dserv_strerror(libhandle));
			rc = 1;
		}
		dserv_handle_destroy(libhandle);
	} else {
		usage(USAGE_NONE);
	}

	return (rc);
}
