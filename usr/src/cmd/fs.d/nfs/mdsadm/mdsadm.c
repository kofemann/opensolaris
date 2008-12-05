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

#include <stdio.h>
#include <strings.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/param.h>
#include <libintl.h>
#include <locale.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>

#include <sys/systeminfo.h>
#include <netdb.h>
#include <nss_dbdefs.h>

#include <nfs/nfs.h>
#include <nfs/export.h>
#include <nfs/nfssys.h>

extern char *optarg;
extern int optind;
extern int _nfssys(enum nfssys_op, void *);

int verbose = 0;
char *prog;

/*
 * taken from layoutrecall_type4 enum defined in nfs41_kprot.h
 */
#define	LAYOUTRECALL4_FILE	1
#define	LAYOUTRECALL4_FSID	2
#define	LAYOUTRECALL4_ALL	3

/*
 * operation list:
 *   things we can do with this command
 */
typedef enum {
	OP_INVAL = -1,
	OP_RECALL,
	OP_NOTIFY,
	MAX_OP

} oper_t;

char *op[] = {
	"recall",
	"notify",
	NULL
};

/*
 * type list:
 *   The type of things we can operation on.
 */
typedef enum {
	OT_INVAL = -1,
	OT_LAYOUT,
	OT_NOTIFY_CHANGE,
	OT_NOTIFY_DELETE,
	MAX_OT
} obj_type_t;

char *type[] = {
	"layout",
	"change",
	"delete",
	NULL
};

enum notify_how { NOTIFY_CHANGE = 1, NOTIFY_DELETE };

typedef struct {
	int  required;
	char *attr_name;
	void *attr_val;
} attr_t;

static char usage_lo_recall[] =
" To recall a layout: \n\t"
"mdsadm -o recall -t layout -a [file=<filename> | fsid=<filename> | all]\n";

static char usage_notify[] =
" To do a device notification: \n\t"
"mdsadm -o notify -t [change | delete] -a DID#\n";

struct {
	char *msg;
} usage_messages [] = {
	{ usage_lo_recall },
	{ usage_notify }
};

void
usage(char *msg)
{
	int i;

	fprintf(stderr, "%s\n", msg);
	for (i = 0; i < sizeof (usage_messages)/sizeof (char *); i++)
		fprintf(stderr, usage_messages[i].msg);
	exit(1);
}

oper_t
validate_operation(char *argp)
{
	int i;

	for (i = OP_INVAL+1; op[i] != NULL; i++)
		if (strcmp(argp, op[i]) == 0)
			return (i);
	return (OP_INVAL);
}

obj_type_t
validate_type(char *argp)
{
	int i;

	for (i = OT_INVAL+1; i < MAX_OT; i++)
		if (strcmp(argp, type[i]) == 0)
			return (i);

	return (OT_INVAL);
}

int
validate_attribute(attr_t *valid_attr, char *argp, int *idx)
{
	int i;
	char *ap, *attr, *val;

	ap = strdup(argp);

	attr = strtok(ap, "=");
	val = strtok(NULL, "\0");

	if (attr == NULL || val == NULL) {
		free(ap);
		printf("Error unable to parse args '%s'\n", argp);
		exit(1);
	}

	for (i = 0; valid_attr[i].attr_name != NULL; i++) {
		if (strcmp(ap, valid_attr[i].attr_name) == 0) {
			valid_attr[i].attr_val = val;
			*idx = i;
			return (1);
		}
	}
	free(ap);
	*idx = -1;
	printf("Warning!: Ignoring %s\n", argp);
	return (0);
}

/*
 * validate the passed in device and convert to uaddr
 */
char *
get_uaddrstr(char *dev, char *ip, unsigned short port)
{
	char tmp[1024];

	if ((strcmp(dev, "tcp")  != 0) &&
	    (strcmp(dev, "udp")  != 0) &&
	    (strcmp(dev, "tcp6") != 0) &&
	    (strcmp(dev, "udp6") != 0)) {
		return (NULL);
	}
	(void) sprintf(tmp, "%s.%d.%d", ip, port >> 8, port & 255);
	return (strdup(tmp));
}

/*
 * lo_type:  4 bytes
 * lo_fname: 4 bytes namelen + MAXPATHLEN bytes
 */
char xdrbuf[RNDUP(MAXPATHLEN) + BYTES_PER_XDR_UNIT * 2];

int
layout_recall(int attr_count, char *attrs[])
{
	int	valid_count = 0, i, nax;
	int	rc;
	char	*tstr;
	struct mds_reclo_args lorec;
	XDR	xdrs;

	attr_t need_attr[] = {
		{0, "file", NULL},
		{0, "fsid", NULL},
		{0, "all", NULL},
		NULL
	};

	int num_attr = sizeof (need_attr) / sizeof (attr_t) - 1;

	int	lotype[] = {
		LAYOUTRECALL4_FILE,
		LAYOUTRECALL4_FSID,
		LAYOUTRECALL4_ALL
	};

	if (attr_count != 1) {
		puts("layout_recall: invalid number of attributes\n");
		usage(usage_lo_recall);
	}

	if (strcmp(attrs[0], "all") == 0) {
		nax = 2;
		valid_count = 1;
	} else {
		valid_count = validate_attribute(need_attr, attrs[0], &nax);
	}

	printf("attrs[0] = %s\n", attrs[0]);

	if (valid_count != 1) {
		puts("layout_recall: invalid attribute value\n");
		usage(usage_lo_recall);
	}

	lorec.lo_fname = need_attr[nax].attr_val;
	lorec.lo_type = lotype[nax];

	printf("Recalling Layout: (lorec=0x%p)\n", &lorec);
	printf("\t%s (0x%x) = %s (0x%p)\n", need_attr[nax].attr_name,
	    lorec.lo_type, lorec.lo_fname ? lorec.lo_fname : "",
	    lorec.lo_fname);

	xdrmem_create(&xdrs, xdrbuf, sizeof (xdrbuf), XDR_ENCODE);
	if (! xdr_int(&xdrs, &lorec.lo_type)) {
		printf("error: couldn't XDR encode layout_recall type\n");
		usage(usage_lo_recall);
	}

	if (! xdr_string(&xdrs, &lorec.lo_fname, MAXNAMELEN)) {
		printf("error: couldn't XDR encode layout_recall file name\n");
		usage(usage_lo_recall);
	}

	rc = _nfssys(MDS_RECALL_LAYOUT, &xdrbuf);

	if (rc != 0)
		perror("nfssys:");

	return (0);
}


int
layout(oper_t op, int count, char *attrs[])
{
	int rc = 0;

	switch (op) {
	case OP_RECALL:
		rc = layout_recall(count, attrs);
		break;
	default:
		usage("Bad operation for layout\n");
		break;
	}

	return (rc);
}

/* mdsadm -o notify -t {delete|change} -a DID# */

int
notify(oper_t op, obj_type_t ty, int attr_count, char *attrs[])
{
	int	rc;
	struct mds_notifydev_args node;

	if (attr_count != 1) {
		puts("notify: invalid number of attributes\n");
		usage(usage_notify);
	}

	node.dev_id = strtol(attrs[0], 0, 0);
	node.notify_how = (ty == OT_NOTIFY_CHANGE) ?
	    NOTIFY_CHANGE : NOTIFY_DELETE;
	node.immediate = 0;	/* hmmm */

	rc = _nfssys(MDS_NOTIFY_DEVICE, &node);

	if (rc != 0)
		perror("nfssys:");

	return (0);
}

int
main(int argc, char **argv)
{
	int c;

	oper_t op = OP_INVAL;
	obj_type_t obj_type;
	int attr_count = 0;
	char *attr_args[1024];

	prog = argv[0];

	while ((c = getopt(argc, argv, "o:t:a:v")) != -1) {
		switch (c) {
		/* user asks for verbose output */
		case 'v':
			verbose++;
			break;

		/* collect an operation */
		case 'o':
			if ((op = validate_operation(optarg)) == OP_INVAL)
				usage("Invalid operation\n");
			break;
		/* collect a type */
		case 't':
			if ((obj_type = validate_type(optarg)) == OT_INVAL)
				usage("Invalid type\n");
			break;

		/* Collect attributes.. */
		case 'a':
			attr_args[attr_count++] = optarg;
			break;

		default:
			usage("Usage error");
			exit(-1);
		}
	}

	if (op == OP_INVAL) {
		usage("Usage error");
		exit(-1);
	}

	switch (obj_type) {

	case OT_LAYOUT:
		layout(op, attr_count, attr_args);
		break;

	case OT_NOTIFY_CHANGE:
	case OT_NOTIFY_DELETE:
		notify(op, obj_type, attr_count, attr_args);
		break;

	default:
		usage("Usage error");
		break;
	}

	return (0);
}
