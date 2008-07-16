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
	OP_ADD = 0,
	OP_DEL,
	OP_LIST,
	OP_RECALL,
	MAX_OP

} oper_t;

char *op[] = {
	"add",
	"del",
	"list",
	"recall",
	NULL
};

/*
 * type list:
 *   The type of things we can operation on.
 */
typedef enum {
	OT_INVAL = -1,
	OT_DEV = 0,
	OT_LAYOUT,
	OT_AUTH,
	MAX_OT
} obj_type_t;

char *type[] = {
	"dev",
	"layout",
	"auth",
	NULL
};


typedef struct {
	int  required;
	char *attr_name;
	void *attr_val;
} attr_t;

static char *usage_auth_add =
" To add data-server IP Address Auth record:\n\t"
"use -a ip=<address>\n";


static char *usage_dev_add =
" To add device info:\n\t"
"use -a id=<device_id> -a net=<network> -a ip<address> -a port=<port_number\n";

static char *usage_lo_add =
" To add layout info:\n\t"
"use -a loid=<layout_id> -a dev=<devid1,devid2..> -a unit=<stripe_unit> \n";

static char *usage_lo_recall =
" To recall a layout: \n\t"
"use -a recall=[all | fsid | file] -a file=<path_to_file>\n";


void
usage(char *msg)
{
	fprintf(stderr, "Error!: \n%s\n", msg);
	exit(1);
}

oper_t
validate_operation(char *argp)
{
	int i;

	for (i = OP_ADD; op[i] != NULL; i++)
		if (strcmp(argp, op[i]) == 0)
			return (i);
	return (OP_INVAL);
}

obj_type_t
validate_type(char *argp)
{
	int i;

	for (i = OT_DEV; i < MAX_OT; i++)
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

int
dev_add(int attr_count, char *attrs[])
{
	char    *uaddr;
	int	valid_count = 0, i, rc, nax = -1;
	uint32_t id;

	struct mds_adddev_args arg;

	attr_t need_attr[] = {
		{1, "id",  NULL},
		{1, "net", NULL},
		{1, "ip",  NULL},
		{1, "port", NULL},
		NULL
	};

	if (attr_count != 4) {
		printf("dev_add: need more attributes\n");
		usage(usage_dev_add);
	}


	for (i = 0; i < attr_count; i++) {
		valid_count += validate_attribute(need_attr, attrs[i], &nax);
	}

	if (valid_count != 4) {
		printf("dev_add: need more VALID attributes\n");
		usage(usage_dev_add);
	}

	arg.dev_id = atoi(need_attr[0].attr_val);

	if (arg.dev_id < 2 || arg.dev_id > 199) {
		printf("device id must be between 2 and 199.");
		usage(usage_dev_add);
	}

	uaddr = get_uaddrstr(need_attr[1].attr_val,
	    need_attr[2].attr_val,
	    atoi(need_attr[3].attr_val));

	if (uaddr == NULL)
		usage(usage_dev_add);

	arg.dev_netid = need_attr[1].attr_val;
	arg.dev_addr  = uaddr;
	arg.ds_addr   = need_attr[2].attr_val;

	printf("adding:\n\tid - %d\n\tnetid - %s\n\taddr - %s\n",
	    arg.dev_id, arg.dev_netid, arg.dev_addr);

	rc = _nfssys(MDS_ADD_DEVICE, &arg);

	if (rc != 0)
		perror("nfssys:");

	return (0);
}


int
dev(oper_t op, int count, char *attrs[])
{
	int rc;

	switch (op) {
	case OP_LIST:
		break;
	case OP_ADD:
		printf(" adding devices via this command is deprecated\n");
		break;
	case OP_DEL:
		break;
	default:
		usage("Bad operation for devices\n");
		break;
	}

	return (rc);
}

int
get_layout_devs(char *argp, int devid[])
{
	int rc, id, i = 0;
	char *ap, *dev;

	ap = strdup(argp);
	dev = strtok(ap, ",");
	while (dev != NULL) {
		i++;
		if (i > 20)
			return (20);
		id = atoi(dev);
		devid[ i-1 ] = atoi(dev);
		dev = strtok(NULL, ",");
	}
	return (i);
}

int
layout_add(int attr_count, char *attrs[])
{
	struct mds_addlo_args arg;

	char    *uaddr;
	int	valid_count = 0, i, nax = -1;
	int	rc, dev_count, devs[20];

	attr_t need_attr[] = {
		{1, "dev",  NULL},
		{1, "loid", NULL},
		{1, "unit",  NULL},
		NULL
	};

	bzero(&devs, sizeof (devs));
	bzero(&arg, sizeof (arg));

	if (attr_count != 3) {
		puts("layout_add: need more attributes\n");
		usage(usage_lo_add);
	}


	for (i = 0; i < attr_count; i++) {
		valid_count += validate_attribute(need_attr, attrs[i], &nax);
	}

	if (valid_count != 3) {
		puts("layout_add: need more VALID attributes\n");
		usage(usage_lo_add);
	}

	arg.loid = atoi(need_attr[1].attr_val);
	arg.lo_stripe_unit = atoi(need_attr[2].attr_val);

	/* get the number of devices */
	dev_count = get_layout_devs(need_attr[0].attr_val, arg.lo_devs);
	if (dev_count == 0) {
		puts("layout_add: need to specify device "
		    "list via -a dev=<devid1,devid2>\n");
		usage(usage_lo_add);
	}

	printf("Adding Layout:\n");
	printf("\tid: %d\n", arg.loid);
	printf("\tunit: %d\n", arg.lo_stripe_unit);
	for (i = 0; i < 20; i++)
		printf("\t\tdev[%d] = %d\n",
		    i, arg.lo_devs[i]);

	rc = _nfssys(MDS_ADD_LAYOUT, &arg);

	if (rc != 0)
		perror("nfssys:");

	return (0);
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
	case OP_ADD:
		rc = layout_add(count, attrs);
		break;
	case OP_RECALL:
		rc = layout_recall(count, attrs);
		break;
	default:
		usage("Bad operation for layout\n");
		break;
	}

	return (rc);
}

int
auth_add(int attr_count, char *attrs[])
{
	char    *uaddr;
	int	valid_count = 0, i, rc, nax = -1;
	uint32_t id;

	attr_t need_attr[] = {
		{1, "ip",  NULL},
		NULL
	};

	if (attr_count != 1) {
		printf("auth_add: invalid attribute count.. \n");
		usage(usage_auth_add);
	}


	valid_count += validate_attribute(need_attr, attrs[0], &nax);

	if (valid_count != 1) {
		printf("auth_add: need more VALID attributes\n");
		usage(usage_auth_add);
	}

	printf("adding: IP Addr - %s\n", need_attr[0].attr_val);

	rc = _nfssys(MDS_ADD_DEVICE, need_attr[0].attr_val);

	if (rc != 0)
		perror("nfssys:");

	return (0);
}


int
auth(oper_t op, int count, char *attrs[])
{
	int rc;

	switch (op) {
	case OP_LIST:
		break;
	case OP_ADD:
		rc = auth_add(count, attrs);
		break;
	case OP_DEL:
		break;
	default:
		usage("Bad operation for devices\n");
		break;
	}

	return (rc);
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
			fprintf(stderr, "CLI: error\n");
			exit(-1);
		}
	}

	if (op == OP_INVAL) {
		usage("Specify a valid operation, ie: mdsadm "
		    "-o add -t dev ...");
	}

	switch (obj_type) {

	case OT_DEV:
		dev(op, attr_count, attr_args);
		break;

	case OT_AUTH:
		auth(op, attr_count, attr_args);
		break;

	case OT_LAYOUT:
		layout(op, attr_count, attr_args);
		break;
	default:
		usage("Specify a valid type, ie: -t dev or -t "
		    "layout or -t auth ...");
		break;
	}

	return (0);
}
