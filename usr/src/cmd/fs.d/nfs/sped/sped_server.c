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
 * Door server routines for sped daemon
 */
#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <signal.h>
#include <libintl.h>
#include <limits.h>
#include <errno.h>
#include <sys/types.h>
#include <string.h>
#include <memory.h>
#include <pwd.h>
#include <grp.h>
#include <door.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <deflt.h>
#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <rpc/xdr.h>
#include <nfs/spe.h>
#include <sys/sdt.h>
#include <sys/debug.h>

#include "spedaemon.h"

/*
 * Prototypes
 */
extern void	 sped_kcall(int);
extern int	 _nfssys(int, void *);

bool_t
xdr_count4(XDR *xdrs, count4 *objp)
{
	if (!xdr_uint32_t(xdrs, objp))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_utf8string(XDR *xdrs, utf8string *objp)
{
	if (xdrs->x_op != XDR_FREE)
		return (xdr_bytes(xdrs, (char **)&objp->utf8string_val,
		    (uint_t *)&objp->utf8string_len, NFS4_MAX_UTF8STRING));

	if (objp->utf8string_val != NULL) {
		mem_free(objp->utf8string_val, objp->utf8string_len);
		objp->utf8string_val = NULL;
	}
	return (TRUE);
}

/*
 * Converts a utf8 string to a C string.
 * allocs a new string if not supplied
 */
char *
utf8_to_str(utf8string *str, uint_t *lenp, char *s)
{
	char	*sp;
	char	*u8p;
	int	len;
	int	 i;

	ASSERT(lenp != NULL);

	if (str == NULL)
		return (NULL);

	u8p = str->utf8string_val;
	len = str->utf8string_len;
	if (len <= 0 || u8p == NULL) {
		if (s)
			*s = '\0';
		return (NULL);
	}

	sp = s;
	if (sp == NULL) {
		sp = calloc(1, len + 1);
		if (sp == NULL)
			return (NULL);
	}

	/*
	 * At least check for embedded nulls
	 */
	for (i = 0; i < len; i++) {
		sp[i] = u8p[i];
		if (u8p[i] == '\0') {
#ifdef	DEBUG
			zcmn_err(getzoneid(), CE_WARN,
			    "Embedded NULL in UTF-8 string");
#endif
			if (s == NULL)
				free(sp);
			return (NULL);
		}
	}
	sp[len] = '\0';
	*lenp = len + 1;

	return (sp);
}

/*
 * str_to_utf8 - converts a null-terminated C string to a utf8 string
 */
utf8string *
str_to_utf8(char *nm, utf8string *str)
{
	int len;

	if (str == NULL)
		return (NULL);

	if (nm == NULL || *nm == '\0') {
		str->utf8string_len = 0;
		str->utf8string_val = NULL;
	}

	len = strlen(nm);

	str->utf8string_val = calloc(1, len);
	if (str->utf8string_val == NULL)
		return (NULL);
	str->utf8string_len = len;
	bcopy(nm, str->utf8string_val, len);

	return (str);
}

utf8string *
utf8_copy(utf8string *src, utf8string *dest)
{
	if (src == NULL)
		return (NULL);
	if (dest == NULL)
		return (NULL);

	if (src->utf8string_len > 0) {
		dest->utf8string_val = calloc(1, src->utf8string_len);
		if (dest->utf8string_val == NULL)
			return (NULL);
		bcopy(src->utf8string_val, dest->utf8string_val,
		    src->utf8string_len);
		dest->utf8string_len = src->utf8string_len;
	} else {
		dest->utf8string_val = NULL;
		dest->utf8string_len = 0;
	}

	return (dest);
}

int
utf8_compare(const utf8string *a, const utf8string *b)
{
	int mlen, cmp;
	int alen, blen;
	char *aval, *bval;

	if ((a == NULL) && (b == NULL))
		return (0);
	else if (a == NULL)
		return (-1);
	else if (b == NULL)
		return (1);

	alen = a->utf8string_len;
	blen = b->utf8string_len;
	aval = a->utf8string_val;
	bval = b->utf8string_val;

	if (((alen == 0) || (aval == NULL)) &&
	    ((blen == 0) || (bval == NULL)))
		return (0);
	else if ((alen == 0) || (aval == NULL))
		return (-1);
	else if ((blen == 0) || (bval == NULL))
		return (1);

	mlen = MIN(alen, blen);
	cmp = strncmp(aval, bval, mlen);

	if ((cmp == 0) && (alen == blen))
		return (0);
	else if ((cmp == 0) && (alen < blen))
		return (-1);
	else if (cmp == 0)
		return (1);
	else if (cmp < 0)
		return (-1);
	return (1);
}

void
sped_xdr_dump(char *xbuf, int xlen)
{
	int	i;
	int	j;
	char	buf[100];
	char	str[10];

	j = 0;

	buf[0] = '\0';
	for (i = 0; i < xlen; i++) {
		sprintf(str, " %2X", (unsigned char)xbuf[i]);
		strcat(buf, str);
		j++;
		if (j == 8) {
			printf("ul -- %s\n", buf);
			j = 0;
			buf[0] = '\0';
		}
	}

	if (j != 0) {
		printf("ul -- %s\n", buf);
	}
}

void
sped_populate_policies(spe_policy *p)
{
	struct nfsspe_args	args;
	XDR			xdrs;
	char			*buf;
	size_t			len = 0;

	args.nsa_opcode = SPE_OP_POLICY_POPULATE;
	args.nsa_did = 0xdead4ead;

	if (!p)
		return;

	args.nsa_xdr_len =
	    xdr_sizeof((xdrproc_t)xdr_spe_policy, (void *)p);

	args.nsa_xdr = calloc(args.nsa_xdr_len, sizeof (char));
	if (!args.nsa_xdr)
		return;

	xdrmem_create(&xdrs, args.nsa_xdr, args.nsa_xdr_len, XDR_ENCODE);
	if (!xdr_spe_policy(&xdrs, p)) {
		free(args.nsa_xdr);
		xdr_destroy(&xdrs);
		return;
	}

#if 0
	sped_xdr_dump(args.nsa_xdr, args.nsa_xdr_len);
#endif

	(void) _nfssys(NFS_SPE, &args);

	free(args.nsa_xdr);
	xdr_destroy(&xdrs);
}

void
sped_populate_npools(spe_npool *p)
{
	struct nfsspe_args	args;
	XDR			xdrs;
	char			*buf;
	size_t			len = 0;

	args.nsa_opcode = SPE_OP_NPOOL_POPULATE;
	args.nsa_did = 0xdead4ead;

	if (!p)
		return;

	args.nsa_xdr_len =
	    xdr_sizeof((xdrproc_t)xdr_spe_npool, (void *)p);

	args.nsa_xdr = calloc(args.nsa_xdr_len, sizeof (char));
	if (!args.nsa_xdr)
		return;

	xdrmem_create(&xdrs, args.nsa_xdr, args.nsa_xdr_len, XDR_ENCODE);
	if (!xdr_spe_npool(&xdrs, p)) {
		free(args.nsa_xdr);
		xdr_destroy(&xdrs);
		return;
	}

#if 0
	sped_xdr_dump(args.nsa_xdr, args.nsa_xdr_len);
#endif

	(void) _nfssys(NFS_SPE, &args);

	free(args.nsa_xdr);
	xdr_destroy(&xdrs);
}
