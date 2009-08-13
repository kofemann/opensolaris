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
 * This is a stand alone prototype policy checker for spe.
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <limits.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netdb.h>

#include <nfs/nfs4.h>
#include <nfs/nfssys.h>
#include <rpc/xdr.h>

#include <nfs/spe.h>
#include <nfs/spe_attr.h>
#include "spedaemon.h"

spe_policy	*Spe_policies = NULL;
spe_npool	*Spe_npools = NULL;

boolean_t spe_eval_attribute(spe_interior *si, policy_attributes *pat,
    int *prc, boolean_t bServer);

void spe_free_expr(spe_interior *si);
void spe_free_paths(spe_path *sp);

int spe_parse_paths(spe_path *sp, char *szPath);
void spe_print_attribute(spe_interior *si);
void spe_print_policy(spe_policy *sp);

void
spe_print_stringlist(spe_stringlist *ss)
{
	spe_stringlist	*next;

	char		*s;
	uint_t		len;

	for (; ss; ss = next) {
		next = ss->next;
		s = utf8_to_str(&ss->ss_name, &len, NULL);
		printf(" %s", s);
		free(s);
	}
}

void
spe_print_npool(spe_npool *np)
{
	char		*s;
	uint_t		len;

	if (!np) {
		return;
	}

	s = utf8_to_str(&np->sn_name, &len, NULL);
	printf("kl -- %s", s);
	free(s);

	spe_print_stringlist(np->sn_dses);
	printf("\n");
}

void
spe_print_npool_list(spe_npool *npools)
{
	spe_npool	*np;

	for (np = npools; np; np = np->next) {
		spe_print_npool(np);
	}
}

void
spe_clear_all_stringlist(spe_stringlist **psses)
{
	spe_stringlist	*ss = *psses;
	spe_stringlist	*next;

	*psses = NULL;

	for (; ss; ss = next) {
		next = ss->next;
		UTF8STRING_FREE(ss->ss_name);
		free(ss);
	}
}

void
spe_clear_npool_from_list(spe_npool **pnpools, utf8string *name)
{
	spe_npool	*np, *prev = NULL;

	for (np = *pnpools; np != NULL; prev = np, np = np->next) {
		if (utf8_compare(&np->sn_name, name) == 0) {
			if (prev) {
				prev->next = np->next;
			} else {
				*pnpools = np->next;
			}

			UTF8STRING_FREE(np->sn_name);

			spe_clear_all_stringlist(&np->sn_dses);
			free(np);

			return;
		}
	}
}

void
spe_clear_all_npool_list(spe_npool **pnpools)
{
	spe_npool	*np = *pnpools;
	spe_npool	*next;

	*pnpools = NULL;

	for (; np; np = next) {
		next = np->next;
		UTF8STRING_FREE(np->sn_name);
		spe_clear_all_stringlist(&np->sn_dses);
		free(np);
	}
}

void
spe_free_paths(spe_path *sp)
{
	if (sp == NULL) {
		return;
	}

	if (sp->path) {
		free(sp->path);
		sp->path = NULL;
	}

	if (sp->ext) {
		free(sp->ext);
		sp->ext = NULL;
	}

	if (sp->base) {
		free(sp->base);
		sp->base = NULL;
	}

	if (sp->file) {
		free(sp->file);
		sp->file = NULL;
	}
}

void
spe_free_leaf(spe_leaf *slp)
{
	if (!slp) {
		return;
	}

	if (slp->sl_is_attr == FALSE) {
		switch (slp->sl_data.sd_type) {
		case (SPE_DATA_STRING) :
			if (slp->sl_data.spe_data_u.sz) {
				free(slp->sl_data.spe_data_u.sz);
			}
			break;
		case (SPE_DATA_NETNAME) :
			if (slp->sl_data.spe_data_u.net.sn_name) {
				free(slp->sl_data.spe_data_u.net.sn_name);
			}
			break;
		default:
			break;
		}
	}

	free(slp);
}

void
spe_free_thunk(spe_thunk st)
{
	if (st.st_is_interior == TRUE) {
		spe_free_expr(st.spe_thunk_u.interior);
	} else {
		spe_free_leaf(st.spe_thunk_u.leaf);
	}
}

void
spe_free_expr(spe_interior *si)
{
	uint_t	i;

	if (!si) {
		return;
	}

	for (i = 0; i < si->si_branches.si_branches_len; i++) {
		/*
		 * Note we free the contents and not
		 * a pointer as this is an array!
		 */
		spe_free_thunk(si->si_branches.si_branches_val[i]);
	}

	if (si->si_branches.si_branches_len) {
		free(si->si_branches.si_branches_val);
	}
	free(si);
}

void
spe_clear_policy_from_list(spe_policy **ppolicies, uint_t id)
{
	spe_policy	*sp, *prev = NULL;

	for (sp = *ppolicies; sp != NULL; prev = sp, sp = sp->next) {
		if (sp->sp_id == id) {
			if (prev) {
				prev->next = sp->next;
			} else {
				*ppolicies = sp->next;
			}

			spe_free_expr(sp->sp_attr_expr);
			free(sp);

			return;
		}
	}
}

void
spe_clear_all_policy_list(spe_policy **ppolicies)
{
	spe_policy	*sp = *ppolicies;
	spe_policy	*next;

	*ppolicies = NULL;

	for (; sp; sp = next) {
		next = sp->next;
		spe_free_expr(sp->sp_attr_expr);
		free(sp);
	}
}

/*
 * It is expected that both lists are already sorted by id.
 */
void
spe_merge_policy_lists(spe_policy **pDestination, spe_policy **pSource)
{
	spe_policy	*s, *n, *p = NULL;

	if (*pSource == NULL) {
		return;
	}

	if (*pDestination == NULL) {
		*pDestination = *pSource;
		*pSource = NULL;
		return;
	}

	for (s = *pDestination; s && *pSource; p = s, s = s->next) {
		if (s->sp_id == (*pSource)->sp_id) {
			/*
			 * Overwrite.
			 */
			n = (*pSource)->next;
			(*pSource)->next = s->next;
			spe_free_expr(s->sp_attr_expr);
			free(s);

			if (p) {
				p->next = *pSource;
			} else {
				*pDestination = *pSource;
			}

			s = *pSource;
			*pSource = n;
		} else if (s->sp_id > (*pSource)->sp_id) {
			n = (*pSource)->next;
			(*pSource)->next = s;
			if (p) {
				p->next = *pSource;
			} else {
				*pDestination = *pSource;
			}

			s = *pSource;
			*pSource = n;
		}
	}

	if (*pSource) {
		/*
		 * p can not be NULL here. The earlier checks
		 * take care of an empty destination and we
		 * must be pointing to the last element in the
		 * list.
		 */
		p->next = *pSource;
		*pSource = NULL;
	}
}

void
spe_insert_policy_list(spe_policy **ppolicies, spe_policy *sp,
    boolean_t bVerbose)
{
	spe_policy	*s, *p = NULL;

	if (!sp) {
		return;
	}

	for (s = *ppolicies; s; p = s, s = s->next) {
		if (s->sp_id == sp->sp_id) {
			if (bVerbose == TRUE) {
				fprintf(stderr, "spe_insert_policy_list:"
				    " Replacing policy:\n");
				spe_print_policy(s);
				fprintf(stderr, "with:\n");
				spe_print_policy(sp);
			}

			/*
			 * Overwrite.
			 */
			sp->next = s->next;
			spe_free_expr(s->sp_attr_expr);
			free(s);

			if (p) {
				p->next = sp;
			} else {
				*ppolicies = sp;
			}

			return;
		} else if (s->sp_id > sp->sp_id) {
			sp->next = s;
			if (p) {
				p->next = sp;
			} else {
				*ppolicies = sp;
			}

			return;
		}
	}

	if (p) {
		p->next = sp;
	} else {
		*ppolicies = sp;
	}
}

void
spe_insert_npool_list(spe_npool **pnpools, spe_npool *np,
    boolean_t bVerbose)
{
	spe_npool	*s, *p = NULL;
	int		inames;

	if (!np) {
		return;
	}

	for (s = *pnpools; s; p = s, s = s->next) {
		inames = utf8_compare(&s->sn_name, &np->sn_name);
		if (inames == 0) {
			if (bVerbose == TRUE) {
				fprintf(stderr, "spe_insert_npool_list:"
				    " Replacing npool:\n");
				spe_print_npool(s);
				fprintf(stderr, "with:\n");
				spe_print_npool(np);
			}

			/*
			 * Overwrite.
			 */
			np->next = s->next;

			UTF8STRING_FREE(s->sn_name);

			spe_clear_all_stringlist(&s->sn_dses);
			free(s);

			if (p) {
				p->next = np;
			} else {
				*pnpools = np;
			}

			return;
		} else if (inames > 0) {
			np->next = s;
			if (p) {
				p->next = np;
			} else {
				*pnpools = np;
			}

			return;
		}
	}

	if (p) {
		p->next = np;
	} else {
		*pnpools = np;
	}
}

/*
 * http://infolab.stanford.edu/~manku/bitcount/bitcount.html
 */
int
spe_bitcount(unsigned int n)
{
	int count = 8 * sizeof (int);

	n ^= (unsigned int) -1;
	while (n) {
		count--;
		n &= (n - 1);
	}

	return (count);
}

void
spe_print_address(uint_t addr)
{
	uint_t	rev;
	int	i;
	int	shift;
	char	sep = ' ';

	for (i = 0; i < 4; i++) {
		shift = ((3-i) * 8);

		rev = (addr & (0xff << shift)) >> shift;

		fprintf(stdout, "%c%u", sep, rev);
		sep = '.';
	}
}

int
spe_gethostname(policy_attributes *pat)
{
	int	rc = 0;

	struct hostent	h, *hp;
	char		host_name[SPE_HOSTNAME_BUF];

	char		hbuf[256];
	char		*s;

	rc = gethostname(host_name, SPE_HOSTNAME_BUF);
	if (rc) {
		fprintf(stderr, "Can not get default hostname\n");
		rc = EFAULT;
		goto cleanup;
	}

	hp = gethostbyname_r((char *)host_name,
	    &h, hbuf, sizeof (hbuf), &rc);
	if (hp) {
		s = strchr(hp->h_name, '.');
		if (s) {
			pat->fqdn = strdup(hp->h_name);
			if (!pat->fqdn) {
				fprintf(stderr, "Out of memory on hostname\n");
				rc = ENOMEM;
				goto cleanup;
			}

			*s++ = '\0';
			pat->domain = strdup(s);
			if (!pat->domain) {
				fprintf(stderr, "Out of memory on hostname\n");
				rc = ENOMEM;
				goto cleanup;
			}
		}

		/*
		 * Domain is stripped if needed above...
		 */
		pat->host = strdup(hp->h_name);
		if (!pat->host) {
			fprintf(stderr, "Out of memory on hostname\n");
			rc = ENOMEM;
			goto cleanup;
		}
	}

cleanup:

	return (rc);
}

/*
 * Get it in the right format to get the network info...
 */
int
spe_extract_domain(policy_attributes *pat)
{
	uchar_t	addr[4] = {0};
	int	i;
	int	rc = 0;
	int	shift;

	struct hostent	h, *hp;
	char		hbuf[256];
	char		*s;

	for (i = 0; i < 4; i++) {
		shift = ((3-i) * 8);
		addr[i] = (pat->addr & (0xff << shift)) >> shift;
	}

	if (pat->host) {
		free(pat->host);
	}

	if (pat->domain) {
		free(pat->domain);
	}

	if (pat->fqdn) {
		free(pat->fqdn);
	}

	hp = gethostbyaddr_r((char *)addr, sizeof (struct in_addr),
	    AF_INET, &h, hbuf, sizeof (hbuf), &rc);
	if (hp) {
		s = strchr(hp->h_name, '.');
		if (s) {
			pat->fqdn = strdup(hp->h_name);
			if (!pat->fqdn) {
				fprintf(stderr, "spe_extract_domain:"
				    " Not enough memory\n");
				rc = ENOMEM;
				goto cleanup;
			}

			*s++ = '\0';
			pat->domain = strdup(s);
			if (!pat->domain) {
				fprintf(stderr, "spe_extract_domain:"
				    " Not enough memory\n");
				rc = ENOMEM;
				goto cleanup;
			}
		}

		/*
		 * Domain is stripped if needed above...
		 */
		pat->host = strdup(hp->h_name);
		if (!pat->host) {
			fprintf(stderr, "spe_extract_domain:"
			    " Not enough memory\n");
			rc = ENOMEM;
			goto cleanup;
		}
	}

cleanup:

	return (rc);
}

void
spe_print_netmask(uint_t mask)
{
	int	t;

	t = spe_bitcount(mask);
	printf("/%u", t);
}

void
spe_print_leaf(spe_leaf *sl)
{
	int	i;

	if (!sl) {
		return;
	}

	if (sl->sl_is_attr == TRUE) {
		for (i = 0; i < Attribute_count; i++) {
			if (spe_attribute_table[i].at_attr == sl->sl_attr) {
				fprintf(stdout, "%s",
				    spe_attribute_table[i].at_name);
			}
		}
	} else {
		switch (sl->sl_data.sd_type) {
		case (SPE_DATA_ADDR) :
			spe_print_address(sl->sl_data.spe_data_u.net.sn_addr);
			break;
		case (SPE_DATA_GID) :
			fprintf(stdout, "%d", sl->sl_data.spe_data_u.gid);
			break;
		case (SPE_DATA_INT) :
			fprintf(stdout, "%d", sl->sl_data.spe_data_u.i);
			break;
		case (SPE_DATA_NETNAME) :
			fprintf(stdout, "%s",
			    sl->sl_data.spe_data_u.net.sn_name);
			break;
		case (SPE_DATA_NETWORK) :
			spe_print_address(sl->sl_data.spe_data_u.net.sn_addr);
			spe_print_netmask(sl->sl_data.spe_data_u.net.sn_mask);
			break;
		case (SPE_DATA_STRING) :
			fprintf(stdout, "%s", sl->sl_data.spe_data_u.sz);
			break;
		case (SPE_DATA_UID) :
			fprintf(stdout, "%d", sl->sl_data.spe_data_u.uid);
			break;
		default :
			fprintf(stderr,
			    "spe_print_leaf: Unknown type %d\n",
			    sl->sl_data.sd_type);
			break;
		}
	}
}

void
spe_print_thunk(spe_thunk st)
{
	if (st.st_is_interior == TRUE) {
		spe_print_attribute(st.spe_thunk_u.interior);
	} else {
		spe_print_leaf(st.spe_thunk_u.leaf);
	}
}

void
spe_print_attribute(spe_interior *si)
{
	if (!si) {
		return;
	}

	if (si->si_branches.si_branches_len == 1) {
		fprintf(stdout, "%s", Spe_ops_list[si->si_op]);
		spe_print_thunk(si->si_branches.si_branches_val[0]);
	} else {
		if (si->si_parens) {
			fprintf(stdout, "(");
		}

		spe_print_thunk(si->si_branches.si_branches_val[0]);
		fprintf(stdout, " %s ", Spe_ops_list[si->si_op]);
		spe_print_thunk(si->si_branches.si_branches_val[1]);

		if (si->si_parens) {
			fprintf(stdout, ")");
		}
	}
}

void
spe_print_policy_npools(spe_npool *npools)
{
	char		*s;
	uint_t		len;

	spe_npool	*np;

	boolean_t	bFirst = TRUE;

	for (np = npools; np; np = np->next) {
		s = utf8_to_str(&np->sn_name, &len, NULL);
		fprintf(stdout, "%s%s", bFirst ? "" : ":", s);
		free(s);
		bFirst = FALSE;
	}
}

void
spe_print_policy(spe_policy *sp)
{
	if (!sp) {
		return;
	}

	fprintf(stdout, "ul -- %u, %u, %u, ",
	    sp->sp_id, sp->sp_stripe_count,
	    sp->sp_interlace);

	spe_print_policy_npools(sp->sp_npools);

	fprintf(stdout, ", ");
	spe_print_attribute(sp->sp_attr_expr);
	fprintf(stdout, "\n");
}

void
spe_print_policy_list(spe_policy *policies)
{
	spe_policy	*sp;

	for (sp = policies; sp; sp = sp->next) {
		spe_print_policy(sp);
	}
}

boolean_t
spe_eval_leaf(spe_leaf *sl, policy_attributes *pat,
    spe_attributes *sa, int *prc, boolean_t bServer)
{
	boolean_t	b = FALSE;

	spe_path	*sp;

	if (!sl) {
		*prc = EINVAL;
		return (b);
	}

	if (sl->sl_is_attr == TRUE) {
		*sa = sl->sl_attr;
		return (TRUE);
	}

	if (bServer == TRUE) {
		sp = &pat->sp_server;
	} else {
		sp = &pat->sp_client;
	}

	/*
	 * XXX: Do type checking and handle default!
	 */
	switch (*sa) {
	case (SPE_ATTR_BASE) :
		if (sp->base &&
		    strcmp(sp->base, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(sp->base) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_DOMAIN) :
		/*
		 * Domain matches from the back.
		 */
		if (pat->domain) {
			int	a = strlen(pat->domain);
			int	d = strlen(sl->sl_data.spe_data_u.sz);
			int	s = a - d;

			if (s < 0) {
				break;
			}

			if (strcmp(&pat->domain[s],
			    sl->sl_data.spe_data_u.sz) == 0 &&
			    (s == 0 || pat->domain[s-1] == '.')) {
				b = TRUE;
			}
		}
		break;

	case (SPE_ATTR_EXTENSION) :
		if (sp->ext &&
		    strcmp(sp->ext, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(sp->ext) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_FILE) :
		if (sp->file &&
		    strcmp(sp->file, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(sp->file) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_FQDN) :
		if (pat->fqdn &&
		    strcmp(pat->fqdn, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(pat->fqdn) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_GROUP) :
		if (pat->group &&
		    strcmp(pat->group, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(pat->group) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_HOST) :
		if (pat->host &&
		    strcmp(pat->host, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(pat->host) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_PATH) :
		if (sp->path) {
			int	p = strlen(sp->path);
			int	d = strlen(sl->sl_data.spe_data_u.sz);

			int	t = strncmp(sp->path,
			    sl->sl_data.spe_data_u.sz, d);

			/*
			 * If t == 0, then we might have a match.
			 * Now we need to see if we end on a
			 * directory component.
			 */
			if (t == 0 && (p == d || sp->path[d] == '/')) {
				b = TRUE;
			}
		}
		break;

	case (SPE_ATTR_USER) :
		if (pat->user &&
		    strcmp(pat->user, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(pat->user) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_DAY) :
		if (pat->day == sl->sl_data.spe_data_u.i) {
			b = TRUE;
		}

		break;

	case (SPE_ATTR_HOUR) :
		if (pat->hour == sl->sl_data.spe_data_u.i) {
			b = TRUE;
		}

		break;

	case (SPE_ATTR_IP) :
		if (pat->addr == sl->sl_data.spe_data_u.net.sn_addr) {
			b = TRUE;
		}

		break;

	case (SPE_ATTR_SUBNET) :
		if ((pat->addr & sl->sl_data.spe_data_u.net.sn_mask) ==
		    (sl->sl_data.spe_data_u.net.sn_addr
		    & sl->sl_data.spe_data_u.net.sn_mask)) {
			b = TRUE;
		}
		break;

	case (SPE_ATTR_GID) :
		if (pat->gid == sl->sl_data.spe_data_u.gid) {
			b = TRUE;
		}

		break;

	case (SPE_ATTR_UID) :
		if (pat->uid == sl->sl_data.spe_data_u.uid) {
			b = TRUE;
		}

		break;

	case (SPE_ATTR_WEEKDAY) :
		if (pat->weekday &&
		    strcmp(pat->weekday, sl->sl_data.spe_data_u.sz) == 0 &&
		    strlen(pat->weekday) == strlen(sl->sl_data.spe_data_u.sz)) {
			b = TRUE;
		}
		break;

	default :
		*prc = EINVAL;
		break;
	}

	return (b);
}

boolean_t
spe_eval_thunk(spe_thunk st, policy_attributes *pat,
    spe_attributes *sa, int *prc, boolean_t bServer)
{
	boolean_t	b;

	if (st.st_is_interior == TRUE) {
		b = spe_eval_attribute(st.spe_thunk_u.interior,
		    pat, prc, bServer);
	} else {
		b = spe_eval_leaf(st.spe_thunk_u.leaf, pat,
		    sa, prc, bServer);
	}

	return (b);
}

boolean_t
spe_eval_attribute(spe_interior *si, policy_attributes *pat,
    int *prc, boolean_t bServer)
{
	boolean_t		b = FALSE;
	boolean_t		bLHS;
	boolean_t		bRHS;

	spe_attributes	sa;

	if (!si) {
		*prc = EINVAL;
		return (b);
	}

	if (si->si_branches.si_branches_len == 1) {
		bLHS = spe_eval_thunk(si->si_branches.si_branches_val[0],
		    pat, &sa, prc, bServer);

		/*
		 * Lazy, but only 1 op - which is '!'.
		 */
		if (bLHS == TRUE) {
			b = FALSE;
		} else {
			b = TRUE;
		}
	} else {
		/*
		 * For '==' and '!=', we will get the attribute
		 * from evaluating the LHS.
		 */
		bLHS = spe_eval_thunk(si->si_branches.si_branches_val[0], pat,
		    &sa, prc, bServer);
		if (*prc != 0) {
			return (FALSE);
		}

		/*
		 * Shortcircuit if possible.
		 */
		if (si->si_op == SPE_OP_AND) {
			if (bLHS == FALSE) {
				return (bLHS);
			}
		} else if (si->si_op == SPE_OP_OR) {
			if (bLHS == TRUE) {
				return (bLHS);
			}
		}

		/*
		 * For '==' and '!=', we pass the attribute
		 * in and determine if there is a match.
		 */
		bRHS = spe_eval_thunk(si->si_branches.si_branches_val[1], pat,
		    &sa, prc, bServer);
		if (*prc != 0) {
			return (FALSE);
		}

		switch (si->si_op) {

		/*
		 * Works because of short circuit above.
		 */
		case (SPE_OP_AND) :
			b = bRHS;
			break;

		/*
		 * Works because of short circuit above.
		 */
		case (SPE_OP_OR) :
			b = bRHS;
			break;

		/*
		 * Left hand side is ignored.
		 */
		case (SPE_OP_EQUAL) :
			b = bRHS;
			break;

		case (SPE_OP_NOT_EQUAL) :
			if (bRHS == FALSE) {
				b = TRUE;
			}
			break;

		default:
			b = FALSE;
			*prc = EINVAL;
			break;
		}
	}

	return (b);
}

boolean_t
spe_eval_policies(spe_policy *policies, policy_attributes *pat,
    boolean_t bServer)
{
	spe_policy	*sp;
	boolean_t	b = FALSE;
	int		rc;

	for (sp = policies; sp; sp = sp->next) {
		rc = 0;
		b = spe_eval_attribute(sp->sp_attr_expr, pat, &rc, bServer);
		if (rc == 0 && b == TRUE) {
			fprintf(stdout, "The matching policy is: ");
			spe_print_policy(sp);
			return (TRUE);
		}
	}

	fprintf(stdout, "No matching policy, default would apply.\n");
	return (FALSE);
}

int
spe_global_eval(policy_attributes *pat, uint64_t **gooies,
    uint32_t *unit_size, uint32_t *stripes)
{
	spe_policy	*sp;
	boolean_t	b = FALSE;
	int		rc;

	/*
	 * XXX: Grab from caller.
	 */
	boolean_t	bServer = TRUE;

	for (sp = Spe_policies; sp; sp = sp->next) {
		b = spe_eval_attribute(sp->sp_attr_expr, pat, &rc, bServer);
		if (rc == 0 && b == TRUE) {
			*unit_size = sp->sp_interlace;
			*stripes = sp->sp_stripe_count;
			return (0);
		}
	}

#define	SPED_NO_MATCH	5
	return (SPED_NO_MATCH);
}

int
spe_parse_address(char *token, uint_t *addr)
{
	char		*junk;
	int		i;
	int		t;

	boolean_t	b = FALSE;
	*addr = 0;

	for (i = 0; i < 4; i++) {
		t = strtol(token, &junk, 10);
		if (junk && junk[0] == '/' && i == 3) {
			b = TRUE;
		} else if (junk && junk[0] != '.' && junk[0] != '\0') {
			fprintf(stderr, "spe_parse_address:"
			    " %s is wrong in the %d octet,"
			    " it has non-digits as <%s>\n", token,
			    i+1, junk);
			return (EINVAL);
		} else if (t > 255 || t < 0) {
			fprintf(stderr, "spe_parse_address:"
			    " %s is wrong in the %d octet,"
			    " %d is out of range\n", token,
			    i+1, t);
			return (EINVAL);
		}

		*addr |= t << ((3-i) * 8);
		token = strchr(token, '.');
		if (token == NULL)
			break;
		token++;
	}

	return (0);
}

int
spe_parse_network(char *token, spe_network *sn)
{
	char		*junk;
	uint_t		addr = 0;
	uint_t		mask = 0;
	int		i;
	int		t;

	boolean_t	b = FALSE;

	for (i = 0; i < 4; i++) {
		t = strtol(token, &junk, 10);
		if (junk && junk[0] == '/' && i == 3) {
			b = TRUE;
		} else if (junk && junk[0] != '.' && junk[0] != '\0') {
			fprintf(stderr, "spe_parse_network:"
			    " %s is wrong in the %d octet,"
			    " it has non-digits as <%s>\n", token,
			    i+1, junk);
			return (EINVAL);
		} else if (t > 255 || t < 0) {
			fprintf(stderr, "spe_parse_network:"
			    " %s is wrong in the %d octet,"
			    " %d is out of range\n", token,
			    i+1, t);
			return (EINVAL);
		}

		addr |= t << ((3-i) * 8);
		token = strchr(token, '.');
		if (token == NULL)
			break;
		token++;
	}

	if (b == TRUE) {
		token = &junk[1];	/* advance over '/' */
		t = strtol(token, &junk, 10);
		if (junk && junk[0] != '\0') {
			fprintf(stderr, "spe_parse_network:"
			    " %s is wrong in the netmask,"
			    " it has non-digits as <%s>\n",
			    token, junk);
			return (EINVAL);
		} else if (t < 0 || t > 32) {
			fprintf(stderr, "spe_parse_network:"
			    " %s is wrong in the netmask,"
			    " %d is out of range\n", token, t);
			return (EINVAL);
		}

		mask = t ? ~0 << ((sizeof (struct in_addr) * NBBY) - t) : 0;
	} else {
		if ((addr & 0x00ffffff) == 0)
			mask = 0xff000000;
		else if ((addr & 0x0000ffff) == 0)
			mask = 0xffff0000;
		else if ((addr & 0x000000ff) == 0)
			mask = 0xffffff00;
		else
			mask = 0xffffffff;
	}

	sn->sn_addr = addr;
	sn->sn_mask = mask;

	return (0);
}

/*
 * sn->sn_name will always point to token upon return.
 */
int
spe_parse_netname(char *token, spe_network *sn)
{
	char		*s;
	char		*junk;
	uint_t		addr = 0;
	uint_t		mask = 0;
	int		t;
	char		buff[256];

	struct netent	n;
	struct netent	*np;

	boolean_t	b = FALSE;

	/*
	 * Sock it away because we will not be able
	 * to keep track of the netmask or not.
	 */
	sn->sn_name = token;

	/*
	 * If there is a netmask present, rope it
	 */
	for (s = token; *s != '\0'; s++) {
		if (*s == '/') {
			b = TRUE;
			*s = '\0';
		}
	}

	np = getnetbyname_r(token, &n, buff, sizeof (buff));
	if (np == NULL) {
		fprintf(stderr, "spe_parse_netname:"
		    " %s is wrong in the netmask,"
		    " %d is out of range\n", token, t);
		return (EINVAL);
	}
	addr = np->n_net;

	if (b == TRUE) {
		/*
		 * Reset the string and advance.
		 */
		*s++ = '/';
		t = strtol(s, &junk, 10);

		if (junk && junk[0] != '\0') {
			fprintf(stderr, "spe_parse_netname:"
			    " %s is wrong in the netmask,"
			    " it has non-digits as <%s>\n", token, junk);
			return (EINVAL);
		} else if (t < 0 || t > 32) {
			fprintf(stderr, "spe_parse_netname:"
			    " %s is wrong in the netmask,"
			    " %d is out of range\n", token, t);
			return (EINVAL);
		}

		mask = t ? ~0 << ((sizeof (struct in_addr) * NBBY) - t) : 0;
	} else {
		if ((addr & 0x00ffffff) == 0)
			mask = 0xff000000;
		else if ((addr & 0x0000ffff) == 0)
			mask = 0xffff0000;
		else if ((addr & 0x000000ff) == 0)
			mask = 0xffffff00;
		else
			mask = 0xffffffff;
	}

	sn->sn_addr = addr;
	sn->sn_mask = mask;

	return (0);
}

/*
 * When we parse an attribute-expression...
 */
spe_interior *
spe_parse_expr(spe_interior *si, char *expression, FILE *pf,
    int *piLine, int *prc)
{
	int	i;
	int	j;
	char	*t;
	char	*sub_expr = NULL;
	int	iLen, iParens;

	boolean_t	b;

	spe_leaf	*sl = NULL;

	char	*szError = expression;

	spe_operators	sop;
	spe_interior	*si_new;

	spe_attributes	sa;

	if (!si) {
		fprintf(stderr,
		    "spe_parse_expr: No interior"
		    " node passed in\n");
		*prc = ENOENT;
		goto cleanup;
	}

	if (!expression) {
		fprintf(stderr,
		    "spe_parse_expr: No expression"
		    " passed in\n");
		*prc = ENOENT;
		goto cleanup;
	}

	/*
	 * When processing the LHS, we know that the only recursion we have
	 * to face is when we encounter a '!' or a '('. Otherwise, it has
	 * to be the case that we are eventually consuming an attribute
	 * followed by an operation.
	 */
get_lhs:
	switch (*expression++) {
	case (' ') :
	case ('\t') :
		goto get_lhs;

	/*
	 * Whoa, we did not expect this, did we?
	 */
	case ('\0') :
		fprintf(stderr,
		    "spe_parse_expr: EOS when"
		    " parsing LHS for Line %d in %s\n",
		    *piLine, szError);
		*prc = EINVAL;
		goto cleanup;

	/*
	 * Note that the only way to get an attribute-expression in
	 * the LHS is to have it in parentheses. Something like
	 * a == b && d == e will result in 'a' being the first LHS,
	 * forking a new root for '&&', and then processing 'd' as
	 * another LHS.
	 */
	case ('(') :

		/*
		 * Verify that we have a matching ')'.
		 *
		 * Note, this doesn't verify it is in the right place,
		 * just that it exists!
		 *
		 * We take the sub-expression in the parentheses
		 * and pass it off recursively.
		 */
		t = expression;
		iLen = strlen(t) + 1;
		b = FALSE;

		iParens = 1;
		for (i = 0; i < iLen - 1; i++) {
			if (t[i] == '(') {
				iParens++;
			} else if (t[i] == ')') {
				iParens--;
				if (iParens == 0) {
					b = TRUE;
					sub_expr = (char *)calloc(i+i, 1);
					if (!sub_expr) {
						fprintf(stderr,
						    "spe_parse_expr:"
						    " Not enough memory\n");
						*prc = ENOMEM;
						goto cleanup;
					}
					strncpy(sub_expr, expression, i);
					expression = &t[i+1];
					break;
				}
			}
		}

		if (b == FALSE) {
			fprintf(stderr, "spe_parse_expr:"
			    " Line %d - '!' unmatched '(' %s\n",
			    *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		/*
		 * Now send it away, using the current root.
		 */
		if (!(si = spe_parse_expr(si, sub_expr,
		    pf, piLine, prc))) {
			goto cleanup;
		}

		si->si_parens = TRUE;

		if (sub_expr) {
			free(sub_expr);
			sub_expr = NULL;
		}

		/*
		 * Note that we can be done with this attribute-expression
		 * if it were "(path == /db)".
		 */
		if (*expression == '\0') {
			/*
			 * We could not have changed the parent interior node,
			 * so leave it alone.
			 */
			goto cleanup;
		}

		break;

	case ('!') :
		/*
		 * Scan ahead and make sure the next token is '('.
		 */
		t = expression;
		iLen = strlen(t) + 1;
		b = FALSE;

		for (i = 0; i < iLen - 1; i++) {
			if (t[i] == ' ' || t[i] == '\t') {
				continue;
			} else if (t[i] == '(') {
				b = TRUE;
				break;
			}

			break;
		}

		if (b == FALSE) {
			fprintf(stderr,
			    "spe_parse_expr: Line %d"
			    " - '!' not followed by a '(' %s\n",
			    *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		/*
		 * Okay, now we need to scan ahead and find the end ')'.
		 * Note that we must be sitting on a '(' from above, so we
		 * will need to advance past it.
		 *
		 * We should really let the '(' case handle this, but we
		 * need to know the ending to push in the sub-expression
		 * recursively.
		 */
		b = FALSE;
		iParens = 0;
		for (; i < iLen - 1; i++) {
			if (t[i] == '(') {
				iParens++;
			} else if (t[i] == ')') {
				iParens--;
				if (iParens == 0) {
					b = TRUE;
					sub_expr = (char *)calloc(i+i, 1);
					if (!sub_expr) {
						fprintf(stderr,
						    "spe_parse_expr:"
						    " Not enough memory\n");
						*prc = ENOMEM;
						goto cleanup;
					}
					strncpy(sub_expr, expression, i+1);
					expression = &t[i+1];
					break;
				}
			}
		}

		if (b == FALSE) {
			fprintf(stderr,
			    "spe_parse_expr: Line %d"
			    " - '!' unmatched '(' %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		/*
		 * Fill in the interior node and create the child.
		 */
		si->si_op = SPE_OP_NOT;
		si->si_branches.si_branches_len = 1;

		si->si_branches.si_branches_val =
		    (spe_thunk *)calloc(si->si_branches.si_branches_len,
		    sizeof (spe_thunk));

		si->si_branches.si_branches_val[0].st_is_interior = TRUE;
		si->si_branches.si_branches_val[0].spe_thunk_u.interior
		    = (spe_interior *)calloc(1, sizeof (spe_interior));
		if (!si->si_branches.si_branches_val[0].spe_thunk_u.interior) {
			fprintf(stderr, "spe_parse_expr:"
			    " Not enough memory\n");
			*prc = ENOMEM;
			goto cleanup;
		}

		if (!(si->si_branches.si_branches_val[0].spe_thunk_u.interior =
		    spe_parse_expr(si->si_branches.si_branches_val[0].
		    spe_thunk_u.interior, sub_expr, pf, piLine, prc))) {
			goto cleanup;
		}

		if (sub_expr) {
			free(sub_expr);
			sub_expr = NULL;
		}

		/*
		 * Note that we can be done with this attribute-expression
		 * if it were "!(path == /db)".
		 */
		if (*expression == '\0') {
			/*
			 * We could not have changed the parent interior node,
			 * so leave it alone.
			 */
			goto cleanup;
		}

		break;

	/*
	 * Start of a function name.
	 */
	default :
		/*
		 * Back up to see what we have...
		 */
		expression--;

		b = FALSE;
		iLen = 0;
		for (t = expression; expression != '\0'; expression++) {
			iLen++;
			if (*expression == ' ' || *expression == '\t') {
				*expression++ = '\0';
				break;
			}
		}

		if (t == expression) {
			fprintf(stderr,
			    "spe_parse_expr: Line %d"
			    " - function has no name %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		/*
		 * We do not yet know what the operator is...
		 */
		si->si_branches.si_branches_len = 2;

		si->si_branches.si_branches_val =
		    (spe_thunk *)calloc(si->si_branches.si_branches_len,
		    sizeof (spe_thunk));

		/*
		 * But both children are leaves!
		 */
		si->si_branches.si_branches_val[0].st_is_interior = FALSE;
		si->si_branches.si_branches_val[0].spe_thunk_u.leaf
		    = (spe_leaf *)calloc(1, sizeof (spe_leaf));
		if (!si->si_branches.si_branches_val[0].spe_thunk_u.leaf) {
			fprintf(stderr, "spe_parse_expr:"
			    " Not enough memory\n");
			*prc = ENOMEM;
			goto cleanup;
		}

		si->si_branches.si_branches_val[1].st_is_interior = FALSE;
		si->si_branches.si_branches_val[1].spe_thunk_u.leaf
		    = (spe_leaf *)calloc(1, sizeof (spe_leaf));
		if (!si->si_branches.si_branches_val[1].spe_thunk_u.leaf) {
			fprintf(stderr, "spe_parse_expr:"
			    " Not enough memory\n");
			*prc = ENOMEM;
			goto cleanup;
		}

		sl = si->si_branches.si_branches_val[0].spe_thunk_u.leaf;
		sl->sl_is_attr = TRUE;

		b = FALSE;
		for (i = 0; i < Attribute_count; i++) {
			if (strcmp(t, spe_attribute_table[i].at_name) == 0 &&
			    iLen == spe_attribute_table[i].at_len) {
				sl->sl_attr = spe_attribute_table[i].at_attr;
				b = TRUE;

				break;
			}
		}

		if (b == FALSE) {
			fprintf(stderr, "spe_parse_expr: Line %d"
			    " - function name is invalid %s\n", *piLine, t);
			*prc = EINVAL;
			goto cleanup;
		}

		break;
	}

	szError = expression;

get_operator:

	/*
	 * Both '==' and '!=' already have their si filled in correctly.
	 *
	 * For both '&&' and '||', we need to fork new parents.
	 */
	switch (*expression++) {
	case (' ') :
	case ('\t') :
		goto get_operator;

	case ('\0') :
		fprintf(stderr,
		    "spe_parse_expr: EOS when parsing operator for Line %d"
		    " in %s\n", *piLine, szError);
		*prc = EINVAL;
		goto cleanup;

	case ('!') :
		if (*expression++ != '=') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		si->si_op = SPE_OP_NOT_EQUAL;
		break;

	case ('=') :
		if (*expression++ != '=') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		si->si_op = SPE_OP_EQUAL;
		break;

	case ('|') :
		/*
		 * Rewind so that the compound operator can
		 * handle this correctly.
		 */
		if (*expression-- != '|') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		goto get_compound;

	case ('&') :
		/*
		 * Rewind so that the compound operator can
		 * handle this correctly.
		 */
		if (*expression-- != '&') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		goto get_compound;

	default :
		fprintf(stderr,
		    "spe_parse_expr: Invalid operator for Line %d"
		    " in %s\n", *piLine, szError);
		*prc = EINVAL;
		goto cleanup;
	}

	szError = expression;

get_rhs:

	switch (*expression++) {
	case (' ') :
	case ('\t') :
		goto get_rhs;

	case ('\0') :
		fprintf(stderr,
		    "spe_parse_expr: EOS when parsing perator RHS Line %d"
		    " in %s\n", *piLine, szError);
		*prc = EINVAL;
		goto cleanup;

	/*
	 * Everything from the start of text until a space is valid here.
	 */
	default :
		b = FALSE;

		/*
		 * Rewind to be kind.
		 */
		t = --expression;
		iLen = strlen(t) + 1;

		for (i = 0; i < iLen - 1; i++) {
			if (t[i] == ' ' || t[i] == ')') {
				b = TRUE;
				sub_expr = (char *)calloc(i+1, 1);
				if (!sub_expr) {
					fprintf(stderr, "spe_parse_expr:"
					    " Not enough memory\n");
					*prc = ENOMEM;
					goto cleanup;
				}

				/*
				 * The sub_expr is the payload for data.
				 */
				strncpy(sub_expr, expression, i);
				expression = &t[i+1];
				break;
			}
		}

		/*
		 * We must have consumed all of the remaining input.
		 */
		if (b == FALSE) {
			/*
			 * Copy it to remain consistent.
			 */
			sub_expr = strdup(expression);
			if (!sub_expr) {
				fprintf(stderr, "spe_parse_expr:"
				    " Not enough memory\n");
				*prc = ENOMEM;
				goto cleanup;
			}
			expression += i;
		}

		/*
		 * The LHS will tell us what the type of the data
		 * will be.
		 */
		sl = si->si_branches.si_branches_val[0].spe_thunk_u.leaf;
		sa = sl->sl_attr;

		sl = si->si_branches.si_branches_val[1].spe_thunk_u.leaf;
		sl->sl_is_attr = FALSE;

		switch (sa) {
		/*
		 * Just push the string into the buffer.
		 */
		case (SPE_ATTR_BASE) :
		case (SPE_ATTR_DOMAIN) :
		case (SPE_ATTR_EXTENSION) :
		case (SPE_ATTR_FILE) :
		case (SPE_ATTR_FQDN) :
		case (SPE_ATTR_GROUP) :
		case (SPE_ATTR_HOST) :
		case (SPE_ATTR_PATH) :
		case (SPE_ATTR_USER) :
			sl->sl_data.sd_type = SPE_DATA_STRING;
			sl->sl_data.spe_data_u.sz = sub_expr;
			sub_expr = NULL;
			break;

		case (SPE_ATTR_DAY) :
			sl->sl_data.sd_type = SPE_DATA_INT;

			sl->sl_data.spe_data_u.i = strtol(sub_expr, &t, 10);
			if (t && *t != '\0') {
				fprintf(stderr,
				    "spe_parse_expr: Invalid token %s for"
				    " day for Line %d\n",
				    sub_expr, *piLine);
				*prc = EINVAL;
				goto cleanup;
			}
			break;

		case (SPE_ATTR_HOUR) :
			sl->sl_data.sd_type = SPE_DATA_INT;

			sl->sl_data.spe_data_u.i = strtol(sub_expr, &t, 10);
			if (t && *t != '\0') {
				fprintf(stderr,
				    "spe_parse_expr: Invalid token %s for"
				    " hour for Line %d\n",
				    sub_expr, *piLine);
				*prc = EINVAL;
				goto cleanup;
			}
			break;

		case (SPE_ATTR_IP) :
			sl->sl_data.sd_type = SPE_DATA_ADDR;

			*prc = spe_parse_address(sub_expr,
			    &sl->sl_data.spe_data_u.net.sn_addr);

			if (*prc) {
				goto cleanup;
			}

			break;

		case (SPE_ATTR_SUBNET) :
			/*
			 * If the first character is alphabetic, then
			 * this is a netname.
			 */
			if (isalpha(*sub_expr)) {
				sl->sl_data.sd_type = SPE_DATA_NETNAME;
				*prc = spe_parse_netname(sub_expr,
				    &sl->sl_data.spe_data_u.net);

				sub_expr = NULL;
				if (*prc) {
					goto cleanup;
				}
			} else {
				sl->sl_data.sd_type = SPE_DATA_NETWORK;
				*prc = spe_parse_network(sub_expr,
				    &sl->sl_data.spe_data_u.net);

				if (*prc) {
					goto cleanup;
				}
			}

			break;

		case (SPE_ATTR_GID) :
			sl->sl_data.sd_type = SPE_DATA_GID;

			sl->sl_data.spe_data_u.gid = strtol(sub_expr, &t, 10);
			if (t && *t != '\0') {
				fprintf(stderr,
				    "spe_parse_expr: Invalid token %s for"
				    " gid for Line %d\n",
				    sub_expr, *piLine);
				*prc = EINVAL;
				goto cleanup;
			}
			break;

		case (SPE_ATTR_UID) :
			sl->sl_data.sd_type = SPE_DATA_UID;

			sl->sl_data.spe_data_u.uid = strtol(sub_expr, &t, 10);
			if (t && *t != '\0') {
				fprintf(stderr,
				    "spe_parse_expr: Invalid token %s for"
				    " uid for Line %d\n",
				    sub_expr, *piLine);
				*prc = EINVAL;
				goto cleanup;
			}
			break;

		case (SPE_ATTR_WEEKDAY) :
			j = strlen(sub_expr);
			b = FALSE;

			for (i = 0; Spe_weekdays[i] != NULL; i++) {
				if (strcmp(Spe_weekdays[i], sub_expr) == 0 &&
				    SPE_WEEKDAY_LEN == j) {
					b = TRUE;
					break;
				}
			}

			if (b == FALSE) {
				fprintf(stderr,
				    "spe_parse_expr: Invalid token %s for"
				    " weekday for Line %d\n",
				    sub_expr, *piLine);
				*prc = EINVAL;
				goto cleanup;
			}

			sl->sl_data.sd_type = SPE_DATA_STRING;
			sl->sl_data.spe_data_u.sz = sub_expr;
			sub_expr = NULL;

			break;

		default :
			fprintf(stderr,
			    "spe_parse_expr: Invalid token %s for"
			    " LHS for Line %d\n",
			    sub_expr, *piLine);
			*prc = EINVAL;
			goto cleanup;
		}

		if (sub_expr) {
			free(sub_expr);
			sub_expr = NULL;
		}
	}

	szError = expression;

get_compound:

	/*
	 * We are done processing the RHS. That means if there is anything
	 * left, then we are part of a compound statement. The first thing
	 * in the remaining expression better be either && or ||.
	 */
	switch (*expression++) {
	case (' ') :
	case ('\t') :
		goto get_compound;

	case ('\0') :
		/*
		 * Not an error, done with input.
		 */
		goto cleanup;

	case ('|') :
		if (*expression++ != '|') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		sop = SPE_OP_OR;
		break;

	case ('&') :
		if (*expression++ != '&') {
			fprintf(stderr,
			    "spe_parse_expr: Invalid operator for Line %d"
			    " in %s\n", *piLine, szError);
			*prc = EINVAL;
			goto cleanup;
		}

		sop = SPE_OP_AND;
		break;

	default :
		fprintf(stderr,
		    "spe_parse_expr: Invalid operator for Line %d"
		    " in %s\n", *piLine, szError);
		*prc = EINVAL;
		goto cleanup;
	}

	/*
	 * Now we know we have a valid operation. So we need to
	 * allocate a new internal node and place it above the
	 * existing one.
	 */
	si_new = (spe_interior *)calloc(1, sizeof (*si));
	if (!si_new) {
		fprintf(stderr, "spe_parse_expr:"
		    " Not enough memory\n");
		*prc = ENOMEM;
		goto cleanup;
	}

	/*
	 * Both children are interior nodes...!
	 */
	si_new->si_op = sop;
	si_new->si_branches.si_branches_len = 2;

	si_new->si_branches.si_branches_val =
	    (spe_thunk *)calloc(si_new->si_branches.si_branches_len,
	    sizeof (spe_thunk));

	/*
	 * The first child is the previous root of the parse tree.
	 */
	si_new->si_branches.si_branches_val[0].st_is_interior = TRUE;
	si_new->si_branches.si_branches_val[0].spe_thunk_u.interior = si;

	/*
	 * We hoist the new node into place.
	 */
	si = si_new;

	si_new->si_branches.si_branches_val[1].st_is_interior = TRUE;
	si_new->si_branches.si_branches_val[1].spe_thunk_u.interior
	    = (spe_interior *)calloc(1, sizeof (spe_interior));
	if (!si_new->si_branches.si_branches_val[1].spe_thunk_u.interior) {
		fprintf(stderr, "spe_parse_expr:"
		    " Not enough memory\n");
		*prc = ENOMEM;
		goto cleanup;
	}

	/*
	 * Handle the rest by recursion.
	 */
	if (!(si_new->si_branches.si_branches_val[1].spe_thunk_u.interior =
	    spe_parse_expr(si_new->si_branches.si_branches_val[1].
	    spe_thunk_u.interior, expression, pf, piLine, prc))) {
		goto cleanup;
	}

cleanup:

	if (sub_expr) {
		free(sub_expr);
	}

	return (si);
}

char *
spe_read_continuation(FILE *pf, char *szLine, int *piLine,
    int *piBufMax, int *prc)
{
	char	*p;

	int	iLen;
	int	iBufCurr;
	int	i;
	int	iOld = 0;

	boolean_t	b;

	while (1) {
		iLen = strlen(szLine);

		szLine[iLen - 1] = '\0';

		/*
		 * Now scan backwards looking for a '\\'
		 */
		b = FALSE;
		for (i = iLen - 2; i > 0; i--) {
			if (isspace(szLine[i])) {
				continue;
			}

			if (szLine[i] == '\\') {
				szLine[i] = ' ';
				b = TRUE;
				iOld = i;
				break;
			}

			break;
		}

		if (b == FALSE) {
			return (szLine);
		}

		iBufCurr = *piBufMax - (i + 1);
		if (iBufCurr < MAXBUFSIZE) {
			*piBufMax += MAXBUFSIZE;

			p = realloc(szLine, *piBufMax + MAXBUFSIZE + 1);
			if (!p) {
				*prc = ENOMEM;
				return (szLine);
			}

			szLine = p;
		}

		p = fgets(&szLine[i+1], MAXBUFSIZE, pf);
		if (!p) {
			*prc = EINVAL;
			return (szLine);
		}

		(*piLine)++;
	}
}

int
spe_add_ds_to_npool(spe_npool *np, char *name)
{
	spe_stringlist	*ss, *t;
	spe_stringlist	*prev = NULL;
	int		rc = 0;

	utf8string	us;
	int		inames;

	(void) str_to_utf8(name, &us);
	if (UTF8STRING_NULL(us)) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	for (ss = np->sn_dses; ss != NULL; prev = ss, ss = ss->next) {
		inames = utf8_compare(&ss->ss_name, &us);

		/*
		 * If already there, then throw the new one away.
		 */
		if (inames == 0) {
			goto cleanup;
		} else if (inames > 0) {
			t = (spe_stringlist *)calloc(1, sizeof (*t));
			if (!t) {
				fprintf(stderr, "spe_add_npool_to_policy:"
				    " Not enough memory\n");
				rc = ENOMEM;
				goto cleanup;
			}

			(void) utf8_copy(&us, &t->ss_name);
			if (UTF8STRING_NULL(t->ss_name)) {
				fprintf(stderr, "spe_add_npool_to_policy:"
				    " Not enough memory\n");
				free(t);
				rc = ENOMEM;
				goto cleanup;
			}

			if (prev) {
				prev->next = t;
			} else {
				np->sn_dses = t;
			}

			t->next = ss;

			goto cleanup;
		}
	}

	t = (spe_stringlist *)calloc(1, sizeof (*t));
	if (!t) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	(void) utf8_copy(&us, &t->ss_name);
	if (UTF8STRING_NULL(t->ss_name)) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		free(t);
		rc = ENOMEM;
		goto cleanup;
	}

	if (prev == NULL) {
		np->sn_dses = t;
	} else {
		prev->next = t;
	}

cleanup:

	UTF8STRING_FREE(us);

	return (rc);
}

int
spe_add_npool_to_policy(spe_policy *sp, char *name)
{
	spe_npool	*np, *t;
	spe_npool	*prev = NULL;
	int		rc = 0;

	utf8string	us;
	int		inames;

	(void) str_to_utf8(name, &us);
	if (UTF8STRING_NULL(us)) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	for (np = sp->sp_npools; np != NULL; prev = np, np = np->next) {
		inames = utf8_compare(&np->sn_name, &us);

		/*
		 * If already there, then throw the new one away.
		 */
		if (inames == 0) {
			goto cleanup;
		} else if (inames > 0) {
			t = (spe_npool *)calloc(1, sizeof (*t));
			if (!t) {
				fprintf(stderr, "spe_add_npool_to_policy:"
				    " Not enough memory\n");
				rc = ENOMEM;
				goto cleanup;
			}

			(void) utf8_copy(&us, &t->sn_name);
			if (UTF8STRING_NULL(t->sn_name)) {
				fprintf(stderr, "spe_add_npool_to_policy:"
				    " Not enough memory\n");
				free(t);
				rc = ENOMEM;
				goto cleanup;
			}

			if (prev) {
				prev->next = t;
			} else {
				sp->sp_npools = t;
			}

			t->next = np;

			goto cleanup;
		}
	}

	t = (spe_npool *)calloc(1, sizeof (*t));
	if (!t) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	(void) utf8_copy(&us, &t->sn_name);
	if (UTF8STRING_NULL(t->sn_name)) {
		fprintf(stderr, "spe_add_npool_to_policy:"
		    " Not enough memory\n");
		free(t);
		rc = ENOMEM;
		goto cleanup;
	}

	if (prev == NULL) {
		sp->sp_npools = t;
	} else {
		prev->next = t;
	}

cleanup:

	UTF8STRING_FREE(us);

	return (rc);
}

int
spe_load_policies(char *szFile, spe_policy **ppolicies, boolean_t bVerbose)
{
	FILE	*pf = NULL;
	int	rc = 0;
	char	*p, *t;
	char	*nts;
	char	*w;
	int	iTemp;
	char	*lasts;

	char	*junk;

	char	*szLine = NULL;
	int	iLine = 1;

	spe_policy	*sp = NULL;
	spe_interior	*si = NULL;

	spe_npool	*np = NULL;

	int	iBufMax = MAXBUFSIZE;

	if (!szFile) {
		fprintf(stderr,
		    "spe_load_policies: No filename passed in\n");
		rc = ENOENT;
		goto cleanup;
	}

	szLine = (char *)malloc(MAXBUFSIZE+1);
	if (szLine == NULL) {
		fprintf(stderr,
		    "spe_load_policies: Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	pf = fopen(szFile, "r");
	if (!pf) {
		fprintf(stderr,
		    "spe_load_policies: File %s not present\n",
		    szFile);
		rc = ENOENT;
		goto cleanup;
	}

	/*
	 * Read a line and try to enter it.
	 * Do we quit if just one line is in error?
	 *
	 * Perhaps we should have a verify mode?
	 */
	while ((p = fgets(szLine, MAXBUFSIZE, pf))) {
		szLine = spe_read_continuation(pf, szLine, &iLine,
		    &iBufMax, &rc);
		if (rc) {
			fprintf(stderr, "spe_load_policies:"
			    " Problem reading continuations\n");
			goto cleanup;
		}

		for (p = szLine; *p != '\0'; p++) {
			if (isspace(*p)) {
				continue;
			}

			break;
		}

		if (*p == '\0' || *p == '#') {
			iLine++;
			continue;
		}

		sp = (spe_policy *)calloc(1, sizeof (*sp));
		if (!sp) {
			fprintf(stderr, "spe_load_policies:"
			    " Not enough memory\n");
			rc = ENOMEM;
			goto cleanup;
		}

		w = ", ";
		t = strtok_r(p, w, &lasts);
		if (!t) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - No id for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		iTemp = strtol(t, &junk, 10);
		if (junk && *junk != '\0') {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - id is non-numeric %s\n", iLine, t);
			rc = EINVAL;
			goto cleanup;
		} else if (iTemp < 0) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - id is out of range %s\n", iLine, t);
			rc = EINVAL;
			goto cleanup;
		}

		sp->sp_id = iTemp;

		t = strtok_r(NULL, w, &lasts);
		if (!t) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - No stripe-count for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		iTemp = strtol(t, &junk, 10);
		if (junk && *junk != '\0') {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - stripe-count is non-numeric %s\n", iLine, t);
			rc = EINVAL;
			goto cleanup;
		} else if (iTemp < 0) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - stripe-count is out of range %s\n",
			    iLine, t);
			rc = EINVAL;
			goto cleanup;
		}

		sp->sp_stripe_count = iTemp;

		t = strtok_r(NULL, w, &lasts);
		if (!t) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - No interlace for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		iTemp = strtol(t, &junk, 10);
		if (junk && *junk != '\0') {
			switch (*junk) {
			/*
			 * Limit ourselves to believable sizes for now.
			 */
			case ('k') :
				iTemp *= 1024;
				break;
			case ('m') :
				iTemp *= 1024000;
				break;
			default :
				fprintf(stderr, "spe_load_policies:"
				    " Line %d - interlace is"
				    " non-numeric %s\n", iLine, t);
				rc = EINVAL;
				goto cleanup;
			}

			/*
			 * Handle stuff like kB...
			 */
			if (junk[1] != '\0') {
				fprintf(stderr, "spe_load_policies:"
				    " Line %d - interlace is"
				    " non-numeric %s\n", iLine, t);
				rc = EINVAL;
				goto cleanup;
			}
		}

		if (iTemp < 0) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - stripe-count is out of range %s\n",
			    iLine, t);
			rc = EINVAL;
			goto cleanup;
		}

		sp->sp_interlace = iTemp;

		/*
		 * Save the npool processing for after the
		 * attribute expression...
		 *
		 * npool1:npool2:npool3,
		 */
		w = ", ";
		nts = strtok_r(NULL, w, &lasts);
		if (!nts) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - No npools for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		w = "";
		t = strtok_r(NULL, w, &lasts);
		if (!t) {
			fprintf(stderr, "spe_load_policies: Line %d"
			    " - No attribute-expression for %s\n",
			    iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		sp->sp_attr_expr = (spe_interior *)calloc(1, sizeof (*si));
		if (!sp->sp_attr_expr) {
			fprintf(stderr, "spe_load_policies:"
			    " Not enough memory\n");
			rc = ENOMEM;
			goto cleanup;
		}

		if (!(sp->sp_attr_expr = spe_parse_expr(sp->sp_attr_expr, t,
		    pf, &iLine, &rc)) || rc != 0) {
			goto cleanup;
		}

		w = ":";
		do {
			t = strtok_r(nts, w, &lasts);
			nts = NULL;		/* Hack, hack, but it works! */
			if (t) {
				rc = spe_add_npool_to_policy(sp, t);
				if (rc) {
					goto cleanup;
				}
			}
		} while (t);

		/*
		 * Insert and forget.
		 */
		spe_insert_policy_list(ppolicies, sp, bVerbose);
		sp = NULL;

		iLine++;
	}

cleanup:

	if (szLine) {
		free(szLine);
	}

	if (pf) {
		fclose(pf);
	}

	/*
	 * We only have a valid pointer if it is not
	 * in the global list.
	 */
	if (sp) {
		spe_free_expr(sp->sp_attr_expr);
		free(sp);
	}

	return (rc);
}

int
spe_load_npools(char *szFile, spe_npool **pnpools, boolean_t bVerbose)
{
	FILE	*pf = NULL;
	int	rc = 0;
	char	*p, *t;
	char	*w;
	int	iTemp;
	char	*lasts;

	char	*junk;

	char	*szLine = NULL;
	int	iLine = 1;

	spe_npool	*np = NULL;

	int	iBufMax = MAXBUFSIZE;

	if (!szFile) {
		fprintf(stderr,
		    "spe_load_npools: No filename passed in\n");
		rc = ENOENT;
		goto cleanup;
	}

	szLine = (char *)malloc(MAXBUFSIZE+1);
	if (szLine == NULL) {
		fprintf(stderr,
		    "spe_load_npools: Not enough memory\n");
		rc = ENOMEM;
		goto cleanup;
	}

	pf = fopen(szFile, "r");
	if (!pf) {
		fprintf(stderr,
		    "spe_load_npools: File %s not present\n",
		    szFile);
		rc = ENOENT;
		goto cleanup;
	}

	/*
	 * Read a line and try to enter it.
	 * Do we quit if just one line is in error?
	 *
	 * Perhaps we should have a verify mode?
	 */
	while ((p = fgets(szLine, MAXBUFSIZE, pf))) {
		szLine = spe_read_continuation(pf, szLine, &iLine,
		    &iBufMax, &rc);
		if (rc) {
			fprintf(stderr, "spe_load_npools:"
			    " Problem reading continuations\n");
			goto cleanup;
		}

		for (p = szLine; *p != '\0'; p++) {
			if (isspace(*p)) {
				continue;
			}

			break;
		}

		if (*p == '\0' || *p == '#') {
			iLine++;
			continue;
		}

		np = (spe_npool *)calloc(1, sizeof (*np));
		if (!np) {
			fprintf(stderr, "spe_load_npools:"
			    " Not enough memory\n");
			rc = ENOMEM;
			goto cleanup;
		}

		w = " ";
		t = strtok_r(p, w, &lasts);
		if (!t) {
			fprintf(stderr, "spe_load_npools: Line %d"
			    " - No name for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		(void) str_to_utf8(t, &np->sn_name);
		if (UTF8STRING_NULL(np->sn_name)) {
			fprintf(stderr, "spe_load_npools:"
			    " Not enough memory\n");
			rc = ENOMEM;
			goto cleanup;
		}

		do {
			t = strtok_r(NULL, w, &lasts);
			if (t) {
				rc = spe_add_ds_to_npool(np, t);
				if (rc) {
					goto cleanup;
				}
			}
		} while (t);

		if (!np->sn_dses) {
			fprintf(stderr, "spe_load_npools: Line %d"
			    " - No dses for %s\n", iLine, szLine);
			rc = EINVAL;
			goto cleanup;
		}

		/*
		 * Insert and forget.
		 */
		spe_insert_npool_list(pnpools, np, bVerbose);
		np = NULL;

		iLine++;
	}

cleanup:

	if (szLine) {
		free(szLine);
	}

	if (pf) {
		fclose(pf);
	}

	if (np) {
		UTF8STRING_FREE(np->sn_name);

		spe_clear_all_stringlist(&np->sn_dses);
		free(np);
	}

	return (rc);
}
int
spe_parse_paths(spe_path *sp, char *szPath)
{
	char	*s;
	char	*t;

	spe_free_paths(sp);

	sp->path = strdup(szPath);
	if (sp->path == NULL) {
		fprintf(stderr, "Out of memory on path\n");
		return (ENOMEM);
	}

	/*
	 * Now we need the file.
	 */
	s = strrchr(szPath, '/');
	if (!s) {
		return (0);
	}

	t = strdup(s+1);
	if (t == NULL) {
		fprintf(stderr, "Out of memory on path\n");
		return (ENOMEM);
	}

	sp->file = strdup(t);
	if (sp->file == NULL) {
		fprintf(stderr, "Out of memory on path\n");
		return (ENOMEM);
	}

	s = strrchr(t, '.');
	if (s) {
		sp->ext = strdup(s+1);
		if (sp->ext == NULL) {
			fprintf(stderr, "Out of memory on path\n");
			return (ENOMEM);
		}

		*s = '\0';
	}

	sp->base = t;

	return (0);
}

void
spe_global_dump(void)
{
	spe_print_policy_list(Spe_policies);
}

int
sped_daemon_load(char *server_policy_file, char *server_npool_file)
{
	int	rc = 0;

	spe_policy	*server_policies = NULL;
	spe_npool	*server_npools = NULL;

	boolean_t	bVerbose = FALSE;

	spe_load_policies(server_policy_file, &server_policies, bVerbose);
	spe_load_npools(server_npool_file, &server_npools, bVerbose);

	/*
	 * Could just use server_policies, just mimicing loading
	 * a policy file into memory.
	 */
	spe_merge_policy_lists(&Spe_policies, &server_policies);

	spe_clear_all_npool_list(&Spe_npools);
	Spe_npools = server_npools;

	return (rc);
}
