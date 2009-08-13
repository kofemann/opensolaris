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

#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/errno.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <sys/sdt.h>

#include <rpc/svc.h>
#include <rpc/xdr.h>
#include <nfs/nfs4.h>

#include <nfs/export.h>
#include <nfs/nfs.h>
#include <nfs/nfssys.h>

#include <nfs/nfs4_kprot.h>

#include <nfs/spe.h>
#include <nfs/spe_attr.h>
#include <nfs/spe_impl.h>

typedef struct kspe_state {
	/*
	 * We have potentially many threads trying to get policies
	 * and very rarely, a single thread trying to create policies.
	 * As such, we don't want to block on getting policy evaluations.
	 */
	krwlock_t	ks_rwlock;
	spe_policy	*ks_policies;
	spe_npool	*ks_npools;
} kspe_state_t;

kspe_state_t	*Gkspe = NULL;

boolean_t spe_eval_attribute(spe_interior *si, policy_attributes *pat,
    int *prc, boolean_t bServer);
void spe_free_expr(spe_interior *si);

#define	MAX_PRINT_BUF 2048

static char *
spe_kstrdup(const char *s)
{
	size_t	len;
	char	*new;

	len = strlen(s);
	new = kmem_alloc(len + 1, KM_SLEEP);
	bcopy(s, new, len);
	new[len] = '\0';

	return (new);
}

int
spe_bitcount(unsigned int n)
{
	int	count = 0;

	while (n) {
		count++;
		n &= (n - 1);	/* Clear LSB */
	}

	return (count);
}

void
spe_string_of_address(uint_t addr, char *sz)
{
	uint_t	r[4];
	int	i;
	int	shift;

	for (i = 0; i < 4; i++) {
		shift = ((3-i) * 8);

		r[i] = (addr & (0xff << shift)) >> shift;
	}

	(void) snprintf(sz, 17, "%u.%u.%u.%u", r[0], r[1], r[2], r[3]);
}

void
spe_xdr_dump(char *xbuf, int xlen)
{
	int	i;
	int	j;
	char	buf[100];
	char	str[10];

	j = 0;

	buf[0] = '\0';
	for (i = 0; i < xlen; i++) {
		(void) sprintf(str, " %2X", (unsigned char)xbuf[i]);
		(void) strcat(buf, str);
		j++;
		if (j == 8) {
			DTRACE_NFSV4_1(spe__i__xdr_dump,
			    char *, buf);
			j = 0;
			buf[0] = '\0';
		}
	}

	if (j != 0) {
		DTRACE_NFSV4_1(spe__i__xdr_dump, char *, buf);
	}
}

void
spe_free_paths(spe_path *sp)
{
	if (sp == NULL) {
		return;
	}

	if (sp->path) {
		kmem_free(sp->path, strlen(sp->path) + 1);
		sp->path = NULL;
	}

	if (sp->ext) {
		kmem_free(sp->ext, strlen(sp->ext) + 1);
		sp->ext = NULL;
	}

	if (sp->base) {
		kmem_free(sp->base, strlen(sp->base) + 1);
		sp->base = NULL;
	}

	if (sp->file) {
		kmem_free(sp->file, strlen(sp->file) + 1);
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
				kmem_free(slp->sl_data.spe_data_u.sz,
				    strlen(slp->sl_data.spe_data_u.sz) + 1);
			}
			break;
		case (SPE_DATA_NETNAME) :
			if (slp->sl_data.spe_data_u.net.sn_name) {
				kmem_free(slp->sl_data.spe_data_u.net.sn_name,
				    strlen(slp->sl_data.spe_data_u.net.sn_name)
				    + 1);
			}
			break;
		default:
			break;
		}
	}

	kmem_free(slp, sizeof (spe_leaf));
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
		kmem_free(si->si_branches.si_branches_val,
		    si->si_branches.si_branches_len * sizeof (spe_thunk));
	}
	kmem_free(si, sizeof (spe_interior));
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
			kmem_free(sp, sizeof (spe_policy));

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
		kmem_free(sp, sizeof (spe_policy));
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
		kmem_free(ss, sizeof (spe_stringlist));
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
			kmem_free(np, sizeof (spe_npool));

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
		kmem_free(np, sizeof (spe_npool));
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
			kmem_free(s, sizeof (spe_policy));

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

/* ARGSUSED */
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
			/*
			 * Overwrite.
			 */
			sp->next = s->next;
			spe_free_expr(s->sp_attr_expr);
			kmem_free(s, sizeof (spe_policy));

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
	boolean_t	b = FALSE;
	boolean_t	bLHS;
	boolean_t	bRHS;

	spe_attributes	sa;

	if (!si) {
		*prc = EINVAL;
		return (b);
	}

	*prc = 0;

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
	int		rc = 0;

	for (sp = policies; sp; sp = sp->next) {
		rc = 0;
		b = spe_eval_attribute(sp->sp_attr_expr, pat, &rc, bServer);
		if (rc == 0 && b == TRUE) {
			return (TRUE);
		}
	}

	return (FALSE);
}

/*
 * Possible return codes:
 * 0 - all okay
 * ENOMEM - could not allocate memory
 */
int
spe_parse_paths(spe_path *sp, char *szPath)
{
	char	*s;
	char	*t;
	int	l;

	spe_free_paths(sp);

	/*
	 * This is the case that the vnode's path
	 * was not filled in. If this happens, we
	 * shouldn't puke and we should try our
	 * best with the information we have on hand.
	 *
	 * We've made sure that the paths are NULL
	 * and the attribute evaluation checks for that.
	 */
	if (szPath == NULL) {
		return (0);
	}

	sp->path = spe_kstrdup(szPath);
	if (sp->path == NULL) {
		return (ENOMEM);
	}

	/*
	 * Now we need the file.
	 */
	s = strrchr(szPath, '/');
	if (!s) {
		return (0);
	}

	t = spe_kstrdup(s + 1);
	if (t == NULL) {
		return (ENOMEM);
	}

	l = strlen(t) + 1;

	sp->file = spe_kstrdup(t);
	if (sp->file == NULL) {
		kmem_free(t, l);
		return (ENOMEM);
	}

	s = strrchr(t, '.');
	if (s) {
		sp->ext = spe_kstrdup(s + 1);
		if (sp->ext == NULL) {
			kmem_free(t, l);
			return (ENOMEM);
		}

		*s = '\0';
	}

	sp->base = spe_kstrdup(t);
	kmem_free(t, l);

	if (sp->base == NULL) {
		return (ENOMEM);
	}

	return (0);
}

int (*nfs41_spe_path2mds_sid)(utf8string *, mds_sid *) = NULL;

/*
 * This is the heart of the decision making.
 *
 * For right now, just pick the first N needed.
 */
mds_sid *
spe_map_npools_to_mds_sids(kspe_state_t *kspe, spe_policy *sp,
    int stripe_count)
{
	int		iFound = 0;
	int		i;

	spe_npool	*sn;
	spe_npool	*np;
	spe_stringlist	*ss;

	mds_sid		*mds_sids;

	/*
	 * No mapping function, so return no map!
	 */
	if (nfs41_spe_path2mds_sid == NULL) {
		return (NULL);
	}

	/*
	 * Allocate the mds_sids.
	 */
	mds_sids = kmem_zalloc(stripe_count * sizeof (mds_sid),
	    KM_SLEEP);

	/*
	 * For each npool in the policy, find it in the
	 * list of npools, and start assigning datasets.
	 */
	for (sn = sp->sp_npools; sn != NULL; sn = sn->next) {
		for (np = kspe->ks_npools; np; np = np->next) {
			if (utf8_compare(&np->sn_name, &sn->sn_name) == 0) {
				/*
				 * Now we fill in entries in the *mds_sids
				 * array.
				 */
				for (ss = np->sn_dses; ss; ss = ss->next) {
					i = nfs41_spe_path2mds_sid(
					    &ss->ss_name,
					    &mds_sids[iFound]);
					if (i) {
						continue;
					}

					if (++iFound == stripe_count) {
						return (mds_sids);
					}
				}
			}
		}
	}

error_out:

	/*
	 * For whatever reason, we didn't find enough
	 * entries. So nuke what we have.
	 */
	for (i = 0; i < iFound; i++) {
		kmem_free(mds_sids[i].val, mds_sids[i].len);
	}

	kmem_free(mds_sids, stripe_count * sizeof (mds_sid));

	return (NULL);
}

/*
 * XXX: Would instp tell us server or client? Don't think so...
 *
 * Possible return codes:
 * 0 - found a policy
 * ENOMEM - issue in spe_parse_paths
 * ENOENT - no matching policy
 *
 * Note that if the return is 0, then the values of
 * *stripe_count, *unit_size, and *mds_sids
 * will be set. And in particular, *mds_sids will
 * be allocated memory that the caller is responsible
 * for releasing.
 *
 * For every other return, the values of *stripe_count
 * and *unit_size are undefined. The value of
 * *mds_sids will be NULL.
 */
int
nfs41_spe_allocate(vattr_t *vap, struct netbuf *addr, char *dir_path,
    layout_core_t *plc, int bServer)
{
	kspe_state_t	*kspe = Gkspe;

	unsigned char		*a;
	uint32_t		iaddr = 0;
	int			i;
	int			result;

	policy_attributes	pat;
	spe_policy		*sp;
	boolean_t		b = FALSE;
	char			address[20];

	struct sockaddr_in	*sa;

	plc->lc_mds_sids = NULL;

	if (!kspe) {
		return (ENOENT);
	}

	sa = (struct sockaddr_in *)(addr->buf);

	/*
	 * XXX: Assuming IPv4!
	 */
	a = (unsigned char *)&sa->sin_addr;
	for (i = 0; i < 4; i++) {
		iaddr |= a[i] << ((3-i) * 8);
	}

	pat.addr = iaddr;

	(void) memset(&pat, '\0', sizeof (pat));
	pat.uid = vap->va_uid;
	pat.gid = vap->va_gid;

	result = spe_parse_paths(&pat.sp_server, dir_path);
	if (result) {
		spe_free_paths(&pat.sp_server);
		return (result);
	}

	/*
	 * Purely for debugging purposes.
	 */
	address[0] = '\0';
	spe_string_of_address(iaddr, address);

	/*
	 * Give the client, uid, gid, and path.
	 */
	DTRACE_NFSV4_4(spe__i__check_open, uid_t, pat.uid,
	    gid_t, pat.gid, char *, dir_path, char *, address);

	rw_enter(&kspe->ks_rwlock, RW_READER);

	/*
	 * Find the right policy and then fill in the
	 * mds_sids array.
	 */
	for (sp = kspe->ks_policies; sp; sp = sp->next) {
		result = 0;
		b = spe_eval_attribute(sp->sp_attr_expr, &pat,
		    &result, bServer);

		/*
		 * Give the policy id, match, result, and client.
		 */
		DTRACE_NFSV4_4(spe__i__policy_eval, uint_t, sp->sp_id,
		    boolean_t, b, int, result, char *, address);

		if (result == 0 && b == TRUE) {
			plc->lc_stripe_unit = sp->sp_interlace;
			plc->lc_stripe_count = sp->sp_stripe_count;

			spe_free_paths(&pat.sp_server);

			/*
			 * The client does not care about getting
			 * the mds_sids!
			 */
			if (bServer == FALSE) {
				rw_exit(&kspe->ks_rwlock);
				return (0);
			}

			plc->lc_mds_sids =
			    spe_map_npools_to_mds_sids(kspe,
			    sp, plc->lc_stripe_count);

			rw_exit(&kspe->ks_rwlock);

			/*
			 * XXX: Do we want to differentiate
			 * between not finding enough stripes
			 * versus finding no policy?
			 */
			return (plc->lc_mds_sids ? 0 : ENOENT);
		}
	}

	rw_exit(&kspe->ks_rwlock);

	spe_free_paths(&pat.sp_server);

	/*
	 * If we got here, it means that there was no
	 * default policy.
	 *
	 * XXX: In the short run, that simply means
	 * the admin did not bother setting them up.
	 * It may also mean that we know nothing about
	 * any stinking npools. The caller is responsible
	 * for a "default" default policy. :->
	 *
	 * XXX: Once we add the SMF to handle the npools
	 * and such, this would no longer be the
	 * responsibility of the caller and would be
	 * an ASSERT...
	 */

	return (ENOENT);
}

void
nfs41_spe_fini()
{
	kspe_state_t	*kspe = Gkspe;

	if (kspe == NULL)
		return;

	spe_clear_all_policy_list(&kspe->ks_policies);
	spe_clear_all_npool_list(&kspe->ks_npools);

	rw_destroy(&kspe->ks_rwlock);

	kmem_free(kspe, sizeof (kspe_state_t));

	Gkspe = NULL;
}

void
nfs41_spe_init()
{
	kspe_state_t	*kspe;

	if (Gkspe) {
		nfs41_spe_fini();
	}

	kspe = kmem_zalloc(sizeof (kspe_state_t), KM_SLEEP);

	rw_init(&kspe->ks_rwlock, NULL, RW_DEFAULT, NULL);

	Gkspe = kspe;
}

void
nfs41_spe_svc(void *arg)
{
	spe_policy	*sp = NULL;
	spe_npool	*np = NULL;
	nfsspe_op_t	opcode;
	char		*buf = NULL;
	size_t		len;

	kspe_state_t	*kspe = Gkspe;

	XDR		xdrs;

	model_t		model;

	STRUCT_DECL(nfsspe_args, u_spe);

	model = get_udatamodel();

	if (kspe == NULL) {
		return;
	}

	/*
	 * Initialize the data pointers.
	 */
	STRUCT_INIT(u_spe, model);
	if (copyin(arg, STRUCT_BUF(u_spe), STRUCT_SIZE(u_spe))) {
		(void) set_errno(EFAULT);
		return;
	}

	opcode = STRUCT_FGET(u_spe, nsa_opcode);
	len = STRUCT_FGET(u_spe, nsa_xdr_len);

	DTRACE_NFSV4_2(nfs41__i__spe_svc_args, nfsspe_op_t,
	    opcode, size_t, len);

	if (len) {
		buf = kmem_zalloc(len, KM_SLEEP);
		if (copyin(STRUCT_FGETP(u_spe, nsa_xdr),
		    buf, len)) {
			goto err_out;
		}
	}

	/*
	 * Grab a write lock!
	 * Before here, you may not jump to err_out!
	 */
	rw_enter(&kspe->ks_rwlock, RW_WRITER);

	/*
	 * Should refactor into XDR and non-XDR cases...
	 */
	switch (opcode) {
		case (SPE_OP_POLICY_POPULATE) :
			if (len == 0) {
				goto err_out;
			}

#ifdef DEBUG
			spe_xdr_dump(buf, len);
#endif

			sp = kmem_zalloc(sizeof (*sp), KM_SLEEP);

			xdrmem_create(&xdrs, buf, len, XDR_DECODE);

			if (!xdr_spe_policy(&xdrs, sp)) {
				xdr_destroy(&xdrs);
				goto err_out;
			}

			xdr_destroy(&xdrs);

			spe_clear_all_policy_list(&kspe->ks_policies);
			kspe->ks_policies = sp;

			break;
		case (SPE_OP_NPOOL_POPULATE) :
			if (len == 0) {
				goto err_out;
			}

#ifdef DEBUG
			spe_xdr_dump(buf, len);
#endif

			np = kmem_zalloc(sizeof (*np), KM_SLEEP);

			xdrmem_create(&xdrs, buf, len, XDR_DECODE);

			if (!xdr_spe_npool(&xdrs, np)) {
				xdr_destroy(&xdrs);
				goto err_out;
			}

			xdr_destroy(&xdrs);

			spe_clear_all_npool_list(&kspe->ks_npools);
			kspe->ks_npools = np;

			break;
		case (SPE_OP_POLICY_NUKE) :
		case (SPE_OP_NPOOL_NUKE) :
			break;
		case (SPE_OP_NPOOL_ADD) :
		case (SPE_OP_NPOOL_DELETE) :
		case (SPE_OP_POLICY_ADD) :
		case (SPE_OP_POLICY_DELETE) :
		case (SPE_OP_SET_DOOR) :
		case (SPE_OP_SCHEDULE) :
		default:
			goto err_out;
	}

	if (buf) {
		kmem_free(buf, len);
	}

	rw_exit(&kspe->ks_rwlock);
	return;

err_out:

	if (sp) {
		spe_clear_all_policy_list(&sp);
	}

	if (np) {
		spe_clear_all_npool_list(&np);
	}

	if (buf) {
		kmem_free(buf, len);
	}

	(void) set_errno(EFAULT);
	rw_exit(&kspe->ks_rwlock);
}
