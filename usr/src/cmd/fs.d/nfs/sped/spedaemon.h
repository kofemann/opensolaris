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

#ifndef _SPEDAEMON_H
#define	_SPEDAEMON_H

/*
 * Definitions for the policy list and parse trees.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	MAXBUFSIZE 1024

#ifndef FALSE
#define	FALSE 0
#endif

#ifndef TRUE
#define	TRUE 1
#endif

#define	UTF8STRING_FREE(str)			\
	if ((str).utf8string_len > 0)		\
		free((str).utf8string_val);	\
	(str).utf8string_val = NULL;		\
	(str).utf8string_len = 0;

/*
 * Roll with previous definitions in the kernel
 */
#define	UTF8STRING_NULL(str)			\
	(str).utf8string_len == 0 ? TRUE : FALSE

extern spe_policy *Spe_policies;
extern spe_npool *Spe_npools;

extern void spe_populate_policies(spe_policy *);
extern void spe_populate_npools(spe_npool *);

extern char *utf8_to_str(utf8string *, uint_t *, char *);
extern utf8string *str_to_utf8(char *, utf8string *);
extern utf8string *utf8_copy(utf8string *, utf8string *);
extern int utf8_compare(const utf8string *, const utf8string *);

#ifdef __cplusplus
}
#endif

#endif /* _SPEDAEMON_H */
