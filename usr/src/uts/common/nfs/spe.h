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

#ifndef _SPE_H
#define	_SPE_H

#ifndef _KERNEL
#include <stddef.h>
#endif

#include <sys/sysmacros.h>
#include <sys/types.h>

#include <nfs/spe_prot.h>

/*
 * Simple Policy Engine - spe
 *
 * This daemon is used to determine simple policies for pnfs layouts.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * spe messages from the kernel to the daemon
 */
#define	SPE_SPE_STATS		1
#define	SPE_DS_ZPOOL		2
#define	SPE_RE_EVENT		3
#define	SPE_SS_EVENT		4

/*
 * sped messages from the daemon to the kernel
 */
#define	SPE_DOOR_MAP			1

/*
 * The sped data structures...
 */

#define	MAXBUFSIZE 1024

#ifndef FALSE
#define	FALSE 0
#endif

#ifndef TRUE
#define	TRUE 1
#endif

typedef struct {
	char	*path;
	char	*ext;
	char	*base;
	char	*file;
} spe_path;

typedef struct {
	uid_t		uid;
	gid_t		gid;
	int		day;
	int		hour;
	uint_t		addr;
	uint_t		mask;
	char		*weekday;
	char		*user;
	char		*group;
	char		*host;
	char		*domain;
	char		*fqdn;
	spe_path	sp_server;
	spe_path	sp_client;
} policy_attributes;

#ifdef	__cplusplus
}
#endif

#endif /* _SPE_H */
