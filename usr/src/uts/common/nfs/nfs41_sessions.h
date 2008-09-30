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


#ifndef _NFS41_SESSIONS_H
#define	_NFS41_SESSIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <nfs/nfs41_kprot.h>

typedef union {
	struct {
		uint32_t pad0;
		uint32_t pad1;
		uint32_t start_time;
		uint32_t s_id;
	} impl_id;
	sessionid4 id4;
} sid;

extern int nfs41_birpc;

#ifdef __cplusplus
}
#endif

#endif /* _NFS41_SESSIONS_H */
