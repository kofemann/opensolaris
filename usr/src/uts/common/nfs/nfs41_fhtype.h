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

#ifndef _NFS41_FHTYPE_H
#define	_NFS41_FHTYPE_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	FH41_TYPE_LEGACY,
	FH41_TYPE_NFS,
	FH41_TYPE_DMU_DS,
	FH41_TYPE_MAX
} nfs41_fh_type_t;

extern bool_t xdr_nfs41_fh_type_t(XDR *, nfs41_fh_type_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS41_FHTYPE_H */
