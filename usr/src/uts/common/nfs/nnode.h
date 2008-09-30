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

#ifndef _NNODE_H
#define	_NNODE_H

#include <nfs/nfs4_kprot.h>

#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* boilerplate */

void nnode_mod_init(void);

/* nnodes and their operations */

typedef struct nnode nnode_t;

typedef enum {
	NNOP_OKAY = 0,
	NNOP_OKAY_EOF,
	NNOP_ERR_NOT_IMPL,
	NNOP_ERR_IO,
	NNOP_ERR_BADSTATE,
	NNOP_ERR_NOCREATE
} nnop_error_t;

nnop_error_t nnop_read(nnode_t *, void *, uint64_t, uint32_t);
nnop_error_t nnop_write(nnode_t *, void *, uint64_t, uint32_t);
nnop_error_t nnop_commit(nnode_t *, uint64_t, uint32_t);
nnop_error_t nnop_truncate(nnode_t *, uint64_t);

nnop_error_t nnop_access(nnode_t *, uint32_t);

nnop_error_t nnop_checkstate(nnode_t *, stateid4 *, enum nfsstat4 *);

/* creating implementations of nnodes */

typedef struct {
	nnop_error_t (*ndo_read)(void *, void *, uint64_t,
	    uint32_t);
	nnop_error_t (*ndo_write)(void *, void *, uint64_t,
	    uint32_t);
	nnop_error_t (*ndo_commit)(void *, uint64_t, uint32_t);
	nnop_error_t (*ndo_truncate)(void *, uint64_t);

	void (*ndo_free)(void *);
} nnode_data_ops_t;

typedef struct {
	int	(*nmo_access)(nnode_t *, uint32_t);
	void	(*nmo_free)(void *);
} nnode_metadata_ops_t;

typedef struct {
	nnop_error_t (*nso_checkstate)(void *, stateid4 *, enum nfsstat4 *);
	void	(*nso_free)(void *);
} nnode_state_ops_t;

typedef struct {
	void *ns_fh_value;
	uint32_t ns_fh_len;

	nnode_data_ops_t *ns_data_ops;
	void *ns_data;

	nnode_metadata_ops_t *ns_metadata_ops;
	void *ns_metadata;

	nnode_state_ops_t *ns_state_ops;
	void *ns_state;
} nnode_seed_t;

typedef enum {
	NNODE_FROM_FH_OKAY = 0,
	NNODE_FROM_FH_UNKNOWN,
	NNODE_FROM_FH_STALE,
	NNODE_FROM_FH_BADFH,
	NNODE_FROM_FH_BADCONTEXT
} nnode_from_fh_res_t;

extern nnode_from_fh_res_t (*nnode_build_dserv)(nnode_seed_t *);

/* getting nnodes from keys to be used */

nnode_from_fh_res_t nnode_from_fh(nnode_t **, void *, uint32_t,
    uint32_t);
void nnode_rele(nnode_t **);

#define	NNODE_FROM_FH_V3	0x01
#define	NNODE_FROM_FH_V4	0x02
#define	NNODE_FROM_FH_V41	0x04
#define	NNODE_FROM_FH_MDS	0x08
#define	NNODE_FROM_FH_DS	0x10

/* pure nfs/nnode structures (move to another file?) */

typedef struct {
	int foo;
} nfs_mds_nnode_t;

/* nnode teardown function */
int nnode_teardown_by_instance();

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_H */
