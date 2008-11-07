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

#ifdef _KERNEL
#include <nfs/nfs4_kprot.h>
#else
#include <rpcsvc/nfs4_prot.h>
#endif

#include <nfs/nfs.h>
#include <sys/types.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* boilerplate */

void nnode_mod_init(void);

/* forward declarations */

struct compound_state;

/* nnodes and their operations */

typedef struct nnode nnode_t;

/*
 * Error Reporting
 *
 * Generally, most nnode ops return errno values.  That keeps them more
 * protocol neutral.  However, there are some times when NFSv4 behaves
 * differently than v3; for example, when dealing with mandatory locks.
 *
 * The NNODE_ERROR_SPEC flag indicates that the value is not an errno, but
 * is instead an nnode specific error.  NNODE_ERROR_SPEC must not be set
 * in any valid errno values.
 */

#define	NNODE_ERROR_SPEC	0x40000000
typedef enum {
	NNODE_ERROR_NOTIMPL = NNODE_ERROR_SPEC | 1,
	NNODE_ERROR_LOCK,
	NNODE_ERROR_IODIR,
	NNODE_ERROR_AGAIN,
	NNODE_ERROR_BADFH
} nnode_error_t;

nfsstat4 nnode_stat4(int, uint32_t);
nfsstat3 nnode_stat3(int);

typedef uint32_t nnode_io_flags_t;
#define	NNODE_IO_FLAG_WRITE	0x01
#define	NNODE_IO_FLAG_IN_CRIT	0x02
#define	NNODE_IO_FLAG_RWLOCK	0x04
#define	NNODE_IO_FLAG_EOF	0x08
#define	NNODE_IO_FLAG_PAST_EOF	0x10

nnode_error_t nnop_io_prep(nnode_t *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, offset_t, size_t, bslabel_t *);
nnode_error_t nnop_read(nnode_t *, nnode_io_flags_t *, cred_t *,
    caller_context_t *, uio_t *, int);
nnode_error_t nnop_write(nnode_t *, nnode_io_flags_t *, uio_t *, int, cred_t *,
    caller_context_t *, wcc_data *);
void nnop_io_release(nnode_t *, nnode_io_flags_t, caller_context_t *);
void nnop_post_op_attr(nnode_t *, post_op_attr *);
void nnop_wcc_data_err(nnode_t *, wcc_data *);
vnode_t *nnop_io_getvp(nnode_t *);

vnode_t *nnop_md_getvp(nnode_t *);

nfsstat4 nnop_check_stateid(nnode_t *, struct compound_state *, int, stateid4 *,
    bool_t, bool_t *, bool_t, caller_context_t *);

/* creating implementations of nnodes */

typedef struct {
	int (*ndo_io_prep)(void *, nnode_io_flags_t *, cred_t *,
	    caller_context_t *, offset_t off, size_t, bslabel_t *);
	int (*ndo_read)(void *, nnode_io_flags_t *, cred_t *,
	    caller_context_t *, uio_t *, int);
	int (*ndo_write)(void *, nnode_io_flags_t *, uio_t *, int, cred_t *,
	    caller_context_t *, wcc_data *);
	void (*ndo_io_release)(void *, nnode_io_flags_t, caller_context_t *);
	void (*ndo_post_op_attr)(void *, post_op_attr *);
	void (*ndo_wcc_data_err)(void *, wcc_data *);
	vnode_t *(*ndo_getvp)(void *);
	void (*ndo_free)(void *);
} nnode_data_ops_t;

typedef struct {
	vnode_t *(*nmo_getvp)(void *);
	void	(*nmo_free)(void *);
} nnode_metadata_ops_t;

typedef struct {
	nfsstat4 (*nso_checkstate)(void *, struct compound_state *, int,
	    stateid4 *, bool_t, bool_t *, bool_t, caller_context_t *);
	void	(*nso_free)(void *);
} nnode_state_ops_t;

typedef struct {
	void *ns_key;
	int (*ns_key_compare)(const void *, const void *);
	void (*ns_key_free)(void *);

	nnode_data_ops_t *ns_data_ops;
	void *ns_data;

	nnode_metadata_ops_t *ns_metadata_ops;
	void *ns_metadata;

	nnode_state_ops_t *ns_state_ops;
	void *ns_state;
} nnode_seed_t;

/* getting nnodes from keys to be used */

typedef struct {
	void *nk_keydata;
	int (*nk_compare)(const void *, const void *);
} nnode_key_t;

struct exportinfo;

extern nnode_error_t (*nnode_from_fh_ds)(nnode_t **, nfs_fh4 *);
nnode_error_t nnode_from_fh_v41(nnode_t **, nfs_fh4 *);
nnode_error_t nnode_from_fh_v4(nnode_t **, nfs_fh4 *);
nnode_error_t nnode_from_fh_v3(nnode_t **, nfs_fh3 *, struct exportinfo *);
nnode_error_t nnode_from_vnode(nnode_t **, vnode_t *);
void nnode_rele(nnode_t **);
void nnode_free_export(struct exportinfo *);

void nnode_mod_init(void);
int nnode_mod_fini(void);
void nnode_vn_init(void);
void nnode_vn_fini(void);

/* nnode teardown function */
int nnode_teardown_by_instance();

/* nnode builders for specific implementations */

typedef nnode_error_t (*nnode_init_function_t)(nnode_seed_t *, void *);
int nnode_find_or_create(nnode_t **, nnode_key_t *, uint32_t, void *,
    nnode_init_function_t);

#ifdef	__cplusplus
}
#endif

#endif /* _NNODE_H */
