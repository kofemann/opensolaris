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
#ifndef	_NFS_RFS41_DS_H
#define	_NFS_RFS41_DS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <nfs/nfs41_fhtype.h>

#ifdef	__cplusplus
extern "C" {
#endif
/*
 * NFSv4.1 operation dispatch table
 *   dis_op      : function to call to process operation
 *   dis_resfree : frees space allocated by function
 *   op_flags    : flags to signify which persona may execute
 *   op_name     : name of the operation.
 */
struct op_disp_tbl {
	void	(*dis_op)(nfs_argop4 *, nfs_resop4 *, struct svc_req *,
	    compound_node_t *);
	void	(*dis_resfree)(nfs_resop4 *, compound_node_t *);
	int	op_flag;
	char 	*op_name;
};


/*
 * This data structure specifies the data-server specific
 * operation function pointers for OP_PUTFH, OP_READ, OP_WRITE
 * OP_COMMIT and OP_SECINFO_NONAME; SECINFO_NONAME is included
 * since it may normally require a control protocol message
 * to the MDS.
 */
typedef struct {
	void (*cs_construct)(compound_node_t *, nfsstat4 *, bool_t *);
	void (*cs_destruct)(compound_node_t *);
	struct op_disp_tbl *ds_op_commit;
	struct op_disp_tbl *ds_op_putfh;
	struct op_disp_tbl *ds_op_read;
	struct op_disp_tbl *ds_op_write;
	struct op_disp_tbl *ds_op_secinfo_noname;
} rfs41_persona_funcs_t;

/*
 * rfs41_data_server_register/unregister are structured such that
 * it will be possible to register differing data-server implementations.
 *
 * The type of the implementation is conveyed as a nfs41_fh_type enum.
 *
 * Currently we support just the DMU data-server and NFS41 file handle type,
 * but it would be possible to add (as an example) a VOP_* based data-server.
 *
 */
extern int rfs41_data_server_register(nfs41_fh_type_t, rfs41_persona_funcs_t *);
extern int rfs41_data_server_unregister(nfs41_fh_type_t);

#ifdef	__cplusplus
}
#endif

#endif	/* _NFS_RFS41_DS_H */
