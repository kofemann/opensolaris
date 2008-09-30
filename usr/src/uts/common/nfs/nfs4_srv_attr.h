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

#ifndef _NFS4_SRV_ATTR_H
#define	_NFS4_SRV_ATTR_H

#ifdef _KERNEL
#ifdef	__cplusplus
extern "C" {
#endif

/*
 * When MDS differentiate pnfs shares from non-pnfs shares in
 * exportinfo, check for pnfs and return new attrvers type AV_PNFS.
 * Until then, attrvers is simply based on attrvers of server instance.
 *
 *  (((cs)->instp->attrvers == AV_NFS40) ? AV_NFS40 :
 *	((cs)->exi_pnfs ? AV_PNFS : AV_NFS41))
 */
#define	RFS4_ATTRVERS(cs)	((cs)->instp->attrvers)

/*
 * translation table for attrs
 */
struct nfs4_ntov_table {
	union nfs4_attr_u *na;
	uint8_t amap[NFS41_ATTR_COUNT];
	int attrcnt;
	int attrvers;
	bool_t vfsstat;
};

void nfs4_ntov_table_init(struct nfs4_ntov_table *, attrvers_t);
void nfs4_ntov_table_free(struct nfs4_ntov_table *, struct nfs4_svgetit_arg *);

nfsstat4 do_rfs4_set_attrs(attrmap4 *, fattr4 *,
    struct compound_state *, struct nfs4_svgetit_arg *,
    struct nfs4_ntov_table *, nfs4_attr_cmd_t);
int rfs4_fattr4_acl(nfs4_attr_cmd_t, struct nfs4_svgetit_arg *,
    union nfs4_attr_u *);
int rfs4_fattr4_layout_hint(nfs4_attr_cmd_t, struct nfs4_svgetit_arg *,
    union nfs4_attr_u *);

#ifdef	__cplusplus
}
#endif
#endif /* _KERNEL */
#endif /* _NFS4_SRV_ATTR_H */
