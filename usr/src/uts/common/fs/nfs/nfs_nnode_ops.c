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

#include <nfs/nnode_impl.h>

/*
 * Convert an errno-like value returned from an nnode op into an nfsstat4,
 * for a given minorversion.
 */

nfsstat4
nnode_stat4(int what, uint32_t minorversion)
{
	if (! (what & NNODE_ERROR_SPEC))
		return (puterrno4(what));

	switch (what) {
	case NNODE_ERROR_NOTIMPL:
		return (NFS4ERR_NXIO);
	case NNODE_ERROR_LOCK:
		return (NFS4ERR_LOCKED);
	case NNODE_ERROR_IODIR:
		return (NFS4ERR_ISDIR);
	case NNODE_ERROR_AGAIN:
		return (puterrno4(EAGAIN));
	case NNODE_ERROR_BADFH:
		return (NFS4ERR_BADHANDLE);
	}

	if (minorversion == 0)
		return (NFS4ERR_IO);
	return (NFS4ERR_SERVERFAULT);
}

/*
 * Convert an errno-like value returned from an nnode op into an nfsstat3.
 */

nfsstat3
nnode_stat3(int what)
{
	if (! (what & NNODE_ERROR_SPEC))
		return (puterrno3(what));

	switch (what) {
	case NNODE_ERROR_NOTIMPL:
		return (NFS3ERR_NXIO);
	case NNODE_ERROR_LOCK:
		return (NFS3ERR_ACCES);
	case NNODE_ERROR_IODIR:
		return (NFS3ERR_INVAL);
	case NNODE_ERROR_AGAIN:
		return (NFS3ERR_JUKEBOX);
	case NNODE_ERROR_BADFH:
		return (NFS3ERR_STALE);
	}

	return (NFS3ERR_IO);
}

/*
 * Known implementations:
 * nnode_vn_io_prep
 * dserv_nnode_io_prep
 */

nnode_error_t
nnop_io_prep(nnode_t *nn, nnode_io_flags_t *flags, cred_t *cr,
    caller_context_t *ct, offset_t off, size_t len, bslabel_t *label)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_io_prep == NULL))
		return (NNODE_ERROR_NOTIMPL);

	return (nn->nn_data_ops->ndo_io_prep)(nn->nn_data_ops_data,
	    flags, cr, ct, off, len, label);
}

/*
 * Known implementations:
 * nnode_vn_read
 * dserv_nnode_read
 * nnode_proxy_read
 */

nnode_error_t
nnop_read(nnode_t *nn, nnode_io_flags_t *flags, cred_t *cr,
    caller_context_t *ct, uio_t *uiop, int ioflags)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_read == NULL))
		return (NNODE_ERROR_NOTIMPL);

	return (nn->nn_data_ops->ndo_read)(nn->nn_data_ops_data,
	    flags, cr, ct, uiop, ioflags);
}

/*
 * Known implementations:
 * nnode_vn_write
 * dserv_nnode_write
 * nnode_proxy_write
 */

nnode_error_t
nnop_write(nnode_t *nn, nnode_io_flags_t *flags, uio_t *uiop, int ioflags,
    cred_t *cr, caller_context_t *ct, wcc_data *wcc)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_write == NULL))
		return (NNODE_ERROR_NOTIMPL);

	return (nn->nn_data_ops->ndo_write)(nn->nn_data_ops_data,
	    flags, uiop, ioflags, cr, ct, wcc);
}

/*
 * Known implementations:
 * nnode_proxy_update
 */

void
nnop_update(nnode_t *nn, nnode_io_flags_t flags, cred_t *cr,
    caller_context_t *ct, off64_t off)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_update == NULL))
		return;

	(nn->nn_data_ops->ndo_update)(nn->nn_data_ops_data, flags, cr, ct, off);
}

/*
 * Known implementations:
 * nnode_vn_io_release
 */

void
nnop_io_release(nnode_t *nn, nnode_io_flags_t flags, caller_context_t *ct)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_io_release == NULL))
		return;

	(nn->nn_data_ops->ndo_io_release)(nn->nn_data_ops_data, flags, ct);
}

/*
 * Known implementations:
 * nnode_vn_post_op_attr
 */

void
nnop_post_op_attr(nnode_t *nn, post_op_attr *poa)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_post_op_attr == NULL))
		return;

	(nn->nn_data_ops->ndo_post_op_attr)(nn->nn_data_ops_data, poa);
}

/*
 * Known implementations:
 * nnode_vn_wcc_data_err
 */

void
nnop_wcc_data_err(nnode_t *nn, wcc_data *wcc)
{
	if ((nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_wcc_data_err == NULL))
		return;

	(nn->nn_data_ops->ndo_wcc_data_err)(nn->nn_data_ops_data, wcc);
}

/*
 * nnop_remove_obj
 */
nnode_error_t
nnop_remove_obj(nnode_t *np)
{
	if ((np->nn_data_ops == NULL) ||
	    (np->nn_data_ops->ndo_remove_obj == NULL))
		return (NNODE_ERROR_NOTIMPL);

	return (*(np)->nn_data_ops->ndo_remove_obj)(np->nn_data_ops_data);
}

/*
 * Known implementations:
 * nnode_vn_io_getvp
 */

vnode_t *
nnop_io_getvp(nnode_t *nn)
{
	if ((nn == NULL) || (nn->nn_data_ops == NULL) ||
	    (nn->nn_data_ops->ndo_getvp == NULL))
		return (NULL);

	return (nn->nn_data_ops->ndo_getvp)(nn->nn_data_ops_data);
}

/*
 * Known implementations:
 * nnode_vn_md_getvp
 */

vnode_t *
nnop_md_getvp(nnode_t *nn)
{
	if ((nn->nn_metadata_ops == NULL) ||
	    (nn->nn_metadata_ops->nmo_getvp == NULL))
		return (NULL);

	return (nn->nn_metadata_ops->nmo_getvp)(nn->nn_metadata_ops_data);
}

/*
 * Known implementations:
 * nnode_vn_st_checkstate
 * dserv_mds_checkstate
 */

nfsstat4
nnop_check_stateid(nnode_t *nn, compound_state_t *cs, int mode,
    stateid4 *stateid, bool_t trunc, bool_t *deleg, bool_t do_access,
    caller_context_t *ct, clientid4 *clientid)
{
	if ((nn->nn_state_ops == NULL) ||
	    (nn->nn_state_ops->nso_checkstate == NULL))
		return (NFS4_OK);

	return (nn->nn_state_ops->nso_checkstate)(nn->nn_state_ops_data,
	    cs, mode, stateid, trunc, deleg, do_access, ct, clientid);
}
