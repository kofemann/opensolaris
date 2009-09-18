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


#include <nfs/nfs4.h>
#include <nfs/nfs4_pnfs.h>

bool_t
xdr_stripe_info_t(xdrs, objp)
	XDR *xdrs;
	stripe_info_t *objp;
{

	if (!xdr_uint32_t(xdrs, &objp->stripe_index))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->
	    multipath_list.multipath_list_val,
	    (uint_t *)&objp->multipath_list.multipath_list_len, ~0,
	    sizeof (netaddr4), (xdrproc_t)xdr_netaddr4))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_layoutspecs_t(xdrs, objp)
	XDR *xdrs;
	layoutspecs_t *objp;
{
	if (!xdr_uint32_t(xdrs, &objp->plo_stripe_count))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->plo_stripe_unit))
		return (FALSE);
	if (!xdr_uint32_t(xdrs, &objp->plo_status))
		return (FALSE);
	if (!xdr_layoutiomode4(xdrs, &objp->iomode))
		return (FALSE);
	if (!xdr_offset4(xdrs, &objp->plo_offset))
		return (FALSE);
	if (!xdr_length4(xdrs, &objp->plo_length))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->plo_creation_sec))
		return (FALSE);
	if (!xdr_int64_t(xdrs, &objp->plo_creation_musec))
		return (FALSE);
	if (!xdr_array(xdrs, (char **)&objp->
	    plo_stripe_info_list.plo_stripe_info_list_val,
	    (uint_t *)&objp->plo_stripe_info_list.
	    plo_stripe_info_list_len, ~0,
	    sizeof (stripe_info_t), (xdrproc_t)xdr_stripe_info_t))
		return (FALSE);
	return (TRUE);
}

bool_t
xdr_layoutstats_t(XDR *xdrs, layoutstats_t *objp)
{

	if (!xdr_uint64_t(xdrs, &objp->proxy_iocount))
		return (FALSE);
	if (!xdr_uint64_t(xdrs, &objp->ds_iocount))
		return (FALSE);

	if (!xdr_array(xdrs, (char **)&objp->plo_data.lo_specs,
	    (uint_t *)&objp->plo_data.total_layouts, ~0,
	    sizeof (layoutspecs_t), (xdrproc_t)xdr_layoutspecs_t))
		return (FALSE);

	return (TRUE);
}
