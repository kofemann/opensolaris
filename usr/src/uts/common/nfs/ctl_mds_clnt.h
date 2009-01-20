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

#ifndef _CTL_MDS_CLNT_H
#define	_CTL_MDS_CLNT_H

#include <sys/vfs.h>
#include <nfs/nfs41_filehandle.h>
#include <nfs/mds_state.h>
#include <nfs/nfs_serv_inst.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Value which controls the number of times the control
 * protocol messages from MDS to DS are retried in the case of RPC errors.
 * For the number of times to retry messages in the other direction (DS to
 * MDS) see CTLDS_RETRIES.
 */
#define	CTL_MDS_RETRIES 5
#define	CTL_MDS_TIMEO 60 /* seconds */

int ctl_mds_clnt_remove_file(nfs_server_instance_t *, fsid_t, nfs41_fid_t,
    mds_layout_t *);


#ifdef	__cplusplus
}
#endif

#endif /* _CTL_MDS_CLNT_H */
