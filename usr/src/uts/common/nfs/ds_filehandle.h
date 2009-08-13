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

#ifndef _DS_FILEHANDLE_H
#define	_DS_FILEHANDLE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <nfs/nfs41_filehandle.h>

enum ds_fh_version {
	DS_FH_v1 = 1
};
typedef enum ds_fh_version ds_fh_version;

#define	DS_MAXFIDSZ 64

struct mds_sid_content {
	uint64_t id;
	uint64_t aun;
};
typedef struct mds_sid_content mds_sid_content;

struct mds_sid {
	uint_t len;
	char *val;
};
typedef struct mds_sid mds_sid;

struct mds_dataset_id {
	uint_t len;
	char val[NFS_FH4MAXDATA];
};
typedef struct mds_dataset_id mds_dataset_id;

struct ds_fh_v1 {
	uint32_t flags;			/* FH flags */
	uint32_t gen;			/* Used to revoke/recall */
	uint64_t mds_id;		/* Which MDS contains the object */
	mds_sid mds_sid;		/* Used to map where on the DS */
					/* the object resides in. */
	mds_dataset_id mds_dataset_id;	/* Used to map where on the MDS */
					/* the object resides in. */
	nfs41_fid_t mds_fid;		/* Used by both the DS and MDS */
					/* to index into the dataset */
};
typedef struct ds_fh_v1 ds_fh_v1;

struct mds_ds_fh {
	nfs41_fh_type_t type;		/* MDS or DS? */
	ds_fh_version vers;		/* OTW version number */
	union {
		ds_fh_v1 v1;
		/* new versions will be added here */
	} fh;
};
typedef struct mds_ds_fh mds_ds_fh;

extern void free_mds_ds_fh(mds_ds_fh *);
extern mds_ds_fh *get_mds_ds_fh(nfs_fh4 *);
extern int mds_alloc_ds_fh(fsid_t, nfs41_fid_t, mds_sid *, nfs_fh4 *);
extern bool_t xdr_ds_fh_fmt(XDR *, mds_ds_fh *);
extern bool_t xdr_mds_sid_content(XDR *, mds_sid_content *);
extern bool_t xdr_mds_sid(XDR *, mds_sid *);
extern bool_t xdr_mds_dataset_id(XDR *, mds_dataset_id *);
extern bool_t xdr_ds_fh_v1(XDR *, ds_fh_v1 *);
extern bool_t xdr_encode_ds_fh(mds_ds_fh *, nfs_fh4 *);
extern bool_t xdr_decode_ds_fh(XDR *, nfs_fh4 *);
extern void xdr_free_ds_fh(nfs_fh4 *);

#ifdef	__cplusplus
}
#endif

#endif /* _DS_FILEHANDLE_H */
