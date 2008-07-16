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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifndef _MDS_STATE_H
#define	_MDS_STATE_H

#include <sys/id_space.h>
#include <nfs/nfs4_db_impl.h>
#include <nfs/ds_prot.h>

#define	MDS_MAX_LAYOUT_DEVS 16

/*
 * A means to plop the internal uint23_t device
 * id into an OTW 128 bit device id
 */
typedef union {
	struct {
		uint32_t pad0;
		uint32_t pad1;
		uint32_t pad2;
		uint32_t did;
	} i;
	deviceid4 did4;
} ba_devid_t;

extern void mds_set_deviceid(uint32_t, deviceid4 *);

/*
 * stripe_unit gets plopped into a nfl_util4 in the returned
 * layout information;
 *
 * lo_flags carries if we want dense or sparse data at the
 * data-servers and also if we wish the  NFS Client to commit
 * through the MDS or Data-servers.
 */
typedef struct {
	rfs4_dbe_t	*dbe;
	int		layout_id;
	stateid_t	lo_stateid;
	layouttype4 	layout_type;
	length4		stripe_unit;
	int		stripe_count;
	uint32_t	dev_id;
	uint32_t	dev_index;
	uint32_t	devs[100];
	uint32_t	lo_flags;
} mds_layout_t;

typedef struct {
	rfs4_dbe_t	*dbe;
	uint32_t 	id;   /* table unique */
	clientid4	clnt;
	int		lo_id;
} mds_layout_grant_t;

typedef struct {
	rfs4_dbe_t	*dbe;
	ds_id		ds_id;
	ds_verifier4	verifier;
	uint32_t	dsi_flags;
	time_t		last_access;
	char		*inst_name;
	list_t		dev_list;
} mds_dsinfo_t;

#define	MDS_DSI_REBOOTED	1

/*
 * Allow 4 bits for ds_validuse, the rest is
 * for our use.
 */
#define	MDS_DEV_DS_MASK		0x0000000F
#define	MDS_DEV_SKIP_ME		0x00000010
#define	MDS_DEV_NEW		0x00000020

#define	MDS_SET_DS_FLAGS(dst, flg) \
	dst = (dst & ~MDS_DEV_DS_MASK) | (MDS_DEV_DS_MASK & flg);

/*
 * mds_device:
 *
 * This list is then updated with universal addresses
 * via the control-protocol message DS_REPORTAVAIL.
 *
 * We scan this list to automatically build the default
 * layout and the multipath device struct (mds_mpd)
 */
typedef struct mds_device {
	rfs4_dbe_t	*dbe;
	netaddr4	dev_addr;
	uint_t		dev_flags;
	mds_dsinfo_t   *dev_infop;
	list_node_t	dev_list_next;
} mds_device_t;

/*
 * mds_mpd:
 *
 * the fields mdp_encoded_* are infact the already
 * encoded value for a nfsv4_1_file_layout_ds_addr4
 */
typedef struct mds_mpd {
	rfs4_dbe_t	*dbe;
	uint32_t	mpd_id;
	uint_t 		mpd_encoded_len;
	char 		*mpd_encoded_val;
} mds_mpd_t;

/*
 * used to build the reply to getdevicelist
 */
typedef struct mds_device_list {
	int count;
	deviceid4 *dl;
} mds_device_list_t;

/*
 * mds_auth:
 *
 * This list is populated via the mdsadm command, so that we can
 * validate and associate a data-server instance via the DS_EXIBI
 * protocol message.
 */
typedef struct mds_dsauth {
	rfs4_dbe_t	*dbe;
	char		*ds_addr;
	mds_dsinfo_t    *dev_infop;
} mds_dsauth_t;

/*
 * Tracks the state 'handed out' to the data-server.
 */
typedef struct {
	rfs4_dbe_t	*dbe;
	mds_dsinfo_t   *dev_infop;
} mds_ds_state_t;

/*
 * Tracks the mds_poolid to data-server guid, and
 * associated attributes.
 */
typedef struct {
	rfs4_dbe_t 	*dbe;
	uint32_t 	mds_poolid;
	uint64_t	mds_gpoolid; /* this is ds_id + mds_poolid */
	mds_dsinfo_t 	*ds_dinfop;
	storage_type	ds_stortype; /* Storage type (i.e. ZFS) */
	uint_t		ds_guid_len;
	char 		*ds_guid_val; /* Opaque data server guid */
	uint_t    	ds_attr_len;
	ds_zfsattr 	*ds_attr_val; /* XXX Should this be more general? */
} mds_pool_info_t;

/*
 * A small structure passed in the the poolinfo create
 * entry.
 */
typedef struct {
	struct ds_storinfo *si;
	mds_dsinfo_t *dip;
} pinfo_create_t;


extern krwlock_t mds_layout_lock;

extern krwlock_t mds_device_lock;
extern rfs4_table_t *mds_device_tab;
extern rfs4_index_t *mds_device_idx;

extern krwlock_t mds_mpd_lock;
extern rfs4_table_t *mds_mpd_tab;
extern rfs4_index_t *mds_mpd_idx;

extern rfs4_table_t *mds_dsinfo_tab;
extern rfs4_index_t *mds_dsinfo_idx;
extern rfs4_index_t *mds_dsinfo_ip_idx;

extern rfs4_table_t *mds_dsauth_tab;
extern rfs4_index_t *mds_dsauth_idx;

extern void mds_xdr_devicelist(rfs4_entry_t, void *);
extern mds_dsauth_t *mds_find_dsauth_by_ip(DS_EXIBIargs *, char *);
extern mds_device_t *mds_find_device(uint32_t);
extern mds_layout_t *mds_find_layout(int);
#endif /* _MDS_STATE_H */
