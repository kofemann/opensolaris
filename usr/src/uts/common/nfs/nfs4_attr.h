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

#ifndef _NFS4_ATTR_H
#define	_NFS4_ATTR_H

#ifdef _KERNEL
#ifdef	__cplusplus
extern "C" {
#endif

#include <nfs/nfs4_attrmap.h>

/*
 * dword-relative bit offsets of bitmap words
 * bitmap word 0 is most significant word of dword0
 * bitmap word 1 is least significant word of dword0
 */
#define	FATTR4_WORD0	32
#define	FATTR4_WORD1	0
#define	FATTR4_WORD2	FATTR4_WORD0
#define	FATTR4_WORD3	FATTR4_WORD1

#define	__dw_SUPPORTED_ATTRS	d.d0
#define	__dw_TYPE		d.d0
#define	__dw_FH_EXPIRE_TYPE	d.d0
#define	__dw_CHANGE		d.d0
#define	__dw_SIZE		d.d0
#define	__dw_LINK_SUPPORT	d.d0
#define	__dw_SYMLINK_SUPPORT	d.d0
#define	__dw_NAMED_ATTR		d.d0
#define	__dw_FSID		d.d0
#define	__dw_UNIQUE_HANDLES	d.d0
#define	__dw_LEASE_TIME		d.d0
#define	__dw_RDATTR_ERROR	d.d0
#define	__dw_FILEHANDLE		d.d0
#define	__dw_ACL		d.d0
#define	__dw_ACLSUPPORT		d.d0
#define	__dw_ARCHIVE		d.d0
#define	__dw_CANSETTIME		d.d0
#define	__dw_CASE_INSENSITIVE	d.d0
#define	__dw_CASE_PRESERVING	d.d0
#define	__dw_CHOWN_RESTRICTED	d.d0
#define	__dw_FILEID		d.d0
#define	__dw_FILES_AVAIL	d.d0
#define	__dw_FILES_FREE		d.d0
#define	__dw_FILES_TOTAL	d.d0
#define	__dw_FS_LOCATIONS	d.d0
#define	__dw_HIDDEN		d.d0
#define	__dw_HOMOGENEOUS	d.d0
#define	__dw_MAXFILESIZE	d.d0
#define	__dw_MAXLINK		d.d0
#define	__dw_MAXNAME		d.d0
#define	__dw_MAXREAD		d.d0
#define	__dw_MAXWRITE		d.d0
#define	__dw_MIMETYPE		d.d0
#define	__dw_MODE		d.d0
#define	__dw_NO_TRUNC		d.d0
#define	__dw_NUMLINKS		d.d0
#define	__dw_OWNER		d.d0
#define	__dw_OWNER_GROUP	d.d0
#define	__dw_QUOTA_AVAIL_HARD	d.d0
#define	__dw_QUOTA_AVAIL_SOFT	d.d0
#define	__dw_QUOTA_USED		d.d0
#define	__dw_RAWDEV		d.d0
#define	__dw_SPACE_AVAIL	d.d0
#define	__dw_SPACE_FREE		d.d0
#define	__dw_SPACE_TOTAL	d.d0
#define	__dw_SPACE_USED		d.d0
#define	__dw_SYSTEM		d.d0
#define	__dw_TIME_ACCESS	d.d0
#define	__dw_TIME_ACCESS_SET	d.d0
#define	__dw_TIME_BACKUP	d.d0
#define	__dw_TIME_CREATE	d.d0
#define	__dw_TIME_DELTA		d.d0
#define	__dw_TIME_METADATA	d.d0
#define	__dw_TIME_MODIFY	d.d0
#define	__dw_TIME_MODIFY_SET	d.d0
#define	__dw_MOUNTED_ON_FILEID	d.d0
#define	__dw_DIR_NOTIF_DELAY	d.d0
#define	__dw_DIRENT_NOTIF_DELAY	d.d0
#define	__dw_DACL		d.d0
#define	__dw_SACL		d.d0
#define	__dw_CHANGE_POLICY	d.d0
#define	__dw_FS_STATUS		d.d0
#define	__dw_FS_LAYOUT_TYPE	d.d0
#define	__dw_LAYOUT_HINT	d.d0

#define	__dw_LAYOUT_TYPE	d.d1
#define	__dw_LAYOUT_BLKSIZE	d.d1
#define	__dw_LAYOUT_ALIGNMENT	d.d1
#define	__dw_FS_LOCATIONS_INFO	d.d1
#define	__dw_MDSTHRESHOLD	d.d1
#define	__dw_RETENTION_GET	d.d1
#define	__dw_RETENTION_SET	d.d1
#define	__dw_RETENTEVT_GET	d.d1
#define	__dw_RETENTEVT_SET	d.d1
#define	__dw_RETENTION_HOLD	d.d1
#define	__dw_MODE_SET_MASKED	d.d1
#define	__dw_SUPPATTR_EXCLCREAT	d.d1
#define	__dw_FS_CHARSET_CAP	d.d1

/*
 * Attributes
 */
#define	FATTR4_SUPPORTED_ATTRS_MASK	(1ULL << (FATTR4_WORD0 + 0))
#define	FATTR4_TYPE_MASK		(1ULL << (FATTR4_WORD0 + 1))
#define	FATTR4_FH_EXPIRE_TYPE_MASK	(1ULL << (FATTR4_WORD0 + 2))
#define	FATTR4_CHANGE_MASK		(1ULL << (FATTR4_WORD0 + 3))
#define	FATTR4_SIZE_MASK		(1ULL << (FATTR4_WORD0 + 4))
#define	FATTR4_LINK_SUPPORT_MASK	(1ULL << (FATTR4_WORD0 + 5))
#define	FATTR4_SYMLINK_SUPPORT_MASK	(1ULL << (FATTR4_WORD0 + 6))
#define	FATTR4_NAMED_ATTR_MASK		(1ULL << (FATTR4_WORD0 + 7))
#define	FATTR4_FSID_MASK		(1ULL << (FATTR4_WORD0 + 8))
#define	FATTR4_UNIQUE_HANDLES_MASK	(1ULL << (FATTR4_WORD0 + 9))
#define	FATTR4_LEASE_TIME_MASK		(1ULL << (FATTR4_WORD0 + 10))
#define	FATTR4_RDATTR_ERROR_MASK	(1ULL << (FATTR4_WORD0 + 11))
#define	FATTR4_ACL_MASK			(1ULL << (FATTR4_WORD0 + 12))
#define	FATTR4_ACLSUPPORT_MASK		(1ULL << (FATTR4_WORD0 + 13))
#define	FATTR4_ARCHIVE_MASK		(1ULL << (FATTR4_WORD0 + 14))
#define	FATTR4_CANSETTIME_MASK		(1ULL << (FATTR4_WORD0 + 15))
#define	FATTR4_CASE_INSENSITIVE_MASK	(1ULL << (FATTR4_WORD0 + 16))
#define	FATTR4_CASE_PRESERVING_MASK	(1ULL << (FATTR4_WORD0 + 17))
#define	FATTR4_CHOWN_RESTRICTED_MASK	(1ULL << (FATTR4_WORD0 + 18))
#define	FATTR4_FILEHANDLE_MASK		(1ULL << (FATTR4_WORD0 + 19))
#define	FATTR4_FILEID_MASK		(1ULL << (FATTR4_WORD0 + 20))
#define	FATTR4_FILES_AVAIL_MASK		(1ULL << (FATTR4_WORD0 + 21))
#define	FATTR4_FILES_FREE_MASK		(1ULL << (FATTR4_WORD0 + 22))
#define	FATTR4_FILES_TOTAL_MASK		(1ULL << (FATTR4_WORD0 + 23))
#define	FATTR4_FS_LOCATIONS_MASK	(1ULL << (FATTR4_WORD0 + 24))
#define	FATTR4_HIDDEN_MASK		(1ULL << (FATTR4_WORD0 + 25))
#define	FATTR4_HOMOGENEOUS_MASK		(1ULL << (FATTR4_WORD0 + 26))
#define	FATTR4_MAXFILESIZE_MASK		(1ULL << (FATTR4_WORD0 + 27))
#define	FATTR4_MAXLINK_MASK		(1ULL << (FATTR4_WORD0 + 28))
#define	FATTR4_MAXNAME_MASK		(1ULL << (FATTR4_WORD0 + 29))
#define	FATTR4_MAXREAD_MASK		(1ULL << (FATTR4_WORD0 + 30))
#define	FATTR4_MAXWRITE_MASK		(1ULL << (FATTR4_WORD0 + 31))

#define	FATTR4_MIMETYPE_MASK		(1ULL << (FATTR4_WORD1 + 0))
#define	FATTR4_MODE_MASK		(1ULL << (FATTR4_WORD1 + 1))
#define	FATTR4_NO_TRUNC_MASK		(1ULL << (FATTR4_WORD1 + 2))
#define	FATTR4_NUMLINKS_MASK		(1ULL << (FATTR4_WORD1 + 3))
#define	FATTR4_OWNER_MASK		(1ULL << (FATTR4_WORD1 + 4))
#define	FATTR4_OWNER_GROUP_MASK		(1ULL << (FATTR4_WORD1 + 5))
#define	FATTR4_QUOTA_AVAIL_HARD_MASK	(1ULL << (FATTR4_WORD1 + 6))
#define	FATTR4_QUOTA_AVAIL_SOFT_MASK	(1ULL << (FATTR4_WORD1 + 7))
#define	FATTR4_QUOTA_USED_MASK		(1ULL << (FATTR4_WORD1 + 8))
#define	FATTR4_RAWDEV_MASK		(1ULL << (FATTR4_WORD1 + 9))
#define	FATTR4_SPACE_AVAIL_MASK		(1ULL << (FATTR4_WORD1 + 10))
#define	FATTR4_SPACE_FREE_MASK		(1ULL << (FATTR4_WORD1 + 11))
#define	FATTR4_SPACE_TOTAL_MASK		(1ULL << (FATTR4_WORD1 + 12))
#define	FATTR4_SPACE_USED_MASK		(1ULL << (FATTR4_WORD1 + 13))
#define	FATTR4_SYSTEM_MASK		(1ULL << (FATTR4_WORD1 + 14))
#define	FATTR4_TIME_ACCESS_MASK		(1ULL << (FATTR4_WORD1 + 15))
#define	FATTR4_TIME_ACCESS_SET_MASK	(1ULL << (FATTR4_WORD1 + 16))
#define	FATTR4_TIME_BACKUP_MASK		(1ULL << (FATTR4_WORD1 + 17))
#define	FATTR4_TIME_CREATE_MASK		(1ULL << (FATTR4_WORD1 + 18))
#define	FATTR4_TIME_DELTA_MASK		(1ULL << (FATTR4_WORD1 + 19))
#define	FATTR4_TIME_METADATA_MASK	(1ULL << (FATTR4_WORD1 + 20))
#define	FATTR4_TIME_MODIFY_MASK		(1ULL << (FATTR4_WORD1 + 21))
#define	FATTR4_TIME_MODIFY_SET_MASK	(1ULL << (FATTR4_WORD1 + 22))
#define	FATTR4_MOUNTED_ON_FILEID_MASK	(1ULL << (FATTR4_WORD1 + 23))
#define	FATTR4_DIR_NOTIF_DELAY_MASK	(1ULL << (FATTR4_WORD1 + 24))
#define	FATTR4_DIRENT_NOTIF_DELAY_MASK	(1ULL << (FATTR4_WORD1 + 25))
#define	FATTR4_DACL_MASK		(1ULL << (FATTR4_WORD1 + 26))
#define	FATTR4_SACL_MASK		(1ULL << (FATTR4_WORD1 + 27))
#define	FATTR4_CHANGE_POLICY_MASK	(1ULL << (FATTR4_WORD1 + 28))
#define	FATTR4_FS_STATUS_MASK		(1ULL << (FATTR4_WORD1 + 29))
#define	FATTR4_FS_LAYOUT_TYPE_MASK	(1ULL << (FATTR4_WORD1 + 30))
#define	FATTR4_LAYOUT_HINT_MASK		(1ULL << (FATTR4_WORD1 + 31))

#define	FATTR4_LAYOUT_TYPE_MASK		(1ULL << (FATTR4_WORD2 + 0))
#define	FATTR4_LAYOUT_BLKSIZE_MASK	(1ULL << (FATTR4_WORD2 + 1))
#define	FATTR4_LAYOUT_ALIGNMENT_MASK	(1ULL << (FATTR4_WORD2 + 2))
#define	FATTR4_FS_LOCATIONS_INFO_MASK	(1ULL << (FATTR4_WORD2 + 3))
#define	FATTR4_MDSTHRESHOLD_MASK	(1ULL << (FATTR4_WORD2 + 4))
#define	FATTR4_RETENTION_GET_MASK	(1ULL << (FATTR4_WORD2 + 5))
#define	FATTR4_RETENTION_SET_MASK	(1ULL << (FATTR4_WORD2 + 6))
#define	FATTR4_RETENTEVT_GET_MASK	(1ULL << (FATTR4_WORD2 + 7))
#define	FATTR4_RETENTEVT_SET_MASK	(1ULL << (FATTR4_WORD2 + 8))
#define	FATTR4_RETENTION_HOLD_MASK	(1ULL << (FATTR4_WORD2 + 9))
#define	FATTR4_MODE_SET_MASKED_MASK	(1ULL << (FATTR4_WORD2 + 10))
#define	FATTR4_SUPPATTR_EXCLCREAT_MASK	(1ULL << (FATTR4_WORD2 + 11))
#define	FATTR4_FS_CHARSET_CAP_MASK	(1ULL << (FATTR4_WORD2 + 12))
#define	FATTR4_77_MASK			(1ULL << (FATTR4_WORD2 + 13))
#define	FATTR4_78_MASK			(1ULL << (FATTR4_WORD2 + 14))
#define	FATTR4_79_MASK			(1ULL << (FATTR4_WORD2 + 15))
#define	FATTR4_80_MASK			(1ULL << (FATTR4_WORD2 + 16))
#define	FATTR4_81_MASK			(1ULL << (FATTR4_WORD2 + 17))
#define	FATTR4_82_MASK			(1ULL << (FATTR4_WORD2 + 18))
#define	FATTR4_83_MASK			(1ULL << (FATTR4_WORD2 + 19))
#define	FATTR4_84_MASK			(1ULL << (FATTR4_WORD2 + 20))
#define	FATTR4_85_MASK			(1ULL << (FATTR4_WORD2 + 21))
#define	FATTR4_86_MASK			(1ULL << (FATTR4_WORD2 + 22))
#define	FATTR4_87_MASK			(1ULL << (FATTR4_WORD2 + 23))
#define	FATTR4_88_MASK			(1ULL << (FATTR4_WORD2 + 24))
#define	FATTR4_89_MASK			(1ULL << (FATTR4_WORD2 + 25))
#define	FATTR4_90_MASK			(1ULL << (FATTR4_WORD2 + 26))
#define	FATTR4_91_MASK			(1ULL << (FATTR4_WORD2 + 27))
#define	FATTR4_92_MASK			(1ULL << (FATTR4_WORD2 + 28))
#define	FATTR4_93_MASK			(1ULL << (FATTR4_WORD2 + 29))
#define	FATTR4_94_MASK			(1ULL << (FATTR4_WORD2 + 30))
#define	FATTR4_95_MASK			(1ULL << (FATTR4_WORD2 + 31))

#define	FATTR4_96_MASK	(1ULL << (FATTR4_WORD3 + 0))
#define	FATTR4_97_MASK	(1ULL << (FATTR4_WORD3 + 1))
#define	FATTR4_98_MASK	(1ULL << (FATTR4_WORD3 + 2))
#define	FATTR4_99_MASK	(1ULL << (FATTR4_WORD3 + 3))
#define	FATTR4_100_MASK	(1ULL << (FATTR4_WORD3 + 4))
#define	FATTR4_101_MASK	(1ULL << (FATTR4_WORD3 + 5))
#define	FATTR4_102_MASK	(1ULL << (FATTR4_WORD3 + 6))
#define	FATTR4_103_MASK	(1ULL << (FATTR4_WORD3 + 7))
#define	FATTR4_104_MASK	(1ULL << (FATTR4_WORD3 + 8))
#define	FATTR4_105_MASK	(1ULL << (FATTR4_WORD3 + 9))
#define	FATTR4_106_MASK	(1ULL << (FATTR4_WORD3 + 10))
#define	FATTR4_107_MASK	(1ULL << (FATTR4_WORD3 + 11))
#define	FATTR4_108_MASK	(1ULL << (FATTR4_WORD3 + 12))
#define	FATTR4_109_MASK	(1ULL << (FATTR4_WORD3 + 13))
#define	FATTR4_110_MASK	(1ULL << (FATTR4_WORD3 + 14))
#define	FATTR4_111_MASK	(1ULL << (FATTR4_WORD3 + 15))
#define	FATTR4_112_MASK	(1ULL << (FATTR4_WORD3 + 16))
#define	FATTR4_113_MASK	(1ULL << (FATTR4_WORD3 + 17))
#define	FATTR4_114_MASK	(1ULL << (FATTR4_WORD3 + 18))
#define	FATTR4_115_MASK	(1ULL << (FATTR4_WORD3 + 19))
#define	FATTR4_116_MASK	(1ULL << (FATTR4_WORD3 + 20))
#define	FATTR4_117_MASK	(1ULL << (FATTR4_WORD3 + 21))
#define	FATTR4_118_MASK	(1ULL << (FATTR4_WORD3 + 22))
#define	FATTR4_119_MASK	(1ULL << (FATTR4_WORD3 + 23))
#define	FATTR4_120_MASK	(1ULL << (FATTR4_WORD3 + 24))
#define	FATTR4_121_MASK	(1ULL << (FATTR4_WORD3 + 25))
#define	FATTR4_122_MASK	(1ULL << (FATTR4_WORD3 + 26))
#define	FATTR4_123_MASK	(1ULL << (FATTR4_WORD3 + 27))
#define	FATTR4_124_MASK	(1ULL << (FATTR4_WORD3 + 28))
#define	FATTR4_125_MASK	(1ULL << (FATTR4_WORD3 + 29))
#define	FATTR4_126_MASK	(1ULL << (FATTR4_WORD3 + 30))
#define	FATTR4_127_MASK	(1ULL << (FATTR4_WORD3 + 31))

/*
 * NFS4 attrs which map directly to vattr_t attrs
 */
#define	NFS4_VATTR_MASK (		\
	FATTR4_TYPE_MASK |		\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_FSID_MASK |		\
	FATTR4_FILEID_MASK |		\
	FATTR4_MODE_MASK |		\
	FATTR4_OWNER_MASK |		\
	FATTR4_OWNER_GROUP_MASK |	\
	FATTR4_NUMLINKS_MASK |		\
	FATTR4_TIME_ACCESS_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_RAWDEV_MASK |		\
	FATTR4_SPACE_USED_MASK |	\
	FATTR4_MOUNTED_ON_FILEID_MASK)

#define	NFS4_NTOV_ATTR_MASK NFS4_VATTR_MASK

/*
 * NFS4 attrs requested by default.
 *
 * DEBUG: The pNFS attrs are included in the default
 * NFS41 set for now just to exercise the new attr code.
 * It doesn't cause misbehavior to request the pNFS attrs
 * if the server does not support them; however, it would
 * be better to stop requesting pnfs attrs from servers
 * and that don't support pNFS.
 */
#define	NFS41_DEFAULT_MASK0	NFS4_VATTR_MASK

#define	NFS41_DEFAULT_MASK1 (		\
	FATTR4_LAYOUT_TYPE_MASK |	\
	FATTR4_LAYOUT_BLKSIZE_MASK |	\
	FATTR4_LAYOUT_ALIGNMENT_MASK |	\
	FATTR4_MDSTHRESHOLD_MASK)

#define	NFS4_PATHCONF_MASK (		\
	NFS4_VATTR_MASK |		\
	FATTR4_NO_TRUNC_MASK |		\
	FATTR4_CHOWN_RESTRICTED_MASK |	\
	FATTR4_CASE_INSENSITIVE_MASK |	\
	FATTR4_CASE_PRESERVING_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_CANSETTIME_MASK |	\
	FATTR4_HOMOGENEOUS_MASK |	\
	FATTR4_MAXLINK_MASK |		\
	FATTR4_MAXNAME_MASK |		\
	FATTR4_MAXFILESIZE_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_NTOV_ATTR_AT_MASK (	\
	AT_TYPE |			\
	AT_SIZE |			\
	AT_FSID |			\
	AT_NODEID |			\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_NLINK |			\
	AT_ATIME |			\
	AT_MTIME |			\
	AT_CTIME |			\
	AT_RDEV |			\
	AT_NBLOCKS)

/*
 * Common bitmap4 of filesystem attributes to be gathered
 */
#define	NFS4_FS_ATTR_MASK (		\
	FATTR4_FILES_AVAIL_MASK |	\
	FATTR4_FILES_FREE_MASK |	\
	FATTR4_FILES_TOTAL_MASK |	\
	FATTR4_SPACE_AVAIL_MASK |	\
	FATTR4_SPACE_FREE_MASK |	\
	FATTR4_SPACE_TOTAL_MASK)

#define	NFS4_STATFS_ATTR_MASK (		\
	NFS4_FS_ATTR_MASK |		\
	FATTR4_MAXNAME_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_FS_ATTR_AT_MASK	0

/*
 * Common bitmap4 to gather attr cache state
 */
#define	NFS4_NTOV_ATTR_CACHE_MASK (	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_SIZE_MASK)

/*
 * The corresponding AT_MASK
 */
#define	NFS4_NTOV_ATTR_CACHE_AT_MASK (	\
	AT_CTIME |			\
	AT_MTIME |			\
	AT_SIZE)

#define	NFS4_VTON_ATTR_MASK (		\
	AT_TYPE |			\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_NODEID |			\
	AT_SIZE |			\
	AT_NLINK |			\
	AT_ATIME |			\
	AT_MTIME |			\
	AT_CTIME |			\
	AT_RDEV |			\
	AT_NBLOCKS |			\
	AT_FSID)

#define	NFS4_VTON_ATTR_MASK_SET (	\
	AT_MODE |			\
	AT_UID |			\
	AT_GID |			\
	AT_SIZE |			\
	AT_ATIME |			\
	AT_MTIME)

#define	FATTR4_MANDATTR_MASK0 (		\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_LEASE_TIME_MASK |	\
	FATTR4_RDATTR_ERROR_MASK |	\
	FATTR4_FILEHANDLE_MASK)

#define	NFS4_FSINFO_MASK (		\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_MAXFILESIZE_MASK |	\
	FATTR4_MAXREAD_MASK |		\
	FATTR4_MAXWRITE_MASK)

#define	NFS41_FSINFO_MASK0 (		\
	NFS4_FSINFO_MASK |		\
	FATTR4_FS_LAYOUT_TYPE_MASK)

#define	NFS41_FSINFO_MASK1	FATTR4_SUPPATTR_EXCLCREAT_MASK

/*
 * default layout alignment / blksizes for now
 */
#define	RFS41_DEFAULT_LAYOUT_ALIGNMENT  8192
#define	RFS41_DEFAULT_LAYOUT_BLKSIZE    131072
#define	NFS41_DEFAULT_LAYOUT_STRIPELEN	131072
#define	NFS41_DEFAULT_LAYOUT_NUMSTRIPE	2

enum attrvers {
	AV_NFS40 = 0,
	AV_NFS41,
	AV_COUNT
};
typedef enum attrvers attrvers_t;

#define	NFS4_ATTR_COUNT(avers)	\
	((avers) == AV_NFS40 ? NFS40_ATTR_COUNT : NFS41_ATTR_COUNT)

#define	NFS4_NTOV_MAP_SIZE(avers)	NFS4_ATTR_COUNT(avers)

#define	NFS4_NTOV_MAP(avers)	\
	((avers) == AV_NFS40 ? nfs40_ntov_map : nfs41_ntov_map)

extern attrmap4 nfs4_empty_attrmap;
extern attrmap4 nfs4_pathconf_attrmap;
extern attrmap4 nfs4_vattr_attrmap;
extern attrmap4 nfs4_statfs_attrmap;
extern attrmap4 nfs4_extres_attrmap;
extern attrmap4 nfs4_minrddir_attrmap;
extern attrmap4 rfs41_supp_exclcreat_attrmap;
extern attrmap4 nfs4_attrcache_attrmap;
extern attrmap4 nfs4_leasetime_attrmap;
extern attrmap4 rfs4_fsspace_attrmap;

/*
 * These macros take and ignore vers just for consistency.
 * attr vers 0 and vers 1 contain the same bits.
 */
#define	NFS4_EMPTY_ATTRMAP(vers)	nfs4_empty_attrmap
#define	NFS4_PATHCONF_ATTRMAP(vers)	nfs4_pathconf_attrmap
#define	NFS4_VATTR_ATTRMAP(vers)	nfs4_vattr_attrmap
#define	NFS4_STATFS_ATTRMAP(vers)	nfs4_statfs_attrmap
#define	NFS4_EXTRES_ATTRMAP(vers)	nfs4_extres_attrmap
#define	NFS4_MINRDDIR_ATTRMAP(vers)	nfs4_minrddir_attrmap
#define	RFS41_EXCLCREAT_ATTRMAP(vers)	rfs41_supp_exclcreat_attrmap
#define	NFS4_ATTRCACHE_ATTRMAP(vers)	nfs4_attrcache_attrmap
#define	NFS4_LEASETIME_ATTRMAP(vers)	nfs4_leasetime_attrmap
#define	RFS4_FS_SPACE_ATTRMAP(vers)	rfs4_fsspace_attrmap

#define	MI4_ATTRVERS(m)			((m)->mi_attrvers)
#define	MI4_EMPTY_ATTRMAP(m)		NFS4_EMPTY_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_PATHCONF_ATTRMAP(m)		NFS4_PATHCONF_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_VATTR_ATTRMAP(m)		NFS4_VATTR_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_STATFS_ATTRMAP(m)		NFS4_STATFS_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_EXTRES_ATTRMAP(m)		NFS4_EXTRES_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_MINRDDIR_ATTRMAP(m)		NFS4_MINRDDIR_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_ATTRCACHE_ATTRMAP(m)	NFS4_ATTRCACHE_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_LEASETIME_ATTRMAP(m)	NFS4_LEASETIME_ATTRMAP(MI4_ATTRVERS(m))

extern attrmap4 nfs4_default_attrmap[];
extern attrmap4 nfs4_fsinfo_attrmap[];
extern attrmap4 nfs4_mandatory_attrmap[];
extern attrmap4 nfs4_rddir_attrmap[];
extern attrmap4 rfs4_supp_attrmap[];
extern attrmap4 rfs4_rddir_supp_attrmap[];

#define	NFS4_DEFAULT_ATTRMAP(vers)	nfs4_default_attrmap[vers]
#define	NFS4_FSINFO_ATTRMAP(vers)	nfs4_fsinfo_attrmap[vers]
#define	NFS4_MAND_ATTRMAP(vers)		nfs4_mandatory_attrmap[vers]
#define	NFS4_RDDIR_ATTRMAP(vers)	nfs4_rddir_attrmap[vers]
#define	RFS4_SUPP_ATTRMAP(vers)		rfs4_supp_attrmap[vers]
#define	RFS4_RDDIR_SUPP_ATTRMAP(vers)	rfs4_rddir_supp_attrmap[vers]

#define	MI4_DEFAULT_ATTRMAP(m)		NFS4_DEFAULT_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_FSINFO_ATTRMAP(m)		NFS4_FSINFO_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_MAND_ATTRMAP(m)		NFS4_MAND_ATTRMAP(MI4_ATTRVERS(m))
#define	MI4_RDDIR_ATTRMAP(m)		NFS4_RDDIR_ATTRMAP(MI4_ATTRVERS(m))

#define	NFS4_VPDFL_ATTRMAP(vp)		(MI4_DEFAULT_ATTRMAP(VTOMI4(vp)))

/*
 * These are the support attributes for the NFSv4 server
 */
#define	NFS4_SRV_RDDIR_SUPP_MASK (	\
	FATTR4_SUPPORTED_ATTRS_MASK |	\
	FATTR4_TYPE_MASK |		\
	FATTR4_FH_EXPIRE_TYPE_MASK |	\
	FATTR4_CHANGE_MASK |		\
	FATTR4_SIZE_MASK |		\
	FATTR4_LINK_SUPPORT_MASK |	\
	FATTR4_SYMLINK_SUPPORT_MASK |	\
	FATTR4_NAMED_ATTR_MASK |	\
	FATTR4_FSID_MASK |		\
	FATTR4_UNIQUE_HANDLES_MASK |	\
	FATTR4_LEASE_TIME_MASK |	\
	FATTR4_RDATTR_ERROR_MASK |	\
	FATTR4_CANSETTIME_MASK |	\
	FATTR4_CASE_INSENSITIVE_MASK |	\
	FATTR4_CASE_PRESERVING_MASK |	\
	FATTR4_CHOWN_RESTRICTED_MASK |	\
	FATTR4_FILEHANDLE_MASK |	\
	FATTR4_FILEID_MASK |		\
	FATTR4_FILES_AVAIL_MASK |	\
	FATTR4_FILES_FREE_MASK |	\
	FATTR4_FILES_TOTAL_MASK |	\
	FATTR4_HOMOGENEOUS_MASK |	\
	FATTR4_MAXFILESIZE_MASK |	\
	FATTR4_MAXLINK_MASK |		\
	FATTR4_MAXNAME_MASK |		\
	FATTR4_MAXREAD_MASK |		\
	FATTR4_MAXWRITE_MASK |		\
	FATTR4_MODE_MASK |		\
	FATTR4_NO_TRUNC_MASK |		\
	FATTR4_NUMLINKS_MASK |		\
	FATTR4_OWNER_MASK |		\
	FATTR4_OWNER_GROUP_MASK |	\
	FATTR4_RAWDEV_MASK |		\
	FATTR4_SPACE_AVAIL_MASK |	\
	FATTR4_SPACE_FREE_MASK |	\
	FATTR4_SPACE_TOTAL_MASK |	\
	FATTR4_SPACE_USED_MASK |	\
	FATTR4_TIME_ACCESS_MASK |	\
	FATTR4_TIME_DELTA_MASK |	\
	FATTR4_TIME_METADATA_MASK |	\
	FATTR4_TIME_MODIFY_MASK |	\
	FATTR4_MOUNTED_ON_FILEID_MASK	\
)

#define	NFS4_SRV_SUPP_MASK (		\
	NFS4_SRV_RDDIR_SUPP_MASK |	\
	FATTR4_ACL_MASK |		\
	FATTR4_ACLSUPPORT_MASK |	\
	FATTR4_TIME_ACCESS_SET_MASK |	\
	FATTR4_TIME_MODIFY_SET_MASK	\
)

#define	NFS41_SRV_SUPP_MASK0 (		\
	NFS4_SRV_SUPP_MASK |		\
	FATTR4_FS_LAYOUT_TYPE_MASK |	\
	FATTR4_LAYOUT_HINT_MASK		\
)

#define	NFS41_SRV_SUPP_MASK1 (		\
	FATTR4_LAYOUT_TYPE_MASK |	\
	FATTR4_LAYOUT_BLKSIZE_MASK |	\
	FATTR4_LAYOUT_ALIGNMENT_MASK |	\
	FATTR4_MDSTHRESHOLD_MASK |	\
	FATTR4_SUPPATTR_EXCLCREAT_MASK	\
)

#define	NFS41_SRV_RDDIR_SUPP_MASK0 (	\
	NFS4_SRV_RDDIR_SUPP_MASK |	\
	NFS41_SRV_SUPP_MASK0		\
)
#define	NFS41_SRV_RDDIR_SUPP_MASK1 NFS41_SRV_SUPP_MASK1

/*
 * other settable attrs
 * hidden
 * mimetype
 * archive
 * system
 * time_backup
 * time_create
 * dacl
 * sacl
 * retentevt_set
 * retention_set
 * retention_hold
 * mode_set_masked
 *
 * Note: time_modify_set not in mask because time_modify is the
 * verifier used to implement exclusive create
 */
#define	NFS41_SRV_EXCLCREAT_ATTRS (		\
	FATTR4_SIZE_MASK		|	\
	FATTR4_MODE_MASK		|	\
	FATTR4_ACL_MASK			|	\
	FATTR4_OWNER_MASK		|	\
	FATTR4_OWNER_GROUP_MASK		|	\
	FATTR4_LAYOUT_HINT_MASK		|	\
	FATTR4_TIME_ACCESS_SET_MASK)

#define	FATTR4_FSID_EQ(a, b)					\
	((a)->major == (b)->major && (a)->minor == (b)->minor)

#define	NFS4_MAXNUM_BITWORDS	3
#define	NFS4_MAXNUM_ATTRS	(FATTR4_FS_CHARSET_CAP + 1)


union nfs4_attr_u {
	attrmap4			supported_attrs;
	fattr4_type			type;
	fattr4_fh_expire_type		fh_expire_type;
	fattr4_change			change;
	fattr4_size			size;
	fattr4_link_support		link_support;
	fattr4_symlink_support		symlink_support;
	fattr4_named_attr		named_attr;
	fattr4_fsid			fsid;
	fattr4_unique_handles		unique_handles;
	fattr4_lease_time		lease_time;
	fattr4_rdattr_error		rdattr_error;
	fattr4_acl			acl;
	fattr4_aclsupport		aclsupport;
	fattr4_archive			archive;
	fattr4_cansettime		cansettime;
	fattr4_case_insensitive		case_insensitive;
	fattr4_case_preserving		case_preserving;
	fattr4_chown_restricted		chown_restricted;
	fattr4_fileid			fileid;
	fattr4_files_avail		files_avail;
	fattr4_filehandle		filehandle;
	fattr4_files_free		files_free;
	fattr4_files_total		files_total;
	fattr4_fs_locations		fs_locations;
	fattr4_hidden			hidden;
	fattr4_homogeneous		homogeneous;
	fattr4_maxfilesize		maxfilesize;
	fattr4_maxlink			maxlink;
	fattr4_maxname			maxname;
	fattr4_maxread			maxread;
	fattr4_maxwrite			maxwrite;
	fattr4_mimetype			mimetype;
	fattr4_mode			mode;
	fattr4_no_trunc			no_trunc;
	fattr4_numlinks			numlinks;
	fattr4_owner			owner;
	fattr4_owner_group		owner_group;
	fattr4_quota_avail_hard		quota_avail_hard;
	fattr4_quota_avail_soft		quota_avail_soft;
	fattr4_quota_used		quota_used;
	fattr4_rawdev			rawdev;
	fattr4_space_avail		space_avail;
	fattr4_space_free		space_free;
	fattr4_space_total		space_total;
	fattr4_space_used		space_used;
	fattr4_system			system;
	fattr4_time_access		time_access;
	fattr4_time_access_set		time_access_set;
	fattr4_time_backup		time_backup;
	fattr4_time_create		time_create;
	fattr4_time_delta		time_delta;
	fattr4_time_metadata		time_metadata;
	fattr4_time_modify		time_modify;
	fattr4_time_modify_set		time_modify_set;
	fattr4_mounted_on_fileid	mounted_on_fileid;
	layouttypes4_t			fs_layout_types;
	file_layouthint4		file_layouthint;
	layouttypes4_t			layout_types;
	fattr4_layout_blksize		layout_blksize;
	fattr4_layout_alignment		layout_alignment;
	file_mdsthreshold4		file_mdsthreshold;
	attrmap4			supp_exclcreat;
};

/*
 * Error details when processing the getattr response.
 */
#define	NFS4_GETATTR_OP_OK		0
#define	NFS4_GETATTR_STATUS_ERR		1
#define	NFS4_GETATTR_MANDATTR_ERR	2
#define	NFS4_GETATTR_BITMAP_ERR		3
#define	NFS4_GETATTR_ATSIZE_ERR		4
#define	NFS4_GETATTR_ATUID_ERR		5
#define	NFS4_GETATTR_ATGID_ERR		6
#define	NFS4_GETATTR_ATATIME_ERR	7
#define	NFS4_GETATTR_ATMTIME_ERR	8
#define	NFS4_GETATTR_ATCTIME_ERR	9
#define	NFS4_GETATTR_RAWDEV_ERR		10
#define	NFS4_GETATTR_ATNBLOCK_ERR	11
#define	NFS4_GETATTR_MAXFILESIZE_ERR	12
#define	NFS4_GETATTR_FHANDLE_ERR	13
#define	NFS4_GETATTR_MAXREAD_ERR	14
#define	NFS4_GETATTR_MAXWRITE_ERR	15
#define	NFS4_GETATTR_NOCACHE_OK		16

struct nfs4_pathconf_info {
	unsigned pc4_cache_valid:1;	/* When in rnode4, is data valid? */
	unsigned pc4_no_trunc:1;
	unsigned pc4_chown_restricted:1;
	unsigned pc4_case_insensitive:1;
	unsigned pc4_case_preserving:1;
	unsigned pc4_xattr_valid:1;
	unsigned pc4_xattr_exists:1;
	unsigned pc4_link_support:1;
	unsigned pc4_symlink_support:1;
	unsigned pc4_unique_handles:1;
	unsigned pc4_cansettime:1;
	unsigned pc4_homogeneous:1;
	uint_t	pc4_link_max;
	uint_t	pc4_name_max;
	uint_t	pc4_filesizebits;
};
typedef struct nfs4_pathconf_info nfs4_pathconf_info_t;

struct nfs4_pnfs_attr {
	layouttypes4_t		n4g_fs_layout_type;
	layouttypes4_t		n4g_layout_type;
	fattr4_layout_alignment	n4g_layout_alignment;
	fattr4_layout_blksize	n4g_layout_blksize;
	/*
	 * client only decodes layout hint and mdsthreshold associated
	 * with file-typed layouts.
	 */
	file_layouthint4	n4g_layouthint;
	file_mdsthreshold4	n4g_file_mdsthreshold;
};
typedef struct nfs4_pnfs_attr nfs4_pnfs_attr_t;

/*
 * Used for client only to process incoming getattr results.
 */
typedef struct nfs4_ga_ext_res {
	attrmap4			n4g_suppattrs;
	nfsstat4			n4g_rdattr_error;
	fattr4_fh_expire_type		n4g_fet;
	fattr4_lease_time		n4g_leasetime;
	uint64_t			n4g_maxfilesize;
	uint64_t			n4g_maxread;
	uint64_t			n4g_maxwrite;
	nfstime4			n4g_delta;
	nfs4_pathconf_info_t		n4g_pc4;
	struct statvfs64		n4g_sb;
	union {
		nfs_fh4 n4g_fh;
		struct {
			uint_t len;
			char *val;
			char data[NFS4_FHSIZE];
		} nfs_fh4_alt;
	} n4g_fh_u;
	/*
	 * Bitmask with valid fields being:
	 * ACL4_SUPPORT_ALLOW_ACL
	 * ACL4_SUPPORT_DENY_ACL
	 * ACL4_SUPPORT_AUDIT_ACL
	 * ACL4_SUPPORT_ALARM_ACL
	 */
	fattr4_aclsupport		n4g_aclsupport;
	attrmap4			n4g_supp_exclcreat;
	nfs4_pnfs_attr_t		n4g_pnfs;
} nfs4_ga_ext_res_t;

#ifdef	__cplusplus
}
#endif
#endif /* _KERNEL */
#endif /* _NFS4_ATTR_H */
