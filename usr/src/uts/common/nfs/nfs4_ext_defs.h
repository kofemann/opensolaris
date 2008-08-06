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
#ifndef	_NFS4_EXT_DEFS_H
#define	_NFS4_EXT_DEFS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Extended definition in NFSv4.1
 */
enum nfsstat4 {
	NFS4_OK = 0,
	NFS4ERR_PERM = 1,
	NFS4ERR_NOENT = 2,
	NFS4ERR_IO = 5,
	NFS4ERR_NXIO = 6,
	NFS4ERR_ACCESS = 13,
	NFS4ERR_EXIST = 17,
	NFS4ERR_XDEV = 18,
	NFS4ERR_NOTDIR = 20,
	NFS4ERR_ISDIR = 21,
	NFS4ERR_INVAL = 22,
	NFS4ERR_FBIG = 27,
	NFS4ERR_NOSPC = 28,
	NFS4ERR_ROFS = 30,
	NFS4ERR_MLINK = 31,
	NFS4ERR_NAMETOOLONG = 63,
	NFS4ERR_NOTEMPTY = 66,
	NFS4ERR_DQUOT = 69,
	NFS4ERR_STALE = 70,
	NFS4ERR_BADHANDLE = 10001,
	NFS4ERR_BAD_COOKIE = 10003,
	NFS4ERR_NOTSUPP = 10004,
	NFS4ERR_TOOSMALL = 10005,
	NFS4ERR_SERVERFAULT = 10006,
	NFS4ERR_BADTYPE = 10007,
	NFS4ERR_DELAY = 10008,
	NFS4ERR_SAME = 10009,
	NFS4ERR_DENIED = 10010,
	NFS4ERR_EXPIRED = 10011,
	NFS4ERR_LOCKED = 10012,
	NFS4ERR_GRACE = 10013,
	NFS4ERR_FHEXPIRED = 10014,
	NFS4ERR_SHARE_DENIED = 10015,
	NFS4ERR_WRONGSEC = 10016,
	NFS4ERR_CLID_INUSE = 10017,
	NFS4ERR_RESOURCE = 10018,
	NFS4ERR_MOVED = 10019,
	NFS4ERR_NOFILEHANDLE = 10020,
	NFS4ERR_MINOR_VERS_MISMATCH = 10021,
	NFS4ERR_STALE_CLIENTID = 10022,
	NFS4ERR_STALE_STATEID = 10023,
	NFS4ERR_OLD_STATEID = 10024,
	NFS4ERR_BAD_STATEID = 10025,
	NFS4ERR_BAD_SEQID = 10026,
	NFS4ERR_NOT_SAME = 10027,
	NFS4ERR_LOCK_RANGE = 10028,
	NFS4ERR_SYMLINK = 10029,
	NFS4ERR_RESTOREFH = 10030,
	NFS4ERR_LEASE_MOVED = 10031,
	NFS4ERR_ATTRNOTSUPP = 10032,
	NFS4ERR_NO_GRACE = 10033,
	NFS4ERR_RECLAIM_BAD = 10034,
	NFS4ERR_RECLAIM_CONFLICT = 10035,
	NFS4ERR_BADXDR = 10036,
	NFS4ERR_LOCKS_HELD = 10037,
	NFS4ERR_OPENMODE = 10038,
	NFS4ERR_BADOWNER = 10039,
	NFS4ERR_BADCHAR = 10040,
	NFS4ERR_BADNAME = 10041,
	NFS4ERR_BAD_RANGE = 10042,
	NFS4ERR_LOCK_NOTSUPP = 10043,
	NFS4ERR_OP_ILLEGAL = 10044,
	NFS4ERR_DEADLOCK = 10045,
	NFS4ERR_FILE_OPEN = 10046,
	NFS4ERR_ADMIN_REVOKED = 10047,
	NFS4ERR_CB_PATH_DOWN = 10048,
	NFS4ERR_BADIOMODE = 10049,
	NFS4ERR_BADLAYOUT = 10050,
	NFS4ERR_BAD_SESSION_DIGEST = 10051,
	NFS4ERR_BADSESSION = 10052,
	NFS4ERR_BADSLOT = 10053,
	NFS4ERR_COMPLETE_ALREADY = 10054,
	NFS4ERR_CONN_NOT_BOUND_TO_SESSION = 10055,
	NFS4ERR_DELEG_ALREADY_WANTED = 10056,
	NFS4ERR_BACK_CHAN_BUSY = 10057,
	NFS4ERR_LAYOUTTRYLATER = 10058,
	NFS4ERR_LAYOUTUNAVAILABLE = 10059,
	NFS4ERR_NOMATCHING_LAYOUT = 10060,
	NFS4ERR_RECALLCONFLICT = 10061,
	NFS4ERR_UNKNOWN_LAYOUTTYPE = 10062,
	NFS4ERR_SEQ_MISORDERED = 10063,
	NFS4ERR_SEQUENCE_POS = 10064,
	NFS4ERR_REQ_TOO_BIG = 10065,
	NFS4ERR_REP_TOO_BIG = 10066,
	NFS4ERR_REP_TOO_BIG_TO_CACHE = 10067,
	NFS4ERR_RETRY_UNCACHED_REP = 10068,
	NFS4ERR_UNSAFE_COMPOUND = 10069,
	NFS4ERR_TOO_MANY_OPS = 10070,
	NFS4ERR_OP_NOT_IN_SESSION = 10071,
	NFS4ERR_HASH_ALG_UNSUPP = 10072,
	/* Error 10073 is unused. */
	NFS4ERR_CLIENTID_BUSY = 10074,
	NFS4ERR_PNFS_IO_HOLE = 10075,
	NFS4ERR_SEQ_FALSE_RETRY = 10076,
	NFS4ERR_BAD_HIGH_SLOT = 10077,
	NFS4ERR_DEADSESSION = 10078,
	NFS4ERR_ENCR_ALG_UNSUPP = 10079,
	NFS4ERR_PNFS_NO_LAYOUT = 10080,
	NFS4ERR_NOT_ONLY_OP = 10081,
	NFS4ERR_WRONG_CRED = 10082,
	NFS4ERR_WRONG_TYPE = 10083,
	NFS4ERR_DIRDELEG_UNAVAIL = 10084,
	NFS4ERR_REJECT_DELEG = 10085,
	NFS4ERR_RETURNCONFLICT = 10086
};
typedef enum nfsstat4 nfsstat4;

/*
 * Extended definition in NFSv4.1
 */
enum open_delegation_type4 {
	OPEN_DELEGATE_NONE = 0,
	OPEN_DELEGATE_READ = 1,
	OPEN_DELEGATE_WRITE = 2,
	OPEN_DELEGATE_NONE_EXT = 3
};
typedef enum open_delegation_type4 open_delegation_type4;

/*
 * Extended definition in NFSv4.1
 */
enum open_claim_type4 {
	CLAIM_NULL = 0,
	CLAIM_PREVIOUS = 1,
	CLAIM_DELEGATE_CUR = 2,
	CLAIM_DELEGATE_PREV = 3,
	CLAIM_FH = 4,
	CLAIM_DELEG_CUR_FH = 5,
	CLAIM_DELEG_PREV_FH = 6
};
typedef enum open_claim_type4 open_claim_type4;

/*
 * New type, but needed here so the include ordering will work
 */
enum why_no_delegation4 {
	WND4_NOT_WANTED = 0,
	WND4_CONTENTION = 1,
	WND4_RESOURCE = 2,
	WND4_NOT_SUPP_FTYPE = 3,
	WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4,
	WND4_NOT_SUPP_UPGRADE = 5,
	WND4_NOT_SUPP_DOWNGRADE = 6,
	WND4_CANCELED = 7,
	WND4_IS_DIR = 8
};
typedef enum why_no_delegation4 why_no_delegation4;

/*
 * New type, but needed here so the include ordering will work
 */
struct open_none_delegation4 {
	why_no_delegation4 ond_why;
	union {
		bool_t ond_server_will_push_deleg;
		bool_t ond_server_will_signal_avail;
	} open_none_delegation4_u;
};
typedef struct open_none_delegation4 open_none_delegation4;

#ifdef __cplusplus
}
#endif

#endif	/* _NFS4_EXT_DEFS_H */
