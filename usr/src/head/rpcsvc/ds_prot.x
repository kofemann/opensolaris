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

%#pragma ident	"%Z%%M%	%I%	%E% SMI"



#if defined(RPC_XDR) || defined(RPC_SVC) || defined(RPC_CLNT)
%#include <nfs/ds.h>
#endif

%#include <nfs/nfs41_fhtype.h>

const NFS_FH4MAXDATA		= 26;

%#include <nfs/ds_filehandle.h>

/*
 *  Dot-x file for the data server control protocol.
 */

typedef uint64_t	ds_verifier4;
typedef uint64_t	ds_id;

/* RPCSEC_GSS has a value of '6' - See RFC 2203 */
union ds_secinfo4 switch (uint32_t flavor) {
 case RPCSEC_GSS:
	 rpcsec_gss_info	flavor_info;
 default:
	 void;
};

enum ds_status {
      	DS_OK		= 0,
      	DSERR_NOT_AUTH,
      	DSERR_INVAL,
      	DSERR_ACCESS,
      	DSERR_NOSPC,
      	DSERR_STALE,
      	DSERR_BAD_FH,
      	DSERR_BAD_COOKIE,
      	DSERR_NOTSUPP,
      	DSERR_TOOSMALL,
      	DSERR_SERVERFAULT,
      	DSERR_EXPIRED,
      	DSERR_GRACE,
      	DSERR_FHEXPIRED,
      	DSERR_WRONGSEC,
      	DSERR_RESOURCE,
      	DSERR_STALE_CLIENTID,
      	DSERR_STALE_STATEID,
      	DSERR_OLD_STATEID,
      	DSERR_BAD_STATEID,
	DSERR_XDR,
      	DSERR_ILLEGAL
};

typedef enum ds_status ds_status;

struct ds_attr {
      	int		ds_attrmask;
      	uint64_t	ds_size;
};

typedef struct ds_attr ds_attr;

struct identity {
        ds_verifier4    boot_verifier;
        opaque          instance<MAXPATHLEN>;
};

/*
 * ds_ident  : An identiifier that the MDS can use to distinguish
 *             between data-server instances.
 */
struct DS_EXIBIargs {
      	identity ds_ident;
};


/*
 * ds_id     : The 'short-hand' identifier MDS assigned
 *
 * mds_ident : An identifier that the data-server can use to distinguish
 *             between MDS instances.
 *
 * lease_period: A hint to the data-server on the lease period
 * 		 currently in effect at the MDS.
 */
struct DS_EXIBIresok {
      	ds_id  ds_id;
      	identity mds_ident;
      	uint32_t lease_period;
};


union DS_EXIBIres switch (ds_status status) {
case DS_OK:
	DS_EXIBIresok        dhr_res_ok;
default:
	void;
};

/*
 * DS_CHECKSTATEargs -
 *
 * The message from a DS that is asking for the presented file state
 * to be verified.
 *
 *   fh:
 *
 *   File handle that the DS received in the compound (via PUTFH)
 *   from the client when the client performed I/O.
 *
 *   stateid:
 *
 *   The stateid the client presented for the I/O.
 *
 *   co_owner:
 *
 *   client owner (MUST be same as MDS client owner)
 */
struct DS_CHECKSTATEargs {
      	nfs_fh4      fh;
      	stateid4     stateid;
	client_owner4    co_owner;
};

/*
 * DS_filestate -
 *
 * The reply to the DS from MDS that confirms the
 * validity of the presented state.
 *
 *   mds_clid:
 *
 *   The MDS client id  that corresponds to the presented stateid.
 *
 *   layout:
 *
 *   The layout of the file.  This allows the DS
 *   to determine if the offset that the client is performing
 *   I/O to is valid based on the layout.
 *
 *   open_mode:
 *
 *   The effective open mode for the object + clientid, based on the
 *   mode open() mode and the export mode
 *
 *   mds_fsid:
 *
 *   The contating MDS fsid for the object.
 */
struct ds_filestate {
      	clientid4 mds_clid;
      	layout4   layout;
      	int       open_mode;
      	fsid4     mds_fsid;
};

union DS_CHECKSTATEres switch (ds_status status) {
case DS_OK:
      	ds_filestate    file_state;
default:
      	void;
};

/*
 * DS_zfsattr -
 *
 * Attribute that pertains to the zfs storage information/state etc.
 *
 *    attrname:
 *
 *    Name of attribute.
 *
 *    attrvalue:
 *
 *    Value of the attribute.
 *
 * Supported attributes:
 *
 *
 * +----------+------------+-----------------------------------------
 * | attrname | type       | Description
 * +----------+------------+-----------------------------------------
 * | state    | boolean    | current status of pool: 0=offline,
 * |          |            | 			     1=online
 * +----------+------------+-----------------------------------------
 * | size     | uint64_t   | bytes free on dataset.
 * +----------+------------+-----------------------------------------
 * | config   |  attrvalue: xxx - look at how zpool status
 * |          |   displays the pool
 * |          |  configuration.
 * +----------+------------+-----------------------------------------
 */
struct ds_zfsattr {
      	utf8string  attrname;
      	opaque      attrvalue<>;
};

typedef uint32_t   ds_addruse;

/*
 *  Intended usage for the addresses.
 */
const NFS      = 0x00000001;
const DSERV    = 0x00000002;

/*
 * DS_addr -
 *
 * A structure that is used to specify an address and
 * its usage.
 *
 *    addr:
 *
 *    The specific address on the DS.
 *
 *    validuse:
 *
 *    Bitmap associating the netaddr defined in "addr"
 *    to the protocols that are valid for that interface.
 */
struct ds_addr {
	struct netaddr4     addr;
	ds_addruse          validuse;
};

/*
 * ds_zfsguid -
 *
 *	The data server guid made up of the local zpool guid + dataset id
 */
struct ds_zfsguid {
	uint64_t	zpool_guid;
	uint64_t	dataset_guid;
};

enum storage_type {
	ZFS = 1
};

typedef enum storage_type storage_type;

union ds_guid switch (storage_type stor_type) {
case ZFS:
	opaque	zfsguid<>;
default:
	void;
};

/*
 * ds_guid_map -
 *
 *	The mapping between the local data server guid value and the id-value
 *	assigned by the MDS for mapping.
 *
 *	If the storage type is ZFS, encoded in the ds_guid will be
 *	a ds_zfsguid.  Other storage types may have their own guid
 *	definition.
 *	
 *	Encoded in the mds_ppid field will be an array of mds_ppid_contents.
 */
struct ds_guid_map {
	ds_guid		ds_guid;
      	mds_ppid	mds_ppid_array<>;
};

/*
 * ds_zfsinfo -
 *
 * Contains all the attributes that pertain to the specified ZFS storage
 * identifier.
 *
 *    guid_map:
 *
 *    Unique value identifying the pNFS dataset and the zpool it lives in.
 *    *Note: This has to be unique across all storage in our
 *           system.  Meaning that we may have to generate ids
 *           which take into account the poolid assigned by the  SPA
 *           and the DS that the pool belongs to.
 *
 *    attrs:
 *
 *    List of name value pairs corresponding to the attributes
 *    of the ZFS data store (e.g. zpool and dataset attribues).
 *    *Note: We may want to rethink how we are handling attributes.
 *	     We should probably have some general attributes (e.g.
 *	     online/offline, size, free_size).  Then we can have
 *	     attributes that are specific to the storage type (e.g.
 *	     zpool configuration (e.g. mirrored, RAIDZ),
 *	     dataset attributes (e.g. encryption, compression).
 */
struct ds_zfsinfo {
      	ds_guid_map	guid_map;
	ds_zfsattr	attrs<>;
};

/*
 * ds_storinfo -
 *
 *	Information about the storage available to the data server.
 *	Currently, the only storage type is ZFS, but there may be others
 *	in the future.
 */
union ds_storinfo switch (storage_type type) {
case ZFS:
	ds_zfsinfo zfs_info;
default:
	void;
};

enum ds_attr_version {
	DS_ATTR_v1 = 1
};

/*
 * DS_REPORTAVAILargs -
 *
 * A message to the MDS from a DS to provide availability
 * information for storage pools and network interfaces.
 *
 *    ds_id:
 *
 *    The short-hand idenifier assigned by the MDS and returned 
 *    in the DS_EXIBI reply.
 *
 *    ds_addrs:
 *
 *    An array of DS_addr associated with DS and information
 *    about the intended use of each address; Specified as
 *    an array since it is possible for a DS to have multiple
 *    interfaces available.
 *
 *    ds_attrvers:
 *
 *    Version indicating the set of attributes that the data server is 
 *    aware of/supports. (XXX - This may change to a supported attrs bitmask).
 *
 *    ds_storinfo:
 *
 *    Array of storage information.  For each piece of storage there will
 *    be one entry in this array.
 */
struct DS_REPORTAVAILargs {
      	ds_id             ds_id;
      	ds_verifier4      ds_verifier;
      	struct ds_addr    ds_addrs<>;
	ds_attr_version   ds_attrvers;
      	ds_storinfo       ds_storinfo<>;
};

/*
 * DS_REPORTAVAILres_ok - 
 *
 * Response from the MDS on a successful DS_REPORTAVAIL call.
 *
 * ds_attrvers:
 *
 * Version indicating the set of attributes that the metadata server is
 * aware of/supports.  (XXX - This may change to a supported attrs bitmask).
 *
 * guid_map:
 *
 * Map of data server guids to Metadata Server Pseudo Pool IDs (MDSPPIDs)
 */
struct DS_REPORTAVAILres_ok {
	ds_attr_version	ds_attrvers;
      	ds_guid_map 	guid_map<>;
};

union DS_REPORTAVAILres switch (ds_status status) {
case DS_OK:
      	DS_REPORTAVAILres_ok r;
default:
      	void;
};

/*
 * DS_RENEW -
 *
 * A message from the DS to MDS used to exchnage
 * boot instences. This can be used to indicate to 
 * the MDS when a data server has rebooted, and
 * also to the data-server when the MDS has rebooted.
 *
 * The data-server should drop all state when it
 * detects this condition.
 *
 * The MDS should drop any state that it beleives
 * the data-server is holding.
 *
 */
struct DS_RENEWargs {
      	ds_id        ds_id;
      	ds_verifier4 ds_boottime;
};

union DS_RENEWres switch (ds_status status) {
case DS_OK:
      	ds_verifier4 mds_boottime;
default:
      	void;
};

/*
 * DS_MAP_FSID
 *
 * For a given FSID at the MDS return the root path.
 *
 */
struct DS_MAP_FSIDargs {
      	fsid4 dmfa_fsid;
};

struct DS_MAP_FSIDres {
      	ds_status   dmfr_status;
      	utf8string  dmfr_pathname;
};

/*
 * DS_SECINFO -
 *
 * A message from the DS to MDS used to inquire
 * for the secrity flavors of an object.
 *
 */
struct DS_SECINFOargs {
      	nfs_fh4 	object;
      	netaddr4        cl_addr;
};

union ds_secinfo switch (uint32_t flavor) {
case RPCSEC_GSS:
	rpcsec_gss_info	flavor_info;
default:
	void;
};

typedef ds_secinfo DS_SECINFOresok<>;

union DS_SECINFOres switch (ds_status status) {
case DS_OK:
	DS_SECINFOresok rok;
default:
	void;
};

/*
 * DS_FMATPT -
 *
 * A control protocol message that is used to transport FMA
 * telemetry data to MDS.
 *
 * This is a placeholder for a post pNFS/Basic putback.
 */
struct DS_FMATPTargs {
      	opaque      fma_msg<>;
};


struct DS_FMATPTres {
      	ds_status status;
};

/*
 * DS-SHUTDOWN -
 *
 * A notification to the MDS that this Data Server has/is in
 * the process of a graceful shutdown.
 *
 */
struct DS_SHUTDOWNargs {
      	ds_id        ds_id;
};


struct DS_SHUTDOWNres {
      	ds_status status;
};

program PNFSCTLDS {
	version PNFSCTLDS_V1 {
		void
		    DSPROC_NULL(void) = 0;

		DS_EXIBIres
		    DS_EXIBI(DS_EXIBIargs) = 1;

		DS_CHECKSTATEres
		    DS_CHECKSTATE(DS_CHECKSTATEargs) = 2;

		DS_RENEWres
		    DS_RENEW(DS_RENEWargs) = 3;

		DS_REPORTAVAILres
		    DS_REPORTAVAIL(DS_REPORTAVAILargs) = 4;

		DS_MAP_FSIDres
		    DS_MAP_FSID(DS_MAP_FSIDargs) = 5;

		DS_SECINFOres
		    DS_SECINFO(DS_SECINFOargs) = 6;

		DS_FMATPTres
		    DS_FMATPT(DS_FMATPTargs) = 7;

		DS_SHUTDOWNres
		    DS_SHUTDOWN(DS_SHUTDOWNargs) = 8;
	} = 1;
} = 104001;


/*
 * NFS MDS Control Protocol:
 *
 * Traffic flows from the MDS to the data-server
 */

struct ds_filesegbuf {
      	offset4	offset;
      	opaque	data<>;
};

struct ds_fileseg {
      	offset4 offset;
      	count4	count;
};


/*
 * DS_COMMIT:
 *
 * Commit a range written to a data-server.
 *
 */
struct DS_COMMITargs {
      	nfs_fh4		fh;
      	count4		count;
      	ds_fileseg	cmv<>;
};

struct DS_COMMITresok {
      	ds_verifier4	writeverf;
      	count4		count<>;
};

union DS_COMMITres switch (ds_status status) {
case DS_OK:
      	DS_COMMITresok dresok;
default:
      	void;
};

/*
 * DS_READ:
 *
 * Read a range of bytes from a data-server
 */
struct DS_READargs {
      	nfs_fh4		fh;
      	count4		count;
      	ds_fileseg	rdv<>;
};

struct DS_READresok {
      	bool	eof;
      	count4	count;
      	ds_filesegbuf rdv<>;
};

union DS_READres switch (ds_status status) {
case DS_OK:
      	DS_READresok dresok;
default:
      	void;
};


/*
 * DS_REMOVE:
 *
 * Remove object(s) or entire fsid at the data-server
 *
 */
enum ds_rm_type {
      	DS_OBJ,
      	DS_FSID
};

union DS_REMOVEargs switch (ds_rm_type type) {
case DS_OBJ:
      	nfs_fh4		obj<>;
case DS_FSID:
      	fsid4    	fsid<>;
default:
      	void;
};

struct DS_REMOVEres {
      	ds_status	status;
};

/*
 * DS_WRITE:
 *
 * Write a range of bytes to a data-server
 *
 */
struct DS_WRITEargs {
      	nfs_fh4		fh;
      	stable_how4	stable;
      	count4		count;
      	ds_filesegbuf	wrv<>;
};

struct DS_WRITEresok {
      	stable_how4	committed;
      	ds_verifier4	writeverf;
      	count4		wrv<>;
};

union DS_WRITEres switch (ds_status status) {
case DS_OK:
      	DS_WRITEresok dresok;
default:
      	void;
};

/*
 * DS_INVALIDATE:
 *
 * Invalidate state at the data-server.
 *
 * The scope of invalidation is dependent on object type.
 *
 *   type:
 *
 *   represents the type (and by virtue scope) of state
 invalidation
 *   that should occur at the DS.
 *
 *
 */
enum ds_invalidate_type {
      	DS_INVALIDATE_ALL,
      	DS_INVALIDATE_LAYOUT,
      	DS_INVALIDATE_FSID,
      	DS_INVALIDATE_POOLID,
      	DS_INVALIDATE_CLIENTID,
      	DS_INVALIDATE_STATEID
};

struct ds_inval_stateid {
      	stateid4 stateid;
      	nfs_fh4 fh;
};

struct ds_inval_layout {
      	clientid4 mds_clid;
      	nfs_fh4 fh;
};

union DS_INVALIDATEargs switch (ds_invalidate_type obj) {

case DS_INVALIDATE_LAYOUT:
      	ds_inval_layout ilo;

case DS_INVALIDATE_POOLID:
      	uint64_t    mds_ppid;

case DS_INVALIDATE_FSID:
      	fsid4    fsid;

case DS_INVALIDATE_STATEID:
      	ds_inval_stateid isid;

case DS_INVALIDATE_CLIENTID:
      	clientid4  clid;

case DS_INVALIDATE_ALL:
      	void;
};

struct DS_INVALIDATEres {
      	ds_status status;
};


/*
 * DS_GETATTR:
 *
 * Query data-server for attributes for the specified object.
 *
 *    fh:
 *
 *    The file handle for the object for which the DS
 *    is to give attributes for.
 *
 *    dattr:
 *
 *    Bitmap of attributes. 
 */
struct DS_GETATTRargs {
      	nfs_fh4 fh;
      	ds_attr dattrs;
};

union DS_GETATTRres switch (ds_status status) {
case DS_OK:
      	ds_attr dattrs;
default:
      	void;
};

/*
 * DS_SETATTR:
 *
 * Set/Store attributes for the specified object
 * at the data-server
 *
 *    fh:
 *
 *    The file handle for the object for which the DS
 *    is to set attributes for.
 *
 *    dattrs:
 *
 *    Bitmap of attributes.
 */
struct DS_SETATTRargs {
      	nfs_fh4 fh;
      	ds_attr dattrs;
};

struct DS_SETATTRres {
      	ds_status status;
};


/*
 * DS_STAT:
 *
 * Collect statistics for the status of an object,
 * like size etc..
 *
 */
struct DS_STATargs {
      	nfs_fh4 object;
};


union DS_STATres switch (ds_status status) {
case DS_OK:
      	ds_attr  dattr;
default:
      	void;
};

/*
 * DS_LIST:
 *
 * Get a list of objects from the data-server matching provided
 * criteria. (either mds_fsid or mds_ppid)
 */
enum ds_list_type {
      	DS_LIST_MDS_PPID,
      	DS_LIST_MDS_FSID
};

struct ds_list_ppid_arg {
      	uint64_t mds_ppid;
      	uint64_t cookie;
      	count4   maxcount;
};

struct ds_list_fsid_arg {
      	fsid4 ds_fsid;
      	uint64_t cookie;
      	count4 maxcount;
};

struct DS_LISTresok {
      	ds_fh_v1        dlr_fh_list<>;
      	uint64_t        cookie;
};


union DS_LISTres switch (ds_status dlr_status) {
case DS_OK:
	DS_LISTresok	dlr_ok;
default:
	void;
};

union DS_LISTargs switch (ds_list_type dla_type) {
case DS_LIST_MDS_PPID:
	ds_list_ppid_arg dla_ppid;

case DS_LIST_MDS_FSID:
	ds_list_fsid_arg dla_fsid;

default:
      	void;
};

/*
 * DS_SNAP
 *
 * For a given FSID at the MDS snapshot the data-set.
 *
 */
struct DS_SNAPargs {
      	fsid4 dssa_fsid;
};

struct DS_SNAPres {
      	ds_status   dssr_status;
      	utf8string  dssr_name;
};

/*
 * DS_PNFSSTAT
 *
 * Return the kstat counters.
 *
 */

/* RPC kstats */
const DS_NFSSTAT_RPC     = 0x000000001;

/* NFS kstats */
const DS_NFSSTAT_NFS     = 0x000000002;

/* the DMOV protocol kstats */
const DS_NFSSTAT_DMOV    = 0x000000004;

/* the control protocol kstats */
const DS_NFSSTAT_CP      = 0x000000008;

/* CPU kstat (all stats for module cpu)*/
const DS_NFSSTAT_CPU     = 0x000000010;

/*
 * More anticipated ...
 */
struct DS_PNFSSTATargs {
      	uint64_t dpsa_stat_wanted;
};


struct DS_PNFSSTATres {
      	ds_status   dpsr_status;
      	opaque      dpsr_nvlist<>;
};

program PNFSCTLMDS {
	version PNFSCTLMDS_V1 {

		void
		    DSPROC_NULL(void) = 0;

		DS_COMMITres
		    DS_COMMIT(DS_COMMITargs) = 1;

		DS_GETATTRres
		    DS_GETATTR(DS_GETATTRargs) = 2;

		DS_SETATTRres
		    DS_SETATTR(DS_SETATTRargs) = 3;

		DS_READres
		    DS_READ(DS_READargs) = 4;

		DS_REMOVEres
		    DS_REMOVE(DS_REMOVEargs) = 5;

		DS_WRITEres
		    DS_WRITE(DS_WRITEargs) = 6;

		DS_INVALIDATEres
		    DS_INVALIDATE(DS_INVALIDATEargs) = 7;

		DS_LISTres
		    DS_LIST(DS_LISTargs) = 8;

		DS_STATres
		    DS_STAT(DS_STATargs) = 9;

		DS_SNAPres
		    DS_SNAP(DS_SNAPargs) = 10;

		DS_PNFSSTATres
		    DS_PNFSSTAT(DS_PNFSSTATargs) = 11;
	} = 1;
} = 104000;


/*
 * MOVE !
 */
struct DS_OBJ_MOVEargs {
      	uint64_t taskid;
      	nfs_fh4 source;
      	nfs_fh4 target;
      	struct netaddr4 targetserver;
};

struct DS_OBJ_MOVEres {
      	uint32_t status;
};

struct DS_OBJ_MOVE_STATUSargs {
      	uint64_t taskid;
};

struct DS_OBJ_MOVE_STATUSres {
      	uint64_t maxoffset;
      	bool complete;
      	uint32_t status;
};

struct DS_OBJ_MOVE_ABORTargs {
      	uint64_t taskid;
};

struct DS_OBJ_MOVE_ABORTres {
      	uint32_t status;
};


program PNFSCTLMV {
	version PNFSCTLMV_V1 {
		void
		    DSPROC_NULL(void) = 0;

		DS_OBJ_MOVEres
		    DS_OBJ_MOVE(DS_OBJ_MOVEargs) = 1;

		DS_OBJ_MOVE_ABORTres
		    DS_OBJ_MOVE_ABORT(DS_OBJ_MOVE_ABORTargs) = 2;

		DS_OBJ_MOVE_STATUSres
		    DS_OBJ_MOVE_STATUS(DS_OBJ_MOVE_STATUSargs) = 3;
	} = 1;
} = 104002;
