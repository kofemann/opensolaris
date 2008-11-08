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

#include <ctype.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/tiuser.h>
#include <setjmp.h>
#include <netdb.h>
#include <sys/socket.h>
#include <errno.h>

#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/auth.h>
#include <rpc/clnt.h>
#include <rpc/rpc_msg.h>
#include "snoop.h"

#include <sys/stat.h>
#include <sys/param.h>

/*
 * We generate ds_nfs_com.h with -DUSE_FOR_SNOOP defined to
 * get the parts of the protocol which are already defined in
 * either the base NFSv4 or extended NFSv41 protocols.
 *
 * It will grab the definitions for us and the implementations
 * are over in ./nfs4_xdr.c.
 */
#include "ds_nfs_com.h"
#include "ds_prot.h"

/*
 * Yuck, but with the way things are implemented, this works!.
 * And it needs to be before the "nfs4_cmn.h"
 */
typedef ds_secinfo secinfo4;

#include "nfs4_cmn.h"

extern XDR xdrm;

extern char *get_sum_line();
extern jmp_buf xdr_err;

typedef struct {
	char *short_name;		/* for summary output */
	char *long_name;		/* for detail output */
} type_names_t;

typedef struct {
	char	*short_name;
	char	*long_name;
	void	(*args)(char *, bool_t);
	void	(*res)(char *, bool_t);
} op_info_t;

static void ds_checkstate_args(char *, bool_t);
static void ds_checkstate_res(char *, bool_t);
static void ds_exibi_args(char *, bool_t);
static void ds_exibi_res(char *, bool_t);
static void ds_fmatpt_args(char *, bool_t);
static void ds_fmatpt_res(char *, bool_t);
static void ds_map_mds_dataset_id_args(char *, bool_t);
static void ds_map_mds_dataset_id_res(char *, bool_t);
static void ds_map_mdssid_args(char *, bool_t);
static void ds_map_mdssid_res(char *, bool_t);
static void ds_renew_args(char *, bool_t);
static void ds_renew_res(char *, bool_t);
static void ds_reportavail_args(char *, bool_t);
static void ds_reportavail_res(char *, bool_t);
static void ds_secinfo_args(char *, bool_t);
static void ds_secinfo_res(char *, bool_t);
static void ds_shutdown_args(char *, bool_t);
static void ds_shutdown_res(char *, bool_t);

/*
 * PNFSCTLDS -- 104001
 */
static op_info_t pnfsctlds_ops[] = {
	{"DS_NULL", "Null procedure", NULL, NULL},
	{"DS_CHECKSTATE", "Verify the presented file state",
	    ds_checkstate_args, ds_checkstate_res},
	{"DS_EXIBI", "Exchange Identity and Boot Instance",
	    ds_exibi_args, ds_exibi_res},
	{"DS_FMATPT", "Placeholder for post pNFS/Basic putback",
	    ds_fmatpt_args, ds_fmatpt_res},
	{"DS_MAP_MDS_DATASET_ID", "Return the root path",
	    ds_map_mds_dataset_id_args, ds_map_mds_dataset_id_res},
	{"DS_MAP_MDSSID", "Map the given MDS Storage ID",
	    ds_map_mdssid_args, ds_map_mdssid_res},
	{"DS_RENEW", "Force an exchange of boot instances",
	    ds_renew_args, ds_renew_res},
	{"DS_REPORTAVAIL", "Provide availability information for"
	    " storage pools and network interfaces",
	    ds_reportavail_args, ds_reportavail_res},
	{"DS_SECINFO", "Inquire about security flavors of an object",
	    ds_secinfo_args, ds_secinfo_res},
	{"DS_SHUTDOWN", "Data Server is in a graceful shutdown",
	    ds_shutdown_args, ds_shutdown_res}
};
static uint_t num_pnfsctlds_ops = sizeof (pnfsctlds_ops) / sizeof (op_info_t);

/*
 * PNFSCTLMDS -- 104000
 */
static void mds_commit_args(char *, bool_t);
static void mds_commit_res(char *, bool_t);
static void mds_getattr_args(char *, bool_t);
static void mds_getattr_res(char *, bool_t);
static void mds_invalidate_args(char *, bool_t);
static void mds_invalidate_res(char *, bool_t);
static void mds_list_args(char *, bool_t);
static void mds_list_res(char *, bool_t);
static void mds_obj_move_args(char *, bool_t);
static void mds_obj_move_res(char *, bool_t);
static void mds_obj_move_abort_args(char *, bool_t);
static void mds_obj_move_abort_res(char *, bool_t);
static void mds_obj_move_status_args(char *, bool_t);
static void mds_obj_move_status_res(char *, bool_t);
static void mds_pnfsstat_args(char *, bool_t);
static void mds_pnfsstat_res(char *, bool_t);
static void mds_read_args(char *, bool_t);
static void mds_read_res(char *, bool_t);
static void mds_remove_args(char *, bool_t);
static void mds_remove_res(char *, bool_t);
static void mds_setattr_args(char *, bool_t);
static void mds_setattr_res(char *, bool_t);
static void mds_stat_args(char *, bool_t);
static void mds_stat_res(char *, bool_t);
static void mds_snap_args(char *, bool_t);
static void mds_snap_res(char *, bool_t);
static void mds_write_args(char *, bool_t);
static void mds_write_res(char *, bool_t);

static op_info_t pnfsctlmds_ops[] = {
	{"MDS_NULL", "Null procedure", NULL, NULL},
	{"MDS_COMMIT", "Commit a range written to a DS",
	    mds_commit_args, mds_commit_res},
	{"MDS_GETATTR", "Query DS for attributes for the specified object",
	    mds_getattr_args, mds_getattr_res},
	{"MDS_INVALIDATE", "Invalidate state at the DS",
	    mds_invalidate_args, mds_invalidate_res},
	{"MDS_LIST", "Get a list of objects from the DS",
	    mds_list_args, mds_list_res},
	{"MDS_OBJ_MOVE", "Data movement initiation",
	    mds_obj_move_args, mds_obj_move_res},
	{"MDS_OBJ_MOVE_ABORT", "Stop data movement",
	    mds_obj_move_abort_args, mds_obj_move_abort_res},
	{"MDS_OBJ_MOVE_STATUS", "Query data movement status",
	    mds_obj_move_status_args, mds_obj_move_status_res},
	{"MDS_PNNFSTAT", "Return the kstat counters",
	    mds_pnfsstat_args, mds_pnfsstat_res},
	{"MDS_READ", "Read a range of bytes from a DS",
	    mds_read_args, mds_read_res},
	{"MDS_REMOVE", "Remove object(s) or entire fsid at the DS",
	    mds_remove_args, mds_remove_res},
	{"MDS_SETATTR", "Set/Store attributes for the specified"
	    " object at the DS",
	    mds_setattr_args, mds_setattr_res},
	{"MDS_STAT", "Collect statistics for the status of an object",
	    mds_stat_args, mds_stat_res},
	{"MDS_SNAP", "For a given MDS Dataset ID at the MDS, snapshot"
	    " the data-set",
	    mds_snap_args, mds_snap_res},
	{"MDS_WRITE", "Write a range of bytes to a DS",
	    mds_write_args, mds_write_res}
};
static uint_t num_pnfsctlmds_ops = sizeof (pnfsctlmds_ops) / sizeof (op_info_t);

/*
 * PNFSCTLMV -- 104002
 */
static void ds_move_args(char *, bool_t);
static void ds_move_res(char *, bool_t);

static op_info_t pnfsctlmv_ops[] = {
	{"DS_DS_NULL", "Null procedure", NULL, NULL},
	{"MDS_DS_MOVE", "DS to DS data movement",
	    ds_move_args, ds_move_res},
};
static uint_t num_pnfsctlmv_ops = sizeof (pnfsctlmv_ops) / sizeof (op_info_t);

/*
 * Status types.
 */
static type_names_t ds_status_types[] = {
	{"DS_OK", "OK "},
	{"DSERR_ACCESS", "Permission denied"},
	{"DSERR_ATTR_NOTSUPP", "Attribute not supported"},
	{"DSERR_BAD_COOKIE", "Bad cookie"},
	{"DSERR_BAD_FH", "Bad file handle"},
	{"DSERR_BAD_MDSSID", "Bad MDS sid"},
	{"DSERR_BAD_STATEID", "Bad stateid"},
	{"DSERR_EXPIRED", "Expired"},
	{"DSERR_FHEXPIRED", "File handled expired"},
	{"DSERR_GRACE", "Grace"},
	{"DSERR_INVAL", "Invalid"},
	{"DSERR_NOENT", "No such entry"},
	{"DSERR_NOT_AUTH", "Not authorized"},
	{"DSERR_NOSPC", "No space left on device"},
	{"DSERR_NOTSUPP", "Not supported"},
	{"DSERR_OLD_STATEID", "Old stateid"},
	{"DSERR_PNFS_NO_LAYOUT", "No layout"},
	{"DSERR_RESOURCE", "Resource error"},
	{"DSERR_SERVERFAULT", "General server fault"},
	{"DSERR_STALE", "Stale pNFS file handle"},
	{"DSERR_STALE_CLIENTID", "Stale clientid"},
	{"DSERR_STALE_DSID", "Stale DSid"},
	{"DSERR_STALE_STATEID", "Stale stateid"},
	{"DSERR_TOOSMALL", "Too small"},
	{"DSERR_WRONGSEC", "Wrong security flavor"},
	{"DSERR_XDR", "XDR error"},
	{"DSERR_ILLEGAL", "Illegal"}
};
static uint_t num_status_types =
    sizeof (ds_status_types) / sizeof (type_names_t);

typedef struct {
	op_info_t	*ops;
	char		*name;
	uint_t		count;
} ds_program_t;

static char *storage_types_map[] = {
	"(unknown)",
	"ZFS"
};

static void
detail_client_owner(client_owner4 *cow)
{
	sprintf(get_line(0, 0), "Client Owner hash = [%04X] ",
	    cowner_hash(&cow->co_ownerid));
	sprintf(get_line(0, 0), "    len = %u   val = %s ",
	    cow->co_ownerid.co_ownerid_len,
	    tohex(cow->co_ownerid.co_ownerid_val,
	    cow->co_ownerid.co_ownerid_len));
	sprintf(get_line(0, 0), "    verifier = %llu",
	    cow->co_verifier);
}


/*
 * The state engine will pass in a valid line buffer for all
 * summary actions. It will pass in a NULL pointer for all
 * detailed actions. Therefore, if line is NULL, we know
 * to get a new line for a detailed action.
 */
static void
print_status(char *line, ds_status status)
{
	if (line == NULL)
		line = get_line(0, 0);

	if (status < 0 || status >= num_status_types)
		strcpy(line, "(unknown error)");
	else
		strcpy(line, ds_status_types[status].long_name);
}

/*ARGSUSED*/
static void
interpret_pnfsctl(ds_program_t *dsp, int flags, int type, int xid,
    int vers, int proc, char *data, int len)
{
	char *line = NULL;
	char *line2 = NULL;

	if (proc < 0 || proc >= dsp->count)
		return;

	if (flags & F_SUM) {
		line2 = line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "%s C %s",
			    dsp->name, dsp->ops[proc].short_name);
			line += strlen(line);
			if (dsp->ops[proc].args)
				dsp->ops[proc].args(line, TRUE);
			line += strlen(line);
			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "%s R %s ",
			    dsp->name, dsp->ops[proc].short_name);
			line += strlen(line);
			if (dsp->ops[proc].res) {
				dsp->ops[proc].res(line, TRUE);
			}
		}
	}

	if (flags & F_DTAIL) {
		char buf1[20], buf2[20];
		(void) sprintf(buf1, "%s:  ", dsp->name);
		(void) sprintf(buf2, "Sun %s", dsp->name);
		show_header(buf1, buf2, len);
		show_space();
		(void) sprintf(get_line(0, 0), "Proc = %d (%s)",
		    proc, dsp->ops[proc].long_name);
		if (type == CALL) {
			if (dsp->ops[proc].args)
				dsp->ops[proc].args(NULL, FALSE);
		} else {
			if (dsp->ops[proc].res)
				dsp->ops[proc].res(NULL, FALSE);
		}
		show_trailer();
	}

	utf8free();
}

/*ARGSUSED*/
void
interpret_pnfsctlmv(int flags, int type, int xid, int vers, int proc,
    char *data, int len)
{
	ds_program_t	sp;

	sp.ops = pnfsctlmv_ops;
	sp.count = num_pnfsctlmv_ops;
	sp.name = "CTL-MV";

	interpret_pnfsctl(&sp, flags, type, xid, vers, proc, data, len);
}

/*ARGSUSED*/
void
interpret_pnfsctlds(int flags, int type, int xid, int vers, int proc,
    char *data, int len)
{
	ds_program_t	sp;

	sp.ops = pnfsctlds_ops;
	sp.count = num_pnfsctlds_ops;
	sp.name = "CTL-DS";

	interpret_pnfsctl(&sp, flags, type, xid, vers, proc, data, len);
}

/*ARGSUSED*/
void
interpret_pnfsctlmds(int flags, int type, int xid, int vers, int proc,
    char *data, int len)
{
	ds_program_t	sp;

	sp.ops = pnfsctlmds_ops;
	sp.count = num_pnfsctlmds_ops;
	sp.name = "CTL-MDS";

	interpret_pnfsctl(&sp, flags, type, xid, vers, proc, data, len);
}

/*
 * Helper functions
 */

static void
detail_mds_sid(mds_sid *ms, int index, char *indent)
{
	char	buf[20];

	if (index != -1) {
		sprintf(buf, "[%d]", index);
	} else {
		buf[0] = '\0';
	}

	sprintf(get_line(0, 0), "%s    mds_sid%s", indent, buf);
	sprintf(get_line(0, 0), "%s        %s", indent,
	    tohex(ms->mds_sid_val, ms->mds_sid_len));
}

static bool_t
detail_ds_guid_map(uint_t len, ds_guid_map *dg, char *legend, char *indent)
{
	XDR		zxdr;
	ds_zfsguid	zfsguid;
	char		*p;
	int		i;
	int		j;

	for (i = 0; i < len; i++) {
		sprintf(get_line(0, 0), "%s%s[%d]", indent, legend, i);

		/*
		 * Whenever we get more, we'll have to check this better!
		 */
		if (dg[i].ds_guid.stor_type != ZFS)
			p = storage_types_map[0];
		else
			p = storage_types_map[dg[i].ds_guid.stor_type];

		sprintf(get_line(0, 0), "%s    storage type = %s", indent, p);
		xdrmem_create(&zxdr,
		    dg[i].ds_guid.ds_guid_u.zfsguid.zfsguid_val,
		    dg[i].ds_guid.ds_guid_u.zfsguid.zfsguid_len,
		    XDR_DECODE);
		memset(&zfsguid, '\0', sizeof (zfsguid));
		if (!xdr_ds_zfsguid(&zxdr, &zfsguid))
			return (FALSE);

		sprintf(get_line(0, 0), "%s    zpool guid = %llu",
		    indent, zfsguid.zpool_guid);
		sprintf(get_line(0, 0), "%s    dataset guid = %llu",
		    indent, zfsguid.dataset_guid);

		xdr_free(xdr_ds_zfsguid, (char *)&zfsguid);

		for (j = 0; j < dg[i].mds_sid_array.mds_sid_array_len; j++) {
			detail_mds_sid(&dg[i].mds_sid_array.mds_sid_array_val[j],
			    j, indent);
		}
	}

	return (TRUE);
}

static void
detail_netaddr4(netaddr4 *addr)
{
	sprintf(get_line(0, 0), "    netaddr = %s/%s",
	    addr->na_r_addr, addr->na_r_netid);
}

static void
detail_layout_array(layout4 *alo, int len)
{
	int	i;

	for (i = 0; i < len; i++) {
		sprintf(get_line(0, 0), "Layout [%u]:", i);
		sprintf(get_line(0, 0), "    Layout offset = %llu",
		    alo[i].lo_offset);
		sprintf(get_line(0, 0), "    Layout length = %llu",
		    alo[i].lo_length);
		sprintf(get_line(0, 0), "    Layout iomode = %s",
		    detail_iomode_name(alo[i].lo_iomode));
		sprintf(get_line(0, 0), "    Layout type = %s",
		    detail_lotype_name(alo[i].lo_content.loc_type));
		if (alo[i].lo_content.loc_type == LAYOUT4_NFSV4_1_FILES) {
			detail_file_layout(&alo[i]);
		} else {
			sprintf(get_line(0, 0), "Non-file layout = %s",
			    tohex(alo[i].lo_content.loc_body.loc_body_val,
			    alo[i].lo_content.loc_body.loc_body_len));
		}
	}
}

/*
 * State functions
 */

static void
ds_checkstate_args(char *line, bool_t summary)
{
	DS_CHECKSTATEargs	args;
	client_owner4		*cow;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_CHECKSTATEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	cow = &args.co_owner;
	if (summary) {
		sprintf(line, " %s %s H=[%04X]",
		    sum_stateid(&args.stateid),
		    sum_fh4(&args.fh),
		    cowner_hash(&cow->co_ownerid));
	} else {
		detail_stateid(&args.stateid);
		detail_fh4(&args.fh, "");
		detail_client_owner(cow);
	}

	xdr_free(xdr_DS_CHECKSTATEargs, (char *)&args);
}

static void
ds_checkstate_res(char *line, bool_t summary)
{
	DS_CHECKSTATEres	res;
	ds_filestate		*df;

	int	i;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_CHECKSTATEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		return;
	}

	df = &res.DS_CHECKSTATEres_u.file_state;

	if (summary) {
		sprintf(line, " %s L=%d M=0%03o",
		    sum_clientid(df->mds_clid),
		    df->layout.layout_len,
		    df->open_mode);
	} else {
		detail_clientid(df->mds_clid);
		sprintf(get_line(0, 0), "Mode = 0%03o", df->open_mode);
		detail_layout_array(df->layout.layout_val,
		    df->layout.layout_len);
	}

	xdr_free(xdr_DS_CHECKSTATEres, (char *)&res);
}

static void
ds_exibi_args(char *line, bool_t summary)
{
	DS_EXIBIargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_EXIBIargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
		sprintf(get_line(0, 0), "Identity verifier = %llu",
		    args.ds_ident.boot_verifier);
		sprintf(get_line(0, 0), "Identity instance = %s",
		    utf8localize((utf8string *)&args.ds_ident.instance));
	}

	xdr_free(xdr_DS_EXIBIargs, (char *)&args);
}

static void
ds_exibi_res(char *line, bool_t summary)
{
	DS_EXIBIres	res;
	DS_EXIBIresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_EXIBIres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		return;
	}

	res_ok = &res.DS_EXIBIres_u.res_ok;

	if (summary) {
		sprintf(line, " DI=%llu LP=%hu",
		    res_ok->ds_id,
		    res_ok->mds_lease_period);
	} else {
		sprintf(get_line(0, 0), "DS id = %llu", res_ok->ds_id);
		sprintf(get_line(0, 0), "MDS id = %llu", res_ok->mds_id);
		sprintf(get_line(0, 0), "MDS boot verifier = %llu",
		    res_ok->mds_boot_verifier);
		sprintf(get_line(0, 0), "MDS boot lease = %hu",
		    res_ok->mds_lease_period);
	}

	xdr_free(xdr_DS_EXIBIres, (char *)&res);
}

static void
ds_fmatpt_args(char *line, bool_t summary)
{
	DS_FMATPTargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_FMATPTargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
		sprintf(get_line(0, 0), "FMA event = %s",
		    utf8localize((utf8string *)&args.fma_msg));
	}

	xdr_free(xdr_DS_FMATPTargs, (char *)&args);
}

static void
ds_fmatpt_res(char *line, bool_t summary)
{
	DS_FMATPTres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_FMATPTres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_FMATPTres, (char *)&res);
		return;
	}

	xdr_free(xdr_DS_FMATPTres, (char *)&res);
}

static void
ds_map_mds_dataset_id_args(char *line, bool_t summary)
{
	DS_MAP_MDS_DATASET_IDargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_MAP_MDS_DATASET_IDargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " MDI=%llu",
		    args.mds_dataset_id);
	} else {
		sprintf(get_line(0, 0), "MDS datset id = %llu",
		    args.mds_dataset_id);
	}

	xdr_free(xdr_DS_MAP_MDS_DATASET_IDargs, (char *)&args);
}

static void
ds_map_mds_dataset_id_res(char *line, bool_t summary)
{
	DS_MAP_MDS_DATASET_IDres	res;
	DS_MAP_MDS_DATASET_IDresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_MAP_MDS_DATASET_IDres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_MAP_MDS_DATASET_IDres, (char *)&res);
		return;
	}

	res_ok = &res.DS_MAP_MDS_DATASET_IDres_u.res_ok;

	if (summary) {
		sprintf(line, " P=(%.20s)",
		    utf8localize((utf8string *)&res_ok->pathname));
	} else {
		sprintf(get_line(0, 0), "Pathname = %s",
		    utf8localize((utf8string *)&res_ok->pathname));
	}

	xdr_free(xdr_DS_MAP_MDS_DATASET_IDres, (char *)&res);
}

static void
ds_map_mdssid_args(char *line, bool_t summary)
{
	DS_MAP_MDSSIDargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_MAP_MDSSIDargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
		detail_mds_sid(&args.mma_sid, -1, "");
	}

	xdr_free(xdr_DS_MAP_MDSSIDargs, (char *)&args);
}

static void
ds_map_mdssid_res(char *line, bool_t summary)
{
	DS_MAP_MDSSIDres	res;
	DS_MAP_MDSSIDresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_MAP_MDSSIDres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_MAP_MDSSIDres, (char *)&res);
		return;
	}

	res_ok = &res.DS_MAP_MDSSIDres_u.res_ok;

	if (summary) {
	} else {
		if (!detail_ds_guid_map(1, &res_ok->guid_map, "Guid", "")) {
			xdr_free(xdr_DS_MAP_MDSSIDres, (char *)&res);
			longjmp(xdr_err, 1);
		}

	}

	xdr_free(xdr_DS_MAP_MDSSIDres, (char *)&res);
}

static void
ds_renew_args(char *line, bool_t summary)
{
	DS_RENEWargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_RENEWargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " DI=%llu",
		    args.ds_id);
	} else {
		sprintf(get_line(0, 0), "DS id = %llu", args.ds_id);
		sprintf(get_line(0, 0),
		    "DS Bootime verifier = %llu", args.ds_boottime);
	}

	xdr_free(xdr_DS_RENEWargs, (char *)&args);
}

static void
ds_renew_res(char *line, bool_t summary)
{
	DS_RENEWres	res;
	ds_verifier	*vrfy;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_RENEWres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_RENEWres, (char *)&res);
		return;
	}

	vrfy = &res.DS_RENEWres_u.mds_boottime;

	if (summary) {
	} else {
		sprintf(get_line(0, 0),
		    "MDS Bootime verifier = %llu", vrfy);
	}

	xdr_free(xdr_DS_RENEWres, (char *)&res);
}

static void
ds_reportavail_args_dtl(DS_REPORTAVAILargs *args)
{
	int		i;
	char		*p;

	sprintf(get_line(0, 0), "DS id = %llu", args->ds_id);
	sprintf(get_line(0, 0), "Verifier = %llu", args->ds_verifier);
	sprintf(get_line(0, 0), "Attribute Version = %u", args->ds_attrvers);

	for (i = 0; i < args->ds_addrs.ds_addrs_len; i++) {
		sprintf(get_line(0, 0), "Addr[%d]", i);
		sprintf(get_line(0, 0), "    validuse = %x",
		    args->ds_addrs.ds_addrs_val[i].validuse);
		detail_netaddr4(&args->ds_addrs.ds_addrs_val[i].addr);
	}

	for (i = 0; i < args->ds_storinfo.ds_storinfo_len; i++) {
		ds_zfsinfo	*dz;
		int		j;

		sprintf(get_line(0, 0), "Storage Info[%d]", i);

		/*
		 * Whenever we get more, we'll have to check this better!
		 */
		if (args->ds_storinfo.ds_storinfo_val[i].type != ZFS)
			p = storage_types_map[0];
		else
			p = storage_types_map[args->ds_storinfo.
			    ds_storinfo_val[i].type];

		sprintf(get_line(0, 0), "    Storage Type = %s", p);

		dz = &args->ds_storinfo.ds_storinfo_val[i].ds_storinfo_u.
		    zfs_info;
		if (!detail_ds_guid_map(1, &dz->guid_map, "Guid", "    ")) {
			xdr_free(xdr_DS_REPORTAVAILargs, (char *)args);
			longjmp(xdr_err, 1);
		}

		/*
		 * Note that this nvpair may change to a bitmap!
		 */
		for (j = 0; j < dz->attrs.attrs_len; j++) {
			sprintf(get_line(0, 0), "    Attribute[%d] = ",
			    j, utf8localize((utf8string *)
			    &dz->attrs.attrs_val[j].attrname));
			sprintf(get_line(0, 0), "        %s",
			    utf8localize((utf8string *)
			    &dz->attrs.attrs_val[j].attrvalue));
		}
	}
}

static void
ds_reportavail_args(char *line, bool_t summary)
{
	DS_REPORTAVAILargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_REPORTAVAILargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " DI=%llu A=%d LA=%u LS=%u",
		    args.ds_id,
		    args.ds_attrvers,
		    args.ds_addrs.ds_addrs_len,
		    args.ds_storinfo.ds_storinfo_len);
	} else {
		ds_reportavail_args_dtl(&args);
	}

	xdr_free(xdr_DS_REPORTAVAILargs, (char *)&args);
}

static void
ds_reportavail_res(char *line, bool_t summary)
{
	DS_REPORTAVAILres	res;
	DS_REPORTAVAILresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_REPORTAVAILres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_REPORTAVAILres, (char *)&res);
		return;
	}

	res_ok = &res.DS_REPORTAVAILres_u.res_ok;

	if (summary) {
		sprintf(line, " L=%hu",
		    res_ok->guid_map.guid_map_len);
	} else {
		sprintf(get_line(0, 0), "Attribute Version = %u",
		    res_ok->ds_attrvers);
		if (!detail_ds_guid_map(res_ok->guid_map.guid_map_len,
		    res_ok->guid_map.guid_map_val, "Guid", "")) {
			xdr_free(xdr_DS_REPORTAVAILres, (char *)&res);
			longjmp(xdr_err, 1);
		}
	}

	xdr_free(xdr_DS_REPORTAVAILres, (char *)&res);
}

static void
ds_secinfo_args(char *line, bool_t summary)
{
	DS_SECINFOargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_SECINFOargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " %s",
		    sum_fh4(&args.object));
	} else {
		detail_fh4(&args.object, "");
		detail_netaddr4(&args.cl_addr);
	}

	xdr_free(xdr_DS_SECINFOargs, (char *)&args);
}

static void
ds_secinfo_res(char *line, bool_t summary)
{
	DS_SECINFOres	res;
	DS_SECINFOresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_SECINFOres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_SECINFOres, (char *)&res);
		return;
	}

	res_ok = &res.DS_SECINFOres_u.res_ok;

	if (summary) {
	} else {
		int		i;
		ds_secinfo	*ds;

		for (i = 0; i < res_ok->DS_SECINFOresok_len; i++) {
			ds = &res_ok->DS_SECINFOresok_val[i];
			detail_secinfo4((secinfo4 *)ds);
		}
	}

	xdr_free(xdr_DS_SECINFOres, (char *)&res);
}

static void
ds_shutdown_args(char *line, bool_t summary)
{
	DS_SHUTDOWNargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_SHUTDOWNargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " DI=%llu",
		    args.ds_id);
	} else {
		sprintf(get_line(0, 0), "DS id = %llu", args.ds_id);
	}

	xdr_free(xdr_DS_SHUTDOWNargs, (char *)&args);
}

static void
ds_shutdown_res(char *line, bool_t summary)
{
	DS_SHUTDOWNres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_SHUTDOWNres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_SHUTDOWNres, (char *)&res);
		return;
	}

	xdr_free(xdr_DS_SHUTDOWNres, (char *)&res);
}

static void
mds_commit_args(char *line, bool_t summary)
{
	DS_COMMITargs	args;

	int	i;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_COMMITargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " %s C=%u",
		    sum_fh4(&args.fh),
		    args.cmv.cmv_len);
	} else {
		detail_fh4(&args.fh, "");

		for (i = 0; i < args.cmv.cmv_len; i++) {
			sprintf(get_line(0, 0),
			    "File Segment[%d]", i);
			sprintf(get_line(0, 0),
			    "    offset = %llu",
			    args.cmv.cmv_val[i].offset);
			sprintf(get_line(0, 0),
			    "    count = %u",
			    args.cmv.cmv_val[i].count);
		}
	}

	xdr_free(xdr_DS_COMMITargs, (char *)&args);
}

static void
mds_commit_res(char *line, bool_t summary)
{
	DS_COMMITres	res;
	DS_COMMITresok	*res_ok;

	int	i;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_COMMITres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_COMMITres, (char *)&res);
		return;
	}

	res_ok = &res.DS_COMMITres_u.res_ok;

	if (summary) {
		sprintf(line, " C=%u",
		    res_ok->count.count_len);
	} else {
		sprintf(get_line(0, 0),
		    "Write Verifier = %llu", res_ok->writeverf);
		for (i = 0; i < res_ok->count.count_len; i++) {
			sprintf(get_line(0, 0),
			    "Count[%d] = %u", i,
			    res_ok->count.count_val[i]);
		}
	}

	xdr_free(xdr_DS_COMMITres, (char *)&res);
}

static void
mds_getattr_args(char *line, bool_t summary)
{
	DS_GETATTRargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_GETATTRargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " %s",
		    sum_fh4(&args.fh));
	} else {
		detail_fh4(&args.fh, "");
	}

	xdr_free(xdr_DS_GETATTRargs, (char *)&args);
}

static void
mds_getattr_res(char *line, bool_t summary)
{
	DS_GETATTRres	res;
	ds_attr		*da;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_GETATTRres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_GETATTRres, (char *)&res);
		return;
	}

	da = &res.DS_GETATTRres_u.dattrs;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_GETATTRres, (char *)&res);
}

static void
mds_invalidate_args(char *line, bool_t summary)
{
	DS_INVALIDATEargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_INVALIDATEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_INVALIDATEargs, (char *)&args);
}

static void
mds_invalidate_res(char *line, bool_t summary)
{
	DS_INVALIDATEres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_INVALIDATEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_INVALIDATEres, (char *)&res);
		return;
	}

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_INVALIDATEres, (char *)&res);
}

static void
mds_list_args(char *line, bool_t summary)
{
	DS_LISTargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_LISTargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_LISTargs, (char *)&args);
}

static void
mds_list_res(char *line, bool_t summary)
{
	DS_LISTres	res;
	DS_LISTresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_LISTres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		return;
	}

	res_ok = &res.DS_LISTres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_LISTres, (char *)&res);
}

static void
mds_obj_move_args(char *line, bool_t summary)
{
	DS_OBJ_MOVEargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_OBJ_MOVEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		/*
		 * Not sure if sum_fh4() will be handled
		 * correctly here...
		 */
		sprintf(line, " Tid=%llu S%s",
		    args.taskid, sum_fh4(&args.source));
		line += strlen(line);

		/*
		 * So hack it up!
		 */
		sprintf(line, " T%s",
		    sum_fh4(&args.target));
	} else {
		sprintf(get_line(0, 0), "Task ID = %llu",
		    args.taskid);
		detail_fh4(&args.source, "Source ");
		detail_fh4(&args.target, "Target ");
		detail_netaddr4(&args.targetserver);
	}

	xdr_free(xdr_DS_OBJ_MOVEargs, (char *)&args);
}

static void
mds_obj_move_res(char *line, bool_t summary)
{
	DS_OBJ_MOVEres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_OBJ_MOVEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_OBJ_MOVEres, (char *)&res);
		return;
	}

	xdr_free(xdr_DS_OBJ_MOVEres, (char *)&res);
}

static void
mds_obj_move_abort_args(char *line, bool_t summary)
{
	DS_OBJ_MOVE_ABORTargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_OBJ_MOVE_ABORTargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " Tid=%llu",
		    args.taskid);
	} else {
		sprintf(get_line(0, 0), "Task ID = %llu",
		    args.taskid);
	}

	xdr_free(xdr_DS_OBJ_MOVE_ABORTargs, (char *)&args);
}

static void
mds_obj_move_abort_res(char *line, bool_t summary)
{
	DS_OBJ_MOVE_ABORTres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_OBJ_MOVE_ABORTres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_OBJ_MOVE_ABORTres, (char *)&res);
		return;
	}

	xdr_free(xdr_DS_OBJ_MOVE_ABORTres, (char *)&res);
}

static void
mds_obj_move_status_args(char *line, bool_t summary)
{
	DS_OBJ_MOVE_STATUSargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_OBJ_MOVE_STATUSargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
		sprintf(line, " Tid=%llu",
		    args.taskid);
	} else {
		sprintf(get_line(0, 0), "Task ID = %llu",
		    args.taskid);
	}

	xdr_free(xdr_DS_OBJ_MOVE_STATUSargs, (char *)&args);
}

static void
mds_obj_move_status_res(char *line, bool_t summary)
{
	DS_OBJ_MOVE_STATUSres	res;
	DS_OBJ_MOVE_STATUSresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_OBJ_MOVE_STATUSres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_OBJ_MOVE_STATUSres, (char *)&res);
		return;
	}

	res_ok = &res.DS_OBJ_MOVE_STATUSres_u.res_ok;

	if (summary) {
		sprintf(line, " Max=%llu (%s)",
		    res_ok->maxoffset,
		    res_ok->complete ? "done" :
		    "working");
	} else {
		sprintf(get_line(0, 0), "Max Offset = %llu",
		    res_ok->maxoffset);
		sprintf(get_line(0, 0), "Complete = %s",
		    res_ok->complete ? "done" :
		    "working");
	}

	xdr_free(xdr_DS_OBJ_MOVE_STATUSres, (char *)&res);
}

static void
mds_pnfsstat_args(char *line, bool_t summary)
{
	DS_PNFSSTATargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_PNFSSTATargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_PNFSSTATargs, (char *)&args);
}

static void
mds_pnfsstat_res(char *line, bool_t summary)
{
	DS_PNFSSTATres	res;
	DS_PNFSSTATresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_PNFSSTATres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_PNFSSTATres, (char *)&res);
		return;
	}

	res_ok = &res.DS_PNFSSTATres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_PNFSSTATres, (char *)&res);
}

static void
mds_read_args(char *line, bool_t summary)
{
	DS_READargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_READargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_READargs, (char *)&args);
}

static void
mds_read_res(char *line, bool_t summary)
{
	DS_READres	res;
	DS_READresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_READres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_READres, (char *)&res);
		return;
	}

	res_ok = &res.DS_READres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_READres, (char *)&res);
}

static void
mds_remove_args(char *line, bool_t summary)
{
	DS_REMOVEargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_REMOVEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_REMOVEargs, (char *)&args);
}

static void
mds_remove_res(char *line, bool_t summary)
{
	DS_REMOVEres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_REMOVEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_REMOVEres, (char *)&res);
		return;
	}

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_REMOVEres, (char *)&res);
}

static void
mds_setattr_args(char *line, bool_t summary)
{
	DS_SETATTRargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_SETATTRargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_SETATTRargs, (char *)&args);
}

static void
mds_setattr_res(char *line, bool_t summary)
{
	DS_SETATTRres	res;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_SETATTRres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_SETATTRres, (char *)&res);
		return;
	}

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_SETATTRres, (char *)&res);
}

static void
mds_stat_args(char *line, bool_t summary)
{
	DS_STATargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_STATargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_STATargs, (char *)&args);
}

static void
mds_stat_res(char *line, bool_t summary)
{
	DS_STATres	res;
	ds_attr		*da;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_STATres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_STATres, (char *)&res);
		return;
	}

	da = &res.DS_STATres_u.dattr;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_STATres, (char *)&res);
}

static void
mds_snap_args(char *line, bool_t summary)
{
	DS_SNAPargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_SNAPargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_SNAPargs, (char *)&args);
}

static void
mds_snap_res(char *line, bool_t summary)
{
	DS_SNAPres	res;
	DS_SNAPresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_SNAPres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_SNAPres, (char *)&res);
		return;
	}

	res_ok = &res.DS_SNAPres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_SNAPres, (char *)&res);
}

static void
mds_write_args(char *line, bool_t summary)
{
	DS_WRITEargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_DS_WRITEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_WRITEargs, (char *)&args);
}

static void
mds_write_res(char *line, bool_t summary)
{
	DS_WRITEres	res;
	DS_WRITEresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_DS_WRITEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_DS_WRITEres, (char *)&res);
		return;
	}

	res_ok = &res.DS_WRITEres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_DS_WRITEres, (char *)&res);
}

static void
ds_move_args(char *line, bool_t summary)
{
	MOVEargs	args;

	memset(&args, '\0', sizeof (args));
	if (!xdr_MOVEargs(&xdrm, &args))
		longjmp(xdr_err, 1);

	if (summary) {
	} else {
	}

	xdr_free(xdr_MOVEargs, (char *)&args);
}

static void
ds_move_res(char *line, bool_t summary)
{
	MOVEres	res;
	MOVEresok	*res_ok;

	memset(&res, '\0', sizeof (res));
	if (!xdr_MOVEres(&xdrm, &res))
		longjmp(xdr_err, 1);

	if (res.status != DS_OK) {
		print_status(line, res.status);
		xdr_free(xdr_MOVEres, (char *)&res);
		return;
	}

	res_ok = &res.MOVEres_u.res_ok;

	if (summary) {
	} else {
	}

	xdr_free(xdr_MOVEres, (char *)&res);
}
