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
#include <rpcsvc/nfs_prot.h>

/* use the same nfs4_prot.h as the xdr code */
/* #include "rpcsvc/nfs4_prot.h" */
#include "nfs4_prot.h"

/*
 * Things common to nfs4 and ctl.
 */
#include "nfs4_cmn.h"

/*
 * XXX With NFS v2 and v3, we only need to xdr the pieces that we care
 * about.  Anything else we can ignore and just skip to the next packet.
 * So all the stuff that deals directly with XDR lives in snoop_display.c
 * With v4, we need to XDR entire structures so that we can skip over
 * uninteresting bits in a compound array, so we call XDR directly from
 * here.  We need to rethink how we're going to structure XDR access.  Do
 * we continue to hide it all in snoop_display.c, or do we expose it to all
 * the protocol modules?
 */
extern XDR xdrm;

#ifndef MIN
#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#endif

/*
 * Maximum number of characters to display in compound4 summary line.
 */
#define	SUM_COMPND_MAX	100

/*
 * Maximum number of recognized attributes.
 */
#define	MAX_ATTRIBUTES	77

/*
 * This data structure provides a more convenient way to access an
 * attribute bitmask.  map[N] = value of bit N in a bitmap4.
 * It's defined as a struct so as to step around all the weird rules in C
 * about arrays, pointers, passing them as arguments, etc.
 */

typedef struct {
	char map[MAX_ATTRIBUTES];
} unpkd_attrmap_t;

static void sumarg_cb_getattr(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_getattr(void *obj);
static void sumarg_cb_recall(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_recall(void *obj);

static void sumarg_access(char *buf, size_t buflen, void *obj);
static void dtlarg_access(void *obj);
static void sumarg_close(char *buf, size_t buflen, void *obj);
static void dtlarg_close(void *obj);
static void sumarg_commit(char *buf, size_t buflen, void *obj);
static void dtlarg_commit(void *obj);
static void sumarg_compnt(char *buf, size_t buflen, void *obj);
static void dtlarg_compnt(void *obj);
static void sumarg_create(char *buf, size_t buflen, void *obj);
static void dtlarg_create(void *obj);
static void sumarg_delprge(char *buf, size_t buflen, void *obj);
static void dtlarg_delprge(void *obj);
static void sumarg_delret(char *buf, size_t buflen, void *obj);
static void dtlarg_delret(void *obj);
static void sumarg_getattr(char *buf, size_t buflen, void *obj);
static void dtlarg_getattr(void *obj);
static void sumarg_link(char *buf, size_t buflen, void *obj);
static void dtlarg_link(void *obj);
static void sum_open_to_lock_owner(char *buf, int buflen,
					open_to_lock_owner4 *own);
static void sum_exist_lock_owner(char *buf, int buflen,
					exist_lock_owner4 *own);
static void sum_locker(char *buf, size_t buflen, locker4 *lk);
static void sumarg_lock(char *buf, size_t buflen, void *obj);
static void detail_headerpadsize(count4);
static void detail_open_to_lock_owner(open_to_lock_owner4 *own);
static void detail_exist_lock_owner(exist_lock_owner4 *own);
static void detail_locker(locker4 *lk);
static void dtlarg_lock(void *obj);
static void sumarg_lockt(char *buf, size_t buflen, void *obj);
static void dtlarg_lockt(void *obj);
static void sumarg_locku(char *buf, size_t buflen, void *obj);
static void dtlarg_locku(void *obj);
static void sumarg_lookup(char *buf, size_t buflen, void *obj);
static void dtlarg_lookup(void *obj);
static char *detail_lortype_name(layoutrecall_type4);
static char *sum_lortype_name(layoutrecall_type4);
static void sumarg_open(char *buf, size_t buflen, void *obj);
static void dtlarg_open(void *obj);
static void sumarg_openattr(char *buf, size_t buflen, void *obj);
static void dtlarg_openattr(void *obj);
static void sumarg_open_confirm(char *buf, size_t buflen, void *obj);
static void dtlarg_open_confirm(void *obj);
static void sumarg_open_downgrd(char *buf, size_t buflen, void *obj);
static void dtlarg_open_downgrd(void *obj);
static void sumarg_putfh(char *buf, size_t buflen, void *obj);
static void dtlarg_putfh(void *obj);
static void sumarg_read(char *buf, size_t buflen, void *obj);
static void dtlarg_read(void *obj);
static void sumarg_readdir(char *buf, size_t buflen, void *obj);
static void dtlarg_readdir(void *obj);
static void sumarg_release_lkown(char *buf, size_t buflen, void *obj);
static void dtlarg_release_lkown(void *obj);
static void sumarg_rename(char *buf, size_t buflen, void *obj);
static void dtlarg_rename(void *obj);
static void sumarg_renew(char *buf, size_t buflen, void *obj);
static void dtlarg_renew(void *buf);
static void sumarg_secinfo(char *buf, size_t buflen, void *obj);
static void dtlarg_secinfo(void *obj);
static void sumarg_setattr(char *buf, size_t buflen, void *obj);
static void dtlarg_setattr(void *obj);
static void sumarg_setclid(char *buf, size_t buflen, void *obj);
static void dtlarg_setclid(void *obj);
static void sumarg_setclid_cfm(char *buf, size_t buflen, void *obj);
static void dtlarg_setclid_cfm(void *obj);
static void dtlarg_verify(void *obj);
static void sumarg_write(char *buf, size_t buflen, void *obj);
static void dtlarg_write(void *obj);

static void sumres_cb_getattr(char *buf, size_t buflen, void *obj);
static void dtlres_cb_getattr(void *obj);

static void sumres_access(char *buf, size_t buflen, void *obj);
static void dtlres_access(void *obj);
static void sumres_close(char *buf, size_t buflen, void *obj);
static void dtlres_close(void *obj);
static void sumres_commit(char *buf, size_t buflen, void *obj);
static void dtlres_commit(void *obj);
static void dtlres_create(void *obj);
static void sumres_getattr(char *buf, size_t buflen, void *obj);
static void dtlres_getattr(void *obj);
static void sumres_getfh(char *buf, size_t buflen, void *obj);
static void dtlres_getfh(void *obj);
static void dtlres_link(void *obj);
static void sumres_lock(char *buf, size_t buflen, void *obj);
static void dtlres_lock(void *obj);
static void sumres_lockt(char *buf, size_t buflen, void *obj);
static void dtlres_lockt(void *obj);
static void sumres_locku(char *buf, size_t buflen, void *obj);
static void dtlres_locku(void *obj);
static void sumres_open(char *buf, size_t buflen, void *obj);
static void dtlres_open(void *obj);
static void sumres_open_confirm(char *buf, size_t buflen, void *obj);
static void dtlres_open_confirm(void *obj);
static void sumres_open_downgrd(char *buf, size_t buflen, void *obj);
static void dtlres_open_downgrd(void *obj);
static void sumres_read(char *buf, size_t buflen, void *obj);
static void dtlres_read(void *obj);
static void sumres_readdir(char *buf, size_t buflen, void *obj);
static void dtlres_readdir(void *obj);
static void sumres_readlnk(char *buf, size_t buflen, void *obj);
static void dtlres_readlnk(void *obj);
static void dtlres_remove(void *obj);
static void dtlres_rename(void *obj);
static void sumres_secinfo(char *buf, size_t buflen, void *obj);
static void dtlres_secinfo(void *obj);
static void sumres_setattr(char *buf, size_t buflen, void *obj);
static void dtlres_setattr(void *obj);
static void sumres_setclid(char *buf, size_t buflen, void *obj);
static void dtlres_setclid(void *obj);
static void sumres_write(char *buf, size_t buflen, void *obj);
static void dtlres_write(void *obj);
static void sum_nfsstat4(char *buf, size_t buflen, void *obj);
static void dtl_nfsstat4(void *obj);
static void nfs4_xdr_skip(int nbytes);
static char *sum_lock_type_name(enum nfs_lock_type4 type);

/* nfs4.1 operations */
static void sumarg_cb_layoutrecall(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_layoutrecall(void *obj);
static void sumres_cb_layoutrecall(char *buf, size_t buflen, void *obj);
static void dtlres_cb_layoutrecall(void *obj);
static void sumarg_cb_notify(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_notify(void *obj);
static void sumres_cb_notify(char *buf, size_t buflen, void *obj);
static void dtlres_cb_notify(void *obj);
static void sumarg_cb_push_deleg(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_push_deleg(void *obj);
static void sumres_cb_push_deleg(char *buf, size_t buflen, void *obj);
static void dtlres_cb_push_deleg(void *obj);
static void sumarg_cb_recall_any(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_recall_any(void *obj);
static void sumres_cb_recall_any(char *buf, size_t buflen, void *obj);
static void dtlres_cb_recall_any(void *obj);
static void sumarg_cb_recallable_obj_avail(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_recallable_obj_avail(void *obj);
static void sumres_cb_recallable_obj_avail(char *buf, size_t buflen, void *obj);
static void dtlres_cb_recallable_obj_avail(void *obj);
static void sumarg_cb_recall_slot(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_recall_slot(void *obj);
static void sumres_cb_recall_slot(char *buf, size_t buflen, void *obj);
static void dtlres_cb_recall_slot(void *obj);
static void sumarg_cb_sequence(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_sequence(void *obj);
static void sumres_cb_sequence(char *buf, size_t buflen, void *obj);
static void dtlres_cb_sequence(void *obj);
static void sumarg_cb_wants_cancelled(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_wants_cancelled(void *obj);
static void sumres_cb_wants_cancelled(char *buf, size_t buflen, void *obj);
static void dtlres_cb_wants_cancelled(void *obj);
static void sumarg_cb_notify_lock(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_notify_lock(void *obj);
static void sumres_cb_notify_lock(char *buf, size_t buflen, void *obj);
static void dtlres_cb_notify_lock(void *obj);
static void sumarg_cb_notify_deviceid(char *buf, size_t buflen, void *obj);
static void dtlarg_cb_notify_deviceid(void *obj);

/* nfs4.1 operations */
static void sumarg_backchannel_ctl(char *buf, size_t buflen, void *obj);
static void dtlarg_backchannel_ctl(void *obj);
static void sumarg_bind_conn_to_session(char *buf, size_t buflen, void *obj);
static void dtlarg_bind_conn_to_session(void *obj);
static void sumres_bind_conn_to_session(char *buf, size_t buflen, void *obj);
static void dtlres_bind_conn_to_session(void *obj);
static void sumarg_exchange_id(char *buf, size_t buflen, void *obj);
static void dtlarg_exchange_id(void *obj);
static void sumres_exchange_id(char *buf, size_t buflen, void *obj);
static void dtlres_exchange_id(void *obj);
static void sumarg_create_session(char *buf, size_t buflen, void *obj);
static void sumres_create_session(char *buf, size_t buflen, void *obj);
static void dtlarg_create_session(void *obj);
static void dtlres_create_session(void *obj);
static void sumarg_destroy_session(char *buf, size_t buflen, void *obj);
static void dtlarg_destroy_session(void *obj);
static void sumarg_free_stateid(char *buf, size_t buflen, void *obj);
static void dtlarg_free_stateid(void *obj);
static void sumarg_get_dir_delegation(char *buf, size_t buflen, void *obj);
static void dtlarg_get_dir_delegation(void *obj);
static void sumres_get_dir_delegation(char *buf, size_t buflen, void *obj);
static void dtlres_get_dir_delegation(void *obj);
static void sumarg_getdeviceinfo(char *buf, size_t buflen, void *obj);
static void dtlarg_getdeviceinfo(void *obj);
static void sumres_getdeviceinfo(char *buf, size_t buflen, void *obj);
static void dtlres_getdeviceinfo(void *obj);
static void sumarg_getdevicelist(char *buf, size_t buflen, void *obj);
static void dtlarg_getdevicelist(void *obj);
static void sumres_getdevicelist(char *buf, size_t buflen, void *obj);
static void dtlres_getdevicelist(void *obj);
static void sumarg_layoutcommit(char *buf, size_t buflen, void *obj);
static void dtlarg_layoutcommit(void *obj);
static void sumres_layoutcommit(char *buf, size_t buflen, void *obj);
static void dtlres_layoutcommit(void *obj);
static void sumarg_layoutget(char *buf, size_t buflen, void *obj);
static void dtlarg_layoutget(void *obj);
static void sumres_layoutget(char *buf, size_t buflen, void *obj);
static void dtlres_layoutget(void *obj);
static void sumarg_layoutreturn(char *buf, size_t buflen, void *obj);
static void dtlarg_layoutreturn(void *obj);
static void sumarg_secinfo_no_name(char *buf, size_t buflen, void *obj);
static void dtlarg_secinfo_no_name(void *obj);
static void sumarg_sequence(char *buf, size_t buflen, void *obj);
static void dtlarg_sequence(void *obj);
static void sumres_sequence(char *buf, size_t buflen, void *obj);
static void dtlres_sequence(void *obj);
static void sumarg_set_ssv(char *buf, size_t buflen, void *obj);
static void dtlarg_set_ssv(void *obj);
static void sumres_set_ssv(char *buf, size_t buflen, void *obj);
static void dtlres_set_ssv(void *obj);
static void sumarg_test_stateid(char *buf, size_t buflen, void *obj);
static void dtlarg_test_stateid(void *obj);
static void sumres_test_stateid(char *buf, size_t buflen, void *obj);
static void dtlres_test_stateid(void *obj);
static void sumarg_want_delegation(char *buf, size_t buflen, void *obj);
static void dtlarg_want_delegation(void *obj);
static void sumres_want_delegation(char *buf, size_t buflen, void *obj);
static void dtlres_want_delegation(void *obj);
static void sumarg_destroy_clientid(char *buf, size_t buflen, void *obj);
static void dtlarg_destroy_clientid(void *obj);
static void sumres_destroy_clientid(char *buf, size_t buflen, void *obj);
static void dtlres_destroy_clientid(void *obj);
static void sumarg_reclaim_complete(char *buf, size_t buflen, void *obj);
static void dtlarg_reclaim_complete(void *obj);
static void sumres_reclaim_complete(char *buf, size_t buflen, void *obj);
static void dtlres_reclaim_complete(void *obj);

static void detail_threshold_hint_bitmap(uint32_t);

int nfs4_pkt_start;
int nfs4_pkt_len;
int nfs4_skip_bytes;
int nfs4_fragged_rpc;
char *nfs4err_fragrpc = "<Fragmented RPC>";
char *nfs4err_xdrfrag = "<XDR Error or Fragmented RPC>";

/*
 * need a way to enable this if current testcases are parsing snoop
 * error text. -- maybe an env var would do as temp workaround until
 * testcases changed to grep for new error text.
 */
int nfs4_use_old_error_text = 0;

/*
 * Information about each operation that can appear in a compound call.
 * The function pointers are to formatting functions for summary arguments
 * and results, and detail arguments & results.
 */

typedef struct {
	char	*name;
	void	(*sumarg)(char *, size_t, void *);
	void	(*sumres)(char *, size_t, void *);
	void	(*dtlarg)(void *);
	void	(*dtlres)(void *);
} op_info_t;

static op_info_t cb_opcode_info[] = {
	{"OP_ZERO",	NULL,	NULL,	NULL,	NULL},	/* 0 */
	{"OP_ONE",	NULL,	NULL,	NULL,	NULL},
	{"OP_TWO",	NULL,	NULL,	NULL,	NULL},  /* minor vers */
	{"CB_GETATTR",
	    sumarg_cb_getattr,	sumres_cb_getattr,
	    dtlarg_cb_getattr,	dtlres_cb_getattr},
	{"CB_RECALL",
	    sumarg_cb_recall,	sum_nfsstat4,
	    dtlarg_cb_recall,	dtl_nfsstat4},
	{"CB_LAYOUTRECALL",				/* 5 */
	    sumarg_cb_layoutrecall,	sumres_cb_layoutrecall,
	    dtlarg_cb_layoutrecall,	dtlres_cb_layoutrecall},
	{"CB_NOTIFY",
	    sumarg_cb_notify,	sumres_cb_notify,
	    dtlarg_cb_notify,	dtlres_cb_notify},
	{"CB_PUSH_DELEG",
	    sumarg_cb_push_deleg,	sumres_cb_push_deleg,
	    dtlarg_cb_push_deleg,	dtlres_cb_push_deleg},
	{"CB_RECALL_ANY",
	    sumarg_cb_recall_any,	sumres_cb_recall_any,
	    dtlarg_cb_recall_any,	dtlres_cb_recall_any},
	{"CB_RECALLABLE_OBJ_AVAIL",
	    sumarg_cb_recallable_obj_avail,
	    sumres_cb_recallable_obj_avail,
	    dtlarg_cb_recallable_obj_avail,
	    dtlres_cb_recallable_obj_avail},
	{"CB_RECALL_SLOT",				/* 10 */
	    sumarg_cb_recall_slot,	sumres_cb_recall_slot,
	    dtlarg_cb_recall_slot,	dtlres_cb_recall_slot},
	{"CB_SEQUENCE",
	    sumarg_cb_sequence,	sumres_cb_sequence,
	    dtlarg_cb_sequence,	dtlres_cb_sequence},
	{"CB_WANTS_CANCELLED",
	    sumarg_cb_wants_cancelled,
	    sumres_cb_wants_cancelled,
	    dtlarg_cb_wants_cancelled,
	    dtlres_cb_wants_cancelled},
	{"CB_NOTIFY_LOCK",
	    sumarg_cb_notify_lock,	sumres_cb_notify_lock,
	    dtlarg_cb_notify_lock,	dtlres_cb_notify_lock},
	{"CB_NOTIFY_DEVICEID",
	    sumarg_cb_notify_deviceid,	sum_nfsstat4,
	    dtlarg_cb_notify_deviceid,	dtl_nfsstat4},
};
static uint_t cb_num_opcodes = sizeof (cb_opcode_info) / sizeof (op_info_t *);

static op_info_t opcode_info[] = {
	{"OP_ZERO",	NULL,	NULL,	NULL,	NULL},	/* 0 */
	{"OP_ONE",	NULL,	NULL,	NULL,	NULL},
	{"OP_TWO",	NULL,	NULL,	NULL,	NULL},  /* minor vers */
	{"ACCESS",
	sumarg_access,	sumres_access,	dtlarg_access,	dtlres_access},
	{"CLOSE",
	sumarg_close,	sumres_close,	dtlarg_close,	dtlres_close},
	{"COMMIT",
	sumarg_commit,	sumres_commit,	dtlarg_commit,	dtlres_commit},
	{"CREATE",					/* 5 */
	sumarg_create,	sum_nfsstat4,	dtlarg_create,	dtlres_create},
	{"DELEGPURGE",
	sumarg_delprge,	sum_nfsstat4,	dtlarg_delprge,	dtl_nfsstat4},
	{"DELEGRETURN",
	sumarg_delret,	sum_nfsstat4,	dtlarg_delret,	dtl_nfsstat4},
	{"GETATTR",
	sumarg_getattr,	sumres_getattr,	dtlarg_getattr,	dtlres_getattr},
	{"GETFH",
	NULL,		sumres_getfh,	NULL,	dtlres_getfh},
	{"LINK",					/* 10 */
	sumarg_link,	sum_nfsstat4,	dtlarg_link,	dtlres_link},
	{"LOCK",
	sumarg_lock,	sumres_lock,	dtlarg_lock,	dtlres_lock},
	{"LOCKT",
	sumarg_lockt,	sumres_lockt,	dtlarg_lockt,	dtlres_lockt},
	{"LOCKU",
	sumarg_locku,	sumres_locku,	dtlarg_locku,	dtlres_locku},
	{"LOOKUP",
	sumarg_lookup,	sum_nfsstat4,	dtlarg_lookup,	dtl_nfsstat4},
	{"LOOKUPP",					/* 15 */
	NULL,		sum_nfsstat4,	NULL,		dtl_nfsstat4},
	{"NVERIFY",
	NULL,		sum_nfsstat4,	dtlarg_verify,	dtl_nfsstat4},
	{"OPEN",
	sumarg_open,	sumres_open,	dtlarg_open,	dtlres_open},
	{"OPENATTR",
	sumarg_openattr, sum_nfsstat4, dtlarg_openattr, dtl_nfsstat4},
	{"OPEN_CONFIRM",
	sumarg_open_confirm,
	sumres_open_confirm,
	dtlarg_open_confirm,
	dtlres_open_confirm},
	{"OPEN_DOWNGRADE",
	sumarg_open_downgrd,
	sumres_open_downgrd,
	dtlarg_open_downgrd,
	dtlres_open_downgrd},
	{"PUTFH",
	sumarg_putfh,	sum_nfsstat4,	dtlarg_putfh,	dtl_nfsstat4},
	{"PUTPUBFH",					/* 20 */
	NULL,		sum_nfsstat4,	NULL,		dtl_nfsstat4},
	{"PUTROOTFH",
	NULL,		sum_nfsstat4,	NULL,		dtl_nfsstat4},
	{"READ",
	sumarg_read,	sumres_read,	dtlarg_read,	dtlres_read},
	{"READDIR",
	sumarg_readdir,	sumres_readdir,	dtlarg_readdir,	dtlres_readdir},
	{"READLINK",
	NULL,		sumres_readlnk,	NULL,		dtlres_readlnk},
	{"REMOVE",					/* 25 */
	sumarg_compnt,	sum_nfsstat4,	dtlarg_compnt,	dtlres_remove},
	{"RENAME",
	sumarg_rename,	sum_nfsstat4,	dtlarg_rename,	dtlres_rename},
	{"RENEW",
	sumarg_renew,	sum_nfsstat4,	dtlarg_renew,	dtl_nfsstat4},
	{"RESTOREFH",
	NULL,		sum_nfsstat4,	NULL,		dtl_nfsstat4},
	{"SAVEFH",
	NULL,		sum_nfsstat4,	NULL,		dtl_nfsstat4},
	{"SECINFO",					/* 30 */
	sumarg_secinfo,	sumres_secinfo,	dtlarg_secinfo,	dtlres_secinfo},
	{"SETATTR",
	sumarg_setattr,	sumres_setattr,	dtlarg_setattr,	dtlres_setattr},
	{"SETCLIENTID",
	sumarg_setclid,	sumres_setclid,	dtlarg_setclid,	dtlres_setclid},
	{"SETCLIENTID_CONFIRM",
	sumarg_setclid_cfm,
	sum_nfsstat4,
	dtlarg_setclid_cfm,
	dtl_nfsstat4},
	{"VERIFY",
	NULL,		sum_nfsstat4,	dtlarg_verify,	dtl_nfsstat4},
	{"WRITE",
	sumarg_write,	sumres_write,	dtlarg_write,	dtlres_write},
	{"RELEASE_LOCKOWNER",
	sumarg_release_lkown, sum_nfsstat4,
	dtlarg_release_lkown, dtl_nfsstat4},
	/* nfs4.1 operations */
	{"BACKCHANNEL_CTL",				/* 40 */
	sumarg_backchannel_ctl,		sum_nfsstat4,
	dtlarg_backchannel_ctl,		dtl_nfsstat4},
	{"BIND_CONN_TO_SESSION",
	sumarg_bind_conn_to_session,	sumres_bind_conn_to_session,
	dtlarg_bind_conn_to_session,	dtlres_bind_conn_to_session},
	{"EXCHANGE_ID",
	sumarg_exchange_id,		sumres_exchange_id,
	dtlarg_exchange_id,		dtlres_exchange_id},
	{"CREATE_SESSION",
	sumarg_create_session,		sumres_create_session,
	dtlarg_create_session,		dtlres_create_session},
	{"DESTROY_SESSION",
	sumarg_destroy_session,		sum_nfsstat4,
	dtlarg_destroy_session,		dtl_nfsstat4},
	{"FREE_STATEID",				/* 45 */
	sumarg_free_stateid,		sum_nfsstat4,
	dtlarg_free_stateid,		dtl_nfsstat4},
	{"GET_DIR_DELEGATION",
	sumarg_get_dir_delegation,	sumres_get_dir_delegation,
	dtlarg_get_dir_delegation,	dtlres_get_dir_delegation},
	{"GETDEVICEINFO",
	sumarg_getdeviceinfo,		sumres_getdeviceinfo,
	dtlarg_getdeviceinfo,		dtlres_getdeviceinfo},
	{"GETDEVICELIST",
	sumarg_getdevicelist,		sumres_getdevicelist,
	dtlarg_getdevicelist,		dtlres_getdevicelist},
	{"LAYOUTCOMMIT",
	sumarg_layoutcommit,		sumres_layoutcommit,
	dtlarg_layoutcommit,		dtlres_layoutcommit},
	{"LAYOUTGET",					/* 50 */
	sumarg_layoutget,		sumres_layoutget,
	dtlarg_layoutget,		dtlres_layoutget},
	{"LAYOUTRETURN",
	sumarg_layoutreturn,		sum_nfsstat4,
	dtlarg_layoutreturn,		dtl_nfsstat4},
	{"SECINFO_NO_NAME",
	sumarg_secinfo_no_name,		sumres_secinfo,
	dtlarg_secinfo_no_name,		dtlres_secinfo},
	{"SEQUENCE",
	sumarg_sequence,		sumres_sequence,
	dtlarg_sequence,		dtlres_sequence},
	{"SET_SSV",
	sumarg_set_ssv,			sumres_set_ssv,
	dtlarg_set_ssv,			dtlres_set_ssv},
	{"TEST_STATEID",				/* 55 */
	sumarg_test_stateid,		sumres_test_stateid,
	dtlarg_test_stateid,		dtlres_test_stateid},
	{"WANT_DELEGATION",
	sumarg_want_delegation,		sumres_want_delegation,
	dtlarg_want_delegation,		dtlres_want_delegation},
	{"DESTROY_CLIENTID",
	sumarg_destroy_clientid,		sumres_destroy_clientid,
	dtlarg_destroy_clientid,		dtlres_destroy_clientid},
	{"RECLAIM_COMPLETE",
	sumarg_reclaim_complete,		sumres_reclaim_complete,
	dtlarg_reclaim_complete,		dtlres_reclaim_complete},
};
static uint_t num_opcodes = sizeof (opcode_info) / sizeof (op_info_t *);


typedef struct {
	char *short_name;		/* for summary output */
	char *long_name;		/* for detail output */
} type_names_t;


/*
 * Layout Recall types
 */
static type_names_t lortype_names[] = {
	{"Type 0",	"Type 0"},
	{"FILE",	"Layout for File handle"},
	{"FSID",	"All layouts for objects in FSID"},
	{"ALL",		"All layouts"},
};
static uint_t num_lortypes = sizeof (lortype_names) / sizeof (type_names_t);


/*
 * Layout types
 */
static type_names_t lotype_names[] = {
	{"Type 0",	"Type 0"},
	{"FILE",	"LAYOUT4_NFSV4_1_FILES"},
	{"OBJ",		"LAYOUT4_OSD2_OBJECTS"},
	{"VOL",		"LAYOUT4_BLOCK_VOLUME"},
};
static uint_t num_lotypes = sizeof (lotype_names) / sizeof (type_names_t);

/*
 * Layout iomodes
 */

static type_names_t iomode_names[] = {
	{"?",		"UNKNOWN"},
	{"READ",	"LAYOUTIOMODE4_READ"},
	{"RW",		"LAYOUTIOMODE4_RW"},
	{"ANY",		"LAYOUTIOMODE4_ANY"},
};
static uint_t num_iomodes = sizeof (iomode_names) / sizeof (type_names_t);

/*
 * Layoutreturn types
 */

static type_names_t lrtype_names[] = {
	{"?",		"UNKNOWN"},
	{"FILE",	"LAYOUTRETURN4_FILE"},
	{"FSID",	"LAYOUTRETURN4_FSID"},
	{"ALL",		"LAYOUTRETURN4_ALL"},
};
static uint_t num_lrtypes = sizeof (lrtype_names) / sizeof (type_names_t);

/* stripe type */
static type_names_t stripe_names[] = {
	{"?",		"UNKNOWN"},
	{"SPARSE",      "STRIPE4_SPARSE"},
	{"DENSE",       "STRIPE4_DENSE"},
};
static uint_t num_stripes = sizeof (stripe_names) / sizeof (type_names_t);

/* how the client wants to protect its client */
static type_names_t ps_names[] = {
	{"NONE",	"SP4_NONE"},
	{"MACH_CRED",	"SP4_MACH_CRED"},
	{"SSV",		"SP4_SSV"},
};
static uint_t num_ps = sizeof (ps_names) / sizeof (type_names_t);

/*
 * File types.
 */

typedef type_names_t ftype_names_t;

static ftype_names_t ftype_names[] = {
	{"Type 0",	"Type 0"},
	{"REG",		"Regular File"},
	{"DIR",		"Directory"},
	{"BLK",		"Block Device"},
	{"CHR",		"Character Device"},
	{"LNK",		"Symbolic Link"},	/* 5 */
	{"SOCK",	"Socket"},
	{"FIFO",	"FIFO"},
	{"ATTRDIR",	"Attribute Directory"},
	{"NAMEDATTR",	"Named Attribute"},
};
static uint_t num_ftypes = sizeof (ftype_names) / sizeof (ftype_names_t);

typedef type_names_t flag_t;

static flag_t	open_rflags[] = {
	{"?",	"UNKNOWN"},	/* 0 */
	{"CF",	"CONFIRM"},	/* 1 */
	{"PL",	"POSIX LOCK"},	/* 2 */
	{"?",	"UNKNOWN"},
};
static uint_t num_open_rflags =
	sizeof (open_rflags) / sizeof (ftype_names_t) - 1;

static char *get_flags(uint_t, ftype_names_t *, uint_t, int, char *);

#define	sum_open_rflags(flag) \
	get_flags((flag), open_rflags, num_open_rflags, 1, " RF=")

#define	detail_open_rflags(flag) \
	get_flags((flag), open_rflags, num_open_rflags, 0, NULL)

static void prt_supported_attrs(XDR *);
static void prt_type(XDR *);
static void prt_fh_expire_type(XDR *);
static void prt_change(XDR *);
static void prt_size(XDR *);
static void prt_link_support(XDR *);
static void prt_symlink_support(XDR *);
static void prt_named_attr(XDR *);
static void prt_fsid(XDR *);
static void prt_unique_handles(XDR *);
static void prt_lease_time(XDR *);
static void prt_rdattr_error(XDR *);
static void prt_acl(XDR *);
static void prt_aclsupport(XDR *);
static void prt_archive(XDR *);
static void prt_cansettime(XDR *);
static void prt_case_insensitive(XDR *);
static void prt_case_preserving(XDR *);
static void prt_chown_restricted(XDR *);
static void prt_filehandle(XDR *);
static void prt_fileid(XDR *);
static void prt_mounted_on_fileid(XDR *);
static void prt_files_avail(XDR *);
static void prt_files_free(XDR *);
static void prt_files_total(XDR *);
static void prt_fs_locations(XDR *);
static void prt_hidden(XDR *);
static void prt_homogeneous(XDR *);
static void prt_maxfilesize(XDR *);
static void prt_maxlink(XDR *);
static void prt_maxname(XDR *);
static void prt_maxread(XDR *);
static void prt_maxwrite(XDR *);
static void prt_mimetype(XDR *);
static void prt_mode(XDR *);
static void prt_no_trunc(XDR *);
static void prt_numlinks(XDR *);
static void prt_owner(XDR *);
static void prt_owner_group(XDR *);
static void prt_quota_avail_hard(XDR *);
static void prt_quota_avail_soft(XDR *);
static void prt_quota_used(XDR *);
static void prt_rawdev(XDR *);
static void prt_space_avail(XDR *);
static void prt_space_free(XDR *);
static void prt_space_total(XDR *);
static void prt_space_used(XDR *);
static void prt_system(XDR *);
static void prt_time_access(XDR *);
static void prt_time_access_set(XDR *);
static void prt_time_backup(XDR *);
static void prt_time_create(XDR *);
static void prt_time_delta(XDR *);
static void prt_time_metadata(XDR *);
static void prt_time_modify(XDR *);
static void prt_time_modify_set(XDR *);
/* nfs4.1 attributes */
static void prt_dir_notif_delay(XDR *);
static void prt_dirent_notif_delay(XDR *);
static void prt_dacl(XDR *);
static void prt_sacl(XDR *);
static void prt_change_policy(XDR *);
static void prt_fs_status(XDR *);
static void prt_fs_layout_type(XDR *);
static void prt_layout_hint(XDR *);
static void prt_layout_type(XDR *);
static void prt_layout_blksize(XDR *);
static void prt_layout_alignment(XDR *);
static void prt_fs_locations_info(XDR *);
static void prt_mdsthreshold(XDR *);
static void prt_retention_get(XDR *);
static void prt_retention_set(XDR *);
static void prt_retentevt_get(XDR *);
static void prt_retentevt_set(XDR *);
static void prt_retention_hold(XDR *);
static void prt_mode_set_masked(XDR *);
static void prt_suppattr_exclcreat(XDR *);
static void prt_fs_charset_cap(XDR *);


/*
 * Information for attributes.
 * name		name of the attribute.
 * prt_details	function to XDR decode the attribute and print it.
 *
 * XXX If this table ever gets extensively changed (including
 * reorganization to track changes to the spec), it would probably be a
 * good idea to change to a scheme where the table is mechanically
 * generated.  Look at $SRC/uts/common/rpcsvc for how this is done in the
 * kernel.
 */

typedef struct {
	char	*name;
	void	(*prt_details)(XDR *);
} attr_info_t;


#define	TH4_READ_SIZE_MASK	(1 << TH4_READ_SIZE)
#define	TH4_WRITE_SIZE_MASK	(1 << TH4_WRITE_SIZE)
#define	TH4_READ_IOSIZE_MASK	(1 << TH4_READ_IOSIZE)
#define	TH4_WRITE_IOSIZE_MASK	(1 << TH4_WRITE_IOSIZE)

static attr_info_t attr_info[MAX_ATTRIBUTES] = {
	{"SUPPORTED_ATTRS",	prt_supported_attrs},
	{"TYPE",		prt_type},
	{"FH_EXPIRE_TYPE",	prt_fh_expire_type},
	{"CHANGE",		prt_change},
	{"SIZE",		prt_size},
	{"LINK_SUPPORT",	prt_link_support},	/* 5 */
	{"SYMLINK_SUPPORT",	prt_symlink_support},
	{"NAMED_ATTR",		prt_named_attr},
	{"FSID",		prt_fsid},
	{"UNIQUE_HANDLES",	prt_unique_handles},
	{"LEASE_TIME",		prt_lease_time},	/* 10 */
	{"RDATTR_ERROR",	prt_rdattr_error},
	{"ACL",			prt_acl},
	{"ACLSUPPORT",		prt_aclsupport},
	{"ARCHIVE",		prt_archive},
	{"CANSETTIME",		prt_cansettime},	/* 15 */
	{"CASE_INSENSITIVE",	prt_case_insensitive},
	{"CASE_PRESERVING",	prt_case_preserving},
	{"CHOWN_RESTRICTED",	prt_chown_restricted},
	{"FILEHANDLE",		prt_filehandle},
	{"FILEID",		prt_fileid},		/* 20 */
	{"FILES_AVAIL",		prt_files_avail},
	{"FILES_FREE",		prt_files_free},
	{"FILES_TOTAL",		prt_files_total},
	{"FS_LOCATIONS",	prt_fs_locations},
	{"HIDDEN",		prt_hidden},		/* 25 */
	{"HOMOGENEOUS",		prt_homogeneous},
	{"MAXFILESIZE",		prt_maxfilesize},
	{"MAXLINK",		prt_maxlink},
	{"MAXNAME",		prt_maxname},
	{"MAXREAD",		prt_maxread},		/* 30 */
	{"MAXWRITE",		prt_maxwrite},
	{"MIMETYPE",		prt_mimetype},
	{"MODE",		prt_mode},
	{"NO_TRUNC",		prt_no_trunc},
	{"NUMLINKS",		prt_numlinks},		/* 35 */
	{"OWNER",		prt_owner},
	{"OWNER_GROUP",		prt_owner_group},
	{"QUOTA_AVAIL_HARD",	prt_quota_avail_hard},
	{"QUOTA_AVAIL_SOFT",	prt_quota_avail_soft},
	{"QUOTA_USED",		prt_quota_used},	/* 40 */
	{"RAWDEV",		prt_rawdev},
	{"SPACE_AVAIL",		prt_space_avail},
	{"SPACE_FREE",		prt_space_free},
	{"SPACE_TOTAL",		prt_space_total},
	{"SPACE_USED",		prt_space_used},	/* 45 */
	{"SYSTEM",		prt_system},
	{"TIME_ACCESS",		prt_time_access},
	{"TIME_ACCESS_SET",	prt_time_access_set},
	{"TIME_BACKUP",		prt_time_backup},
	{"TIME_CREATE",		prt_time_create},	/* 50 */
	{"TIME_DELTA",		prt_time_delta},
	{"TIME_METADATA",	prt_time_metadata},
	{"TIME_MODIFY",		prt_time_modify},
	{"TIME_MODIFY_SET",	prt_time_modify_set},
	{"MOUNTED_ON_FILEID",	prt_mounted_on_fileid},	/* 55 */
	/* Attributes supported in nfs4.1 */
	{"DIR_NOTIF_DELAY",	prt_dir_notif_delay},
	{"DIRENT_NOTIF_DELAY",	prt_dirent_notif_delay},
	{"DACL",		prt_dacl},
	{"SACL",		prt_sacl},
	{"CHANGE_POLICY",	prt_change_policy},	/* 60 */
	{"FS_STATUS",		prt_fs_status},
	{"FS_LAYOUT_TYPE",	prt_fs_layout_type},
	{"LAYOUT_HINT",		prt_layout_hint},
	{"LAYOUT_TYPE",		prt_layout_type},
	{"LAYOUT_BLKSIZE",	prt_layout_blksize},	/* 65 */
	{"LAYOUT_ALIGNMENT",	prt_layout_alignment},
	{"FS_LOCATIONS_INFO",	prt_fs_locations_info},
	{"MDSTHRESHOLD",	prt_mdsthreshold},
	{"RETENTION_GET",	prt_retention_get},
	{"RETENTION_SET",	prt_retention_set},	/* 70 */
	{"RETENTEVT_GET",	prt_retentevt_get},
	{"RETENTEVT_SET",	prt_retentevt_set},
	{"RETENTION_HOLD",	prt_retention_hold},
	{"MODE_SET_MASKED",	prt_mode_set_masked},
	{"SUPPATTR_EXCLCREAT",	prt_suppattr_exclcreat}, /* 75 */
	{"FS_CHARSET_CAP",	prt_fs_charset_cap},
};

extern char *get_sum_line();

extern jmp_buf xdr_err;

static void sum_comp4res(char *, char *(*)(void));
static char *sum_compound4args(void);
static char *sum_compound4res(void);
static char *sum_operand(nfs_argop4 *opp);
static char *sum_result(nfs_resop4 *resp);

static char *sum_cb_compound4args(void);
static char *sum_cb_compound4res(void);
static char *sum_cb_operand(nfs_cb_argop4 *opp);
static char *sum_cb_result(nfs_cb_resop4 *resp);

static void detail_acetype4(acetype4);
static void detail_uint32_bitmap(uint32_t, char *[], int);
static void detail_aceflag4(aceflag4);
static void detail_acemask4(acemask4);
static void detail_nfs_argop4(void);
static void detail_nfs_resop4(void);
static void detail_cb_argop4(void);
static void detail_cb_resop4(void);

static char *attr_name(uint_t);
static char *claim_name(enum open_claim_type4 claim_type);
static char *delegation_type_name(enum open_delegation_type4 type);
static char *flavor_name(uint_t flavor);
static char *gss_svc_name(rpc_gss_svc_t svc);
static char *limitby_name(enum limit_by4 limitby);
static char *lock_type_name(enum nfs_lock_type4);
static char *opcode_name(uint_t);
static char *cb_opcode_name(uint_t opnum);
static char *status_name(int);
static char *status_name_compat(int);
static char *status_name_pcol(int);
static char *sum_type_name(nfs_ftype4);
static void sum_access4(char *buf, size_t buflen, uint32_t bits);
static void detail_access4(char *, uint32_t);
static void sum_claim(char *buf, size_t buflen, open_claim4 *claim);
static void detail_claim(open_claim4 *claim);
static void sum_delegation(char *buf, size_t buflen, open_delegation4 *delp);
static void detail_delegation(open_delegation4 *delp);
static void detail_lock_owner(lock_owner4 *owner);
static void detail_open_owner(open_owner4 *owner);
static void sum_openflag(char *bufp, int buflen, openflag4 *flagp);
static char *get_deleg_typestr(open_delegation_type4 dt);
static void detail_openflag(openflag4 *flagp);
static void sum_name(char *buf, size_t buflen, open_claim4 *claim);
static void detail_rpcsec_gss(rpcsec_gss_info *);
static char *sum_space_limit(nfs_space_limit4 *limitp);
static void detail_space_limit(nfs_space_limit4 *limitp);
static char *detail_type_name(nfs_ftype4);
static char *createhow4_name(createhow4 *crtp);


static void showxdr_utf8string(char *);
static void sum_pathname4(char *, size_t, pathname4 *);
static void detail_pathname4(pathname4 *pathp);
static void sum_compname4(char *buf, size_t buflen, component4 *comp);
static void detail_compname4(component4 *comp);

static void detail_fattr4(fattr4 *attrp);
static void detail_attr_bitmap(char *, bitmap4 *, unpkd_attrmap_t *);
static void sum_attr_bitmap(char *buf, size_t buflen, bitmap4 *mapp);
static void detail_fattr4_change(char *msg, fattr4_change chg);

#define	DONT_CHANGE		0
#define	SET_TO_SERVER_TIME	1
#define	SET_TO_CLIENT_TIME	2

static stateid4 spec_stateid_0 =
	{0, {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
static stateid4 spec_stateid_1 =
	{0xFFFFFFFF, {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1}};

static char *procnames_short[] = {
	"NULL4",	/*  0 */
	"COMPOUND4"	/*  1 */
};

static char *procnames_long[] = {
	"Null procedure",		/*  0 */
	"Compound",			/*  1 */
};

static char *cb_procnames_short[] = {
	"CB_NULL",	/*  0 */
	"CB_COMPOUND"	/*  1 */
};

static char *cb_procnames_long[] = {
	"Null CallBack procedure",	/*  0 */
	"CallBack compound",		/*  1 */
};

static char *acetype4_names[] = {
	"ACE4_ACCESS_ALLOWED_ACE_TYPE",
	"ACE4_ACCESS_DENIED_ACE_TYPE",
	"ACE4_SYSTEM_AUDIT_ACE_TYPE",
	"ACE4_SYSTEM_ALARM_ACE_TYPE"
};
#define	ACETYPE4_NAMES_MAX (sizeof (acetype4_names) / sizeof (char *))

static char *aceflag4_names[] = {
	"ACE4_FILE_INHERIT_ACE",
	"ACE4_DIRECTORY_INHERIT_ACE",
	"ACE4_NO_PROPAGATE_INHERIT_ACE",
	"ACE4_INHERIT_ONLY_ACE",
	"ACE4_SUCCESSFUL_ACCESS_ACE_FLAG",
	"ACE4_FAILED_ACCESS_ACE_FLAG",
	"ACE4_IDENTIFIER_GROUP"
};
#define	ACEFLAG4_NAMES_MAX (sizeof (aceflag4_names) / sizeof (char *))

static char *acemask4_names[] = {
	"ACE4_READ_DATA/ACE4_LIST_DIRECTORY",
	"ACE4_WRITE_DATA/ACE4_ADD_FILE",
	"ACE4_APPEND_DATA/ACE4_ADD_SUBDIRECTORY",
	"ACE4_READ_NAMED_ATTRS",
	"ACE4_WRITE_NAMED_ATTRS",
	"ACE4_EXECUTE",
	"ACE4_DELETE_CHILD",
	"ACE4_READ_ATTRIBUTES",
	"ACE4_WRITE_ATTRIBUTES",
	"UNDEFINED",	/* 0x00000200 */
	"UNDEFINED",	/* 0x00000400 */
	"UNDEFINED",	/* 0x00000800 */
	"UNDEFINED",	/* 0x00001000 */
	"UNDEFINED",	/* 0x00002000 */
	"UNDEFINED",	/* 0x00004000 */
	"UNDEFINED",	/* 0x00008000 */
	"ACE4_DELETE",
	"ACE4_READ_ACL",
	"ACE4_WRITE_ACL",
	"ACE4_WRITE_OWNER",
	"ACE4_SYNCHRONIZE"
};
#define	ACEMASK4_NAMES_MAX (sizeof (acemask4_names) / sizeof (char *))

static char *seq_status[] = {
	"SEQ4_STATUS_CB_PATH_DOWN",
	"SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING",
	"SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED",
	"SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED",
	"SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED",
	"SEQ4_STATUS_ADMIN_STATE_REVOKED",
	"SEQ4_STATUS_RECALLABLE_STATE_REVOKED",
	"SEQ4_STATUS_LEASE_MOVED",
	"SEQ4_STATUS_RESTART_RECLAIM_NEEDED"
};
#define	SEQ_STATUS_MAX	(sizeof (seq_status) / sizeof (char *))

static flag_t   session_flags[] = {
	{"RS",	"PERSIST"},	/* 1: Reliable semantics */
	{"BC",	"BACKCHAN"},	/* 2: conn used for back channel, too */
	{"DP",	"RDMA"},	/* 3: conn is non-streamed; Begin RDMA */
	{"?",	"UNKNOWN"}	/* 4: Unknown Flag */
};
static uint_t num_session_flags = sizeof (session_flags) / sizeof (flag_t) - 1;

#define	sum_sn_flags(flag) \
	get_flags((flag), session_flags, num_session_flags, 1, " SF=")
#define	detail_sn_flags(flag) \
	get_flags((flag), session_flags, num_session_flags, 0, NULL)

#define	MAXPROC	1

/*ARGSUSED*/
void
interpret_nfs4_cb(int flags, int type, int xid, int vers, int proc,
		char *data, int len)
{
	char *line = NULL;

	if (proc < 0 || proc > MAXPROC)
		return;

	if (flags & F_SUM) {
		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "NFS C %s",
			    proc == CB_COMPOUND ? "CB4" :
			    cb_procnames_short[proc]);
			line += strlen(line);

			if (proc == CB_COMPOUND) {
				static utf8string tag;

				if (!xdr_utf8string(&xdrm, &tag))
					longjmp(xdr_err, 1);
				sprintf(line, " (%.20s) %s",
				    utf8localize(&tag),
				    sum_cb_compound4args());
				xdr_free(xdr_utf8string, (char *)&tag);
			}
			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "NFS R %s ",
			    proc == CB_COMPOUND ? "CB4" :
			    cb_procnames_short[proc]);
			line += strlen(line);
			if (proc == CB_COMPOUND)
				sum_comp4res(line, sum_cb_compound4res);
		}
	}

	if (flags & F_DTAIL) {
		show_header("NFS:  ", "Sun NFS4 CallBack", len);
		show_space();
		(void) sprintf(get_line(0, 0), "Proc = %d (%s)",
		    proc, cb_procnames_long[proc]);
		if (proc == CB_COMPOUND) {
			if (type == CALL) {
				showxdr_utf8string("Tag = %s");
				detail_cb_argop4();
			} else {
				nfsstat4 status;

				status = getxdr_long();
				showxdr_utf8string("Tag = %s");
				sprintf(get_line(0, 0), "Status = %d (%s)",
				    status, status_name(status));
				detail_cb_resop4();
			}
		}
		show_trailer();
	}

	utf8free();			/* cf. utf8localize() */
}


/*ARGSUSED*/
void
interpret_nfs4(int flags, int type, int xid, int vers, int proc,
		char *data, int len)
{
	char *line = NULL;

	if (proc < 0 || proc > MAXPROC)
		return;

	nfs4_fragged_rpc = 0;
	nfs4_pkt_len = len;
	nfs4_pkt_start = xdr_getpos(&xdrm);

	if (flags & F_SUM) {
		line = get_sum_line();

		if (type == CALL) {
			(void) sprintf(line, "NFS C %s",
			    proc == NFSPROC4_COMPOUND ? "4" :
			    procnames_short[proc]);
			line += strlen(line);

			if (proc == NFSPROC4_COMPOUND) {
				static utf8string tag;

				if (!xdr_utf8string(&xdrm, &tag))
					longjmp(xdr_err, 1);
				sprintf(line, " (%.20s) %s",
				    utf8localize(&tag),
				    sum_compound4args());
				xdr_free(xdr_utf8string, (char *)&tag);
			}
			check_retransmit(line, xid);
		} else {
			(void) sprintf(line, "NFS R %s ",
			    proc == NFSPROC4_COMPOUND ? "4" :
			    procnames_short[proc]);
			line += strlen(line);

			if (proc == NFSPROC4_COMPOUND)
				sum_comp4res(line, sum_compound4res);
		}
	}

	if (flags & F_DTAIL) {
		show_header("NFS:  ", "Sun NFS", len);
		show_space();
		(void) sprintf(get_line(0, 0), "Proc = %d (%s)",
		    proc, procnames_long[proc]);
		if (proc == NFSPROC4_COMPOUND) {
			if (type == CALL) {
				showxdr_utf8string("Tag = %s");
				detail_nfs_argop4();
			} else {
				nfsstat4 status;

				status = getxdr_long();
				showxdr_utf8string("Tag = %s");
				sprintf(get_line(0, 0), "Status = %d (%s)",
				    status, status_name(status));
				detail_nfs_resop4();
			}
		}
		show_trailer();
	}

	utf8free();			/* cf. utf8localize() */
}



/*
 * Return the names and arguments of the oplist elements, up to
 * SUM_COMPND_MAX characters.  If the elements don't fit, include a "..."
 * at the end of the string.
 */

static char *
sum_compound4args(void)
{
	static char buf[SUM_COMPND_MAX + 2]; /* 1 for null, 1 for overflow */
	int numops;
	const size_t buflen = sizeof (buf);
	char *bp;
	nfs_argop4 one_op;
	uint32_t minor_version;

	buf[0] = '\0';

	if (setjmp(xdr_err)) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf),
		    nfs4_fragged_rpc ? nfs4err_fragrpc : nfs4err_xdrfrag);
		return (buf);
	}

	/*
	 * might be nice to print minor version, but doesn't
	 * seem like very useful info for summary mode
	 */
	if (!xdr_uint32_t(&xdrm, &minor_version))
		longjmp(xdr_err, 1);

	numops = getxdr_long();
	bp = buf;
	while (numops-- > 0) {
		char *operand;

		bzero(&one_op, sizeof (one_op));

		if (!xdr_nfs_argop4(&xdrm, &one_op)) {
			xdr_free(xdr_nfs_argop4, (char *)&one_op);
			longjmp(xdr_err, 1);
		}
		snprintf(bp, buflen - (bp - buf), "%s ",
		    opcode_name(one_op.argop));
		bp += strlen(bp);

		operand = sum_operand(&one_op);
		if (strlen(operand) > 0) {
			snprintf(bp, buflen - (bp - buf), "%s ", operand);
			bp += strlen(bp);
		}

		/* nfs4_skip_bytes set by xdr_nfs4_argop4 */
		if (nfs4_skip_bytes != 0)
			nfs4_xdr_skip(nfs4_skip_bytes);

		xdr_free(xdr_nfs_argop4, (char *)&one_op);

		/* add "..." if past the "end" of the buffer */
		if (bp - buf > SUM_COMPND_MAX) {
			strcpy(buf + SUM_COMPND_MAX - strlen("..."),
			    "...");
			break;
		}
	}

	return (buf);
}

static void
nfs4_xdr_skip(int nbytes)
{
	int resid, off, len, cur_pos, new_pos;

	len = RNDUP(nbytes);
	cur_pos = xdr_getpos(&xdrm);

	/*
	 * Time to skip over the rd/wr data.  If the
	 * rd/wr data is completely contained in the first
	 * frag, we must skip over it to process the rest of
	 * the packet.
	 *
	 * nfs4_pkt_start: XDR position of start of NFS4 compound
	 * nfs4_pkt_len: number of bytes in pkt relative to
	 *		 nfs4_pkt_start
	 *
	 * cur_pos: current XDR position
	 * off: current XDR position relative to nfs4_pkt_start
	 * resid: number of unprocessed bytes in current pkt
	 *	  (relative to cur_pos/off)
	 *
	 * If nbytes <= resid, then we must skip over the rd/wr
	 * bytes so we can read the next op/compound in this
	 * packet.  Otherwise, set the fragged flag so we can
	 * display the fragged_rpc message.
	 */
	off = cur_pos - nfs4_pkt_start;
	resid = nfs4_pkt_len - off;

	/*
	 * set nfs4_fragged_rpc if the requested number of "skip"
	 * bytes is larger than the bytes remaining in the XDR
	 * stream/current packet.  The global is reset to 0 at
	 * start of interpret_nfs4.
	 */
	new_pos = cur_pos + ((nfs4_fragged_rpc = len > resid) ? resid : len);

	/* there's nothing to do for error case (if it fails pkt is doomed) */
	xdr_setpos(&xdrm, new_pos);
}


/*
 * Return the names and arguments of the oplist elements, up to
 * SUM_COMPND_MAX characters.  If the elements don't fit, include a "..."
 * at the end of the string.
 */
static char *
sum_cb_compound4args(void)
{
	static char buf[SUM_COMPND_MAX + 2]; /* 1 for null, 1 for overflow */
	int numops;
	const size_t buflen = sizeof (buf);
	char *bp;
	nfs_cb_argop4 one_op;
	uint32_t minor_version, callback_ident;

	buf[0] = '\0';
	if (setjmp(xdr_err)) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), "<XDR Error or Fragmented"
		    " RPC>");
		return (buf);
	}

	/*
	 * might be nice to print minor version, but doesn't
	 * seem like very useful info for summary mode
	 */
	if (!xdr_uint32_t(&xdrm, &minor_version))
		longjmp(xdr_err, 1);

	/* print callback_ident */
	if (!xdr_uint32_t(&xdrm, &callback_ident))
		longjmp(xdr_err, 1);
	snprintf(buf, buflen, "CBID=%u ", callback_ident);

	bp = buf + strlen(buf);
	numops = getxdr_long();

	while (numops-- > 0) {
		char *operand;

		bzero(&one_op, sizeof (one_op));
		if (!xdr_nfs_cb_argop4(&xdrm, &one_op)) {
			xdr_free(xdr_nfs_cb_argop4, (char *)&one_op);
			longjmp(xdr_err, 1);
		}

		snprintf(bp, buflen - (bp - buf), "%s ",
		    cb_opcode_name(one_op.argop));
		bp += strlen(bp);
		operand = sum_cb_operand(&one_op);
		if (strlen(operand) > 0) {
			snprintf(bp, buflen - (bp - buf), "%s ", operand);
			bp += strlen(bp);
		}

		xdr_free(xdr_nfs_cb_argop4, (char *)&one_op);

		/* add "..." if past the "end" of the buffer */
		if (bp - buf > SUM_COMPND_MAX) {
			strcpy(buf + SUM_COMPND_MAX - strlen("..."),
			    "...");
			break;
		}
	}

	return (buf);
}

/*
 * Return the summarized argument list for the given nfs_argop4.
 */

static char *
sum_operand(nfs_argop4 *opp)
{
	static char buf[1024];
	void (*fmtproc)(char *, size_t, void *);

	buf[0] = '\0';
	if (opp->argop < num_opcodes) {
		fmtproc = opcode_info[opp->argop].sumarg;
		if (fmtproc != NULL)
			fmtproc(buf, sizeof (buf), &opp->nfs_argop4_u);
	}

	return (buf);
}

/*
 * Return the summarized argument list for the given nfs_argop4.
 */

static char *
sum_cb_operand(nfs_cb_argop4 *opp)
{
	static char buf[1024];
	void (*fmtproc)(char *, size_t, void *);

	buf[0] = '\0';
	if (opp->argop < cb_num_opcodes) {
		fmtproc = cb_opcode_info[opp->argop].sumarg;
		if (fmtproc != NULL)
			fmtproc(buf, sizeof (buf), &opp->nfs_cb_argop4_u);
	}

	return (buf);
}

/*
 * Print details about the nfs_argop4 that is next in the XDR stream.
 */

static void
detail_nfs_argop4(void)
{
	int numops;
	nfs_argop4 one_op;
	void (*fmtproc)(void *);
	uint32_t minor_version;

	if (!xdr_uint32_t(&xdrm, &minor_version))
		longjmp(xdr_err, 1);

	(void) sprintf(get_line(0, 0), "Minor version = %u",
	    minor_version);

	numops = getxdr_long();
	(void) sprintf(get_line(0, 0), "Number of operations = %d",
	    numops);

	while (numops-- > 0) {
		bzero(&one_op, sizeof (one_op));

		if (!xdr_nfs_argop4(&xdrm, &one_op)) {
			xdr_free(xdr_nfs_argop4, (char *)&one_op);
			longjmp(xdr_err, 1);
		}

		get_line(0, 0);		/* blank line to separate ops */
		sprintf(get_line(0, 0), "Op = %d (%s)",
		    one_op.argop, opcode_name(one_op.argop));
		if (one_op.argop < num_opcodes) {
			fmtproc = opcode_info[one_op.argop].dtlarg;
			if (fmtproc != NULL)
				fmtproc(&one_op.nfs_argop4_u);
		}

		/* nfs4_skip_bytes set by xdr_nfs_argop4() */
		if (nfs4_skip_bytes)
			nfs4_xdr_skip(nfs4_skip_bytes);

		xdr_free(xdr_nfs_argop4, (char *)&one_op);
	}
}


/*
 * Print details about the nfs_argop4 that is next in the XDR stream.
 */
static void
detail_cb_argop4(void)
{
	int numops;
	nfs_cb_argop4 one_op;
	void (*fmtproc)(void *);
	uint32_t minor_version, callback_ident;

	if (!xdr_uint32_t(&xdrm, &minor_version))
		longjmp(xdr_err, 1);
	(void) sprintf(get_line(0, 0), "Minor version = %u",
	    minor_version);

	if (!xdr_uint32_t(&xdrm, &callback_ident))
		longjmp(xdr_err, 1);
	(void) sprintf(get_line(0, 0), "Callback Ident = %u",
	    callback_ident);

	numops = getxdr_long();
	(void) sprintf(get_line(0, 0), "Number of operations = %d",
	    numops);

	while (numops-- > 0) {
		bzero(&one_op, sizeof (one_op));
		if (!xdr_nfs_cb_argop4(&xdrm, &one_op)) {
			xdr_free(xdr_nfs_cb_argop4, (char *)&one_op);
			longjmp(xdr_err, 1);
		}

		get_line(0, 0);		/* blank line to separate ops */
		sprintf(get_line(0, 0), "Op = %d (%s)",
		    one_op.argop, cb_opcode_name(one_op.argop));
		if (one_op.argop < cb_num_opcodes) {
			fmtproc = cb_opcode_info[one_op.argop].dtlarg;
			if (fmtproc != NULL)
				fmtproc(&one_op.nfs_cb_argop4_u);
		}

		xdr_free(xdr_nfs_cb_argop4, (char *)&one_op);
	}
}

/*
 * component_name: return a printable string for the given component4.  I'm
 * leaving this as a separate function (as opposed to having the callers
 * call utf8localize() directly) in case the definition of component4
 * changes.
 */

static char *
component_name(component4 *cp)
{
	return (utf8localize(cp));
}

/*
 * linktext_name.  cf. component_name().
 */

static char *
linktext_name(linktext4 *lp)
{
	return (utf8localize(lp));
}

/*
 * stable_how4_name: return a string for "how".
 */

static char *
stable_how4_name(stable_how4 how)
{
	char *result;

	switch (how) {
	case UNSTABLE4:
		result = "ASYNC";
		break;
	case DATA_SYNC4:
		result = "DSYNC";
		break;
	case FILE_SYNC4:
		result = "FSYNC";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * sum_open_share_access: return a string corresponding to the
 * given OPEN share access bitmask.
 */

static char *
sum_open_share_access(int32_t mask)
{
	char *result;

	switch (mask) {
	case 0:
		result = "N";
		break;
	case OPEN4_SHARE_ACCESS_READ:
		result = "R";
		break;
	case OPEN4_SHARE_ACCESS_WRITE:
		result = "W";
		break;
	case OPEN4_SHARE_ACCESS_BOTH:
		result = "RW";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * sum_open_share_deny: return a string corresponding to the
 * given OPEN share deny bitmask.
 */

static char *
sum_open_share_deny(int32_t mask)
{
	char *result;

	switch (mask) {
	case OPEN4_SHARE_DENY_NONE:
		result = "N";
		break;
	case OPEN4_SHARE_DENY_READ:
		result = "R";
		break;
	case OPEN4_SHARE_DENY_WRITE:
		result = "W";
		break;
	case OPEN4_SHARE_DENY_BOTH:
		result = "RW";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

static int
special_stateid(stateid4 *stateid)
{

	if (! memcmp(stateid, &spec_stateid_0, sizeof (*stateid)))
		return (0);

	if (! memcmp(stateid, &spec_stateid_1, sizeof (*stateid)))
		return (1);

	return (-1);
}

char *
cmn_sum_stateid(stateid4 *stateid, char *prefix)
{
	static char buf[32];
	int spec;

	if ((spec = special_stateid(stateid)) < 0)
		snprintf(buf, sizeof (buf), "%s%04X:%u", prefix,
		    stateid_hash(stateid), stateid->seqid);
	else
		snprintf(buf, sizeof (buf), "%s%s", prefix,
		    spec == 0 ? "SPC0" : (spec == 1 ? "SPC1" : "SPC?"));
	return (buf);
}

void
cmn_detail_stateid(stateid4 *stateid, char *prefix)
{
	int spec;
	char seqstr[32] = {0};

	spec = special_stateid(stateid);

	if (spec < 0)
		sprintf(get_line(0, 0), "%sState ID hash = %04X",
		    prefix, stateid_hash(stateid));
	else
		sprintf(get_line(0, 0), "%sState ID hash = %s",	prefix,
		    spec == 0 ? "SPECIAL_0" :
		    (spec == 1 ? "SPECIAL_1" : "SPECIAL_?"));

	sprintf(get_line(0, 0), "    len = %u    val = %s",
	    sizeof (stateid->other),
	    tohex(stateid->other, sizeof (stateid->other)));

	/*
	 * If spec 0/1 stateid, print seqid in hex; otherwise,
	 * use decimal.  This makes it more clear how spec stateids
	 * are constructed [obvious that either all bits are 0, or all
	 * bits are 1].
	 */
	if (spec == -1)
		sprintf(seqstr, "%d", stateid->seqid);
	else
		sprintf(seqstr, "%08X", stateid->seqid);

	sprintf(get_line(0, 0), "    %sState ID Sequence ID = %s",
	    prefix, seqstr);
}

static char *
sum_lock_denied(LOCK4denied *denied)
{
	static char buf[64];

	sprintf(buf, "%s %llu %llu LO=%04X",
	    sum_lock_type_name(denied->locktype),
	    denied->offset, denied->length,
	    owner_hash(&denied->owner.owner));

	return (buf);
}

static void
detail_lock_denied(LOCK4denied *denied)
{
	sprintf(get_line(0, 0), "Type = %s", lock_type_name(denied->locktype));
	detail_lock_owner(&denied->owner);
	sprintf(get_line(0, 0), "Offset = %llu", denied->offset);
	sprintf(get_line(0, 0), "Length = %llu", denied->length);
}

/*
 * sum_createhow4: return the string name of "how".
 */

static char *
createhow4_name(createhow4 *crtp)
{
	char *result;

	switch (crtp->mode) {
	case UNCHECKED4:
		result = "UNCHECKED";
		break;
	case GUARDED4:
		result = "GUARDED";
		break;
	case EXCLUSIVE4:
		result = "EXCLUSIVE";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * detail_createhow4: print detail information about "how".
 */

static void
detail_createhow4(createhow4 *crtp)
{
	sprintf(get_line(0, 0), "Method = %s",
	    createhow4_name(crtp));

	switch (crtp->mode) {
	case UNCHECKED4:
	case GUARDED4:
		detail_fattr4(&crtp->createhow4_u.createattrs);
		break;
	case EXCLUSIVE4:
		sprintf(get_line(0, 0), "  Verifier = %s",
		    tohex(crtp->createhow4_u.createverf,
		    NFS4_VERIFIER_SIZE));
		break;
	}
}

static void
detail_createtype4(createtype4 *crtp)
{
	sprintf(get_line(0, 0), "Type = %s",
	    detail_type_name(crtp->type));
	switch (crtp->type) {
	case NF4LNK:
		sprintf(get_line(0, 0), "Linkdata = %s",
		    utf8localize(&crtp->createtype4_u.linkdata));
		break;
	case NF4BLK:
	case NF4CHR:
		sprintf(get_line(0, 0), "Specdata1 = %04x Specdata2 = %04x",
		    crtp->createtype4_u.devdata.specdata1,
		    crtp->createtype4_u.devdata.specdata2);
		break;
	default:
		break;
	}
}

static void
sumarg_access(char *buf, size_t buflen, void *obj)
{
	ACCESS4args *args = (ACCESS4args *)obj;

	sum_access4(buf, buflen, args->access);
}

static void
dtlarg_access(void *obj)
{
	ACCESS4args *args = (ACCESS4args *)obj;

	detail_access4("Access bits", args->access);
}

static void
sumarg_close(char *buf, size_t buflen, void *obj)
{
	CLOSE4args *args = (CLOSE4args *)obj;

	snprintf(buf, buflen, "SQ=%u %s",
	    args->seqid, sum_open_stateid(&args->open_stateid));
}

static void
dtlarg_close(void *obj)
{
	CLOSE4args *args = (CLOSE4args *)obj;

	detail_open_stateid(&args->open_stateid);
	sprintf(get_line(0, 0), "Sequence ID = %u", args->seqid);
}

static void
sumarg_commit(char *buf, size_t buflen, void *obj)
{
	COMMIT4args *args = (COMMIT4args *)obj;

	snprintf(buf, buflen, "at %llu for %u ", args->offset,
	    args->count);
}

static void
dtlarg_commit(void *obj)
{
	COMMIT4args *args = (COMMIT4args *)obj;

	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Count = %u", args->count);
}

static void
sumarg_compnt(char *buf, size_t buflen, void *obj)
{
	component4 *comp = (component4 *)obj;

	snprintf(buf, buflen, "%s", component_name(comp));
}

static void
dtlarg_compnt(void *obj)
{
	component4 *comp = (component4 *)obj;

	sprintf(get_line(0, 0), "Name = %s", component_name(comp));
}

static void
sumarg_create(char *buf, size_t buflen, void *obj)
{
	CREATE4args *args = (CREATE4args *)obj;

	snprintf(buf, buflen, "%s %s ", component_name(&args->objname),
	    sum_type_name(args->objtype.type));
}

static void
dtlarg_create(void *obj)
{
	CREATE4args *args = (CREATE4args *)obj;

	sprintf(get_line(0, 0), "Name = %s", component_name(&args->objname));
	detail_createtype4(&args->objtype);
	detail_fattr4(&args->createattrs);
}

static void
sumarg_delprge(char *buf, size_t buflen, void *obj)
{
	DELEGPURGE4args *args = (DELEGPURGE4args *)obj;

	snprintf(buf, buflen, "%s", sum_clientid(args->clientid));
}

static void
dtlarg_delprge(void *obj)
{
	DELEGPURGE4args *args = (DELEGPURGE4args *)obj;

	detail_clientid(args->clientid);
}

static void
sumarg_delret(char *buf, size_t buflen, void *obj)
{
	DELEGRETURN4args *args = (DELEGRETURN4args *)obj;

	snprintf(buf, buflen, "%s", sum_deleg_stateid(&args->deleg_stateid));
}

static void
dtlarg_delret(void *obj)
{
	DELEGRETURN4args *args = (DELEGRETURN4args *)obj;

	detail_deleg_stateid(&args->deleg_stateid);
}

static void
sumarg_getattr(char *buf, size_t buflen, void *obj)
{
	GETATTR4args *args = (GETATTR4args *)obj;

	sum_attr_bitmap(buf, buflen, &args->attr_request);
}

static void
dtlarg_getattr(void *obj)
{
	GETATTR4args *args = (GETATTR4args *)obj;

	detail_attr_bitmap("", &args->attr_request, NULL);
}

static void
sumarg_cb_getattr(char *buf, size_t buflen, void *obj)
{
	CB_GETATTR4args *args = (CB_GETATTR4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "%s ", sum_fh4(&args->fh));
	bp += strlen(bp);
	sum_attr_bitmap(bp, buflen - (bp - buf), &args->attr_request);
}

static void
dtlarg_cb_getattr(void *obj)
{
	CB_GETATTR4args *args = (CB_GETATTR4args *)obj;

	detail_fh4(&args->fh, "");
	detail_attr_bitmap("", &args->attr_request, NULL);
}

static void
sumarg_cb_recall(char *buf, size_t buflen, void *obj)
{
	CB_RECALL4args *args = (CB_RECALL4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "%s %s TR=%s", sum_fh4(&args->fh),
	    sum_stateid(&args->stateid), args->truncate ? "T" : "F");
}

static void
dtlarg_cb_recall(void *obj)
{
	CB_RECALL4args *args = (CB_RECALL4args *)obj;

	detail_fh4(&args->fh, "");
	detail_stateid(&args->stateid);
	sprintf(get_line(0, 0), "Truncate = %s",
	    args->truncate ? "True" : "False");
}


/*
 * name openhow seqid claim access deny owner
 */
static void
sumarg_open(char *buf, size_t buflen, void *obj)
{
	OPEN4args *args = (OPEN4args *)obj;
	char *bp = buf;
	int blen = buflen, len;

	sum_name(bp, buflen, &args->claim);
	bp += (len = strlen(bp));
	blen -= len;

	sum_openflag(bp, blen, &args->openhow);
	bp += (len = strlen(bp));
	blen -= len;

	snprintf(bp, blen, " SQ=%u", args->seqid);
	bp += (len = strlen(bp));
	blen -= len;

	sum_claim(bp, blen, &args->claim);
	bp += (len = strlen(bp));
	blen -= len;

	snprintf(bp, blen, " AC=%s DN=%s OO=%04X",
	    sum_open_share_access(args->share_access),
	    sum_open_share_deny(args->share_deny),
	    owner_hash(&args->owner.owner));
}

static void
dtlarg_open(void *obj)
{
	OPEN4args *args = (OPEN4args *)obj;

	detail_claim(&args->claim);
	detail_openflag(&args->openhow);
	detail_open_owner(&args->owner);
	sprintf(get_line(0, 0), "Sequence ID = %u", args->seqid);
	sprintf(get_line(0, 0), "Access = 0x%x (%s)",
	    args->share_access, sum_open_share_access(args->share_access));
	sprintf(get_line(0, 0), "Deny   = 0x%x (%s)",
	    args->share_deny, sum_open_share_access(args->share_deny));
}

static void
sumarg_openattr(char *buf, size_t buflen, void *obj)
{
	OPENATTR4args *args = (OPENATTR4args *)obj;

	snprintf(buf, buflen, "CD=%s",
	    args->createdir ? "T" : "F");
}

static void
dtlarg_openattr(void *obj)
{
	OPENATTR4args *args = (OPENATTR4args *)obj;

	sprintf(get_line(0, 0), "CreateDir = %s",
	    args->createdir ? "True" : "False");
}

static void
sumarg_open_confirm(char *buf, size_t buflen, void *obj)
{
	char *bp = buf;
	OPEN_CONFIRM4args *args = (OPEN_CONFIRM4args *)obj;

	snprintf(bp, buflen, "SQ=%u %s", args->seqid,
	    sum_open_stateid(&args->open_stateid));
}

static void
dtlarg_open_confirm(void *obj)
{
	OPEN_CONFIRM4args *args = (OPEN_CONFIRM4args *)obj;

	sprintf(get_line(0, 0), "Sequence ID = %u", args->seqid);
	detail_open_stateid(&args->open_stateid);
}

static void
sumarg_open_downgrd(char *buf, size_t buflen, void *obj)
{
	OPEN_DOWNGRADE4args *args = (OPEN_DOWNGRADE4args *)obj;

	snprintf(buf, buflen, "SQ=%u %s AC=%s DN=%s",
	    args->seqid, sum_open_stateid(&args->open_stateid),
	    sum_open_share_access(args->share_access),
	    sum_open_share_deny(args->share_deny));
}

static void
dtlarg_open_downgrd(void *obj)
{
	OPEN_DOWNGRADE4args *args = (OPEN_DOWNGRADE4args *)obj;

	sprintf(get_line(0, 0), "Open Sequence ID = %u", args->seqid);
	detail_open_stateid(&args->open_stateid);
	sprintf(get_line(0, 0), "Access = 0x%x (%s)",
	    args->share_access, sum_open_share_access(args->share_access));
	sprintf(get_line(0, 0), "Deny   = 0x%x (%s)",
	    args->share_deny, sum_open_share_access(args->share_deny));
}

static void
sumarg_putfh(char *buf, size_t buflen, void *obj)
{
	PUTFH4args *args = (PUTFH4args *)obj;

	snprintf(buf, buflen, "%s", sum_fh4(&args->object));
}

static void
dtlarg_putfh(void *obj)
{
	PUTFH4args *args = (PUTFH4args *)obj;

	detail_fh4(&args->object, "");
}

static void
sumarg_link(char *buf, size_t buflen, void *obj)
{
	LINK4args *args = (LINK4args *)obj;

	snprintf(buf, buflen, "%s", component_name(&args->newname));
}

static void
dtlarg_link(void *obj)
{
	LINK4args *args = (LINK4args *)obj;

	sprintf(get_line(0, 0), "New name = %s",
	    component_name(&args->newname));
}

static void
sum_open_to_lock_owner(char *buf, int buflen, open_to_lock_owner4 *own)
{
	snprintf(buf, buflen, " OSQ=%u %s LSQ=%u LO=%04X", own->open_seqid,
	    sum_open_stateid(&own->open_stateid), own->lock_seqid,
	    owner_hash(&own->lock_owner.owner));
}

static void
sum_exist_lock_owner(char *buf, int buflen, exist_lock_owner4 *own)
{
	snprintf(buf, buflen, " LSQ=%u %s", own->lock_seqid,
	    sum_lock_stateid(&own->lock_stateid));
}

static void
sum_locker(char *buf, size_t len, locker4 *lk)
{
	if (lk->new_lock_owner == TRUE)
		sum_open_to_lock_owner(buf, len, &lk->locker4_u.open_owner);
	else
		sum_exist_lock_owner(buf, len, &lk->locker4_u.lock_owner);
}

static char *
sum_lock_type_name(enum nfs_lock_type4 type)
{
	char *result;

	switch (type) {
	case READ_LT:
		result = "RD";
		break;
	case WRITE_LT:
		result = "WR";
		break;
	case READW_LT:
		result = "RDW";
		break;
	case WRITEW_LT:
		result = "WRW";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

static void
sumarg_lock(char *buf, size_t buflen, void *obj)
{
	LOCK4args *args = (LOCK4args *)obj;
	char *bp = buf;

	snprintf(buf, buflen, "%s%s%llu:%llu",
	    sum_lock_type_name(args->locktype),
	    args->reclaim ? " reclaim " : " ",
	    args->offset, args->length);

	bp += strlen(buf);
	sum_locker(bp, buflen - (bp - buf), &args->locker);
}

static void
detail_open_to_lock_owner(open_to_lock_owner4 *own)
{
	sprintf(get_line(0, 0), "Open Sequence ID = %u", own->open_seqid);
	detail_open_stateid(&own->open_stateid);
	sprintf(get_line(0, 0), "Lock Sequence ID = %u", own->lock_seqid);
	detail_lock_owner(&own->lock_owner);
}

static void
detail_exist_lock_owner(exist_lock_owner4 *own)
{
	detail_lock_stateid(&own->lock_stateid);
	sprintf(get_line(0, 0), "Lock Sequence ID = %u", own->lock_seqid);
}

static void
detail_locker(locker4 *lk)
{
	if (lk->new_lock_owner == TRUE)
		detail_open_to_lock_owner(&lk->locker4_u.open_owner);
	else
		detail_exist_lock_owner(&lk->locker4_u.lock_owner);
}

static void
dtlarg_lock(void *obj)
{
	LOCK4args *args = (LOCK4args *)obj;

	sprintf(get_line(0, 0), "Type = %s", lock_type_name(args->locktype));
	sprintf(get_line(0, 0), "Reclaim = %s",
	    args->reclaim ? "TRUE" : "FALSE");
	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Length = %llu", args->length);
	detail_locker(&args->locker);
}

static void
sumarg_lockt(char *buf, size_t buflen, void *obj)
{
	LOCKT4args *args = (LOCKT4args *)obj;

	snprintf(buf, buflen, "R=%llu:%llu",
	    args->offset, args->length);
}

static void
dtlarg_lockt(void *obj)
{
	LOCKT4args *args = (LOCKT4args *)obj;

	sprintf(get_line(0, 0), "Type = %s", lock_type_name(args->locktype));
	detail_lock_owner(&args->owner);
	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Length = %llu", args->length);
}

static void
sumarg_locku(char *buf, size_t buflen, void *obj)
{
	LOCKU4args *args = (LOCKU4args *)obj;

	snprintf(buf, buflen, "R=%llu:%llu LSQ=%u %s",
	    args->offset, args->length, args->seqid,
	    sum_lock_stateid(&args->lock_stateid));
}


static void
dtlarg_locku(void *obj)
{
	LOCKU4args *args = (LOCKU4args *)obj;

	sprintf(get_line(0, 0), "Type = %s", lock_type_name(args->locktype));
	sprintf(get_line(0, 0), "Sequence ID = %u", args->seqid);
	detail_lock_stateid(&args->lock_stateid);
	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Length = %llu", args->length);
}

static void
sumarg_lookup(char *buf, size_t buflen, void *obj)
{
	LOOKUP4args *args = (LOOKUP4args *)obj;

	sum_compname4(buf, buflen, &args->objname);
}

static void
dtlarg_lookup(void *obj)
{
	LOOKUP4args *args = (LOOKUP4args *)obj;

	detail_compname4(&args->objname);
}

static void
sumarg_read(char *buf, size_t buflen, void *obj)
{
	READ4args *args = (READ4args *)obj;

	snprintf(buf, buflen, "%s at %llu for %u",
	    sum_stateid(&args->stateid), args->offset, args->count);
}

static void
dtlarg_read(void *obj)
{
	READ4args *args = (READ4args *)obj;

	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Count = %u", args->count);
	detail_stateid(&args->stateid);
}

static void
sumarg_readdir(char *buf, size_t buflen, void *obj)
{
	READDIR4args *args = (READDIR4args *)obj;

	snprintf(buf, buflen, "Cookie=%llu (%s) for %u/%u",
	    args->cookie, tohex(args->cookieverf, NFS4_VERIFIER_SIZE),
	    args->dircount, args->maxcount);
}

static void
dtlarg_readdir(void *obj)
{
	READDIR4args *args = (READDIR4args *)obj;

	sprintf(get_line(0, 0), "Cookie = %llu", args->cookie);
	sprintf(get_line(0, 0), "Verifier = %s",
	    tohex(args->cookieverf, NFS4_VERIFIER_SIZE));
	sprintf(get_line(0, 0), "Dircount = %u", args->dircount);
	sprintf(get_line(0, 0), "Maxcount = %u", args->maxcount);
	detail_attr_bitmap("", &args->attr_request, NULL);
}

static void
dtlarg_release_lkown(void *obj)
{
	RELEASE_LOCKOWNER4args *args = (RELEASE_LOCKOWNER4args *)obj;

	detail_lock_owner(&args->lock_owner);
}

static void
sumarg_release_lkown(char *buf, size_t buflen, void *obj)

{
	RELEASE_LOCKOWNER4args *args = (RELEASE_LOCKOWNER4args *)obj;

	snprintf(buf, buflen, "LO=%04X", owner_hash(&args->lock_owner.owner));
}

static void
sumarg_rename(char *buf, size_t buflen, void *obj)
{
	RENAME4args *args = (RENAME4args *)obj;

	snprintf(buf, buflen, "%s to %s",
	    component_name(&args->oldname),
	    component_name(&args->newname));
}

static void
dtlarg_rename(void *obj)
{
	RENAME4args *args = (RENAME4args *)obj;

	sprintf(get_line(0, 0), "Old name = %s",
	    component_name(&args->oldname));
	sprintf(get_line(0, 0), "New name = %s",
	    component_name(&args->newname));
}

static void
sumarg_renew(char *buf, size_t buflen, void *obj)
{
	RENEW4args *args = (RENEW4args *)obj;

	snprintf(buf, buflen, "%s", sum_clientid(args->clientid));
}
static void
dtlarg_renew(void *obj)
{
	RENEW4args *args = (RENEW4args *)obj;

	detail_clientid(args->clientid);
}

static void
sumarg_secinfo(char *buf, size_t buflen, void *obj)
{
	SECINFO4args *args = (SECINFO4args *)obj;

	snprintf(buf, buflen, "%s",
	    component_name(&args->name));
}

static void
dtlarg_secinfo(void *obj)
{
	SECINFO4args *args = (SECINFO4args *)obj;

	sprintf(get_line(0, 0), "Name = %s",
	    component_name(&args->name));
}

static void
sumarg_setattr(char *buf, size_t buflen, void *obj)
{
	SETATTR4args *args = (SETATTR4args *)obj;

	snprintf(buf, buflen, "%s", sum_stateid(&args->stateid));
}

static void
dtlarg_setattr(void *obj)
{
	SETATTR4args *args = (SETATTR4args *)obj;

	detail_stateid(&args->stateid);
	detail_fattr4(&args->obj_attributes);
}

static void
sumarg_setclid(char *buf, size_t buflen, void *obj)
{
	SETCLIENTID4args *args = (SETCLIENTID4args *)obj;

	snprintf(buf, buflen, "Prog=%u ID=%s Addr=%s CBID=%u",
	    args->callback.cb_program,
	    args->callback.cb_location.na_r_netid,
	    args->callback.cb_location.na_r_addr, args->callback_ident);
}

static void
dtlarg_setclid(void *obj)
{
	SETCLIENTID4args *args = (SETCLIENTID4args *)obj;

	sprintf(get_line(0, 0), "Verifier=%s",
	    tohex(args->client.verifier, NFS4_VERIFIER_SIZE));
	sprintf(get_line(0, 0), "ID = (%d) %s",
	    args->client.id.id_len,
	    tohex(args->client.id.id_val, args->client.id.id_len));

	sprintf(get_line(0, 0), "Callback Program = %u",
	    args->callback.cb_program);
	sprintf(get_line(0, 0), "Callback Net ID = %s",
	    args->callback.cb_location.na_r_netid);
	sprintf(get_line(0, 0), "Callback Addr = %s",
	    args->callback.cb_location.na_r_addr);
	sprintf(get_line(0, 0), "Callback Ident = %u", args->callback_ident);
}

static void
sumarg_setclid_cfm(char *buf, size_t buflen, void *obj)
{
	SETCLIENTID_CONFIRM4args *args = (SETCLIENTID_CONFIRM4args *)obj;

	snprintf(buf, buflen, "%s CFV=%s", sum_clientid(args->clientid),
	    tohex(args->setclientid_confirm, NFS4_VERIFIER_SIZE));
}

static void
dtlarg_setclid_cfm(void *obj)
{
	SETCLIENTID_CONFIRM4args *args = (SETCLIENTID_CONFIRM4args *)obj;

	detail_clientid(args->clientid);
	sprintf(get_line(0, 0), "Set Client ID Confirm Verifier = %s",
	    tohex(args->setclientid_confirm, NFS4_VERIFIER_SIZE));
}


static void
dtlarg_verify(void *obj)
{
	NVERIFY4args *args = (NVERIFY4args *)obj;

	detail_fattr4(&args->obj_attributes);
}

static void
sumarg_write(char *buf, size_t buflen, void *obj)
{
	WRITE4args *args = (WRITE4args *)obj;

	snprintf(buf, buflen, "%s at %llu for %u",
	    sum_stateid(&args->stateid), args->offset, args->data.data_len);
}

static void
dtlarg_write(void *obj)
{
	WRITE4args *args = (WRITE4args *)obj;

	sprintf(get_line(0, 0), "Offset = %llu", args->offset);
	sprintf(get_line(0, 0), "Count = %u", args->data.data_len);
	sprintf(get_line(0, 0), "Stable = %s", stable_how4_name(args->stable));
	detail_stateid(&args->stateid);
}

char *
sum_fh4(nfs_fh4 *fh)
{
	static char buf[20];

	sprintf(buf, "FH=%04X", fh4_hash(fh));

	return (buf);
}

void
detail_fh4(nfs_fh4 *fh, char *label)
{
	int i;
	uchar_t *cp;
	char *bufp;

	sprintf(get_line(0, 0), "%sFile handle = [%04X]", label, fh4_hash(fh));
	bufp = get_line(0, 0);
	sprintf(bufp, "(%d) ", fh->nfs_fh4_len);
	bufp += strlen(bufp);
	/* XXX use tohex()? */
	for (i = 0, cp = (uchar_t *)fh->nfs_fh4_val;
	    i < fh->nfs_fh4_len;
	    i++, cp++) {
		if (i != 0 && i % 32 == 0)
			bufp = get_line(0, 0);
		sprintf(bufp, "%02x", *cp);
		bufp += strlen(bufp);
	}
}

static void
detail_fattr4(fattr4 *attrp)
{
	unpkd_attrmap_t provided;
	uint_t attrnum;
	XDR attrxdr;
	jmp_buf old_errbuf;

	xdrmem_create(&attrxdr, attrp->attr_vals.attrlist4_val,
	    attrp->attr_vals.attrlist4_len, XDR_DECODE);

	bcopy(xdr_err, old_errbuf, sizeof (old_errbuf));
	if (setjmp(xdr_err)) {
		sprintf(get_line(0, 0), "<attr_vals too short>");
		goto done;
	}

	detail_attr_bitmap("", &attrp->attrmask, &provided);
	for (attrnum = 0; attrnum < MAX_ATTRIBUTES; attrnum++) {
		if (provided.map[attrnum]) {
			attr_info[attrnum].prt_details(&attrxdr);
		}
	}

done:
	bcopy(old_errbuf, xdr_err, sizeof (old_errbuf));
}

static void
detail_threshold_item4(threshold_item4 *thi)
{
	XDR txdr;
	jmp_buf old_errbuf;
	uint32_t b, val;

	sprintf(get_line(0, 0), "    %s",
	    detail_lotype_name(thi->thi_layout_type));

	if (thi->thi_hintset.bitmap4_len == 0)
		return;

	b = ((uint32_t *)(thi->thi_hintset.bitmap4_val))[0];
	sprintf(get_line(0, 0), "      Threshold hint bitmap = 0x%08x", b);

	xdrmem_create(&txdr, thi->thi_hintlist.thi_hintlist_val,
	    thi->thi_hintlist.thi_hintlist_len, XDR_DECODE);

	bcopy(xdr_err, old_errbuf, sizeof (old_errbuf));
	if (setjmp(xdr_err)) {
		sprintf(get_line(0, 0), "<attr_vals too short>");
		goto done;
	}

	if (b & TH4_READ_SIZE_MASK) {
		if (!xdr_uint32_t(&txdr, &val))
			longjmp(xdr_err, 1);
		sprintf(get_line(0, 0), "        Read size = %u", val);
	}
	if (b & TH4_READ_IOSIZE_MASK) {
		if (!xdr_uint32_t(&txdr, &val))
			longjmp(xdr_err, 1);
		sprintf(get_line(0, 0), "        Read IO size = %u", val);
	}
	if (b & TH4_WRITE_SIZE_MASK) {
		if (!xdr_uint32_t(&txdr, &val))
			longjmp(xdr_err, 1);
		sprintf(get_line(0, 0), "        Write size = %u", val);
	}
	if (b & TH4_WRITE_IOSIZE_MASK) {
		if (!xdr_uint32_t(&txdr, &val))
			longjmp(xdr_err, 1);
		sprintf(get_line(0, 0), "        Write IO size = %u", val);
	}
done:
	bcopy(old_errbuf, xdr_err, sizeof (old_errbuf));
}

static void
sum_attr_bitmap(char *buf, size_t buflen, bitmap4 *mapp)
{
	uint_t num_words;
	char *bp;
	size_t curlen, remaining;

	buf[0] = '\0';
	for (num_words = 0; num_words < mapp->bitmap4_len; num_words++) {
		curlen = strlen(buf);
		if (curlen + sizeof ("<Too Long>") >= buflen) {
			strcpy(buf + buflen - sizeof ("<Too Long>"),
			    "<Too Long>");
			return;
		}
		bp = buf + curlen;
		remaining = buflen - curlen;
		snprintf(bp, remaining,
		    num_words == 0 ? "%x" : " %x",
		    mapp->bitmap4_val[num_words]);
	}
}

/*
 * Print detail information for the given attribute bitmap, and fill in the
 * unpacked version of the map if "unpacked" is non-null.  Returns the
 * number of bytes in the bitmap.  "prefix" is an initial string that is
 * printed at the front of each line.
 */

static void
detail_attr_bitmap(char *prefix, bitmap4 *bitp, unpkd_attrmap_t *unpacked)
{
	uint_t num_words;
	uint32_t *wp;
	uint_t byte_num;

	if (unpacked != NULL)
		memset(unpacked, 0, sizeof (unpkd_attrmap_t));

	/*
	 * Break the bitmap into octets, then print in hex and
	 * symbolically.
	 */

	for (num_words = 0, wp = bitp->bitmap4_val;
	    num_words < bitp->bitmap4_len;
	    num_words++, wp++) {
		for (byte_num = 0; byte_num < 4; byte_num++) {
			uchar_t val = (*wp) >> (byte_num * 8);
			char *buf = get_line(0, 0);
			uint_t attrnum;
			int bit;

			sprintf(buf, "%s  0x%02x  ", prefix, val);
			attrnum = num_words * 32 + byte_num * 8;
			for (bit = 7; bit >= 0; bit--) {
				if (val & (1 << bit)) {
					strcat(buf, " ");
					strcat(buf,
					    attr_name(attrnum + bit));
					if (unpacked != NULL)
						unpacked->map[attrnum + bit] =
						    1;
				}
			}
		}
	}
}

/*
 * Format the summary line results from a COMPOUND4 call.
 */

static void
sum_comp4res(char *line, char *(*sumres_fn)(void))
{
	nfsstat4 status;
	static utf8string tag;

	status = getxdr_long();
	if (!xdr_utf8string(&xdrm, &tag))
		longjmp(xdr_err, 1);

	sprintf(line, "(%.20s) %s %s", utf8localize(&tag),
	    status_name(status), sumres_fn());

	xdr_free(xdr_utf8string, (char *)&tag);
}


/*
 * Return a set of summary strings for the result data that's next in the
 * XDR stream, up to SUM_COMPND_MAX characters.  If the strings don't fit,
 * include a "..." at the end of the string.
 */

static char *
sum_compound4res(void)
{
	static char buf[SUM_COMPND_MAX + 2]; /* 1 for null, 1 for overflow */
	int numres;
	const size_t buflen = sizeof (buf);
	char *bp;
	nfs_resop4 one_res;

	buf[0] = '\0';
	if (setjmp(xdr_err)) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf),
		    nfs4_fragged_rpc ? nfs4err_fragrpc : nfs4err_xdrfrag);
		return (buf);
	}

	numres = getxdr_long();
	bp = buf;
	while (numres-- > 0) {
		char *result;

		bzero(&one_res, sizeof (one_res));

		if (!xdr_nfs_resop4(&xdrm, &one_res)) {
			xdr_free(xdr_nfs_resop4, (char *)&one_res);
			longjmp(xdr_err, 1);
		}

		snprintf(bp, buflen - (bp - buf), "%s ",
		    opcode_name(one_res.resop));
		bp += strlen(bp);

		result = sum_result(&one_res);
		if (strlen(result) > 0) {
			snprintf(bp, buflen - (bp - buf), "%s ", result);
			bp += strlen(bp);
		}

		/* nfs4_skip_bytes set by xdr_nfs4_argop4() */
		if (nfs4_skip_bytes != 0)
			nfs4_xdr_skip(nfs4_skip_bytes);

		xdr_free(xdr_nfs_resop4, (char *)&one_res);
		/* add "..." if past the "end" of the buffer */
		if (bp - buf > SUM_COMPND_MAX) {
			strcpy(buf + SUM_COMPND_MAX - strlen("..."),
			    "...");
			break;
		}
	}

	return (buf);
}


/*
 * Return a set of summary strings for the result data that's next in the
 * XDR stream, up to SUM_COMPND_MAX characters.  If the strings don't fit,
 * include a "..." at the end of the string.
 */

static char *
sum_cb_compound4res(void)
{
	static char buf[SUM_COMPND_MAX + 2]; /* 1 for null, 1 for overflow */
	int numres;
	const size_t buflen = sizeof (buf);
	char *bp;
	nfs_cb_resop4 one_res;

	buf[0] = '\0';
	if (setjmp(xdr_err)) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), "<XDR Error or Fragmented"
		    " RPC>");
		return (buf);
	}

	numres = getxdr_long();
	bp = buf;
	while (numres-- > 0) {
		bzero(&one_res, sizeof (one_res));
		if (!xdr_nfs_cb_resop4(&xdrm, &one_res)) {
			xdr_free(xdr_nfs_cb_resop4, (char *)&one_res);
			longjmp(xdr_err, 1);
		}
		snprintf(bp, buflen - (bp - buf), "%s %s ",
		    cb_opcode_name(one_res.resop),
		    sum_cb_result(&one_res));
		bp += strlen(bp);

		xdr_free(xdr_nfs_cb_resop4, (char *)&one_res);

		/* add "..." if past the "end" of the buffer */
		if (bp - buf > SUM_COMPND_MAX) {
			strcpy(buf + SUM_COMPND_MAX - strlen("..."),
			    "...");
			break;
		}
	}

	return (buf);
}


/*
 * Return the summarized results for the given resultdata.
 */

static char *
sum_result(nfs_resop4 *resp)
{
	static char buf[1024];
	void (*fmtproc)(char *, size_t, void *);

	buf[0] = '\0';
	if (resp->resop < num_opcodes)
		fmtproc = opcode_info[resp->resop].sumres;
	else if (resp->resop == OP_ILLEGAL)
		fmtproc = sum_nfsstat4;
	else
		fmtproc = NULL;

	if (fmtproc != NULL)
		fmtproc(buf, sizeof (buf), &resp->nfs_resop4_u);

	return (buf);
}

/*
 * Return the summarized results for the given resultdata.
 */

static char *
sum_cb_result(nfs_cb_resop4 *resp)
{
	static char buf[1024];
	void (*fmtproc)(char *, size_t, void *);

	buf[0] = '\0';
	if (resp->resop < cb_num_opcodes)
		fmtproc = cb_opcode_info[resp->resop].sumres;
	else if (resp->resop == OP_CB_ILLEGAL)
		fmtproc = sum_nfsstat4;
	else
		fmtproc = NULL;

	if (fmtproc != NULL)
		fmtproc(buf, sizeof (buf), &resp->nfs_cb_resop4_u);

	return (buf);
}


static void
dtl_change_info(char *msg, change_info4 *infop)
{
	sprintf(get_line(0, 0), "%s:", msg);
	sprintf(get_line(0, 0), "  Atomic = %s",
	    infop->atomic ? "TRUE" : "FALSE");
	detail_fattr4_change("  Before", infop->before);
	detail_fattr4_change("  After", infop->after);
}

static void
detail_fattr4_change(char *msg, fattr4_change chg)
{
	sprintf(get_line(0, 0), "%s: 0x%llx", msg, chg);
	/* XXX print as time_t, too? */
}

static void
sum_nfsstat4(char *buf, size_t buflen, void *obj)
{
	nfsstat4 status = *(nfsstat4 *)obj;

	strncpy(buf, status_name(status), buflen);
}

static void
dtl_nfsstat4(void *obj)
{
	nfsstat4 status = *(nfsstat4 *)obj;

	sprintf(get_line(0, 0), "Status = %d (%s)", status,
	    status_name(status));
}

static void
sumres_access(char *buf, size_t buflen, void *obj)
{
	ACCESS4res *res = (ACCESS4res *)obj;
	char *bp = buf;
	int len, blen = buflen;

	strcpy(bp, status_name(res->status));
	if (res->status == NFS4_OK) {
		bp += (len = strlen(bp));
		blen -= len;

		snprintf(bp, blen, " Supp=");
		bp += (len = strlen(bp));
		blen -= len;

		sum_access4(bp, blen, res->ACCESS4res_u.resok4.supported);
		bp += (len = strlen(bp));
		blen -= len;

		snprintf(bp, blen, " Allow=");
		bp += (len = strlen(bp));
		blen -= len;

		sum_access4(bp, blen, res->ACCESS4res_u.resok4.access);
	}
}

static void
dtlres_access(void *obj)
{
	ACCESS4res *res = (ACCESS4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_access4("Supported Attributes",
		    res->ACCESS4res_u.resok4.supported);
		detail_access4("Allowed Attributes",
		    res->ACCESS4res_u.resok4.access);
	}
}

static void
sumres_close(char *buf, size_t buflen, void *obj)
{
	CLOSE4res *res = (CLOSE4res *)obj;

	if (res->status == NFS4_OK)
		snprintf(buf, buflen, "%s",
		    sum_open_stateid(&res->CLOSE4res_u.open_stateid));
}

static void
dtlres_close(void *obj)
{
	CLOSE4res *res = (CLOSE4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_open_stateid(&res->CLOSE4res_u.open_stateid);
	}
}

static void
sumres_commit(char *buf, size_t buflen, void *obj)
{
	COMMIT4res *res = (COMMIT4res *)obj;

	if (res->status == NFS4_OK)
		snprintf(buf, buflen, "Verf=%s",
		    tohex(res->COMMIT4res_u.resok4.writeverf,
		    NFS4_VERIFIER_SIZE));
}

static void
dtlres_commit(void *obj)
{
	COMMIT4res *res = (COMMIT4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		sprintf(get_line(0, 0), "Verifier = %s",
		    tohex(res->COMMIT4res_u.resok4.writeverf,
		    NFS4_VERIFIER_SIZE));
	}
}

static void
dtlres_create(void *obj)
{
	CREATE4res *res = (CREATE4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		dtl_change_info("Change Information",
		    &res->CREATE4res_u.resok4.cinfo);
		detail_attr_bitmap("", &res->CREATE4res_u.resok4.attrset,
		    NULL);
	}
}

static void
sumres_getattr(char *buf, size_t buflen, void *obj)
{
	GETATTR4res *res = (GETATTR4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
}

static void
dtlres_getattr(void *obj)
{
	GETATTR4res *res = (GETATTR4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_fattr4(&res->GETATTR4res_u.resok4.obj_attributes);
	}
}

static void
sumres_cb_getattr(char *buf, size_t buflen, void *obj)
{
	CB_GETATTR4res *res = (CB_GETATTR4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
}

static void
dtlres_cb_getattr(void *obj)
{
	CB_GETATTR4res *res = (CB_GETATTR4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_fattr4(&res->CB_GETATTR4res_u.resok4.obj_attributes);
	}
}


static void
sumres_getfh(char *buf, size_t buflen, void *obj)
{
	char *bp;
	GETFH4res *res = (GETFH4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_fh4(&res->GETFH4res_u.resok4.object));
	}
}

static void
dtlres_getfh(void *obj)
{
	GETFH4res *res = (GETFH4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_fh4(&res->GETFH4res_u.resok4.object, "");
	}
}

static void
dtlres_link(void *obj)
{
	LINK4res *res = (LINK4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		dtl_change_info("Change Information",
		    &res->LINK4res_u.resok4.cinfo);
	}
}

static void
sumres_lock(char *buf, size_t buflen, void *obj)
{
	char *bp;
	LOCK4res *res = (LOCK4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_lock_stateid(&res->LOCK4res_u.resok4.lock_stateid));
	}
	if (res->status == NFS4ERR_DENIED) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_lock_denied(&res->LOCK4res_u.denied));
	}
}

static void
dtlres_lock(void *obj)
{
	LOCK4res *res = (LOCK4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_lock_stateid(&res->LOCK4res_u.resok4.lock_stateid);
	}
	if (res->status == NFS4ERR_DENIED) {
		detail_lock_denied(&res->LOCK4res_u.denied);
	}
}

static void
sumres_lockt(char *buf, size_t buflen, void *obj)
{
	char *bp;
	LOCKT4res *res = (LOCKT4res *)obj;

	strcpy(buf, status_name(res->status));
	if (res->status == NFS4ERR_DENIED) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_lock_denied(&res->LOCKT4res_u.denied));
	}
}

static void
dtlres_lockt(void *obj)
{
	LOCKT4res *res = (LOCKT4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4ERR_DENIED) {
		detail_lock_denied(&res->LOCKT4res_u.denied);
	}
}

static void
sumres_locku(char *buf, size_t buflen, void *obj)
{
	char *bp;
	LOCKU4res *res = (LOCKU4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	bp = buf + strlen(buf);
	if (res->status == NFS4_OK)
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_lock_stateid(&res->LOCKU4res_u.lock_stateid));
}

static void
dtlres_locku(void *obj)
{
	LOCKU4res *res = (LOCKU4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK)
		detail_lock_stateid(&res->LOCKU4res_u.lock_stateid);
}

static void
sumres_open(char *buf, size_t buflen, void *obj)
{
	char *bp = buf;
	OPEN4res *res = (OPEN4res *)obj;
	uint_t rflags;
	int len, blen = buflen;

	strncpy(bp, status_name(res->status), blen);

	if (res->status == NFS4_OK) {
		bp += (len = strlen(bp));
		blen -= len;

		snprintf(bp, blen, " %s",
		    sum_stateid(&res->OPEN4res_u.resok4.stateid));
		bp += (len = strlen(bp));
		blen -= len;

		if ((rflags = res->OPEN4res_u.resok4.rflags) != 0) {
			snprintf(bp, blen, "%s", sum_open_rflags(rflags));
			bp += (len = strlen(bp));
			blen -= len;
		}

		sum_delegation(bp, blen, &res->OPEN4res_u.resok4.delegation);
	}
}

static void
dtlres_open(void *obj)
{
	OPEN4res *res = (OPEN4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_stateid(&res->OPEN4res_u.resok4.stateid);
		dtl_change_info("Change Information",
		    &res->OPEN4res_u.resok4.cinfo);
		sprintf(get_line(0, 0), "Flags = 0x%x (%s)",
		    res->OPEN4res_u.resok4.rflags,
		    detail_open_rflags(res->OPEN4res_u.resok4.rflags));
		detail_attr_bitmap("", &res->OPEN4res_u.resok4.attrset,
		    NULL);
		detail_delegation(&res->OPEN4res_u.resok4.delegation);
	}
}

static void
sumres_open_confirm(char *buf, size_t buflen, void *obj)
{
	char *bp;
	OPEN_CONFIRM4res *res = (OPEN_CONFIRM4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_open_stateid(&res->OPEN_CONFIRM4res_u.resok4.
		    open_stateid));
	}
}

static void
dtlres_open_confirm(void *obj)
{
	OPEN_CONFIRM4res *res = (OPEN_CONFIRM4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_open_stateid(&res->OPEN_CONFIRM4res_u.resok4.
		    open_stateid);
	}
}

static void
sumres_open_downgrd(char *buf, size_t buflen, void *obj)
{
	char *bp;
	OPEN_DOWNGRADE4res *res = (OPEN_DOWNGRADE4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_open_stateid(&res->OPEN_DOWNGRADE4res_u.resok4.
		    open_stateid));
	}
}

static void
dtlres_open_downgrd(void *obj)
{
	OPEN_DOWNGRADE4res *res = (OPEN_DOWNGRADE4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		detail_open_stateid(&res->OPEN_DOWNGRADE4res_u.resok4.
		    open_stateid);
	}
}

static void
sumres_read(char *buf, size_t buflen, void *obj)
{
	char *bp;
	READ4res *res = (READ4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " (%u bytes) %s",
		    res->READ4res_u.resok4.data.data_len,
		    res->READ4res_u.resok4.eof ? "EOF" : "");
	}
}

static void
dtlres_read(void *obj)
{
	READ4res *res = (READ4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		sprintf(get_line(0, 0), "Count = %u bytes read",
		    res->READ4res_u.resok4.data.data_len);
		sprintf(get_line(0, 0), "End of file = %s",
		    res->READ4res_u.resok4.eof ? "TRUE" : "FALSE");
	}
}

static void
sumres_readdir(char *buf, size_t buflen, void *obj)
{
	char *bp;
	READDIR4res *res = (READDIR4res *)obj;
	int num_entries = 0;
	entry4 *ep;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		for (ep = res->READDIR4res_u.resok4.reply.entries;
		    ep != NULL;
		    ep = ep->nextentry)
			num_entries++;
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %d entries (%s)",
		    num_entries,
		    res->READDIR4res_u.resok4.reply.eof
		    ? "No more" : "More");
	}
}

static void
dtlres_readdir(void *obj)
{
	READDIR4res *res = (READDIR4res *)obj;
	int num_entries = 0;
	entry4 *ep;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		for (ep = res->READDIR4res_u.resok4.reply.entries;
		    ep != NULL;
		    ep = ep->nextentry) {
			num_entries++;
			sprintf(get_line(0, 0),
			    "------------------ entry #%d",
			    num_entries);
			sprintf(get_line(0, 0), "Cookie = %llu",
			    ep->cookie);
			sprintf(get_line(0, 0), "Name = %s",
			    component_name(&ep->name));
			detail_fattr4(&ep->attrs);
		}
		if (num_entries == 0)
			sprintf(get_line(0, 0), "(No entries)");
		sprintf(get_line(0, 0), "EOF = %s",
		    res->READDIR4res_u.resok4.reply.eof ? "TRUE" : "FALSE");
		sprintf(get_line(0, 0), "Verifer = %s",
		    tohex(res->READDIR4res_u.resok4.cookieverf,
		    NFS4_VERIFIER_SIZE));
	}
}

static void
sumres_readlnk(char *buf, size_t buflen, void *obj)
{
	char *bp;
	READLINK4res *res = (READLINK4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s",
		    linktext_name(&res->READLINK4res_u.resok4.link));
	}
}

static void
dtlres_readlnk(void *obj)
{
	READLINK4res *res = (READLINK4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		sprintf(get_line(0, 0), "Link = %s",
		    linktext_name(&res->READLINK4res_u.resok4.link));
	}
}

static void
dtlres_remove(void *obj)
{
	REMOVE4res *res = (REMOVE4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		dtl_change_info("Change Information",
		    &res->REMOVE4res_u.resok4.cinfo);
	}
}

static void
dtlres_rename(void *obj)
{
	RENAME4res *res = (RENAME4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		dtl_change_info("Source Change Information",
		    &res->RENAME4res_u.resok4.source_cinfo);
		dtl_change_info("Target Change Information",
		    &res->RENAME4res_u.resok4.target_cinfo);
	}
}

static void
sumres_secinfo(char *buf, size_t buflen, void *obj)
{
	char *bp;
	SECINFO4res *res = (SECINFO4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	bp = buf + strlen(buf);
	if (res->status == NFS4_OK) {
		uint_t numinfo = res->SECINFO4res_u.resok4.SECINFO4resok_len;
		secinfo4 *infop;

		for (infop = res->SECINFO4res_u.resok4.SECINFO4resok_val;
		    numinfo != 0;
		    infop++, numinfo--) {
			snprintf(bp, buflen - (bp - buf), " %s",
			    flavor_name(infop->flavor));
			bp += strlen(bp);
		}
	}
}

static void
dtlres_secinfo(void *obj)
{
	SECINFO4res *res = (SECINFO4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		uint_t numinfo =
		    res->SECINFO4res_u.resok4.SECINFO4resok_len;
		secinfo4 *infop;

		for (infop = res->SECINFO4res_u.resok4.SECINFO4resok_val;
		    numinfo != 0;
		    infop++, numinfo--) {
			detail_secinfo4(infop);
		}
	}
}

static void
sumres_setattr(char *buf, size_t buflen, void *obj)
{
	SETATTR4res *res = (SETATTR4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	sum_attr_bitmap(buf, buflen, &res->attrsset);
}

static void
dtlres_setattr(void *obj)
{
	SETATTR4res *res = (SETATTR4res *)obj;

	dtl_nfsstat4(obj);
	detail_attr_bitmap("", &res->attrsset, NULL);
}

static void
sumres_setclid(char *buf, size_t buflen, void *obj)
{
	char *bp;
	SETCLIENTID4res *res = (SETCLIENTID4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	switch (res->status) {
	case NFS_OK:
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %s CFV=%s",
		    sum_clientid(res->SETCLIENTID4res_u.resok4.clientid),
		    tohex(res->SETCLIENTID4res_u.resok4.setclientid_confirm,
		    NFS4_VERIFIER_SIZE));
		break;
	case NFS4ERR_CLID_INUSE:
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " ID=%s Addr=%s",
		    res->SETCLIENTID4res_u.client_using.na_r_netid,
		    res->SETCLIENTID4res_u.client_using.na_r_addr);
		break;
	}
}

static void
dtlres_setclid(void *obj)
{
	SETCLIENTID4res *res = (SETCLIENTID4res *)obj;

	dtl_nfsstat4(obj);
	switch (res->status) {
	case NFS_OK:
		detail_clientid(res->SETCLIENTID4res_u.resok4.clientid);
		sprintf(get_line(0, 0), "Set Client ID Confirm Verifier = %s",
		    tohex(res->SETCLIENTID4res_u.resok4.setclientid_confirm,
		    NFS4_VERIFIER_SIZE));
		break;
	case NFS4ERR_CLID_INUSE:
		sprintf(get_line(0, 0), "Used by Net ID = %s",
		    res->SETCLIENTID4res_u.client_using.na_r_netid);
		sprintf(get_line(0, 0), "Used by Addr = %s",
		    res->SETCLIENTID4res_u.client_using.na_r_addr);
		break;
	}
}

static void
sumres_write(char *buf, size_t buflen, void *obj)
{
	char *bp;
	WRITE4res *res = (WRITE4res *)obj;

	strncpy(buf, status_name(res->status), buflen);
	if (res->status == NFS4_OK) {
		bp = buf + strlen(buf);
		snprintf(bp, buflen - (bp - buf), " %u (%s)",
		    res->WRITE4res_u.resok4.count,
		    stable_how4_name(res->WRITE4res_u.resok4.committed));
	}
}

static void
dtlres_write(void *obj)
{
	WRITE4res *res = (WRITE4res *)obj;

	dtl_nfsstat4(obj);
	if (res->status == NFS4_OK) {
		sprintf(get_line(0, 0), "Count = %u bytes written",
		    res->WRITE4res_u.resok4.count);
		sprintf(get_line(0, 0), "Stable = %s",
		    stable_how4_name(res->WRITE4res_u.resok4.committed));
		sprintf(get_line(0, 0), "Verifier = %s",
		    tohex(res->WRITE4res_u.resok4.writeverf,
		    NFS4_VERIFIER_SIZE));
	}
}

/*
 * Print details about the nfs_resop4 that is next in the XDR stream.
 */

static void
detail_nfs_resop4(void)
{
	int numres;
	nfs_resop4 one_res;
	void (*fmtproc)(void *);

	numres = getxdr_long();
	(void) sprintf(get_line(0, 0), "Number of results = %d",
	    numres);

	while (numres-- > 0) {
		bzero(&one_res, sizeof (one_res));

		if (!xdr_nfs_resop4(&xdrm, &one_res)) {
			xdr_free(xdr_nfs_resop4, (char *)&one_res);
			longjmp(xdr_err, 1);
		}

		get_line(0, 0);		/* blank line to separate ops */
		sprintf(get_line(0, 0), "Op = %d (%s)",
		    one_res.resop, opcode_name(one_res.resop));
		if (one_res.resop < num_opcodes)
			fmtproc = opcode_info[one_res.resop].dtlres;
		else if (one_res.resop == OP_ILLEGAL)
			fmtproc = dtl_nfsstat4;
		else
			fmtproc = NULL;

		if (fmtproc != NULL)
			fmtproc(&one_res.nfs_resop4_u);

		/* nfs4_skip_bytes set by xdr_nfs_resop4()() */
		if (nfs4_skip_bytes)
			nfs4_xdr_skip(nfs4_skip_bytes);

		xdr_free(xdr_nfs_resop4, (char *)&one_res);
	}
}


/*
 * Print details about the nfs_cb_resop4 that is next in the XDR stream.
 */

static void
detail_cb_resop4(void)
{
	int numres;
	nfs_cb_resop4 one_res;
	void (*fmtproc)(void *);

	numres = getxdr_long();
	(void) sprintf(get_line(0, 0), "Number of results = %d",
	    numres);

	while (numres-- > 0) {
		bzero(&one_res, sizeof (one_res));
		if (!xdr_nfs_cb_resop4(&xdrm, &one_res))
			longjmp(xdr_err, 1);

		get_line(0, 0);		/* blank line to separate ops */
		sprintf(get_line(0, 0), "Op = %d (%s)",
		    one_res.resop, cb_opcode_name(one_res.resop));
		if (one_res.resop < cb_num_opcodes)
			fmtproc = cb_opcode_info[one_res.resop].dtlres;
		else if (one_res.resop == OP_CB_ILLEGAL)
			fmtproc = dtl_nfsstat4;
		else
			fmtproc = NULL;

		if (fmtproc != NULL)
			fmtproc(&one_res.nfs_cb_resop4_u);

		xdr_free(xdr_nfs_cb_resop4, (char *)&one_res);
	}
}


/*
 * Return the name of a lock type.
 */
static char *
lock_type_name(enum nfs_lock_type4 type)
{
	char *result;

	switch (type) {
	case READ_LT:
		result = "READ";
		break;
	case WRITE_LT:
		result = "WRITE";
		break;
	case READW_LT:
		result = "READW";
		break;
	case WRITEW_LT:
		result = "WRITEW";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * Return the name of an opcode.
 */

static char *
opcode_name(uint_t opnum)
{
	static char buf[20];

	if (opnum < num_opcodes)
		return (opcode_info[opnum].name);

	if (opnum == OP_ILLEGAL)
		return ("ILLEGAL");

	sprintf(buf, "op %d", opnum);
	return (buf);
}

/*
 * Return the name of an opcode.
 */
static char *
cb_opcode_name(uint_t opnum)
{
	static char buf[20];

	if (opnum < cb_num_opcodes)
		return (cb_opcode_info[opnum].name);

	if (opnum == OP_CB_ILLEGAL)
		return ("CB_ILLEGAL");

	sprintf(buf, "op %d", opnum);
	return (buf);
}


/*
 * Fill in a summary string for the given access bitmask.
 */

static void
sum_access4(char *buf, size_t buflen, uint32_t bits)
{
	buf[0] = '\0';

	if (bits & ACCESS4_READ)
		(void) strncat(buf, "rd,", buflen);
	if (bits & ACCESS4_LOOKUP)
		(void) strncat(buf, "lk,", buflen);
	if (bits & ACCESS4_MODIFY)
		(void) strncat(buf, "mo,", buflen);
	if (bits & ACCESS4_EXTEND)
		(void) strncat(buf, "ext,", buflen);
	if (bits & ACCESS4_DELETE)
		(void) strncat(buf, "dl,", buflen);
	if (bits & ACCESS4_EXECUTE)
		(void) strncat(buf, "exc,", buflen);
	if (buf[0] != '\0')
		buf[strlen(buf) - 1] = '\0';
}

/*
 * Print detail information about the given access bitmask.
 */

static void
detail_access4(char *descrip, uint32_t bits)
{
	sprintf(get_line(0, 0), "%s = 0x%08x", descrip, bits);

	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_READ, "Read", "(no read)"));
	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_LOOKUP, "Lookup", "(no lookup)"));
	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_MODIFY, "Modify", "(no modify)"));
	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_EXTEND, "Extend", "(no extend)"));
	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_DELETE, "Delete", "(no delete)"));
	(void) sprintf(get_line(0, 0), "	%s",
	    getflag(bits, ACCESS4_EXECUTE, "Execute", "(no execute)"));
}


/*
 * Fill in a summary string for the given open_claim4.
 */
static void
sum_name(char *buf, size_t buflen, open_claim4 *claim)
{
	char *bp = buf;

	switch (claim->claim) {
	case CLAIM_NULL:
		snprintf(bp, buflen, "%s ",
		    component_name(&claim->open_claim4_u.file));
		break;
	case CLAIM_PREVIOUS:
		break;
	case CLAIM_DELEGATE_CUR:
		snprintf(bp, buflen, "%s ",
		    component_name(&claim->open_claim4_u.
		    delegate_cur_info.file));
		break;
	case CLAIM_DELEGATE_PREV:
		snprintf(bp, buflen, "%s ",
		    component_name(&claim->open_claim4_u.
		    file_delegate_prev));
		break;
	case CLAIM_FH:
		break;
	case CLAIM_DELEG_CUR_FH:
		break;
	case CLAIM_DELEG_PREV_FH:
		break;
	}
}

/*
 * Fill in a summary string for the given open_claim4.
 */
static void
sum_claim(char *buf, size_t buflen, open_claim4 *claim)
{
	char *bp = buf;

	switch (claim->claim) {
	case CLAIM_NULL:
		snprintf(bp, buflen, " CT=N");
		break;
	case CLAIM_PREVIOUS:
		snprintf(bp, buflen, " CT=P DT=%s",
		    get_deleg_typestr(claim->open_claim4_u.delegate_type));
		break;
	case CLAIM_DELEGATE_CUR:
		snprintf(bp, buflen, " CT=DC %s",
		    sum_deleg_stateid(&claim->open_claim4_u.
		    delegate_cur_info.delegate_stateid));
		break;
	case CLAIM_DELEGATE_PREV:
		snprintf(bp, buflen, " CT=DP");
		break;
	case CLAIM_FH:
		snprintf(bp, buflen, " CT=FH");
		break;
	case CLAIM_DELEG_CUR_FH:
		snprintf(bp, buflen, " CT=CUR_FH");
		break;
	case CLAIM_DELEG_PREV_FH:
		snprintf(bp, buflen, " CT=PREV_FH");
		break;
	default:
		snprintf(bp, buflen, " CT=? (%d)", claim->claim);
		break;
	}
}

static char *
get_deleg_typestr(open_delegation_type4 dt)
{
	char *str = "";

	switch (dt) {
	case OPEN_DELEGATE_NONE:
		str = "N";
		break;
	case OPEN_DELEGATE_READ:
		str = "R";
		break;
	case OPEN_DELEGATE_WRITE:
		str = "W";
		break;
	default:
		str = "?";
	}

	return (str);
}

/*
 * Print detail information for the given open_claim4.
 */

static void
detail_claim(open_claim4 *claim)
{
	sprintf(get_line(0, 0), "Claim Type = %d (%s)",
	    claim->claim, claim_name(claim->claim));

	switch (claim->claim) {
	case CLAIM_NULL:
		detail_compname4(&claim->open_claim4_u.file);
		break;
	case CLAIM_PREVIOUS:
		sprintf(get_line(0, 0), "Delegate Type = %s (val = %d)",
		    get_deleg_typestr(claim->open_claim4_u.delegate_type),
		    claim->open_claim4_u.delegate_type);
		break;
	case CLAIM_DELEGATE_CUR:
		detail_compname4(&claim->open_claim4_u.delegate_cur_info.file);
		detail_deleg_stateid(&claim->open_claim4_u.delegate_cur_info.
		    delegate_stateid);
		break;
	case CLAIM_DELEGATE_PREV:
		detail_compname4(&claim->open_claim4_u.file_delegate_prev);
		break;
	}
}

/*
 * Return a summary string for the given clientid4.
 */
char *
sum_clientid(clientid4 client)
{
	static char buf[50];

	snprintf(buf, sizeof (buf), "CL=%llx", client);

	return (buf);
}

/*
 * Print a detail string for the given clientid4.
 */
void
detail_clientid(clientid4 client)
{
	sprintf(get_line(0, 0), "Client ID = %llx", client);
}

/*
 * Write a summary string for the given delegation into buf.
 */

static void
sum_delegation(char *buf, size_t buflen, open_delegation4 *delp)
{
	switch (delp->delegation_type) {
	case OPEN_DELEGATE_NONE:
		snprintf(buf, buflen, " DT=N");
		break;
	case OPEN_DELEGATE_READ:
		snprintf(buf, buflen, " DT=R %s",
		    sum_deleg_stateid(&delp->open_delegation4_u.write.
		    stateid));
		break;
	case OPEN_DELEGATE_WRITE:
		snprintf(buf, buflen, " DT=W %s %s",
		    sum_deleg_stateid(&delp->open_delegation4_u.write.
		    stateid),
		    sum_space_limit(&delp->open_delegation4_u.write.
		    space_limit));
		break;
	default:
		snprintf(buf, buflen, " DT=?");
		break;
	}
}

static void
detail_delegation(open_delegation4 *delp)
{
	sprintf(get_line(0, 0), "Delegation Type = %d (%s)",
	    delp->delegation_type,
	    delegation_type_name(delp->delegation_type));

	switch (delp->delegation_type) {
	case OPEN_DELEGATE_NONE:
		/* no-op */
		break;
	case OPEN_DELEGATE_READ:
		detail_deleg_stateid(&delp->open_delegation4_u.read.stateid);
		sprintf(get_line(0, 0), "Recall = %s",
		    delp->open_delegation4_u.read.recall ?
		    "TRUE" : "FALSE");
		sprintf(get_line(0, 0), "[nfsacl4]");
		break;
	case OPEN_DELEGATE_WRITE:
		detail_deleg_stateid(&delp->open_delegation4_u.write.stateid);
		sprintf(get_line(0, 0), "Recall = %s",
		    delp->open_delegation4_u.write.recall ?
		    "TRUE" : "FALSE");
		detail_space_limit(&delp->open_delegation4_u.write.
		    space_limit);
		sprintf(get_line(0, 0), "[nfsacl4]");
		break;
	}
}


static void
detail_open_owner(open_owner4 *owner)
{
	sprintf(get_line(0, 0), "Open Owner hash = [%04X] ",
	    owner_hash(&owner->owner));
	sprintf(get_line(0, 0), "    len = %u   val = %s ",
	    owner->owner.owner_len,
	    tohex(owner->owner.owner_val, owner->owner.owner_len));
	detail_clientid(owner->clientid);
}

static void
detail_lock_owner(lock_owner4 *owner)
{
	sprintf(get_line(0, 0), "Lock Owner hash = [%04X] ",
	    owner_hash(&owner->owner));
	sprintf(get_line(0, 0), "    len = %u   val = %s ",
	    owner->owner.owner_len,
	    tohex(owner->owner.owner_val, owner->owner.owner_len));
	detail_clientid(owner->clientid);
}

static void
sum_openflag(char *bufp, int buflen, openflag4 *flagp)
{
	if (flagp->opentype == OPEN4_CREATE) {
		switch (flagp->openflag4_u.how.mode) {
		case UNCHECKED4:
			snprintf(bufp, buflen, "OT=CR(U)");
			break;
		case GUARDED4:
			snprintf(bufp, buflen, "OT=CR(G)");
			break;
		case EXCLUSIVE4:
			snprintf(bufp, buflen, "OT=CR(E)");
			break;
		default:
			snprintf(bufp, buflen, "OT=CR(?:%d)",
			    flagp->openflag4_u.how.mode);
			break;
		}
	} else
		snprintf(bufp, buflen, "OT=NC");
}

static void
detail_openflag(openflag4 *flagp)
{
	sprintf(get_line(0, 0), "Open Type = %s",
	    flagp->opentype == OPEN4_CREATE ? "CREATE" : "NOCREATE");
	if (flagp->opentype == OPEN4_CREATE)
		detail_createhow4(&flagp->openflag4_u.how);
}

/*
 * Fill in buf with the given path.
 */
static void
sum_pathname4(char *buf, size_t buflen, pathname4 *pathp)
{
	char *bp = buf;
	uint_t component;

	for (component = 0; component < pathp->pathname4_len;
	    component++) {
		snprintf(bp, buflen - (bp - buf),
		    component == 0 ? "%s" : "/%s",
		    component_name(&pathp->pathname4_val[component]));
		bp += strlen(bp);
	}
}

static void
sum_compname4(char *buf, size_t buflen, component4 *comp)
{
	snprintf(buf, buflen, "%s", component_name(comp));
}

static void
detail_compname4(component4 *comp)
{
	sprintf(get_line(0, 0), "%s", component_name(comp));
}

static void
detail_pathname4(pathname4 *pathp)
{
	char *bp = get_line(0, 0);
	uint_t component;

	sprintf(bp, "File name = ");
	bp += strlen(bp);

	for (component = 0; component < pathp->pathname4_len; component++) {
		sprintf(bp, component == 0 ? "%s" : "/%s",
		    component_name(&pathp->pathname4_val[component]));
		bp += strlen(bp);
	}
}

/*
 * Print detail information about the rpcsec_gss_info that is XDR-encoded
 * at mem.
 */

void
detail_rpcsec_gss(rpcsec_gss_info *info)
{
	sprintf(get_line(0, 0), "OID = %s",
	    tohex(info->oid.sec_oid4_val, info->oid.sec_oid4_len));
	sprintf(get_line(0, 0), "QOP = %u", info->qop);
	sprintf(get_line(0, 0), "Service = %d (%s)",
	    info->service, gss_svc_name(info->service));
}

/*
 * Print detail information about the given secinfo4.
 */

void
detail_secinfo4(secinfo4 *infop)
{
	sprintf(get_line(0, 0), "Flavor = %d (%s)",
	    infop->flavor, flavor_name(infop->flavor));
	switch (infop->flavor) {
	case RPCSEC_GSS:
		detail_rpcsec_gss(&infop->secinfo4_u.flavor_info);
		break;
	}
}


/*
 * Return a summary string corresponding to the given nfs_space_limit4.
 */

static char *
sum_space_limit(nfs_space_limit4 *limitp)
{
	static char buf[64];
	int buflen = sizeof (buf);

	buf[0] = '\0';
	switch (limitp->limitby) {
	case NFS_LIMIT_SIZE:
		snprintf(buf, buflen, "LB=SZ(%llu)",
		    limitp->nfs_space_limit4_u.filesize);
		break;
	case NFS_LIMIT_BLOCKS:
		snprintf(buf, buflen, "LB=BL(%u*%u)",
		    limitp->nfs_space_limit4_u.mod_blocks.num_blocks,
		    limitp->nfs_space_limit4_u.mod_blocks.bytes_per_block);
		break;
	default:
		snprintf(buf, buflen, "LB=?(%d)", limitp->limitby);
		break;
	}

	return (buf);
}

/*
 * Print detail information about the given nfs_space_limit4.
 */

static void
detail_space_limit(nfs_space_limit4 *limitp)
{
	sprintf(get_line(0, 0), "LimitBy = %d (%s)",
	    limitp->limitby,
	    limitby_name(limitp->limitby));

	switch (limitp->limitby) {
	case NFS_LIMIT_SIZE:
		sprintf(get_line(0, 0), "Bytes = %llu",
		    limitp->nfs_space_limit4_u.filesize);
		break;
	case NFS_LIMIT_BLOCKS:
		sprintf(get_line(0, 0), "Blocks = %u",
		    limitp->nfs_space_limit4_u.mod_blocks.num_blocks);
		sprintf(get_line(0, 0), "Bytes Per Block = %u",
		    limitp->nfs_space_limit4_u.mod_blocks.bytes_per_block);
		break;
	}
}


/*
 * Return the short name of a file type.
 */

static char *
sum_type_name(nfs_ftype4 type)
{
	static char buf[20];

	if (type < num_ftypes)
		return (ftype_names[type].short_name);
	else {
		sprintf(buf, "type %d", type);
		return (buf);
	}
}


/*
 * Return string with long/short flag names
 */

static char *
get_flags(uint_t flag, ftype_names_t *names, uint_t num_flags, int shortname,
	char *prefix)
{
	static char buf[200];
	char *bp = buf, *str;
	int i, len, blen = sizeof (buf);
	ftype_names_t *fn = NULL;

	*bp = '\0';

	if (prefix) {
		snprintf(bp, blen, "%s", prefix);
		bp += (len = sizeof (bp));
		blen -= len;
	}

	for (i = 0; i < 32; i++)
		if (flag & (1 << i)) {
			fn = names + (i < num_flags ? i : num_flags);
			str = (shortname ? fn->short_name : fn->long_name);

			snprintf(bp, blen, "%s,", str);
			bp += (len = strlen(bp));
			blen -= len;
		}

	if (fn)
		*(bp - 1) = '\0';
	else
		*buf = '\0';

	return (buf);
}


/*
 * Return the long name of a file type.
 */

static char *
detail_type_name(nfs_ftype4 type)
{
	static char buf[20];

	if (type < num_ftypes)
		return (ftype_names[type].long_name);
	else {
		sprintf(buf, "type %d", type);
		return (buf);
	}
}

/*
 * Return the name of an attribute.
 */

static char *
attr_name(uint_t attrnum)
{
	static char buf[20];

	if (attrnum < MAX_ATTRIBUTES)
		return (attr_info[attrnum].name);
	else {
		sprintf(buf, "attr #%d", attrnum);
		return (buf);
	}
}

/*
 * Return the name of the given open_claim_type4.
 */

static char *
claim_name(enum open_claim_type4 claim_type)
{
	char *result;

	switch (claim_type) {
	case CLAIM_NULL:
		result = "NULL";
		break;
	case CLAIM_PREVIOUS:
		result = "PREVIOUS";
		break;
	case CLAIM_DELEGATE_CUR:
		result = "DELEGATE CURRENT";
		break;
	case CLAIM_DELEGATE_PREV:
		result = "DELEGATE PREVIOUS";
		break;
	case CLAIM_FH:
		result = "FILEHANDLE";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * Return a string naming the given delegation.
 */

static char *
delegation_type_name(enum open_delegation_type4 type)
{
	char *result;

	switch (type) {
	case OPEN_DELEGATE_NONE:
		result = "NONE";
		break;
	case OPEN_DELEGATE_READ:
		result = "READ";
		break;
	case OPEN_DELEGATE_WRITE:
		result = "WRITE";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

/*
 * Return the name of the given authentication flavor.
 */

static char *
flavor_name(uint_t flavor)
{
	char *result;
	static char buf[50];

	switch (flavor) {
	case AUTH_SYS:
		result = "AUTH_SYS";
		break;
	case AUTH_NONE:
		result = "AUTH_NONE";
		break;
	case AUTH_DH:
		result = "AUTH_DH";
		break;
	case RPCSEC_GSS:
		result = "RPCSEC_GSS";
		break;
	default:
		sprintf(buf, "[flavor %d]", flavor);
		result = buf;
		break;
	}

	return (result);
}

/*
 * Return the name of the given rpc_gss_svc_t.
 */

static char *
gss_svc_name(rpc_gss_svc_t svc)
{
	char *result;
	static char buf[50];

	switch (svc) {
	case RPC_GSS_SVC_NONE:
		result = "NONE";
		break;
	case RPC_GSS_SVC_INTEGRITY:
		result = "INTEGRITY";
		break;
	case RPC_GSS_SVC_PRIVACY:
		result = "PRIVACY";
		break;
	default:
		sprintf(buf, "Service %d", svc);
		result = buf;
		break;
	}

	return (result);
}

/*
 * Return a string name for the given limit_by4.
 */

static char *
limitby_name(enum limit_by4 limitby)
{
	char *result;

	switch (limitby) {
	case NFS_LIMIT_SIZE:
		result = "SIZE";
		break;
	case NFS_LIMIT_BLOCKS:
		result = "BLOCKS";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

static char *
status_name(int status)
{
	char *p;

	switch (status) {
	case NFS4_OK:				/* 0 */
		p = "NFS4_OK"; break;
	case NFS4ERR_PERM:			/* 1 */
		p = "NFS4ERR_PERM"; break;
	case NFS4ERR_NOENT:			/* 2 */
		p = "NFS4ERR_NOENT"; break;
	case NFS4ERR_IO:			/* 5 */
		p = "NFS4ERR_IO"; break;
	case NFS4ERR_NXIO:			/* 6 */
		p = "NFS4ERR_NXIO"; break;
	case NFS4ERR_ACCESS:			/* 13 */
		p = "NFS4ERR_ACCESS"; break;
	case NFS4ERR_EXIST:			/* 17 */
		p = "NFS4ERR_EXIST"; break;
	case NFS4ERR_XDEV:			/* 18 */
		p = "NFS4ERR_XDEV"; break;
	case NFS4ERR_NOTDIR:			/* 20 */
		p = "NFS4ERR_NOTDIR"; break;
	case NFS4ERR_ISDIR:			/* 21 */
		p = "NFS4ERR_ISDIR"; break;
	case NFS4ERR_INVAL:			/* 22 */
		p = "NFS4ERR_INVAL"; break;
	case NFS4ERR_FBIG:			/* 27 */
		p = "NFS4ERR_FBIG"; break;
	case NFS4ERR_NOSPC:			/* 28 */
		p = "NFS4ERR_NOSPC"; break;
	case NFS4ERR_ROFS:			/* 30 */
		p = "NFS4ERR_ROFS"; break;
	case NFS4ERR_MLINK:			/* 31 */
		p = "NFS4ERR_MLINK"; break;
	case NFS4ERR_NAMETOOLONG:		/* 63 */
		p = "NFS4ERR_NAMETOOLONG"; break;
	case NFS4ERR_NOTEMPTY:			/* 66 */
		p = "NFS4ERR_NOTEMPTY"; break;
	case NFS4ERR_DQUOT:			/* 69 */
		p = "NFS4ERR_DQUOT"; break;
	case NFS4ERR_STALE:			/* 70 */
		p = "NFS4ERR_STALE"; break;
	case NFS4ERR_BADHANDLE:			/* 10001 */
		p = "NFS4ERR_BADHANDLE"; break;
	case NFS4ERR_BAD_COOKIE:		/* 10003 */
		p = "NFS4ERR_BAD_COOKIE"; break;
	case NFS4ERR_NOTSUPP:			/* 10004 */
		p = "NFS4ERR_NOTSUPP"; break;
	case NFS4ERR_TOOSMALL:			/* 10005 */
		p = "NFS4ERR_TOOSMALL"; break;
	case NFS4ERR_SERVERFAULT:		/* 10006 */
		p = "NFS4ERR_SERVERFAULT"; break;
	case NFS4ERR_BADTYPE:			/* 10007 */
		p = "NFS4ERR_BADTYPE"; break;
	case NFS4ERR_DELAY:			/* 10008 */
		p = "NFS4ERR_DELAY"; break;
	case NFS4ERR_SAME:			/* 10009 */
		p = "NFS4ERR_SAME"; break;
	case NFS4ERR_DENIED:			/* 10010 */
		p = "NFS4ERR_DENIED"; break;
	case NFS4ERR_EXPIRED:			/* 10011 */
		p = "NFS4ERR_EXPIRED"; break;
	case NFS4ERR_LOCKED:			/* 10012 */
		p = "NFS4ERR_LOCKED"; break;
	case NFS4ERR_GRACE:			/* 10013 */
		p = "NFS4ERR_GRACE"; break;
	case NFS4ERR_FHEXPIRED:			/* 10014 */
		p = "NFS4ERR_FHEXPIRED"; break;
	case NFS4ERR_SHARE_DENIED:		/* 10015 */
		p = "NFS4ERR_SHARE_DENIED"; break;
	case NFS4ERR_WRONGSEC:			/* 10016 */
		p = "NFS4ERR_WRONGSEC"; break;
	case NFS4ERR_CLID_INUSE:		/* 10017 */
		p = "NFS4ERR_CLID_INUSE"; break;
	case NFS4ERR_RESOURCE:			/* 10018 */
		p = "NFS4ERR_RESOURCE"; break;
	case NFS4ERR_MOVED:			/* 10019 */
		p = "NFS4ERR_MOVED"; break;
	case NFS4ERR_NOFILEHANDLE:		/* 10020 */
		p = "NFS4ERR_NOFILEHANDLE"; break;
	case NFS4ERR_MINOR_VERS_MISMATCH:	/* 10021 */
		p = "NFS4ERR_MINOR_VERS_MISMATCH"; break;
	case NFS4ERR_STALE_CLIENTID: 		/* 10022 */
		p = "NFS4ERR_STALE_CLIENTID"; break;
	case NFS4ERR_STALE_STATEID:		/* 10023 */
		p = "NFS4ERR_STALE_STATEID"; break;
	case NFS4ERR_OLD_STATEID:		/* 10024 */
		p = "NFS4ERR_OLD_STATEID"; break;
	case NFS4ERR_BAD_STATEID:		/* 10025 */
		p = "NFS4ERR_BAD_STATEID"; break;
	case NFS4ERR_BAD_SEQID:			/* 10026 */
		p = "NFS4ERR_BAD_SEQID"; break;
	case NFS4ERR_NOT_SAME:			/* 10027 */
		p = "NFS4ERR_NOT_SAME"; break;
	case NFS4ERR_LOCK_RANGE:		/* 10028 */
		p = "NFS4ERR_LOCK_RANGE"; break;
	case NFS4ERR_SYMLINK:			/* 10029 */
		p = "NFS4ERR_SYMLINK"; break;
	case NFS4ERR_RESTOREFH:			/* 10030 */
		p = "NFS4ERR_RESTOREFH"; break;
	case NFS4ERR_LEASE_MOVED:		/* 10031 */
		p = "NFS4ERR_LEASE_MOVED"; break;
	case NFS4ERR_ATTRNOTSUPP:		/* 10032 */
		p = "NFS4ERR_ATTRNOTSUPP"; break;
	case NFS4ERR_NO_GRACE:			/* 10033 */
		p = "NFS4ERR_NO_GRACE"; break;
	case NFS4ERR_RECLAIM_BAD:		/* 10034 */
		p = "NFS4ERR_RECLAIM_BAD"; break;
	case NFS4ERR_RECLAIM_CONFLICT:		/* 10035 */
		p = "NFS4ERR_RECLAIM_CONFLICT"; break;
	case NFS4ERR_BADXDR:			/* 10036 */
		p = "NFS4ERR_BADXDR"; break;
	case NFS4ERR_LOCKS_HELD:		/* 10037 */
		p = "NFS4ERR_LOCKS_HELD"; break;
	case NFS4ERR_OPENMODE:			/* 10038 */
		p = "NFS4ERR_OPENMODE"; break;
	case NFS4ERR_BADOWNER:			/* 10039 */
		p = "NFS4ERR_BADOWNER"; break;
	case NFS4ERR_BADCHAR:			/* 10040 */
		p = "NFS4ERR_BADCHAR"; break;
	case NFS4ERR_BADNAME:			/* 10041 */
		p = "NFS4ERR_BADNAME"; break;
	case NFS4ERR_BAD_RANGE:			/* 10042 */
		p = "NFS4ERR_BAD_RANGE"; break;
	case NFS4ERR_LOCK_NOTSUPP:		/* 10043 */
		p = "NFS4ERR_LOCK_NOTSUPP"; break;
	case NFS4ERR_OP_ILLEGAL:		/* 10044 */
		p = "NFS4ERR_OP_ILLEGAL"; break;
	case NFS4ERR_DEADLOCK:			/* 10045 */
		p = "NFS4ERR_DEADLOCK"; break;
	case NFS4ERR_FILE_OPEN:			/* 10046 */
		p = "NFS4ERR_FILE_OPEN"; break;
	case NFS4ERR_ADMIN_REVOKED:		/* 10047 */
		p = "NFS4ERR_ADMIN_REVOKED"; break;
	case NFS4ERR_CB_PATH_DOWN:		/* 10048 */
		p = "NFS4ERR_CB_PATH_DOWN"; break;
	/* nfs4.1 error code */
	case NFS4ERR_BADIOMODE:			/* 10049 */
		p = "NFS4ERR_BADIOMODE"; break;
	case NFS4ERR_BADLAYOUT:			/* 10050 */
		p = "NFS4ERR_BADLAYOUT"; break;
	case NFS4ERR_BAD_SESSION_DIGEST:	/* 10051 */
		p = "NFS4ERR_BAD_SESSION_DIGEST"; break;
	case NFS4ERR_BADSESSION:		/* 10052 */
		p = "NFS4ERR_BADSESSION"; break;
	case NFS4ERR_BADSLOT:			/* 10053 */
		p = "NFS4ERR_BADSLOT"; break;
	case NFS4ERR_COMPLETE_ALREADY:		/* 10054 */
		p = "NFS4ERR_COMPLETE_ALREADY"; break;
	case NFS4ERR_CONN_NOT_BOUND_TO_SESSION:	/* 10055 */
		p = "NFS4ERR_CONN_NOT_BOUND_TO_SESSION"; break;
	case NFS4ERR_DELEG_ALREADY_WANTED:	/* 10056 */
		p = "NFS4ERR_DELEG_ALREADY_WANTED"; break;
	case NFS4ERR_BACK_CHAN_BUSY:		/* 10057 */
		p = "NFS4ERR_BACK_CHAN_BUSY"; break;
	case NFS4ERR_LAYOUTTRYLATER:		/* 10058 */
		p = "NFS4ERR_LAYOUTTRYLATER"; break;
	case NFS4ERR_LAYOUTUNAVAILABLE:		/* 10059 */
		p = "NFS4ERR_LAYOUTUNAVAILABLE"; break;
	case NFS4ERR_NOMATCHING_LAYOUT:		/* 10060 */
		p = "NFS4ERR_NOMATCHING_LAYOUT"; break;
	case NFS4ERR_RECALLCONFLICT:		/* 10061 */
		p = "NFS4ERR_RECALLCONFLICT"; break;
	case NFS4ERR_UNKNOWN_LAYOUTTYPE:	/* 10062 */
		p = "NFS4ERR_UNKNOWN_LAYOUTTYPE"; break;
	case NFS4ERR_SEQ_MISORDERED:		/* 10063 */
		p = "NFS4ERR_SEQ_MISORDERED"; break;
	case NFS4ERR_SEQUENCE_POS:		/* 10064 */
		p = "NFS4ERR_SEQUENCE_POS"; break;
	case NFS4ERR_REQ_TOO_BIG:		/* 10065 */
		p = "NFS4ERR_REQ_TOO_BIG"; break;
	case NFS4ERR_REP_TOO_BIG:		/* 10066 */
		p = "NFS4ERR_REP_TOO_BIG"; break;
	case NFS4ERR_REP_TOO_BIG_TO_CACHE:	/* 10067 */
		p = "NFS4ERR_REP_TOO_BIG_TO_CACHE"; break;
	case NFS4ERR_RETRY_UNCACHED_REP:	/* 10068 */
		p = "NFS4ERR_RETRY_UNCACHED_REP"; break;
	case NFS4ERR_UNSAFE_COMPOUND:		/* 10069 */
		p = "NFS4ERR_UNSAFE_COMPOUND"; break;
	case NFS4ERR_TOO_MANY_OPS:		/* 10070 */
		p = "NFS4ERR_TOO_MANY_OPS"; break;
	case NFS4ERR_OP_NOT_IN_SESSION:		/* 10071 */
		p = "NFS4ERR_OP_NOT_IN_SESSION"; break;
	case NFS4ERR_HASH_ALG_UNSUPP:		/* 10072 */
		p = "NFS4ERR_HASH_ALG_UNSUPP"; break;
	/* Error 10073 is unused. */
	case NFS4ERR_CLIENTID_BUSY:		/* 10074 */
		p = "NFS4ERR_CLIENTID_BUSY"; break;
	case NFS4ERR_PNFS_IO_HOLE:		/* 10075 */
		p = "NFS4ERR_PNFS_IO_HOLE"; break;
	case NFS4ERR_SEQ_FALSE_RETRY:		/* 10076 */
		p = "NFS4ERR_SEQ_FALSE_RETRY"; break;
	case NFS4ERR_BAD_HIGH_SLOT:		/* 10077 */
		p = "NFS4ERR_BAD_HIGH_SLOT"; break;
	case NFS4ERR_DEADSESSION:		/* 10078 */
		p = "NFS4ERR_DEADSESSION"; break;
	case NFS4ERR_ENCR_ALG_UNSUPP:		/* 10079 */
		p = "NFS4ERR_ENCR_ALG_UNSUPP"; break;
	case NFS4ERR_PNFS_NO_LAYOUT:		/* 10080 */
		p = "NFS4ERR_PNFS_NO_LAYOUT"; break;
	case NFS4ERR_NOT_ONLY_OP:		/* 10081 */
		p = "NFS4ERR_NOT_ONLY_OP"; break;
	case NFS4ERR_WRONG_CRED:		/* 10082 */
		p = "NFS4ERR_WRONG_CRED"; break;
	case NFS4ERR_WRONG_TYPE:		/* 10083 */
		p = "NFS4ERR_WRONG_TYPE"; break;
	case NFS4ERR_DIRDELEG_UNAVAIL:		/* 10084 */
		p = "NFS4ERR_DIRDELEG_UNAVAIL"; break;
	case NFS4ERR_REJECT_DELEG:		/* 10085 */
		p = "NFS4ERR_REJECT_DELEG"; break;
	case NFS4ERR_RETURNCONFLICT:		/* 10086 */
		p = "NFS4ERR_RETURNCONFLICT"; break;
	default:
		p = "(unknown error)"; break;
	}

	return (p);
}

char *
nfsstat4_to_name(int status)
{
	return (status_name(status));
}

static char *
sum_sequenceid(sequenceid4 seq)
{
	static char buf[64];

	snprintf(buf, sizeof (buf), "SQ=%u", seq);
	return (buf);
}

static void
sum_sec_parm(char *buf, size_t buflen, callback_sec_parms4 parms)
{
	snprintf(buf, buflen, " %s", flavor_name(parms.cb_secflavor));
}

static void
sumarg_create_session(char *buf, size_t buflen, void *obj)
{
	CREATE_SESSION4args *args = (CREATE_SESSION4args *)obj;
	char *bp = buf;
	uint_t i;

	snprintf(bp, buflen, "%s ", sum_clientid(args->csa_clientid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    sum_sequenceid(args->csa_sequence));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ", sum_sn_flags(args->csa_flags));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "CB=%u",
	    args->csa_cb_program);

	for (i = 0; i < args->csa_sec_parms.csa_sec_parms_len; i++) {
		bp += strlen(bp);
		sum_sec_parm(bp, buflen - (bp - buf),
		    args->csa_sec_parms.csa_sec_parms_val[i]);
	}
}

static char *
sum_sessionid(sessionid4 sid)
{
	static char buf[64];

	snprintf(buf, sizeof (buf), "SID=%04X", sessionid_hash(sid));
	return (buf);
}

static void
sumres_create_session(char *buf, size_t buflen, void *obj)
{
	CREATE_SESSION4res *res = (CREATE_SESSION4res *)obj;
	CREATE_SESSION4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->csr_status));
	if (res->csr_status == NFS4_OK) {
		resok = &res->CREATE_SESSION4res_u.csr_resok4;
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_sessionid(resok->csr_sessionid));
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_sequenceid(resok->csr_sequence));
		bp += strlen(bp);
		snprintf(bp, buflen - (bp -buf), " %s",
		    sum_sn_flags(resok->csr_flags));
	}
}

static void
detail_sequenceid(sequenceid4 seq)
{
	sprintf(get_line(0, 0), "Sequence ID = %u", seq);
}

static void
detail_channel_attr(channel_attrs4 attr)
{
	int i;

	detail_headerpadsize(attr.ca_headerpadsize);
	sprintf(get_line(0, 0), "\tMaximum request size = %u",
	    attr.ca_maxrequestsize);
	sprintf(get_line(0, 0), "\tMaximum response size = %u",
	    attr.ca_maxresponsesize);
	sprintf(get_line(0, 0), "\tMaximum response cache size = %u",
	    attr.ca_maxresponsesize_cached);
	sprintf(get_line(0, 0), "\tMaximum number of operations = %u",
	    attr.ca_maxoperations);
	sprintf(get_line(0, 0), "\tMaximum number of requests = %u",
	    attr.ca_maxrequests);

	for (i = 0; i < attr.ca_rdma_ird.ca_rdma_ird_len; i++)
		sprintf(get_line(0, 0), "\tRDMA channel attribute [i] = %u",
		    attr.ca_rdma_ird.ca_rdma_ird_val[i]);
}

static void
detail_sessionid(sessionid4 sid)
{
	sprintf(get_line(0, 0), "Session ID hash = [%04X] ",
	    sessionid_hash(sid));
	sprintf(get_line(0, 0), "    (16) %s",
	    tohex(sid, 16));
}

static void
detail_headerpadsize(count4 size)
{
	sprintf(get_line(0, 0), "Header padding = %u", size);
}

static void
detail_use_in_rdma_mode(bool_t val)
{
	sprintf(get_line(0, 0), "Use the connection in RDMA mode = %s",
	    val ? "TRUE" : "FALSE");
}

static void
detail_authsys_parms(authsys_parms aup)
{
	uint_t i;

	char *bp = get_line(0, 0);
	sprintf(bp, "time=%u machine=%s uid=%u gid=%u",
	    aup.aup_time, aup.aup_machname, aup.aup_uid, aup.aup_gid);

	for (i = 0; i < aup.aup_len; i++) {
		bp += strlen(bp);
		sprintf(bp, " gids[i]=%u", aup.aup_gids[i]);
	}
}

static void
detail_gss_handles4(gss_cb_handles4 hdl)
{
	uint_t i;

	char *bp = get_line(0, 0);
	sprintf(bp, "Service = %d (%s); ",
	    hdl.gcbp_service, gss_svc_name(hdl.gcbp_service));

	bp += strlen(bp);
	sprintf(bp, "The handle from server=%s;",
	    tohex(hdl.gcbp_handle_from_server.gsshandle4_t_val,
	    hdl.gcbp_handle_from_server.gsshandle4_t_len));

	bp += strlen(bp);
	sprintf(bp, "The handle for client=%s",
	    tohex(hdl.gcbp_handle_from_client.gsshandle4_t_val,
	    hdl.gcbp_handle_from_client.gsshandle4_t_len));
}

static void
detail_sec_parm(callback_sec_parms4 sec)
{
	sprintf(get_line(0, 0), "Flavor = %d (%s)",
	    sec.cb_secflavor, flavor_name(sec.cb_secflavor));

	switch (sec.cb_secflavor) {
	case AUTH_NONE:
		break;
	case AUTH_SYS:
		detail_authsys_parms(sec.callback_sec_parms4_u.cbsp_sys_cred);
		break;
	case RPCSEC_GSS:
		detail_gss_handles4(sec.callback_sec_parms4_u.cbsp_gss_handles);
		break;
	defaul:
		break;
	}
}

static void
dtlarg_create_session(void *obj)
{
	CREATE_SESSION4args *args = (CREATE_SESSION4args *)obj;
	callback_sec_parms4 parms;
	uint_t i;

	detail_clientid(args->csa_clientid);
	detail_sequenceid(args->csa_sequence);
	sprintf(get_line(0, 0), "Flags = 0x%x (%s)",
	    args->csa_flags, detail_sn_flags(args->csa_flags));
	sprintf(get_line(0, 0), "Attributes of the fore channel: ");
	detail_channel_attr(args->csa_fore_chan_attrs);
	sprintf(get_line(0, 0), "Attributes of the back channel: ");
	detail_channel_attr(args->csa_back_chan_attrs);
	sprintf(get_line(0, 0), "Callback program ID = %u",
	    args->csa_cb_program);
	for (i = 0; i < args->csa_sec_parms.csa_sec_parms_len; i++)
		parms = args->csa_sec_parms.csa_sec_parms_val[i];
		detail_sec_parm(parms);
}

static void
dtlres_create_session(void *obj)
{
	CREATE_SESSION4res *res = (CREATE_SESSION4res *)obj;
	CREATE_SESSION4resok *resok;

	dtl_nfsstat4(obj);
	if (res->csr_status == NFS4_OK) {
		resok = &res->CREATE_SESSION4res_u.csr_resok4;
		detail_sessionid(resok->csr_sessionid);
		detail_sequenceid(resok->csr_sequence);
		sprintf(get_line(0, 0), "Flags = 0x%x (%s)",
		    resok->csr_flags, detail_sn_flags(resok->csr_flags));
		sprintf(get_line(0, 0), "Attributes of the fore channel:");
		detail_channel_attr(resok->csr_fore_chan_attrs);
		sprintf(get_line(0, 0), "Attributes of the back channel:");
		detail_channel_attr(resok->csr_back_chan_attrs);
	}
}

static char *
sum_verifier(verifier4 verifier)
{
	static char buf[32];

	snprintf(buf, sizeof (buf), "Verf=%s",
	    tohex(verifier, NFS4_VERIFIER_SIZE));

	return (buf);
}

static void
detail_verifier(verifier4 verifier)
{
	sprintf(get_line(0, 0), "Verifier=%s",
	    tohex(verifier, NFS4_VERIFIER_SIZE));
}

static char *
print_ei_flag(uint32_t flag)
{
	static char buf[64];
	char *bp = buf;
	size_t buflen = sizeof (buf);

	if (flag & EXCHGID4_FLAG_SUPP_MOVED_REFER) {
		snprintf(bp, buflen, "MOVED_REFER ");
		bp += strlen(buf);
	}

	if (flag & EXCHGID4_FLAG_SUPP_MOVED_MIGR) {
		snprintf(bp, buflen - (bp - buf), "MOVED_MIGR ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_BIND_PRINC_STATEID) {
		snprintf(bp, buflen - (bp - buf), "PRINC_STATEID ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_USE_NON_PNFS) {
		snprintf(bp, buflen - (bp - buf), "NON_PNFS ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_USE_PNFS_MDS) {
		snprintf(bp, buflen - (bp - buf), "PNFS_MDS ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_USE_PNFS_DS) {
		snprintf(bp, buflen - (bp - buf), "PNFS_DS ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_UPD_CONFIRMED_REC_A) {
		snprintf(bp, buflen - (bp - buf), "CONFIRMED_REC_A ");
		bp += strlen(bp);
	}

	if (flag & EXCHGID4_FLAG_CONFIRMED_R) {
		snprintf(bp, buflen - (bp - buf), "CONFIRMED_R ");
		bp += strlen(bp);
	}

	return (buf);
}
static char *
sum_ps_name(state_protect_how4 type)
{
	static char buf[32];

	if (type < num_ps)
		return (ps_names[type].short_name);
	else {
		sprintf(buf, "ps_how=%d", type);
		return (buf);
	}
}

static char *
detail_ps_name(state_protect_how4 type)
{
	static char buf[64];

	if (type < num_ps)
		return (ps_names[type].long_name);
	else {
		sprintf(buf, "Unkown protect state type = %d", type);
		return (buf);
	}
}

static void
sum_ei_state_protect4_a(char *buf, size_t buflen, state_protect4_a *spa)
{
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_ps_name(spa->spa_how));
}

static void
detail_ei_state_protect4_a(state_protect4_a *spa)
{
	sprintf(get_line(0, 0), "State protest = %s",
	    detail_ps_name(spa->spa_how));
}

static void
sum_ei_state_protect4_r(char *buf, size_t buflen, state_protect4_r *spr)
{
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_ps_name(spr->spr_how));
}

static void
detail_ei_state_protect4_r(state_protect4_r *spr)
{
	sprintf(get_line(0, 0), "State protect = %s",
	    detail_ps_name(spr->spr_how));
}

static void
sum_nfs_impl_id4(char *buf, size_t buflen, nfs_impl_id4 *impl)
{
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%*s.",
	    impl->nii_name.utf8string_len,
	    impl->nii_name.utf8string_val);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%*s ",
	    impl->nii_domain.utf8string_len,
	    impl->nii_domain.utf8string_val);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    format_time(impl->nii_date.seconds, impl->nii_date.nseconds));
	bp += strlen(bp);
}

static void
detail_nfs_impl_id4(nfs_impl_id4 *impl)
{
	sprintf(get_line(0, 0), "Domain = %*s",
	    impl->nii_domain.utf8string_len,
	    impl->nii_domain.utf8string_val);
	sprintf(get_line(0, 0), "Name = %*s",
	    impl->nii_name.utf8string_len,
	    impl->nii_name.utf8string_val);
	sprintf(get_line(0, 0), "Time = %s",
	    format_time(impl->nii_date.seconds, impl->nii_date.nseconds));
}

static void
sumarg_exchange_id(char *buf, size_t buflen, void *obj)
{
	EXCHANGE_ID4args *args = (EXCHANGE_ID4args *)obj;
	nfs_impl_id4 *impl;
	char *bp = buf;
	int i, n;

	snprintf(bp, buflen, "%s",
	    sum_verifier(args->eia_clientowner.co_verifier));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " COID=%04X",
	    cowner_hash(&args->eia_clientowner.co_ownerid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    print_ei_flag(args->eia_flags));
	bp += strlen(bp);
	sum_ei_state_protect4_a(bp, buflen - (bp - buf),
	    &args->eia_state_protect);
	bp += strlen(bp);

	n = args->eia_client_impl_id.eia_client_impl_id_len;
	impl = args->eia_client_impl_id.eia_client_impl_id_val;
	for (i = 0; i < n; i++) {
		sum_nfs_impl_id4(bp, buflen - (bp - buf), impl + i);
		bp += strlen(bp);
	}
}

static void
dtlarg_exchange_id(void *obj)
{
	nfs_impl_id4 *impl;
	int n, i;

	EXCHANGE_ID4args *args = (EXCHANGE_ID4args *)obj;

	detail_verifier(args->eia_clientowner.co_verifier);
	sprintf(get_line(0, 0), "Client Owner ID hash = [%04X] ",
	    cowner_hash(&args->eia_clientowner.co_ownerid));
	sprintf(get_line(0, 0), "    (%d) %s",
	    args->eia_clientowner.co_ownerid.co_ownerid_len,
	    tohex(args->eia_clientowner.co_ownerid.co_ownerid_val,
	    args->eia_clientowner.co_ownerid.co_ownerid_len));
	sprintf(get_line(0, 0), "Flag = %s",
	    print_ei_flag(args->eia_flags));
	detail_ei_state_protect4_a(&args->eia_state_protect);

	n = args->eia_client_impl_id.eia_client_impl_id_len;
	impl = args->eia_client_impl_id.eia_client_impl_id_val;
	for (i = 0; i < n; i++)
		detail_nfs_impl_id4(impl + i);
}

static void
sumres_exchange_id(char *buf, size_t buflen, void *obj)
{
	EXCHANGE_ID4res *res = (EXCHANGE_ID4res *)obj;
	EXCHANGE_ID4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->eir_status));
	if (res->eir_status != NFS4_OK)
		return;

	resok = &res->EXCHANGE_ID4res_u.eir_resok4;
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_clientid(resok->eir_clientid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_sequenceid(resok->eir_sequenceid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    print_ei_flag(resok->eir_flags));
	bp += strlen(bp);
	sum_ei_state_protect4_r(bp, buflen - (bp - buf),
	    &resok->eir_state_protect);
}

static void
detail_server_owner(server_owner4 owner)
{
	sprintf(get_line(0, 0), "Server owner minor ID = %llu",
	    owner.so_minor_id);
	if (owner.so_major_id.so_major_id_len != 0)
		sprintf(get_line(0, 0), "Server owner major ID = %s",
		    tohex(owner.so_major_id.so_major_id_val,
		    owner.so_major_id.so_major_id_len));
	else
		sprintf(get_line(0, 0), "Server owner major ID is not set");
}

static void
dtlres_exchange_id(void *obj)
{
	EXCHANGE_ID4res *res = (EXCHANGE_ID4res *)obj;
	EXCHANGE_ID4resok *resok;
	nfs_impl_id4 *impl;
	int i, n;

	dtl_nfsstat4(obj);
	if (res->eir_status != NFS4_OK)
		return;

	resok = &res->EXCHANGE_ID4res_u.eir_resok4;
	detail_clientid(resok->eir_clientid);
	detail_sequenceid(resok->eir_sequenceid);
	sprintf(get_line(0, 0), "Flag = %s",
	    print_ei_flag(resok->eir_flags));
	detail_ei_state_protect4_r(&resok->eir_state_protect);
	detail_server_owner(resok->eir_server_owner);
	if (resok->eir_server_scope.eir_server_scope_len == 0) {
		sprintf(get_line(0, 0), "Server scope is not set");
		return;
	}
	sprintf(get_line(0, 0), "Server scope = %s",
	    tohex(resok->eir_server_scope.eir_server_scope_val,
	    resok->eir_server_scope.eir_server_scope_len));

	impl = resok->eir_server_impl_id.eir_server_impl_id_val;
	n = resok->eir_server_impl_id.eir_server_impl_id_len;
	for (i = 0; i < n; i++)
		detail_nfs_impl_id4(impl + i);
}

static char *
sum_bcts_dir_from_client(channel_dir_from_client4 type)
{
	char *result;

	switch (type) {
	case 0x1:
		result = "FORE";
		break;
	case 0x2:
		result = "BACK";
		break;
	case 0x3:
		result = "FORE or BOTH";
		break;
	case 0x7:
		result = "BACK or BOTH";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

static void
detail_bcts_dir_from_client(channel_dir_from_client4 type)
{
	char *bp = get_line(0, 0);

	switch (type) {
	case 0x1:
		sprintf(bp, "Binding to fore channel");
		break;
	case 0x2:
		sprintf(bp, "Binding to back channel");
		break;
	case 0x3:
		sprintf(bp, "Binding to fore or both channel");
		break;
	case 0x7:
		sprintf(bp, "Binding to back or both channel");
	default:
		sprintf(bp, "Binding to invalid channel");
		break;
	}
}

static char *
sum_bcts_dir_from_server(channel_dir_from_server4 type)
{
	char *result;

	switch (type) {
	case 0x1:
		result = "FORE";
		break;
	case 0x2:
		result = "BACK";
		break;
	case 0x3:
		result = "BOTH";
		break;
	default:
		result = "?";
		break;
	}

	return (result);
}

static void
detail_bcts_dir_from_server(channel_dir_from_server4 type)
{
	char *bp = get_line(0, 0);

	switch (type) {
	case 0x1:
		sprintf(bp, "Binding to fore channel");
		break;
	case 0x2:
		sprintf(bp, "Binding to back channel");
		break;
	case 0x3:
		sprintf(bp, "Binding to both channel");
		break;
	default:
		sprintf(bp, "Binding to invalid channel");
		break;
	}
}

static void
detail_bcts_nonce(uint64_t val)
{
	sprintf(get_line(0, 0), "Nonce value = %llu", val);
}

static void
sumarg_bind_conn_to_session(char *buf, size_t buflen, void *obj)
{
	BIND_CONN_TO_SESSION4args *args = (BIND_CONN_TO_SESSION4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "%s", sum_sessionid(args->bctsa_sessid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_bcts_dir_from_client(args->bctsa_dir));
	bp += strlen(bp);
}

static void
dtlarg_bind_conn_to_session(void *obj)
{
	BIND_CONN_TO_SESSION4args *args = (BIND_CONN_TO_SESSION4args *)obj;

	detail_sessionid(args->bctsa_sessid);
	detail_bcts_dir_from_client(args->bctsa_dir);
	detail_use_in_rdma_mode(args->bctsa_use_conn_in_rdma_mode);
}

static void
sumres_bind_conn_to_session(char *buf, size_t buflen, void *obj)
{
	BIND_CONN_TO_SESSION4res *res = (BIND_CONN_TO_SESSION4res *)obj;
	BIND_CONN_TO_SESSION4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->bctsr_status));
	if (res->bctsr_status == NFS4_OK) {
		resok = &res->BIND_CONN_TO_SESSION4res_u.bctsr_resok4;
		snprintf(bp, buflen, "%s", sum_sessionid(resok->bctsr_sessid));
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_bcts_dir_from_server(resok->bctsr_dir));
		bp += strlen(bp);
	}
}

static void
dtlres_bind_conn_to_session(void *obj)
{
	BIND_CONN_TO_SESSION4res *res = (BIND_CONN_TO_SESSION4res *)obj;
	BIND_CONN_TO_SESSION4resok *resok;

	dtl_nfsstat4(obj);
	if (res->bctsr_status == NFS4_OK) {
		resok = &res->BIND_CONN_TO_SESSION4res_u.bctsr_resok4;
		detail_sessionid(resok->bctsr_sessid);
		detail_bcts_dir_from_server(resok->bctsr_dir);
		detail_use_in_rdma_mode(resok->bctsr_use_conn_in_rdma_mode);
	}
}

static void
sumarg_backchannel_ctl(char *buf, size_t buflen, void *obj)
{
	BACKCHANNEL_CTL4args *args = (BACKCHANNEL_CTL4args *)obj;
	char *bp = buf;
	uint_t i;

	sprintf(bp, "CB=%u", args->bca_cb_program);
	for (i = 0; i < args->bca_sec_parms.bca_sec_parms_len; i++) {
		bp += strlen(bp);
		sum_sec_parm(bp, buflen - (bp - buf),
		    args->bca_sec_parms.bca_sec_parms_val[i]);
	}
}

static void
dtlarg_backchannel_ctl(void *obj)
{
	BACKCHANNEL_CTL4args *args = (BACKCHANNEL_CTL4args *)obj;
	uint_t i;

	sprintf(get_line(0, 0), "Callback program ID = %u",
	    args->bca_cb_program);
	for (i = 0; i < args->bca_sec_parms.bca_sec_parms_len; i++)
		detail_sec_parm(args->bca_sec_parms.bca_sec_parms_val[i]);
}

static void
sumarg_set_ssv(char *buf, size_t buflen, void *obj)
{
	SET_SSV4args *args = (SET_SSV4args *)obj;

	snprintf(buf, buflen, "SSV=%s DG=%s",
	    tohex(args->ssa_ssv.ssa_ssv_val, args->ssa_ssv.ssa_ssv_len),
	    tohex(args->ssa_digest.ssa_digest_val,
	    args->ssa_digest.ssa_digest_len));
}

static void
dtlarg_set_ssv(void *obj)
{
	SET_SSV4args *args = (SET_SSV4args *)obj;

	sprintf(get_line(0, 0), "SSV = %s",
	    tohex(args->ssa_ssv.ssa_ssv_val, args->ssa_ssv.ssa_ssv_len));
	sprintf(get_line(0, 0), "Digest = %s",
	    tohex(args->ssa_digest.ssa_digest_val,
	    args->ssa_digest.ssa_digest_len));
}

static void
sumres_set_ssv(char *buf, size_t buflen, void *obj)
{
	SET_SSV4res *res = (SET_SSV4res *)obj;
	SET_SSV4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->ssr_status));
	bp += strlen(bp);
	if (res->ssr_status == NFS4_OK) {
		resok = &res->SET_SSV4res_u.ssr_resok4;
		snprintf(bp, buflen - (bp - buf), "DG=%s",
		    tohex(resok->ssr_digest.ssr_digest_val,
		    resok->ssr_digest.ssr_digest_len));
	}
}

static void
dtlres_set_ssv(void *obj)
{
	SET_SSV4res *res = (SET_SSV4res *)obj;
	SET_SSV4resok *resok;

	dtl_nfsstat4(obj);
	if (res->ssr_status == NFS4_OK) {
		resok = &res->SET_SSV4res_u.ssr_resok4;
		sprintf(get_line(0, 0), "Digest = %s",
		    tohex(resok->ssr_digest.ssr_digest_val,
		    resok->ssr_digest.ssr_digest_len));
	}
}

static void
sumarg_destroy_session(char *buf, size_t buflen, void *obj)
{
	DESTROY_SESSION4args *args = (DESTROY_SESSION4args *)obj;

	snprintf(buf, buflen, "%s", sum_sessionid(args->dsa_sessionid));
}

static void
dtlarg_destroy_session(void *obj)
{
	DESTROY_SESSION4args *args = (DESTROY_SESSION4args *)obj;

	detail_sessionid(args->dsa_sessionid);
}

static void
sumarg_sequence(char *buf, size_t buflen, void *obj)
{
	SEQUENCE4args *args = (SEQUENCE4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "%s ", sum_sessionid(args->sa_sessionid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    sum_sequenceid(args->sa_sequenceid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "SLID=%u", args->sa_slotid);
}

static void
dtlarg_sequence(void *obj)
{
	SEQUENCE4args *args = (SEQUENCE4args *)obj;

	detail_sessionid(args->sa_sessionid);
	detail_sequenceid(args->sa_sequenceid);
	sprintf(get_line(0, 0), "Slot ID = %u", args->sa_slotid);
	sprintf(get_line(0, 0), "Highest slotid = %u", args->sa_highest_slotid);
	sprintf(get_line(0, 0), "Cache flag = %s",
	    args->sa_cachethis? "TRUE" : "FALSE");
}

static char *
sum_seq_status(uint32_t status)
{
	static char buf[32];

	snprintf(buf, sizeof (buf), "ST=%x", status);
	return (buf);
}

static void
detail_seq_status(uint32_t status)
{
	int bit;

	sprintf(get_line(0, 0), "status = %x", status);
	for (bit = 0; bit < SEQ_STATUS_MAX; bit++) {
		if (status & (1 << bit)) {
			sprintf(get_line(0, 0), "\t%s",
			    seq_status[bit]);
		}
	}
}

static void
sumres_sequence(char *buf, size_t buflen, void *obj)
{
	SEQUENCE4res *res = (SEQUENCE4res *)obj;
	SEQUENCE4resok *resok;
	char *bp = buf;

	strncpy(bp, status_name(res->sr_status), buflen);
	if (res->sr_status == NFS4_OK) {
		resok = &res->SEQUENCE4res_u.sr_resok4;
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_sessionid(resok->sr_sessionid));
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_sequenceid(resok->sr_sequenceid));
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " SLID=%u",
		    resok->sr_slotid);
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_seq_status(resok->sr_status_flags));
	}
}

static void
dtlres_sequence(void *obj)
{
	SEQUENCE4res *res = (SEQUENCE4res *)obj;
	SEQUENCE4resok *resok;

	dtl_nfsstat4(obj);
	if (res->sr_status == NFS4_OK) {
		resok = &res->SEQUENCE4res_u.sr_resok4;
		detail_sessionid(resok->sr_sessionid);
		detail_sequenceid(resok->sr_sequenceid);
		sprintf(get_line(0, 0), "Slot ID = %u", resok->sr_slotid);
		sprintf(get_line(0, 0), "Highest slotid = %u",
		    resok->sr_highest_slotid);
		sprintf(get_line(0, 0), "Target highest slotid = %u",
		    resok->sr_target_highest_slotid);
		detail_seq_status(resok->sr_status_flags);
	}
}

static void
sumarg_cb_sequence(char *buf, size_t buflen, void *obj)
{
	CB_SEQUENCE4args *args = (CB_SEQUENCE4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "%s ", sum_sessionid(args->csa_sessionid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    sum_sequenceid(args->csa_sequenceid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "SLID=%u", args->csa_slotid);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "cachethis=%d",
	    args->csa_cachethis);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "num calls = %d",
	    args->csa_referring_call_lists.csa_referring_call_lists_len);
	bp += strlen(bp);
}

static void
detail_referring_call_list(uint_t ref, referring_call_list4 list)
{
	referring_call4 *call;
	uint_t i;

	sprintf(get_line(0, 0),
	    "Referring call list[%u]: Session ID = %s",
	    i, tohex(list.rcl_sessionid, 16));

	for (i = 0;
	    i < list.rcl_referring_calls.rcl_referring_calls_len;
	    i++) {

		call = &list.rcl_referring_calls.rcl_referring_calls_val[i];
		sprintf(get_line(0, 0),
		    "    Sequence ID = %u   Slot ID = %u",
		    call->rc_sequenceid, call->rc_slotid);
	}
}

static void
dtlarg_cb_sequence(void *obj)
{
	CB_SEQUENCE4args *args = (CB_SEQUENCE4args *)obj;
	referring_call_list4 *list;
	uint_t i;

	detail_sessionid(args->csa_sessionid);
	detail_sequenceid(args->csa_sequenceid);
	sprintf(get_line(0, 0), "Slot ID = %u", args->csa_slotid);
	sprintf(get_line(0, 0), "Highest slot = %u", args->csa_highest_slotid);
	sprintf(get_line(0, 0), "Cache this = %s",
	    args->csa_cachethis ? "TRUE" : "FALSE");

	list = args->csa_referring_call_lists.csa_referring_call_lists_val;
	for (i = 0;
	    i < args->csa_referring_call_lists.csa_referring_call_lists_len;
	    i++) {
		detail_referring_call_list(i, list[i]);
	}
}

static void
sumres_cb_sequence(char *buf, size_t buflen, void *obj)
{
	CB_SEQUENCE4res *res = (CB_SEQUENCE4res *)obj;
	CB_SEQUENCE4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->csr_status));
	if (res->csr_status != NFS4_OK)
		return;

	resok = &res->CB_SEQUENCE4res_u.csr_resok4;
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    sum_sessionid(resok->csr_sessionid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "%s ",
	    sum_sequenceid(resok->csr_sequenceid));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "SLID=%u ",
	    resok->csr_slotid);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "Highest SLID=%u ",
	    resok->csr_highest_slotid);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), "Target highest SLID=%u ",
	    resok->csr_target_highest_slotid);
	bp += strlen(bp);
}

static void
dtlres_cb_sequence(void *obj)
{
	CB_SEQUENCE4res *res = (CB_SEQUENCE4res *)obj;
	CB_SEQUENCE4resok *resok;

	dtl_nfsstat4(obj);
	if (res->csr_status == NFS4_OK) {
		resok = &res->CB_SEQUENCE4res_u.csr_resok4;
		detail_sessionid(resok->csr_sessionid);
		detail_sequenceid(resok->csr_sequenceid);
		sprintf(get_line(0, 0), "Slot ID = %u", resok->csr_slotid);
		sprintf(get_line(0, 0), "Highest slotid = %u",
		    resok->csr_highest_slotid);
		sprintf(get_line(0, 0), "Target highest slotid = %u",
		    resok->csr_target_highest_slotid);
	}
}

static void
sumarg_test_stateid(char *buf, size_t buflen, void *obj)
{
	TEST_STATEID4args *args = (TEST_STATEID4args *)obj;
	stateid4 *stateid;
	char prefix[32];
	char *bp = buf;
	uint_t i;

	for (i = 0; i < args->ts_stateids.ts_stateids_len; i++) {
		stateid = &args->ts_stateids.ts_stateids_val[i];
		sprintf(prefix, "ST[%u]=", i);
		snprintf(bp, buflen - (bp - buf), "%s ",
		    cmn_sum_stateid(stateid, prefix));
		bp += strlen(bp);
	}
}

static void
dtlarg_test_stateid(void *obj)
{
	TEST_STATEID4args *args = (TEST_STATEID4args *)obj;
	stateid4 *stateid;
	char prefix[32];
	uint_t i;

	for (i = 0; i < args->ts_stateids.ts_stateids_len; i++) {
		stateid = &args->ts_stateids.ts_stateids_val[i];
		sprintf(prefix, "[%u] : ", i);
		cmn_detail_stateid(stateid, prefix);
	}
}

static void
sum_ts_resok(char *buf, size_t buflen, TEST_STATEID4resok *resok)
{
	nfsstat4 status;
	char *bp = buf;
	uint_t i;

	for (i = 0;
	    i < resok->tsr_status_codes.tsr_status_codes_len;
	    i++) {

		status = resok->tsr_status_codes.tsr_status_codes_val[i];
		if (i == 0)
			snprintf(bp, buflen - (bp - buf), " ");
		if (i > 0)
			snprintf(bp, buflen - (bp - buf), ",");
		bp += strlen(bp);
		sum_nfsstat4(bp, buflen - (bp -buf), &status);
		bp += strlen(bp);
	}
}

static void
sumres_test_stateid(char *buf, size_t buflen, void *obj)
{
	TEST_STATEID4res *res = (TEST_STATEID4res *)obj;
	char *bp = buf;

	strncpy(bp, status_name(res->tsr_status), buflen);
	if (res->tsr_status == NFS4_OK) {
		bp += strlen(bp);
		sum_ts_resok(bp, buflen - (bp - buf),
		    &res->TEST_STATEID4res_u.tsr_resok4);
	}
}

static void
detail_ts_resok(TEST_STATEID4resok *resok)
{
	nfsstat4 status;
	uint_t i;

	for (i = 0;
	    i < resok->tsr_status_codes.tsr_status_codes_len;
	    i++) {

		status = resok->tsr_status_codes.tsr_status_codes_val[i];
		sprintf(get_line(0, 0), "[%u] : Status %d (%s)",
		    i, status, status_name(status));
	}
}

static void
dtlres_test_stateid(void *obj)
{
	TEST_STATEID4res *res = (TEST_STATEID4res *)obj;
	nfsstat4 status;

	dtl_nfsstat4(obj);
	if (res->tsr_status == NFS4_OK)
		detail_ts_resok(&res->TEST_STATEID4res_u.tsr_resok4);
}

static void
sumarg_free_stateid(char *buf, size_t buflen, void *obj)
{
	FREE_STATEID4args *args = (FREE_STATEID4args *)obj;

	snprintf(buf, buflen, "%s", cmn_sum_stateid(&args->fsa_stateid, "ST="));
}

static void
dtlarg_free_stateid(void *obj)
{
	FREE_STATEID4args *args = (FREE_STATEID4args *)obj;

	cmn_detail_stateid(&args->fsa_stateid, "");
}

static void
sumarg_get_dir_delegation(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_get_dir_delegation(void *obj)
{
}

static void
sumres_get_dir_delegation(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_get_dir_delegation(void *obj)
{
}

static char *
detail_lortype_name(layoutrecall_type4 lortype)
{
	static char buf[32];

	if (lortype < num_lortypes)
		return (lortype_names[lortype].long_name);

	sprintf(buf, "lorec_type=%d", lortype);
	return (buf);
}


static char *
sum_lortype_name(layoutrecall_type4 lortype)
{
	static char buf[32];

	if (lortype < num_lortypes)
		return (lortype_names[lortype].short_name);

	sprintf(buf, "lorec_type=%d", lortype);
	return (buf);
}

static char *
sum_lotype_name(layouttype4 type)
{
	static char buf[32];

	if (type < num_lotypes)
		return (lotype_names[type].short_name);
	else {
		sprintf(buf, "lotype=%d", type);
		return (buf);
	}
}

char *
detail_lotype_name(layouttype4 type)
{
	static char buf[64];

	if (type >= 0 && type < num_lotypes)
		return (lotype_names[type].long_name);
	else {
		sprintf(buf, "Unknown layout type(%d)", type);
		return (buf);
	}
}

static char *
sum_iomode_name(layoutiomode4 mode)
{
	static char buf[32];

	if (mode < num_iomodes)
		return (iomode_names[mode].short_name);
	else {
		sprintf(buf, "iomode=%d", mode);
		return (buf);
	}
}

char *
detail_iomode_name(layoutiomode4 mode)
{
	static char buf[64];

	if (mode < num_iomodes)
		return (iomode_names[mode].long_name);
	else {
		sprintf(buf, "Unknown layout iomode = %d", mode);
		return (buf);
	}
}

static char *
sum_lrtype_name(layoutreturn_type4 type)
{
	static char buf[32];

	if (type < num_lrtypes)
		return (lrtype_names[type].short_name);
	else {
		sprintf(buf, "lrtype=%d", type);
		return (buf);
	}
}

static char *
detail_lrtype_name(layoutreturn_type4 type)
{
	static char buf[64];

	if (type < num_lrtypes)
		return (lrtype_names[type].long_name);
	else {
		sprintf(buf, "Unkown layoutreturn type = %d", type);
		return (buf);
	}
}

static void
print_netaddr4(char *buf, size_t buflen, netaddr4 *na)
{
	char *copy = NULL;
	char *bp = buf;

	/*
	 * We are always able to print addr/net.  We try to print
	 * more helpful formats for the more common netids.
	 *
	 * For "tcp", which is tcp/IPv4, we try to print hostname:portnumber,
	 * or if hostname cannot be determined, we try to print
	 * ipaddr:portnumber.
	 */
	if (strcmp("tcp", na->na_r_netid) == 0) {
#ifdef REVERSE_DNS
		char *copy = strdup(na->na_r_addr);
		struct hostent *host;
		struct in_addr addr;
		char *penultimate;
		char *ultimate;
		int port;

		/* chop off final two octets */
		ultimate = strrchr(copy, '.');
		if (ultimate == NULL)
			goto failsafe;
		*(ultimate++) = '\0';
		penultimate = strrchr(copy, '.');
		if (penultimate == NULL)
			goto failsafe;
		*(penultimate++) = '\0';

		/* convert final two octets into port number */
		errno = 0;
		port = strtol(penultimate, NULL, 0) << 8 +
		    strtol(ultimate, NULL, 0);
		if (errno != 0)
			goto failsafe;

		/* try to convert IPv4 into host name */
		if ((inet_aton(copy, &addr)) &&
		    ((host = gethostbyaddr((char *)&addr,
		    4, AF_INET)) != NULL)) {
			snprintf(bp, buflen - (bp - buf), " %s", host->h_name);
		/* otherwise, use IP address */
		} else {
			snprintf(bp, buflen - (bp - buf), " %s", copy);
		}
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), ":%d/tcp", port);
#endif
		snprintf(bp, buflen - (bp - buf), "tcp:%s", na->na_r_addr);

		return;
	}

failsafe:
	/* just print "address/netid". */
	if (copy != NULL)
		free(copy);
	snprintf(bp, buflen - (bp - buf), "%s/%s",
	    na->na_r_addr, na->na_r_netid);
}

static void
print_multipath_list4(char *buf, size_t buflen, multipath_list4 *mpl)
{
	char *bp = buf;
	netaddr4 *addr;
	int i, n;

	n = mpl->multipath_list4_len;
	addr = mpl->multipath_list4_val;

	for (i = 0; i < n; i++) {
		sprintf(bp, " [%u] ", i);
		bp += strlen(bp);
		print_netaddr4(bp, buflen - (bp - buf), addr + i);
		bp += strlen(bp);
	}
}


static void
sum_devaddr(char *buf, size_t buflen,
	device_addr4 *d_addr, layouttype4 type)
{
	nfsv4_1_file_layout_ds_addr4 devi;
	netaddr4 *addr;
	multipath_list4 *mpl;
	XDR xdr;
	int i, n;
	uint32_t *index;
	char *bp = buf;

	if (type == LAYOUT4_NFSV4_1_FILES) {
		xdrmem_create(&xdr,
		    d_addr->da_addr_body.da_addr_body_val,
		    d_addr->da_addr_body.da_addr_body_len, XDR_DECODE);
		bzero(&devi, sizeof (devi));
		if (! xdr_nfsv4_1_file_layout_ds_addr4(&xdr, &devi))
			longjmp(xdr_err, 1);

		n = devi.nflda_stripe_indices.nflda_stripe_indices_len;
		index = devi.nflda_stripe_indices.nflda_stripe_indices_val;
		for (i = 0; i < n; i++) {
			snprintf(bp, buflen - (bp - buf), "%s%u",
			    i ? "," : " ", index[i]);
			bp += strlen(bp);
		}

		n = devi.nflda_multipath_ds_list.nflda_multipath_ds_list_len;
		mpl = devi.nflda_multipath_ds_list.nflda_multipath_ds_list_val;
		for (i = 0; i < n; i++) {
			print_multipath_list4(bp, buflen - (bp - buf), mpl + i);
			bp += strlen(bp);
		}

		xdr_free(xdr_nfsv4_1_file_layout_ds_addr4, (char *)&devi);
	}
}

static void
detail_devaddr(device_addr4 *d_addr, layouttype4 type)
{
	nfsv4_1_file_layout_ds_addr4 devi;
	netaddr4 *addr;
	multipath_list4 *mpl;
	XDR xdr;
	int i, n;
	uint32_t *index;
	char *bp, *buf;
	size_t buflen;

	if (type == LAYOUT4_NFSV4_1_FILES) {
		xdrmem_create(&xdr,
		    d_addr->da_addr_body.da_addr_body_val,
		    d_addr->da_addr_body.da_addr_body_len, XDR_DECODE);
		bzero(&devi, sizeof (devi));
		if (! xdr_nfsv4_1_file_layout_ds_addr4(&xdr, &devi))
			longjmp(xdr_err, 1);

		n = devi.nflda_stripe_indices.nflda_stripe_indices_len;
		index = devi.nflda_stripe_indices.nflda_stripe_indices_val;
		buf = get_line(0, 0);
		buflen = SUM_COMPND_MAX;
		sprintf(buf, "    stripe_indices:");
		bp = buf + strlen(buf);
		for (i = 0; i < n; i++) {
			snprintf(bp, buflen - (bp - buf), "%s%u",
			    i ? ", " : " ", index[i]);
			bp += strlen(bp);
		}

		n = devi.nflda_multipath_ds_list.nflda_multipath_ds_list_len;
		mpl = devi.nflda_multipath_ds_list.nflda_multipath_ds_list_val;
		for (i = 0; i < n; i++) {
			buf = get_line(0, 0);
			buflen = SUM_COMPND_MAX;
			sprintf(buf, "    multipath_ds_list[%u]:", i);
			bp = buf + strlen(buf);
			print_multipath_list4(bp, buflen - (bp - buf), mpl + i);
		}

		xdr_free(xdr_nfsv4_1_file_layout_ds_addr4, (char *)&devi);
	}
}

static void
detail_deviceid(deviceid4 did)
{
	sprintf(get_line(0, 0), "Device ID hash = [%04X] ",
	    deviceid_hash(did));
	sprintf(get_line(0, 0), "    (16) %s",
	    tohex(did, 16));
}

static void
sumarg_getdeviceinfo(char *buf, size_t buflen, void *obj)
{
	GETDEVICEINFO4args *args = (GETDEVICEINFO4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen, "DID=%04X",
	    deviceid_hash(args->gdia_device_id));

	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_lotype_name(args->gdia_layout_type));

	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " MAX=%u",
	    args->gdia_maxcount);
}

static void
dtlarg_getdeviceinfo(void *obj)
{
	GETDEVICEINFO4args *args = (GETDEVICEINFO4args *)obj;
	bitmap4 *bp;
	int i;

	detail_deviceid(args->gdia_device_id);
	sprintf(get_line(0, 0), "Layout Type = %s",
	    detail_lotype_name(args->gdia_layout_type));
	sprintf(get_line(0, 0), "Max count = %u", args->gdia_maxcount);
	bp = &args->gdia_notify_types;
	sprintf(get_line(0, 0), "bitmap4_len = %u", bp->bitmap4_len);
	for (i = 0; i < bp->bitmap4_len; i++)
		sprintf(get_line(0, 0), "value: 0x%x", bp->bitmap4_val[i]);
}

static void
sumres_getdeviceinfo(char *buf, size_t buflen, void *obj)
{
	GETDEVICEINFO4res *res = (GETDEVICEINFO4res *)obj;
	GETDEVICEINFO4resok *resok;
	char *bp = buf;
	layouttype4 lotype;

	strcpy(bp, status_name(res->gdir_status));
	if (res->gdir_status == NFS4_OK) {
		resok = &res->GETDEVICEINFO4res_u.gdir_resok4;
		lotype = resok->gdir_device_addr.da_layout_type;
		bp += strlen(bp);
		if (lotype == LAYOUT4_NFSV4_1_FILES) {
			snprintf(bp, buflen - (bp - buf), " DEV=");
			bp += strlen(bp);
			sum_devaddr(bp, buflen - (bp - buf),
			    &resok->gdir_device_addr, lotype);
		}
	}
}

static void
dtlres_getdeviceinfo(void *obj)
{
	GETDEVICEINFO4res *res = (GETDEVICEINFO4res *)obj;
	GETDEVICEINFO4resok *resok;
	layouttype4 lotype;
	char *buf;

	dtl_nfsstat4(obj);
	if (res->gdir_status == NFS4_OK) {
		resok = &res->GETDEVICEINFO4res_u.gdir_resok4;
		lotype = resok->gdir_device_addr.da_layout_type;
		sprintf(get_line(0, 0), "Layout type = %s",
		    detail_lotype_name(lotype));
		if (lotype == LAYOUT4_NFSV4_1_FILES) {
			sprintf(get_line(0, 0), "Device address: ");
			detail_devaddr(&resok->gdir_device_addr, lotype);
		}
	}
}

static void
sumarg_getdevicelist(char *buf, size_t buflen, void *obj)
{
	GETDEVICELIST4args *args = (GETDEVICELIST4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%s",
	    sum_lotype_name(args->gdla_layout_type));
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " Max=%u", args->gdla_maxdevices);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " CK=%llx", args->gdla_cookie);
	bp += strlen(bp);
	snprintf(bp, buflen - (bp - buf), " %s",
	    sum_verifier(args->gdla_cookieverf));
}

static void
dtlarg_getdevicelist(void *obj)
{
	GETDEVICELIST4args *args = (GETDEVICELIST4args *)obj;

	sprintf(get_line(0, 0), "%s",
	    detail_lotype_name(args->gdla_layout_type));
	sprintf(get_line(0, 0), "Max device count = %u", args->gdla_maxdevices);
	sprintf(get_line(0, 0), "NFS Cookie = %llx", args->gdla_cookie);
	detail_verifier(args->gdla_cookieverf);
}

static void
sum_devicelist(char *buf, size_t buflen, GETDEVICELIST4resok *resok)
{
	deviceid4 *devid;
	char *bp = buf;
	uint_t i, len;

	len = resok->gdlr_deviceid_list.gdlr_deviceid_list_len;
	if (!len) {
		snprintf(bp, buflen, "NO_DEV");
		return;
	}
	for (i = 0; i < len; i++) {
		devid = &resok->gdlr_deviceid_list.gdlr_deviceid_list_val[i];
		snprintf(bp, buflen - (bp - buf), " DEV[i]=%04X ",
		    deviceid_hash(*devid));
		bp += strlen(bp);
	}
}

static void
sumres_getdevicelist(char *buf, size_t buflen, void *obj)
{
	GETDEVICELIST4res *res = (GETDEVICELIST4res *)obj;
	GETDEVICELIST4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->gdlr_status));
	if (res->gdlr_status == NFS4_OK) {
		resok = &res->GETDEVICELIST4res_u.gdlr_resok4;
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " CK=%llx",
		    resok->gdlr_cookie);
			bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_verifier(resok->gdlr_cookieverf));
		bp += strlen(bp);
		sum_devicelist(bp, buflen - (bp - buf), resok);
	}
}

static void
detail_devicelist(GETDEVICELIST4resok *resok)
{
	deviceid4 *devid;
	uint_t i, len;
	char *buf;
	layouttype4 lotype;

	len = resok->gdlr_deviceid_list.gdlr_deviceid_list_len;
	if (!len) {
		sprintf(get_line(0, 0), "No device list");
		return;
	}
	for (i = 0; i < len; i++) {
		devid = &resok->gdlr_deviceid_list.gdlr_deviceid_list_val[i];
		detail_deviceid(*devid);
	}
}

static void
dtlres_getdevicelist(void *obj)
{
	GETDEVICELIST4res *res = (GETDEVICELIST4res *)obj;
	GETDEVICELIST4resok *resok;

	dtl_nfsstat4(obj);
	if (res->gdlr_status == NFS4_OK) {
		resok = &res->GETDEVICELIST4res_u.gdlr_resok4;
		sprintf(get_line(0, 0), "NFS Cookie = %llx",
		    resok->gdlr_cookie);
		detail_verifier(resok->gdlr_cookieverf);
		detail_devicelist(resok);
		sprintf(get_line(0, 0), "EOF flag = %s",
		    resok->gdlr_eof ? "TRUE" : "FALSE");
	}
}

static void
sumarg_layoutcommit(char *buf, size_t buflen, void *obj)
{
	LAYOUTCOMMIT4args *args = (LAYOUTCOMMIT4args *)obj;
	newoffset4 *noff;
	nfstime4 *time;
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%s",
	    sum_stateid(&args->loca_stateid));
}

static void
dtlarg_layoutcommit(void *obj)
{
	LAYOUTCOMMIT4args *args = (LAYOUTCOMMIT4args *)obj;
	newoffset4 *noff;
	nfstime4 *time;

	sprintf(get_line(0, 0), "Offset = %llu",
	    args->loca_offset);
	sprintf(get_line(0, 0), "Length = %llu",
	    args->loca_length);

	sprintf(get_line(0, 0), "Reclaim = %s",
	    args->loca_reclaim ? "TRUE" : "FALSE");

	detail_stateid(&args->loca_stateid);

	if (args->loca_last_write_offset.no_newoffset) {
		noff = &args->loca_last_write_offset;
		sprintf(get_line(0, 0), "Last write offset = %llu",
		    noff->newoffset4_u.no_offset);
	} else
		sprintf(get_line(0, 0), "No last_write_offset provided");

	if (args->loca_time_modify.nt_timechanged) {
		time = &args->loca_time_modify.newtime4_u.nt_time;
		sprintf(get_line(0, 0), "Time modify = %s",
		    format_time(time->seconds, time->nseconds));
	} else
		sprintf(get_line(0, 0), "No time_modify provided");

	sprintf(get_line(0, 0), "Layoutupdate type = %s",
	    detail_lotype_name(args->loca_layoutupdate.lou_type));
	sprintf(get_line(0, 0), "Layoutupdate data = %s",
	    tohex(args->loca_layoutupdate.lou_body.lou_body_val,
	    args->loca_layoutupdate.lou_body.lou_body_len));
}

static void
sumres_layoutcommit(char *buf, size_t buflen, void *obj)
{
	LAYOUTCOMMIT4res *res = (LAYOUTCOMMIT4res *)obj;
	LAYOUTCOMMIT4resok *resok;
	char *bp = buf;

	strcpy(bp, status_name(res->locr_status));
	if (res->locr_status == NFS4_OK) {
		resok = &res->LAYOUTCOMMIT4res_u.locr_resok4;
		bp += strlen(bp);
		if (resok->locr_newsize.ns_sizechanged)
			snprintf(bp, buflen - (bp - buf), " NSIZE=%llu",
			    resok->locr_newsize.newsize4_u.ns_size);
		else
			snprintf(bp, buflen - (bp - buf), " NO_CHANGE");
	}
}

static void
dtlres_layoutcommit(void *obj)
{
	LAYOUTCOMMIT4res *res = (LAYOUTCOMMIT4res *)obj;
	LAYOUTCOMMIT4resok *resok;

	dtl_nfsstat4(obj);
	if (res->locr_status == NFS4_OK) {
		resok = &res->LAYOUTCOMMIT4res_u.locr_resok4;
		if (resok->locr_newsize.ns_sizechanged)
			sprintf(get_line(0, 0), "Changed size = %llu",
			    resok->locr_newsize.newsize4_u.ns_size);
		else
			sprintf(get_line(0, 0), "The size is not changed");
	}
}

static void
sumarg_layoutget(char *buf, size_t buflen, void *obj)
{
	LAYOUTGET4args *args = (LAYOUTGET4args *)obj;
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%s",
	    sum_stateid(&args->loga_stateid));
}

static void
dtlarg_layoutget(void *obj)
{
	LAYOUTGET4args *args = (LAYOUTGET4args *)obj;

	sprintf(get_line(0, 0), "Signal layout available = %s",
	    args->loga_signal_layout_avail ? "TRUE" : "FALSE");
	sprintf(get_line(0, 0), "Layout type = %s",
	    detail_lotype_name(args->loga_layout_type));
	sprintf(get_line(0, 0), "Layout iomode = %s",
	    detail_iomode_name(args->loga_iomode));
	sprintf(get_line(0, 0), "Offset = %llu",
	    args->loga_offset);
	sprintf(get_line(0, 0), "Length = %llu",
	    args->loga_length);
	sprintf(get_line(0, 0), "Minimum size overlap = %llu",
	    args->loga_minlength);
	detail_stateid(&args->loga_stateid);
	sprintf(get_line(0, 0), "Max count = %u",
	    args->loga_maxcount);
}

static void
sum_file_layout(char *buf, size_t buflen, layout4 *lo)
{
	static nfsv4_1_file_layout4 fl;
	char *bp = buf;
	uint_t i, n;
	nfs_fh4 *fh;
	XDR xdr;

	bzero(&fl, sizeof (fl));
	xdrmem_create(&xdr,
	    lo->lo_content.loc_body.loc_body_val,
	    lo->lo_content.loc_body.loc_body_len,
	    XDR_DECODE);
	if (! xdr_nfsv4_1_file_layout4(&xdr, &fl))
		longjmp(xdr_err, 1);

	snprintf(bp, buflen, " %04X 0x%x",
	    deviceid_hash(fl.nfl_deviceid), fl.nfl_util);
	bp += strlen(bp);
	n = fl.nfl_fh_list.nfl_fh_list_len;
	fh = fl.nfl_fh_list.nfl_fh_list_val;
	for (i = 0; i < n; i++) {
		strncat(bp, " ", buflen - (bp - buf));
		bp += strlen(bp);
		if (i == fl.nfl_first_stripe_index) {
			strncat(bp, "<start>", buflen - (bp - buf));
			bp += strlen(bp);
		}
		snprintf(bp, buflen - (bp - buf), "%04X", fh4_hash(fh + i));
		bp += strlen(bp);
	}

	xdr_free(xdr_nfsv4_1_file_layout4, (char *)&fl);
}

static void
sumres_layoutget(char *buf, size_t buflen, void *obj)
{
	LAYOUTGET4res *res = (LAYOUTGET4res *)obj;
	LAYOUTGET4resok *resok;
	layout4 *lo;
	char *bp = buf;

	strcpy(bp, status_name(res->logr_status));
	if (res->logr_status == NFS4_OK) {
		resok = &res->LAYOUTGET4res_u.logr_resok4;
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), "%s",
		    sum_stateid(&resok->logr_stateid));
	} else if (res->logr_status == NFS4ERR_LAYOUTTRYLATER) {
		bp += strlen(bp);
		snprintf(bp, buflen - (bp - buf), "%s",
		    res->LAYOUTGET4res_u.logr_will_signal_layout_avail ?
		    "SIGNAL" : "NO_SIGNAL");
	}
}

void
detail_file_layout(layout4 *lo)
{
	nfsv4_1_file_layout4 fl;
	uint_t i;
	XDR xdr;

	bzero(&fl, sizeof (fl));
	xdrmem_create(&xdr,
	    lo->lo_content.loc_body.loc_body_val,
	    lo->lo_content.loc_body.loc_body_len,
	    XDR_DECODE);
	if (! xdr_nfsv4_1_file_layout4(&xdr, &fl))
		longjmp(xdr_err, 1);

	detail_deviceid(fl.nfl_deviceid);
	sprintf(get_line(0, 0), "Util = 0x%x", fl.nfl_util);
	sprintf(get_line(0, 0), "    stripe_unit = %d", fl.nfl_util >> 6);
	if (fl.nfl_util & NFL4_UFLG_DENSE)
		sprintf(get_line(0, 0), "    UFLG_DENSE");
	if (fl.nfl_util & NFL4_UFLG_COMMIT_THRU_MDS)
		sprintf(get_line(0, 0), "    UFLG_COMMIT_THRU_MDS");
	sprintf(get_line(0, 0), "First stripe = %d", fl.nfl_first_stripe_index);
	for (i = 0; i < fl.nfl_fh_list.nfl_fh_list_len; i++) {
		sprintf(get_line(0, 0), "fh[%u] = (%u) %s",
		    i, fl.nfl_fh_list.nfl_fh_list_val[i].nfs_fh4_len,
		    tohex(fl.nfl_fh_list.nfl_fh_list_val[i].nfs_fh4_val,
		    fl.nfl_fh_list.nfl_fh_list_val[i].nfs_fh4_len));
	}
	xdr_free(xdr_nfsv4_1_file_layout4, (char *)&fl);
}

static void
dtlres_layoutget(void *obj)
{
	LAYOUTGET4res *res = (LAYOUTGET4res *)obj;
	LAYOUTGET4resok *resok;
	layout4 *lo;
	int i;

	dtl_nfsstat4(obj);
	if (res->logr_status == NFS4_OK) {
		resok = &res->LAYOUTGET4res_u.logr_resok4;
		detail_stateid(&resok->logr_stateid);
		for (i = 0; i < resok->logr_layout.logr_layout_len; i++) {
			lo = &resok->logr_layout.logr_layout_val[i];
			sprintf(get_line(0, 0), "Layout [%u]:", i);
			sprintf(get_line(0, 0), "Return layout on close = %s",
			    resok->logr_return_on_close ? "TRUE" : "FALSE");
			sprintf(get_line(0, 0), "Layout offset = %llu",
			    lo->lo_offset);
			sprintf(get_line(0, 0), "Layout length = %llu",
			    lo->lo_length);
			sprintf(get_line(0, 0), "Layout iomode = %s",
			    detail_iomode_name(lo->lo_iomode));
			sprintf(get_line(0, 0), "Layout type = %s",
			    detail_lotype_name(lo->lo_content.loc_type));
			if (lo->lo_content.loc_type == LAYOUT4_NFSV4_1_FILES) {
				detail_file_layout(lo);
			} else
				sprintf(get_line(0, 0), "Non-file layout = %s",
				    tohex(lo->lo_content.loc_body.loc_body_val,
				    lo->lo_content.loc_body.loc_body_len));
		}
	} else if (res->logr_status == NFS4ERR_LAYOUTTRYLATER) {
		sprintf(get_line(0, 0), "Will signal layout avail = %s",
		    res->LAYOUTGET4res_u.logr_will_signal_layout_avail ?
		    "TRUE" : "FALSE");
	}
}

static void
sumarg_layoutreturn(char *buf, size_t buflen, void *obj)
{
	LAYOUTRETURN4args *args = (LAYOUTRETURN4args *)obj;
	layoutreturn4 *lr = &args->lora_layoutreturn;
	char *bp = buf;

	if (lr->lr_returntype == LAYOUTRETURN4_FILE)
		snprintf(bp, buflen - (bp - buf), "%s",
		    sum_stateid(&lr->layoutreturn4_u.lr_layout.lrf_stateid));
	else
		snprintf(bp, buflen - (bp - buf), "Returntype=%s",
		    sum_lrtype_name(lr->lr_returntype));
}

static void
dtlarg_layoutreturn(void *obj)
{
	LAYOUTRETURN4args *args = (LAYOUTRETURN4args *)obj;
	layoutreturn4 *lr = &args->lora_layoutreturn;

	sprintf(get_line(0, 0), "Reclaim = %s",
	    args->lora_reclaim ? "TRUE" : "FALSE");
	sprintf(get_line(0, 0), "Layout type = %s",
	    detail_lotype_name(args->lora_layout_type));
	sprintf(get_line(0, 0), "Layout iomode = %s",
	    detail_iomode_name(args->lora_iomode));
	sprintf(get_line(0, 0), "Layoutreturn type = %s",
	    detail_lrtype_name(lr->lr_returntype));
	if (lr->lr_returntype == LAYOUTRETURN4_FILE) {
		sprintf(get_line(0, 0), "Layoutreturn Offset = %llu",
		    lr->layoutreturn4_u.lr_layout.lrf_offset);
		sprintf(get_line(0, 0), "Layoutreturn Length = %llu",
		    lr->layoutreturn4_u.lr_layout.lrf_length);
		detail_stateid(&lr->layoutreturn4_u.lr_layout.lrf_stateid);
	}
}


static void
sumarg_secinfo_no_name(char *buf, size_t buflen, void *obj)
{
	char style;

	switch (*(SECINFO_NO_NAME4args *)obj) {
	case SECINFO_STYLE4_CURRENT_FH:
		style = 'C';
		break;
	case SECINFO_STYLE4_PARENT:
		style = 'P';
		break;
	default:
		style = '?';
		break;
	}
	snprintf(buf, buflen, " ST=%c", style);
}

static void
dtlarg_secinfo_no_name(void *obj)
{
	char *style;

	switch (*(SECINFO_NO_NAME4args *)obj) {
	case SECINFO_STYLE4_CURRENT_FH:
		style = "CURRENT_FH";
		break;
	case SECINFO_STYLE4_PARENT:
		style = "PARENT";
		break;
	default:
		style = "???";
		break;
	}
	sprintf(get_line(0, 0), "Style = %s", style);
}

static void
sumarg_want_delegation(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_want_delegation(void *obj)
{
}

static void
sumres_want_delegation(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_want_delegation(void *obj)
{
}

static void
sumarg_destroy_clientid(char *buf, size_t buflen, void *obj)
{
	DESTROY_CLIENTID4args *a = obj;

	snprintf(buf, buflen, "%s",
	    sum_clientid(a->dca_clientid));
}

static void
dtlarg_destroy_clientid(void *obj)
{
	DESTROY_CLIENTID4args *a = obj;

	detail_clientid(a->dca_clientid);
}

static void
sumres_destroy_clientid(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_destroy_clientid(void *obj)
{
}

static void
sumarg_reclaim_complete(char *buf, size_t buflen, void *obj)
{
	RECLAIM_COMPLETE4args *a = obj;
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%s",
	    (a->rca_one_fs) ? "<one-fs>" : "<all-fs>");
	bp += strlen(bp);
}

static void
dtlarg_reclaim_complete(void *obj)
{
	RECLAIM_COMPLETE4args *a = obj;

	sprintf(get_line(0, 0), "One_FS = %d", a->rca_one_fs);
}

static void
sumres_reclaim_complete(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_reclaim_complete(void *obj)
{
}

static void
sumarg_cb_layoutrecall(char *buf, size_t buflen, void *obj)
{
	CB_LAYOUTRECALL4args	*args = (CB_LAYOUTRECALL4args *)obj;
	layoutrecall_file4	*lor_file;
	fsid4			*lor_fsid;
	char *bp = buf;

	switch (args->clora_recall.lor_recalltype) {
	case LAYOUTRECALL4_FILE:
		lor_file = &args->clora_recall.layoutrecall4_u.lor_layout;
		snprintf(bp, buflen - (bp - buf), " %s",
		    sum_stateid(&lor_file->lor_stateid));
		break;
	case LAYOUTRECALL4_FSID:
		lor_fsid = &args->clora_recall.layoutrecall4_u.lor_fsid;
		snprintf(bp, buflen - (bp - buf), " (%llx, %llx)",
		    lor_fsid->major, lor_fsid->minor);
		break;
	}
}

static void
dtlarg_cb_layoutrecall(void *obj)
{
	CB_LAYOUTRECALL4args	*args = (CB_LAYOUTRECALL4args *)obj;
	layoutrecall_file4	*lor_file;
	fsid4			*lor_fsid;

	sprintf(get_line(0, 0), "Layout type        = %s",
	    detail_lotype_name(args->clora_type));

	sprintf(get_line(0, 0), "Layout iomode      = %s",
	    detail_iomode_name(args->clora_iomode));

	sprintf(get_line(0, 0), "Changed            = %s",
	    args->clora_changed ? "TRUE" : "FALSE");

	sprintf(get_line(0, 0), "Layout Recall type = %s",
	    detail_lortype_name(args->clora_recall.lor_recalltype));

	switch (args->clora_recall.lor_recalltype) {
	case LAYOUTRECALL4_FILE:
		lor_file = &args->clora_recall.layoutrecall4_u.lor_layout;
		sprintf(get_line(0, 0), "Layout associated with FILE");
		detail_fh4(&lor_file->lor_fh, "");
		sprintf(get_line(0, 0), "Offset  = %llu",
		    lor_file->lor_offset);
		sprintf(get_line(0, 0), "Length  = %llu",
		    lor_file->lor_length);
		detail_stateid(&lor_file->lor_stateid);
		break;
	case LAYOUTRECALL4_FSID:
		lor_fsid = &args->clora_recall.layoutrecall4_u.lor_fsid;
		sprintf(get_line(0, 0), "Layouts associated with FSID");
		sprintf(get_line(0, 0), "FS ID: Major = %llx, Minor = %llx",
		    lor_fsid->major, lor_fsid->minor);
		break;
	case LAYOUTRECALL4_ALL:
		sprintf(get_line(0, 0), "ALL Layouts");
		break;
	}
}

static void
sumres_cb_layoutrecall(char *buf, size_t buflen, void *obj)
{
	CB_LAYOUTRECALL4res *res = (CB_LAYOUTRECALL4res *)obj;
	char *bp = buf;

	snprintf(bp, buflen - (bp - buf), "%s ",
	    status_name(res->clorr_status));
}

static void
dtlres_cb_layoutrecall(void *obj)
{
	dtl_nfsstat4(obj);
}

static void
sumarg_cb_notify(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_notify(void *obj)
{
}

static void
sumres_cb_notify(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_notify(void *obj)
{
}

static void
sumarg_cb_push_deleg(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_push_deleg(void *obj)
{
}

static void
sumres_cb_push_deleg(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_push_deleg(void *obj)
{
}

static void
sumarg_cb_recall_any(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_recall_any(void *obj)
{
}

static void
sumres_cb_recall_any(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_recall_any(void *obj)
{
}

static void
sumarg_cb_recallable_obj_avail(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_recallable_obj_avail(void *obj)
{
}

static void
sumres_cb_recallable_obj_avail(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_recallable_obj_avail(void *obj)
{
}

static void
sumarg_cb_recall_slot(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_recall_slot(void *obj)
{
}

static void
sumres_cb_recall_slot(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_recall_slot(void *obj)
{
}

static void
sumarg_cb_wants_cancelled(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_wants_cancelled(void *obj)
{
}

static void
sumres_cb_wants_cancelled(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_wants_cancelled(void *obj)
{
}

static void
sumarg_cb_notify_lock(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_notify_lock(void *obj)
{
}

static void
sumres_cb_notify_lock(char *buf, size_t buflen, void *obj)
{
}

static void
dtlres_cb_notify_lock(void *obj)
{
}


/*
 * Attribute print functions.  See attr_info_t.
 */

static void
prt_supported_attrs(XDR *xdr)
{
	static bitmap4 val;

	if (!xdr_bitmap4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Supported Attributes:");
	detail_attr_bitmap("\t", &val, NULL);
	xdr_free(xdr_bitmap4, (char *)&val);
}

static void
prt_type(XDR *xdr)
{
	nfs_ftype4 val;

	if (!xdr_nfs_ftype4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Type = %s", sum_type_name(val));
}

static void
prt_fh_expire_type(XDR *xdr)
{
	fattr4_fh_expire_type val;
	char *buf;
	bool_t first = TRUE;

	if (!xdr_fattr4_fh_expire_type(xdr, &val))
		longjmp(xdr_err, 1);
	buf = get_line(0, 0);

	sprintf(buf, "Filehandle expire type = ");
	if ((val & (FH4_NOEXPIRE_WITH_OPEN | FH4_VOLATILE_ANY |
	    FH4_VOL_MIGRATION | FH4_VOL_RENAME)) == 0) {
		strcat(buf, "Persistent");
		return;
	}
	if (val & FH4_NOEXPIRE_WITH_OPEN) {
		strcat(buf, "No Expire With OPEN");
		first = FALSE;
	}
	if (val & FH4_VOLATILE_ANY) {
		if (first)
			first = FALSE;
		else
			strcat(buf, ", ");
		strcat(buf, "Volatile at any time");
	}
	if (val & FH4_VOL_MIGRATION) {
		if (first)
			first = FALSE;
		else
			strcat(buf, ", ");
		strcat(buf, "Volatile at Migration");
	}
	if (val & FH4_VOL_RENAME) {
		if (first)
			first = FALSE;
		else
			strcat(buf, ", ");
		strcat(buf, "Volatile at Rename");
	}
}

static void
prt_change(XDR *xdr)
{
	changeid4 val;

	if (!xdr_changeid4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Change ID = 0x%llx", val);
	/* XXX print as time_t, too? */
}

static void
prt_size(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Size = %llu", val);
}

static void
prt_link_support(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Link Support = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_symlink_support(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Symlink Support = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_named_attr(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Has Named Attributes = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_fsid(XDR *xdr)
{
	fsid4 val;

	if (!xdr_fsid4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "FS ID: Major = %llx, Minor = %llx",
	    val.major, val.minor);
}

static void
prt_unique_handles(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Unique Handles = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_lease_time(XDR *xdr)
{
	uint32_t val;

	if (!xdr_uint32_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Lease Time = %u", val);
}

static void
prt_rdattr_error(XDR *xdr)
{
	nfsstat4 val;

	if (!xdr_nfsstat4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Rdattr Error = %u (%s)",
	    val, status_name(val));
}

static void
prt_acl(XDR *xdr)
{
	static fattr4_acl val;
	char buffy[NFS4_OPAQUE_LIMIT];
	int i, len;

	if (!xdr_fattr4_acl(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "ACL of %d entries", val.fattr4_acl_len);
	for (i = 0; i < val.fattr4_acl_len; i++) {
		sprintf(get_line(0, 0), "nfsace4[%d]", i);

		sprintf(get_line(0, 0), "  type = %x",
		    val.fattr4_acl_val[i].type);
		detail_acetype4(val.fattr4_acl_val[i].type);

		sprintf(get_line(0, 0), "  flags = %x",
		    val.fattr4_acl_val[i].flag);
		detail_aceflag4(val.fattr4_acl_val[i].flag);

		sprintf(get_line(0, 0), "  mask = %x",
		    val.fattr4_acl_val[i].access_mask);
		detail_acemask4(val.fattr4_acl_val[i].access_mask);

		len = val.fattr4_acl_val[i].who.utf8string_len;
		if (len >= NFS4_OPAQUE_LIMIT)
			len = NFS4_OPAQUE_LIMIT - 1;
		(void) strncpy(buffy, val.fattr4_acl_val[i].who.utf8string_val,
		    len);
		buffy[len] = '\0';
		sprintf(get_line(0, 0), "  who = %s", buffy);
	}
	xdr_free(xdr_fattr4_acl, (char *)&val);
}

static void
detail_acetype4(acetype4 type)
{
	if (type >= ACETYPE4_NAMES_MAX) {
		sprintf(get_line(0, 0), "     unknown type");
	} else {
		sprintf(get_line(0, 0), "     %s", acetype4_names[type]);
	}
}

static void
detail_uint32_bitmap(uint32_t mask, char *mask_names[], int names_max)
{
	char buffy[BUFSIZ], *name;
	char *indent = "     ";
	char *spacer = "  ";
	int pending = 0;
	int bit;
	int len, namelen, spacelen;

	strcpy(buffy, indent);
	len = strlen(buffy);
	spacelen = strlen(spacer);

	for (bit = 0; bit < names_max; bit++) {
		if (mask & (1 << bit)) {
			name = mask_names[bit];
			namelen = strlen(name);
			/* 80 - 6 for "NFS:  " = 74 */
			if ((len + spacelen + namelen) >= 74) {
				sprintf(get_line(0, 0), "%s", buffy);
				strcpy(buffy, indent);
				len = strlen(buffy);
				pending = 0;
			}
			(void) strlcat(buffy, spacer, sizeof (buffy));
			(void) strlcat(buffy, name, sizeof (buffy));
			pending = 1;
			len += spacelen + namelen;
		}
	}
	if (pending)
		sprintf(get_line(0, 0), "%s", buffy);
}

static void
detail_aceflag4(aceflag4 flag)
{
	detail_uint32_bitmap(flag, aceflag4_names, ACEFLAG4_NAMES_MAX);
}

static void
detail_acemask4(acemask4 mask)
{
	detail_uint32_bitmap(mask, acemask4_names, ACEMASK4_NAMES_MAX);
}

static void
prt_aclsupport(XDR *xdr)
{
	fattr4_aclsupport val;

	if (!xdr_fattr4_aclsupport(xdr, &val))
		longjmp(xdr_err, 1);
	if (val & ACL4_SUPPORT_ALLOW_ACL)
		sprintf(get_line(0, 0), "ALLOW ACL Supported");
	if (val & ACL4_SUPPORT_DENY_ACL)
		sprintf(get_line(0, 0), "DENY ACL Supported");
	if (val & ACL4_SUPPORT_AUDIT_ACL)
		sprintf(get_line(0, 0), "AUDIT ACL Supported");
	if (val & ACL4_SUPPORT_ALARM_ACL)
		sprintf(get_line(0, 0), "ALARM ACL Supported");
}

static void
prt_archive(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Archived = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_cansettime(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Server Can Set Time = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_case_insensitive(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Case Insensitive Lookups = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_case_preserving(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Case Preserving = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_chown_restricted(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Chown Is Restricted = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_filehandle(XDR *xdr)
{
	static nfs_fh4 val;

	if (!xdr_nfs_fh4(xdr, &val))
		longjmp(xdr_err, 1);
	detail_fh4(&val, "");
	xdr_free(xdr_nfs_fh4, (char *)&val);
}

static void
prt_fileid(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "File ID = %llu", val);
}

static void
prt_mounted_on_fileid(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Mounted On File ID = %llu", val);
}

static void
prt_files_avail(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Files Available = %llu", val);
}

static void
prt_files_free(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Files Free = %llu", val);
}

static void
prt_files_total(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Files Total = %llu", val);
}

static void
prt_fs_locations(XDR *xdr)
{
	static fs_locations4 val;

	if (!xdr_fs_locations4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "[fs_locations]"); /* XXX */
	detail_pathname4(&val.fs_root);
	xdr_free(xdr_fs_locations4, (char *)&val);
}

static void
prt_hidden(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Hidden = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_homogeneous(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "FS Is Homogeneous = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_maxfilesize(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Maximum File Size = %llu", val);
}

static void
prt_maxlink(XDR *xdr)
{
	uint32_t val;

	if (!xdr_uint32_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Maximum Number of Links = %u", val);
}

static void
prt_maxname(XDR *xdr)
{
	uint32_t val;

	if (!xdr_uint32_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Maximum File Name Length = %u", val);
}

static void
prt_maxread(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Maximum Read Size = %llu", val);
}

static void
prt_maxwrite(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);

	sprintf(get_line(0, 0), "Maximum Write Size = %llu", val);
}

static void
prt_mimetype(XDR *xdr)
{
	static utf8string val;

	if (!xdr_utf8string(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "MIME Type = %s", utf8localize(&val));
	xdr_free(xdr_utf8string, (char *)&val);
}

static void
prt_mode(XDR *xdr)
{
	mode4 val;

	if (!xdr_mode4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Mode = 0%03o", val);
}

static void
prt_no_trunc(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Long Names Are Error (no_trunc) = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_numlinks(XDR *xdr)
{
	uint32_t val;

	if (!xdr_uint32_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Number of Links = %u", val);
}

static void
prt_owner(XDR *xdr)
{
	static utf8string val;

	if (!xdr_utf8string(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Owner = %s", utf8localize(&val));
	xdr_free(xdr_utf8string, (char *)&val);
}

static void
prt_owner_group(XDR *xdr)
{
	static utf8string val;

	if (!xdr_utf8string(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Group = %s", utf8localize(&val));
	xdr_free(xdr_utf8string, (char *)&val);
}

static void
prt_quota_avail_hard(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Quota Hard Limit = %llu", val);
}

static void
prt_quota_avail_soft(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Quota Soft Limit = %llu", val);
}

static void
prt_quota_used(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Quota Used = %llu", val);
}

static void
prt_rawdev(XDR *xdr)
{
	specdata4 val;

	if (!xdr_specdata4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Raw Device ID = %u, %u",
	    val.specdata1, val.specdata2);
}

static void
prt_space_avail(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Space Available = %llu", val);
}

static void
prt_space_free(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Space Free = %llu", val);
}

static void
prt_space_total(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Total Disk Space = %llu", val);
}

static void
prt_space_used(XDR *xdr)
{
	uint64_t val;

	if (!xdr_uint64_t(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Space Used (this object) = %llu", val);
}

static void
prt_system(XDR *xdr)
{
	bool_t val;

	if (!xdr_bool(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "System File = %s",
	    val ? "TRUE" : "FALSE");
}

static void
prt_time_access(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Last Access Time = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_time_access_set(XDR *xdr)
{
	settime4 val;

	if (!xdr_settime4(xdr, &val))
		longjmp(xdr_err, 1);
	if (val.set_it == SET_TO_CLIENT_TIME4) {
		sprintf(get_line(0, 0), "Access Time = %s (set to client time)",
		    format_time(val.settime4_u.time.seconds,
		    val.settime4_u.time.nseconds));
	} else if (val.set_it == SET_TO_SERVER_TIME4) {
		sprintf(get_line(0, 0), "Access Time (set to server time)");
	} else
		longjmp(xdr_err, 1);
}

static void
prt_time_backup(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Last Backup Time = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_time_create(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Creation Time = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_time_delta(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Server Time Granularity = %lld.%09d sec",
	    val.seconds, val.nseconds);
}

static void
prt_time_metadata(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Last Metadata Change Time = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_time_modify(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Last Modification Time = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_time_modify_set(XDR *xdr)
{
	settime4 val;

	if (!xdr_settime4(xdr, &val))
		longjmp(xdr_err, 1);
	if (val.set_it == SET_TO_CLIENT_TIME4) {
		sprintf(get_line(0, 0),
		    "Modification Time = %s (set to client time)",
		    format_time(val.settime4_u.time.seconds,
		    val.settime4_u.time.nseconds));
	} else if (val.set_it == SET_TO_SERVER_TIME4) {
		sprintf(get_line(0, 0),
		    "Modification Time (set to server time)");
	} else
		longjmp(xdr_err, 1);
}

static void
prt_dir_notif_delay(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0),
	    "Notification delays on directory attributes = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_dirent_notif_delay(XDR *xdr)
{
	nfstime4 val;

	if (!xdr_nfstime4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0),
	    "Notification delays on child attributes = %s",
	    format_time(val.seconds, val.nseconds));
}

static void
prt_dacl(XDR *xdr)
{

	static fattr4_dacl val;

	if (!xdr_fattr4_dacl(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_dacl, (char *)&val);
}

static void
prt_sacl(XDR *xdr)
{
	static fattr4_sacl val;

	if (!xdr_fattr4_sacl(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_sacl, (char *)&val);
}

static void
prt_change_policy(XDR *xdr)
{
	change_policy4 val;

	if (!xdr_change_policy4(xdr, &val))
		longjmp(xdr_err, 1);
}

static void
prt_fs_status(XDR *xdr)
{
	fattr4_fs_status val;

	if (!xdr_fattr4_fs_status(xdr, &val))
		longjmp(xdr_err, 1);
}

static void
prt_fs_layout_type(XDR *xdr)
{
	static fattr4_fs_layout_types val;
	char *bufp;
	int i;

	if (!xdr_fattr4_fs_layout_types(xdr, &val))
		longjmp(xdr_err, 1);

	bufp = get_line(0, 0);
	sprintf(bufp, "Layout types available for the file system : ");
	for (i = 0; i < val.fattr4_fs_layout_types_len; i++) {
		bufp += strlen(bufp);
		sprintf(bufp,
		    sum_lotype_name(val.fattr4_fs_layout_types_val[i]));
	}

	xdr_free(xdr_fattr4_fs_layout_types, (char *)&val);
}

static void
prt_file_layouthint4(fattr4_layout_hint *rawhint)
{
	struct nfsv4_1_file_layouthint4 hint;
	XDR xdr;

	if (rawhint->loh_type != 1)
		return;

	xdrmem_create(&xdr,
	    rawhint->loh_body.loh_body_val,
	    rawhint->loh_body.loh_body_len,
	    XDR_DECODE);
	bzero(&hint, sizeof (hint));
	if (! xdr_nfsv4_1_file_layouthint4(&xdr, &hint))
		longjmp(xdr_err, 1);

	sprintf(get_line(0, 0),
	    "care = 0x%x", hint.nflh_care);
	if (hint.nflh_care & NFLH4_CARE_DENSE)
		sprintf(get_line(0, 0), "    CARE_DENSE");
	if (hint.nflh_care & NFLH4_CARE_COMMIT_THRU_MDS)
		sprintf(get_line(0, 0), "    CARE_COMMIT_THRU_MDS");
	if (hint.nflh_care & NFLH4_CARE_STRIPE_UNIT_SIZE)
		sprintf(get_line(0, 0), "    CARE_STRIPE_UNIT_SIZE");
	if (hint.nflh_care & NFLH4_CARE_STRIPE_COUNT)
		sprintf(get_line(0, 0), "    CARE_STRIPE_COUNT");
	sprintf(get_line(0, 0),
	    "util = 0x%x", hint.nflh_util);
	sprintf(get_line(0, 0),
	    "stripe_count = %d", hint.nflh_stripe_count);

	xdr_free(xdr_nfsv4_1_file_layouthint4, (char *)&hint);
}

static void
prt_layout_hint(XDR *xdr)
{
	static fattr4_layout_hint val;

	if (!xdr_fattr4_layout_hint(xdr, &val))
		longjmp(xdr_err, 1);

	sprintf(get_line(0, 0),
	    "Client specified hint for file layout: %s %s",
	    sum_lotype_name(val.loh_type),
	    tohex(val.loh_body.loh_body_val, val.loh_body.loh_body_len));

	if (val.loh_type == 1)
		prt_file_layouthint4(&val);

	xdr_free(xdr_fattr4_layout_hint, (char *)&val);
}

static void
prt_layout_type(XDR *xdr)
{
	static fattr4_layout_types val;
	layouttype4 * ptype;

	if (!xdr_fattr4_layout_types(xdr, &val))
		longjmp(xdr_err, 1);

	ptype = (layouttype4 *)&val;
	sprintf(get_line(0, 0),
	    "Layout types available for the file: %s",
	    sum_lotype_name(*ptype));
}

static void
prt_layout_blksize(XDR *xdr)
{
	fattr4_layout_blksize val;

	if (!xdr_fattr4_layout_blksize(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0),
	    "Preferred block size for layout related I/O = %u", val);
}

static void
prt_layout_alignment(XDR *xdr)
{
	fattr4_layout_alignment val;

	if (!xdr_fattr4_layout_alignment(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0),
	    "Preferred alignment for layout related I/O = %u", val);
}

static void
prt_fs_locations_info(XDR *xdr)
{
	static fattr4_fs_locations val;

	if (!xdr_fattr4_fs_locations(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_fs_locations, (char *)&val);
}

static void
prt_mdsthreshold(XDR *xdr)
{
	static fattr4_mdsthreshold val;
	int i;
	threshold_item4 *thi;

	if (!xdr_fattr4_mdsthreshold(xdr, &val))
		longjmp(xdr_err, 1);

	sprintf(get_line(0, 0), "MDS threshold hintlist len = %d",
	    val.mth_hints.mth_hints_len);

	thi = (threshold_item4 *)val.mth_hints.mth_hints_val;
	for (i = 0; i < val.mth_hints.mth_hints_len; i++)
		detail_threshold_item4(&thi[i]);

	xdr_free(xdr_fattr4_mdsthreshold, (char *)&val);
}

static void
prt_retention_get(XDR *xdr)
{
	static fattr4_retention_get val;

	if (!xdr_fattr4_retention_get(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_retention_get, (char *)&val);
}

static void
prt_retention_set(XDR *xdr)
{
	static fattr4_retention_set val;

	if (!xdr_fattr4_retention_set(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_retention_set, (char *)&val);
}

static void
prt_retentevt_get(XDR *xdr)
{
	static fattr4_retentevt_get val;

	if (!xdr_fattr4_retentevt_get(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_retentevt_get, (char *)&val);
}

static void
prt_retentevt_set(XDR *xdr)
{
	static fattr4_retentevt_set val;

	if (!xdr_fattr4_retentevt_set(xdr, &val))
		longjmp(xdr_err, 1);

	xdr_free(xdr_fattr4_retentevt_set, (char *)&val);
}

static void
prt_retention_hold(XDR *xdr)
{
	fattr4_retention_hold val;

	if (!xdr_fattr4_retention_hold(xdr, &val))
		longjmp(xdr_err, 1);
}

static void
prt_mode_set_masked(XDR *xdr)
{
	static fattr4_mode_set_masked val;

	if (!xdr_fattr4_mode_set_masked(xdr, &val))
		longjmp(xdr_err, 1);
}

static void
prt_suppattr_exclcreat(XDR *xdr)
{
	static bitmap4 val;

	if (!xdr_bitmap4(xdr, &val))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), "Supported Attributes for Exclusive Create:");
	detail_attr_bitmap("\t", &val, NULL);
	xdr_free(xdr_bitmap4, (char *)&val);
}

static void
prt_fs_charset_cap(XDR *xdr)
{
	static fattr4_fs_charset_cap4 val;

	if (!xdr_fattr4_fs_charset_cap4(xdr, &val))
		longjmp(xdr_err, 1);
}

/*
 * Display the UTF8 string that is next in the XDR stream.
 */

static void
showxdr_utf8string(char *fmt)
{
	static utf8string string;

	if (!xdr_utf8string(&xdrm, &string))
		longjmp(xdr_err, 1);
	sprintf(get_line(0, 0), fmt, utf8localize(&string));
	xdr_free(xdr_utf8string, (char *)&string);
}

/*
 * utf8string is defined in nfs4_prot.x as an opaque array, which means
 * when it is decoded into a string, the string might not have a trailing
 * null.  Also, the string will still be encoded in UTF-8, rather than
 * whatever character encoding is associated with the current locale.  This
 * routine converts a utf8string into a (null-terminated) C string.  One day
 * it will convert into the current character encoding, too.  To avoid
 * dealing with storage management issues, it allocates storage for each
 * new string, then this storage is "freed" when the packet has been
 * processed.
 */

#define	MAX_UTF8_STRINGS	512

static char *utf_buf[MAX_UTF8_STRINGS];
static size_t utf_buflen[MAX_UTF8_STRINGS];
static uint_t cur_utf_buf = 0;

char *
utf8localize(utf8string *utf8str)
{
	size_t newsize, oldsize, len;
	char *result, *cp;

	len = utf8str->utf8string_len;
	if (len == 0)
		return ("");
	if (cur_utf_buf >= MAX_UTF8_STRINGS)
		return ("[Too Many UTF-8 Strings]");

	newsize = oldsize = utf_buflen[cur_utf_buf];


	if (oldsize < len + 1) {
		/* truncate opaques at NFS4_OPAQUE_LIMIT */
		if (len > NFS4_OPAQUE_LIMIT)
			len = NFS4_OPAQUE_LIMIT;
		newsize = len + 1;
	}
	if (newsize != oldsize) {
		utf_buf[cur_utf_buf] = realloc(utf_buf[cur_utf_buf],
		    newsize);
		if (utf_buf[cur_utf_buf] == NULL) {
			pr_err("out of memory\n");
			utf_buflen[cur_utf_buf] = 0;
			return ("");
		}
		utf_buflen[cur_utf_buf] = newsize;
	}

	result = utf_buf[cur_utf_buf];
	strncpy(result, utf8str->utf8string_val, len);
	result[len] = '\0';
	for (cp = result; cp < result + len; cp++) {
		if (!isprint(*cp)) {
			*cp = '.';
		}
	}

	cur_utf_buf++;

	return (result);
}

void
utf8free()
{
	cur_utf_buf = 0;
}


/*
 * adler16(): adler32 hash code shamelessly copied and mutiliated from
 * usr/src/uts/common/io/ppp/spppcomp/zlib.[ch]
 *
 * The alg was originally created to provide a running
 * checksum, but we don't need that -- we just want to
 * chksum data described by buf,len; therefore, the first
 * parameter was removed (held the running checksum),
 * and s1/s2 are always set to their required initial
 * values (1 and 0).  I also ripped out code which only
 * applied to large data sets (bufs larger than 5k).  All
 * I wanted was their core checksum alg (which is supposed
 * to do really well).  The v2/v3 hash alg didn't work well
 * at all for v4 stuff -- it produced too many collisions.
 *
 * The copyright info from uts/common/io/ppp/spppcomp/zlib.[ch]
 * is included below.
 */

/* -----zlib.c copyright info below */
/*
 * Copyright 2000 Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Updated from zlib-1.0.4 to zlib-1.1.3 by James Carlson.
 *
 * This file is derived from various .h and .c files from the zlib-1.0.4
 * distribution by Jean-loup Gailly and Mark Adler, with some additions
 * by Paul Mackerras to aid in implementing Deflate compression and
 * decompression for PPP packets.  See zlib.h for conditions of
 * distribution and use.
 *
 * Changes that have been made include:
 * - added Z_PACKET_FLUSH (see zlib.h for details)
 * - added inflateIncomp and deflateOutputPending
 * - allow strm->next_out to be NULL, meaning discard the output
 *
 * $Id: zlib.c,v 1.11 1998/09/13 23:37:12 paulus Exp $
 */
/* +++ adler32.c */
/*
 * adler32.c -- compute the Adler-32 checksum of a data stream
 * Copyright (C) 1995-1998 Mark Adler
 * For conditions of distribution and use, see copyright notice in zlib.h
 */
/* From: adler32.c,v 1.10 1996/05/22 11:52:18 me Exp $ */
/* -----zlib.c copyright info above */

/* -----zlib.h copyright info below */
/*
 * Copyright 2000 Sun Microsystems, Inc.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation is hereby granted, provided that the above
 * copyright notice appears in all copies.
 *
 * SUN MAKES NO REPRESENTATION OR WARRANTIES ABOUT THE SUITABILITY OF
 * THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
 * TO THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE, OR NON-INFRINGEMENT.  SUN SHALL NOT BE LIABLE
 * FOR ANY DAMAGES SUFFERED BY LICENSEE AS A RESULT OF USING,
 * MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS DERIVATIVES
 *
 * This file has been altered from its original by Sun Microsystems to
 * fit local coding style.
 */
/* -----zlib.h copyright info above */

#define	DO1(buf, i)  {s1 += buf[i]; s2 += s1; }
#define	DO2(buf, i)  DO1(buf, i); DO1(buf, i+1);
#define	DO4(buf, i)  DO2(buf, i); DO2(buf, i+2);
#define	DO8(buf, i)  DO4(buf, i); DO4(buf, i+4);
#define	DO16(buf)   DO8(buf, 0); DO8(buf, 8);

uint32_t
adler16(void *p, int len)
{
	uint32_t s1 = 1;
	uint32_t s2 = 0;
	uchar_t *buf = p;

	while (len >= 16) {
		DO16(buf);
		buf += 16;
		len -= 16;
	}

	while (len > 0) {
		s1 += *buf++;
		s2 += s1;
		len--;
	}

	return ((uint32_t)(s2 ^ s1) & 0xFFFFU);
}

static void
sumarg_cb_notify_deviceid(char *buf, size_t buflen, void *obj)
{
}

static void
dtlarg_cb_notify_deviceid(void *obj)
{
	CB_NOTIFY_DEVICEID4args *args = (CB_NOTIFY_DEVICEID4args *)obj;
	int i, j, found = 0;
	notify4 *no;
	bitmap4 *bp;
	XDR x;
	notify_deviceid_change4 ndc;
	notify_deviceid_delete4 ndd;
	char *loname;

	sprintf(get_line(0, 0),
	    "changes: %d", args->cnda_changes.cnda_changes_len);

	for (i = 0; i < args->cnda_changes.cnda_changes_len; i++) {
		no = &args->cnda_changes.cnda_changes_val[i];
		bp = &no->notify_mask;
		if (bp->bitmap4_len > 0) {

			xdrmem_create(&x, no->notify_vals.notifylist4_val,
			    no->notify_vals.notifylist4_len, XDR_DECODE);

			if (bp->bitmap4_val[0] & (1<<NOTIFY_DEVICEID4_CHANGE)) {
				found = 1;
				sprintf(get_line(0, 0), "CHANGE");
				if (xdr_notify_deviceid_change4(&x, &ndc)) {
					sprintf(get_line(0, 0),
					    detail_lotype_name(
					    ndc.ndc_layouttype));
					detail_deviceid(ndc.ndc_deviceid);
					sprintf(get_line(0, 0), "immediate: %d",
					    ndc.ndc_immediate);
				} else
					longjmp(xdr_err, 1);
			}
			if (bp->bitmap4_val[0] & (1<<NOTIFY_DEVICEID4_DELETE)) {
				found = 1;
				sprintf(get_line(0, 0), "DELETE");
				if (xdr_notify_deviceid_delete4(&x, &ndd)) {
					sprintf(get_line(0, 0),
					    detail_lotype_name(
					    ndd.ndd_layouttype));
					detail_deviceid(ndd.ndd_deviceid);
				} else
					longjmp(xdr_err, 1);
			}
		}
		if (!found) {
			sprintf(get_line(0, 0), "bitmap4_len = %u",
			    bp->bitmap4_len);
			for (j = 0; j < bp->bitmap4_len; j++)
				sprintf(get_line(0, 0),
				    "value: 0x%x", bp->bitmap4_val[j]);
		}
	}

}
