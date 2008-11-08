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

#ifndef	_NFS4_CMN_H
#define	_NFS4_CMN_H

#ifdef	__cplusplus
extern "C" {
#endif

extern uint32_t adler16(void *, int);

extern char *cmn_sum_stateid(stateid4 *, char *);
extern char *cmn_sum_stateid(stateid4 *, char *);

extern char *detail_iomode_name(layoutiomode4);
extern char *detail_lotype_name(layouttype4);
extern void detail_file_layout(layout4 *);


extern void detail_clientid(clientid4);
extern void detail_fh4(nfs_fh4 *, char *);
extern void detail_secinfo4(secinfo4 *);

extern char *sum_clientid(clientid4);
extern char *sum_fh4(nfs_fh4 *);

extern void utf8free(void);
extern char *utf8localize(utf8string *);

#define	fh4_hash(fh) adler16((fh)->nfs_fh4_val, (fh)->nfs_fh4_len)
#define	stateid_hash(st) adler16((st)->other, sizeof ((st)->other))
#define	owner_hash(own) adler16((own)->owner_val, (own)->owner_len)
#define	sessionid_hash(sid) adler16(sid, 16)
#define	deviceid_hash(did) adler16(did, 16)
#define	cowner_hash(oid) adler16((oid)->co_ownerid_val, (oid)->co_ownerid_len)

#define	sum_deleg_stateid(st)	cmn_sum_stateid((st), "DST=")
#define	sum_open_stateid(st)	cmn_sum_stateid((st), "OST=")
#define	sum_lock_stateid(st)	cmn_sum_stateid((st), "LST=")
#define	sum_stateid(st)		cmn_sum_stateid((st), "ST=")

#define	detail_deleg_stateid(st)	cmn_detail_stateid((st), "Delegation ")
#define	detail_open_stateid(st)		cmn_detail_stateid((st), "Open ")
#define	detail_lock_stateid(st)		cmn_detail_stateid((st), "Lock ")
#define	detail_stateid(st)		cmn_detail_stateid((st), "")

#define	SPECIAL_STATEID0	"SPC0"
#define	SPECIAL_STATEID1	"SPC1"

#ifdef	__cplusplus
}
#endif

#endif /* !_NFS4_CMN_H */
