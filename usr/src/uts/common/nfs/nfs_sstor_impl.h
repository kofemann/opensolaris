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

#pragma ident	"@(#)nfs_sstor_impl.h	1.1	08/04/30 SMI"

#ifndef _NFS_SSTOR_H
#define	_NFS_SSTOR_H

#pragma ident	"@(#)nfs_sstor_impl.h	1.1	08/04/30 SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef DEBUG
#define	TABSIZE 17
#else
#define	TABSIZE 2047
#endif

#define	ADDRHASH(key) ((unsigned long)(key) >> 3)
#define	MAXTABSZ 1024*1024

/* The values below are rfs4_lease_time units */

#ifdef DEBUG
#define	CLIENT_CACHE_TIME 1
#define	OPENOWNER_CACHE_TIME 1
#define	STATE_CACHE_TIME 1
#define	LO_STATE_CACHE_TIME 1
#define	LOCKOWNER_CACHE_TIME 1
#define	FILE_CACHE_TIME 3
#define	DELEG_STATE_CACHE_TIME 1
#else
#define	CLIENT_CACHE_TIME 10
#define	OPENOWNER_CACHE_TIME 5
#define	STATE_CACHE_TIME 1
#define	LO_STATE_CACHE_TIME 1
#define	LOCKOWNER_CACHE_TIME 3
#define	FILE_CACHE_TIME 40
#define	DELEG_STATE_CACHE_TIME 1
#endif

int sstor_init(nfs_server_instance_t *, int);

bool_t rfs4_client_create(rfs4_entry_t, void *);
void   rfs4_client_destroy(rfs4_entry_t);
bool_t rfs4_client_expiry(rfs4_entry_t);
uint32_t clientid_hash(void *);
bool_t clientid_compare(rfs4_entry_t, void *);
void *clientid_mkkey(rfs4_entry_t);
uint32_t nfsclnt_hash(void *);
bool_t nfsclnt_compare(rfs4_entry_t, void *);
void *nfsclnt_mkkey(rfs4_entry_t);

bool_t openowner_create(rfs4_entry_t, void *);
void   openowner_destroy(rfs4_entry_t);
bool_t rfs4_openowner_expiry(rfs4_entry_t);
uint32_t openowner_hash(void *);
bool_t openowner_compare(rfs4_entry_t, void *);
void *openowner_mkkey(rfs4_entry_t);

bool_t rfs4_state_create(rfs4_entry_t, void *);
void rfs4_state_destroy(rfs4_entry_t);
bool_t rfs4_state_expiry(rfs4_entry_t);
uint32_t state_hash(void *);
bool_t state_compare(rfs4_entry_t, void *);
void *state_mkkey(rfs4_entry_t);
uint32_t state_owner_file_hash(void *);
bool_t state_owner_file_compare(rfs4_entry_t, void *);
void *state_owner_file_mkkey(rfs4_entry_t);
uint32_t state_file_hash(void *);
bool_t state_file_compare(rfs4_entry_t, void *);
void *state_file_mkkey(rfs4_entry_t);

bool_t rfs4_lo_state_create(rfs4_entry_t, void *);
void rfs4_lo_state_destroy(rfs4_entry_t);
bool_t rfs4_lo_state_expiry(rfs4_entry_t);
uint32_t lo_state_hash(void *);
bool_t lo_state_compare(rfs4_entry_t, void *);
void *lo_state_mkkey(rfs4_entry_t);
uint32_t lo_state_lo_hash(void *);
bool_t lo_state_lo_compare(rfs4_entry_t, void *);
void *lo_state_lo_mkkey(rfs4_entry_t);
bool_t rfs4_lockowner_create(rfs4_entry_t, void *);
void rfs4_lockowner_destroy(rfs4_entry_t);
bool_t rfs4_lockowner_expiry(rfs4_entry_t);
uint32_t lockowner_hash(void *);
bool_t lockowner_compare(rfs4_entry_t, void *);
void *lockowner_mkkey(rfs4_entry_t);
uint32_t pid_hash(void *);
bool_t pid_compare(rfs4_entry_t, void *);
void *pid_mkkey(rfs4_entry_t);
bool_t rfs4_file_create(rfs4_entry_t, void *);
void rfs4_file_destroy(rfs4_entry_t);
uint32_t file_hash(void *);
bool_t file_compare(rfs4_entry_t, void *);
void *file_mkkey(rfs4_entry_t);
bool_t rfs4_deleg_state_create(rfs4_entry_t, void *);
void rfs4_deleg_state_destroy(rfs4_entry_t);
bool_t rfs4_deleg_state_expiry(rfs4_entry_t);
uint32_t deleg_hash(void *);
bool_t deleg_compare(rfs4_entry_t, void *);
void *deleg_mkkey(rfs4_entry_t);
uint32_t deleg_state_hash(void *);
bool_t deleg_state_compare(rfs4_entry_t, void *);
void *deleg_state_mkkey(rfs4_entry_t);

#ifdef	__cplusplus
}
#endif

#endif /* _NFS_SSTOR_H */
