#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
# 
# uts/common/nfs/Makefile
#
# include global definitions
#
include ../../../Makefile.master


HDRS=	export.h		\
	lm.h			\
	mount.h			\
	nfs.h			\
	nfssys.h		\
	nfs_acl.h		\
	nfs_clnt.h		\
	nfs_cmd.h		\
	nfs_log.h		\
	nfs_sec.h		\
	nfs4.h			\
	nfs4_attr.h		\
	nfs4_clnt.h		\
	rnode.h			\
	rnode4.h		\
	nfs4_kprot.h		\
	nfs4_db_impl.h		\
	nfs4_idmap_impl.h	\
	nfsid_map.h		\
	auth.h			\
	nfs4_ext_defs.h		\
	nfs41_kprot.h		\
	nfs_serv_inst.h		\
	nfs4_pnfs.h		\
	nfs41_sessions.h	\
	nfs4_clnt_impl.h	\
	nfs41_fhtype.h		\
	nfs41_filehandle.h	\
	ds_filehandle.h		\
	nfs4_attrmap.h		\
	nfs4_srv_readdir.h	\
	nfs4_srv_attr.h		\
	mds_state.h		\
	ds.h			\
	ctl_mds_clnt.h		\
	range.h			\
	range_impl.h		\
	nnode.h			\
	nnode_impl.h		\
	nnode_vn.h		\
	nnode_proxy.h		\
	spe.h			\
	spe_attr.h		\
	spe_impl.h		\
	dserv_impl.h


PROTOCOL_DIR = $(SRC)/head/rpcsvc
DERIVED_FILES = ds_prot.h ds_nfs_xdr.h mds_odl.h spe_prot.h

CLEANFILES += $(DERIVED_FILES)

$(CLOSED_BUILD)CLOSEDHDRS=	lm_impl.h	lm_nlm.h	lm_server.h

ALLHDRS= $(HDRS) $(CLOSEDHDRS) $(DERIVED_FILES)

ROOTDIRS= $(ROOT)/usr/include/nfs

ROOTHDRS= $(ALLHDRS:%=$(ROOTDIRS)/%)

CHECKHDRS= $(HDRS:%.h=%.check) \
	$(CLOSEDHDRS:%.h=$(CLOSED)/uts/common/nfs/%.check)

$(ROOTDIRS)/%: %
	$(INS.file)

$(ROOTDIRS)/%: $(CLOSED)/uts/common/nfs/%
	$(INS.file)

.KEEP_STATE:

.PARALLEL: $(CHECKHDRS)

install_h: $(ROOTDIRS) $(ROOTHDRS) $(DERIVED_FILES)

$(ROOTDIRS):
	$(INS.dir)

check:	$(CHECKHDRS)

clean clobber:
	$(RM) $(DERIVED_FILES)
	$(RM) $(ROOTHDRS)

ds_prot.h: $(PROTOCOL_DIR)/ds_prot.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/ds_prot.x >$@ 

mds_odl.h: $(PROTOCOL_DIR)/mds_odl.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/mds_odl.x >$@ 

ds_nfs_xdr.h: $(PROTOCOL_DIR)/ds_nfs_com.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/ds_nfs_com.x | \
	egrep 'bool_t xdr_.+\(XDR \*\, ' >$@ 

spe_prot.h: $(PROTOCOL_DIR)/spe_prot.x
	$(RPCGEN) -C -h $(PROTOCOL_DIR)/spe_prot.x >$@
