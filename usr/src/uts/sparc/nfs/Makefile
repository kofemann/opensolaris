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
# uts/sparc/nfs/Makefile
#
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#	This makefile drives the production of the nfs file system
#	kernel module.
#
#	sparc architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Define the module and object file sets.
#
MODULE		= nfs
OBJECTS		= $(NFS_OBJS:%=$(OBJS_DIR)/%) $(OBJS_DIR)/ds_xdr.o \
		$(OBJS_DIR)/ds_nfs_xdr.o $(OBJS_DIR)/spe_xdr.o
LINTS		= $(NFS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(ROOT_FS_DIR)/$(MODULE)
ROOTLINK	= $(ROOT_SYS_DIR)/$(MODULE)

PROTOCOL_DIR	= $(UTSBASE)/../head/rpcsvc
NFSHDR		= $(UTSBASE)/common/nfs
DS_DERIVED_HDRS	= $(NFSHDR)/ds_prot.h
SPE_DERIVED_HDRS= $(NFSHDR)/spe_prot.h
DERIVED_HDRS	= $(DS_DERIVED_HDRS) $(SPE_DERIVED_HDRS)
DERIVED_FILES	= ds_xdr.c spe_xdr.c $(DERIVED_HDRS)

#
#	Include common rules.
#
include $(UTSBASE)/sparc/Makefile.sparc

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTLINK)

#
#	Overrides.
#
MODSTUBS_DIR	= $(OBJS_DIR)
$(MODSTUBS_O)	:= AS_CPPFLAGS += -DNFS_MODULE
CLEANFILES	+= $(MODSTUBS_O)
CFLAGS		+= $(CCVERBOSE)
INC_PATH	+= -I$(UTSBASE)/common/fs/zfs

#
# For now, disable these lint checks; maintainers should endeavor
# to investigate and remove these for maximum lint coverage.
# Please do not carry these forward to new Makefiles.
#
LINTTAGS	+= -erroff=E_SUSPICIOUS_COMPARISON
LINTTAGS	+= -erroff=E_BAD_PTR_CAST_ALIGN
LINTTAGS	+= -erroff=E_SUPPRESSION_DIRECTIVE_UNUSED
LINTTAGS	+= -erroff=E_STATIC_UNUSED
LINTTAGS	+= -erroff=E_PTRDIFF_OVERFLOW
LINTTAGS	+= -erroff=E_ASSIGN_NARROW_CONV

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)
	$(RM)	$(DERIVED_FILES)

clobber:	$(CLOBBER_DEPS)
	$(RM)	$(DERIVED_FILES)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

$(NFSHDR)/ds_prot.h: $(PROTOCOL_DIR)/ds_prot.x
	cd $(NFSHDR); $(MAKE) $(@F)


$(NFSHDR)/ds_nfs_xdr.h: $(PROTOCOL_DIR)/ds_nfs_com.x
	cd $(NFSHDR); $(MAKE) $(@F)


ds_xdr.c: $(PROTOCOL_DIR)/ds_prot.x
	$(RPCGEN) -C -c $(PROTOCOL_DIR)/ds_prot.x | \
		$(EGREP) -v '^#include.+/ds_prot\.h"' > $@

$(OBJS_DIR)/ds_xdr.o: ds_xdr.c $(NFSHDR)/ds.h $(DS_DERIVED_HDRS)
	$(COMPILE.c) -o $@ ds_xdr.c
	$(CTFCONVERT_O)


ds_nfs_xdr.c: $(PROTOCOL_DIR)/ds_nfs_com.x
	$(RPCGEN) -C -c $(PROTOCOL_DIR)/ds_nfs_com.x | \
		$(EGREP) -v '^#include.+/ds_nfs_com\.h"' > $@

$(OBJS_DIR)/ds_nfs_xdr.o: ds_nfs_xdr.c $(NFSHDR)/ds.h $(DS_DERIVED_HDRS)
	$(COMPILE.c) -o $@ ds_nfs_xdr.c
	$(CTFCONVERT_O)

$(NFSHDR)/spe_prot.h: $(PROTOCOL_DIR)/spe_prot.x
	cd $(NFSHDR); $(MAKE) $(@F)

spe_xdr.c: $(PROTOCOL_DIR)/spe_prot.x
	$(RPCGEN) -C -c $(PROTOCOL_DIR)/spe_prot.x | \
		$(EGREP) -v '^#include.+/spe_prot\.h"' | \
		$(EGREP) -v 'void.+bzero' > $@

$(OBJS_DIR)/spe_xdr.o: spe_xdr.c $(SPE_DERIVED_HDRS)
	$(COMPILE.c) -o $@ spe_xdr.c
	$(CTFCONVERT_O)

$(ROOTLINK):	$(ROOT_SYS_DIR) $(ROOTMODULE)
	-$(RM) $@; ln $(ROOTMODULE) $@

#
#	Include common targets.
#
include $(UTSBASE)/sparc/Makefile.targ
