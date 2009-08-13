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
#

FSTYPE	  =	nfs
TYPEPROG  =	sped
#TESTPROG  =	nfsmapid_test
ATTMK	  =	$(TYPEPROG)

include		../../Makefile.fstype

LDLIBS   +=	-L$(ROOT)/usr/lib/nfs -R/usr/lib/nfs
LDLIBS   +=	-lnsl -ldoor -ldtrace -lsocket
SRCS	  =	sped.c spedaemon.c sped_server.c
DSRC	  =	sped_dt.d
DOBJ	  =	$(DSRC:%.d=%.o)
OBJS	  =	$(SRCS:%.c=%.o)
CPPFLAGS +=	-I../lib -D_POSIX_PTHREAD_SEMANTICS

PROTOCOL_DIR	= $(SRC)/head/rpcsvc
DERIVED_FILES	= sped_xdr.c

#all:		$(TYPEPROG) $(TESTPROG)
all:		$(TYPEPROG)

spe_xdr.c:	$(PROTOCOL_DIR)/spe_prot.x
		$(RPCGEN) -C -c $(PROTOCOL_DIR)/spe_prot.x | \
			$(EGREP) -v '^#include.+/spe_prot\.h"' | \
			$(EGREP) -v 'void.+bzero' > $@

spe_xdr.o:	spe_xdr.c
		$(COMPILE.c) -o $@ spe_xdr.c

$(TYPEPROG):	$(OBJS) $(DSRC) spe_xdr.o
		$(COMPILE.d) -s $(DSRC) -o $(DOBJ) $(OBJS)
		$(LINK.c) $(ZIGNORE) -o $@ $(DOBJ) $(OBJS) spe_xdr.o $(LDLIBS)
		$(POST_PROCESS)

TESTSRCS  =	sped_test.c
TESTOBJS  =	$(TESTSRCS:%.c=%.o)
TEST_OBJS =	$(TESTOBJS)

$(TESTPROG):	$(TEST_OBJS)
		$(LINK.c) -o $@ $(TEST_OBJS) $(LDLIBS)
		$(POST_PROCESS)

POFILE	  =	sped.po
catalog:	$(POFILE)

$(POFILE):	$(SRCS)
		$(RM) $@
		$(COMPILE.cpp) $(SRCS) > $@.i
		$(XGETTEXT) $(XGETFLAGS) $@.i
		sed "/^domain/d" messages.po > $@
		$(RM) $@.i messages.po

clean:
		$(RM) $(OBJS) $(TESTPROG) $(TESTOBJS) $(DOBJ) $(POFILE) \
		$(DERIVED_FILES) spe_xdr.o

lint:		$(SRCS) lint_SRCS
