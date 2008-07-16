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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#ident	"%Z%%M%	%I%	%E% SMI"

PROG =		dservd
OBJS =		dservd.o tbind_sup.o
SRCS =		$(OBJS:%.o=%.c)
LIBOBJS =	nfs_tbind.o thrpool.o
POFILES = 	$(OBJS:.o=.po)
MANIFEST=	dserv.xml

include ../../Makefile.cmd

POFILE = 	$(PROG)_all.po
LDLIBS +=	-ldserv -lnsl
CPPFLAGS +=	-I../../fs.d/nfs/lib -I.

lint := LINTFLAGS = -ux

ROOTMANIFESTDIR= $(ROOTSVCNETWORK)
$(ROOTMANIFEST) := FILEMODE= 444

.KEEP_STATE:

all: $(PROG)

$(PROG): $(OBJS) $(LIBOBJS)
	$(LINK.c) -o $@ $(OBJS) $(LIBOBJS) $(LDLIBS)
	$(POST_PROCESS)

%.o: ../../fs.d/nfs/lib/%.c
	$(COMPILE.c) -o $@ $<

$(POFILE): $(POFILES)
	cat $(POFILES) > $(POFILE)

install: all $(ROOTUSRSBINPROG) $(ROOTMANIFEST)

check:	$(CHKMANIFEST)

clean:
	$(RM) $(OBJS) $(LIBOBJS)

lint: lint_SRCS

include ../../Makefile.targ
