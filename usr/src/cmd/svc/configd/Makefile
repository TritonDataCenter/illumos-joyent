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
# Copyright 2015 RackTop Systems.
#
# Copyright 2020 Joyent, Inc.
#

include Makefile.shared.com

CPPFLAGS += -I. -I../common -I$(SRC)/common/svc \
	-I$(ROOT)/usr/include/sqlite-sys -D_REENTRANT

LDLIBS += -lsecdb -lbsm -lumem -luutil -lsqlite-sys

SCRIPTFILE	= restore_repository
ROOTSCRIPTFILE	= $(ROOTLIBSVCBIN)/$(SCRIPTFILE)

.KEEP_STATE:
.PARALLEL: $(OBJS)

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

$(ROOTLIBSVCBIN)/%: %.sh
	$(INS.rename)

install: all $(ROOTLIBSVCBINPROG) $(ROOTVARSADMFILE) $(ROOTSCRIPTFILE)

clean:
	$(RM) $(OBJS)

clobber: clean

include $(SRC)/cmd/Makefile.targ

FRC:
