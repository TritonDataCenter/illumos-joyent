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
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# Copyright 2019 Nexenta by DDN, Inc.  All rights reserved.
# Copyright (c) 2018, Joyent, Inc.
#

PROG=	smbadm
SRCS=	smbadm.c

include ../../Makefile.cmd
include ../../Makefile.ctf
include ../Makefile.smbsrv.defs

OBJS=	smbadm.o smbinfo.o

LDLIBS += -L$(ROOT)/usr/lib/smbsrv -lsmb -lsmbns \
		 -lsecdb -lofmt -lcmdutils -lumem
LDFLAGS += -R/usr/lib/smbsrv

.KEEP_STATE:

SMOFF += free

all:		$(PROG)

clean:
	$(RM) $(OBJS)

lint:		lint_SRCS

$(PROG):	$(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

include ../../Makefile.targ

install: all .WAIT $(ROOTUSRSBINPROG)
