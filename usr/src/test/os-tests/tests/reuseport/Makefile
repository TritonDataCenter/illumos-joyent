#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright (c) 2012 by Delphix. All rights reserved.
# Copyright 2016 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

PROG =	\
	rp_test_tcp \
	rp_test_tcp_noopt \
	rp_test_tcp_seteuid \
	rp_test_tcp_toggle \
	rp_test_udp \
	rp_test_udp_noopt \
	rp_test_udp_seteuid \
	rp_test_udp_toggle

OBJS = $(PROG:%=%.o)
SRCS = $(OBJS:%.o=%.c)

LDLIBS += -lsocket
LDLIBS64 += -lsocket

CSTD = $(CSTD_GNU99)

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/reuseport

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

LINTS = $(PROG:%=%.ln)

all: $(PROG)

install: all $(CMDS)

lint: $(LINTS)

clobber: clean
	-$(RM) $(PROG)

clean:
	-$(RM) $(OBJS)

%.ln: %.c
	$(LINT.c) $< $(UTILS) $(LDLIBS)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
