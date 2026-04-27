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
# Copyright 2026 Oxide Computer Company
#

#
# Makefile for various libsocket tests.
#

PROGS = \
	getifaddrs_dl \
	inet6_opt \
	nametoindex

PROGS32 += $(PROGS:%=%.32)
PROGS64 += $(PROGS:%=%.64)

ROOTOPTDIR = $(ROOT)/opt/os-tests/tests
ROOTOPTSOCK = $(ROOTOPTDIR)/libsocket
ROOTOPTPROGS = $(PROGS32:%=$(ROOTOPTSOCK)/%) $(PROGS64:%=$(ROOTOPTSOCK)/%)

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/cmd/Makefile.ctf

CPPFLAGS += -D_REENTRANT
CSTD = $(CSTD_GNU17)
CTF_MODE = link
LDLIBS += -lsocket
LDLIBS64 += -lsocket

getifaddrs_dl.32 := LDLIBS += -ldladm -ldlpi
getifaddrs_dl.64 := LDLIBS64 += -ldladm -ldlpi

.KEEP_STATE:

all: $(PROGS32) $(PROGS64)

clobber: clean
	-$(RM) $(PROGS32) $(PROGS64)

clean:
	-$(RM) *.o.32 *.o.64

install: $(ROOTOPTSOCK) .WAIT $(ROOTOPTPROGS)

$(ROOTOPTSOCK): $(ROOTOPTTESTS)
	$(INS.dir)

$(ROOTOPTSOCK)/%: %
	$(INS.file)

%.o.32: %.c
	$(COMPILE.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.o.64: %.c
	$(COMPILE64.c) -o $@ -c $<
	$(POST_PROCESS_O)

%.64: %.o.64
	$(LINK64.c) -o $@ $< $(LDLIBS64)
	$(POST_PROCESS)

%.32: %.o.32
	$(LINK.c) -o $@ $< $(LDLIBS)
	$(POST_PROCESS)
