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
# Copyright (c) 2012, 2016 by Delphix. All rights reserved.
# Copyright 2018 Joyent, Inc.
#

include $(SRC)/cmd/Makefile.cmd

SUBDIRS = no-relobj-group-merge strip-groups

DATAFILES =	common.sh

ROOTOPTPKG = $(ROOT)/opt/elf-tests
TESTDIR = $(ROOTOPTPKG)/tests/groups/

DATA = $(DATAFILES:%=$(TESTDIR)/%)
$(DATA) := FILEMODE = 0444

all:

install: all $(DATA)

clean:
	-$(RM) $(CLEANFILES)

$(DATA): $(TESTDIR)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %.sh
	$(INS.rename)

$(TESTDIR)/%: %
	$(INS.file)

include $(SRC)/test/Makefile.com
