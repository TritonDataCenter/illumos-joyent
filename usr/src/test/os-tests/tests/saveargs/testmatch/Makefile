
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
# Copyright 2012, Richard Lowe.
#

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/Makefile.master.64

.KEEP_STATE:

OBJECTS = testmatch.o data.o
PROG = testmatch

LDLIBS += -lsaveargs

AS_CPPFLAGS += -D_ASM

ROOTOPTPKG = $(ROOT)/opt/os-tests
TESTDIR = $(ROOTOPTPKG)/tests/saveargs/testmatch

CMDS = $(PROG:%=$(TESTDIR)/%)
$(CMDS) := FILEMODE = 0555

$(PROG): $(OBJECTS)
	$(LINK.c) -o $@ $(OBJECTS) $(LDLIBS)
	$(POST_PROCESS)

clean:
	$(RM) $(OBJECTS) $(PROG)

clobber: clean

all: $(PROG)

install: $(CMDS)

$(CMDS): $(TESTDIR) $(PROG)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
