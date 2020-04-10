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
# Copyright 2025 MNX Cloud, Inc.
#

PROG=		zstream
OBJS=		zstream.o zstream_dump.o zstream_redup.o $(HEXDUMP_OBJS)
POFILE=		zstream.po

include ../Makefile.cmd
include ../Makefile.cmd.64
include $(SRC)/common/hexdump/Makefile.com

INCS +=	-I../../uts/common/fs/zfs
INCS +=	-I../../common/zfs

LDLIBS += -lzutil -lzfs -lnvpair -lumem

CSTD=	$(CSTD_GNU99)

CPPFLAGS += -D_REENTRANT $(INCS)
$(NOT_RELEASE_BUILD)CPPFLAGS += -DDEBUG

zstream_redup.o := CPPFLAGS += -I../../lib/libzfs/common
zstream_redup.o := CPPFLAGS += -I../../lib/libzutil/common

.KEEP_STATE:

.PARALLEL:

all: $(PROG)

$(PROG): $(OBJS)
	$(LINK.c) -o $@ $(OBJS) $(LDLIBS)
	$(POST_PROCESS)

install: all $(ROOTUSRSBINPROG)

clean:
	$(RM) $(OBJS)

FRC:

include $(SRC)/common/hexdump/Makefile.targ
include ../Makefile.targ
