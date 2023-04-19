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
# Copyright 2023 MNX Cloud, Inc.
#

PROG=pkgsrc-wrapper
#KSHPROG=pkgsrc-wrapper

# Add programs to $WRAPPER_LINKS that you want to actually have hardlink to
# the pkgsrc wrapper.
WRAPPER_LINKS=csh
WRAPPER_LINKS+=tcsh
WRAPPER_LINKS+=zsh

include ../Makefile.cmd

.KEEP_STATE:

all: $(PROG)

install: all $(ROOTPROG) $(WRAPPER_LINKS)

$(WRAPPER_LINKS):
	$(LN) $(ROOTPROG) $(ROOTBIN)/%

clean:

$(PROG).po:
	$(TOUCH) $(PROG).po

include ../Makefile.targ
