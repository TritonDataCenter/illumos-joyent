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
# Copyright 2019, Joyent, Inc.
# Copyright 2026 RackTop Systems, Inc.
#

UTSBASE = ../..

MODULE		= ice
OBJECTS		= $(ICE_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
CONF_SRCDIR	= $(UTSBASE)/common/io/ice

FWDIR		= $(UTSBASE)/common/io/ice
DDP_VERSION	= 1.3.41.0
DDP_FILE	= ice-$(DDP_VERSION).pkg
ROOTFIRMWARE	= $(DDP_FILE:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%)

include $(UTSBASE)/intel/Makefile.intel

ALL_TARGET	= $(BINARY) $(CONFMOD)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOT_CONFFILE)

LDFLAGS		+= -N misc/mac

MAPFILES	+= ddi mac random genunix

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS) $(ROOTFIRMWARE)

$(ROOT_FIRMARE_DIR)/$(MODULE)/ice.pkg := INSLINKTARGET = $(DDP_FILE)

include $(UTSBASE)/Makefile.mapfile
include $(UTSBASE)/intel/Makefile.targ

$(ROOT_FIRMWARE_DIR)/$(MODULE)/%: FRC
	$(INS.symlink)

FRC:
