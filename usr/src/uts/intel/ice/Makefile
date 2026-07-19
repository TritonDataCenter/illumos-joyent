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
# Copyright 2026 Edgecast Cloud LLC.
#

UTSBASE = ../..

FWDIR		= $(UTSBASE)/common/io/ice/firmware
FWFILES		= ice.pkg

MODULE		= ice
OBJECTS		= $(ICE_OBJS:%=$(OBJS_DIR)/%) $(ICE_INTC_OBJS:%=$(OBJS_DIR)/%)
ROOTMODULE	= $(ROOT_DRV_DIR)/$(MODULE)
ROOTFIRMWARE	= $(FWFILES:%=$(ROOT_FIRMWARE_DIR)/$(MODULE)/%)
CONF_SRCDIR	= $(UTSBASE)/common/io/ice

include $(UTSBASE)/intel/Makefile.intel

CPPFLAGS	+= -I$(UTSBASE)/common/io/ice
CPPFLAGS	+= -I$(UTSBASE)/common/io/ice/core

#
# The driver registers with the MAC framework (GLDv3).
#
LDFLAGS		+= -N misc/mac

ALL_TARGET	= $(BINARY)
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE) $(ROOTFIRMWARE) $(ROOT_CONFFILE)

#
# The core/ files are vendored Intel common code; relax the smatch checks they
# do not satisfy on the vendored objects only, so the illumos shim and glue
# keep full coverage.
#
$(OBJS_DIR)/ice_common.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_controlq.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_sched.o		:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_switch.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_nvm.o		:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_flow.o		:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_flex_pipe.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_ddp_common.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_vlan_mode.o	:= SMOFF += all_func_returns
$(OBJS_DIR)/ice_fwlog.o		:= SMOFF += all_func_returns

.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

install:	$(INSTALL_DEPS)

include $(UTSBASE)/intel/Makefile.targ
