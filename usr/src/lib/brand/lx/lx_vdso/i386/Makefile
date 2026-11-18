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
# Copyright 2016 Joyent, Inc.
#

ISASRCDIR=.
TARGET_ARCH=$(MACH)

include ../Makefile.com

ASFLAGS += -D__$(MACH)
VDSO_VERIFY =	/bin/sh ./check-vdso-unwind.sh $(DYNLIB) \
    $(ELFDUMP) $(ELFEDIT) $(AWK)

SONAME = linux-gate.so.1

#
# You might ask, why aren't we overriding BUILD.SO in Makefile.com.
# See the amd64 Makefile for more answers
#
BUILD.SO =	$(LD) -o $@ $(GSHARED) $(DYNFLAGS) $(PICS) $(LDLIBS)

ASSYMDEP_OBJS = lx_vdso.o

CLOBBERFILES	= $(ROOTLIBDIR)/$(DYNLIB) $(ROOTLIBDIR)/$(LINTLIB)

# Set the object entry point for __vsyscall-ers.  The link-editor emits
# PT_SUNW_UNWIND for .eh_frame_hdr; Linux unwinders require the equivalent
# PT_GNU_EH_FRAME program header (0x6474e550).
entryfix: $(DYNLIB)
	$(ELFEDIT) -e "ehdr:e_entry \
	    $$($(ELFEDIT) -re 'sym:st_value -osimple __vsyscall' $(DYNLIB))" \
	    $(DYNLIB)
	@if $(ELFEDIT) -re 'phdr:p_type 0x6464e550' $(DYNLIB) \
	    >/dev/null 2>&1; then \
	    $(ELFEDIT) -e 'phdr:p_type 0x6464e550 0x6474e550' $(DYNLIB); \
	else \
	    $(ELFEDIT) -re 'phdr:p_type 0x6474e550' $(DYNLIB) \
	    >/dev/null; \
	fi

all: entryfix

install: all $(ROOTLIBS)
