#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet
# at http://www.illumos.org/license/CDDL.
#

#
# Copyright 2011, Richard Lowe
# Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
# Copyright 2015 Joyent, Inc.
#

include		$(SRC)/Makefile.master

MANSECT=	4m

MANFILES=	bufmod.4m	\
		connld.4m	\
		datafilt.4m	\
		ldterm.4m	\
		pckt.4m		\
		pfmod.4m	\
		pipemod.4m	\
		ptem.4m		\
		sppptun.4m	\
		timod.4m	\
		tirdwr.4m	\
		ttcompat.4m	\
		usb_ah.4m	\
		usbkbm.4m	\
		usbms.4m	\
		vuidmice.4m

.KEEP_STATE:

include		$(SRC)/man/Makefile.man

install:	$(ROOTMANFILES) $(MANLINK_SRCS)
	$(MANLINK_INSTALL)
