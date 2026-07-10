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
# Copyright 2026 Edgecast Cloud LLC.
#

#
# NOTE: The @PYTHON@ macro's default is whatever is in the compilation
# environment. On SmartOS, this is typically in /opt/local, the pkgsrc root.
#
# The problem which we must address here is that tests in SmartOS are entirely
# under the control of the`smartos-test script, and that runs in the global
# zone. As of OS-8403, the global zone pkgsrc root is assumed to be in
# /opt/tools.
#
# We opt to use '/usr/bin/env python' because the smartos-test script sets PATH
# appropriately, and is responsible for successful execution of anything here
# in usr/src/test it runs.
#
PYSHEBANG=/usr/bin/env python

all     :=      TARGET = all
install :=      TARGET = install
clean   :=      TARGET = clean
clobber :=      TARGET = clobber
check   :=      TARGET = check

.KEEP_STATE:

all clean clobber install: $(SUBDIRS)
check: $(CHKSUBDIRS)

$(SUBDIRS): FRC
	cd $@; pwd; $(MAKE) $(TARGET)

FRC:
