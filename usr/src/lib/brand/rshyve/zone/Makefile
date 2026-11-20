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
# Copyright 2026 Edgecast Cloud LLC.
#

#
# The rshyve brand is the bhyve brand with /usr/sbin/rshyve as the
# hypervisor.  Everything here is built from the bhyve brand's sources.
#

include $(SRC)/cmd/Makefile.cmd
include ../Makefile.rshyve
include $(SRC)/cmd/Makefile.cmd.64

BHYVE_ZONE =	../../bhyve/zone
ZHYVE_SRC =	$(SRC)/cmd/zhyve

SCRIPTS =	attach binstall detach statechange uninstall
PROG1 =		boot
PROG2 =		bhhwcompat
PROG3 =		zhyve
PROGS =		$(SCRIPTS) $(PROG1) $(PROG2) $(PROG3)
TEMPLATES =	SYSrshyve.xml
XMLDOCS =	config.xml platform.xml

CLEANFILES +=	$(PROGS) $(TEMPLATES) $(XMLDOCS)

$(PROG1) :=	LDLIBS += -lnvpair -lcustr
$(PROG2) :=	CPPFLAGS = -I$(COMPAT)/bhyve -I$(CONTRIB)/bhyve \
	$(CPPFLAGS.master) -I$(SRC)/uts/intel \
	-I$(COMPAT)/bhyve/amd64 -I$(CONTRIB)/bhyve/amd64
$(PROG3) :=	CPPFLAGS += -DZHYVE_HYPERVISOR='"/usr/sbin/rshyve"'
$(PROG3) :=	LDLIBS += -lnvpair

REBRAND =	$(SED) -e 's|/usr/lib/brand/bhyve/|/usr/lib/brand/rshyve/|g' \
		-e 's|name="bhyve"|name="rshyve"|' \
		-e 's|name="SYSbhyve"|name="SYSrshyve"|' \
		-e 's|brand="bhyve"|brand="rshyve"|' \
		-e 's|^ps_brand=.*|ps_brand=rshyve|'

CLOBBERFILES =	$(ROOTXMLDOCS) $(ROOTTEMPLATES) $(ROOTPROGS)
$(ROOTPROGS) :=	FILEMODE = 755

all: $(PROGS) $(TEMPLATES) $(XMLDOCS)

install: all $(ROOTPROGS) $(ROOTXMLDOCS) $(ROOTTEMPLATES)

$(PROG1) $(PROG2): $(BHYVE_ZONE)/$$@.c
	$(LINK.c) -o $@ $(BHYVE_ZONE)/$@.c $(LDLIBS)
	$(POST_PROCESS)

$(PROG3): $(ZHYVE_SRC)/zhyve.c
	$(LINK.c) -o $@ $(ZHYVE_SRC)/zhyve.c $(LDLIBS)
	$(POST_PROCESS)

$(SCRIPTS) $(XMLDOCS): $(BHYVE_ZONE)/$$@
	$(RM) $@
	$(REBRAND) $(BHYVE_ZONE)/$@ > $@

SYSrshyve.xml: $(BHYVE_ZONE)/SYSbhyve.xml
	$(RM) $@
	$(REBRAND) $(BHYVE_ZONE)/SYSbhyve.xml > $@

clean:
	$(RM) $(CLEANFILES)

include $(SRC)/cmd/Makefile.targ
