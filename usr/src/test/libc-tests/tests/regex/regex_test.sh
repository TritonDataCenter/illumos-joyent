#! /usr/bin/sh
#
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
# Copyright 2018 Nexenta Systems, Inc.
# Copyright 2023 Bill Sommerfeld <sommerfeld@hamachi.org>
#

TESTDIR=$(dirname $0)
TREGEX=${TESTDIR}/testregex

for t in basic bug16127 categorize forcedassoc leftassoc \
    nullsubexpr repetition rightassoc; do
	${TREGEX} -F ${TESTDIR}/data/${t}.dat | \
	    diff -u - ${TESTDIR}/data/${t}.out || \
	    exit 1
done

exit 0
