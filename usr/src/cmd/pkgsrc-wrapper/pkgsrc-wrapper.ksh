#! /usr/bin/ksh
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
# Copyright 2023 MNX Cloud, Inc.
#

remap() {
	# Some commands need remapping to a binary.  For now that's only
	# csh -> tcsh.
	case $1 in
	csh)	echo "tcsh" ;;
	*)	echo $1 ;;
	esac
}

OLDPATH=$PATH
# Use just the set of pkgsrc paths for now.
PATH=/opt/tools/bin:/opt/tools/sbin:/opt/local/bin:/opt/local/sbin

basecmd="$(/usr/bin/basename "$0")"
remapcmd="$(remap "$basecmd")"
cmd="$(type -fp "$remapcmd")"

if [[ $? != 0 ]]; then
    printf 'Attempt to install %s from pkgsrc\n' "$remapcmd" >&2
    exit 1
fi

# Restore PATH at this point, since 'cmd' is a full path.
export PATH=$OLDPATH
cmd=$(PATH=$PATH type -fp "$cmd")
if [[ -z $cmd ]]; then
   echo "INTERNAL ERROR: command $cmd is suddenly missing" >&2
   exit 2
fi

exec -a "$basecmd" "$cmd" "$@"
