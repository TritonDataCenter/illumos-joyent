#!/usr/bin/ksh

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
# Copyright 2019 Joyent, Inc.
# Copyright 2024 RackTop Systems, Inc.
#

export LIBSEC_TESTS="/opt/libsec-tests"
runner="/opt/test-runner/bin/run"

function fail
{
	echo $1 >&2
	exit ${2:-1}
}

function find_runfile
{
	typeset distro=
	if [[ -f $LIBSEC_TESTS/runfiles/default.run ]]; then
		distro=default
	fi

	[[ -n $distro ]] && echo $LIBSEC_TESTS/runfiles/$distro.run
}

while getopts c: c; do
	case $c in
	'c')
		runfile=$OPTARG
		[[ -f $runfile ]] || fail "Cannot read file: $runfile"
		;;
	esac
done
shift $((OPTIND - 1))

[[ -z $runfile ]] && runfile=$(find_runfile)
[[ -z $runfile ]] && fail "Couldn't determine distro"

$runner -c $runfile

exit $?
