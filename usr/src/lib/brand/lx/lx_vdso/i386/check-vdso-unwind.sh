#!/bin/sh
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# Copyright 2026 Edgecast Cloud LLC.
#
# Validate the final i386 vDSO after both entryfix and vdso_tool have run.
set -eu

if [ "$#" -ne 4 ]; then
	echo "usage: $0 vdso elfdump elfedit awk" >&2
	exit 2
fi
vdso=$1
elfdump=$2
elfedit=$3
awk=$4

"$elfdump" -pc "$vdso" | "$awk" '
	function hex(v, i, d, n) {
		sub(/^0x/, "", v)
		n = 0
		for (i = 1; i <= length(v); i++) {
			d = index("0123456789abcdef",
			    tolower(substr(v, i, 1))) - 1
			if (d < 0)
				return (-1)
			n = n * 16 + d
		}
		return (n)
	}
	/^Program Header/ { type = ""; addr = size = 0; flags = ""; next }
	$1 == "p_vaddr:" { addr = hex($2); flags = $0; next }
	$3 == "p_type:" { type = $5; next }
	$1 == "p_filesz:" { size = hex($2); next }
	$1 == "p_offset:" {
		off = hex($2)
		if (type == "PT_LOAD") {
			loads++
			loadsize = size
			if (addr != 0 || off != 0 || flags !~ /PF_X/ ||
			    flags !~ /PF_R/ || flags ~ /PF_W/)
				bad = 1
		} else if (type == "PT_SUNW_EH_FRAME") {
			headers++
			haddr = addr
			hoff = off
			hsize = size
		}
		next
	}
	/^Section Header/ {
		section = ""
		if ($4 == ".eh_frame_hdr" || $4 == ".eh_frame")
			section = $4
		next
	}
	$1 == "sh_addr:" && section != "" {
		saddr = hex($2)
		alloc = ($0 ~ /SHF_ALLOC/)
		next
	}
	$1 == "sh_size:" && section != "" { ssize = hex($2); next }
	$1 == "sh_offset:" && section != "" {
		soff = hex($2)
		if (!alloc || ssize <= 0 || saddr != soff ||
		    saddr + ssize > loadsize)
			bad = 1
		if (section == ".eh_frame_hdr") {
			hdrs++
			if (saddr != haddr || soff != hoff || ssize != hsize)
				bad = 1
		} else {
			frames++
		}
		section = ""
	}
	END {
		if (bad || loads != 1 || headers != 1 || hdrs != 1 ||
		    frames != 1) {
			print "i386 vDSO unwind sections are not in one load segment"
			exit 1
		}
	}'

entry=$("$elfedit" -re 'ehdr:e_entry -osimple' "$vdso")
bytes=$(dd if="$vdso" bs=1 skip=$((entry)) count=3 2>/dev/null |
    od -An -tx1 | tr -d ' \n')
if [ "$bytes" != cd80c3 ]; then
	echo 'i386 vDSO entry is not int 0x80; ret' >&2
	exit 1
fi

"$elfdump" -u "$vdso" | "$awk" -v entry="$entry" '
	/^CIE:/ { cies++ }
	/^[[:space:]]*FDE:/ { fdes++ }
	$1 == "initloc:" && $2 == entry && $4 == "0x3" { fde++ }
	/DW_CFA_def_cfa: r4 .*offset=4/ { cfa++ }
	/DW_CFA_offset: r8, cfa-4/ { retaddr++ }
	END {
		if (fdes != 1 || cies != 1 || fde != 1 ||
		    cfa != 1 || retaddr != 1) {
			print "i386 vDSO entry lacks the expected unwind frame"
			exit 1
		}
	}'
