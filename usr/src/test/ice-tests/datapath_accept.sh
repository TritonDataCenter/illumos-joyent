#!/bin/bash
#
# ice(4D) on-hardware datapath acceptance suite.
#
# Unlike the source-invariant python checks in this directory, this runs on a
# host with a live ice0 and a physical peer.  It exercises attach state, FMA
# and error counters, bidirectional throughput, ping at the configured MTU,
# and repeated plumb/unplumb, and asserts no counter or fault regressions.
#
# Run on the DUT (e.g. boston) with the peer (e.g. hunter) already running
# "iperf -s" on PEER_IP:
#
#   datapath_accept.sh <peer_ip> [mtu]
#
# Exit status is 0 only if every check passes.
#
# Copyright 2026 MNX Cloud, Inc.

set -u

PEER_IP="${1:?usage: datapath_accept.sh <peer_ip> [mtu]}"
MTU="${2:-1500}"
LINK=ice0
ADDR_LOCAL=192.0.2.1/30
IPERF=/opt/tools/bin/iperf
FAILED=0

msg() { printf '%s %s\n' "$1" "$2"; }
pass() { msg "PASS" "$1"; }
fail() { msg "FAIL" "$1"; FAILED=1; }

kv() { kstat -p "ice:0:$1" 2>/dev/null | awk '{print $2}'; }

require_zero() {
	# require_zero <kstat-suffix> <label>
	local v
	v=$(kv "$1")
	if [[ -z "$v" ]]; then
		fail "$2: kstat ice:0:$1 missing"
	elif [[ "$v" != "0" ]]; then
		fail "$2: ice:0:$1 = $v (expected 0)"
	else
		pass "$2 ($1 = 0)"
	fi
}

echo "=== ice datapath acceptance: peer=$PEER_IP mtu=$MTU ==="

# 1. Driver loaded and bound.
if ! modinfo | grep -qiw ice; then
	fail "ice module not loaded"
	exit 1
fi
pass "ice module loaded"

# 2. Configure MTU (requires the link unplumbed) and plumb the test address.
ipadm delete-addr "$LINK/v4accept" 2>/dev/null
ipadm delete-if "$LINK" 2>/dev/null
if ! dladm set-linkprop -p mtu="$MTU" "$LINK" 2>/dev/null; then
	fail "could not set mtu=$MTU on $LINK"
fi
ipadm create-if "$LINK" 2>/dev/null
if ipadm create-addr -T static -a "$ADDR_LOCAL" "$LINK/v4accept" 2>/dev/null; then
	pass "plumbed $ADDR_LOCAL mtu=$MTU"
else
	fail "could not plumb $ADDR_LOCAL"
fi

# 3. Link state.  dladm show-phys columns: LINK MEDIA STATE SPEED DUPLEX DEVICE.
sleep 2
LSTATE=$(dladm show-phys "$LINK" 2>/dev/null | awk 'NR==2{print $3}')
LSPEED=$(dladm show-phys "$LINK" 2>/dev/null | awk 'NR==2{print $4}')
if [[ "$LSTATE" == "up" ]]; then
	pass "link up ($LSPEED Mbps)"
else
	fail "link state=$LSTATE"
fi

# 4. FMA and hardware fault counters must be clean before traffic.
require_zero "fm:acc_err" "FMA access errors (pre)"
require_zero "fm:dma_err" "FMA dma errors (pre)"
require_zero "fm:erpt_dropped" "FMA ereports dropped (pre)"

# 5. Reachability: small and near-MTU ICMP.
if ping -sn "$PEER_IP" 56 3 >/dev/null 2>&1; then
	pass "ping 56B x3"
else
	fail "ping 56B failed"
fi
# Large ping sized just under the MTU (leave room for IP+ICMP headers).
BIG=$((MTU - 60))
if ping -sn "$PEER_IP" "$BIG" 3 >/dev/null 2>&1; then
	pass "ping ${BIG}B x3 (near-MTU)"
else
	fail "ping ${BIG}B failed (peer MTU mismatch?)"
fi

# 6. Counters before traffic.
RXB0=$(kv "pfstats:rx_bytes"); TXB0=$(kv "pfstats:tx_bytes")

# 7. TX throughput (peer must run iperf -s).  Run this script on both hosts to
# cover both directions; iperf dual/reverse mode is unreliable here.
echo "--- iperf 10s, 4 streams (DUT -> peer) ---"
IOUT=$("$IPERF" -c "$PEER_IP" -t 10 -P 4 2>&1)
echo "$IOUT" | grep -E "SUM|Mbits|Gbits" | tail -2
if echo "$IOUT" | grep -qE "Gbits/sec|Mbits/sec"; then
	pass "iperf throughput completed"
else
	fail "iperf produced no throughput result"
fi

# 8. Counters advanced.
RXB1=$(kv "pfstats:rx_bytes"); TXB1=$(kv "pfstats:tx_bytes")
if (( RXB1 > RXB0 )); then pass "rx_bytes advanced ($RXB0 -> $RXB1)"; else fail "rx_bytes did not advance"; fi
if (( TXB1 > TXB0 )); then pass "tx_bytes advanced ($TXB0 -> $TXB1)"; else fail "tx_bytes did not advance"; fi

# 9. Error and FMA counters still clean after traffic.
for k in mac:ierrors mac:oerrors mac:fcs_errors mac:align_errors \
    mac:macrcv_errors mac:macxmt_errors pfstats:crc_errors \
    fm:acc_err fm:dma_err fm:erpt_dropped; do
	require_zero "$k" "clean after traffic"
done

# 10. Repeated plumb/unplumb; link and FMA must recover each cycle.
echo "--- plumb/unplumb x3 ---"
for i in 1 2 3; do
	ipadm delete-addr "$LINK/v4accept" 2>/dev/null
	ipadm delete-if "$LINK" 2>/dev/null
	ipadm create-if "$LINK" 2>/dev/null
	ipadm create-addr -T static -a "$ADDR_LOCAL" "$LINK/v4accept" 2>/dev/null
	sleep 2
	ST=$(dladm show-phys "$LINK" 2>/dev/null | awk 'NR==2{print $3}')
	if [[ "$ST" == "up" ]]; then pass "cycle $i: link up"; else fail "cycle $i: link $ST"; fi
done
require_zero "fm:acc_err" "FMA access errors (post-cycle)"
require_zero "fm:dma_err" "FMA dma errors (post-cycle)"

echo "=== $([ $FAILED -eq 0 ] && echo ALL-PASS || echo FAILURES-PRESENT) ==="
exit $FAILED
