#!/usr/bin/env bash
# Exercises sr-route-helper in a throwaway network namespace, against a stand-in for
# the router's RPC (and, for the systemd-resolved checks, a stand-in for resolvectl), so
# nothing on the host changes. Needs root.
#
#   sudo test/netns-test.sh [path/to/sr-route-helper]
#
# The namespace has a real uplink (veth, gateway metric 100), a second adapter whose
# gateway has a lower address but a worse metric (the case that broke the old gateway
# pick), and a third whose cable is "unplugged" but has the best metric of all. Later
# steps add a point-to-point uplink with no next hop, like PPP or a cellular modem.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/../target/release/sr-route-helper}
NS=srrh-test
T=$(mktemp -d)
J=$T/journal.json
STATE=$T/state.json
RPC=ipc://$T/rpc.sock
RPC_TCP=tcp://127.0.0.1:11190
FAKE_RPC=$RPC
DNSPORT=$T/dnsport
export FAKE_RESOLVED=$T/resolved.json
mkdir -p $T/bin; ln -s "$HERE/fake-resolvectl" $T/bin/resolvectl
PASS=0; FAIL=0
in_ns() { ip netns exec $NS "$@"; }
ok() { echo "  ok   $*"; PASS=$((PASS+1)); }
bad() { echo "  FAIL $*"; FAIL=$((FAIL+1)); }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else bad "$what"; fi; }
routes() { in_ns ip -4 route show table main; in_ns ip -6 route show table main | grep -v '^fe80\|expires'; }
route_get() { in_ns ip route get "$1" 2>&1; }
route6_get() { in_ns ip -6 route get "$1" 2>&1; }
state() { echo "$1" > $STATE; }
wait_for() { local i; for i in $(seq 1 ${3:-40}); do if eval "$2" >/dev/null 2>&1; then ok "$1"; return; fi; sleep 0.25; done; bad "$1 (timed out)"; }
start_helper() { ip netns exec $NS "$BIN" run --rpc $RPC --journal $J --interval 1 --fail-after 2 --dns-mode resolv-conf --exit-dns 10.99.0.53 "$@" >>$T/helper.log 2>&1 & HELPER=$!; }
start_fake() { ip netns exec $NS python3 "$HERE/fake-router.py" $FAKE_RPC $STATE "$@" >>$T/fake.log 2>&1 & FAKE=$!; sleep 0.5; }
stop_helper() { kill -TERM $HELPER 2>/dev/null; wait $HELPER 2>/dev/null; }
blocked() { local out; out=$(route_get "$1"); grep -qiE 'unreachable|no route to host' <<<"$out"; }   # `ip` exits 2 here
rstate() { python3 -c "import json,sys; s=json.load(open('$FAKE_RESOLVED')).get('$1',{}); print(s.get('$2'))"; }
add_tun() { in_ns ip tuntap add sr-tun0 mode tun; in_ns ip link set sr-tun0 up; in_ns ip addr add 10.192.0.1/16 dev sr-tun0; }

cleanup() {
  kill -9 ${HELPER:-} ${FAKE:-} ${PPP:-} 2>/dev/null
  ip netns del $NS 2>/dev/null; rm -rf /etc/netns/$NS
  echo "logs: $T"
}
trap cleanup EXIT

ip netns del $NS 2>/dev/null
ip netns add $NS
mkdir -p /etc/netns/$NS; echo "nameserver 192.168.1.1" > /etc/netns/$NS/resolv.conf
in_ns ip link set lo up
in_ns sysctl -qw net.ipv6.conf.all.disable_ipv6=0
# uplink
in_ns ip link add up0 type veth peer name up0p
in_ns ip link set up0p up; in_ns ip link set up0 up
in_ns ip addr add 192.168.1.20/24 dev up0
in_ns ip route add default via 192.168.1.1 dev up0 metric 100
in_ns ip -6 addr add 2001:db8:1::20/64 dev up0 nodad
in_ns ip -6 route add default via 2001:db8:1::1 dev up0 metric 100
# second adapter: lower gateway address, worse metric
in_ns ip link add fake0 type veth peer name fake0p; in_ns ip link set fake0p up; in_ns ip link set fake0 up
in_ns ip addr add 10.3.0.2/24 dev fake0
in_ns ip route add default via 10.3.0.1 dev fake0 metric 500
# unplugged adapter with the best metric
in_ns ip link add down0 type veth peer name down0p
in_ns ip link set down0 up
in_ns ip addr add 10.4.0.2/24 dev down0
in_ns ip route add default via 10.4.0.1 dev down0 metric 1 onlink 2>/dev/null || true
# a WireGuard-style tunnel of some other VPN with an even better default: never the uplink
in_ns ip link add wg9 type veth peer name wg9p 2>/dev/null   # named like a VPN
in_ns ip link set wg9p up; in_ns ip link set wg9 up; in_ns ip addr add 10.9.0.2/24 dev wg9
in_ns ip route add default via 10.9.0.1 dev wg9 metric 2
# the router's tunnel
add_tun
BASE=$(routes); BASE_DNS=$(cat /etc/netns/$NS/resolv.conf)
echo "baseline routes:"; echo "$BASE" | sed 's/^/    /'

echo "1. full tunnel mapped (RPC over the Unix socket)"
state '{"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9", "203.0.113.7", "192.168.1.50", "2001:db8:77::7"]}'
start_fake
start_helper
wait_for "tunnel routes up" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
check "talking to the router over ipc://" grep -q "running (RPC ipc://" $T/helper.log
check "gateway is the real uplink, not the second, unplugged or VPN adapter" grep -q "IPv4 gateway is 192.168.1.1 on up0" $T/helper.log
check "relay pinned via uplink" bash -c "ip netns exec $NS ip route get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"
check "second relay pinned" bash -c "ip netns exec $NS ip route get 203.0.113.7 | grep -q 'via 192.168.1.1 dev up0'"
check "LAN stays local" bash -c "ip netns exec $NS ip route get 192.168.1.50 | grep -q 'dev up0'"
check "other private space stays off the tunnel" bash -c "ip netns exec $NS ip route get 172.20.0.9 | grep -q 'via 192.168.1.1 dev up0'"
check "multicast stays on the link" bash -c "ip netns exec $NS ip route get 239.1.2.3 | grep -q 'dev up0'"
check "exit DNS goes into the tunnel" bash -c "ip netns exec $NS ip route get 10.99.0.53 | grep -q 'dev sr-tun0'"
check "IPv6 blocked (no leak around the exit)" bash -c "ip netns exec $NS ip -6 route get 2606:4700::1111 2>&1 | grep -qiE 'unreachable|no route to host'"
check "IPv6 on the directly connected subnet still reachable" bash -c "ip netns exec $NS ip -6 route get 2001:db8:1::50 | grep -q 'dev up0'"
check "routed IPv6 subnet blocked too" bash -c "ip netns exec $NS ip -6 route get 2001:db8:2::50 2>&1 | grep -qiE 'unreachable|no route to host'"
check "IPv6 relay pinned through the block" bash -c "ip netns exec $NS ip -6 route get 2001:db8:77::7 | grep -q 'via 2001:db8:1::1 dev up0'"
check "fail-closed sinks under the tunnel routes" bash -c "ip netns exec $NS ip route show proto 211 | grep -q 'unreachable 0.0.0.0/1 metric 6'"
check "resolv.conf points at the router" grep -q "nameserver 127.3.2.1" /etc/netns/$NS/resolv.conf
check "journal written" test -s $J
check "routes carry the helper's protocol" bash -c "ip netns exec $NS ip route show proto 211 | grep -q '0.0.0.0/1 dev sr-tun0'"

echo "2. relay list changes"
state '{"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9", "198.51.100.4"]}'
T0=$(date +%s%N)
wait_for "new relay pinned" "route_get 198.51.100.4 | grep -q 'via 192.168.1.1'"
MS=$(( ($(date +%s%N) - T0) / 1000000 ))
check "pinned within a second (${MS} ms; was up to 3 s)" test $MS -lt 1000
wait_for "dropped relay unpinned" "route_get 203.0.113.7 | grep -q 'dev sr-tun0'"

echo "3. uplink goes away, second adapter takes over"
in_ns ip route del default via 192.168.1.1 dev up0 metric 100
wait_for "pins follow to the second adapter" "route_get 9.9.9.9 | grep -q 'via 10.3.0.1 dev fake0'"
in_ns ip route add default via 192.168.1.1 dev up0 metric 100
wait_for "pins come back to the uplink" "route_get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"

echo "4. no usable uplink at all: hold, never route relays into the tunnel"
in_ns ip route del default via 192.168.1.1 dev up0 metric 100
in_ns ip route del default via 10.3.0.1 dev fake0 metric 500
wait_for "exit traffic blocked, not looping into the tunnel" "blocked 1.1.1.1"
check "relay not sent into the tunnel" bash -c "! ip netns exec $NS ip route get 9.9.9.9 2>&1 | grep -q sr-tun0"
check "says why" grep -q "no usable IPv4 uplink" $T/helper.log
check "DNS stays on the router" grep -q "nameserver 127.3.2.1" /etc/netns/$NS/resolv.conf
in_ns ip route add default via 10.3.0.1 dev fake0 metric 500
in_ns ip route add default via 192.168.1.1 dev up0 metric 100
wait_for "tunnel back with the uplink" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
wait_for "pins back on the uplink" "route_get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"

echo "5. point-to-point uplink with no next hop (PPP / cellular style)"
# A tun device named like a modem, held open so it has carrier, with `default dev ppp0`.
ip netns exec $NS python3 -c '
import fcntl, os, struct, time
fd = os.open("/dev/net/tun", os.O_RDWR)
fcntl.ioctl(fd, 0x400454ca, struct.pack("16sH", b"ppp0", 0x0001 | 0x1000))
time.sleep(3600)' & PPP=$!
sleep 0.5
in_ns ip link set ppp0 up; in_ns ip addr add 100.70.0.2 peer 100.70.0.1 dev ppp0
in_ns ip route add default dev ppp0 metric 50
check "ppp0 is point-to-point" bash -c "ip netns exec $NS ip link show ppp0 | grep -q POINTOPOINT"
wait_for "ppp0 picked as the uplink" "grep -q 'IPv4 gateway is ppp0 (no next hop)' $T/helper.log"
wait_for "relay pinned straight out of ppp0" "route_get 9.9.9.9 | grep -q 'dev ppp0' && ! route_get 9.9.9.9 | grep -q via"
check "private space kept on ppp0" bash -c "ip netns exec $NS ip route get 172.20.0.9 | grep -q 'dev ppp0'"
check "exit traffic still into the tunnel" bash -c "ip netns exec $NS ip route get 1.1.1.1 | grep -q 'dev sr-tun0'"
in_ns ip route del default dev ppp0 metric 50
kill $PPP; wait $PPP 2>/dev/null; PPP=
wait_for "back on the veth uplink" "route_get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"

echo "5b. multipath (ECMP) default whose first next hop is on the unplugged adapter"
L=$(wc -l < $T/helper.log)
in_ns ip route add default metric 40 nexthop via 10.4.0.1 dev down0 onlink nexthop via 10.3.0.1 dev fake0
check "the multipath route is there, first hop link-down" bash -c "ip netns exec $NS ip route show default metric 40 | grep -q 'dev down0.*linkdown'"
wait_for "the live next hop is picked" "tail -n +$((L+1)) $T/helper.log | grep -q 'IPv4 gateway is 10.3.0.1 on fake0'"
wait_for "relay pinned via the live next hop" "route_get 9.9.9.9 | grep -q 'via 10.3.0.1 dev fake0'"
in_ns ip route del default metric 40
wait_for "back on the veth uplink" "route_get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"

echo "6. unmap"
state '{"mapped": [], "first_hops": ["9.9.9.9"]}'
wait_for "all helper routes gone" "! ip netns exec $NS ip route show proto 211 | grep -q . && ! ip netns exec $NS ip -6 route show proto 211 | grep -q ."
check "routes identical to before" test "$(routes)" == "$BASE"
check "resolv.conf restored" test "$(cat /etc/netns/$NS/resolv.conf)" == "$BASE_DNS"
check "journal removed" test ! -e $J

echo "7. kill -9 while mapped, then restore"
state '{"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9"]}'
wait_for "mapped again" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
sleep 0.5
kill -9 $HELPER; wait $HELPER 2>/dev/null
check "leftovers present after the crash" bash -c "ip netns exec $NS ip route show proto 211 | grep -q ."
in_ns "$BIN" restore --journal $J >>$T/helper.log 2>&1
check "restore: routes identical to before" test "$(routes)" == "$BASE"
check "restore: resolv.conf restored" test "$(cat /etc/netns/$NS/resolv.conf)" == "$BASE_DNS"

echo "8. kill -9 and a lost journal: the next start sweeps by protocol"
start_helper
wait_for "mapped" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
sleep 0.5
kill -9 $HELPER; wait $HELPER 2>/dev/null
rm -f $J
state '{"mapped": [], "first_hops": []}'
start_helper
wait_for "next start removed every leftover route" "test \"\$(routes)\" == \"\$BASE\""
echo "$BASE_DNS" > /etc/netns/$NS/resolv.conf   # the lost journal held the old resolv.conf

echo "9. router stops answering: fail closed"
state '{"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9"]}'
wait_for "mapped" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
kill -9 $FAKE; wait $FAKE 2>/dev/null
wait_for "exit traffic held blocked, not sent in the clear" "blocked 1.1.1.1 && ! ip netns exec $NS ip route show proto 211 | grep -q 'dev sr-tun0'" 60
check "IPv6 still blocked" bash -c "ip netns exec $NS ip -6 route get 2606:4700::1111 2>&1 | grep -qiE 'unreachable|no route to host'"
check "LAN still reachable" bash -c "ip netns exec $NS ip route get 192.168.1.50 | grep -q 'dev up0'"
check "relay still pinned for when the router is back" bash -c "ip netns exec $NS ip route get 9.9.9.9 | grep -q 'via 192.168.1.1 dev up0'"
check "exit DNS refused, not sent to the LAN" blocked 10.99.0.53
check "resolv.conf still points at the router" grep -q "nameserver 127.3.2.1" /etc/netns/$NS/resolv.conf
echo "# Generated by NetworkManager
nameserver 192.168.1.1" > /etc/netns/$NS/resolv.conf
wait_for "resolv.conf rewritten by someone else is pointed back at the router" "grep -q 'nameserver 127.3.2.1' /etc/netns/$NS/resolv.conf"
kill -9 $HELPER; wait $HELPER 2>/dev/null
start_helper
sleep 3
check "a restarted helper keeps holding" blocked 1.1.1.1
start_fake
wait_for "back up when the router answers again" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"

echo "10. tunnel interface disappears"
in_ns ip link del sr-tun0
check "sinks take over at once (no wait for the helper)" blocked 1.1.1.1
sleep 1.5
check "still blocked once the helper has looked" blocked 1.1.1.1
check "resolv.conf still points at the router" grep -q "nameserver 127.3.2.1" /etc/netns/$NS/resolv.conf
add_tun
wait_for "back when the tunnel returns" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"

echo "11. --fail-open keeps the old behaviour"
stop_helper
check "stop restored everything" test "$(routes)" == "$BASE"
check "stop restored the newer resolv.conf (theirs)" grep -q "Generated by NetworkManager" /etc/netns/$NS/resolv.conf
echo "$BASE_DNS" > /etc/netns/$NS/resolv.conf
start_helper --fail-open
wait_for "mapped" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
check "no sinks when failing open" bash -c "! ip netns exec $NS ip route show proto 211 | grep -q 'metric 6'"
kill -9 $FAKE; wait $FAKE 2>/dev/null
wait_for "routes taken down after the router went quiet" "test \"\$(routes)\" == \"\$BASE\"" 60
check "resolv.conf restored" test "$(cat /etc/netns/$NS/resolv.conf)" == "$BASE_DNS"
start_fake
wait_for "back up when the router answers again" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
stop_helper

echo "12. range mapping only"
start_helper
state '{"mapped": ["203.0.113.0/24"], "first_hops": ["203.0.113.7", "9.9.9.9"]}'
wait_for "range goes to the tunnel" "route_get 203.0.113.50 | grep -q 'dev sr-tun0'"
check "everything else out of the tunnel" bash -c "! ip netns exec $NS ip route get 1.1.1.1 | grep -q 'dev sr-tun0'"
check "relay inside the range pinned" bash -c "ip netns exec $NS ip route get 203.0.113.7 | grep -q 'via 192.168.1.1'"
check "relay outside the range not pinned" bash -c "! ip netns exec $NS ip route show proto 211 | grep -q 9.9.9.9"
check "resolv.conf untouched for a range" test "$(cat /etc/netns/$NS/resolv.conf)" == "$BASE_DNS"
stop_helper

echo "13. systemd-resolved (stand-in resolvectl)"
kill -9 $FAKE; wait $FAKE 2>/dev/null
echo '{"up0": {"dns": ["192.168.1.1"], "domain": [], "default-route": true}, "fake0": {"dns": ["10.3.0.1"], "domain": [], "default-route": true}}' > $FAKE_RESOLVED
echo "nameserver 127.0.0.53" > /etc/netns/$NS/resolv.conf
start_fake $DNSPORT
state '{"mapped": ["0.0.0.0/0"], "first_hops": ["9.9.9.9"]}'
PATH=$T/bin:$PATH start_helper --dns-mode auto --router-comm python3
wait_for "mapped" "route_get 1.1.1.1 | grep -q 'dev sr-tun0'"
check "picked resolved mode" grep -q "DNS now goes through the router (Resolved)" $T/helper.log
wait_for "tunnel link's DNS server is the router's 127.0.0.1 listener" "test \"\$(rstate sr-tun0 dns)\" == \"['127.0.0.1:\$(cat $DNSPORT)']\""
check "tunnel link takes every lookup (~.)" test "$(rstate sr-tun0 domain)" == "['~.']"
check "tunnel link is a DNS default route" test "$(rstate sr-tun0 default-route)" == "True"
check "resolv.conf left alone" test "$(cat /etc/netns/$NS/resolv.conf)" == "nameserver 127.0.0.53"
in_ns ip link del sr-tun0
wait_for "tunnel gone: uplinks stop answering DNS while holding" "test \"\$(rstate up0 default-route)\" == False -a \"\$(rstate fake0 default-route)\" == False"
check "and exit traffic is blocked" blocked 1.1.1.1
add_tun
wait_for "tunnel back: uplinks get DNS back" "test \"\$(rstate up0 default-route)\" == True -a \"\$(rstate fake0 default-route)\" == True"
wait_for "new tunnel link set up again" "test \"\$(rstate sr-tun0 domain)\" == \"['~.']\""
state '{"mapped": [], "first_hops": []}'
wait_for "unmap: tunnel link's DNS settings taken back" "test \"\$(rstate sr-tun0 dns)\" == '[]' -a \"\$(rstate sr-tun0 domain)\" == '[]' -a \"\$(rstate sr-tun0 default-route)\" == False"
check "uplinks untouched after unmap" test "$(rstate up0 dns)" == "['192.168.1.1']"
stop_helper
echo "$BASE_DNS" > /etc/netns/$NS/resolv.conf
kill -9 $FAKE; wait $FAKE 2>/dev/null

echo "14. older router without first_hops (over TCP)"
FAKE_RPC=$RPC_TCP; start_fake
state '{"mapped": ["0.0.0.0/0"], "first_hops": [], "old_router": true}'
RPC=$RPC_TCP start_helper --pin 9.9.9.9
wait_for "warns that first hops can't be listed" "grep -q 'no llarp.first_hops' $T/helper.log"
wait_for "--pin still honoured" "route_get 9.9.9.9 | grep -q 'via 192.168.1.1'"

echo "15. SIGTERM puts everything back"
stop_helper
check "routes identical to before" test "$(routes)" == "$BASE"
check "resolv.conf restored" test "$(cat /etc/netns/$NS/resolv.conf)" == "$BASE_DNS"
check "journal removed" test ! -e $J

echo
echo "passed $PASS, failed $FAIL"
[ $FAIL -eq 0 ]
