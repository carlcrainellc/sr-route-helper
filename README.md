# sr-route-helper

A small Linux program that sets up routes and DNS when [Session Router] maps an exit, and
always puts them back. It runs beside the router with the router's own route handling
turned off (`[network] auto-routing=false`); the helper does not patch the router.
Full-tunnel exits need the router's `first_hops` RPC, which is not in upstream Session
Router yet (see below). Range mappings and `--pin` work without it.

[Session Router]: https://github.com/session-foundation/session-router

## Why

Mapping an exit means sending your traffic into the router's tunnel while keeping the
router's own connections to relays out of it. On Linux the router does this itself today,
and we hit three problems with it:

- **Picking the wrong gateway.** The router takes the first default route listed in
  `/proc/net/route`. That isn't the one Linux actually uses: it ignores route metrics and
  whether the link is up, so a second adapter, an unplugged one, or another VPN can win.
  Relay traffic then gets pinned to a gateway that goes nowhere and the connection dies.
- **Leftover routes.** Pinned routes are only remembered in memory. If the router crashes
  or is killed, they stay behind, and DNS can be left pointing at a router that isn't
  running.
- **IPv6 slipping around the exit.** With a full IPv4 tunnel and no IPv6 in the tunnel,
  IPv6 traffic goes straight out the normal connection.

The same design is used on Windows, so both platforms behave alike.

## What it does

It asks the router which ranges are mapped and which relays it is talking to directly,
looks at the routing table, and brings the system in line. It checks every 0.5 seconds
while an exit is mapped, every 0.25 seconds for a few seconds after the relays or the
gateway change, and every 3 seconds when nothing is mapped.

- **Uplink:** the default route with the lowest metric on a link that is up. VPNs and
  overlays never count: our own tunnel, WireGuard, tun/tap, GRE, VXLAN and the like (by
  interface kind), and names such as `wg*`, `tun*`, `tailscale*`, `mullvad*`. PPP,
  PPPoE and cellular modems (`ppp*`, `wwan*`, `rmnet*`) do count, point-to-point or not,
  and so does a default route with no next hop (`default dev ppp0`).
- **First hops:** each relay address gets a host route out of the uplink (via its next
  hop, or straight out of the device), so it never goes into the tunnel. They follow the
  uplink when it changes (Wi-Fi to Ethernet, a VPN going away).
- **Full tunnel:** `0.0.0.0/1` and `128.0.0.0/1` into the tunnel, leaving the existing
  default route alone. Private and LAN space (10/8, 172.16/12, 192.168/16, 100.64/10),
  link-local and multicast stay on the local network. An exit-side resolver you name
  with `--exit-dns` goes into the tunnel anyway.
- **No uplink:** if there's no usable uplink, the tunnel routes are held back, because
  the router's own traffic would otherwise loop into its tunnel. Exit traffic is blocked
  until an uplink appears.
- **IPv6:** while only IPv4 goes through the exit, IPv6 is refused (`::/1` and
  `8000::/1` unreachable), so it can't leak around it. That includes IPv6 on your home
  network, except the subnets you are directly connected to (their own routes are more
  specific): link-local `fe80::`, and your LAN's `/64` on each interface, still work.
  IPv6 subnets behind another router at home, and the IPv6 internet, don't.
  `--allow-ipv6` turns this off. IPv6 relays are still pinned and keep working.
- **Ranges:** a mapping for specific ranges just routes those ranges into the tunnel.
  DNS is left alone.
- **DNS:** with a full tunnel, lookups go to the router.
  - On **systemd-resolved** (resolv.conf points at its stub), the tunnel link gets the
    router as its DNS server, the `~.` domain (every lookup) and the DNS default route.
    The server is the router's listener on `127.0.0.1` (a random port on systemd builds;
    the helper finds it by the router's process name). resolved 249 and later sends a
    link's queries out of that link and only special-cases 127.0.0.1, so the
    `127.3.2.1` listener doesn't work there. If the helper can't find the listener (for
    example because the router runs as another user), set `[dns] listen=127.0.0.1:953`
    (keep `127.3.2.1` too) in the router and pass `--resolved-dns 127.0.0.1:953`.
  - Anywhere else, it rewrites `/etc/resolv.conf` to `nameserver 127.3.2.1`. If
    NetworkManager, resolvconf or a DHCP client rewrites the file while the exit is up,
    the helper points it back at the router. Afterwards it puts back the newest version
    it saw from them. (NetworkManager set up to use systemd-resolved is the case above.)

## Fail closed

Under every route into the tunnel there is an unreachable route for the same range, one
metric worse (metric 6, the tunnel route is 5). While the tunnel is there it wins. When
the tunnel interface goes away, the kernel drops its routes and the unreachable ones take
over at once, even if the helper itself is gone. This matches the router's own
`blackhole-routes` (on by default), except that programs get an immediate error rather
than a silent drop.

If the router stops answering (3 checks in a row) or its tunnel disappears while an exit
is mapped, the helper holds:

- exit traffic stays blocked, and so does IPv6
- the LAN stays reachable, and relays stay pinned for when the router comes back
- DNS stays pointed at the router, so lookups fail instead of going to your normal
  resolver. On systemd-resolved, which forgets a tunnel link's settings when the link
  goes away, the other links' DNS default route is turned off until the helper is back
  or restored.

The hold ends when the router answers again: it carries on with the mapping, or, if
nothing is mapped any more, takes everything down. It also ends when you stop the helper
(SIGTERM, SIGINT or SIGHUP) or run `sr-route-helper restore`. Both of those put
everything back right away, held or not.

`--fail-open` brings back the old behaviour: no unreachable routes, and routes and DNS
come down when the router or its tunnel goes away.

## Undo

Every change is written to a small journal file *before* it is made
(`/var/lib/sr-route-helper/journal.json`). Every route the helper adds also carries its
own route protocol number (211, `ip route show proto 211`), so leftovers are found even
if the journal is lost.

- A clean stop (SIGTERM, SIGINT, SIGHUP), an unmap, or `restore` puts everything back.
- After a crash or `kill -9`, the next `run` carries on from the journal. If it was
  holding, it keeps holding, and routes of ours the journal doesn't list are removed.
  `restore` undoes everything instead.

## Install

```sh
cargo build --release
sudo install -m 755 target/release/sr-route-helper /usr/bin/
sudo install -m 644 sr-route-helper.service /etc/systemd/system/
```

Tell the router to leave routes alone, in its config:

```ini
[network]
auto-routing=false
```

Then restart the router and start the helper:

```sh
sudo systemctl restart session-router
sudo systemctl enable --now sr-route-helper
```

`sr-route-helper.service` runs as root with only `CAP_NET_ADMIN` and the usual sandboxing.
A deliberate stop or restart of `session-router` stops it too, which puts everything back.
A router crash doesn't, so it holds. It doesn't restore on its own crash either: it's
restarted and carries on from its journal.

By hand:

```sh
sudo sr-route-helper run        # keep things in line until stopped
sudo sr-route-helper plan       # show what it would do right now, change nothing
sudo sr-route-helper restore    # undo anything an earlier run left behind
```

`sr-route-helper --help` lists the options (RPC address, tunnel name, journal path,
intervals, DNS mode, `--fail-open`). By default it talks to the router over its Unix
socket, `ipc:///var/lib/session-router/rpc.sock`, when that exists (file permissions
decide who may use it), and otherwise over `tcp://127.0.0.1:1190`.

## The router's `first_hops` call

To keep the router's own connections out of the tunnel, the helper asks the router which
relays it is talking to directly (`llarp.first_hops`, a small read-only RPC call). A
router without that call still works with the helper, but only addresses given with
`--pin` are kept out of the tunnel. The helper says so in its log. Relays the router
connects to then go into its own tunnel and those connections fail, so a full-tunnel exit
generally won't come up. That call is not in upstream Session Router yet.

## Tests

`cargo test` covers the planning, the uplink and tunnel rules, the journal, and the DNS
logic.

`sudo test/netns-test.sh` (CI runs it too) runs the helper in a throwaway network namespace against a
stand-in for the router's RPC (over the Unix socket, and TCP for one step). The namespace
has:

- the real uplink
- a second adapter with a lower gateway address but a worse metric
- an unplugged adapter with the best metric
- a VPN-named adapter with an even better metric
- later, a point-to-point `ppp0` with no next hop

The script checks:

- gateway choice, and pins that follow the uplink
- how fast a new relay is pinned
- holding when there is no uplink
- LAN and multicast staying local, the IPv6 block and the directly connected IPv6 subnet
- DNS, including a resolv.conf rewritten by someone else
- unmap, `kill -9` followed by restore, and a lost journal
- failing closed when the router goes quiet or the tunnel disappears, and a restarted
  helper that keeps holding
- `--fail-open`
- range mappings, an older router, and SIGTERM

The systemd-resolved steps use `test/fake-resolvectl`, a stand-in that records what the
helper tells resolved. They check the settings, not real lookups. Each undo check
compares the routing table and resolv.conf with how they were before.

## Known limits

- A relay the router starts talking to can still go into the tunnel for up to one check
  (0.25-0.5 seconds) before it is pinned. A notification from the router would close
  that gap.
- On systemd-resolved, finding the router's 127.0.0.1 listener needs the helper to see
  the router's sockets. Run as root with only `CAP_NET_ADMIN`, it can see them only when
  the match by user is unambiguous. Otherwise use `--resolved-dns` as above.
- While holding on systemd-resolved, NetworkManager may turn a link's DNS default route
  back on when it reconnects. Lookups could then reach that link's resolver, but the
  traffic that follows is still blocked.

## License

GPL-3.0-or-later, the same as Session Router. See [LICENSE](LICENSE).
