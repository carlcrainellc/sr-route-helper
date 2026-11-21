# Running alongside other VPNs (plan)

Nothing here is built yet. It's the plan for when another VPN is on the same machine.

## Today

The helper never uses another VPN's interface as the uplink. It decides which interfaces are VPNs from the link kind (wireguard, gre, ...), from tun/tap devices, and from common names like `wg*` or `tailscale*`. If another VPN holds the default route, the helper uses the next real uplink and puts its own routes on top. The two VPNs then fight over the routes, and whichever has the lower metric wins.

## 1. Detect by kind and route ownership, not names

- Drop the name list.
- Treat an interface as another VPN if:
  - its link kind is a tunnel kind, or
  - it's a tun/tap device that isn't ours, or
  - it holds a default route or a `0.0.0.0/1` + `128.0.0.0/1` pair that we didn't add (route protocol, or a different interface).
- PPP and cellular links still count as uplinks. Recognise them by link type (ARPHRD_PPP, raw-IP modems), not by name.

## 2. `--uplink IFACE`

This tells the helper to treat IFACE as the uplink even if it looks like a VPN. The use case is running Session Router on purpose inside another VPN: relays go out through the VPN, and exit traffic goes into our tunnel. If IFACE goes down, we hold (fail closed) and don't go looking for another uplink.

## 3. Refuse when another VPN owns the routes

When `--uplink` isn't set and another interface owns the default routes, the helper doesn't map. It:

- logs `another VPN is active on wg0; not routing the exit (use --uplink wg0 to run on top of it)`
- reports this as the reason through the router's map status
- changes nothing and keeps checking, then maps once the other VPN goes away

This replaces today's silent metric fight.

## 4. Policy routing (fwmark) mode

Instead of pinning each relay address, this mode routes by packet mark:

- An `ip rule` sends packets with mark M to a table that only has the physical default route.
- Everything else uses the main table, which holds the tunnel routes.

That avoids the per-relay host routes and the race when a new relay is dialled, and it can coexist with VPNs that use rules too (WireGuard's `wg-quick`, Tailscale).

It needs the router to set `SO_MARK` on its own sockets (relay connections and bootstrap), which is a router change: a config option such as `[network] socket-mark=`, plus CAP_NET_ADMIN, which it already has. Until the router does that, this mode can't work. Pins stay the default.

## 5. Split mode

Only chosen things go through the exit:

- **By address:** routes only for the listed ranges. That's mostly there already, because a range mapping only routes that range.
- **By app:** put the app in a cgroup, mark its packets with nftables (`meta cgroup`), and use an `ip rule` for that mark into a table whose default is the tunnel. Everything else keeps the normal routes, and DNS has to follow the same split.

This needs the fwmark pieces from (4), but not the router change: it marks the app's packets, not the router's.

## Order

1 and 3 first (small, and they make the current behaviour safe), then 2, then 5 by address. 4 and app split wait on the router marking its sockets.
