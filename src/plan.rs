//! Works out which routes should exist, from a snapshot of the system and the router.
//!
//! Nothing in here touches the system, so every rule can be tested with plain data.

use crate::net::{lan_v4, link_only_v4, never_a_relay, Net};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Metric for every route the helper adds. On Linux the longest prefix wins first, so this
/// only matters against another route with the very same prefix.
pub const METRIC: u32 = 5;

/// Metric for the fail-closed sinks that sit under each tunnel route. The tunnel route
/// (metric 5) wins while it exists; when the tunnel goes away the kernel drops its routes
/// and these take over at once, even if the helper itself is gone.
pub const SINK_METRIC: u32 = 6;

/// Interface kinds (`IFLA_INFO_KIND`) that are tunnels or overlays, never the uplink.
const TUNNEL_KINDS: &[&str] = &[
    "wireguard",
    "tun",
    "tap",
    "sit",
    "ipip",
    "ip6tnl",
    "gre",
    "gretap",
    "ip6gre",
    "ip6gretap",
    "erspan",
    "ip6erspan",
    "vti",
    "vti6",
    "xfrm",
    "geneve",
    "vxlan",
    "bareudp",
    "amt",
];

/// Names VPN clients commonly give their interfaces.
const TUNNEL_NAMES: &[&str] = &[
    "wg",
    "tun",
    "tap",
    "tailscale",
    "mullvad",
    "utun",
    "nordlynx",
    "proton",
    "zt",
    "ipsec",
];

/// Names of real uplinks that happen to be point-to-point or headerless (PPP, PPPoE,
/// cellular modems). These are never treated as tunnels, whatever their kind says.
const UPLINK_NAMES: &[&str] = &["ppp", "wwan", "rmnet", "usb", "mbim", "qmi"];

/// Whether an interface is a VPN or overlay tunnel rather than a possible uplink.
///
/// The point-to-point flag and a missing link-layer header are *not* used: PPP, PPPoE and
/// raw-IP cellular modems have both and are real uplinks.
pub fn is_tunnel(name: &str, kind: Option<&str>, loopback: bool, has_tun_flags: bool) -> bool {
    if loopback {
        return true;
    }
    if UPLINK_NAMES.iter().any(|p| name.starts_with(p)) {
        return false;
    }
    kind.is_some_and(|k| TUNNEL_KINDS.contains(&k))
        || has_tun_flags
        || TUNNEL_NAMES.iter().any(|p| name.starts_with(p))
}

/// One network interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub index: u32,
    pub name: String,
    /// Administratively up and the carrier is present.
    pub up: bool,
    /// A VPN or overlay tunnel (see [`is_tunnel`]): never the physical uplink.
    pub tunnel: bool,
}

/// A route as read from the main table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SysRoute {
    pub dst: Net,
    pub gateway: Option<IpAddr>,
    pub oif: Option<u32>,
    pub metric: u32,
    /// A plain unicast route (not unreachable/blackhole/local/...).
    pub unicast: bool,
    /// The kernel flagged the next hop as link-down.
    pub linkdown: bool,
    /// Added by this helper (carries its route protocol number).
    pub ours: bool,
}

/// Where traffic leaves the machine when it isn't going through the tunnel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gateway {
    /// The next hop, or `None` for a device route such as `default dev ppp0`.
    pub via: Option<IpAddr>,
    pub oif: u32,
    pub dev: String,
}

impl Gateway {
    /// How to send something out of this uplink: via the next hop, or straight out of the
    /// device when the default route has none.
    pub fn how(&self) -> How {
        match self.via {
            Some(gw) => How::Via { gw, oif: self.oif },
            None => How::Dev {
                oif: self.oif,
                link_scope: true,
            },
        }
    }
}

impl std::fmt::Display for Gateway {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.via {
            Some(v) => write!(f, "{} on {}", v, self.dev),
            None => write!(f, "{} (no next hop)", self.dev),
        }
    }
}

/// The physical uplink for one address family: the default route with the lowest metric
/// whose interface is up and isn't a tunnel (ours or anybody's). Ties go to the lower
/// interface index so the answer doesn't flap. A default route without a next hop
/// (`default dev ppp0`) counts.
pub fn pick_gateway(
    routes: &[SysRoute],
    links: &[Link],
    v6: bool,
    tun: Option<u32>,
) -> Option<Gateway> {
    routes
        .iter()
        .filter(|r| r.dst.is_default() && r.dst.is_v4() != v6)
        .filter(|r| r.unicast && !r.linkdown && !r.ours)
        .filter_map(|r| {
            let via = r.gateway.filter(|g| !g.is_unspecified());
            let oif = r.oif?;
            if Some(oif) == tun {
                return None;
            }
            let link = links.iter().find(|l| l.index == oif)?;
            if !link.up || link.tunnel {
                return None;
            }
            Some((
                r.metric,
                oif,
                Gateway {
                    via,
                    oif,
                    dev: link.name.clone(),
                },
            ))
        })
        .min_by_key(|(m, i, _)| (*m, *i))
        .map(|(_, _, g)| g)
}

/// Why a route exists. Routes are added in this order and removed in reverse, so the
/// router's own traffic always has a way out, and the fail-closed sinks are in place,
/// before anything is sent into the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    /// A relay the router talks to directly, sent out of the physical gateway.
    Pin,
    /// Local-network, link-local or multicast space kept off the tunnel.
    Keep,
    /// Unreachable route under a tunnel route, so exit traffic is refused rather than
    /// sent in the clear when the tunnel disappears.
    Sink,
    /// The exit's own DNS resolver, sent into the tunnel even though it is private space.
    ExitDns,
    /// Traffic for the exit.
    Tunnel,
    /// IPv6 refused while a full IPv4 tunnel is up, so it can't leak around the exit.
    Block,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum How {
    Via { gw: IpAddr, oif: u32 },
    Dev { oif: u32, link_scope: bool },
    Unreachable,
}

/// One route the helper wants in the main table.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Want {
    pub dst: Net,
    pub how: How,
    pub role: Role,
    pub metric: u32,
}

impl std::fmt::Display for Want {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.how {
            How::Via { gw, oif } => write!(f, "{} via {} (if {})", self.dst, gw, oif)?,
            How::Dev { oif, .. } => write!(f, "{} dev (if {})", self.dst, oif)?,
            How::Unreachable => write!(f, "unreachable {}", self.dst)?,
        }
        if self.metric != METRIC {
            write!(f, " metric {}", self.metric)?;
        }
        write!(f, " [{:?}]", self.role)
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    /// Keep private/LAN IPv4 space off a full tunnel (default on).
    pub keep_lan: bool,
    /// Refuse IPv6 while only IPv4 goes through the exit (default on).
    pub block_ipv6: bool,
    /// Put sinks under the tunnel routes and hold traffic blocked when the router or its
    /// tunnel goes away (default on; `--fail-open` turns it off).
    pub fail_closed: bool,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            keep_lan: true,
            block_ipv6: true,
            fail_closed: true,
        }
    }
}

/// Everything a plan is made from.
#[derive(Debug, Clone, Default)]
pub struct Inputs {
    /// Union of all mapped exit ranges.
    pub mapped: Vec<Net>,
    pub first_hops: Vec<IpAddr>,
    pub exit_dns: Vec<IpAddr>,
    pub tun: Option<u32>,
    pub gw4: Option<Gateway>,
    pub gw6: Option<Gateway>,
    pub opts: Options,
}

/// What the plan could not do, for the log.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notes {
    /// Relays caught by the IPv6 block with no IPv6 uplink to pin them to.
    pub unpinned: Vec<IpAddr>,
    /// Address families whose tunnel routes were held back because there is no usable
    /// uplink to pin the router's own traffic to (sinks only, if failing closed).
    pub held: Vec<&'static str>,
}

pub fn halves(v6: bool) -> [Net; 2] {
    if v6 {
        ["::/1".parse().unwrap(), "8000::/1".parse().unwrap()]
    } else {
        [Net::v4(0, 0, 0, 0, 1), Net::v4(128, 0, 0, 0, 1)]
    }
}

/// True when this plan sends all IPv4 into the tunnel.
pub fn is_full_v4(mapped: &[Net]) -> bool {
    mapped.iter().any(|n| n.is_v4() && n.is_default())
}

fn fam(v6: bool) -> &'static str {
    if v6 {
        "IPv6"
    } else {
        "IPv4"
    }
}

pub fn plan(i: &Inputs) -> (Vec<Want>, Notes) {
    let mut out: Vec<Want> = Vec::new();
    let mut notes = Notes::default();
    let Some(tun) = i.tun else {
        return (out, notes);
    };
    if i.mapped.is_empty() {
        return (out, notes);
    }
    let push = |out: &mut Vec<Want>, w: Want| {
        if !out.iter().any(|o| o.dst == w.dst && o.role == w.role) {
            out.push(w);
        }
    };
    let full4 = is_full_v4(&i.mapped);
    let full6 = i.mapped.iter().any(|n| !n.is_v4() && n.is_default());
    let mut hops = i.first_hops.clone();
    hops.sort();
    hops.dedup();
    hops.retain(|h| !never_a_relay(*h));

    // What goes into the tunnel. A default range becomes two halves so the existing
    // default route stays in place for everything we pin to it.
    let mut tunnel: Vec<Net> = Vec::new();
    for v6 in [false, true] {
        let full = if v6 { full6 } else { full4 };
        let ranges: Vec<Net> = if full {
            halves(v6).to_vec()
        } else {
            i.mapped
                .iter()
                .filter(|n| n.is_v4() != v6)
                .copied()
                .collect()
        };
        if ranges.is_empty() {
            continue;
        }
        let gw = if v6 { &i.gw6 } else { &i.gw4 };
        // Without an uplink the router's own traffic would loop into its tunnel. A full
        // tunnel always catches relays (including ones it dials next), a range only if a
        // known relay is inside it.
        let catches_relay = full || hops.iter().any(|h| ranges.iter().any(|n| n.contains(*h)));
        let hold = gw.is_none() && catches_relay;
        for n in &ranges {
            if i.opts.fail_closed {
                push(
                    &mut out,
                    Want {
                        dst: *n,
                        how: How::Unreachable,
                        role: Role::Sink,
                        metric: SINK_METRIC,
                    },
                );
            }
            if !hold {
                tunnel.push(*n);
            }
        }
        if hold {
            notes.held.push(fam(v6));
        }
    }
    for n in &tunnel {
        push(
            &mut out,
            Want {
                dst: *n,
                how: How::Dev {
                    oif: tun,
                    link_scope: false,
                },
                role: Role::Tunnel,
                metric: METRIC,
            },
        );
    }
    let mut blocked: Vec<Net> = Vec::new();
    if full4 && !full6 && i.opts.block_ipv6 {
        for n in halves(true) {
            blocked.push(n);
            push(
                &mut out,
                Want {
                    dst: n,
                    how: How::Unreachable,
                    role: Role::Block,
                    metric: METRIC,
                },
            );
        }
    }

    // Local network space stays local on a full tunnel.
    if let (true, true, Some(g)) = (full4, i.opts.keep_lan, &i.gw4) {
        for n in lan_v4() {
            push(
                &mut out,
                Want {
                    dst: n,
                    how: g.how(),
                    role: Role::Keep,
                    metric: METRIC,
                },
            );
        }
        for n in link_only_v4() {
            push(
                &mut out,
                Want {
                    dst: n,
                    how: How::Dev {
                        oif: g.oif,
                        link_scope: true,
                    },
                    role: Role::Keep,
                    metric: METRIC,
                },
            );
        }
    }

    // The exit's resolver goes through the tunnel even when it sits in private space, and
    // is refused (not sent to the LAN) when the tunnel is gone.
    for d in &i.exit_dns {
        let in_tunnel = tunnel.iter().any(|n| n.contains(*d));
        let sunk = i.opts.fail_closed
            && out
                .iter()
                .any(|w| w.role == Role::Sink && w.dst.contains(*d));
        if in_tunnel {
            push(
                &mut out,
                Want {
                    dst: Net::host(*d),
                    how: How::Dev {
                        oif: tun,
                        link_scope: false,
                    },
                    role: Role::ExitDns,
                    metric: METRIC,
                },
            );
        }
        if sunk {
            push(
                &mut out,
                Want {
                    dst: Net::host(*d),
                    how: How::Unreachable,
                    role: Role::Sink,
                    metric: SINK_METRIC,
                },
            );
        }
    }

    // First hops: any relay address that would otherwise land in the tunnel (or in the
    // IPv6 block) goes straight out of the physical uplink.
    for h in hops {
        let caught = tunnel.iter().chain(blocked.iter()).any(|n| n.contains(h));
        if !caught {
            continue;
        }
        let gw = if h.is_ipv4() { &i.gw4 } else { &i.gw6 };
        match gw {
            Some(g) => push(
                &mut out,
                Want {
                    dst: Net::host(h),
                    how: g.how(),
                    role: Role::Pin,
                    metric: METRIC,
                },
            ),
            None => notes.unpinned.push(h),
        }
    }
    out.sort_by_key(|a| (a.role, a.dst, a.metric));
    (out, notes)
}

/// What to keep while the router or its tunnel is gone and we fail closed: everything
/// except the routes into the tunnel. The sinks then refuse exit traffic, the IPv6 block
/// stays, the LAN stays reachable and relays stay pinned for when the router comes back.
pub fn hold(current: &[Want]) -> Vec<Want> {
    current
        .iter()
        .filter(|w| !matches!(w.role, Role::Tunnel | Role::ExitDns))
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn link(index: u32, name: &str, up: bool, tunnel: bool) -> Link {
        Link {
            index,
            name: name.into(),
            up,
            tunnel,
        }
    }
    fn dflt(gw: &str, oif: u32, metric: u32) -> SysRoute {
        let g: IpAddr = gw.parse().unwrap();
        SysRoute {
            dst: if g.is_ipv4() {
                "0.0.0.0/0".parse().unwrap()
            } else {
                "::/0".parse().unwrap()
            },
            gateway: Some(g),
            oif: Some(oif),
            metric,
            unicast: true,
            linkdown: false,
            ours: false,
        }
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    /// The bug that cut a user's internet: a second adapter with a lower-numbered gateway
    /// must not win over the real uplink just because its address sorts first.
    #[test]
    fn gateway_is_lowest_metric_not_lowest_address() {
        let links = [link(2, "eth0", true, false), link(3, "eth1", true, false)];
        let routes = [dflt("192.168.1.1", 2, 100), dflt("10.3.0.1", 3, 500)];
        assert_eq!(
            pick_gateway(&routes, &links, false, None).unwrap().via,
            Some(ip("192.168.1.1"))
        );
    }

    #[test]
    fn gateway_skips_down_links_tunnels_and_our_tun() {
        let links = [
            link(2, "eth0", true, false),
            link(3, "wlan0", false, false),
            link(4, "wg0", true, true),
            link(9, "sr-tun0", true, false),
        ];
        let routes = [
            dflt("192.168.1.1", 2, 600),
            dflt("192.168.50.1", 3, 1),
            dflt("10.66.0.1", 4, 0),
            dflt("10.0.0.1", 9, 0),
        ];
        let g = pick_gateway(&routes, &links, false, Some(9)).unwrap();
        assert_eq!((g.via, g.dev.as_str()), (Some(ip("192.168.1.1")), "eth0"));
        // A link-down next hop and our own leftovers never count either.
        let mut r2 = routes.to_vec();
        r2[0].linkdown = true;
        assert!(pick_gateway(&r2, &links, false, Some(9)).is_none());
        r2[0].linkdown = false;
        r2[0].ours = true;
        assert!(pick_gateway(&r2, &links, false, Some(9)).is_none());
    }

    #[test]
    fn gateway_ties_go_to_lower_index_and_families_stay_apart() {
        let links = [link(2, "a", true, false), link(5, "b", true, false)];
        let routes = [
            dflt("192.168.9.1", 5, 100),
            dflt("192.168.1.1", 2, 100),
            dflt("fe80::1", 5, 1),
        ];
        assert_eq!(pick_gateway(&routes, &links, false, None).unwrap().oif, 2);
        let g6 = pick_gateway(&routes, &links, true, None).unwrap();
        assert_eq!((g6.via, g6.oif), (Some(ip("fe80::1")), 5));
    }

    fn gw(via: &str, oif: u32) -> Gateway {
        Gateway {
            via: Some(ip(via)),
            oif,
            dev: "eth0".into(),
        }
    }

    fn full_inputs() -> Inputs {
        Inputs {
            mapped: vec!["0.0.0.0/0".parse().unwrap()],
            first_hops: vec![
                ip("9.9.9.9"),
                ip("203.0.113.7"),
                ip("192.168.1.20"),
                ip("2001:db8::7"),
            ],
            exit_dns: vec![ip("10.99.0.53")],
            tun: Some(9),
            gw4: Some(gw("192.168.1.1", 2)),
            gw6: Some(gw("fe80::1", 2)),
            opts: Options::default(),
        }
    }

    #[test]
    fn full_tunnel_plan() {
        let (p, notes) = plan(&full_inputs());
        // The route that carries traffic (each tunnel range also has a sink under it).
        let find = |dst: &str| {
            p.iter()
                .find(|w| w.dst == dst.parse::<Net>().unwrap() && w.role != Role::Sink)
                .cloned()
        };
        assert_eq!(
            find("0.0.0.0/1").unwrap().how,
            How::Dev {
                oif: 9,
                link_scope: false
            }
        );
        assert_eq!(find("128.0.0.0/1").unwrap().role, Role::Tunnel);
        assert_eq!(find("::/1").unwrap().how, How::Unreachable);
        assert_eq!(
            find("10.0.0.0/8").unwrap().how,
            How::Via {
                gw: ip("192.168.1.1"),
                oif: 2
            }
        );
        assert_eq!(
            find("224.0.0.0/4").unwrap().how,
            How::Dev {
                oif: 2,
                link_scope: true
            }
        );
        assert_eq!(find("10.99.0.53/32").unwrap().role, Role::ExitDns);
        assert_eq!(
            find("9.9.9.9/32").unwrap().how,
            How::Via {
                gw: ip("192.168.1.1"),
                oif: 2
            }
        );
        assert_eq!(find("203.0.113.7/32").unwrap().role, Role::Pin);
        // IPv6 relays are pinned through the block, LAN hops aren't pinned at all.
        assert_eq!(
            find("2001:db8::7/128").unwrap().how,
            How::Via {
                gw: ip("fe80::1"),
                oif: 2
            }
        );
        assert!(find("192.168.1.20/32").is_none());
        assert!(notes.unpinned.is_empty());
        // Pins come first, the tunnel after them.
        let first_tunnel = p.iter().position(|w| w.role == Role::Tunnel).unwrap();
        assert!(p[..first_tunnel].iter().any(|w| w.role == Role::Pin));
        assert!(p[first_tunnel..].iter().all(|w| w.role != Role::Pin));
    }

    #[test]
    fn nothing_mapped_or_no_tun_means_no_routes() {
        let mut i = full_inputs();
        i.mapped.clear();
        assert!(plan(&i).0.is_empty());
        let mut i = full_inputs();
        i.tun = None;
        assert!(plan(&i).0.is_empty());
    }

    #[test]
    fn range_mapping_only_pins_hops_inside_it() {
        let mut i = full_inputs();
        i.mapped = vec!["203.0.113.0/24".parse().unwrap()];
        let (p, _) = plan(&i);
        let dsts: Vec<String> = p.iter().map(|w| format!("{w}")).collect();
        assert_eq!(
            dsts,
            vec![
                "203.0.113.7/32 via 192.168.1.1 (if 2) [Pin]",
                "unreachable 203.0.113.0/24 metric 6 [Sink]",
                "203.0.113.0/24 dev (if 9) [Tunnel]"
            ]
        );
    }

    #[test]
    fn options_turn_off_lan_keep_and_ipv6_block() {
        let mut i = full_inputs();
        i.opts = Options {
            keep_lan: false,
            block_ipv6: false,
            fail_closed: true,
        };
        let (p, _) = plan(&i);
        assert!(p
            .iter()
            .all(|w| w.role != Role::Keep && w.role != Role::Block));
        // Without the IPv6 block an IPv6 relay isn't caught by anything, so no pin.
        assert!(!p
            .iter()
            .any(|w| w.dst == "2001:db8::7/128".parse().unwrap()));
    }

    /// No IPv4 uplink: the tunnel routes are held back (relays would loop into the
    /// tunnel), but the sinks go in so nothing leaks either.
    #[test]
    fn no_uplink_holds_the_tunnel_and_keeps_the_sinks() {
        let mut i = full_inputs();
        i.gw4 = None;
        let (p, notes) = plan(&i);
        assert_eq!(notes.held, vec!["IPv4"]);
        assert!(p.iter().all(|w| !(w.role == Role::Tunnel && w.dst.is_v4())));
        assert!(p.iter().all(|w| w.role != Role::Keep));
        assert!(p.iter().all(|w| w.role != Role::Pin || !w.dst.is_v4()));
        let sinks: Vec<String> = p
            .iter()
            .filter(|w| w.role == Role::Sink)
            .map(|w| w.dst.to_string())
            .collect();
        assert_eq!(sinks, vec!["0.0.0.0/1", "10.99.0.53/32", "128.0.0.0/1"]);
        // Failing open there is nothing at all for IPv4.
        i.opts.fail_closed = false;
        let (p, notes) = plan(&i);
        assert_eq!(notes.held, vec!["IPv4"]);
        assert!(p.iter().all(|w| !w.dst.is_v4()));
    }

    #[test]
    fn range_without_uplink_is_fine_unless_a_relay_is_inside() {
        let mut i = full_inputs();
        i.gw4 = None;
        i.mapped = vec!["198.51.100.0/24".parse().unwrap()];
        let (p, notes) = plan(&i);
        assert!(notes.held.is_empty());
        assert!(p.iter().any(|w| w.role == Role::Tunnel));
        i.mapped = vec!["203.0.113.0/24".parse().unwrap()];
        let (p, notes) = plan(&i);
        assert_eq!(notes.held, vec!["IPv4"]);
        assert!(p.iter().all(|w| w.role != Role::Tunnel));
    }

    #[test]
    fn sinks_sit_under_every_tunnel_route_unless_failing_open() {
        let (p, _) = plan(&full_inputs());
        for t in p.iter().filter(|w| w.role == Role::Tunnel) {
            assert!(
                p.iter().any(|s| s.role == Role::Sink
                    && s.dst == t.dst
                    && s.how == How::Unreachable
                    && s.metric == SINK_METRIC),
                "no sink under {t}"
            );
        }
        // Sinks go in before the tunnel routes.
        let first_tunnel = p.iter().position(|w| w.role == Role::Tunnel).unwrap();
        let last_sink = p.iter().rposition(|w| w.role == Role::Sink).unwrap();
        assert!(last_sink < first_tunnel);
        let mut i = full_inputs();
        i.opts.fail_closed = false;
        assert!(plan(&i).0.iter().all(|w| w.role != Role::Sink));
    }

    #[test]
    fn hold_keeps_everything_but_the_tunnel() {
        let (p, _) = plan(&full_inputs());
        let h = hold(&p);
        assert!(h
            .iter()
            .all(|w| !matches!(w.role, Role::Tunnel | Role::ExitDns)));
        for r in [Role::Sink, Role::Pin, Role::Keep, Role::Block] {
            assert!(h.iter().any(|w| w.role == r), "{r:?} dropped");
        }
        assert_eq!(
            h.len(),
            p.iter()
                .filter(|w| !matches!(w.role, Role::Tunnel | Role::ExitDns))
                .count()
        );
    }

    #[test]
    fn tunnels_are_told_apart_from_point_to_point_uplinks() {
        // Real uplinks, including the point-to-point and headerless ones.
        for (name, kind) in [
            ("eth0", Some("veth")),
            ("enp3s0", None),
            ("wlan0", None),
            ("ppp0", None),
            ("ppp0", Some("ppp")),
            ("wwan0", None),
            ("wwan0", Some("tun")), // userspace modem drivers
            ("rmnet_data0", Some("rmnet")),
            ("usb0", None),
        ] {
            assert!(!is_tunnel(name, kind, false, false), "{name} {kind:?}");
        }
        // VPNs and overlays.
        for (name, kind, tf) in [
            ("wg0", Some("wireguard"), false),
            ("home", Some("wireguard"), false),
            ("tun0", Some("tun"), true),
            ("anything", None, true),
            ("sit1", Some("sit"), false),
            ("vx0", Some("vxlan"), false),
            ("tailscale0", None, false),
            ("mullvad-wg", None, false),
            ("utun3", None, false),
            ("ipsec0", Some("xfrm"), false),
        ] {
            assert!(is_tunnel(name, kind, false, tf), "{name} {kind:?}");
        }
        assert!(is_tunnel("lo", None, true, false));
    }

    #[test]
    fn gateway_less_uplink_is_picked_and_pins_go_out_of_the_device() {
        let links = [link(4, "ppp0", true, false)];
        let mut r = dflt("10.0.0.1", 4, 0);
        r.gateway = None;
        let g = pick_gateway(&[r], &links, false, None).unwrap();
        assert_eq!((g.via, g.oif, g.dev.as_str()), (None, 4, "ppp0"));
        let mut i = full_inputs();
        i.gw4 = Some(g);
        let (p, notes) = plan(&i);
        assert!(notes.held.is_empty());
        let dev = How::Dev {
            oif: 4,
            link_scope: true,
        };
        let pin = p
            .iter()
            .find(|w| w.dst == "9.9.9.9/32".parse().unwrap())
            .unwrap();
        assert_eq!((pin.role, &pin.how), (Role::Pin, &dev));
        let lan = p
            .iter()
            .find(|w| w.dst == "192.168.0.0/16".parse().unwrap())
            .unwrap();
        assert_eq!((lan.role, &lan.how), (Role::Keep, &dev));
        assert!(p
            .iter()
            .any(|w| w.role == Role::Tunnel && w.dst == "0.0.0.0/1".parse().unwrap()));
    }

    #[test]
    fn full_ipv6_mapping_tunnels_ipv6_instead_of_blocking() {
        let mut i = full_inputs();
        i.mapped.push("::/0".parse().unwrap());
        let (p, _) = plan(&i);
        let w = p
            .iter()
            .find(|w| w.dst == "::/1".parse().unwrap() && w.role != Role::Sink)
            .unwrap();
        assert_eq!(w.role, Role::Tunnel);
        assert!(p
            .iter()
            .any(|w| w.dst == "::/1".parse().unwrap() && w.role == Role::Sink));
        assert!(p.iter().all(|w| w.role != Role::Block));
    }
}
