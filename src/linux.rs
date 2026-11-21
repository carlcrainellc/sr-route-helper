//! Reading and changing the main routing table over rtnetlink.

use crate::net::Net;
use crate::plan::{self, How, Link, SysRoute, Want};
use netlink_packet_core::{
    NetlinkHeader, NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_CREATE, NLM_F_DUMP, NLM_F_EXCL,
    NLM_F_REQUEST,
};
use netlink_packet_route::link::{LinkAttribute, LinkFlags, LinkInfo, LinkLayerType, LinkMessage};
use netlink_packet_route::route::{
    RouteAddress, RouteAttribute, RouteFlags, RouteHeader, RouteMessage, RouteNextHopFlags,
    RouteProtocol, RouteScope, RouteType,
};
use netlink_packet_route::{AddressFamily, RouteNetlinkMessage};
use netlink_sys::{protocols::NETLINK_ROUTE, Socket, SocketAddr};
use std::io;
use std::net::IpAddr;

/// Route protocol number stamped on every route the helper adds (`ip route show proto 211`).
/// Lets a restore find our routes even if the journal is gone.
pub const PROTO: u8 = 211;
const MAIN: u32 = 254;

pub struct Netlink {
    sock: Socket,
    seq: u32,
}

impl Netlink {
    pub fn open() -> io::Result<Netlink> {
        let mut sock = Socket::new(NETLINK_ROUTE)?;
        sock.bind_auto()?;
        sock.connect(&SocketAddr::new(0, 0))?;
        Ok(Netlink { sock, seq: 1 })
    }

    /// Sends one request and collects every answer until DONE (dumps) or the ACK.
    fn request(
        &mut self,
        msg: RouteNetlinkMessage,
        flags: u16,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        let mut hdr = NetlinkHeader::default();
        hdr.flags = flags;
        hdr.sequence_number = self.seq;
        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);
        let mut packet = NetlinkMessage::new(hdr, NetlinkPayload::from(msg));
        packet.finalize();
        let mut buf = vec![0u8; packet.buffer_len()];
        packet.serialize(&mut buf);
        self.sock.send(&buf, 0)?;

        let dump = flags & NLM_F_DUMP == NLM_F_DUMP;
        let mut out = Vec::new();
        let mut rx = vec![0u8; 1 << 16];
        loop {
            let n = self.sock.recv(&mut &mut rx[..], 0)?;
            let mut off = 0;
            while off < n {
                let m = NetlinkMessage::<RouteNetlinkMessage>::deserialize(&rx[off..n])
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                let len = m.header.length as usize;
                if len == 0 {
                    break;
                }
                off += len;
                if m.header.sequence_number != seq {
                    continue;
                }
                match m.payload {
                    NetlinkPayload::Done(_) => return Ok(out),
                    NetlinkPayload::Error(e) => match e.code {
                        None => return Ok(out),
                        Some(c) => return Err(io::Error::from_raw_os_error(-c.get())),
                    },
                    NetlinkPayload::InnerMessage(i) => {
                        out.push(i);
                        if !dump {
                            // non-dump requests end with the ACK above
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    pub fn links(&mut self) -> io::Result<Vec<Link>> {
        let msgs = self.request(
            RouteNetlinkMessage::GetLink(LinkMessage::default()),
            NLM_F_REQUEST | NLM_F_DUMP,
        )?;
        Ok(msgs
            .into_iter()
            .filter_map(|m| match m {
                RouteNetlinkMessage::NewLink(l) => Some(l),
                _ => None,
            })
            .map(|l| {
                let name = l
                    .attributes
                    .iter()
                    .find_map(|a| {
                        if let LinkAttribute::IfName(n) = a {
                            Some(n.clone())
                        } else {
                            None
                        }
                    })
                    .unwrap_or_default();
                let kind = l.attributes.iter().find_map(|a| match a {
                    LinkAttribute::LinkInfo(infos) => infos.iter().find_map(|i| match i {
                        LinkInfo::Kind(k) => Some(k.to_string()),
                        _ => None,
                    }),
                    _ => None,
                });
                let f = l.header.flags;
                let loopback = f.contains(LinkFlags::Loopback)
                    || l.header.link_layer_type == LinkLayerType::Loopback;
                // tun/tap devices have this file whatever they are called.
                let tun_flags = !name.is_empty()
                    && std::path::Path::new("/sys/class/net")
                        .join(&name)
                        .join("tun_flags")
                        .exists();
                Link {
                    index: l.header.index,
                    up: f.contains(LinkFlags::Up)
                        && (f.contains(LinkFlags::Running) || f.contains(LinkFlags::LowerUp)),
                    tunnel: plan::is_tunnel(&name, kind.as_deref(), loopback, tun_flags),
                    name,
                }
            })
            .collect())
    }

    /// Every route in the main table, both families.
    pub fn routes(&mut self) -> io::Result<Vec<SysRoute>> {
        let mut out = Vec::new();
        for fam in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut q = RouteMessage::default();
            q.header.address_family = fam;
            for m in self.request(RouteNetlinkMessage::GetRoute(q), NLM_F_REQUEST | NLM_F_DUMP)? {
                if let RouteNetlinkMessage::NewRoute(r) = m {
                    out.extend(to_sys_hops(&r));
                }
            }
        }
        Ok(out)
    }

    /// Adds a route. `Exists` means a route with the same prefix and metric is already
    /// there; the caller decides what to do about it.
    pub fn add(&mut self, w: &Want) -> io::Result<Added> {
        match self.request(
            RouteNetlinkMessage::NewRoute(build(w)),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ) {
            Ok(_) => Ok(Added::Yes),
            Err(e) if e.raw_os_error() == Some(libc::EEXIST) => {
                let ours = self.routes()?.iter().any(|r| {
                    r.ours
                        && r.dst == w.dst
                        && r.metric == w.metric
                        && r.unicast == (w.how != How::Unreachable)
                });
                Ok(if ours {
                    Added::OursAlready
                } else {
                    Added::Theirs
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Deletes one of our routes. Matches on prefix, metric, type and our protocol number
    /// only (any scope), because the interface may be gone. Returns false when the kernel
    /// had no such route (already gone, for example with its interface).
    pub fn delete(&mut self, w: &Want) -> io::Result<bool> {
        let mut m = build(w);
        m.attributes.retain(|a| {
            matches!(
                a,
                RouteAttribute::Destination(_)
                    | RouteAttribute::Priority(_)
                    | RouteAttribute::Table(_)
            )
        });
        // RT_SCOPE_NOWHERE is the kernel's "any scope" on delete (as `ip route del` sends).
        m.header.scope = RouteScope::NoWhere;
        self.del_msg(m)
    }

    fn del_msg(&mut self, m: RouteMessage) -> io::Result<bool> {
        match self.request(RouteNetlinkMessage::DelRoute(m), NLM_F_REQUEST | NLM_F_ACK) {
            Ok(_) => Ok(true),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ESRCH) | Some(libc::ENODEV) | Some(libc::ENOENT)
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }

    /// Removes every route in the main table carrying our protocol number, except the
    /// ones in `keep` (prefix, metric and type). Returns how many were removed.
    pub fn sweep_except(&mut self, keep: &[Want]) -> io::Result<usize> {
        let mut n = 0;
        for fam in [AddressFamily::Inet, AddressFamily::Inet6] {
            let mut q = RouteMessage::default();
            q.header.address_family = fam;
            let found: Vec<RouteMessage> = self
                .request(RouteNetlinkMessage::GetRoute(q), NLM_F_REQUEST | NLM_F_DUMP)?
                .into_iter()
                .filter_map(|m| match m {
                    RouteNetlinkMessage::NewRoute(r)
                        if r.header.protocol == RouteProtocol::Other(PROTO)
                            && table_of(&r) == MAIN =>
                    {
                        Some(r)
                    }
                    _ => None,
                })
                .filter(|r| {
                    let Some(s) = to_sys(r) else { return true };
                    !keep.iter().any(|w| {
                        w.dst == s.dst
                            && w.metric == s.metric
                            && s.unicast == (w.how != How::Unreachable)
                    })
                })
                .collect();
            for r in found {
                if self.del_msg(r)? {
                    n += 1;
                }
            }
        }
        Ok(n)
    }

    /// Removes every route in the main table carrying our protocol number. Returns how
    /// many were removed.
    pub fn sweep(&mut self) -> io::Result<usize> {
        self.sweep_except(&[])
    }
}

/// What [`Netlink::add`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Added {
    Yes,
    /// One of ours with the same prefix and metric is already there (a leftover).
    OursAlready,
    /// Somebody else's route has that prefix and metric.
    Theirs,
}

fn table_of(r: &RouteMessage) -> u32 {
    r.attributes
        .iter()
        .find_map(|a| {
            if let RouteAttribute::Table(t) = a {
                Some(*t)
            } else {
                None
            }
        })
        .unwrap_or(r.header.table as u32)
}

fn addr(a: &RouteAddress) -> Option<IpAddr> {
    match a {
        RouteAddress::Inet(v) => Some(IpAddr::V4(*v)),
        RouteAddress::Inet6(v) => Some(IpAddr::V6(*v)),
        _ => None,
    }
}

fn to_sys(r: &RouteMessage) -> Option<SysRoute> {
    if table_of(r) != MAIN {
        return None;
    }
    let v6 = r.header.address_family == AddressFamily::Inet6;
    let mut dst = None;
    let mut gateway = None;
    let mut oif = None;
    let mut metric = 0;
    for a in &r.attributes {
        match a {
            RouteAttribute::Destination(d) => dst = addr(d),
            RouteAttribute::Gateway(g) => gateway = addr(g),
            RouteAttribute::Oif(i) => oif = Some(*i),
            RouteAttribute::Priority(p) => metric = *p,
            _ => {}
        }
    }
    let zero: IpAddr = if v6 {
        "::".parse().unwrap()
    } else {
        "0.0.0.0".parse().unwrap()
    };
    Some(SysRoute {
        dst: Net::new(dst.unwrap_or(zero), r.header.destination_prefix_length),
        gateway,
        oif,
        metric,
        unicast: r.header.kind == RouteType::Unicast,
        linkdown: r.header.flags.contains(RouteFlags::Linkdown)
            || r.header.flags.contains(RouteFlags::Dead),
        ours: r.header.protocol == RouteProtocol::Other(PROTO),
    })
}

/// Like [`to_sys`], but a multipath (ECMP) route becomes one entry per next hop, each with
/// that hop's gateway and interface, and marked link-down if the kernel flags that hop dead
/// or link-down. So a default route whose first next hop went away still offers the live one.
fn to_sys_hops(r: &RouteMessage) -> Vec<SysRoute> {
    let Some(base) = to_sys(r) else {
        return Vec::new();
    };
    let hops = r.attributes.iter().find_map(|a| match a {
        RouteAttribute::MultiPath(h) => Some(h),
        _ => None,
    });
    let Some(hops) = hops else {
        return vec![base];
    };
    hops.iter()
        .map(|nh| SysRoute {
            gateway: nh.attributes.iter().find_map(|a| match a {
                RouteAttribute::Gateway(g) => addr(g),
                _ => None,
            }),
            oif: Some(nh.interface_index),
            linkdown: base.linkdown
                || nh.flags.contains(RouteNextHopFlags::Linkdown)
                || nh.flags.contains(RouteNextHopFlags::Dead),
            ..base.clone()
        })
        .collect()
}

fn build(w: &Want) -> RouteMessage {
    let mut m = RouteMessage::default();
    m.header = RouteHeader {
        address_family: if w.dst.is_v4() {
            AddressFamily::Inet
        } else {
            AddressFamily::Inet6
        },
        destination_prefix_length: w.dst.prefix,
        table: RouteHeader::RT_TABLE_MAIN,
        protocol: RouteProtocol::Other(PROTO),
        scope: match w.how {
            How::Dev {
                link_scope: true, ..
            } => RouteScope::Link,
            How::Dev { .. } => RouteScope::Link,
            _ => RouteScope::Universe,
        },
        kind: if w.how == How::Unreachable {
            RouteType::Unreachable
        } else {
            RouteType::Unicast
        },
        ..Default::default()
    };
    if w.dst.prefix > 0 {
        m.attributes
            .push(RouteAttribute::Destination(w.dst.addr.into()));
    }
    m.attributes.push(RouteAttribute::Table(MAIN));
    m.attributes.push(RouteAttribute::Priority(w.metric));
    match w.how {
        How::Via { gw, oif } => {
            m.attributes.push(RouteAttribute::Gateway(gw.into()));
            m.attributes.push(RouteAttribute::Oif(oif));
        }
        How::Dev { oif, .. } => m.attributes.push(RouteAttribute::Oif(oif)),
        How::Unreachable => {}
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_route::route::RouteNextHop;
    use std::net::Ipv6Addr;

    fn default6(attrs: Vec<RouteAttribute>) -> RouteMessage {
        let mut m = RouteMessage::default();
        m.header.address_family = AddressFamily::Inet6;
        m.header.table = RouteHeader::RT_TABLE_MAIN;
        m.header.kind = RouteType::Unicast;
        m.attributes = attrs;
        m
    }

    fn hop(gw: &str, oif: u32, flags: RouteNextHopFlags) -> RouteNextHop {
        let mut h = RouteNextHop::default();
        h.flags = flags;
        h.interface_index = oif;
        h.attributes = vec![RouteAttribute::Gateway(RouteAddress::Inet6(
            gw.parse::<Ipv6Addr>().unwrap(),
        ))];
        h
    }

    #[test]
    fn plain_route_is_one_entry() {
        let r = default6(vec![
            RouteAttribute::Oif(3),
            RouteAttribute::Priority(100),
            RouteAttribute::Gateway(RouteAddress::Inet6("fe80::1".parse().unwrap())),
        ]);
        let s = to_sys_hops(&r);
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].oif, Some(3));
        assert_eq!(s[0].metric, 100);
        assert!(!s[0].linkdown);
    }

    #[test]
    fn multipath_splits_into_hops_and_marks_dead_ones() {
        let r = default6(vec![
            RouteAttribute::Priority(50),
            RouteAttribute::MultiPath(vec![
                hop("fe80::1", 2, RouteNextHopFlags::Linkdown),
                hop("fe80::2", 3, RouteNextHopFlags::empty()),
                hop("fe80::3", 4, RouteNextHopFlags::Dead),
            ]),
        ]);
        let s = to_sys_hops(&r);
        assert_eq!(s.len(), 3);
        assert!(s.iter().all(|h| h.metric == 50 && h.dst.is_default()));
        assert_eq!(
            s.iter().map(|h| (h.oif, h.linkdown)).collect::<Vec<_>>(),
            vec![(Some(2), true), (Some(3), false), (Some(4), true)]
        );
        assert_eq!(s[1].gateway, Some("fe80::2".parse().unwrap()));
    }

    #[test]
    fn multipath_gateway_is_the_live_hop() {
        let r = default6(vec![
            RouteAttribute::Priority(50),
            RouteAttribute::MultiPath(vec![
                hop("fe80::1", 2, RouteNextHopFlags::Linkdown),
                hop("fe80::2", 3, RouteNextHopFlags::empty()),
            ]),
        ]);
        let links = [2, 3].map(|i| Link {
            index: i,
            name: format!("eth{i}"),
            up: true,
            tunnel: false,
        });
        let g = plan::pick_gateway(&to_sys_hops(&r), &links, true, None).unwrap();
        assert_eq!(g.oif, 3);
        assert_eq!(g.via, Some("fe80::2".parse().unwrap()));
    }
}
