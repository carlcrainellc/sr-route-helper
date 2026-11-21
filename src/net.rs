//! IP prefixes and the address classes the helper treats specially.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IPv4 or IPv6 prefix such as `10.0.0.0/8` or `::/1`. Host bits are always zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Net {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl Net {
    pub fn new(addr: IpAddr, prefix: u8) -> Net {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.min(max);
        let addr = match addr {
            IpAddr::V4(a) => {
                let m = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                IpAddr::V4(Ipv4Addr::from(u32::from(a) & m))
            }
            IpAddr::V6(a) => {
                let m = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                IpAddr::V6(Ipv6Addr::from(u128::from(a) & m))
            }
        };
        Net { addr, prefix }
    }

    pub fn host(addr: IpAddr) -> Net {
        Net::new(addr, if addr.is_ipv4() { 32 } else { 128 })
    }

    pub fn v4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> Net {
        Net::new(IpAddr::V4(Ipv4Addr::new(a, b, c, d)), prefix)
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }

    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                Net::new(ip, self.prefix).addr == self.addr
            }
            _ => false,
        }
    }
}

impl fmt::Display for Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Net, String> {
        let s = s.trim();
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = a.parse().map_err(|_| format!("not an IP range: {s:?}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match p {
            Some(p) => p
                .parse::<u8>()
                .ok()
                .filter(|&p| p <= max)
                .ok_or_else(|| format!("bad prefix length in {s:?}"))?,
            None => max,
        };
        Ok(Net::new(addr, prefix))
    }
}

impl Serialize for Net {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Net {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Net, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Private IPv4 ranges that normally live on the local network or behind the home
/// router: they stay off the tunnel unless asked otherwise.
pub fn lan_v4() -> [Net; 4] {
    [
        Net::v4(10, 0, 0, 0, 8),
        Net::v4(172, 16, 0, 0, 12),
        Net::v4(192, 168, 0, 0, 16),
        Net::v4(100, 64, 0, 0, 10),
    ]
}

/// Link-local and multicast IPv4: these only make sense on the physical link.
pub fn link_only_v4() -> [Net; 2] {
    [Net::v4(169, 254, 0, 0, 16), Net::v4(224, 0, 0, 0, 4)]
}

/// Addresses that can never be a relay's public address, so pinning them is pointless
/// (and pinning a LAN address via the gateway would be wrong).
pub fn never_a_relay(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || lan_v4().iter().any(|n| n.contains(ip))
        }
        IpAddr::V6(a) => {
            a.is_unspecified()
                || a.is_loopback()
                || a.is_multicast()
                || (a.segments()[0] & 0xffc0) == 0xfe80
                || (a.segments()[0] & 0xfe00) == 0xfc00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_normalises_host_bits() {
        let n: Net = "10.1.2.3/8".parse().unwrap();
        assert_eq!(n.to_string(), "10.0.0.0/8");
        let n: Net = "2001:db8::1/32".parse().unwrap();
        assert_eq!(n.to_string(), "2001:db8::/32");
        assert_eq!("1.2.3.4".parse::<Net>().unwrap().prefix, 32);
        assert!("1.2.3.4/33".parse::<Net>().is_err());
        assert!("nope".parse::<Net>().is_err());
    }

    #[test]
    fn contains_respects_family() {
        let n: Net = "0.0.0.0/1".parse().unwrap();
        assert!(n.contains("9.9.9.9".parse().unwrap()));
        assert!(!n.contains("203.0.113.7".parse().unwrap()));
        assert!(!n.contains("::1".parse().unwrap()));
    }

    #[test]
    fn relay_candidates() {
        for ip in [
            "10.3.0.1",
            "192.168.1.5",
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.251",
            "fe80::1",
            "fd00::5",
        ] {
            assert!(never_a_relay(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["9.9.9.9", "2a01:4f9::1"] {
            assert!(!never_a_relay(ip.parse().unwrap()), "{ip}");
        }
    }
}
