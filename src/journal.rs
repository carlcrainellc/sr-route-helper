//! A small file listing every change the helper has made and not yet undone.
//!
//! Each change is written down *before* it is made, so after a crash or power cut the
//! next start (or `sr-route-helper restore`) knows exactly what to take back. Undoing a
//! change that never happened is harmless: deleting a missing route is not an error.

use crate::plan::Want;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum DnsChange {
    /// `resolv.conf` was overwritten; `original` is what was there before and `ours` is
    /// what we wrote, so a file somebody else rewrote since is left alone.
    ResolvConf {
        path: String,
        original: String,
        ours: String,
    },
    /// systemd-resolved was told to send every lookup to the router on the tunnel link.
    Resolved {
        link: String,
        /// Which instance of the tunnel link the settings went on; a new one (the router
        /// restarted) needs them again.
        #[serde(default)]
        ifindex: u32,
        /// The DNS server given to resolved for the tunnel link.
        #[serde(default)]
        server: String,
        #[serde(default)]
        prev_dns: Vec<String>,
        prev_domains: Vec<String>,
        prev_default_route: Option<bool>,
        /// Links whose DNS default route we turned off while holding (fail closed with the
        /// tunnel gone); they get it back on undo.
        #[serde(default)]
        muted: Vec<String>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    #[serde(default)]
    pub routes: Vec<Want>,
    #[serde(default)]
    pub dns: Option<DnsChange>,
}

impl Journal {
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty() && self.dns.is_none()
    }

    /// A missing file is an empty journal. A damaged one is reported, not ignored, so the
    /// caller can still fall back to sweeping routes by protocol number.
    pub fn load(path: &Path) -> io::Result<Journal> {
        match fs::read(path) {
            Ok(b) if b.iter().all(|c| c.is_ascii_whitespace()) => Ok(Journal::default()),
            Ok(b) => serde_json::from_slice(&b).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {e}", path.display()),
                )
            }),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(Journal::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes to a temporary file, syncs it, then renames it over the old one, so the file
    /// on disk is always either the old or the new journal, never half of one.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        if self.is_empty() {
            return match fs::remove_file(path) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            };
        }
        let dir = path
            .parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(dir)?;
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(&serde_json::to_vec_pretty(self).expect("journal serialises"))?;
            f.sync_all()?;
        }
        fs::rename(&tmp, path)?;
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plan::{How, Role};

    #[test]
    fn round_trip_and_empty_removes_file() {
        let dir = std::env::temp_dir().join(format!("srrh-journal-{}", std::process::id()));
        let path = dir.join("j.json");
        assert!(Journal::load(&path).unwrap().is_empty());
        let j = Journal {
            routes: vec![Want {
                dst: "0.0.0.0/1".parse().unwrap(),
                how: How::Dev {
                    oif: 7,
                    link_scope: false,
                },
                role: Role::Tunnel,
                metric: 5,
            }],
            dns: Some(DnsChange::ResolvConf {
                path: "/etc/resolv.conf".into(),
                original: "nameserver 192.168.1.1\n".into(),
                ours: "nameserver 127.3.2.1\n".into(),
            }),
        };
        j.save(&path).unwrap();
        assert_eq!(Journal::load(&path).unwrap(), j);
        Journal::default().save(&path).unwrap();
        assert!(!path.exists());
        fs::write(&path, b"{not json").unwrap();
        assert!(Journal::load(&path).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    /// A journal written before the resolved fields were added still loads, so an upgrade
    /// can undo what the old version did.
    #[test]
    fn old_resolved_entry_still_loads() {
        let dir = std::env::temp_dir().join(format!("srrh-journal-old-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("j.json");
        fs::write(
            &path,
            r#"{"routes": [], "dns": {"kind": "resolved", "link": "sr-tun0", "prev_domains": [], "prev_default_route": false}}"#,
        )
        .unwrap();
        let j = Journal::load(&path).unwrap();
        match j.dns {
            Some(DnsChange::Resolved {
                link,
                ifindex,
                server,
                muted,
                ..
            }) => assert_eq!(
                (link.as_str(), ifindex, server.as_str(), muted.len()),
                ("sr-tun0", 0, "", 0)
            ),
            other => panic!("{other:?}"),
        }
        let _ = fs::remove_dir_all(dir);
    }
}
