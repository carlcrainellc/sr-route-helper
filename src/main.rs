//! sr-route-helper: routes and DNS for Session Router exits on Linux, with crash-safe undo.
//!
//! Run it next to a router that has `[network] auto-routing=false`. See README.md.

mod dns;
mod journal;
mod linux;
mod net;
mod plan;
mod rpc;
mod zmtp;

use journal::Journal;
use linux::Netlink;
use plan::{Gateway, Inputs, Options, Role, Want};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use std::{io, process};

static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

const USAGE: &str = "\
usage: sr-route-helper <run|restore|plan> [options]

  run       keep routes and DNS in line with the router's exit mappings until stopped
            (SIGTERM/SIGINT/SIGHUP put everything back, then exit)
  restore   undo whatever an earlier run left behind, then exit
  plan      print what `run` would set up right now, change nothing

options:
  --rpc ADDR            router RPC: ipc:///path/rpc.sock or tcp://127.0.0.1:1190
                        (default auto: /var/lib/session-router/rpc.sock if it exists)
  --tun NAME            router tunnel interface (default sr-tun0)
  --journal PATH        change journal (default /var/lib/sr-route-helper/journal.json)
  --interval SECS       check interval while nothing is mapped (default 3)
  --active-interval S   check interval while an exit is mapped (default 0.5); for a few
                        seconds after relays or the gateway change it is 0.25
  --fail-after N        the router has to miss N checks in a row to count as gone (default 3)
  --fail-open           when the router or its tunnel goes away, take routes and DNS down
                        instead of holding exit traffic blocked (the default)
  --dns-mode MODE       auto | resolved | resolv-conf | off (default auto)
  --dns IP              router DNS listener for resolv.conf (default 127.3.2.1)
  --resolved-dns ADDR   DNS server to give systemd-resolved, e.g. 127.0.0.1:953 (default:
                        the router's own 127.0.0.1 listener, found by process name)
  --router-comm NAME    the router's process name, for that lookup (default session-router)
  --resolv-conf PATH    default /etc/resolv.conf
  --exit-dns IP         exit-side resolver to send into the tunnel (repeatable)
  --pin IP              extra address to keep out of the tunnel (repeatable)
  --tunnel-lan          send private/LAN IPv4 space into a full tunnel too
  --allow-ipv6          don't block IPv6 while only IPv4 goes through the exit
";

#[derive(Debug, Clone)]
struct Cfg {
    rpc: String,
    tun: String,
    journal: PathBuf,
    interval: Duration,
    active_interval: Duration,
    fail_after: u32,
    dns_mode: dns::Mode,
    dns: String,
    resolved_dns: Option<String>,
    router_comm: String,
    resolv_conf: PathBuf,
    exit_dns: Vec<IpAddr>,
    pins: Vec<IpAddr>,
    opts: Options,
}

/// Interval for a few seconds after something changed, so a newly dialed relay is
/// pinned quickly.
const BURST_INTERVAL: Duration = Duration::from_millis(250);
const BURST_FOR: Duration = Duration::from_secs(5);

fn secs(v: String, min: f64) -> Result<Duration, String> {
    Ok(Duration::from_secs_f64(
        v.parse::<f64>().map_err(|e| e.to_string())?.max(min),
    ))
}

fn parse_args(args: &[String]) -> Result<(String, Cfg), String> {
    let mut cmd = None;
    let mut c = Cfg {
        rpc: rpc::DEFAULT_ADDR.into(),
        tun: "sr-tun0".into(),
        journal: "/var/lib/sr-route-helper/journal.json".into(),
        interval: Duration::from_secs(3),
        active_interval: Duration::from_millis(500),
        fail_after: 3,
        dns_mode: dns::Mode::Auto,
        dns: "127.3.2.1".into(),
        resolved_dns: None,
        router_comm: "session-router".into(),
        resolv_conf: "/etc/resolv.conf".into(),
        exit_dns: vec![],
        pins: vec![],
        opts: Options::default(),
    };
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let mut val = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{a} needs a value"))
        };
        let ip = |s: String| {
            s.parse::<IpAddr>()
                .map_err(|_| format!("not an IP address: {s}"))
        };
        match a.as_str() {
            "--rpc" => c.rpc = val()?,
            "--tun" => c.tun = val()?,
            "--journal" => c.journal = val()?.into(),
            "--interval" => c.interval = secs(val()?, 0.5)?,
            "--active-interval" => c.active_interval = secs(val()?, 0.1)?,
            "--fail-after" => {
                c.fail_after = val()?.parse::<u32>().map_err(|e| e.to_string())?.max(1)
            }
            "--fail-open" => c.opts.fail_closed = false,
            "--dns-mode" => c.dns_mode = val()?.parse()?,
            "--dns" => c.dns = ip(val()?)?.to_string(),
            "--resolved-dns" => {
                let v = val()?;
                let ok = v.parse::<IpAddr>().is_ok() || v.parse::<std::net::SocketAddr>().is_ok();
                if !ok {
                    return Err(format!("not an address or address:port: {v}"));
                }
                c.resolved_dns = Some(v)
            }
            "--router-comm" => c.router_comm = val()?,
            "--resolv-conf" => c.resolv_conf = val()?.into(),
            "--exit-dns" => c.exit_dns.push(ip(val()?)?),
            "--pin" => c.pins.push(ip(val()?)?),
            "--tunnel-lan" => c.opts.keep_lan = false,
            "--allow-ipv6" => c.opts.block_ipv6 = false,
            "-h" | "--help" => return Err(String::new()),
            s if !s.starts_with('-') && cmd.is_none() => cmd = Some(s.to_owned()),
            s => return Err(format!("unknown option {s}")),
        }
    }
    let cmd = cmd.ok_or_else(String::new)?;
    if !matches!(cmd.as_str(), "run" | "restore" | "plan") {
        return Err(format!("unknown command {cmd}"));
    }
    Ok((cmd, c))
}

macro_rules! say {
    ($($t:tt)*) => { eprintln!("sr-route-helper: {}", format!($($t)*)) };
}

struct Helper {
    cfg: Cfg,
    nl: Netlink,
    journal: Journal,
    rpc: Option<rpc::Client>,
    failures: u32,
    no_first_hops: bool,
    gw4: Option<Gateway>,
    gw6: Option<Gateway>,
    last_notes: plan::Notes,
    last_hops: Vec<IpAddr>,
    dns_mode: dns::Mode,
    /// Failing closed: the router or its tunnel is gone and exit traffic is held.
    held: bool,
    /// Said that we're failing open, so it isn't repeated every check.
    opened: bool,
    burst_until: Option<Instant>,
}

/// What one look at the router and the system found.
struct Snapshot {
    inputs: Inputs,
    /// The router or its tunnel is gone.
    gone: Option<String>,
}

impl Helper {
    fn new(cfg: Cfg) -> io::Result<Helper> {
        let dns_mode = if cfg.dns_mode == dns::Mode::Auto {
            let (m, who) = dns::detect(&cfg.resolv_conf);
            if let Some(who) = who {
                say!(
                    "{} is managed by {who}; if it rewrites the file while an exit is mapped, \
                     the helper points it back at the router",
                    cfg.resolv_conf.display()
                );
            }
            m
        } else {
            cfg.dns_mode
        };
        Ok(Helper {
            nl: Netlink::open()?,
            journal: Journal::default(),
            rpc: None,
            failures: 0,
            no_first_hops: false,
            gw4: None,
            gw6: None,
            last_notes: plan::Notes::default(),
            last_hops: vec![],
            dns_mode,
            held: false,
            opened: false,
            burst_until: None,
            cfg,
        })
    }

    fn save(&self) {
        if let Err(e) = self.journal.save(&self.cfg.journal) {
            say!("could not write {}: {e}", self.cfg.journal.display());
        }
    }

    fn burst(&mut self) {
        self.burst_until = Some(Instant::now() + BURST_FOR);
    }

    /// How long to wait before the next check.
    fn next_interval(&self) -> Duration {
        if self.burst_until.is_some_and(|t| Instant::now() < t) {
            BURST_INTERVAL.min(self.cfg.active_interval)
        } else if !self.journal.is_empty() {
            self.cfg.active_interval
        } else {
            self.cfg.interval
        }
    }

    /// Undo everything in the journal, then sweep any route still carrying our protocol
    /// number (covers a lost or damaged journal).
    fn restore(&mut self) -> io::Result<()> {
        let loaded = Journal::load(&self.cfg.journal);
        let j = match loaded {
            Ok(j) => j,
            Err(e) => {
                say!("journal unreadable ({e}); sweeping by route protocol instead");
                Journal::default()
            }
        };
        self.journal = j;
        if let Some(d) = self.journal.dns.clone() {
            match dns::undo(&d) {
                Ok(()) => say!("DNS put back"),
                Err(e) => say!("could not put DNS back: {e}"),
            }
            self.journal.dns = None;
            self.save();
        }
        let mut routes = std::mem::take(&mut self.journal.routes);
        routes.sort_by_key(|w| std::cmp::Reverse(w.role));
        let mut n = 0;
        for w in &routes {
            match self.nl.delete(w) {
                Ok(true) => n += 1,
                Ok(false) => {}
                Err(e) => say!("could not remove {w}: {e}"),
            }
        }
        let swept = self.nl.sweep()?;
        self.journal = Journal::default();
        self.save();
        if n + swept > 0 {
            say!("removed {n} journaled route(s), {swept} more by protocol");
        }
        Ok(())
    }

    /// Start of `run`: carry on from the journal a previous run left (so a held, failed
    /// closed state survives a crash or restart of the helper), and remove any route of
    /// ours the journal doesn't list.
    fn resume(&mut self) -> io::Result<()> {
        match Journal::load(&self.cfg.journal) {
            Ok(j) => self.journal = j,
            Err(e) => {
                say!("journal unreadable ({e}); sweeping by route protocol instead");
                self.journal = Journal::default();
            }
        }
        let stale = self.nl.sweep_except(&self.journal.routes)?;
        if stale > 0 {
            say!("removed {stale} leftover route(s) the journal didn't list");
        }
        if !self.journal.is_empty() {
            say!(
                "picking up {} route(s){} from the last run",
                self.journal.routes.len(),
                if self.journal.dns.is_some() {
                    " and DNS"
                } else {
                    ""
                }
            );
        }
        Ok(())
    }

    fn rpc(&mut self) -> Result<&mut rpc::Client, rpc::Error> {
        if self.rpc.is_none() {
            let addr = rpc::resolve_addr(&self.cfg.rpc);
            self.rpc = Some(rpc::Client::connect(&addr, Duration::from_secs(2))?);
        }
        Ok(self.rpc.as_mut().unwrap())
    }

    fn snapshot(&mut self) -> io::Result<Snapshot> {
        let links = self.nl.links()?;
        let routes = self.nl.routes()?;
        let tun = links
            .iter()
            .find(|l| l.name == self.cfg.tun)
            .map(|l| l.index);
        let gw4 = plan::pick_gateway(&routes, &links, false, tun);
        let gw6 = plan::pick_gateway(&routes, &links, true, tun);
        self.note_gateway(false, &gw4);
        self.note_gateway(true, &gw6);

        // Somebody else (the router's own poker) holding tunnel routes means two managers.
        let theirs = |t: u32| {
            routes
                .iter()
                .any(|r| !r.ours && r.oif == Some(t) && plan::halves(false).contains(&r.dst))
        };
        if tun.is_some_and(theirs) {
            say!(
                "the router is installing its own exit routes too: set [network] auto-routing=false"
            );
        }

        let mut inputs = Inputs {
            mapped: vec![],
            first_hops: self.cfg.pins.clone(),
            exit_dns: self.cfg.exit_dns.clone(),
            tun,
            gw4,
            gw6,
            opts: self.cfg.opts.clone(),
        };
        if tun.is_none() {
            return Ok(Snapshot {
                inputs,
                gone: Some(format!("tunnel interface {} is not there", self.cfg.tun)),
            });
        }
        let mapped = self.rpc().and_then(|c| c.mapped_ranges());
        let mapped = match mapped {
            Ok(m) => m,
            Err(e) => {
                self.rpc = None;
                return Ok(Snapshot {
                    inputs,
                    gone: Some(format!("router RPC: {e}")),
                });
            }
        };
        inputs.mapped = mapped;
        if !inputs.mapped.is_empty() && !self.no_first_hops {
            match self.rpc().and_then(|c| c.first_hops()) {
                Ok(h) => inputs.first_hops.extend(h),
                Err(rpc::Error::Unknown(_)) => {
                    self.no_first_hops = true;
                    say!(
                        "this router can't list its first hops (no llarp.first_hops); only --pin addresses are kept out of the tunnel"
                    );
                }
                Err(e) => {
                    self.rpc = None;
                    return Ok(Snapshot {
                        inputs,
                        gone: Some(format!("router RPC: {e}")),
                    });
                }
            }
        }
        Ok(Snapshot { inputs, gone: None })
    }

    fn note_gateway(&mut self, v6: bool, now: &Option<Gateway>) {
        let last = if v6 { &mut self.gw6 } else { &mut self.gw4 };
        if last != now {
            let fam = if v6 { "IPv6" } else { "IPv4" };
            match (&*last, now) {
                (_, Some(g)) => say!("{fam} gateway is {g}"),
                (Some(g), None) => say!("{fam} gateway {g} has gone away"),
                _ => {}
            }
            *last = now.clone();
            self.burst_until = Some(Instant::now() + BURST_FOR);
        }
    }

    fn note_plan(&mut self, notes: plan::Notes) {
        if notes.held != self.last_notes.held {
            for f in &notes.held {
                if !self.last_notes.held.contains(f) {
                    say!(
                        "no usable {f} uplink to keep the router's own traffic out of the tunnel; \
                         {f} exit traffic is held{}",
                        if self.cfg.opts.fail_closed {
                            " (blocked)"
                        } else {
                            ""
                        }
                    );
                }
            }
            for f in &self.last_notes.held {
                if !notes.held.contains(f) {
                    say!("{f} uplink is back; {f} goes through the exit again");
                }
            }
        }
        if notes.unpinned != self.last_notes.unpinned && !notes.unpinned.is_empty() {
            say!(
                "no IPv6 uplink to pin {:?} to; they stay blocked",
                notes.unpinned
            );
        }
        self.last_notes = notes;
    }

    /// One check: work out what should be there and make it so.
    fn tick(&mut self) -> io::Result<()> {
        let snap = self.snapshot()?;
        let Some(why) = &snap.gone else {
            if self.held {
                say!("the router is back");
            }
            self.held = false;
            self.opened = false;
            self.failures = 0;
            let mut hops = snap.inputs.first_hops.clone();
            hops.sort();
            hops.dedup();
            if hops != self.last_hops {
                self.last_hops = hops;
                self.burst();
            }
            let (want, notes) = plan::plan(&snap.inputs);
            // Held for want of an uplink and failing closed: DNS stays on the router too.
            let held4 = self.cfg.opts.fail_closed && notes.held.contains(&"IPv4");
            self.note_plan(notes);
            self.sync_routes(&want)?;
            let full = plan::is_full_v4(&snap.inputs.mapped)
                && (held4 || want.iter().any(|w| w.role == Role::Tunnel && w.dst.is_v4()));
            self.sync_dns(full, snap.inputs.tun.unwrap_or(0));
            return Ok(());
        };
        self.failures += 1;
        let tun_gone = snap.inputs.tun.is_none();
        if !tun_gone && self.failures < self.cfg.fail_after {
            say!(
                "{why} (check {} of {}), leaving routes as they are",
                self.failures,
                self.cfg.fail_after
            );
            return Ok(());
        }
        if self.journal.is_empty() {
            return Ok(());
        }
        if !self.cfg.opts.fail_closed {
            if !self.opened {
                say!("{why}: taking routes and DNS down (--fail-open)");
                self.opened = true;
            }
            self.sync_routes(&[])?;
            self.sync_dns(false, 0);
            return Ok(());
        }
        if !self.held {
            say!(
                "{why}: holding exit traffic blocked until the router is back \
                 (stop the helper or run `sr-route-helper restore` to give up)"
            );
            self.held = true;
        }
        let want = plan::hold(&self.journal.routes);
        self.sync_routes(&want)?;
        self.hold_dns(tun_gone);
        Ok(())
    }

    fn sync_routes(&mut self, want: &[Want]) -> io::Result<()> {
        // Forget journaled routes the kernel already dropped (their interface went away),
        // so they get put back if still wanted.
        let present: Vec<(net::Net, u32)> = self
            .nl
            .routes()?
            .into_iter()
            .filter(|r| r.ours)
            .map(|r| (r.dst, r.metric))
            .collect();
        let before = self.journal.routes.len();
        self.journal
            .routes
            .retain(|w| present.contains(&(w.dst, w.metric)));
        if self.journal.routes.len() != before {
            self.save();
        }

        let mut gone: Vec<Want> = self
            .journal
            .routes
            .iter()
            .filter(|w| !want.contains(w))
            .cloned()
            .collect();
        gone.sort_by_key(|w| std::cmp::Reverse(w.role));
        for w in gone {
            match self.nl.delete(&w) {
                Ok(true) => say!("removed {w}"),
                Ok(false) => say!("{w} was already gone"),
                Err(e) => {
                    say!("could not remove {w}: {e}");
                    continue;
                }
            }
            self.journal.routes.retain(|x| x != &w);
            self.save();
        }
        let mut new: Vec<Want> = want
            .iter()
            .filter(|w| !self.journal.routes.contains(w))
            .cloned()
            .collect();
        new.sort_by_key(|a| a.role);
        for w in new {
            // Written down first: if we die right after the add, restore still finds it.
            self.journal.routes.push(w.clone());
            self.save();
            let mut r = self.nl.add(&w);
            if let Ok(linux::Added::OursAlready) = r {
                // A leftover of ours the journal lost track of: replace it.
                say!("{w}: replacing a leftover route of ours");
                r = self.nl.delete(&w).and_then(|_| self.nl.add(&w));
            }
            match r {
                Ok(linux::Added::Yes) => {
                    say!("added {w}");
                    continue;
                }
                Ok(linux::Added::Theirs) => say!(
                    "{w}: another program's route has this prefix and metric; leaving it \
                     (traffic follows theirs)"
                ),
                Ok(linux::Added::OursAlready) => say!("{w}: could not replace our leftover"),
                Err(e) => say!("could not add {w}: {e}"),
            }
            self.journal.routes.retain(|x| x != &w);
            self.save();
        }
        Ok(())
    }

    fn dns_target(&self, tun_index: u32) -> dns::Target<'_> {
        dns::Target {
            mode: self.dns_mode,
            resolv_conf: &self.cfg.resolv_conf,
            tun_name: &self.cfg.tun,
            tun_index,
            dns: &self.cfg.dns,
            resolved_dns: self.cfg.resolved_dns.as_deref(),
            router_comm: &self.cfg.router_comm,
        }
    }

    /// Points DNS at the router (or back), journaling first.
    fn set_dns(&mut self, tun_index: u32) {
        let (c, warn) = match dns::prepare(&self.dns_target(tun_index)) {
            Ok((Some(c), w)) => (c, w),
            Ok((None, _)) => return,
            Err(e) => return say!("can't read current DNS settings: {e}"),
        };
        if let Some(w) = warn {
            say!("{w}");
        }
        self.journal.dns = Some(c.clone());
        self.save();
        match dns::apply(&c) {
            Ok(()) => say!("DNS now goes through the router ({:?})", self.dns_mode),
            Err(e) => {
                say!("could not change DNS: {e}");
                let _ = dns::undo(&c);
                self.journal.dns = None;
                self.save();
            }
        }
    }

    fn sync_dns(&mut self, want: bool, tun_index: u32) {
        let want = want && self.dns_mode != dns::Mode::Off;
        match (self.journal.dns.clone(), want) {
            (None, true) => self.set_dns(tun_index),
            (Some(mut c), true) => match &mut c {
                journal::DnsChange::ResolvConf { .. } => match dns::reassert(&mut c) {
                    Ok(true) => {
                        say!("resolv.conf was rewritten by something else; pointing it at the router again");
                        self.journal.dns = Some(c);
                        self.save();
                    }
                    Ok(false) => {}
                    Err(e) => say!("could not rewrite resolv.conf: {e}"),
                },
                journal::DnsChange::Resolved { ifindex, muted, .. } => {
                    if !muted.is_empty() || *ifindex != tun_index {
                        // Back from a hold, or a new tunnel link (the router restarted):
                        // give the uplinks their DNS back and set up the new link.
                        let _ = dns::undo(&c);
                        self.journal.dns = None;
                        self.save();
                        self.set_dns(tun_index);
                    }
                }
            },
            (Some(c), false) => {
                match dns::undo(&c) {
                    Ok(()) => say!("DNS put back"),
                    Err(e) => say!("could not put DNS back: {e}"),
                }
                self.journal.dns = None;
                self.save();
            }
            (None, false) => {}
        }
    }

    /// Failing closed: DNS stays pointed at the (absent) router, so lookups fail instead of
    /// going to the uplink's resolver. resolved forgets a tunnel link's settings when the
    /// link goes away, so then the uplinks' DNS default route is turned off until we're
    /// back or restored.
    fn hold_dns(&mut self, tun_gone: bool) {
        let Some(mut c) = self.journal.dns.clone() else {
            return;
        };
        match &mut c {
            journal::DnsChange::ResolvConf { .. } => {
                if let Ok(true) = dns::reassert(&mut c) {
                    say!(
                        "resolv.conf was rewritten while holding; pointing it at the router again"
                    );
                    self.journal.dns = Some(c);
                    self.save();
                }
            }
            journal::DnsChange::Resolved { link, muted, .. } if tun_gone => {
                let more: Vec<String> = dns::links_to_mute(link)
                    .into_iter()
                    .filter(|l| !muted.contains(l))
                    .collect();
                if more.is_empty() {
                    return;
                }
                muted.extend(more.iter().cloned());
                self.journal.dns = Some(c);
                self.save();
                for l in more {
                    match dns::mute(&l) {
                        Ok(()) => say!("resolved: no DNS via {l} while holding"),
                        Err(e) => say!("could not turn off DNS via {l}: {e}"),
                    }
                }
            }
            _ => {}
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (cmd, cfg) = match parse_args(&args) {
        Ok(x) => x,
        Err(e) => {
            if !e.is_empty() {
                eprintln!("sr-route-helper: {e}\n");
            }
            eprint!("{USAGE}");
            process::exit(2);
        }
    };
    let mut h = match Helper::new(cfg) {
        Ok(h) => h,
        Err(e) => {
            say!("can't open netlink: {e}");
            process::exit(1);
        }
    };
    match cmd.as_str() {
        "plan" => {
            let snap = match h.snapshot() {
                Ok(s) => s,
                Err(e) => {
                    say!("{e}");
                    process::exit(1)
                }
            };
            if let Some(why) = &snap.gone {
                println!("nothing to do: {why}");
            }
            println!(
                "mapped: {:?}",
                snap.inputs
                    .mapped
                    .iter()
                    .map(|n| n.to_string())
                    .collect::<Vec<_>>()
            );
            println!(
                "gateway v4: {:?}\ngateway v6: {:?}\nDNS mode: {:?}",
                snap.inputs.gw4, snap.inputs.gw6, h.dns_mode
            );
            let (want, notes) = plan::plan(&snap.inputs);
            for w in &want {
                println!("  {w}");
            }
            if !notes.unpinned.is_empty() {
                println!("unpinned (no gateway): {:?}", notes.unpinned);
            }
            if !notes.held.is_empty() {
                println!("held (no usable uplink): {:?}", notes.held);
            }
        }
        "restore" => {
            if let Err(e) = h.restore() {
                say!("{e}");
                process::exit(1);
            }
        }
        _ => run(h),
    }
}

fn run(mut h: Helper) {
    unsafe {
        for s in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::signal(s, on_signal as *const () as libc::sighandler_t);
        }
    }
    if let Err(e) = h.resume() {
        say!("can't read the routing table: {e}");
        process::exit(1);
    }
    say!(
        "running (RPC {}, tunnel {}, DNS {:?}, {})",
        rpc::resolve_addr(&h.cfg.rpc),
        h.cfg.tun,
        h.dns_mode,
        if h.cfg.opts.fail_closed {
            "fails closed"
        } else {
            "fails open"
        }
    );
    while !STOP.load(Ordering::SeqCst) {
        let t = Instant::now();
        if let Err(e) = h.tick() {
            say!("check failed: {e}");
        }
        let wait = h.next_interval();
        while !STOP.load(Ordering::SeqCst) && t.elapsed() < wait {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    say!("stopping; putting routes and DNS back");
    if let Err(e) = h.restore() {
        say!("restore failed: {e}");
        process::exit(1);
    }
}
