//! The few calls the helper makes to the router's local RPC (OxenMQ over ZMTP 3).
//!
//! Requests are `[command, tag, json]` and answers `["REPLY", tag, json]` with
//! `{"result": ...}` or `{"error": "..."}` inside.
//!
//! The router listens on `tcp://127.0.0.1:1190` and, on Linux, `ipc://rpc.sock` in its
//! data directory. The Unix socket is preferred: who may use it is decided by its file
//! permissions, while the TCP port is open to every local user.

use crate::net::Net;
use crate::zmtp;
use serde_json::{json, Value};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

/// `auto`: the router's Unix socket when it exists, else its TCP port.
pub const DEFAULT_ADDR: &str = "auto";
pub const DEFAULT_IPC: &str = "ipc:///var/lib/session-router/rpc.sock";
pub const DEFAULT_TCP: &str = "tcp://127.0.0.1:1190";

/// Turns `auto` into a concrete address; anything else is returned as is.
pub fn resolve_addr(addr: &str) -> String {
    if addr != "auto" {
        return addr.to_owned();
    }
    let ipc = DEFAULT_IPC.strip_prefix("ipc://").unwrap();
    if Path::new(ipc).exists() {
        DEFAULT_IPC.to_owned()
    } else {
        DEFAULT_TCP.to_owned()
    }
}

/// A connection over TCP or a Unix socket.
enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Stream {
    fn connect(addr: &str, timeout: Duration) -> io::Result<Stream> {
        let s = if let Some(path) = addr.strip_prefix("ipc://") {
            Stream::Unix(UnixStream::connect(path)?)
        } else {
            let a = addr.strip_prefix("tcp://").unwrap_or(addr);
            let sa: SocketAddr = a.to_socket_addrs()?.next().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("can't resolve {a}"))
            })?;
            let t = TcpStream::connect_timeout(&sa, timeout)?;
            t.set_nodelay(true)?;
            Stream::Tcp(t)
        };
        match &s {
            Stream::Tcp(t) => {
                t.set_read_timeout(Some(timeout))?;
                t.set_write_timeout(Some(timeout))?;
            }
            Stream::Unix(u) => {
                u.set_read_timeout(Some(timeout))?;
                u.set_write_timeout(Some(timeout))?;
            }
        }
        Ok(s)
    }

    fn try_clone(&self) -> io::Result<Stream> {
        Ok(match self {
            Stream::Tcp(t) => Stream::Tcp(t.try_clone()?),
            Stream::Unix(u) => Stream::Unix(u.try_clone()?),
        })
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(t) => t.read(buf),
            Stream::Unix(u) => u.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Tcp(t) => t.write(buf),
            Stream::Unix(u) => u.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Tcp(t) => t.flush(),
            Stream::Unix(u) => u.flush(),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// The router doesn't know this command (an older build).
    Unknown(String),
    Router(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(e) => write!(f, "{e}"),
            Error::Unknown(c) => write!(f, "this router doesn't know `{c}`"),
            Error::Router(m) => write!(f, "router: {m}"),
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

pub struct Client {
    reader: BufReader<Stream>,
    writer: BufWriter<Stream>,
    next: u64,
}

impl Client {
    /// Connects to `tcp://HOST:PORT` or `ipc:///path/to/rpc.sock`.
    pub fn connect(addr: &str, timeout: Duration) -> Result<Client, Error> {
        let s = Stream::connect(addr, timeout)?;
        let mut hs = s.try_clone()?;
        zmtp::handshake(&mut hs, "DEALER")?;
        Ok(Client {
            reader: BufReader::new(s.try_clone()?),
            writer: BufWriter::new(s),
            next: 1,
        })
    }

    pub fn call(&mut self, command: &str, args: &Value) -> Result<Value, Error> {
        let tag = format!("srrh-{}", self.next);
        self.next += 1;
        let body = serde_json::to_vec(args).expect("json");
        zmtp::write_message(
            &mut self.writer,
            &[command.as_bytes(), tag.as_bytes(), &body],
        )?;
        self.writer.flush()?;
        loop {
            let parts = zmtp::read_message(&mut self.reader)?;
            match parts.first().map(Vec::as_slice) {
                Some(b"REPLY") if parts.get(1).map(Vec::as_slice) == Some(tag.as_bytes()) => {
                    return decode(parts.get(2).map(Vec::as_slice).unwrap_or(b""));
                }
                Some(b"UNKNOWNCOMMAND") => return Err(Error::Unknown(command.into())),
                Some(b"FORBIDDEN") => {
                    return Err(Error::Router(format!("`{command}` needs admin access")));
                }
                _ => {}
            }
        }
    }

    /// The union of all mapped exit ranges.
    pub fn mapped_ranges(&mut self) -> Result<Vec<Net>, Error> {
        let v = self.call("llarp.list_exits", &json!({}))?;
        Ok(parse_ranges(&v))
    }

    pub fn first_hops(&mut self) -> Result<Vec<IpAddr>, Error> {
        let v = self.call("llarp.first_hops", &json!({}))?;
        Ok(v.get("first_hops")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|x| {
                        x.as_str()?
                            .trim_matches(|c| c == '[' || c == ']')
                            .parse()
                            .ok()
                    })
                    .collect()
            })
            .unwrap_or_default())
    }
}

fn decode(data: &[u8]) -> Result<Value, Error> {
    if data.is_empty() {
        return Ok(Value::Null);
    }
    let v: Value =
        serde_json::from_slice(data).map_err(|e| Error::Router(format!("bad reply: {e}")))?;
    if let Some(e) = v.get("error") {
        return Err(Error::Router(
            e.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| e.to_string()),
        ));
    }
    Ok(v.get("result").cloned().unwrap_or(v))
}

/// `list_exits` answers either a bare array of exits or `{"exits": [...], ...}`
/// depending on the router build.
pub fn parse_ranges(v: &Value) -> Vec<Net> {
    let exits = v
        .as_array()
        .or_else(|| v.get("exits").and_then(Value::as_array));
    let mut out: Vec<Net> = Vec::new();
    for e in exits.into_iter().flatten() {
        for r in e
            .get("ranges")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(n) = r
                .as_str()
                .and_then(|s| s.parse::<Net>().ok())
                .filter(|n| !out.contains(n))
            {
                out.push(n);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_list_exits_shapes() {
        let a = json!([{"address": "x.sesh", "ranges": ["0.0.0.0/0"]}, {"address": "y.sesh", "ranges": ["0.0.0.0/0", "10.9.0.0/16"]}]);
        assert_eq!(parse_ranges(&a).len(), 2);
        let b = json!({"routes_up": true, "exits": [{"address": "x.sesh", "ranges": ["203.0.113.0/24"]}]});
        assert_eq!(
            parse_ranges(&b),
            vec!["203.0.113.0/24".parse::<Net>().unwrap()]
        );
        assert!(parse_ranges(&json!([])).is_empty());
    }

    #[test]
    fn replies() {
        assert_eq!(
            decode(br#"{"result":{"first_hops":["1.2.3.4"]}}"#).unwrap()["first_hops"][0],
            "1.2.3.4"
        );
        assert!(matches!(decode(br#"{"error":"nope"}"#), Err(Error::Router(m)) if m == "nope"));
        // Some replies come back without the {"result": ...} wrapper.
        assert_eq!(decode(br#"[1]"#).unwrap(), json!([1]));
    }
}
