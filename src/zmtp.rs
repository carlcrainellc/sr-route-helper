//! Just enough ZMTP 3.0 to act as a DEALER with the NULL mechanism, over any byte stream
//! (TCP or a Unix socket).
//!
//! Session Router's RPC listens with OxenMQ on `tcp://127.0.0.1:1190` and `ipc://rpc.sock`
//! (plain, no CURVE). The helper only reads (`list_exits`, `first_hops`). Writing the wire
//! format by hand keeps libzmq out of the picture.

use std::io::{self, Read, Write};

pub const SIGNATURE_HEAD: u8 = 0xFF;
pub const SIGNATURE_TAIL: u8 = 0x7F;

const FLAG_MORE: u8 = 0x01;
const FLAG_LONG: u8 = 0x02;
const FLAG_COMMAND: u8 = 0x04;

/// Largest frame we accept from the router. Replies are small JSON documents.
pub const MAX_FRAME: u64 = 16 * 1024 * 1024;

/// The 64-byte greeting for ZMTP 3.0 with the NULL mechanism.
pub fn greeting(as_server: bool) -> [u8; 64] {
    let mut g = [0u8; 64];
    g[0] = SIGNATURE_HEAD;
    g[9] = SIGNATURE_TAIL;
    g[10] = 3; // major
    g[11] = 0; // minor
    g[12..16].copy_from_slice(b"NULL");
    g[32] = as_server as u8;
    g
}

/// Checks a peer greeting: signature, version 3.x and the NULL mechanism.
pub fn check_greeting(g: &[u8; 64]) -> io::Result<()> {
    if g[0] != SIGNATURE_HEAD || g[9] != SIGNATURE_TAIL {
        return Err(bad("peer did not send a ZMTP signature"));
    }
    if g[10] < 3 {
        return Err(bad(&format!(
            "peer speaks ZMTP {}.{}, need 3.x",
            g[10], g[11]
        )));
    }
    let mech = &g[12..32];
    let end = mech.iter().position(|&b| b == 0).unwrap_or(mech.len());
    if &mech[..end] != b"NULL" {
        return Err(bad(&format!(
            "peer wants security mechanism {:?}, only NULL is supported",
            String::from_utf8_lossy(&mech[..end])
        )));
    }
    Ok(())
}

/// Body of a READY command carrying the given properties.
pub fn ready_body(props: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = Vec::new();
    b.push(5);
    b.extend_from_slice(b"READY");
    for (name, value) in props {
        b.push(name.len() as u8);
        b.extend_from_slice(name.as_bytes());
        b.extend_from_slice(&(value.len() as u32).to_be_bytes());
        b.extend_from_slice(value);
    }
    b
}

/// Parses a command body into its name and properties (properties only for READY).
pub type Properties = Vec<(String, Vec<u8>)>;

pub fn parse_command(body: &[u8]) -> io::Result<(String, Properties)> {
    let n = *body.first().ok_or_else(|| bad("empty command"))? as usize;
    let name = body
        .get(1..1 + n)
        .ok_or_else(|| bad("short command name"))?;
    let name = String::from_utf8_lossy(name).into_owned();
    let mut props = Vec::new();
    if name == "READY" {
        let mut rest = &body[1 + n..];
        while !rest.is_empty() {
            let kl = rest[0] as usize;
            let key = rest
                .get(1..1 + kl)
                .ok_or_else(|| bad("short property name"))?;
            let lenb = rest
                .get(1 + kl..5 + kl)
                .ok_or_else(|| bad("short property length"))?;
            let vl = u32::from_be_bytes(lenb.try_into().unwrap()) as usize;
            let val = rest
                .get(5 + kl..5 + kl + vl)
                .ok_or_else(|| bad("short property value"))?;
            props.push((String::from_utf8_lossy(key).into_owned(), val.to_vec()));
            rest = &rest[5 + kl + vl..];
        }
    }
    Ok((name, props))
}

pub fn write_frame<W: Write>(w: &mut W, body: &[u8], more: bool, command: bool) -> io::Result<()> {
    let mut flags = 0u8;
    if more {
        flags |= FLAG_MORE;
    }
    if command {
        flags |= FLAG_COMMAND;
    }
    if body.len() > 255 {
        w.write_all(&[flags | FLAG_LONG])?;
        w.write_all(&(body.len() as u64).to_be_bytes())?;
    } else {
        w.write_all(&[flags, body.len() as u8])?;
    }
    w.write_all(body)
}

pub fn write_message<W: Write>(w: &mut W, parts: &[&[u8]]) -> io::Result<()> {
    for (i, p) in parts.iter().enumerate() {
        write_frame(w, p, i + 1 < parts.len(), false)?;
    }
    w.flush()
}

pub struct Frame {
    pub body: Vec<u8>,
    pub more: bool,
    pub command: bool,
}

pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Frame> {
    let mut f = [0u8; 1];
    r.read_exact(&mut f)?;
    let flags = f[0];
    if flags & !(FLAG_MORE | FLAG_LONG | FLAG_COMMAND) != 0 {
        return Err(bad("reserved frame flag bits set"));
    }
    let len = if flags & FLAG_LONG != 0 {
        let mut l = [0u8; 8];
        r.read_exact(&mut l)?;
        u64::from_be_bytes(l)
    } else {
        let mut l = [0u8; 1];
        r.read_exact(&mut l)?;
        l[0] as u64
    };
    if len > MAX_FRAME {
        return Err(bad(&format!("frame of {len} bytes is over the limit")));
    }
    let mut body = vec![0u8; len as usize];
    r.read_exact(&mut body)?;
    Ok(Frame {
        body,
        more: flags & FLAG_MORE != 0,
        command: flags & FLAG_COMMAND != 0,
    })
}

/// Reads one multipart message, skipping any commands (PING etc.) in between.
pub fn read_message<R: Read>(r: &mut R) -> io::Result<Vec<Vec<u8>>> {
    let mut parts = Vec::new();
    loop {
        let f = read_frame(r)?;
        if f.command {
            continue;
        }
        parts.push(f.body);
        if !f.more {
            return Ok(parts);
        }
    }
}

/// Client side of the handshake: greeting both ways, then READY both ways.
pub fn handshake<S: Read + Write>(s: &mut S, socket_type: &str) -> io::Result<()> {
    s.write_all(&greeting(false))?;
    s.flush()?;
    let mut g = [0u8; 64];
    s.read_exact(&mut g)?;
    check_greeting(&g)?;
    write_frame(
        s,
        &ready_body(&[("Socket-Type", socket_type.as_bytes())]),
        false,
        true,
    )?;
    s.flush()?;
    let f = read_frame(s)?;
    if !f.command {
        return Err(bad("expected READY from peer"));
    }
    let (name, props) = parse_command(&f.body)?;
    if name == "ERROR" {
        return Err(bad("peer refused the connection"));
    }
    if name != "READY" {
        return Err(bad(&format!("expected READY from peer, got {name}")));
    }
    let peer_type = props
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("Socket-Type"))
        .map(|(_, v)| String::from_utf8_lossy(v).into_owned());
    match peer_type.as_deref() {
        Some("ROUTER") | Some("DEALER") => Ok(()),
        other => Err(bad(&format!(
            "peer socket type {other:?} can't talk to a DEALER"
        ))),
    }
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_frames_round_trip() {
        for size in [0usize, 1, 255, 256, 70_000] {
            let body = vec![7u8; size];
            let mut buf = Vec::new();
            write_frame(&mut buf, &body, true, false).unwrap();
            let f = read_frame(&mut buf.as_slice()).unwrap();
            assert_eq!(f.body, body);
            assert!(f.more);
            assert!(!f.command);
            let expected_header = if size > 255 { 9 } else { 2 };
            assert_eq!(buf.len(), expected_header + size);
        }
    }

    #[test]
    fn ready_round_trip() {
        let body = ready_body(&[("Socket-Type", b"DEALER"), ("Identity", b"")]);
        let (name, props) = parse_command(&body).unwrap();
        assert_eq!(name, "READY");
        assert_eq!(props[0], ("Socket-Type".to_string(), b"DEALER".to_vec()));
        assert_eq!(props[1], ("Identity".to_string(), Vec::new()));
    }

    #[test]
    fn greeting_checks() {
        assert!(check_greeting(&greeting(true)).is_ok());
        let mut g = greeting(true);
        g[12..17].copy_from_slice(b"CURVE");
        assert!(check_greeting(&g).is_err());
        let mut g = greeting(true);
        g[10] = 2;
        assert!(check_greeting(&g).is_err());
        let mut g = greeting(true);
        g[0] = 0;
        assert!(check_greeting(&g).is_err());
    }

    #[test]
    fn oversized_frame_is_refused() {
        let mut buf = vec![FLAG_LONG];
        buf.extend_from_slice(&(MAX_FRAME + 1).to_be_bytes());
        assert!(read_frame(&mut buf.as_slice()).is_err());
    }

    #[test]
    fn commands_are_skipped_inside_messages() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"\x04PING", false, true).unwrap();
        write_frame(&mut buf, b"a", true, false).unwrap();
        write_frame(&mut buf, b"b", false, false).unwrap();
        let parts = read_message(&mut buf.as_slice()).unwrap();
        assert_eq!(parts, vec![b"a".to_vec(), b"b".to_vec()]);
    }
}
