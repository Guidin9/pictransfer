//! Minimal RFC 6455 client (text frames, ping/pong, close) over tokio-rustls,
//! with the keepalive from protocol §6.3. Throwaway spike code.

use std::{
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
    time::Duration,
};

use ring::rand::SecureRandom;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::{Instant, sleep, sleep_until},
};

use crate::STATS;

/// Counts TLS-level bytes (what crosses the TCP socket, minus TCP/IP headers).
struct Counting<T>(T);

impl<T: AsyncRead + Unpin> AsyncRead for Counting<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.0).poll_read(cx, buf);
        STATS.bytes_in.fetch_add((buf.filled().len() - before) as u64, Ordering::Relaxed);
        r
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Counting<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.0).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            STATS.bytes_out.fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

fn err(msg: &str) -> io::Error {
    io::Error::other(msg.to_string())
}

/// Runs forever: connect, keep alive, reconnect with backoff (1, 2, 4 … 300 s, ±20 %).
pub async fn run(url: String, keepalive: Duration, on_connected: impl Fn()) {
    let mut backoff = 1u64;
    loop {
        STATS.connects.fetch_add(1, Ordering::Relaxed);
        if session(&url, keepalive, &on_connected).await.is_ok() {
            backoff = 1;
        }
        STATS.disconnects.fetch_add(1, Ordering::Relaxed);
        let mut r = [0u8; 1];
        let _ = ring::rand::SystemRandom::new().fill(&mut r);
        let jitter = 0.8 + 0.4 * (r[0] as f64 / 255.0);
        sleep(Duration::from_secs_f64(backoff as f64 * jitter)).await;
        backoff = (backoff * 2).min(300);
    }
}

async fn session(url: &str, keepalive: Duration, on_connected: &impl Fn()) -> io::Result<()> {
    let rest = url.strip_prefix("wss://").ok_or_else(|| err("wss only"))?;
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));

    let tcp = TcpStream::connect((host, 443)).await?;
    tcp.set_nodelay(true)?;
    // Built per session and dropped with it: no root store stays resident while disconnected.
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .map_err(|_| err("tls versions"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name = rustls::pki_types::ServerName::try_from(host.to_string()).map_err(|_| err("server name"))?;
    let mut s = tokio_rustls::TlsConnector::from(Arc::new(cfg)).connect(name, Counting(tcp)).await?;

    let mut key = [0u8; 16];
    ring::rand::SystemRandom::new().fill(&mut key).map_err(|_| err("rng"))?;
    let key = b64(&key);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;

    let mut buf = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    let head_end = loop {
        let n = s.read(&mut tmp).await?;
        if n == 0 {
            return Err(err("eof in handshake"));
        }
        buf.extend_from_slice(&tmp[..n]);
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > 8192 {
            return Err(err("handshake too large"));
        }
    };
    let head = String::from_utf8_lossy(&buf[..head_end]).to_ascii_lowercase();
    let expect = b64(
        ring::digest::digest(
            &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
        )
        .as_ref(),
    )
    .to_ascii_lowercase();
    if !head.starts_with("http/1.1 101") || !head.contains(&format!("sec-websocket-accept: {expect}")) {
        return Err(err("bad upgrade response"));
    }
    buf.drain(..head_end);
    buf.shrink_to(1024);
    on_connected();

    let mut next_ping = Instant::now() + keepalive;
    let mut awaiting = false;
    let mut missed = 0u32;
    loop {
        tokio::select! {
            _ = sleep_until(next_ping) => {
                if awaiting {
                    missed += 1;
                    STATS.missed.fetch_add(1, Ordering::Relaxed);
                    if missed >= 2 {
                        return Err(err("two missed pongs"));
                    }
                }
                s.write_all(&frame(0x1, b"p")).await?;
                STATS.pings.fetch_add(1, Ordering::Relaxed);
                awaiting = true;
                next_ping += keepalive;
            }
            n = s.read(&mut tmp) => {
                let n = n?;
                if n == 0 {
                    return Err(err("eof"));
                }
                buf.extend_from_slice(&tmp[..n]);
                while let Some((op, payload, used)) = parse(&buf)? {
                    match op {
                        0x1 if payload == b"o" => {
                            awaiting = false;
                            missed = 0;
                            STATS.pongs.fetch_add(1, Ordering::Relaxed);
                        }
                        0x9 => s.write_all(&frame(0xA, &payload)).await?,
                        0x8 => return Ok(()),
                        _ => {}
                    }
                    buf.drain(..used);
                }
            }
        }
    }
}

/// Client frame: FIN, opcode, masked payload (< 126 bytes is all we send).
fn frame(op: u8, payload: &[u8]) -> Vec<u8> {
    let mut mask = [0u8; 4];
    let _ = ring::rand::SystemRandom::new().fill(&mut mask);
    let mut f = vec![0x80 | op, 0x80 | payload.len() as u8];
    f.extend_from_slice(&mask);
    f.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    f
}

/// Server frame (unmasked). Returns (opcode, payload, bytes used) once complete.
fn parse(b: &[u8]) -> io::Result<Option<(u8, Vec<u8>, usize)>> {
    if b.len() < 2 {
        return Ok(None);
    }
    if b[1] & 0x80 != 0 {
        return Err(err("masked server frame"));
    }
    let (len, hdr) = match b[1] & 0x7f {
        126 if b.len() >= 4 => (u16::from_be_bytes([b[2], b[3]]) as usize, 4),
        126 => return Ok(None),
        127 => return Err(err("frame too large")),
        n => (n as usize, 2),
    };
    if len > 64 * 1024 {
        return Err(err("frame too large"));
    }
    if b.len() < hdr + len {
        return Ok(None);
    }
    Ok(Some((b[0] & 0x0f, b[hdr..hdr + len].to_vec(), hdr + len)))
}

fn b64(data: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64_rfc4648() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn parse_rejects_masked_and_huge() {
        assert!(parse(&[0x81, 0x81, 0, 0, 0, 0, 0]).is_err());
        assert!(parse(&[0x81, 127]).is_err());
        assert!(parse(&[0x81, 2, b'o']).unwrap().is_none());
        assert_eq!(parse(&[0x81, 1, b'o']).unwrap(), Some((1, b"o".to_vec(), 3)));
    }
}
