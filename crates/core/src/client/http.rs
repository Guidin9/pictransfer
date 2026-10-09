//! A tiny HTTP/1.1 client: one request per connection (`Connection: close`),
//! `Content-Length` request bodies, `Content-Length` or close-delimited
//! response bodies, a response size cap and a timeout. Chunked responses are
//! rejected (the Worker always sends sized JSON bodies).

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ClientError, Counters, Inner, REQUEST_TIMEOUT, transport};

/// Maximum response head (status line + headers).
pub const MAX_HEAD: usize = 8 * 1024;
const MAX_HEADERS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHead {
    pub status: u16,
    /// Header names lowercased; values trimmed. Order preserved.
    pub headers: Vec<(String, String)>,
}

impl ResponseHead {
    /// The single value of a header; `Err` if it appears more than once.
    pub fn header(&self, name: &str) -> Result<Option<&str>, ClientError> {
        let mut found = None;
        for (k, v) in &self.headers {
            if k == name {
                if found.is_some() {
                    return Err(ClientError::Protocol);
                }
                found = Some(v.as_str());
            }
        }
        Ok(found)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// How the response body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyLen {
    Empty,
    Fixed(usize),
    UntilClose,
}

/// Serializes a request. Header names/values come from this module's callers
/// only (fixed names; values are validated: auth header, token, host).
pub fn build_request(
    method: &str,
    target: &str,
    host: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Vec<u8> {
    let mut s = format!("{method} {target} HTTP/1.1\r\nHost: {host}\r\n");
    for (k, v) in headers {
        s.push_str(k);
        s.push_str(": ");
        s.push_str(v);
        s.push_str("\r\n");
    }
    if let Some(b) = body {
        s.push_str("Content-Type: application/json\r\n");
        s.push_str(&format!("Content-Length: {}\r\n", b.len()));
    }
    s.push_str("\r\n");
    let mut out = s.into_bytes();
    if let Some(b) = body {
        out.extend_from_slice(b);
    }
    out
}

fn find_head_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .and_then(|i| i.checked_add(4))
}

fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// Parses a complete response head. Returns `Ok(None)` until `\r\n\r\n` has
/// arrived, and the head length (including the blank line) when it has.
pub fn parse_head(buf: &[u8]) -> Result<Option<(ResponseHead, usize)>, ClientError> {
    let Some(end) = find_head_end(buf) else {
        return if buf.len() >= MAX_HEAD {
            Err(ClientError::ResponseTooLarge)
        } else {
            Ok(None)
        };
    };
    if end > MAX_HEAD {
        return Err(ClientError::ResponseTooLarge);
    }
    let text = std::str::from_utf8(
        buf.get(..end.saturating_sub(4))
            .ok_or(ClientError::Protocol)?,
    )
    .map_err(|_| ClientError::Protocol)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(ClientError::Protocol)?;
    let rest = status_line
        .strip_prefix("HTTP/1.1 ")
        .ok_or(ClientError::Protocol)?;
    let code = rest.get(..3).ok_or(ClientError::Protocol)?;
    let after = rest.get(3..).ok_or(ClientError::Protocol)?;
    if !code.bytes().all(|c| c.is_ascii_digit()) || !(after.is_empty() || after.starts_with(' ')) {
        return Err(ClientError::Protocol);
    }
    let status: u16 = code.parse().map_err(|_| ClientError::Protocol)?;
    if !(100..=599).contains(&status) {
        return Err(ClientError::Protocol);
    }
    let mut headers = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(ClientError::Protocol);
        }
        let (k, v) = line.split_once(':').ok_or(ClientError::Protocol)?;
        // No whitespace before the colon, no obs-fold continuation lines.
        if !is_token(k) || v.contains(['\r', '\n']) {
            return Err(ClientError::Protocol);
        }
        headers.push((
            k.to_ascii_lowercase(),
            v.trim_matches([' ', '\t']).to_string(),
        ));
    }
    Ok(Some((ResponseHead { status, headers }, end)))
}

/// Body delimitation (RFC 9112 §6.3) for a response to a non-HEAD request.
pub fn body_len(head: &ResponseHead) -> Result<BodyLen, ClientError> {
    if head.status < 200 || head.status == 204 || head.status == 304 {
        return Ok(BodyLen::Empty);
    }
    if head.header("transfer-encoding")?.is_some() {
        return Err(ClientError::Protocol);
    }
    match head.header("content-length")? {
        Some(v) => {
            if v.is_empty() || v.len() > 12 || !v.bytes().all(|c| c.is_ascii_digit()) {
                return Err(ClientError::Protocol);
            }
            v.parse::<usize>()
                .map(BodyLen::Fixed)
                .map_err(|_| ClientError::Protocol)
        }
        None => Ok(BodyLen::UntilClose),
    }
}

/// Reads a response head. Returns it, its length, and any bytes read past it.
pub(crate) async fn read_head<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
) -> Result<(ResponseHead, usize, Vec<u8>), ClientError> {
    let mut buf: Vec<u8> = Vec::with_capacity(1024);
    let mut tmp = [0u8; 1024];
    loop {
        if let Some((head, len)) = parse_head(&buf)? {
            let rest = buf.split_off(len);
            return Ok((head, len, rest));
        }
        let n = s.read(&mut tmp).await.map_err(|_| ClientError::Io)?;
        if n == 0 {
            return Err(ClientError::Io);
        }
        buf.extend_from_slice(tmp.get(..n).ok_or(ClientError::Io)?);
    }
}

/// Reads the body that follows `head` (`body` holds bytes already read past
/// the head), keeping `head_len + body` within `cap`.
pub(crate) async fn read_body<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    head: &ResponseHead,
    head_len: usize,
    mut body: Vec<u8>,
    cap: usize,
) -> Result<Vec<u8>, ClientError> {
    let mut tmp = [0u8; 4096];
    match body_len(head)? {
        BodyLen::Empty => body.clear(),
        BodyLen::Fixed(n) => {
            if head_len.saturating_add(n) > cap {
                return Err(ClientError::ResponseTooLarge);
            }
            if body.len() > n {
                // Extra bytes after the body on a `Connection: close` exchange.
                return Err(ClientError::Protocol);
            }
            body.reserve_exact(n.saturating_sub(body.len()));
            while body.len() < n {
                let want = n.saturating_sub(body.len()).min(tmp.len());
                let chunk = tmp.get_mut(..want).ok_or(ClientError::Io)?;
                let k = s.read(chunk).await.map_err(|_| ClientError::Io)?;
                if k == 0 {
                    return Err(ClientError::Io);
                }
                body.extend_from_slice(chunk.get(..k).ok_or(ClientError::Io)?);
            }
        }
        BodyLen::UntilClose => loop {
            if head_len.saturating_add(body.len()) > cap {
                return Err(ClientError::ResponseTooLarge);
            }
            let k = s.read(&mut tmp).await.map_err(|_| ClientError::Io)?;
            if k == 0 {
                break;
            }
            body.extend_from_slice(tmp.get(..k).ok_or(ClientError::Io)?);
        },
    }
    if head_len.saturating_add(body.len()) > cap {
        return Err(ClientError::ResponseTooLarge);
    }
    Ok(body)
}

/// Reads one response from `s` with a total size cap.
pub(crate) async fn read_response<S: tokio::io::AsyncRead + Unpin>(
    s: &mut S,
    cap: usize,
) -> Result<Response, ClientError> {
    let (head, head_len, rest) = read_head(s).await?;
    let body = read_body(s, &head, head_len, rest, cap).await?;
    Ok(Response {
        status: head.status,
        body,
    })
}

/// Sends one signed request and reads the response, within [`REQUEST_TIMEOUT`].
/// `target` is the exact path and query that is sent and signed (§6.1).
pub(crate) async fn signed_request(
    inner: &Inner,
    method: &str,
    target: &str,
    body: Option<&[u8]>,
    extra: &[(&str, &str)],
    cap: usize,
) -> Result<Response, ClientError> {
    let auth = inner.sign(method, target, body.unwrap_or(&[]));
    let mut headers: Vec<(&str, &str)> = vec![("Authorization", auth.as_str())];
    headers.extend_from_slice(extra);
    headers.push(("Connection", "close"));
    let req = build_request(method, target, &inner.url.host_header(), &headers, body);
    Counters::inc(&inner.counters.http_requests);
    tokio::time::timeout(REQUEST_TIMEOUT, async {
        let mut s = transport::connect(&inner.url, &inner.counters).await?;
        s.write_all(&req).await.map_err(|_| ClientError::Io)?;
        s.flush().await.map_err(|_| ClientError::Io)?;
        read_response(&mut s, cap).await
    })
    .await
    .map_err(|_| ClientError::Timeout)?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
    }

    fn read(raw: &[u8], cap: usize) -> Result<Response, ClientError> {
        let mut s = raw;
        rt().block_on(read_response(&mut s, cap))
    }

    #[test]
    fn request_serialization() {
        let r = build_request(
            "POST",
            "/v1/groups/abc/log",
            "h.example",
            &[("Authorization", "WARP1 x")],
            Some(b"{}"),
        );
        assert_eq!(
            r,
            b"POST /v1/groups/abc/log HTTP/1.1\r\nHost: h.example\r\nAuthorization: WARP1 x\r\n\
              Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
        );
        let r = build_request("GET", "/x?after=1", "h", &[], None);
        assert_eq!(r, b"GET /x?after=1 HTTP/1.1\r\nHost: h\r\n\r\n");
    }

    #[test]
    fn parses_responses() {
        let r = read(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nX: y\r\n\r\n{}",
            1024,
        )
        .unwrap();
        assert_eq!((r.status, r.body.as_slice()), (200, &b"{}"[..]));
        let r = read(b"HTTP/1.1 204 No Content\r\n\r\n", 1024).unwrap();
        assert_eq!((r.status, r.body.len()), (204, 0));
        let r = read(b"HTTP/1.1 500 Internal\r\n\r\nabc", 1024).unwrap();
        assert_eq!(r.body, b"abc");
        let r = read(b"HTTP/1.1 403\r\ncontent-length:0\r\n\r\n", 1024).unwrap();
        assert_eq!(r.status, 403);
    }

    #[test]
    fn rejects_bad_responses() {
        for raw in [
            &b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n"[..],
            b"HTTP/1.1 20 OK\r\n\r\n",
            b"HTTP/1.1 2000 OK\r\n\r\n",
            b"HTTP/1.1 099 x\r\n\r\n",
            b"HTTP/1.1 200OK\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nBad Header: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nNoColon\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n folded\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n{}",
        ] {
            assert!(
                read(raw, 1 << 20).is_err(),
                "{:?}",
                String::from_utf8_lossy(raw)
            );
        }
        // Truncated: EOF before the head or the body is complete.
        assert_eq!(read(b"HTTP/1.1 200 OK\r\n", 1024), Err(ClientError::Io));
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n{}", 1024),
            Err(ClientError::Io)
        );
        // Invalid UTF-8 in the head.
        assert_eq!(
            read(b"HTTP/1.1 200 OK\r\nX: \xff\r\n\r\n", 1024),
            Err(ClientError::Protocol)
        );
    }

    #[test]
    fn size_caps() {
        let big = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", 2000);
        assert_eq!(
            read(big.as_bytes(), 1024),
            Err(ClientError::ResponseTooLarge)
        );
        let mut close = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        close.extend(std::iter::repeat_n(b'a', 5000));
        assert_eq!(read(&close, 1024), Err(ClientError::ResponseTooLarge));
        let mut head = b"HTTP/1.1 200 OK\r\n".to_vec();
        head.extend(std::iter::repeat_n(b'a', MAX_HEAD + 10));
        assert_eq!(read(&head, 1 << 20), Err(ClientError::ResponseTooLarge));
        let mut many = b"HTTP/1.1 200 OK\r\n".to_vec();
        for _ in 0..=MAX_HEADERS {
            many.extend_from_slice(b"a: b\r\n");
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(read(&many, 1 << 20), Err(ClientError::Protocol));
    }
}
