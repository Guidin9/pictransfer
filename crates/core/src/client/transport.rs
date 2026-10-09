//! TCP (+ TLS for `https`) connections with byte counting.
//!
//! The rustls config and root store are built per connection and dropped
//! with it, so nothing stays resident while the agent is idle (spike B).

use std::{
    io,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll},
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::client::TlsStream;

use super::{ClientError, Counters, ServerUrl};

/// Counts bytes crossing the TCP socket.
pub(crate) struct Counting {
    inner: TcpStream,
    counters: Arc<Counters>,
}

impl AsyncRead for Counting {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let r = Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = buf.filled().len().saturating_sub(before);
        self.counters
            .bytes_in
            .fetch_add(n as u64, Ordering::Relaxed);
        r
    }
}

impl AsyncWrite for Counting {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let r = Pin::new(&mut self.inner).poll_write(cx, data);
        if let Poll::Ready(Ok(n)) = &r {
            self.counters
                .bytes_out
                .fetch_add(*n as u64, Ordering::Relaxed);
        }
        r
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A plain or TLS connection.
pub(crate) enum Stream {
    Plain(Counting),
    Tls(Box<TlsStream<Counting>>),
}

impl AsyncRead for Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_read(cx, buf),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_write(cx, data),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_write(cx, data),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_flush(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            Stream::Plain(s) => Pin::new(s).poll_shutdown(cx),
            Stream::Tls(s) => Pin::new(s.as_mut()).poll_shutdown(cx),
        }
    }
}

/// Opens a connection to the server (no timeout here; callers wrap it).
pub(crate) async fn connect(
    url: &ServerUrl,
    counters: &Arc<Counters>,
) -> Result<Stream, ClientError> {
    let tcp = TcpStream::connect((url.host.as_str(), url.port))
        .await
        .map_err(|_| ClientError::Connect)?;
    tcp.set_nodelay(true).map_err(|_| ClientError::Connect)?;
    let counting = Counting {
        inner: tcp,
        counters: counters.clone(),
    };
    if !url.tls {
        return Ok(Stream::Plain(counting));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| ClientError::Tls)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    let name =
        rustls::pki_types::ServerName::try_from(url.host.clone()).map_err(|_| ClientError::Tls)?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, counting)
        .await
        .map_err(|_| ClientError::Tls)?;
    Ok(Stream::Tls(Box::new(tls)))
}
