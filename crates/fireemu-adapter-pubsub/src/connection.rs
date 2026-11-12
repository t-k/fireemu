//! The accepted sockets of the Pub/Sub listener, with the id the REST negative cache keys on.
//!
//! The id is taken when the socket is accepted and never reused, so a later connection that gets the
//! same source port does not inherit an entry. When the socket is dropped (the connection closed) the
//! cache forgets everything it held for it.

use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use fireemu_core_pubsub::rest_negative_cache::{ConnectionId, RestNegativeCache};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tonic::transport::server::Connected;

/// What a request carries in its extensions: the connection it arrived on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AcceptedConnection(pub(crate) ConnectionId);

/// A socket that tells the negative cache when it closes.
pub(crate) struct TrackedStream {
    inner: TcpStream,
    id: ConnectionId,
    cache: Option<Arc<Mutex<RestNegativeCache>>>,
}

impl TrackedStream {
    pub(crate) const fn new(
        inner: TcpStream,
        id: ConnectionId,
        cache: Option<Arc<Mutex<RestNegativeCache>>>,
    ) -> Self {
        Self { inner, id, cache }
    }
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        if let Some(cache) = &self.cache {
            if let Ok(mut cache) = cache.lock() {
                cache.forget_connection(self.id);
            }
        }
    }
}

impl Connected for TrackedStream {
    type ConnectInfo = AcceptedConnection;

    fn connect_info(&self) -> Self::ConnectInfo {
        AcceptedConnection(self.id)
    }
}

impl AsyncRead for TrackedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
