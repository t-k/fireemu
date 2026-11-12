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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[tokio::test]
    async fn the_tracked_stream_passes_reads_writes_and_the_shutdown_through() {
        let (mut client, server) = pair().await;
        let mut tracked = TrackedStream::new(server, ConnectionId::new(7), None);
        assert!(tracked.is_write_vectored());
        // `write_all` goes through `poll_write`, `read_exact` through `poll_read`.
        tracked.write_all(b"hello").await.unwrap();
        tracked.flush().await.unwrap();
        let mut buffer = [0_u8; 5];
        client.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"hello");
        client.write_all(b"world").await.unwrap();
        tracked.read_exact(&mut buffer).await.unwrap();
        assert_eq!(&buffer, b"world");
        // A vectored write reaches the peer whole.
        let written = tracked
            .write_vectored(&[std::io::IoSlice::new(b"ab"), std::io::IoSlice::new(b"cd")])
            .await
            .unwrap();
        assert_eq!(written, 4);
        let mut four = [0_u8; 4];
        client.read_exact(&mut four).await.unwrap();
        assert_eq!(&four, b"abcd");
        // The shutdown reaches the peer: it reads the end of the stream.
        tracked.shutdown().await.unwrap();
        assert_eq!(client.read(&mut buffer).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn the_connection_id_is_what_the_request_will_carry_and_a_drop_forgets_the_connection() {
        let (_client, server) = pair().await;
        let cache = Arc::new(Mutex::new(RestNegativeCache::default()));
        let id = ConnectionId::new(9);
        let tracked = TrackedStream::new(server, id, Some(cache.clone()));
        assert_eq!(tracked.connect_info().0, id);
        let resource = fireemu_core_pubsub::rest_negative_cache::RestResource::parse_path(
            "/v1/projects/p/subscriptions/s",
        )
        .unwrap();
        let now = fireemu_core_types::time::LogicalInstant::UNIX_EPOCH;
        cache.lock().unwrap().observe(
            id,
            &resource,
            fireemu_core_pubsub::rest_negative_cache::RestRequest::Get,
            now,
            fireemu_core_pubsub::rest_negative_cache::RestOutcome::NotFound,
        );
        assert_eq!(cache.lock().unwrap().len(), 1);
        drop(tracked);
        assert_eq!(cache.lock().unwrap().len(), 0);
    }
}
