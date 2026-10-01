//! Ending a connection after its response without turning unread request bytes into a reset.
//!
//! A server that answers from the request head alone (a refusal) and closes the connection while the
//! client is still sending its body makes the kernel answer those bytes with a reset, which can
//! discard the response the client has not read yet. [`GracefulClose`] wraps the stream a hyper
//! connection serves: when the connection finishes and hyper shuts the stream down, it announces the end
//! of the response (FIN) first and then reads and discards what the client still sends, within bounds
//! ([`DrainBounds`]): until the client closes, goes quiet, has sent more than the listener accepts, or the
//! total time is up. Nothing is ever kept.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _, ReadBuf};

/// How long a quiet client is waited for after the response.
pub const DRAIN_IDLE: Duration = Duration::from_millis(500);
/// The most time the whole drain may take, whatever the client keeps sending.
pub const DRAIN_TOTAL: Duration = Duration::from_secs(2);

/// The fewest bytes any listener reads and discards after it has answered.
pub const MIN_DRAIN_BYTES: usize = 1024 * 1024;

/// What a listener is willing to read and throw away after it has answered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DrainBounds {
    /// The most bytes read (wire bytes, framing included).
    pub limit_bytes: usize,
    /// How long the client may stay silent.
    pub idle: Duration,
    /// The most time the drain may take.
    pub total: Duration,
}

impl DrainBounds {
    /// The bounds for a listener whose largest accepted body is `largest_body` bytes: that, plus an
    /// eighth for the framing of a chunked body (about 9 bytes per chunk, so chunks of 64 bytes or
    /// more fit), so a client that sends a legitimate body is not reset; a client that frames it in
    /// smaller chunks, or sends more, can still be. A listener with a small limit still reads up to
    /// [`MIN_DRAIN_BYTES`], so that a body somewhat over its limit, which it refuses, is answered too.
    #[must_use]
    pub const fn for_largest_body(largest_body: usize) -> Self {
        let framed = largest_body.saturating_add(largest_body / 8);
        Self {
            limit_bytes: if framed < MIN_DRAIN_BYTES {
                MIN_DRAIN_BYTES
            } else {
                framed
            },
            idle: DRAIN_IDLE,
            total: DRAIN_TOTAL,
        }
    }
}

/// Announces the end of the response (FIN) on `stream`, then reads and discards what the client still
/// sends until it closes, is silent for `bounds.idle`, has sent `bounds.limit_bytes`, or `bounds.total`
/// has passed. A stream whose shutdown fails is not read.
pub async fn close_gracefully<S>(stream: &mut S, bounds: DrainBounds)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if stream.shutdown().await.is_err() {
        return;
    }
    let deadline = tokio::time::Instant::now() + bounds.total;
    let mut sink = vec![0_u8; 16 * 1024];
    let mut drained = 0_usize;
    loop {
        let until = deadline.min(tokio::time::Instant::now() + bounds.idle);
        match tokio::time::timeout_at(until, stream.read(&mut sink)).await {
            Ok(Ok(read)) if read > 0 => {
                drained += read;
                if drained >= bounds.limit_bytes {
                    return;
                }
            }
            _ => return,
        }
    }
}

type Closing = Pin<Box<dyn Future<Output = ()> + Send>>;

enum State<S> {
    Open(S, DrainBounds),
    Closing(Closing),
    Closed,
}

/// A stream that ends gracefully when it is shut down (see the module documentation): hand it to a
/// hyper connection in place of the raw stream. Reads and writes go straight through until the
/// shutdown; afterwards a read sees the end of the stream and a write fails.
pub struct GracefulClose<S> {
    state: State<S>,
}

impl<S> GracefulClose<S> {
    /// Wraps `stream`, which is ended with the drain of `bounds` when it is shut down.
    #[must_use]
    pub const fn new(stream: S, bounds: DrainBounds) -> Self {
        Self {
            state: State::Open(stream, bounds),
        }
    }
}

impl<S> Unpin for GracefulClose<S> {}

impl<S: AsyncRead + Unpin> AsyncRead for GracefulClose<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Open(stream, _) => Pin::new(stream).poll_read(cx, buf),
            State::Closing(_) | State::Closed => Poll::Ready(Ok(())),
        }
    }
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "the connection was shut down")
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send + 'static> AsyncWrite for GracefulClose<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.state {
            State::Open(stream, _) => Pin::new(stream).poll_write(cx, data),
            State::Closing(_) | State::Closed => Poll::Ready(Err(closed())),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.state {
            State::Open(stream, _) => Pin::new(stream).poll_flush(cx),
            State::Closing(_) | State::Closed => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match std::mem::replace(&mut self.state, State::Closed) {
                State::Open(mut stream, bounds) => {
                    self.state = State::Closing(Box::pin(async move {
                        close_gracefully(&mut stream, bounds).await;
                    }));
                }
                State::Closing(mut closing) => {
                    if closing.as_mut().poll(cx).is_pending() {
                        self.state = State::Closing(closing);
                        return Poll::Pending;
                    }
                    return Poll::Ready(Ok(()));
                }
                State::Closed => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        close_gracefully, DrainBounds, GracefulClose, DRAIN_IDLE, DRAIN_TOTAL, MIN_DRAIN_BYTES,
    };
    use std::io;
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
    use tokio::time::{timeout, Duration, Instant};

    // No assertion here depends on how fast the machine is. Whether the close ends, how many reads it
    // made and how many bytes it read are counted, not timed; the only timing left is a lower bound
    // (a timer never fires early) and upper bounds of a second or more, against bounds of tens of
    // milliseconds. A call that must end is wrapped in `timeout`, and a stream that is read again and
    // again counts its reads, so a loop that does not end fails the test by its name instead of
    // hanging it. (A paused clock would need tokio's `test-util` in Cargo.toml, which every Quint
    // model binds through the Cargo authority.)
    const IDLE: Duration = Duration::from_millis(50);
    const TOTAL: Duration = Duration::from_millis(1500);
    const LIMIT: usize = 64 * 1024;
    const GUARD: Duration = Duration::from_secs(10);
    const SLACK: Duration = Duration::from_secs(1);
    const MAX_READS: usize = 1_000;

    /// A stream that counts the reads and the bytes read, whether it was shut down, and whose
    /// shutdown can fail.
    struct Probe<S> {
        inner: S,
        bytes: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
        shut_down: Arc<AtomicBool>,
        fail_shutdown: bool,
    }

    struct Counters {
        bytes: Arc<AtomicUsize>,
        reads: Arc<AtomicUsize>,
        shut_down: Arc<AtomicBool>,
    }

    impl<S> Probe<S> {
        fn new(inner: S) -> (Self, Counters) {
            let counters = Counters {
                bytes: Arc::new(AtomicUsize::new(0)),
                reads: Arc::new(AtomicUsize::new(0)),
                shut_down: Arc::new(AtomicBool::new(false)),
            };
            (
                Self {
                    inner,
                    bytes: counters.bytes.clone(),
                    reads: counters.reads.clone(),
                    shut_down: counters.shut_down.clone(),
                    fail_shutdown: false,
                },
                counters,
            )
        }
    }

    impl<S: AsyncRead + Unpin> AsyncRead for Probe<S> {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            assert!(
                self.reads.fetch_add(1, Ordering::SeqCst) < MAX_READS,
                "the stream was read {MAX_READS} times: the loop does not end"
            );
            let before = buf.filled().len();
            let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
            if poll.is_ready() {
                self.bytes
                    .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
            }
            poll
        }
    }

    impl<S: AsyncWrite + Unpin> AsyncWrite for Probe<S> {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            self.shut_down.store(true, Ordering::SeqCst);
            if self.fail_shutdown {
                return Poll::Ready(Err(io::Error::other("shutdown refused")));
            }
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }

    /// Runs the close and returns how long it took; fails if it does not end.
    async fn closing<S>(stream: &mut S, limit: usize) -> Duration
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        closing_with(
            stream,
            DrainBounds {
                limit_bytes: limit,
                idle: IDLE,
                total: TOTAL,
            },
        )
        .await
    }

    async fn closing_with<S>(stream: &mut S, bounds: DrainBounds) -> Duration
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let started = Instant::now();
        timeout(GUARD, close_gracefully(stream, bounds))
            .await
            .expect("the close ends");
        started.elapsed()
    }

    #[test]
    fn the_bounds_of_a_listener_cover_its_largest_body_with_room_for_chunked_framing() {
        use std::hint::black_box;
        let bounds = DrainBounds::for_largest_body(black_box(32 * 1024 * 1024));
        assert_eq!(bounds.limit_bytes, 32 * 1024 * 1024 + 4 * 1024 * 1024);
        assert_eq!(bounds.idle, DRAIN_IDLE);
        assert_eq!(bounds.total, DRAIN_TOTAL);
        // A quiet client does not hold the connection beyond the idle time, and nobody beyond the total.
        assert!(black_box(DRAIN_IDLE) >= Duration::from_millis(100));
        assert!(black_box(DRAIN_IDLE) < black_box(DRAIN_TOTAL));
        assert!(black_box(DRAIN_TOTAL) >= Duration::from_secs(1));
        assert!(black_box(DRAIN_TOTAL) <= Duration::from_secs(5));
        // The largest body cannot overflow the limit.
        assert_eq!(
            DrainBounds::for_largest_body(usize::MAX).limit_bytes,
            usize::MAX
        );
        // A small limit is raised to the floor, and a limit just above the floor is not.
        assert_eq!(
            DrainBounds::for_largest_body(black_box(256 * 1024)).limit_bytes,
            MIN_DRAIN_BYTES
        );
        assert_eq!(
            DrainBounds::for_largest_body(black_box(0)).limit_bytes,
            MIN_DRAIN_BYTES
        );
        assert_eq!(
            DrainBounds::for_largest_body(black_box(MIN_DRAIN_BYTES)).limit_bytes,
            MIN_DRAIN_BYTES + MIN_DRAIN_BYTES / 8
        );
    }

    #[tokio::test]
    async fn the_end_of_the_response_is_announced_before_anything_is_read() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        let (mut probe, counters) = Probe::new(server);
        let task = tokio::spawn(async move { closing(&mut probe, LIMIT).await });
        // The client sees the end of the response (EOF) while it has not closed its own side.
        let mut seen = Vec::new();
        timeout(GUARD, client.read_to_end(&mut seen))
            .await
            .expect("the shutdown reaches the client")
            .expect("a clean end");
        assert!(counters.shut_down.load(Ordering::SeqCst));
        assert_eq!(
            counters.bytes.load(Ordering::SeqCst),
            0,
            "nothing was sent yet"
        );
        drop(client);
        timeout(GUARD, task)
            .await
            .expect("it ends")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_client_that_closes_ends_it_at_once_after_one_read() {
        let (server, client) = tokio::io::duplex(1024 * 1024);
        let (mut probe, counters) = Probe::new(server);
        drop(client);
        closing(&mut probe, LIMIT).await;
        assert_eq!(
            counters.reads.load(Ordering::SeqCst),
            1,
            "one read saw the end of the stream"
        );
    }

    #[tokio::test]
    async fn the_rest_of_the_body_is_read_and_discarded_until_the_client_closes() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        let (mut probe, counters) = Probe::new(server);
        let task = tokio::spawn(async move { closing(&mut probe, 1024 * 1024).await });
        client
            .write_all(&vec![7_u8; 20_000])
            .await
            .expect("the body is written");
        tokio::time::sleep(Duration::from_millis(10)).await;
        client
            .write_all(&vec![7_u8; 5_000])
            .await
            .expect("more body");
        drop(client);
        timeout(GUARD, task)
            .await
            .expect("it ends")
            .expect("no panic");
        assert_eq!(counters.bytes.load(Ordering::SeqCst), 25_000);
    }

    #[tokio::test]
    async fn it_stops_reading_at_the_byte_limit() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        let (mut probe, counters) = Probe::new(server);
        client
            .write_all(&vec![1_u8; 600 * 1024])
            .await
            .expect("a large body fits the pipe");
        closing(&mut probe, LIMIT).await;
        let drained = counters.bytes.load(Ordering::SeqCst);
        assert!(drained >= LIMIT, "{drained}");
        assert!(
            drained < LIMIT + 32 * 1024,
            "stopped soon after the limit: {drained}"
        );
    }

    #[tokio::test]
    async fn a_silent_client_is_given_the_idle_time_and_no_more() {
        let (server, _client) = tokio::io::duplex(1024);
        let (mut probe, _) = Probe::new(server);
        let elapsed = closing(&mut probe, LIMIT).await;
        assert!(elapsed >= IDLE, "{elapsed:?}");
        assert!(
            elapsed < TOTAL,
            "the idle time ends it, not the total time: {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn a_client_that_keeps_trickling_is_cut_off_at_the_total_time() {
        // The idle time is a hundred times the trickle interval, so a writer that is late (a loaded
        // machine) cannot end the drain by silence before the total time does.
        const TRICKLE: Duration = Duration::from_millis(10);
        const TRICKLE_TOTAL: Duration = Duration::from_millis(500);
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        let (mut probe, _) = Probe::new(server);
        let trickle = tokio::spawn(async move {
            while client.write_all(b"x").await.is_ok() {
                tokio::time::sleep(TRICKLE).await;
            }
        });
        let elapsed = closing_with(
            &mut probe,
            DrainBounds {
                limit_bytes: LIMIT,
                idle: TRICKLE * 100,
                total: TRICKLE_TOTAL,
            },
        )
        .await;
        assert!(elapsed >= TRICKLE_TOTAL, "{elapsed:?}");
        assert!(elapsed < TRICKLE_TOTAL + SLACK, "{elapsed:?}");
        trickle.abort();
    }

    #[tokio::test]
    async fn a_failing_shutdown_ends_it_without_reading() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        client
            .write_all(&vec![3_u8; 10_000])
            .await
            .expect("written");
        let (mut probe, counters) = Probe::new(server);
        probe.fail_shutdown = true;
        closing(&mut probe, LIMIT).await;
        assert!(counters.shut_down.load(Ordering::SeqCst));
        assert_eq!(counters.reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn a_read_error_ends_it_after_one_read() {
        /// Fails every read, and fails the test if it is read again after the first failure.
        struct Broken(Arc<AtomicUsize>);
        impl AsyncRead for Broken {
            fn poll_read(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                _: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                assert!(
                    self.0.fetch_add(1, Ordering::SeqCst) < 1,
                    "the stream was read again after its read failed"
                );
                Poll::Ready(Err(io::Error::other("reset")))
            }
        }
        impl AsyncWrite for Broken {
            fn poll_write(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                Poll::Ready(Ok(data.len()))
            }
            fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
            fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
                Poll::Ready(Ok(()))
            }
        }
        let reads = Arc::new(AtomicUsize::new(0));
        closing(&mut Broken(reads.clone()), LIMIT).await;
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    // ---- the wrapper hyper serves ----

    fn bounds(limit: usize) -> DrainBounds {
        DrainBounds {
            limit_bytes: limit,
            idle: IDLE,
            total: TOTAL,
        }
    }

    #[tokio::test]
    async fn the_wrapper_passes_reads_and_writes_through_until_the_shutdown() {
        let (server, mut client) = tokio::io::duplex(1024);
        let mut wrapped = GracefulClose::new(server, bounds(LIMIT));
        client.write_all(b"request").await.expect("written");
        let mut seen = [0_u8; 7];
        wrapped.read_exact(&mut seen).await.expect("read through");
        assert_eq!(&seen, b"request");
        wrapped.write_all(b"response").await.expect("write through");
        wrapped.flush().await.expect("flush through");
        let mut answer = [0_u8; 8];
        client
            .read_exact(&mut answer)
            .await
            .expect("the client reads");
        assert_eq!(&answer, b"response");
    }

    #[tokio::test]
    async fn the_shutdown_of_the_wrapper_announces_the_end_then_discards_the_rest_of_the_body() {
        let (server, mut client) = tokio::io::duplex(1024 * 1024);
        let mut wrapped = GracefulClose::new(server, bounds(1024 * 1024));
        wrapped.write_all(b"refused").await.expect("response");
        let closing = tokio::spawn(async move {
            wrapped.shutdown().await.expect("a graceful shutdown");
        });
        // The client sees the whole response and then the end, while it is still sending.
        let mut answer = Vec::new();
        timeout(GUARD, client.read_to_end(&mut answer))
            .await
            .expect("the end reaches the client")
            .expect("clean");
        assert_eq!(answer, b"refused");
        // What it sends after that is accepted (no reset) until it closes.
        client
            .write_all(&vec![9_u8; 50_000])
            .await
            .expect("late body written");
        drop(client);
        timeout(GUARD, closing)
            .await
            .expect("the shutdown ends")
            .expect("no panic");
    }

    #[tokio::test]
    async fn a_wrapper_shut_down_twice_ends_both_times_and_refuses_further_io() {
        let (server, client) = tokio::io::duplex(1024);
        drop(client);
        let mut wrapped = GracefulClose::new(server, bounds(LIMIT));
        timeout(GUARD, wrapped.shutdown())
            .await
            .expect("ends")
            .expect("first");
        timeout(GUARD, wrapped.shutdown())
            .await
            .expect("ends")
            .expect("second");
        assert_eq!(
            wrapped
                .write_all(b"x")
                .await
                .expect_err("no write after shutdown")
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        let mut byte = [0_u8; 1];
        assert_eq!(
            timeout(GUARD, wrapped.read(&mut byte))
                .await
                .expect("a read after the shutdown ends at once")
                .expect("a read sees the end"),
            0
        );
        wrapped
            .flush()
            .await
            .expect("a flush after shutdown is harmless");
    }

    // ---- properties ----

    use proptest::prelude::*;

    proptest! {
        /// The bounds of a listener always cover its largest body with the framing margin, never
        /// fall below the floor, never exceed what the margin and the floor say, and grow with the
        /// body.
        #[test]
        fn the_limit_covers_the_body_with_its_margin_and_never_the_floor_less(
            largest in 0_usize..=usize::MAX,
            more in 0_usize..1_000_000,
        ) {
            let bounds = DrainBounds::for_largest_body(largest);
            prop_assert!(bounds.limit_bytes >= MIN_DRAIN_BYTES);
            prop_assert!(bounds.limit_bytes >= largest);
            prop_assert!(bounds.limit_bytes >= largest.saturating_add(largest / 8).min(usize::MAX));
            let ceiling = largest.saturating_add(largest / 8).max(MIN_DRAIN_BYTES);
            prop_assert_eq!(bounds.limit_bytes, ceiling);
            prop_assert!(
                DrainBounds::for_largest_body(largest.saturating_add(more)).limit_bytes
                    >= bounds.limit_bytes
            );
            prop_assert_eq!(bounds.idle, DRAIN_IDLE);
            prop_assert_eq!(bounds.total, DRAIN_TOTAL);
        }

        /// Model of the drain: a client that sends `total` bytes and closes has all of them read
        /// when they fit the limit, and otherwise is read up to the limit and not much past it (one
        /// read of 16 KiB); the connection is always shut down first and the drain always ends.
        #[test]
        fn the_drain_reads_the_whole_body_within_the_limit_and_stops_at_the_limit_otherwise(
            total in 0_usize..400_000,
            limit in 1_usize..400_000,
        ) {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("a runtime");
            runtime.block_on(async {
                let (server, mut client) = tokio::io::duplex(1024 * 1024);
                client.write_all(&vec![7_u8; total]).await.expect("written");
                drop(client);
                let (mut probe, counters) = Probe::new(server);
                closing(&mut probe, limit).await;
                let read = counters.bytes.load(Ordering::SeqCst);
                prop_assert!(counters.shut_down.load(Ordering::SeqCst));
                if total < limit {
                    prop_assert_eq!(read, total);
                } else {
                    prop_assert!(read >= limit, "read {read} of a limit of {limit}");
                    prop_assert!(read < limit + 16 * 1024, "read {read} of a limit of {limit}");
                    prop_assert!(read <= total);
                }
                Ok(())
            })?;
        }
    }
}
