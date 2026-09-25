//! The RFC 6455 server: a dedicated tokio accept loop on the logging port. No hyper upgrade is
//! needed; the handshake is a handful of headers and the frames are small.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast::error::RecvError;

use crate::bus::LogBus;
use crate::wire::{
    close_frame, encode_frame, encode_text_frame, handshake_response, parse_handshake, unmask,
    ClientFrame, HandshakeError,
};

/// The largest handshake request head accepted, in bytes. A well-formed handshake is a few
/// hundred bytes; anything larger is refused rather than buffered.
const MAX_HANDSHAKE_BYTES: usize = 8 * 1024;

/// How long a peer may take to send its complete handshake head.
const HANDSHAKE_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// The bounds a connection's handshake must stay inside. Both exist so one peer cannot hold a
/// task and a file descriptor open for free; neither is reachable by a well-formed client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeLimits {
    /// How long the peer may take to send the complete request head.
    pub read_timeout: Duration,
    /// The largest request head accepted, in bytes.
    pub max_head_bytes: usize,
}

impl Default for HandshakeLimits {
    fn default() -> Self {
        Self {
            read_timeout: HANDSHAKE_READ_TIMEOUT,
            max_head_bytes: MAX_HANDSHAKE_BYTES,
        }
    }
}

/// The largest client frame payload accepted, in bytes. Clients send only tiny control frames;
/// a larger frame closes the connection rather than allocating for it.
const MAX_CLIENT_PAYLOAD: usize = 1 << 20;

/// Serves the Logging emulator on `listener` until the task is dropped. Each accepted connection
/// is handled on its own task; a failing connection never affects the others or the daemon.
pub async fn serve_logging(listener: TcpListener, bus: LogBus) {
    serve_logging_with_limits(listener, bus, HandshakeLimits::default()).await;
}

/// [`serve_logging`] with explicit handshake bounds. Tests use it to exercise the deadline and
/// the header-size cap without waiting for the production values.
pub async fn serve_logging_with_limits(
    listener: TcpListener,
    bus: LogBus,
    limits: HandshakeLimits,
) {
    loop {
        // A transient accept error must not tear the whole emulator down.
        let Ok((stream, _peer)) = listener.accept().await else {
            continue;
        };
        let bus = bus.clone();
        tokio::spawn(async move {
            let _ = handle_connection(stream, bus, limits).await;
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    bus: LogBus,
    limits: HandshakeLimits,
) -> io::Result<()> {
    // Disable Nagle so a single small log frame reaches the client immediately.
    let _ = stream.set_nodelay(true);
    let mut reader = BufReader::new(stream);

    // The head must arrive whole, inside the deadline and inside the size cap. A peer that
    // stalls or floods is answered once and dropped, so it cannot hold this task and its file
    // descriptor open. Nothing of the log stream is written on any of these paths.
    let head = match tokio::time::timeout(
        limits.read_timeout,
        read_handshake_head(&mut reader, limits.max_head_bytes),
    )
    .await
    {
        Ok(outcome) => match outcome? {
            HeadOutcome::Head(head) => head,
            // The peer closed first: there is nobody left to answer.
            HeadOutcome::Closed => return Ok(()),
            HeadOutcome::TooLarge => return refuse(&mut reader, &HandshakeError::TooLarge).await,
        },
        Err(_elapsed) => return refuse(&mut reader, &HandshakeError::Timeout).await,
    };
    let handshake = match parse_handshake(&head) {
        Ok(h) => h,
        Err(e) => return refuse(&mut reader, &e).await,
    };

    reader
        .get_mut()
        .write_all(handshake_response(&handshake.key).as_bytes())
        .await?;

    // Snapshot history and subscribe atomically, then replay history before any live frame.
    let mut sub = bus.subscribe();
    for frame in &sub.history {
        reader
            .get_mut()
            .write_all(&encode_text_frame(frame))
            .await?;
    }

    loop {
        tokio::select! {
            live = sub.live.recv() => match live {
                Ok(text) => {
                    reader.get_mut().write_all(&encode_text_frame(&text)).await?;
                }
                // The client fell behind the live buffer: it keeps the history it has and the
                // stream continues from here (a documented divergence: no replay of the gap).
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return Ok(()),
            },
            frame = read_client_frame(&mut reader) => match frame? {
                Some(ClientFrame::Ping(payload)) => {
                    reader.get_mut().write_all(&encode_frame(0xA, &payload)).await?;
                }
                Some(ClientFrame::Close) => {
                    let _ = reader.get_mut().write_all(&close_frame()).await;
                    let _ = reader.get_mut().shutdown().await;
                    return Ok(());
                }
                // Data and pong frames carry no request; ignore and keep streaming.
                Some(ClientFrame::Data | ClientFrame::Pong) => {}
                // The client's half closed: stop.
                None => return Ok(()),
            },
        }
    }
}

/// Answers one refused handshake and closes the connection. No frame is ever written here.
async fn refuse(reader: &mut BufReader<TcpStream>, error: &HandshakeError) -> io::Result<()> {
    reader
        .get_mut()
        .write_all(error.response().as_bytes())
        .await?;
    let _ = reader.get_mut().shutdown().await;
    Ok(())
}

/// How reading the request head ended.
enum HeadOutcome {
    /// The complete head, up to and including the blank line.
    Head(String),
    /// The peer closed before the head was complete.
    Closed,
    /// The head exceeded the accepted size.
    TooLarge,
}

/// Reads the request head up to the blank line that ends the headers, refusing one larger than
/// `max_head_bytes`. The caller bounds this in time.
async fn read_handshake_head<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    max_head_bytes: usize,
) -> io::Result<HeadOutcome> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).await?;
        if n == 0 {
            return Ok(HeadOutcome::Closed);
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return Ok(HeadOutcome::Head(
                String::from_utf8_lossy(&buf).into_owned(),
            ));
        }
        if buf.len() > max_head_bytes {
            return Ok(HeadOutcome::TooLarge);
        }
    }
}

/// Reads one client frame, handling masking and extended lengths. `Ok(None)` means the peer's
/// half closed. Data frames are consumed but reported as [`ClientFrame::Data`].
async fn read_client_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> io::Result<Option<ClientFrame>> {
    let mut header = [0u8; 2];
    if !read_exact_or_eof(reader, &mut header).await? {
        return Ok(None);
    }
    let opcode = header[0] & 0x0f;
    let masked = header[1] & 0x80 != 0;
    let len7 = (header[1] & 0x7f) as usize;

    let payload_len = match len7 {
        126 => {
            let mut ext = [0u8; 2];
            if !read_exact_or_eof(reader, &mut ext).await? {
                return Ok(None);
            }
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            if !read_exact_or_eof(reader, &mut ext).await? {
                return Ok(None);
            }
            let len = u64::from_be_bytes(ext);
            usize::try_from(len).unwrap_or(usize::MAX)
        }
        other => other,
    };

    // RFC 6455 §5.1: every client-to-server frame MUST be masked.
    if !masked {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client frame is not masked",
        ));
    }
    if payload_len > MAX_CLIENT_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "client frame payload too large",
        ));
    }

    let mut mask = [0u8; 4];
    if !read_exact_or_eof(reader, &mut mask).await? {
        return Ok(None);
    }
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 && !read_exact_or_eof(reader, &mut payload).await? {
        return Ok(None);
    }
    unmask(&mut payload, mask);

    Ok(Some(match opcode {
        0x8 => ClientFrame::Close,
        0x9 => ClientFrame::Ping(payload),
        0xA => ClientFrame::Pong,
        // 0x0 continuation, 0x1 text, 0x2 binary, and any reserved data opcode: ignored.
        _ => ClientFrame::Data,
    }))
}

/// Fills `buf` exactly. `Ok(false)` means clean EOF before the first byte or mid-buffer.
async fn read_exact_or_eof<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = reader.read(&mut buf[filled..]).await?;
        if n == 0 {
            return Ok(false);
        }
        filled += n;
    }
    Ok(true)
}
