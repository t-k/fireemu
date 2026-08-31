//! A real client connects to a bound Logging emulator, completes the RFC 6455 handshake, and
//! reads the `EmulatorLog` frames the daemon publishes. This is the primary evidence for the
//! WebSocket surface: the differential harness cannot easily gate a live WS stream, so an
//! end-to-end socket test stands in.

#![allow(clippy::cast_possible_truncation)]

use std::time::Duration;

use fireemu_adapter_logging::wire::sec_websocket_accept;
use fireemu_adapter_logging::{serve_logging, LogBus, LogInput};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Binds the emulator on an ephemeral loopback port and returns the bus and address.
async fn start() -> (LogBus, std::net::SocketAddr) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let bus = LogBus::with_capacity(16);
    let served = bus.clone();
    tokio::spawn(async move { serve_logging(listener, served).await });
    (bus, addr)
}

/// Completes the client handshake and returns the open stream, asserting the accept header.
async fn handshake(addr: std::net::SocketAddr, host: &str) -> TcpStream {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let key = "dGhlIHNhbXBsZSBub25jZQ==";
    let request = format!(
        "GET / HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();

    let head = read_http_head(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 101"),
        "expected 101, got: {head}"
    );
    let expected = sec_websocket_accept(key);
    assert!(
        head.to_ascii_lowercase().contains(&format!(
            "sec-websocket-accept: {}",
            expected.to_ascii_lowercase()
        )),
        "missing/incorrect accept header: {head}"
    );
    stream
}

/// Reads bytes until the blank line ending an HTTP head.
async fn read_http_head(stream: &mut TcpStream) -> String {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.unwrap();
        assert_ne!(n, 0, "connection closed during handshake");
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            return String::from_utf8_lossy(&buf).into_owned();
        }
    }
}

/// Reads one unmasked server text frame's payload as a string.
async fn read_text_frame(stream: &mut TcpStream) -> String {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0] & 0x0f, 0x1, "expected a text frame");
    assert_eq!(header[1] & 0x80, 0, "server frames must not be masked");
    let len7 = (header[1] & 0x7f) as usize;
    let len = match len7 {
        126 => {
            let mut ext = [0u8; 2];
            stream.read_exact(&mut ext).await.unwrap();
            u16::from_be_bytes(ext) as usize
        }
        127 => {
            let mut ext = [0u8; 8];
            stream.read_exact(&mut ext).await.unwrap();
            u64::from_be_bytes(ext) as usize
        }
        other => other,
    };
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    String::from_utf8(payload).unwrap()
}

/// Sends a masked client frame with the given opcode (RFC 6455 requires client masking).
async fn send_client_frame(stream: &mut TcpStream, opcode: u8, payload: &[u8]) {
    let mask = [0xAA, 0xBB, 0xCC, 0xDD];
    let mut frame = vec![0x80 | opcode, 0x80 | (payload.len() as u8)];
    frame.extend_from_slice(&mask);
    frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    stream.write_all(&frame).await.unwrap();
}

#[tokio::test]
async fn a_functions_log_frame_reaches_a_connected_client() {
    let (bus, addr) = start().await;
    let mut stream = handshake(addr, "127.0.0.1").await;

    // A functions runner line published live, tagged like EmulatorLogger.forFunction would.
    bus.publish(
        &LogInput::plain("info", "makeUppercase: hello world", 1_700_000_000_123)
            .for_function("makeUppercase")
            .for_emulator("functions"),
    );

    let frame = tokio::time::timeout(Duration::from_secs(5), read_text_frame(&mut stream))
        .await
        .expect("no frame arrived");
    let value: serde_json::Value = serde_json::from_str(&frame).unwrap();
    assert_eq!(value["level"], "info");
    assert_eq!(value["timestamp"], 1_700_000_000_123_i64);
    assert_eq!(value["message"], "makeUppercase: hello world");
    assert_eq!(value["data"]["metadata"]["emulator"]["name"], "functions");
    assert_eq!(
        value["data"]["metadata"]["function"]["name"],
        "makeUppercase"
    );
}

#[tokio::test]
async fn history_is_replayed_before_live_frames() {
    let (bus, addr) = start().await;
    // Two lines exist before the client connects.
    bus.publish(&LogInput::plain("info", "first", 1).for_emulator("functions"));
    bus.publish(&LogInput::plain("info", "second", 2).for_emulator("functions"));

    let mut stream = handshake(addr, "localhost").await;
    let a = read_text_frame(&mut stream).await;
    let b = read_text_frame(&mut stream).await;
    assert!(a.contains("first"));
    assert!(b.contains("second"));

    // Then a live line arrives in order.
    bus.publish(&LogInput::plain("warn", "third", 3).for_emulator("functions"));
    let c = read_text_frame(&mut stream).await;
    assert!(c.contains("third"));
    let value: serde_json::Value = serde_json::from_str(&c).unwrap();
    assert_eq!(value["level"], "warn");
}

#[tokio::test]
async fn a_ping_is_answered_with_a_pong() {
    let (_bus, addr) = start().await;
    let mut stream = handshake(addr, "127.0.0.1").await;
    send_client_frame(&mut stream, 0x9, b"ka").await;

    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0] & 0x0f, 0xA, "expected a pong");
    let len = (header[1] & 0x7f) as usize;
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await.unwrap();
    assert_eq!(&payload, b"ka");
}

#[tokio::test]
async fn a_foreign_host_is_refused() {
    let (_bus, addr) = start().await;
    let mut stream = TcpStream::connect(addr).await.unwrap();
    let request = "GET / HTTP/1.1\r\nHost: evil.example.com\r\nUpgrade: websocket\r\n\
                   Connection: Upgrade\r\nSec-WebSocket-Key: k\r\n\r\n";
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_http_head(&mut stream).await;
    assert!(
        head.starts_with("HTTP/1.1 403"),
        "expected 403, got: {head}"
    );
}
