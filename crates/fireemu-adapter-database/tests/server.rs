//! The REST API over real sockets: plain requests, and event streams with their keep-alive
//! and their cleanup when the client goes away.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_database::rest::{Database, RestOptions};
use fireemu_adapter_database::server::{serve, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start(keep_alive: Duration) -> (String, Arc<Mutex<Database>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 3)));
    let config = ServerConfig {
        keep_alive,
        clock: Arc::new(|| 1_000),
        ..ServerConfig::default()
    };
    tokio::spawn(serve(listener, Arc::clone(&database), config));
    (address, database)
}

async fn exchange(address: &str, method: &str, target: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

async fn read_until(stream: &mut TcpStream, needle: &str) -> String {
    let mut seen = Vec::new();
    let mut buffer = [0u8; 1024];
    tokio::time::timeout(Duration::from_secs(5), async {
        while !String::from_utf8_lossy(&seen).contains(needle) {
            let n = stream.read(&mut buffer).await.unwrap();
            assert!(n > 0, "stream closed before {needle:?}");
            seen.extend_from_slice(&buffer[..n]);
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "timed out waiting for {needle:?} in {:?}",
            String::from_utf8_lossy(&seen)
        )
    });
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn plain_requests_round_trip() {
    let (address, _) = start(Duration::from_secs(30)).await;
    let put = exchange(&address, "PUT", "/a.json?ns=t1", r#"{"x":1}"#).await;
    assert!(put.starts_with("HTTP/1.1 200"), "{put}");
    assert!(put.ends_with(r#"{"x":1}"#), "{put}");
    let get = exchange(&address, "GET", "/a/x.json?ns=t1", "").await;
    assert!(
        get.contains("content-type: application/json; charset=utf-8"),
        "{get}"
    );
    assert!(get.ends_with("\r\n\r\n1"), "{get}");
    let refused = exchange(&address, "GET", "/a?ns=t1", "").await;
    assert!(refused.starts_with("HTTP/1.1 400"), "{refused}");
}

#[tokio::test]
async fn raw_quotes_and_braces_in_the_query_are_accepted() {
    // curl and the Firebase documentation send `orderBy="$key"` unencoded; the official
    // emulator accepts it, so the server must not refuse the request line.
    let (address, _) = start(Duration::from_secs(30)).await;
    exchange(&address, "PUT", "/d.json?ns=q1", r#"{"a":1,"b":2}"#).await;
    let get = exchange(
        &address,
        "GET",
        "/d.json?ns=q1&orderBy=\"$key\"&startAt=\"b\"",
        "",
    )
    .await;
    assert!(get.starts_with("HTTP/1.1 200"), "{get}");
    assert!(get.ends_with(r#"{"b":2}"#), "{get}");
    let braces = exchange(
        &address,
        "GET",
        "/d.json?ns=q1&orderBy=\"$priority\"&startAt={}",
        "",
    )
    .await;
    assert!(braces.ends_with(r#"{"a":1,"b":2}"#), "{braces}");
    // A quote is an ordinary key character; angle brackets pass in the query too.
    let quoted_path = exchange(&address, "PUT", "/\"q\".json?ns=q2&x=<>", "1").await;
    assert!(quoted_path.starts_with("HTTP/1.1 200"), "{quoted_path}");
    let read = exchange(&address, "GET", "/.json?ns=q2", "").await;
    assert!(read.ends_with(r#"{"\"q\"":1}"#), "{read}");
}

#[tokio::test]
async fn streams_deliver_changes_and_keep_alives_and_close_with_the_client() {
    let (address, database) = start(Duration::from_millis(100)).await;
    exchange(&address, "PUT", "/s.json?ns=e1", r#"{"a":1}"#).await;
    let mut stream = TcpStream::connect(&address).await.unwrap();
    let request = format!(
        "GET /s.json?ns=e1 HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = read_until(&mut stream, "data: {\"path\":\"/\",\"data\":{\"a\":1}}\n\n").await;
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        head.contains("content-type: text/event-stream; charset=utf-8"),
        "{head}"
    );

    exchange(&address, "PUT", "/s/a.json?ns=e1", "2").await;
    read_until(
        &mut stream,
        "event: put\ndata: {\"path\":\"/a\",\"data\":2}\n\n",
    )
    .await;
    read_until(&mut stream, "event: keep-alive\ndata: null\n\n").await;
    assert_eq!(database.lock().unwrap().subscription_count(), 1);

    drop(stream);
    // The next keep-alive or write finds the client gone and closes the subscription.
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            exchange(&address, "PUT", "/s/a.json?ns=e1", "3").await;
            exchange(&address, "PUT", "/s/a.json?ns=e1", "4").await;
            if database.lock().unwrap().subscription_count() == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the subscription was not closed");
}

#[tokio::test]
async fn oversized_bodies_are_refused() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 3)));
    let config = ServerConfig {
        max_body_bytes: 4,
        ..ServerConfig::default()
    };
    tokio::spawn(serve(listener, Arc::clone(&database), config));
    let response = exchange(&address, "PUT", "/a.json?ns=t1", "123456").await;
    assert!(response.starts_with("HTTP/1.1 413"), "{response}");
    assert!(response.ends_with("Request body too large."), "{response}");
    assert!(database.lock().unwrap().tree("t1").is_none());
}

/// A minimal WebSocket client for the tests: masked text frames out, unmasked frames in.
struct Client {
    stream: TcpStream,
    buffer: Vec<u8>,
}

impl Client {
    async fn connect(address: &str, target: &str) -> (Self, String) {
        Self::connect_with(address, target, "13").await
    }

    async fn connect_with(address: &str, target: &str, version: &str) -> (Self, String) {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: {version}\r\n\r\n"
        );
        stream.write_all(request.as_bytes()).await.unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!(
                stream.read(&mut byte).await.unwrap(),
                1,
                "closed during the handshake"
            );
            head.push(byte[0]);
        }
        (
            Self {
                stream,
                buffer: Vec::new(),
            },
            String::from_utf8(head).unwrap(),
        )
    }

    async fn send(&mut self, opcode: u8, payload: &[u8]) {
        let mask = [7u8, 1, 2, 3];
        let mut frame = vec![0x80 | opcode];
        if payload.len() < 126 {
            frame.push(0x80 | u8::try_from(payload.len()).unwrap());
        } else {
            frame.push(0x80 | 0x7E);
            frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
    }

    async fn send_frame(&mut self, fin: bool, opcode: u8, payload: &[u8]) {
        let mask = [7u8, 1, 2, 3];
        let mut frame = vec![(u8::from(fin) << 7) | opcode];
        frame.push(0x80 | u8::try_from(payload.len()).unwrap());
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).await.unwrap();
    }

    async fn text(&mut self, text: &str) {
        self.send(0x1, text.as_bytes()).await;
    }

    /// Sends a text frame; `false` when the server has gone.
    async fn try_text(&mut self, text: &str) -> bool {
        let mask = [7u8, 1, 2, 3];
        let payload = text.as_bytes();
        let mut frame = vec![0x81];
        if payload.len() < 126 {
            frame.push(0x80 | u8::try_from(payload.len()).unwrap());
        } else {
            frame.push(0x80 | 0x7E);
            frame.extend_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame).await.is_ok()
    }

    /// The next frame: opcode and payload.
    async fn next(&mut self) -> (u8, Vec<u8>) {
        self.next_within(Duration::from_secs(5)).await
    }

    /// The next frame, waiting at most `limit`. A reset reads as the end too.
    async fn next_within(&mut self, limit: Duration) -> (u8, Vec<u8>) {
        match self.next_or_end_within(limit).await {
            (RESET, payload) => (0xFF, payload),
            frame => frame,
        }
    }

    /// The next frame, waiting at most `limit`: opcode 0xFF for the end of the stream and
    /// [`RESET`] for a reset connection.
    async fn next_or_end_within(&mut self, limit: Duration) -> (u8, Vec<u8>) {
        tokio::time::timeout(limit, async {
            loop {
                if self.buffer.len() >= 2 {
                    let opcode = self.buffer[0] & 0x0F;
                    let (len, at) = match self.buffer[1] & 0x7F {
                        126 if self.buffer.len() >= 4 => (
                            usize::from(u16::from_be_bytes([self.buffer[2], self.buffer[3]])),
                            4,
                        ),
                        126 | 127 => (usize::MAX, 0),
                        short => (usize::from(short), 2),
                    };
                    if len != usize::MAX && self.buffer.len() >= at + len {
                        let payload = self.buffer[at..at + len].to_vec();
                        self.buffer.drain(..at + len);
                        return (opcode, payload);
                    }
                }
                let mut chunk = [0u8; 4096];
                let Ok(n) = self.stream.read(&mut chunk).await else {
                    return (RESET, Vec::new());
                };
                if n == 0 {
                    return (0xFF, Vec::new());
                }
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no frame within {limit:?}"))
    }

    async fn next_text(&mut self) -> String {
        let (opcode, payload) = self.next().await;
        assert_eq!(opcode, 0x1, "{payload:?}");
        String::from_utf8(payload).unwrap()
    }
}

/// What [`Client::next_or_end_within`] answers for a reset connection.
const RESET: u8 = 0xFE;

#[tokio::test]
async fn a_closed_websocket_ends_with_its_data_even_when_the_client_sent_more() {
    // The flake report of 2026-10-21: a socket closed while the client's frames sit unread is
    // reset, and the reset loses the server's last data and its FIN (macOS may even drop the
    // reset, leaving the client half-open). The server reads and discards what is left first.
    let (address, _database) = start(Duration::from_secs(30)).await;
    for _ in 0..20 {
        let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=wl").await;
        client.next_text().await;
        client.send(0x8, &[0x03, 0xE8]).await;
        for _ in 0..64 {
            client.text(&"x".repeat(1_000)).await;
        }
        let (opcode, _) = client.next_or_end_within(Duration::from_secs(10)).await;
        assert_eq!(opcode, 0x8, "the close echo");
        let (end, _) = client.next_or_end_within(Duration::from_secs(10)).await;
        assert_eq!(end, 0xFF, "a clean end of stream, not a reset");
    }
}

#[tokio::test]
async fn the_realtime_protocol_runs_over_a_websocket() {
    let (address, database) = start(Duration::from_secs(30)).await;
    let (mut client, head) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo="),
        "{head}"
    );
    let handshake = client.next_text().await;
    assert!(
        handshake.starts_with(r#"{"t":"c","d":{"t":"h","d":{"ts":1000,"v":"5","h":""#),
        "{handshake}"
    );

    client
        .text(r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/a","d":{"x":1}}}}"#)
        .await;
    assert_eq!(
        client.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":""}}}"#
    );
    client
        .text(r#"{"t":"d","d":{"r":2,"a":"g","b":{"p":"/a","q":{}}}}"#)
        .await;
    assert_eq!(
        client.next_text().await,
        r#"{"t":"d","d":{"r":2,"b":{"s":"ok","d":{"x":1}}}}"#
    );
    assert!(database
        .lock()
        .unwrap()
        .tree("w1")
        .unwrap()
        .get(&fireemu_core_database::Path::from_keys(["a", "x"]))
        .is_some());

    // A WebSocket ping is answered with a pong carrying the same payload.
    client.send(0x9, b"hey").await;
    assert_eq!(client.next().await, (0xA, b"hey".to_vec()));
    // A close is answered with a close.
    client.send(0x8, &[0x03, 0xE8]).await;
    assert_eq!(client.next().await, (0x8, vec![0x03, 0xE8]));
}

#[tokio::test]
async fn the_websocket_upgrade_refuses_versions_and_namespaces() {
    let (address, _) = start(Duration::from_secs(30)).await;
    let (mut client, head) = Client::connect(&address, "/.ws?v=4&ns=w1").await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert_eq!(
        client.next_text().await,
        r#"{"t":"c","d":{"t":"s","d":"Version error. Please make sure you are using the latest Firebase library"}}"#
    );
    // The official emulator drops the connection without a close frame (1006).
    assert_eq!(client.next().await.0, 0xFF);
    let (_, refused) = Client::connect(&address, "/.ws?v=5&ns=Bad_NS").await;
    assert!(refused.starts_with("HTTP/1.1 403"), "{refused}");
}

#[tokio::test]
async fn unmasked_frames_close_the_connection_with_a_protocol_error() {
    let (address, _) = start(Duration::from_secs(30)).await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    client.next_text().await;
    client.stream.write_all(&[0x81, 0x01, b'a']).await.unwrap();
    assert_eq!(client.next().await, (0x8, vec![0x03, 0xEA]));
}

async fn start_with(config: ServerConfig) -> (String, Arc<Mutex<Database>>) {
    start_full(config, RestOptions::default()).await
}

async fn start_full(config: ServerConfig, options: RestOptions) -> (String, Arc<Mutex<Database>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(options, 3)));
    tokio::spawn(serve(listener, Arc::clone(&database), config));
    (address, database)
}

/// Reads until the server closes the connection; panics if it stays open past `limit`.
async fn read_until_closed(stream: &mut TcpStream, limit: Duration) -> String {
    let mut seen = Vec::new();
    let mut buffer = [0u8; 1024];
    tokio::time::timeout(limit, async {
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(&buffer[..n]),
            }
        }
    })
    .await
    .expect("the server kept a stalled connection open");
    String::from_utf8_lossy(&seen).into_owned()
}

#[tokio::test]
async fn stalled_headers_and_bodies_are_cut_off() {
    let (address, _) = start_with(ServerConfig {
        header_timeout: Duration::from_millis(300),
        body_timeout: Duration::from_millis(300),
        ..ServerConfig::default()
    })
    .await;
    let mut stalled_head = TcpStream::connect(&address).await.unwrap();
    stalled_head
        .write_all(b"GET /a.json?ns=t1 HT")
        .await
        .unwrap();
    read_until_closed(&mut stalled_head, Duration::from_secs(5)).await;

    let mut stalled_body = TcpStream::connect(&address).await.unwrap();
    stalled_body
        .write_all(b"PUT /a.json?ns=t1 HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n12")
        .await
        .unwrap();
    let answer = read_until_closed(&mut stalled_body, Duration::from_secs(5)).await;
    assert!(
        answer.is_empty() || answer.starts_with("HTTP/1.1 408"),
        "{answer}"
    );
}

#[tokio::test]
async fn a_stream_that_stops_reading_is_closed_once_its_queue_fills() {
    let (address, database) = start_with(ServerConfig {
        stream_queue: 4,
        ..ServerConfig::default()
    })
    .await;
    let mut stream = TcpStream::connect(&address).await.unwrap();
    stream
        .write_all(
            format!(
                "GET /s.json?ns=q HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    read_until(&mut stream, "event: put").await;
    // Never read again: large events fill the socket buffers, then the queue.
    let big = format!("\"{}\"", "x".repeat(200_000));
    tokio::time::timeout(Duration::from_secs(10), async {
        for i in 0.. {
            exchange(
                &address,
                "PUT",
                &format!("/s/k{}.json?ns=q&print=silent", i % 50),
                &big,
            )
            .await;
            if database.lock().unwrap().subscription_count() == 0 {
                break;
            }
        }
    })
    .await
    .expect("the stalled stream was never closed");
}

#[tokio::test]
async fn a_conditional_header_that_is_not_ascii_never_matches() {
    let (address, database) = start(Duration::from_secs(30)).await;
    exchange(&address, "PUT", "/a.json?ns=t1", "1").await;
    let mut stream = TcpStream::connect(&address).await.unwrap();
    let mut request = b"PUT /a.json?ns=t1 HTTP/1.1\r\nHost: x\r\nIf-Match: \xe9\r\nContent-Length: 1\r\nConnection: close\r\n\r\n2".to_vec();
    stream.write_all(&request).await.unwrap();
    request.clear();
    let answer = read_until_closed(&mut stream, Duration::from_secs(5)).await;
    assert!(answer.starts_with("HTTP/1.1 412"), "{answer}");
    let stored = database.lock().unwrap().tree("t1").unwrap().get_json(
        &fireemu_core_database::Path::from_keys(["a"]),
        fireemu_core_database::Format::Plain,
    );
    assert_eq!(stored, fireemu_core_database::Json::int(1));
}

// WebSocket round 2 (review 2026-10-19-rtdb-ws-review.md).

#[tokio::test]
async fn upgrades_follow_the_official_emulator_on_paths_and_versions() {
    let (address, _) = start(Duration::from_secs(30)).await;
    // The official emulator upgrades whatever Sec-WebSocket-Version the client names.
    let (mut client, head) = Client::connect_with(&address, "/.ws?v=5&ns=w1", "8").await;
    assert!(head.starts_with("HTTP/1.1 101"), "{head}");
    assert!(client
        .next_text()
        .await
        .starts_with(r#"{"t":"c","d":{"t":"h""#));
    // It does not upgrade other paths.
    let (_, other) = Client::connect(&address, "/anything.json?v=5&ns=w1").await;
    assert!(!other.starts_with("HTTP/1.1 101"), "{other}");
}

#[tokio::test]
async fn websocket_control_and_data_frames_over_a_socket() {
    let (address, _) = start_full(
        ServerConfig::default(),
        RestOptions {
            realtime_message_bytes: 64,
            ..RestOptions::default()
        },
    )
    .await;
    // A fragmented message with a ping between its fragments.
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    client.next_text().await;
    let message = br#"{"t":"d","d":{"r":1,"a":"echo","b":{"d":"x"}}}"#;
    client.send_frame(false, 0x1, &message[..10]).await;
    client.send_frame(true, 0x9, b"p").await;
    client.send_frame(true, 0x0, &message[10..]).await;
    assert_eq!(client.next().await, (0xA, b"p".to_vec()));
    assert_eq!(
        client.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":"x"}}}"#
    );
    // A message over the realtime limit closes with 1009.
    client.text(&"x".repeat(65)).await;
    assert_eq!(client.next().await, (0x8, 1009u16.to_be_bytes().to_vec()));

    // Text that is not UTF-8 closes with 1007.
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    client.next_text().await;
    client.send(0x1, &[0xff, 0xfe]).await;
    assert_eq!(client.next().await, (0x8, 1007u16.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn close_codes_are_checked_before_they_are_echoed() {
    let (address, _) = start(Duration::from_secs(30)).await;
    for (payload, answer) in [
        (vec![0x03], 1002u16),
        (1005u16.to_be_bytes().to_vec(), 1002),
        (999u16.to_be_bytes().to_vec(), 1002),
        (5000u16.to_be_bytes().to_vec(), 1002),
        ([0x03, 0xE8, 0xff].to_vec(), 1007),
        (3000u16.to_be_bytes().to_vec(), 3000),
        (1000u16.to_be_bytes().to_vec(), 1000),
    ] {
        let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
        client.next_text().await;
        client.send(0x8, &payload).await;
        assert_eq!(
            client.next().await,
            (0x8, answer.to_be_bytes().to_vec()),
            "{payload:?}"
        );
    }
    // An empty close is answered with an empty close.
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    client.next_text().await;
    client.send(0x8, &[]).await;
    assert_eq!(client.next().await, (0x8, Vec::new()));
}

#[tokio::test]
async fn idle_realtime_connections_are_closed() {
    let (address, _) = start_with(ServerConfig {
        realtime_idle: Duration::from_millis(300),
        ..ServerConfig::default()
    })
    .await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w1").await;
    client.next_text().await;
    // Nothing is sent; the server ends the connection after the idle time.
    let (opcode, _) = client.next().await;
    assert!(opcode == 0x8 || opcode == 0xFF, "{opcode}");
}

#[tokio::test]
async fn realtime_listens_receive_writes_from_other_connections_and_rest() {
    let (address, database) = start(Duration::from_secs(30)).await;
    let (mut reader, _) = Client::connect(&address, "/.ws?v=5&ns=w9").await;
    reader.next_text().await;
    let (mut writer, _) = Client::connect(&address, "/.ws?v=5&ns=w9").await;
    writer.next_text().await;
    reader
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#)
        .await;
    assert_eq!(
        reader.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#
    );
    writer
        .text(r#"{"t":"d","d":{"r":1,"a":"p","b":{"p":"/a/b","d":1}}}"#)
        .await;
    assert_eq!(
        writer.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":""}}}"#
    );
    assert_eq!(
        reader.next_text().await,
        r#"{"t":"d","d":{"b":{"p":"a/b","d":1},"a":"d"}}"#
    );
    exchange(&address, "PUT", "/a/c.json?ns=w9", "2").await;
    assert_eq!(
        reader.next_text().await,
        r#"{"t":"d","d":{"b":{"p":"a/c","d":2},"a":"d"}}"#
    );
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    // Closing the connection ends its listens.
    reader.send(0x8, &[0x03, 0xE8]).await;
    assert_eq!(reader.next().await, (0x8, vec![0x03, 0xE8]));
    tokio::time::timeout(Duration::from_secs(5), async {
        while database.lock().unwrap().listen_count() != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the closed connection kept its listen");
}

#[tokio::test]
async fn a_listener_that_stops_reading_is_dropped_once_its_queue_fills() {
    // A long idle time: only the full queue can drop the listener within the test's time.
    let (address, database) = start_with(ServerConfig {
        stream_queue: 4,
        realtime_idle: Duration::from_secs(120),
        ..ServerConfig::default()
    })
    .await;
    let (mut reader, _) = Client::connect(&address, "/.ws?v=5&ns=w10").await;
    reader.next_text().await;
    reader
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/s","h":""}}}"#)
        .await;
    reader.next_text().await;
    // Never read again: large pushes fill the socket buffers, then the queue.
    let big = format!("\"{}\"", "x".repeat(200_000));
    tokio::time::timeout(Duration::from_secs(10), async {
        for i in 0.. {
            exchange(
                &address,
                "PUT",
                &format!("/s/k{}.json?ns=w10&print=silent", i % 50),
                &big,
            )
            .await;
            if database.lock().unwrap().listen_count() == 0 {
                break;
            }
        }
    })
    .await
    .expect("the stalled listener was never dropped");
}

#[tokio::test]
async fn a_message_larger_than_the_byte_budget_reaches_a_listener_with_an_empty_queue() {
    // The official emulator delivers it. The queue unit tests pin the drop that follows
    // when a second message would wait with it.
    let (address, database) = start_with(ServerConfig {
        stream_queue_bytes: 10_000,
        realtime_idle: Duration::from_secs(120),
        ..ServerConfig::default()
    })
    .await;
    let (mut reader, _) = Client::connect(&address, "/.ws?v=5&ns=w11").await;
    reader.next_text().await;
    reader
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/s","h":""}}}"#)
        .await;
    reader.next_text().await;
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    let big = format!("\"{}\"", "x".repeat(20_000));
    exchange(&address, "PUT", "/s.json?ns=w11&print=silent", &big).await;
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    // It arrives, split into frames as the SDK reads a long message.
    let mut received = String::new();
    while !received.contains("xxxxx\"") {
        received.push_str(&reader.next_text().await);
    }
    assert_eq!(database.lock().unwrap().listen_count(), 1);
}

#[tokio::test]
async fn a_client_that_stops_reading_is_dropped_after_the_write_deadline() {
    let (address, database) = start_with(ServerConfig {
        realtime_idle: Duration::from_millis(500),
        ..ServerConfig::default()
    })
    .await;
    exchange(
        &address,
        "PUT",
        "/big.json?ns=w12&print=silent",
        &format!("\"{}\"", "x".repeat(100_000)),
    )
    .await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w12").await;
    client.next_text().await;
    client
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/other","h":""}}}"#)
        .await;
    client.next_text().await;
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    // Ask for the large value again and again without reading the answers.
    tokio::time::timeout(Duration::from_secs(10), async {
        for r in 2.. {
            let frame =
                format!(r#"{{"t":"d","d":{{"r":{r},"a":"g","b":{{"p":"/big","q":{{}}}}}}}}"#);
            // A write that fails or blocks means the server has stopped reading too.
            let _ = tokio::time::timeout(Duration::from_millis(200), client.try_text(&frame)).await;
            if database.lock().unwrap().listen_count() == 0 {
                break;
            }
        }
    })
    .await
    .expect("the stalled client was never dropped");
}

#[tokio::test]
async fn a_null_tag_is_answered_and_reset_before_the_connection_drops() {
    let (address, _) = start(Duration::from_secs(30)).await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w13").await;
    client.next_text().await;
    client
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/w","q":{"i":".key","l":2,"vf":"l"},"t":null,"h":""}}}"#)
        .await;
    assert_eq!(
        client.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"internal_error","d":"An internal error occurred"}}}"#
    );
    assert_eq!(
        client.next_text().await,
        format!(r#"{{"t":"c","d":{{"t":"r","d":"{address}"}}}}"#)
    );
    assert_eq!(client.next().await.0, 0xFF);
}

#[tokio::test]
async fn a_client_that_pings_without_reading_is_dropped_after_the_write_deadline() {
    let (address, database) = start_with(ServerConfig {
        realtime_idle: Duration::from_millis(500),
        ..ServerConfig::default()
    })
    .await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w14").await;
    client.next_text().await;
    client
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#)
        .await;
    client.next_text().await;
    let payload = [7u8; 125];
    let mask = [1u8, 2, 3, 4];
    let mut ping = vec![0x89, 0x80 | 0x7D];
    ping.extend_from_slice(&mask);
    ping.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    let batch: Vec<u8> = ping
        .iter()
        .copied()
        .cycle()
        .take(ping.len() * 200)
        .collect();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            // Writing may block or fail once the server stops reading; that is expected.
            let _ =
                tokio::time::timeout(Duration::from_millis(100), client.stream.write_all(&batch))
                    .await;
            if database.lock().unwrap().listen_count() == 0 {
                break;
            }
        }
    })
    .await
    .expect("the stalled client was never dropped");
}

#[tokio::test]
async fn a_reset_outside_any_request_reaches_listeners_at_once() {
    let (address, database) = start(Duration::from_secs(30)).await;
    exchange(&address, "PUT", "/a.json?ns=w15", "1").await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w15").await;
    client.next_text().await;
    client
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/a","h":""}}}"#)
        .await;
    client.next_text().await;
    client.next_text().await;
    database
        .lock()
        .unwrap()
        .clear_namespaces_where(|ns| ns == "w15");
    assert_eq!(
        client.next_text().await,
        r#"{"t":"d","d":{"b":{"p":"a","d":null},"a":"d"}}"#
    );
}

#[tokio::test]
async fn stopping_the_server_stops_its_flush_task() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 3)));
    let server = tokio::spawn(serve(
        listener,
        Arc::clone(&database),
        ServerConfig::default(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(Arc::strong_count(&database) > 1);
    server.abort();
    let _ = server.await;
    // The flush task held the database too; it goes with the server.
    for _ in 0..100 {
        if Arc::strong_count(&database) == 1 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("the database is still held after the server stopped");
}

#[tokio::test]
async fn a_closing_websocket_writes_what_it_registered_and_listeners_hear_it() {
    let (address, _) = start(Duration::from_secs(30)).await;
    exchange(
        &address,
        "PUT",
        "/presence/other.json?ns=w20",
        r#""online""#,
    )
    .await;
    let (mut listener, _) = Client::connect(&address, "/.ws?v=5&ns=w20").await;
    listener.next_text().await;
    listener
        .text(r#"{"t":"d","d":{"r":1,"a":"q","b":{"p":"/presence","h":""}}}"#)
        .await;
    listener.next_text().await;
    listener.next_text().await;
    let (mut leaving, _) = Client::connect(&address, "/.ws?v=5&ns=w20").await;
    leaving.next_text().await;
    leaving
        .text(r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/presence/me","d":"offline"}}}"#)
        .await;
    assert_eq!(
        leaving.next_text().await,
        r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":""}}}"#
    );
    // A close frame ends the connection; a dropped socket would too.
    leaving.send(0x8, &[0x03, 0xe8]).await;
    drop(leaving);
    assert_eq!(
        listener.next_text().await,
        r#"{"t":"d","d":{"b":{"p":"presence","d":{"me":"offline"}},"a":"m"}}"#
    );
    assert_eq!(
        exchange(&address, "GET", "/presence.json?ns=w20", "")
            .await
            .rsplit("\r\n\r\n")
            .next()
            .unwrap(),
        r#"{"me":"offline","other":"online"}"#
    );
}

/// Reads `target` until it answers `expected`, for writes that land after a connection ends.
async fn eventually(address: &str, target: &str, expected: &str) {
    for _ in 0..100 {
        let response = exchange(address, "GET", target, "").await;
        if response.rsplit("\r\n\r\n").next() == Some(expected) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("{target} never answered {expected}");
}

#[tokio::test]
async fn an_idle_websocket_writes_what_it_registered_when_it_is_closed() {
    let (address, _) = start_with(ServerConfig {
        realtime_idle: Duration::from_millis(300),
        ..ServerConfig::default()
    })
    .await;
    let (mut client, _) = Client::connect(&address, "/.ws?v=5&ns=w21").await;
    client.next_text().await;
    client
        .text(r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/idle","d":1}}}"#)
        .await;
    client.next_text().await;
    eventually(&address, "/idle.json?ns=w21", "1").await;
}

#[tokio::test]
async fn a_websocket_dropped_for_falling_behind_writes_what_it_registered_once() {
    let (address, database) = start_with(ServerConfig {
        stream_queue: 2,
        realtime_idle: Duration::from_secs(120),
        ..ServerConfig::default()
    })
    .await;
    let (mut reader, _) = Client::connect(&address, "/.ws?v=5&ns=w22").await;
    reader.next_text().await;
    reader
        .text(r#"{"t":"d","d":{"r":1,"a":"o","b":{"p":"/presence","d":"offline"}}}"#)
        .await;
    reader.next_text().await;
    reader
        .text(r#"{"t":"d","d":{"r":2,"a":"q","b":{"p":"/a","h":""}}}"#)
        .await;
    while !reader.next_text().await.contains(r#""r":2"#) {}
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    // The reader stops reading; large writes fill its socket, then its queue.
    for n in 0..200 {
        if database.lock().unwrap().listen_count() == 0 {
            break;
        }
        // A different value each time: an equal write is no write and pushes nothing.
        let big = format!("\"{n}{}\"", "x".repeat(300_000));
        exchange(&address, "PUT", "/a.json?ns=w22&print=silent", &big).await;
    }
    assert_eq!(database.lock().unwrap().listen_count(), 0, "never dropped");
    eventually(&address, "/presence.json?ns=w22", r#""offline""#).await;
    // What the dropped socket still sends does not land after the onDisconnect write. This
    // shows the outcome only: whether the server read the frame and refused it, or never
    // read it, is pinned by server::tests::a_connection_dropped_for_falling_behind_answers_nothing_more.
    reader
        .text(r#"{"t":"d","d":{"r":3,"a":"p","b":{"p":"/presence","d":"online"}}}"#)
        .await;
    // Reading again lets the server finish the pushes it was writing. The backlog is megabytes
    // of large frames, which a loaded machine can take a while to drain; the connection then
    // ends with a clean end of stream, never a reset (the server reads what is left first).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let mut drained = 0;
    let end = loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        let (opcode, payload) = reader.next_or_end_within(left).await;
        drained += payload.len();
        if matches!(opcode, 0x8 | 0xFF | RESET) {
            break opcode;
        }
    };
    assert_ne!(end, RESET, "reset after draining {drained} bytes");
    eventually(&address, "/presence.json?ns=w22", r#""offline""#).await;
}

#[tokio::test]
async fn a_stream_the_rules_no_longer_allow_ends_after_its_cancel_event() {
    let (address, database) = start(Duration::from_secs(60)).await;
    let rules = |body: &'static str| {
        let address = address.clone();
        async move {
            let mut stream = TcpStream::connect(&address).await.unwrap();
            let request = format!(
                "PUT /.settings/rules.json?ns=rc HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer owner\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).await.unwrap();
            response
        }
    };
    assert!(rules(r#"{"rules":{".read":true}}"#)
        .await
        .starts_with("HTTP/1.1 200"));
    let mut stream = TcpStream::connect(&address).await.unwrap();
    let request = format!(
        "GET /s.json?ns=rc HTTP/1.1\r\nHost: {address}\r\nAccept: text/event-stream\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    read_until(&mut stream, "data: {\"path\":\"/\",\"data\":null}\n\n").await;
    assert!(rules(r#"{"rules":{".read":false}}"#)
        .await
        .starts_with("HTTP/1.1 200"));
    // The chunked body ends right after the event.
    let tail = read_until(&mut stream, "0\r\n\r\n").await;
    assert!(
        tail.ends_with("event: cancel\ndata: Permission denied\n\n\r\n0\r\n\r\n"),
        "{tail:?}"
    );
    assert_eq!(database.lock().unwrap().subscription_count(), 0);
}
