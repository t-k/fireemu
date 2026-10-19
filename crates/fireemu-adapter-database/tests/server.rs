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
        let mut stream = TcpStream::connect(address).await.unwrap();
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: {address}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
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

    async fn text(&mut self, text: &str) {
        self.send(0x1, text.as_bytes()).await;
    }

    /// The next frame: opcode and payload.
    async fn next(&mut self) -> (u8, Vec<u8>) {
        tokio::time::timeout(Duration::from_secs(5), async {
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
                let n = self.stream.read(&mut chunk).await.unwrap();
                if n == 0 {
                    return (0xFF, Vec::new());
                }
                self.buffer.extend_from_slice(&chunk[..n]);
            }
        })
        .await
        .expect("no frame within 5 s")
    }

    async fn next_text(&mut self) -> String {
        let (opcode, payload) = self.next().await;
        assert_eq!(opcode, 0x1, "{payload:?}");
        String::from_utf8(payload).unwrap()
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
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 3)));
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
    tokio::time::timeout(Duration::from_secs(30), async {
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
