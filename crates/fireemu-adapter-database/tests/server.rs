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
