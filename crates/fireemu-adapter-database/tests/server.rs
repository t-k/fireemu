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
