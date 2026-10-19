//! Long polling (`/.lp`) over real sockets: a connection's life, held requests, pushes from
//! other connections and REST, segments, and the answers for unknown connections. Expected
//! texts are the official emulator's (firebase-database-emulator v4.11.2).

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_database::rest::{Database, RestOptions};
use fireemu_adapter_database::server::{serve, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn start(config: ServerConfig) -> (String, Arc<Mutex<Database>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 3)));
    let config = ServerConfig {
        clock: Arc::new(|| 1_000),
        ..config
    };
    tokio::spawn(serve(listener, Arc::clone(&database), config));
    (address, database)
}

/// One request: the status, the `Content-Type` and the body.
async fn get(address: &str, method: &str, target: &str, body: &str) -> (u16, String, String) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {address}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(10),
        stream.read_to_string(&mut response),
    )
    .await
    .expect("no answer within 10 s")
    .unwrap();
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    let status = head[9..12].parse().unwrap();
    let content_type = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-type: ")
                .map(str::to_owned)
        })
        .unwrap_or_default();
    (status, content_type, body.to_owned())
}

/// The SDK's web-safe base64 of a message.
fn b64(message: &str) -> String {
    fireemu_core_database::hash::base64(message.as_bytes())
        .replace('+', "-")
        .replace('/', "_")
        .replace('=', ".")
}

struct Lp {
    address: String,
    id: String,
    pw: String,
    ns: String,
    segment: u64,
    serial: u64,
}

impl Lp {
    async fn start(address: &str, ns: &str) -> (Self, String) {
        let (status, content_type, body) = get(
            address,
            "GET",
            &format!("/.lp?start=t&ser=1&cb=3&v=5&ns={ns}"),
            "",
        )
        .await;
        assert_eq!(
            (status, content_type.as_str()),
            (200, "application/javascript; charset=utf-8")
        );
        let line = body
            .lines()
            .find(|l| l.contains("pLPCommand('start'"))
            .unwrap();
        let parts: Vec<&str> = line.split('\'').collect();
        (
            Self {
                address: address.to_owned(),
                id: parts[3].to_owned(),
                pw: parts[5].to_owned(),
                ns: ns.to_owned(),
                segment: 0,
                serial: 10,
            },
            body,
        )
    }

    fn target(&mut self, messages: &[&str]) -> String {
        self.serial += 1;
        let mut target = format!(
            "/.lp?id={}&pw={}&ser={}&ns={}",
            self.id, self.pw, self.serial, self.ns
        );
        for (i, message) in messages.iter().enumerate() {
            write!(
                target,
                "&seg{i}={}&ts{i}=1&d{i}={}",
                self.segment,
                b64(message)
            )
            .unwrap();
            self.segment += 1;
        }
        target
    }

    async fn poll(&mut self, messages: &[&str]) -> String {
        let target = self.target(messages);
        get(&self.address, "GET", &target, "").await.2
    }
}

fn request(r: u64, action: &str, body: &str) -> String {
    format!(r#"{{"t":"d","d":{{"r":{r},"a":"{action}","b":{body}}}}}"#)
}

#[tokio::test]
async fn a_connection_starts_answers_and_receives_pushes() {
    let (address, database) = start(ServerConfig::default()).await;
    let (mut lp, body) = Lp::start(&address, "lp1").await;
    assert!(
        body.starts_with(
            "\nfunction pLPCommand(c, a1, a2, a3, a4) {\nparent.window[\"pLPCommand3\"]"
        ),
        "{body}"
    );
    assert!(
        body.contains(&format!("         pLPCommand('start','{}','{}');\npRTLPCB(0,[{{\"t\":\"c\",\"d\":{{\"t\":\"h\",\"d\":{{\"ts\":1000,\"v\":\"5\",\"h\":\"{address}\",\"s\":\"", lp.id, lp.pw)),
        "{body}"
    );
    assert_eq!(lp.pw.len(), 10);
    // A write is answered in the same request.
    assert_eq!(
        lp.poll(&[&request(1, "p", r#"{"p":"/a","d":1}"#)]).await,
        "pRTLPCB(1,[{\"t\":\"d\",\"d\":{\"r\":1,\"b\":{\"s\":\"ok\",\"d\":\"\"}}}]);\n"
    );
    // A listen: its value, then the acknowledgement.
    assert_eq!(
        lp.poll(&[&request(2, "q", r#"{"p":"/a","h":""}"#)]).await,
        "pRTLPCB(2,[{\"t\":\"d\",\"d\":{\"b\":{\"p\":\"a\",\"d\":1},\"a\":\"d\"}},{\"t\":\"d\",\"d\":{\"r\":2,\"b\":{\"s\":\"ok\",\"d\":{}}}}]);\n"
    );
    // A held request is answered when another client writes.
    let target = lp.target(&[]);
    let held = tokio::spawn({
        let address = address.clone();
        async move { get(&address, "GET", &target, "").await.2 }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(!held.is_finished());
    get(&address, "PUT", "/a.json?ns=lp1", "2").await;
    assert_eq!(
        held.await.unwrap(),
        "pRTLPCB(3,[{\"t\":\"d\",\"d\":{\"b\":{\"p\":\"a\",\"d\":2},\"a\":\"d\"}}]);\n"
    );
    // A new request releases the held one with nothing.
    let target = lp.target(&[]);
    let held = tokio::spawn({
        let address = address.clone();
        async move { get(&address, "GET", &target, "").await.2 }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        lp.poll(&[&request(3, "echo", r#"{"d":"x"}"#)]).await,
        "pRTLPCB(5,[{\"t\":\"d\",\"d\":{\"r\":3,\"b\":{\"s\":\"ok\",\"d\":\"x\"}}}]);\n"
    );
    assert_eq!(held.await.unwrap(), "pRTLPCB(4,[]);\n");
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    // The client leaves: its held request ends empty, its listens go, it is unknown after.
    let target = lp.target(&[]);
    let held = tokio::spawn({
        let address = address.clone();
        async move { get(&address, "GET", &target, "").await.2 }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let (status, content_type, body) = get(
        &address,
        "GET",
        &format!("/.lp?disconn=t&id={}&pw={}&ns=lp1", lp.id, lp.pw),
        "",
    )
    .await;
    assert_eq!(
        (status, content_type.as_str(), body.as_str()),
        (200, "application/javascript; charset=utf-8", "<!-- -->")
    );
    assert_eq!(held.await.unwrap(), "");
    assert_eq!(database.lock().unwrap().listen_count(), 0);
    assert_eq!(
        lp.poll(&[]).await,
        format!("pRTLPCB(0,[{{\"t\":\"c\",\"d\":{{\"t\":\"r\",\"d\":\"{address}\"}}}}]);\npLPCommand('close');\n")
    );
}

#[tokio::test]
async fn unknown_connections_frames_and_bad_segments() {
    let (address, _) = start(ServerConfig::default()).await;
    let reset = format!(
        "pRTLPCB(0,[{{\"t\":\"c\",\"d\":{{\"t\":\"r\",\"d\":\"{address}\"}}}}]);\npLPCommand('close');\n"
    );
    assert_eq!(get(&address, "GET", "/.lp", "").await.2, reset);
    let (mut lp, _) = Lp::start(&address, "lp2").await;
    assert_eq!(
        get(
            &address,
            "GET",
            &format!("/.lp?id={}&pw=nope&ser=9", lp.id),
            ""
        )
        .await
        .2,
        reset
    );
    let (status, content_type, body) = get(
        &address,
        "GET",
        &format!("/.lp?dframe=t&id={}&pw={}&ns=lp2", lp.id, lp.pw),
        "",
    )
    .await;
    assert_eq!(
        (status, content_type.as_str()),
        (200, "text/html; charset=utf-8")
    );
    assert!(
        body.contains(&format!(
            "EnvSendPing(\"/.lp?disconn=t&id={}&pw={}\");",
            lp.id, lp.pw
        )),
        "{body}"
    );
    assert_eq!(
        get(&address, "GET", "/.lp?dframe=t&id=x&pw=y", "").await.2,
        ""
    );
    let (status, _, body) = get(
        &address,
        "GET",
        &format!(
            "/.lp?id={}&pw={}&ser=9&seg0=0&ts0=1&d0=%25%25%25",
            lp.id, lp.pw
        ),
        "",
    )
    .await;
    assert_eq!(
        (status, body.as_str()),
        (400, "{\n  \"error\" : \"Bad Request\"\n}\n")
    );
    // The bad packet used segment 0. A packet split over two requests is answered once it is whole; POST works as GET.
    let message = b64(&request(1, "echo", r#"{"d":"split"}"#));
    let (first, second) = message.split_at(10);
    let target = format!(
        "/.lp?id={}&pw={}&ser=20&seg0=1&ts0=2&d0={first}",
        lp.id, lp.pw
    );
    let held = tokio::spawn({
        let address = address.clone();
        async move { get(&address, "POST", &target, "").await.2 }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    let target = format!(
        "/.lp?id={}&pw={}&ser=21&seg0=2&ts0=2&d0={second}",
        lp.id, lp.pw
    );
    assert_eq!(
        get(&address, "GET", &target, "").await.2,
        "pRTLPCB(2,[{\"t\":\"d\",\"d\":{\"r\":1,\"b\":{\"s\":\"ok\",\"d\":\"split\"}}}]);\n"
    );
    assert_eq!(held.await.unwrap(), "pRTLPCB(1,[]);\n");
    lp.segment = 3;
    assert!(lp
        .poll(&[&request(2, "echo", r#"{"d":"y"}"#)])
        .await
        .starts_with("pRTLPCB(3,"));
    // Messages stay whole: no WebSocket frame counts, even past 16384 characters.
    let big = "x".repeat(20_000);
    lp.poll(&[&request(3, "p", &format!(r#"{{"p":"/big","d":"{big}"}}"#))])
        .await;
    assert_eq!(
        lp.poll(&[&request(4, "g", r#"{"p":"/big","q":{}}"#)]).await,
        format!("pRTLPCB(5,[{{\"t\":\"d\",\"d\":{{\"r\":4,\"b\":{{\"s\":\"ok\",\"d\":\"{big}\"}}}}}}]);\n")
    );
}

#[tokio::test]
async fn a_held_request_that_runs_out_closes_the_connection() {
    let (address, database) = start(ServerConfig {
        long_poll_hold: Duration::from_millis(300),
        ..ServerConfig::default()
    })
    .await;
    let (mut lp, _) = Lp::start(&address, "lp3").await;
    lp.poll(&[&request(1, "q", r#"{"p":"/a","h":""}"#)]).await;
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    assert_eq!(lp.poll(&[]).await, "<!-- -->");
    // Closed at once, well before an idle connection would be (twice the hold time).
    assert_eq!(database.lock().unwrap().listen_count(), 0);
    assert!(lp.poll(&[]).await.ends_with("pLPCommand('close');\n"));
}

#[tokio::test]
async fn a_connection_that_never_polls_is_closed() {
    let (address, _) = start(ServerConfig {
        long_poll_hold: Duration::from_millis(200),
        ..ServerConfig::default()
    })
    .await;
    let (mut lp, _) = Lp::start(&address, "lp4").await;
    tokio::time::sleep(Duration::from_millis(900)).await;
    assert!(lp.poll(&[]).await.ends_with("pLPCommand('close');\n"));
}

/// A step of the model: messages answered in one request, a write by another client while
/// a request is held, or a held request released by the next one.
#[derive(Debug, Clone)]
enum Step {
    Echo(usize),
    WriteWhileHeld,
    ReleasedByNext(usize),
}

fn step() -> impl proptest::strategy::Strategy<Value = Step> {
    use proptest::prelude::*;
    prop_oneof![
        (1usize..4).prop_map(Step::Echo),
        Just(Step::WriteWhileHeld),
        (1usize..3).prop_map(Step::ReleasedByNext),
    ]
}

/// The answer number and messages of a `pRTLPCB` answer.
fn read_packet(body: &str) -> (u64, Vec<String>) {
    let inner = body
        .strip_prefix("pRTLPCB(")
        .and_then(|rest| rest.strip_suffix(");\n"))
        .unwrap_or_else(|| panic!("{body:?}"));
    let (number, array) = inner.split_once(',').unwrap();
    let fireemu_core_database::Json::Array(items) =
        fireemu_adapter_database::json_text::parse(array).unwrap()
    else {
        panic!("{body:?}")
    };
    let messages = items
        .iter()
        .map(|m| {
            fireemu_adapter_database::json_text::render(
                m,
                fireemu_adapter_database::json_text::Style::Compact,
            )
        })
        .collect();
    (number.parse().unwrap(), messages)
}

proptest::proptest! {
    #![proptest_config(proptest::prelude::ProptestConfig::with_cases(24))]

    /// Every message reaches the client exactly once, in order, in answers numbered without
    /// gaps, whichever request carries it.
    #[test]
    fn answers_carry_every_message_once_in_order(steps in proptest::collection::vec(step(), 1..8)) {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let (address, _) = start(ServerConfig::default()).await;
            let (mut lp, _) = Lp::start(&address, "model").await;
            let mut answers = Vec::new();
            let mut expected = Vec::new();
            answers.push(lp.poll(&[&request(1, "q", r#"{"p":"/a","h":""}"#)]).await);
            expected.push(r#"{"t":"d","d":{"r":1,"b":{"s":"ok","d":{}}}}"#.to_owned());
            let mut r = 1;
            let mut value = 0;
            let echoes = |lp_r: &mut u64, n: usize, expected: &mut Vec<String>| -> Vec<String> {
                (0..n).map(|_| {
                    *lp_r += 1;
                    expected.push(format!(r#"{{"t":"d","d":{{"r":{lp_r},"b":{{"s":"ok","d":"e"}}}}}}"#));
                    request(*lp_r, "echo", r#"{"d":"e"}"#)
                }).collect()
            };
            for step in &steps {
                match step {
                    Step::Echo(n) => {
                        let messages = echoes(&mut r, *n, &mut expected);
                        let refs: Vec<&str> = messages.iter().map(String::as_str).collect();
                        answers.push(lp.poll(&refs).await);
                    }
                    Step::WriteWhileHeld => {
                        let target = lp.target(&[]);
                        let held = tokio::spawn({
                            let address = address.clone();
                            async move { get(&address, "GET", &target, "").await.2 }
                        });
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        value += 1;
                        get(&address, "PUT", "/a.json?ns=model", &value.to_string()).await;
                        expected.push(format!(r#"{{"t":"d","d":{{"b":{{"p":"a","d":{value}}},"a":"d"}}}}"#));
                        answers.push(held.await.unwrap());
                    }
                    Step::ReleasedByNext(n) => {
                        let target = lp.target(&[]);
                        let held = tokio::spawn({
                            let address = address.clone();
                            async move { get(&address, "GET", &target, "").await.2 }
                        });
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        let messages = echoes(&mut r, *n, &mut expected);
                        let refs: Vec<&str> = messages.iter().map(String::as_str).collect();
                        answers.push(lp.poll(&refs).await);
                        answers.push(held.await.unwrap());
                    }
                }
            }
            let mut packets: Vec<(u64, Vec<String>)> = answers.iter().map(|a| read_packet(a)).collect();
            packets.sort_by_key(|(n, _)| *n);
            let numbers: Vec<u64> = packets.iter().map(|(n, _)| *n).collect();
            assert_eq!(numbers, (1..=packets.len() as u64).collect::<Vec<_>>());
            let got: Vec<String> = packets.into_iter().flat_map(|(_, m)| m).collect();
            let canonical = |text: &String| {
                fireemu_adapter_database::json_text::render(
                    &fireemu_adapter_database::json_text::parse(text).unwrap(),
                    fireemu_adapter_database::json_text::Style::Compact,
                )
            };
            assert_eq!(got, expected.iter().map(canonical).collect::<Vec<_>>());
        });
    }
}

#[tokio::test]
async fn a_message_the_server_cannot_handle_ends_the_connection() {
    // The official emulator stops answering the connection; this server ends it, so the
    // SDK reconnects at once.
    let (address, database) = start(ServerConfig::default()).await;
    let (mut lp, _) = Lp::start(&address, "lp5").await;
    lp.poll(&[&request(1, "q", r#"{"p":"/a","h":""}"#)]).await;
    assert_eq!(database.lock().unwrap().listen_count(), 1);
    assert_eq!(lp.poll(&[&request(2, "g", "{}")]).await, "<!-- -->");
    assert_eq!(database.lock().unwrap().listen_count(), 0);
    assert!(lp.poll(&[]).await.ends_with("pLPCommand('close');\n"));
}

#[tokio::test]
async fn pushes_waiting_for_a_request_go_before_the_connections_own() {
    let (address, _) = start(ServerConfig::default()).await;
    let (mut lp, _) = Lp::start(&address, "lp6").await;
    lp.poll(&[&request(1, "q", r#"{"p":"/a","h":""}"#)]).await;
    // Another client writes while no request is held: the push waits in the outbox.
    get(&address, "PUT", "/a.json?ns=lp6", "1").await;
    assert_eq!(
        lp.poll(&[&request(2, "p", r#"{"p":"/a","d":2}"#)]).await,
        "pRTLPCB(2,[{\"t\":\"d\",\"d\":{\"b\":{\"p\":\"a\",\"d\":1},\"a\":\"d\"}},{\"t\":\"d\",\"d\":{\"b\":{\"p\":\"a\",\"d\":2},\"a\":\"d\"}},{\"t\":\"d\",\"d\":{\"r\":2,\"b\":{\"s\":\"ok\",\"d\":\"\"}}}]);\n"
    );
}
