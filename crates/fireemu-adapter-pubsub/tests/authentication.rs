//! The local strict authentication boundary and its production-recorded refusals.

use std::fmt::Write as _;
use std::sync::{Arc, Mutex};

use fireemu_adapter_pubsub::{serve_pubsub, PagingPolicy, PubSubHandle};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use fireemu_proto_pubsub::google::pubsub::v1 as pb;
use pb::publisher_client::PublisherClient;
use pb::subscriber_client::SubscriberClient;
use proptest::prelude::*;
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// Pull keeps its recorded legacy immediate-return field in these transport fixtures.
#[allow(deprecated)]
fn pull_request() -> pb::PullRequest {
    pb::PullRequest {
        subscription: SUBSCRIPTION.to_owned(),
        max_messages: 100,
        return_immediately: true,
    }
}

const MESSAGE: &str = "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.";
const TOPIC: &str = "projects/demo-app/topics/auth-topic";
const SUBSCRIPTION: &str = "projects/demo-app/subscriptions/auth-source";

struct Server {
    address: std::net::SocketAddr,
    policy: PagingPolicy,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Server {
    async fn start(policy: PagingPolicy) -> Self {
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(99))),
            Arc::new(Mutex::new(VirtualClock::new(
                LogicalInstant::from_unix_seconds(0),
            ))),
            None,
        )
        .with_paging_policy(policy);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            serve_pubsub(listener, handle).await.unwrap();
        });
        Self {
            address,
            policy,
            task,
        }
    }

    async fn channel(&self) -> tonic::transport::Channel {
        tonic::transport::Channel::from_shared(format!("http://{}", self.address))
            .unwrap()
            .connect()
            .await
            .unwrap()
    }

    async fn bootstrap(&self) {
        let mut publisher = PublisherClient::new(self.channel().await);
        publisher
            .create_topic(pb::Topic {
                name: TOPIC.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
        let mut subscriber = SubscriberClient::new(self.channel().await);
        subscriber
            .create_subscription(pb::Subscription {
                name: SUBSCRIPTION.to_owned(),
                topic: TOPIC.to_owned(),
                ..Default::default()
            })
            .await
            .unwrap();
    }

    async fn rest(&self, method: &str, path: &str, headers: &[&str], body: &[u8]) -> (u16, Value) {
        let mut authorization = String::new();
        for value in headers {
            write!(authorization, "Authorization: {value}\r\n").unwrap();
        }
        self.rest_with_headers(method, path, &authorization, body)
            .await
    }

    async fn rest_with_headers(
        &self,
        method: &str,
        path: &str,
        headers: &str,
        body: &[u8],
    ) -> (u16, Value) {
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let request = format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{headers}Connection: close\r\n\r\n", self.address, body.len());
        stream.write_all(request.as_bytes()).await.unwrap();
        stream.write_all(body).await.unwrap();
        let mut response = Vec::new();
        // Stop at the complete Content-Length frame. Reading past a completed refusal can
        // observe a reset when the server closes with the rejected request body unread.
        loop {
            if let Some(separator) = response.windows(4).position(|part| part == b"\r\n\r\n") {
                let headers = std::str::from_utf8(&response[..separator]).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .expect("JSON response has an exact Content-Length");
                if response.len() >= separator + 4 + length {
                    assert_eq!(response.len(), separator + 4 + length);
                    break;
                }
            }
            let mut chunk = [0; 4096];
            let count = stream
                .read(&mut chunk)
                .await
                .expect("complete HTTP response frame");
            assert_ne!(count, 0, "connection closed before a complete response");
            response.extend_from_slice(&chunk[..count]);
        }
        let separator = response
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        let status = std::str::from_utf8(&response[..separator])
            .unwrap()
            .lines()
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let body = &response[separator + 4..];
        if self.policy == PagingPolicy::Strict {
            assert_eq!(
                body.last(),
                Some(&b'\n'),
                "strict authentication responses keep the active profile"
            );
            assert_ne!(body.get(body.len() - 2), Some(&b'\n'));
        } else {
            let parsed: Value = serde_json::from_slice(body).unwrap();
            assert_eq!(body, serde_json::to_vec(&parsed).unwrap());
        }
        (
            status,
            serde_json::from_slice(&response[separator + 4..]).unwrap(),
        )
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn alternate_credential_carriers_are_present_even_when_empty_or_encoded() {
    // These input carriers were not observed in production. The assigned local contract
    // applies the recorded Publisher refusal envelope to each present credential.
    let carriers = [
        ("?access_token=unsupported", ""),
        ("?access_token=", ""),
        ("?access_token", ""),
        ("?%61ccess_token=unsupported", ""),
        ("?key=unsupported", ""),
        ("?key=", ""),
        ("?%6Bey=unsupported", ""),
        ("?unrelated=%ff&key=unsupported", ""),
        ("?key=first&key=second", ""),
        ("", "X-Goog-Api-Key: unsupported\r\n"),
        ("", "X-Goog-Api-Key: \r\n"),
        ("", "x-goog-api-key: first\r\nX-Goog-Api-Key: second\r\n"),
    ];
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let server = Server::start(policy).await;
        server.bootstrap().await;
        let mut publisher = PublisherClient::new(server.channel().await);
        for value in ["", "unsupported"] {
            let mut request = tonic::Request::new(pb::GetTopicRequest {
                topic: TOPIC.to_owned(),
            });
            request
                .metadata_mut()
                .insert("x-goog-api-key", value.parse().unwrap());
            let result = publisher.get_topic(request).await;
            if policy == PagingPolicy::Strict {
                let error = result.unwrap_err();
                assert_eq!(error.code(), tonic::Code::Unauthenticated);
                assert_eq!(error.message(), MESSAGE);
            } else {
                assert!(result.is_ok());
            }
        }
        for (query, headers) in carriers {
            for (method, path, payload, rpc) in [
                (
                    "GET",
                    format!("/v1/{TOPIC}{query}"),
                    b"{}".as_slice(),
                    "GetTopic",
                ),
                (
                    "PUT",
                    format!("/v1/projects/demo-app/topics/alternate-rejected{query}"),
                    b"{}".as_slice(),
                    "CreateTopic",
                ),
                (
                    "POST",
                    format!("/v1/{TOPIC}:publish{query}"),
                    b"{\"messages\":[{\"data\":\"eA==\"}]}".as_slice(),
                    "Publish",
                ),
            ] {
                let (status, body) = server
                    .rest_with_headers(method, &path, headers, payload)
                    .await;
                if policy == PagingPolicy::Strict {
                    assert_eq!(status, 401, "{query:?}: {rpc}");
                    assert_eq!(body, expected_rest(rpc));
                } else {
                    assert!(matches!(status, 200 | 409), "{query:?}: {rpc}: {body}");
                }
            }
        }
        let (status, _) = server
            .rest(
                "GET",
                "/v1/projects/demo-app/topics/alternate-rejected",
                &[],
                b"{}",
            )
            .await;
        assert_eq!(
            status,
            if policy == PagingPolicy::Strict {
                404
            } else {
                200
            }
        );
        let mut subscriber = SubscriberClient::new(server.channel().await);
        let messages = subscriber
            .pull(pull_request())
            .await
            .unwrap()
            .into_inner()
            .received_messages;
        assert_eq!(
            messages.len(),
            if policy == PagingPolicy::Strict {
                0
            } else {
                carriers.len()
            }
        );
        for query in [
            "?Access_token=x",
            "?access-token=x",
            "?key_suffix=x",
            "?api_key=x",
            "?value=access_token%3Dx",
            "?access+token=x",
        ] {
            assert_eq!(
                server
                    .rest("GET", &format!("/v1/{TOPIC}{query}"), &[], b"{}")
                    .await
                    .0,
                200
            );
        }
        let (status, _) = server
            .rest_with_headers(
                "PUT",
                "/v1/projects/demo-app/topics/invalid-alternate?access_token=",
                "",
                b"{",
            )
            .await;
        assert_eq!(
            status,
            if policy == PagingPolicy::Strict {
                401
            } else {
                400
            }
        );
    }
}

fn expected_rest(method: &str) -> Value {
    json!({"error": {"code": 401, "status": "UNAUTHENTICATED", "message": MESSAGE, "details": [{
        "@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": "CREDENTIALS_MISSING", "metadata": {
            "method": format!("google.pubsub.v1.Publisher.{method}"), "service": "pubsub.googleapis.com"
        }
    }]}})
}

fn authenticated<T>(message: T, values: &[&str]) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    for value in values {
        request
            .metadata_mut()
            .append("authorization", value.parse().unwrap());
    }
    request
}

#[tokio::test]
async fn recorded_rest_authentication_envelopes_and_header_near_misses_are_profile_scoped() {
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let server = Server::start(policy).await;
        server.bootstrap().await;
        for headers in [
            vec!["Bearer invalid"],
            vec![""],
            vec![" "],
            vec!["Bearer owner"],
            vec!["Basic invalid"],
            vec!["Firebase invalid"],
            vec!["invalid"],
            vec!["Bearer eyJhbGciOiJub25lIn0.e30."],
            vec!["Bearer eyJhbGciOiJSUzI1NiJ9.e30.altered"],
            vec!["", "Bearer invalid"],
            vec!["Bearer invalid", ""],
        ] {
            for (method, path, body, rpc) in [
                ("GET", format!("/v1/{TOPIC}"), b"{}".as_slice(), "GetTopic"),
                (
                    "PUT",
                    "/v1/projects/demo-app/topics/auth-rejected".to_owned(),
                    b"{}".as_slice(),
                    "CreateTopic",
                ),
                (
                    "POST",
                    format!("/v1/{TOPIC}:publish"),
                    b"{\"messages\":[{\"data\":\"eA==\"}]}".as_slice(),
                    "Publish",
                ),
            ] {
                let (status, body) = server.rest(method, &path, &headers, body).await;
                if policy == PagingPolicy::Strict {
                    assert_eq!(status, 401, "{headers:?}: {rpc}");
                    assert_eq!(body, expected_rest(rpc), "{headers:?}: {rpc}");
                } else {
                    assert!(matches!(status, 200 | 409), "{headers:?}: {rpc}: {body}");
                }
            }
        }
        let (status, _) = server
            .rest(
                "GET",
                "/v1/projects/demo-app/topics/auth-rejected",
                &[],
                b"{}",
            )
            .await;
        assert_eq!(
            status,
            if policy == PagingPolicy::Strict {
                404
            } else {
                200
            }
        );
        let mut subscriber = SubscriberClient::new(server.channel().await);
        let pulled = subscriber.pull(pull_request()).await.unwrap().into_inner();
        assert_eq!(
            pulled.received_messages.len(),
            if policy == PagingPolicy::Strict {
                0
            } else {
                11
            }
        );
    }
}

#[tokio::test]
async fn recorded_native_authentication_refusals_and_headerless_exception_cover_publisher_methods()
{
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let server = Server::start(policy).await;
        server.bootstrap().await;
        let mut publisher = PublisherClient::new(server.channel().await);
        for headers in [
            vec!["Bearer invalid"],
            vec![""],
            vec!["Bearer owner"],
            vec!["Bearer a.b.altered"],
            vec!["", "Bearer invalid"],
        ] {
            let get = publisher
                .get_topic(authenticated(
                    pb::GetTopicRequest {
                        topic: TOPIC.to_owned(),
                    },
                    &headers,
                ))
                .await;
            let create = publisher
                .create_topic(authenticated(
                    pb::Topic {
                        name: "projects/demo-app/topics/native-rejected".to_owned(),
                        ..Default::default()
                    },
                    &headers,
                ))
                .await;
            let publish = publisher
                .publish(authenticated(
                    pb::PublishRequest {
                        topic: TOPIC.to_owned(),
                        messages: vec![pb::PubsubMessage {
                            data: b"x".to_vec(),
                            ..Default::default()
                        }],
                    },
                    &headers,
                ))
                .await;
            if policy == PagingPolicy::Strict {
                for error in [get.unwrap_err(), create.unwrap_err(), publish.unwrap_err()] {
                    assert_eq!(error.code(), tonic::Code::Unauthenticated);
                    assert_eq!(error.message(), MESSAGE);
                }
            } else {
                assert!(get.is_ok());
                assert!(create.is_ok() || create.unwrap_err().code() == tonic::Code::AlreadyExists);
                assert!(publish.is_ok());
            }
        }
        assert!(publisher
            .get_topic(pb::GetTopicRequest {
                topic: TOPIC.to_owned()
            })
            .await
            .is_ok());
    }
}

#[tokio::test]
async fn authentication_precedes_body_validation_and_stream_opening() {
    for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
        let server = Server::start(policy).await;
        server.bootstrap().await;
        let (status, body) = server
            .rest(
                "PUT",
                "/v1/projects/demo-app/topics/invalid-json",
                &["Bearer invalid"],
                b"{",
            )
            .await;
        assert_eq!(
            status,
            if policy == PagingPolicy::Strict {
                401
            } else {
                400
            }
        );
        if policy == PagingPolicy::Strict {
            assert_eq!(body, expected_rest("CreateTopic"));
        }
        let mut publisher = PublisherClient::new(server.channel().await);
        let result = publisher
            .create_topic(authenticated(
                pb::Topic {
                    name: "invalid-name".to_owned(),
                    ..Default::default()
                },
                &["Bearer invalid"],
            ))
            .await;
        assert_eq!(
            result.unwrap_err().code(),
            if policy == PagingPolicy::Strict {
                tonic::Code::Unauthenticated
            } else {
                tonic::Code::InvalidArgument
            }
        );
        let mut subscriber = SubscriberClient::new(server.channel().await);
        for headers in [vec![], vec!["Bearer invalid"], vec![""]] {
            let frames = tokio_stream::iter([pb::StreamingPullRequest {
                subscription: SUBSCRIPTION.to_owned(),
                stream_ack_deadline_seconds: 10,
                ..Default::default()
            }]);
            let result = subscriber
                .streaming_pull(authenticated(frames, &headers))
                .await;
            if policy == PagingPolicy::Strict && !headers.is_empty() {
                let error = result.unwrap_err();
                assert_eq!(error.code(), tonic::Code::Unauthenticated);
                assert_eq!(error.message(), MESSAGE);
            } else {
                assert!(result.is_ok());
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]
    #[test]
    fn accepted_and_rejected_publications_match_header_presence_reference(trace in prop::collection::vec((0usize..4, "[a-z]{1,8}"), 1..12)) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
                let server = Server::start(policy).await;
                server.bootstrap().await;
                let mut publisher = PublisherClient::new(server.channel().await);
                let mut expected = Vec::new();
                for (count, payload) in &trace {
                    let headers = vec!["Bearer untrusted"; *count];
                    let result = publisher.publish(authenticated(pb::PublishRequest { topic: TOPIC.to_owned(), messages: vec![pb::PubsubMessage { data: payload.as_bytes().to_vec(), ..Default::default() }] }, &headers)).await;
                    let accepted = policy == PagingPolicy::Emulator || *count == 0;
                    assert_eq!(result.is_ok(), accepted);
                    if accepted { expected.push(payload.as_bytes().to_vec()); } else { assert_eq!(result.unwrap_err().code(), tonic::Code::Unauthenticated); }
                }
                let mut subscriber = SubscriberClient::new(server.channel().await);
                let actual = subscriber.pull(pull_request()).await.unwrap().into_inner().received_messages.into_iter().map(|message| message.message.unwrap().data).collect::<Vec<_>>();
                assert_eq!(actual, expected);
            }
        });
    }

    #[test]
    fn credential_carrier_publications_match_presence_reference(trace in prop::collection::vec((0usize..8, "[a-z]{1,8}"), 1..12)) {
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        runtime.block_on(async {
            for policy in [PagingPolicy::Strict, PagingPolicy::Emulator] {
                let server = Server::start(policy).await;
                server.bootstrap().await;
                let mut expected = Vec::new();
                for (carrier, payload) in &trace {
                    let (query, headers) = match carrier {
                        0 => ("", ""),
                        1 => ("?access_token=x", ""),
                        2 => ("?key=x", ""),
                        3 => ("", "X-Goog-Api-Key: x\r\n"),
                        4 => ("?%61ccess_token=x", ""),
                        5 => ("?key=", ""),
                        6 => ("?unrelated=x", ""),
                        _ => ("", "X-Goog-Api-Key-Suffix: x\r\n"),
                    };
                    let body = serde_json::to_vec(&json!({"messages":[{"data":base64::Engine::encode(&base64::engine::general_purpose::STANDARD,payload.as_bytes())}]})).unwrap();
                    let (status, response) = server.rest_with_headers("POST", &format!("/v1/{TOPIC}:publish{query}"), headers, &body).await;
                    let accepted = policy == PagingPolicy::Emulator || matches!(carrier, 0 | 6 | 7);
                    if accepted { assert_eq!(status, 200); expected.push(payload.as_bytes().to_vec()); }
                    else { assert_eq!(status, 401); assert_eq!(response, expected_rest("Publish")); }
                }
                let mut subscriber = SubscriberClient::new(server.channel().await);
                let actual = subscriber.pull(pull_request()).await.unwrap().into_inner().received_messages.into_iter().map(|message| message.message.unwrap().data).collect::<Vec<_>>();
                assert_eq!(actual, expected);
            }
        });
    }
}
