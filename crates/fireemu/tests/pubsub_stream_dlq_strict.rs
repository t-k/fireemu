//! Seeded reference-model checks through the public REST surface, without new dependencies.
use fireemu_adapter_pubsub::{serve_pubsub, PubSubHandle, PubSubProfile};
use fireemu_core_pubsub::PubSubState;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::time::LogicalInstant;
use proptest::prelude::*;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct OwnedServer {
    address: std::net::SocketAddr,
    handle: PubSubHandle,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for OwnedServer {
    fn drop(&mut self) {
        self.handle.cancel_push_dispatcher();
        self.task.abort();
    }
}
impl OwnedServer {
    async fn new(seed: u64, profile: PubSubProfile, nanos: i128) -> Self {
        let handle = PubSubHandle::new(
            Arc::new(Mutex::new(PubSubState::new(seed))),
            Arc::new(Mutex::new(VirtualClock::new(LogicalInstant::from_nanos(
                nanos,
            )))),
            None,
        )
        .with_profile(profile);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let cloned = handle.clone();
        let task = tokio::spawn(async move {
            serve_pubsub(listener, cloned).await.unwrap();
        });
        Self {
            address,
            handle,
            task,
        }
    }
    async fn rest(&self, method: &str, path: &str, body: Value) -> (u16, Value, Vec<u8>) {
        let bytes = serde_json::to_vec(&body).unwrap();
        let mut stream = tokio::net::TcpStream::connect(self.address).await.unwrap();
        let header=format!("{method} {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",self.address,bytes.len());
        stream.write_all(header.as_bytes()).await.unwrap();
        stream.write_all(&bytes).await.unwrap();
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes).await.unwrap();
        let split = bytes.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        let code = std::str::from_utf8(&bytes[..split])
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let bytes = bytes[split + 4..].to_vec();
        (code, serde_json::from_slice(&bytes).unwrap(), bytes)
    }
}
proptest! {
    #![proptest_config(ProptestConfig {cases:32,rng_seed:proptest::test_runner::RngSeed::Fixed(0x20d1_0020),..ProptestConfig::default()})]
    #[test]
    fn strict_ack_codec_and_publication_shapes_match_delivery_model(seed in any::<u64>(),fraction in 0u32..1_000_000_000,attrs in prop::collection::btree_map("[a-z]{1,8}","[a-z0-9]{0,10}",0..5)) {
        let rt=tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        rt.block_on(async {
            for profile in [PubSubProfile::Strict,PubSubProfile::Emulator] {
                let server=OwnedServer::new(seed,profile,1_700_000_000_000_000_000+i128::from(fraction)).await;
                let topic="projects/demo-shapes/topics/topic";let sub="projects/demo-shapes/subscriptions/sub";
                assert_eq!(server.rest("PUT",&format!("/v1/{topic}"),json!({})).await.0,200);
                assert_eq!(server.rest("PUT",&format!("/v1/{sub}"),json!({"topic":topic,"ackDeadlineSeconds":10})).await.0,200);
                let (code,published,_)=server.rest("POST",&format!("/v1/{topic}:publish"),json!({"messages":[{"data":"eA==","attributes":attrs}]})).await;assert_eq!(code,200);
                let (_,pull,_)=server.rest("POST",&format!("/v1/{sub}:pull"),json!({"maxMessages":1})).await;
                let received=&pull["receivedMessages"][0];let first_ack=received["ackId"].as_str().unwrap();let message=&received["message"];
                assert_eq!(message["messageId"],published["messageIds"][0]);assert_eq!(message["data"],"eA==");
                let expected=serde_json::to_value(&attrs).unwrap();assert_eq!(message.get("attributes").cloned().unwrap_or_else(||json!({})),expected);
                if profile==PubSubProfile::Strict {assert_eq!(first_ack.len(),196);assert_eq!(message["messageId"].as_str().unwrap().len(),17);let timestamp=message["publishTime"].as_str().unwrap();let fractional=timestamp.split_once('.').map_or("",|(_,v)|v.strip_suffix('Z').unwrap());assert!([0,3,6,9].contains(&fractional.len()));if fraction%1000!=0 {assert_eq!(fractional.len(),9);} }
                assert_eq!(server.rest("POST",&format!("/v1/{sub}:modifyAckDeadline"),json!({"ackIds":[first_ack],"ackDeadlineSeconds":0})).await.0,200);
                let (_,again,_)=server.rest("POST",&format!("/v1/{sub}:pull"),json!({"maxMessages":1})).await;let second=&again["receivedMessages"][0];assert_eq!(second["message"]["messageId"],message["messageId"]);assert_ne!(second["ackId"],received["ackId"]);
                assert_eq!(server.rest("POST",&format!("/v1/{sub}:acknowledge"),json!({"ackIds":[second["ackId"]]})).await.0,200);
                let (_,empty,bytes)=server.rest("POST",&format!("/v1/{sub}:pull"),json!({"maxMessages":1})).await;
                assert_eq!(empty,if profile==PubSubProfile::Strict {json!({})}else{json!({"receivedMessages":[]})});if profile==PubSubProfile::Strict {assert_eq!(bytes,b"{}\n");}
            }
        });
    }
}
