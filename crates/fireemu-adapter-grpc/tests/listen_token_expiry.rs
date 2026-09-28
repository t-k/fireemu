//! How a held `Listen` stream ends when its ID token expires (AUTH-FS-CROSS stage 2).
//!
//! Production (two recordings, 2026-09-28) ended every held native stream with `INTERNAL`
//! (code 13) around its token's expiry, without waiting for a later commit: all six were gone
//! 35 seconds after expiry, and one was already gone a minute before it. When exactly the
//! stream closes is not settled by that evidence, so these tests only bound it: open while
//! the token is fresh, closed with `INTERNAL` once the session clock is 35 seconds past expiry,
//! with no commit at all. The official emulator never ends a stream for an expired token, and
//! neither does the `emulator` profile. Socket-free: the stream runs in-process on a pinned
//! session clock the tests move.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use fireemu_adapter_grpc::gateway::Gateway;
use fireemu_adapter_grpc::local::LocalBackend;
use fireemu_adapter_grpc::rules::{RulesEnforcer, TokenSemantics};
use fireemu_adapter_grpc::streams::{listen_stream, StreamContext};
use fireemu_core_auth::jwt::{encode_unsigned, TokenAcceptance};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthStore, NewUser};
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_rules::runtime::{LoadedRules, RulesetSlot};
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use fireemu_proto_firestore::google::firestore::v1 as pb;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Code, Status};

const PROJECT: &str = "demo-app";
const DB: &str = "projects/demo-app/databases/(default)";
const START: LogicalInstant = LogicalInstant::from_unix_seconds(1_788_004_860);
/// Firebase ID tokens live one hour.
const TOKEN_LIFE_SECONDS: i64 = 3600;
/// Production had ended every held stream by the probe 35 seconds after expiry.
const LATEST_END_AFTER_EXPIRY_SECONDS: i64 = 35;
/// Longer than the stream's own look at its deadline (at most a second apart).
const NOTICE: Duration = Duration::from_secs(3);
const RULES: &str = r"
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /held/{id} {
      allow read: if request.auth != null;
    }
  }
}";

/// Which profile the daemon would build the Firestore enforcer for.
#[derive(Clone, Copy)]
enum Profile {
    Strict,
    Emulator,
}

struct Held {
    backend: Arc<LocalBackend>,
    clock: Arc<Mutex<VirtualClock>>,
    input: Option<mpsc::Sender<Result<pb::ListenRequest, Status>>>,
    output: mpsc::Receiver<Result<pb::ListenResponse, Status>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

fn commit(backend: &LocalBackend, marker: &str) {
    backend
        .commit(&pb::CommitRequest {
            database: DB.to_owned(),
            writes: vec![pb::Write {
                operation: Some(pb::write::Operation::Update(pb::Document {
                    name: format!("{DB}/documents/held/doc"),
                    fields: [(
                        "marker".to_owned(),
                        pb::Value {
                            value_type: Some(pb::value::ValueType::StringValue(marker.to_owned())),
                        },
                    )]
                    .into_iter()
                    .collect(),
                    ..Default::default()
                })),
                ..Default::default()
            }],
            ..Default::default()
        })
        .unwrap();
}

impl Held {
    /// A stream opened at `START` with a token issued at `START`, listening to one document.
    async fn open(profile: Profile) -> Self {
        let auth = Arc::new(Mutex::new(AuthStore::new(
            PROJECT,
            SplitMix64::new(5),
            TotpPolicy::default(),
        )));
        let token = {
            let mut store = auth.lock().unwrap();
            let uid = store
                .create_user_with_id(NewUser::email("held@example.com"), Some("held"), START)
                .unwrap();
            encode_unsigned(&store.id_token_claims(&uid, None, START).unwrap())
        };
        let strict = matches!(profile, Profile::Strict);
        let clock = Arc::new(Mutex::new(VirtualClock::new(START)));
        let enforcer = RulesEnforcer::new(
            Arc::new(RulesetSlot::new(LoadedRules::from_source(RULES).unwrap())),
            auth,
            clock.clone(),
        )
        .with_token_acceptance(if strict {
            TokenAcceptance::Verified
        } else {
            TokenAcceptance::EmulatorMock
        })
        .with_token_semantics(TokenSemantics::Firestore)
        .with_listen_token_expiry(strict);
        let authorization = format!("Bearer {token}");
        let principal = enforcer
            .principal_from_authorization_for_project(Some(&authorization), PROJECT)
            .unwrap();
        let gateway = Arc::new(Gateway {
            enforce_limits: true,
            ctx: PlanningContext {
                edition: FirestoreEdition::Standard,
                api_mode: FirestoreApiMode::Native,
                policy: IndexValidationPolicy::Production,
            },
            indexes: IndexSet::default(),
        });
        let backend = Arc::new(LocalBackend::new(
            (*gateway).clone(),
            Arc::new(Mutex::new(VirtualClock::new(START))),
            7,
        ));
        commit(&backend, "initial");
        let context = StreamContext {
            local: backend.clone(),
            gateway,
            rules: Some(Arc::new(enforcer)),
            principal,
            authorization: Some(authorization),
            epoch: backend.epoch(),
            app_check: None,
        };
        let (input, requests) = mpsc::channel(8);
        let (responses, output) = mpsc::channel(16);
        let task = tokio::spawn(listen_stream(
            context,
            ReceiverStream::new(requests),
            responses,
        ));
        input
            .send(Ok(pb::ListenRequest {
                database: DB.to_owned(),
                target_change: Some(pb::listen_request::TargetChange::AddTarget(pb::Target {
                    target_id: 1,
                    target_type: Some(pb::target::TargetType::Documents(
                        pb::target::DocumentsTarget {
                            documents: vec![format!("{DB}/documents/held/doc")],
                        },
                    )),
                    ..Default::default()
                })),
                ..Default::default()
            }))
            .await
            .unwrap();
        let mut held = Self {
            backend,
            clock,
            input: Some(input),
            output,
            task: Some(task),
        };
        held.snapshot("initial").await;
        held
    }

    /// Moves the session clock to `seconds` after `START`.
    fn clock_at(&self, seconds: i64) {
        self.clock
            .lock()
            .unwrap()
            .advance_to(
                START
                    .checked_add(LogicalDuration::from_seconds(seconds))
                    .unwrap(),
            )
            .unwrap();
    }

    /// Waits up to `limit` for the next response; `None` when nothing came.
    async fn within(
        &mut self,
        limit: Duration,
    ) -> Option<Option<Result<pb::ListenResponse, Status>>> {
        tokio::time::timeout(limit, self.output.recv()).await.ok()
    }

    /// Reads one snapshot of the document up to its global `NO_CHANGE` boundary.
    async fn snapshot(&mut self, marker: &str) {
        use pb::listen_response::ResponseType as R;
        let mut seen = false;
        for _ in 0..8 {
            let response = self
                .within(Duration::from_secs(5))
                .await
                .expect("a snapshot within five seconds")
                .expect("the stream remains open")
                .expect("a response, not an error");
            match response.response_type.unwrap() {
                R::DocumentChange(change) => {
                    let doc = change.document.unwrap();
                    assert_eq!(
                        doc.fields["marker"].value_type,
                        Some(pb::value::ValueType::StringValue(marker.to_owned()))
                    );
                    seen = true;
                }
                R::TargetChange(change) if change.target_ids.is_empty() => {
                    assert!(seen, "boundary before the document");
                    return;
                }
                R::TargetChange(change) => assert!(change.cause.is_none()),
                other => panic!("unexpected Listen response {other:?}"),
            }
        }
        panic!("missing snapshot boundary");
    }

    /// The stream's end, waited for up to `limit`; the first response must be the end.
    async fn end_within(&mut self, limit: Duration) -> Option<Code> {
        match self.within(limit).await {
            None => None,
            Some(None) => panic!("the stream closed without a status"),
            Some(Some(Err(status))) => Some(status.code()),
            Some(Some(Ok(response))) => panic!("a response before the end: {response:?}"),
        }
    }
}

#[tokio::test]
async fn a_held_stream_stays_open_while_its_token_is_fresh() {
    let mut held = Held::open(Profile::Strict).await;
    held.clock_at(TOKEN_LIFE_SECONDS / 2);
    assert!(held.within(NOTICE).await.is_none());
    commit(&held.backend, "half-life");
    held.snapshot("half-life").await;
    held.input.take();
}

#[tokio::test]
async fn a_held_stream_ends_with_internal_after_its_token_expires_without_a_commit() {
    let mut held = Held::open(Profile::Strict).await;
    held.clock_at(TOKEN_LIFE_SECONDS + LATEST_END_AFTER_EXPIRY_SECONDS);
    assert_eq!(held.end_within(NOTICE).await, Some(Code::Internal));
    // Nothing follows the end.
    assert!(matches!(held.within(NOTICE).await, Some(None)));
}

/// A commit that meets the stream past its token's Firestore allowance ends it the same way,
/// not as an unauthenticated refresh with a target removal.
#[tokio::test]
async fn a_commit_after_expiry_meets_an_ended_stream_not_an_unauthenticated_one() {
    let mut held = Held::open(Profile::Strict).await;
    held.clock_at(TOKEN_LIFE_SECONDS + LATEST_END_AFTER_EXPIRY_SECONDS);
    commit(&held.backend, "late");
    assert_eq!(held.end_within(NOTICE).await, Some(Code::Internal));
}

#[tokio::test]
async fn the_emulator_profile_keeps_a_held_stream_past_its_token_expiry() {
    let mut held = Held::open(Profile::Emulator).await;
    held.clock_at(TOKEN_LIFE_SECONDS + LATEST_END_AFTER_EXPIRY_SECONDS);
    assert!(held.within(NOTICE).await.is_none());
    commit(&held.backend, "after-expiry");
    held.snapshot("after-expiry").await;
    held.input.take();
}
