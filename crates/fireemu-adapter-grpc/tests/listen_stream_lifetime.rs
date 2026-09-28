//! How long a held `Listen` stream lives (AUTH-FS-CROSS stage 2).
//!
//! Production ended every held native stream with `INTERNAL` (code 13) 3,600.17-3,600.19 s after
//! it opened, in all twelve streams of the two packet-v7 recordings (2026-09-28); each token had
//! been issued seconds before its stream, so its exp fell 0.65-2.67 s earlier and does not
//! explain the close. A stream opened with an older token was not observed, so the strict
//! profile invents no close at the token's exp. The official emulator never ends a stream this
//! way, and neither does the `emulator` profile. Socket-free: the stream runs in-process on a
//! pinned session clock the tests move.

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
/// Production closed a held stream 3,600 s after it opened.
const LIFETIME_SECONDS: i64 = 3600;
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
    /// A stream opened `opened_after` seconds after `START` with a token issued at `START`,
    /// listening to one document.
    async fn open(profile: Profile, opened_after: i64) -> Self {
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
        .with_listen_stream_lifetime(strict);
        clock
            .lock()
            .unwrap()
            .advance_to(
                START
                    .checked_add(LogicalDuration::from_seconds(opened_after))
                    .unwrap(),
            )
            .unwrap();
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
async fn a_held_stream_stays_open_until_its_hour_is_up() {
    let mut held = Held::open(Profile::Strict, 0).await;
    held.clock_at(LIFETIME_SECONDS - 1);
    assert!(held.within(NOTICE).await.is_none());
    commit(&held.backend, "last-second");
    held.snapshot("last-second").await;
    held.input.take();
}

#[tokio::test]
async fn a_held_stream_ends_with_internal_once_its_hour_is_up_without_a_commit() {
    let mut held = Held::open(Profile::Strict, 0).await;
    held.clock_at(LIFETIME_SECONDS + 1);
    assert_eq!(held.end_within(NOTICE).await, Some(Code::Internal));
    // Nothing follows the end.
    assert!(matches!(held.within(NOTICE).await, Some(None)));
}

/// A commit that meets the stream past its hour ends it the same way, not with a snapshot.
#[tokio::test]
async fn a_commit_after_the_hour_meets_an_ended_stream() {
    let mut held = Held::open(Profile::Strict, 0).await;
    held.clock_at(LIFETIME_SECONDS + 1);
    commit(&held.backend, "late");
    assert_eq!(held.end_within(NOTICE).await, Some(Code::Internal));
}

/// The hour counts from the stream's opening, not from the token's issue: a stream opened ten
/// minutes after its token outlives the token's exp (nothing closes it there; a stream opened
/// with an older token was not observed in production).
#[tokio::test]
async fn the_hour_counts_from_the_opening_and_the_tokens_exp_closes_nothing() {
    let opened = 600;
    let mut held = Held::open(Profile::Strict, opened).await;
    held.clock_at(LIFETIME_SECONDS + 20);
    assert!(held.within(NOTICE).await.is_none());
    held.clock_at(opened + LIFETIME_SECONDS - 1);
    assert!(held.within(NOTICE).await.is_none());
    held.clock_at(opened + LIFETIME_SECONDS + 1);
    assert_eq!(held.end_within(NOTICE).await, Some(Code::Internal));
}

#[tokio::test]
async fn the_emulator_profile_keeps_a_held_stream_past_its_hour() {
    let mut held = Held::open(Profile::Emulator, 0).await;
    held.clock_at(LIFETIME_SECONDS + 1);
    assert!(held.within(NOTICE).await.is_none());
    held.input.take();
}
