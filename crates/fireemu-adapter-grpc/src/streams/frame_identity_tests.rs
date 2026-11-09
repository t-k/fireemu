//! Frame identity of the `Listen` producer.
//!
//! Generated scenarios drive the real `listen_stream` over a bounded channel: targets of several
//! kinds are added, removed, resumed and listened to once, while commits land at chosen points of a
//! partly read snapshot. Each scenario's transcript (client actions interleaved with every frame
//! received) is hashed, and the digests are compared with `tests/fixtures/listen_frame_identity.txt`,
//! which was recorded from the producer before the queued snapshot rows were compacted. Any change
//! to a frame, its content or its position relative to a write fails the comparison.
//!
//! Recording: `FIREEMU_LISTEN_FRAMES_RECORD=1 cargo nextest run -p fireemu-adapter-grpc --lib
//! frame_identity`. Scheduling is deterministic: a current-thread runtime, requests sent only when
//! the stream is idle, and commits only while the producer is blocked on a full channel or idle.

use super::*;
use fireemu_core_firestore::index::{IndexSet, IndexValidationPolicy, PlanningContext};
use fireemu_core_firestore::store::WriteOp;
use fireemu_core_firestore::value::Value;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::edition::{FirestoreApiMode, FirestoreEdition};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use prost::Message;
use sha2::{Digest, Sha256};

const SCENARIOS: u64 = 160;
const DATABASE: &str = "projects/demo-app/databases/(default)";
const GOLDEN: &str = "tests/fixtures/listen_frame_identity.txt";

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0 >> 33
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

fn context(strict: bool) -> (StreamContext, Arc<std::sync::Mutex<VirtualClock>>) {
    let gateway = Gateway {
        enforce_limits: true,
        ctx: PlanningContext {
            edition: FirestoreEdition::Standard,
            api_mode: FirestoreApiMode::Native,
            policy: if strict {
                IndexValidationPolicy::Production
            } else {
                IndexValidationPolicy::Emulator
            },
        },
        indexes: IndexSet::default(),
    };
    let clock = Arc::new(std::sync::Mutex::new(VirtualClock::new(
        LogicalInstant::UNIX_EPOCH,
    )));
    let local = Arc::new(LocalBackend::new(gateway.clone(), Arc::clone(&clock), 7));
    (
        StreamContext {
            local: local.clone(),
            gateway: Arc::new(gateway),
            rules: None,
            principal: Principal::Owner,
            authorization: None,
            epoch: local.epoch(),
            app_check: None,
        },
        clock,
    )
}

fn document_path(relative: &str) -> DocumentPath {
    crate::encode::decode_document_name(&format!("{DATABASE}/documents/{relative}")).unwrap()
}

fn set_write(relative: &str, k: i64, v: &str) -> Write {
    Write {
        op: WriteOp::Set {
            path: document_path(relative),
            fields: BTreeMap::from([
                ("k".to_owned(), Value::Integer(k)),
                ("v".to_owned(), Value::String(v.to_owned())),
            ]),
            update_mask: None,
        },
        precondition: None,
        transforms: Vec::new(),
    }
}

fn delete_write(relative: &str) -> Write {
    Write {
        op: WriteOp::Delete {
            path: document_path(relative),
        },
        precondition: None,
        transforms: Vec::new(),
    }
}

/// What a target listens to.
#[derive(Clone, Debug)]
enum Spec {
    Collection,
    KEquals(i64),
    KOrdered {
        descending: bool,
        limit: Option<i32>,
    },
    Documents(Vec<u64>),
}

fn spec(rng: &mut Lcg) -> Spec {
    match rng.below(4) {
        0 => Spec::Collection,
        1 => Spec::KEquals(i64::try_from(rng.below(4)).unwrap()),
        2 => Spec::KOrdered {
            descending: rng.chance(50),
            limit: rng
                .chance(50)
                .then(|| i32::try_from(rng.below(12) + 1).unwrap()),
        },
        _ => Spec::Documents((0..=rng.below(3)).map(|_| rng.below(48)).collect()),
    }
}

fn target(id: i32, spec: &Spec) -> pb::Target {
    use pb::structured_query as sq;
    let k = || sq::FieldReference {
        field_path: "k".to_owned(),
    };
    let target_type = if let Spec::Documents(indexes) = spec {
        pb::target::TargetType::Documents(pb::target::DocumentsTarget {
            documents: indexes
                .iter()
                .map(|index| format!("{DATABASE}/documents/c/d{index:03}"))
                .collect(),
        })
    } else {
        let mut query = pb::StructuredQuery {
            from: vec![sq::CollectionSelector {
                collection_id: "c".to_owned(),
                all_descendants: false,
            }],
            ..Default::default()
        };
        match spec {
            Spec::KEquals(value) => {
                query.r#where = Some(sq::Filter {
                    filter_type: Some(sq::filter::FilterType::FieldFilter(sq::FieldFilter {
                        field: Some(k()),
                        op: sq::field_filter::Operator::Equal as i32,
                        value: Some(pb::Value {
                            value_type: Some(pb::value::ValueType::IntegerValue(*value)),
                        }),
                    })),
                });
            }
            Spec::KOrdered { descending, limit } => {
                query.order_by = vec![sq::Order {
                    field: Some(k()),
                    direction: if *descending {
                        sq::Direction::Descending as i32
                    } else {
                        sq::Direction::Ascending as i32
                    },
                }];
                query.limit = *limit;
            }
            _ => {}
        }
        pb::target::TargetType::Query(pb::target::QueryTarget {
            parent: format!("{DATABASE}/documents"),
            query_type: Some(pb::target::query_target::QueryType::StructuredQuery(query)),
        })
    };
    pb::Target {
        target_id: id,
        target_type: Some(target_type),
        ..Default::default()
    }
}

fn add_request(target: pb::Target) -> pb::ListenRequest {
    pb::ListenRequest {
        database: DATABASE.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::AddTarget(target)),
        ..Default::default()
    }
}

fn remove_request(id: i32) -> pb::ListenRequest {
    pb::ListenRequest {
        database: DATABASE.to_owned(),
        target_change: Some(pb::listen_request::TargetChange::RemoveTarget(id)),
        ..Default::default()
    }
}

/// Per-kind frame counts, so the corpus is shown to reach every frame kind it should.
#[derive(Default, Debug)]
struct Coverage {
    document_change: usize,
    document_removed: usize,
    document_delete: usize,
    filter: usize,
    add: usize,
    current: usize,
    no_change: usize,
    remove: usize,
    reset: usize,
    errors: usize,
    largest_snapshot: usize,
}

struct Transcript {
    hash: Sha256,
    frames: usize,
    /// Strict tokens carry random bytes: a token is hashed as the index of its first sighting, so
    /// which frames share a token is still compared.
    tokens: Vec<Vec<u8>>,
}

impl Transcript {
    fn action(&mut self, text: &str) {
        self.hash.update(b"A");
        self.hash.update(text.as_bytes());
        self.hash.update(b"\n");
    }

    fn frame(
        &mut self,
        frame: &Result<pb::ListenResponse, Status>,
        coverage: &mut Coverage,
        token: &mut Option<Vec<u8>>,
    ) {
        use pb::listen_response::ResponseType as R;
        use pb::target_change::TargetChangeType as Kind;
        self.frames += 1;
        match frame {
            Ok(response) => {
                self.hash.update(b"F");
                let mut canonical = response.clone();
                if let Some(pb::listen_response::ResponseType::TargetChange(change)) =
                    canonical.response_type.as_mut()
                {
                    if !change.resume_token.is_empty() {
                        let index = self
                            .tokens
                            .iter()
                            .position(|known| *known == change.resume_token)
                            .unwrap_or_else(|| {
                                self.tokens.push(change.resume_token.clone());
                                self.tokens.len() - 1
                            });
                        change.resume_token = format!("token#{index}").into_bytes();
                    }
                }
                self.hash.update(canonical_bytes(&canonical));
                match response.response_type.as_ref() {
                    Some(R::DocumentChange(change)) if change.target_ids.is_empty() => {
                        coverage.document_removed += 1;
                    }
                    Some(R::DocumentChange(_)) => coverage.document_change += 1,
                    Some(R::DocumentDelete(_) | R::DocumentRemove(_)) => {
                        coverage.document_delete += 1;
                    }
                    Some(R::Filter(_)) => coverage.filter += 1,
                    Some(R::TargetChange(change)) => {
                        match Kind::try_from(change.target_change_type) {
                            Ok(Kind::Add) => coverage.add += 1,
                            Ok(Kind::Current) => coverage.current += 1,
                            Ok(Kind::NoChange) => {
                                coverage.no_change += 1;
                                if change.target_ids.is_empty() && !change.resume_token.is_empty() {
                                    *token = Some(change.resume_token.clone());
                                }
                            }
                            Ok(Kind::Remove) => coverage.remove += 1,
                            Ok(Kind::Reset) => coverage.reset += 1,
                            Err(_) => {}
                        }
                    }
                    None => {}
                }
            }
            Err(status) => {
                coverage.errors += 1;
                self.hash.update(b"E");
                self.hash.update((status.code() as i32).to_be_bytes());
                self.hash.update(status.message().as_bytes());
            }
        }
        self.hash.update(b"\n");
    }
}

/// The frame's encoding with document fields in key order (prost encodes a map in `HashMap`
/// order, which differs between runs). The fields here hold scalars only.
fn canonical_bytes(response: &pb::ListenResponse) -> Vec<u8> {
    let mut response = response.clone();
    let mut fields = Vec::new();
    if let Some(pb::listen_response::ResponseType::DocumentChange(change)) =
        response.response_type.as_mut()
    {
        if let Some(document) = change.document.as_mut() {
            let mut sorted = std::mem::take(&mut document.fields)
                .into_iter()
                .collect::<Vec<_>>();
            sorted.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in sorted {
                fields.extend_from_slice(key.as_bytes());
                fields.push(0);
                fields.extend_from_slice(&value.encode_to_vec());
                fields.push(0);
            }
        }
    }
    let mut bytes = response.encode_to_vec();
    bytes.extend_from_slice(&fields);
    bytes
}

/// The next frame, or `None` once the producer is idle (or gone).
async fn next_frame(
    outbound: &mut mpsc::Receiver<Result<pb::ListenResponse, Status>>,
) -> Option<Result<pb::ListenResponse, Status>> {
    for _ in 0..256 {
        match outbound.try_recv() {
            Ok(frame) => return Some(frame),
            Err(mpsc::error::TryRecvError::Empty) => tokio::task::yield_now().await,
            Err(mpsc::error::TryRecvError::Disconnected) => return None,
        }
    }
    None
}

#[allow(clippy::too_many_lines)]
async fn scenario(seed: u64, strict: bool, coverage: &mut Coverage) -> (String, usize) {
    let mut rng = Lcg(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ u64::from(strict));
    let (ctx, clock) = context(strict);
    let local = Arc::clone(&ctx.local);
    let parent = database_parent(DATABASE).unwrap();
    let mut transcript = Transcript {
        hash: Sha256::new(),
        frames: 0,
        tokens: Vec::new(),
    };
    // Large snapshots in a quarter of the scenarios, so a refresh spans many channel slots.
    let initial = if rng.chance(25) {
        40 + rng.below(220)
    } else {
        rng.below(24)
    };
    coverage.largest_snapshot = coverage
        .largest_snapshot
        .max(usize::try_from(initial).unwrap());
    let mut seed_writes = vec![set_write("other/x", 0, "x")];
    for index in 0..initial {
        seed_writes.push(set_write(
            &format!("c/d{index:03}"),
            i64::try_from(rng.below(4)).unwrap(),
            "v0",
        ));
    }
    for chunk in seed_writes.chunks(100) {
        local
            .commit_writes(&parent, chunk, &|_, _, _| Ok(()))
            .unwrap();
    }
    transcript.action(&format!("seed {initial}"));
    let capacity = 1 + usize::try_from(rng.below(3)).unwrap();
    let (requests, inbound) = mpsc::channel(4);
    let (responses, mut outbound) = mpsc::channel(capacity);
    let stream = tokio::spawn(listen_stream(
        ctx,
        tokio_stream::wrappers::ReceiverStream::new(inbound),
        responses,
    ));
    let mut active: BTreeMap<i32, Spec> = BTreeMap::new();
    let mut removed: Vec<(i32, Spec)> = Vec::new();
    let mut token: Option<Vec<u8>> = None;
    let mut next_id = 1;
    let mut version = 0_u64;
    let mut ended = false;
    let steps = 4 + rng.below(10);
    for _ in 0..steps {
        if ended {
            break;
        }
        match rng.below(10) {
            // Add a target (sometimes `once`), after draining so the request meets an idle stream.
            0..=2 => {
                while let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
                let spec = spec(&mut rng);
                let mut add = target(next_id, &spec);
                add.once = rng.chance(10);
                transcript.action(&format!("add {next_id} {spec:?} once={}", add.once));
                if requests.send(Ok(add_request(add))).await.is_err() {
                    ended = true;
                    continue;
                }
                active.insert(next_id, spec);
                next_id += 1;
                // The first frame shows the request was consumed before any later commit.
                if let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
            }
            // Remove a target.
            3 => {
                let Some((&id, _)) = active.iter().nth(
                    usize::try_from(rng.below(u64::try_from(active.len().max(1)).unwrap()))
                        .unwrap(),
                ) else {
                    continue;
                };
                while let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
                transcript.action(&format!("remove {id}"));
                if requests.send(Ok(remove_request(id))).await.is_err() {
                    ended = true;
                    continue;
                }
                removed.push((id, active.remove(&id).unwrap()));
                if let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
            }
            // Resume a removed target from the latest global token, with or without a count.
            4 => {
                let (Some((id, spec)), Some(resume)) = (removed.pop(), token.clone()) else {
                    continue;
                };
                while let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
                let mut add = target(id, &spec);
                // Sometimes bytes this daemon never issued: the target is reset and replayed.
                let resume = if rng.chance(20) {
                    b"not-a-token".to_vec()
                } else {
                    resume
                };
                add.resume_type = Some(pb::target::ResumeType::ResumeToken(resume));
                add.expected_count = rng.chance(50).then(|| i32::try_from(rng.below(6)).unwrap());
                transcript.action(&format!(
                    "resume {id} {spec:?} expected={:?}",
                    add.expected_count
                ));
                if requests.send(Ok(add_request(add))).await.is_err() {
                    ended = true;
                    continue;
                }
                active.insert(id, spec);
                if let Some(frame) = next_frame(&mut outbound).await {
                    transcript.frame(&frame, coverage, &mut token);
                }
            }
            // Commit while the producer may be blocked in the middle of a refresh.
            5..=7 => {
                let mut writes = Vec::new();
                for _ in 0..=rng.below(4) {
                    let index = rng.below(48);
                    let relative = format!("c/d{index:03}");
                    if rng.chance(30) {
                        writes.push(delete_write(&relative));
                    } else {
                        version += 1;
                        writes.push(set_write(
                            &relative,
                            i64::try_from(rng.below(4)).unwrap(),
                            &format!("v{version}"),
                        ));
                    }
                }
                // One commit per path: the batch must not write a document twice.
                let mut written = BTreeSet::new();
                writes.retain(|write| {
                    let path = match &write.op {
                        WriteOp::Set { path, .. } | WriteOp::Delete { path } => path.clone(),
                        WriteOp::Verify { .. } => unreachable!(),
                    };
                    written.insert(path)
                });
                clock
                    .lock()
                    .unwrap()
                    .advance(LogicalDuration::from_millis(5))
                    .unwrap();
                let result = local.commit_writes(&parent, &writes, &|_, _, _| Ok(()));
                transcript.action(&format!("commit {} {}", writes.len(), result.is_ok()));
            }
            // Read a few frames.
            _ => {
                let count = 1 + rng.below(40);
                transcript.action(&format!("read {count}"));
                for _ in 0..count {
                    match next_frame(&mut outbound).await {
                        Some(frame) => transcript.frame(&frame, coverage, &mut token),
                        None => break,
                    }
                }
            }
        }
        if stream.is_finished() && outbound.is_empty() {
            ended = true;
        }
    }
    while let Some(frame) = next_frame(&mut outbound).await {
        transcript.frame(&frame, coverage, &mut token);
    }
    transcript.action("close");
    drop(requests);
    drop(outbound);
    stream.await.unwrap();
    let digest = transcript.hash.finalize();
    (
        digest.iter().fold(String::new(), |mut text, byte| {
            use std::fmt::Write as _;
            let _ = write!(text, "{byte:02x}");
            text
        }),
        transcript.frames,
    )
}

#[tokio::test(flavor = "current_thread")]
async fn listen_frames_match_the_recorded_transcripts() {
    let mut coverage = Coverage::default();
    let mut lines = Vec::new();
    for seed in 0..SCENARIOS {
        for strict in [false, true] {
            let (digest, frames) = scenario(seed, strict, &mut coverage).await;
            lines.push(format!(
                "{seed} {} {frames} {digest}",
                if strict { "strict" } else { "emulator" }
            ));
        }
    }
    let actual = lines.join("\n") + "\n";
    let golden = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(GOLDEN);
    if std::env::var_os("FIREEMU_LISTEN_FRAMES_RECORD").is_some() {
        std::fs::write(&golden, &actual).unwrap();
    }
    // Every frame kind the producer emits for these targets is reached by the corpus.
    assert!(coverage.document_change > 1000, "{coverage:?}");
    assert!(coverage.largest_snapshot >= 200, "{coverage:?}");
    for count in [
        coverage.document_removed,
        coverage.document_delete,
        coverage.filter,
        coverage.add,
        coverage.current,
        coverage.no_change,
        coverage.remove,
        coverage.reset,
    ] {
        assert!(count > 0, "{coverage:?}");
    }
    let expected = std::fs::read_to_string(&golden).unwrap();
    for (line, (actual, expected)) in actual.lines().zip(expected.lines()).enumerate() {
        assert_eq!(actual, expected, "scenario line {line}");
    }
    assert_eq!(actual.lines().count(), expected.lines().count());
}
