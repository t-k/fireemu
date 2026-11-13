//! Replays the four production recordings of the REST negative cache (packet `PUBSUB-NEGCACHE`,
//! runs 50a305aa54d1, 331317b47c44, 903d638614a1 and 70602e8b29e0) through the model and compares every request's answer
//! class with what production did: a fast 404 (a hit) or a forwarded answer. The recordings are
//! `conformance/pubsub-negcache/recordings/run-{1,2,3,4}.json` (masked).
//!
//! Every request of every cell must match, except the recorded divergences below. Each one is a
//! question the recordings leave open (`rule.md`), so it is named here and checked exactly: a change
//! to the model that moves a divergence, in either direction, fails this test.

use fireemu_core_pubsub::rest_negative_cache::{
    ConnectionId, RestNegativeCache, RestOutcome, RestRequest, RestResource,
};
use fireemu_core_types::time::{LogicalDuration, LogicalInstant};
use serde_json::Value;

fn load(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../conformance/pubsub-negcache/recordings/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
    let document: Value = serde_json::from_str(&text).unwrap();
    document["requests"].as_array().unwrap().clone()
}

fn instant(millis: f64) -> LogicalInstant {
    #[allow(clippy::cast_possible_truncation)]
    let nanos = (millis * 1_000_000.0).round() as i128;
    LogicalInstant::from_unix_seconds(1_800_000_000)
        .checked_add(LogicalDuration::from_nanos(nanos))
        .unwrap()
}

fn connection(index: u16) -> ConnectionId {
    ConnectionId::new(u64::from(index))
}

/// One divergence: (cell, step).
type Divergence = (String, u64);

/// Replays one run and returns every request whose predicted class differs from the recorded one.
fn replay(requests: &[Value]) -> (usize, Vec<Divergence>) {
    let mut cache = RestNegativeCache::default();
    let mut checked = 0;
    let mut divergences = Vec::new();
    let mut fresh = 1000_u16;
    let mut current_cell = String::new();
    for request in requests {
        let cell = request["cell"].as_str().unwrap();
        if cell != current_cell {
            // Each cell starts on its own connection; a new entry never carries over.
            cell.clone_into(&mut current_cell);
            fresh += 1;
        }
        let conn = if request["conn"] == "fresh" {
            fresh += 1;
            connection(fresh)
        } else {
            connection(fresh)
        };
        let started = request["startedAtMs"].as_f64().unwrap();
        let status = request["status"].as_u64().unwrap();
        let observed_hit = status == 404 && request["latency"] == "fast";
        let method = request["method"].as_str().unwrap();
        let full_path = request["path"].as_str().unwrap();
        let (path, query) = full_path.split_once('?').unwrap_or((full_path, ""));
        let resource = RestResource::parse_path(path);
        let kind = match method {
            "GET" => RestRequest::Get,
            "PATCH" => RestRequest::Patch,
            "DELETE" => RestRequest::Delete,
            _ => RestRequest::Other,
        };
        let consulted = query.is_empty().then_some(resource.as_ref()).flatten();
        let predicted_hit =
            consulted.is_some_and(|r| cache.serves(conn, r, kind, instant(started)));
        checked += 1;
        if predicted_hit != observed_hit {
            divergences.push((cell.to_owned(), request["step"].as_u64().unwrap()));
        }
        // The backend saw the request when production forwarded it (a hit never reached it) and the
        // model did not answer it either (as the adapter does).
        if let Some(resource) = consulted {
            if !predicted_hit && !observed_hit {
                let outcome = match status {
                    200..=299 => RestOutcome::Success,
                    404 => RestOutcome::NotFound,
                    _ => RestOutcome::Other,
                };
                cache.observe(conn, resource, kind, instant(started), outcome);
            }
        }
    }
    (checked, divergences)
}

fn names(list: &[(&str, u64)]) -> Vec<Divergence> {
    list.iter().map(|&(c, s)| (c.to_owned(), s)).collect()
}

#[test]
fn run_1_matches_the_model_except_the_recorded_open_questions() {
    let (checked, divergences) = replay(&load("run-1.json"));
    assert_eq!(checked, 155);
    assert_eq!(
        divergences,
        names(&[
            // N1, a never-created name: a miss at 3.0 s that the model predicts as a hit.
            ("N1", 1),
            // A2, an entry armed by a DELETE 404: production answered from the cache, the model
            // does not arm on a DELETE.
            ("A2", 2),
        ]),
        "{divergences:?}"
    );
}

#[test]
fn run_2_matches_the_model_except_the_recorded_open_questions() {
    let (checked, divergences) = replay(&load("run-2.json"));
    assert_eq!(checked, 155);
    assert_eq!(
        divergences,
        names(&[
            ("N1", 1),
            // N1 again: a miss at 9.0 s in this run only (the other run hit).
            ("N1", 3),
            ("A2", 2),
            ("A2", 3),
        ]),
        "{divergences:?}"
    );
}

#[test]
fn run_3_matches_the_model_except_the_recorded_open_questions() {
    let (checked, divergences) = replay(&load("run-3.json"));
    assert_eq!(checked, 177);
    assert_eq!(
        divergences,
        names(&[
            // DELETE 404 arming remains open.
            ("DA4", 4),
            ("DA4", 5),
            // Activation for never-created names remains open.
            ("N1a", 1),
            ("N1b", 1),
            ("N1c", 1),
            ("N1d", 1),
            ("N1e", 1),
            ("N1f", 1),
            ("N1g", 1),
            ("N1h", 1),
            ("N1i", 1),
            ("N1j", 1),
            ("N1k", 1),
            ("N1l", 1),
            ("N1m", 1),
            ("N1n", 1),
            ("N1o", 1),
            ("N1p", 1),
            // Recent-200 exemption at four seconds remains open.
            ("E200-4b", 5),
            ("E200-4b", 6),
            // Recent-200 exemption at 13 seconds remains open.
            ("E200-13b", 5),
            ("E200-13b", 6),
            // The window edge varies within the recorded band.
            ("W25a", 2),
            ("W25b", 2),
            ("W30a", 2),
            ("W30b", 2),
            ("W40a", 2),
            ("W40a", 3),
            ("W45b", 2),
            ("W45b", 3),
            ("W50b", 2),
            ("W50b", 3),
        ]),
        "{divergences:?}"
    );
}

#[test]
fn run_4_matches_the_model_except_the_recorded_open_questions() {
    let (checked, divergences) = replay(&load("run-4.json"));
    assert_eq!(checked, 177);
    assert_eq!(
        divergences,
        names(&[
            // Activation for never-created names remains open.
            ("N1a", 1),
            ("N1b", 1),
            ("N1c", 1),
            ("N1d", 1),
            ("N1e", 1),
            ("N1f", 1),
            ("N1g", 1),
            ("N1h", 1),
            ("N1i", 1),
            ("N1j", 1),
            ("N1k", 1),
            ("N1l", 1),
            ("N1m", 1),
            ("N1n", 1),
            ("N1o", 1),
            ("N1p", 1),
            // Recent-200 exemption at 13 seconds remains open.
            ("E200-13a", 5),
            ("E200-13a", 6),
            ("E200-13b", 5),
            ("E200-13b", 6),
            // The window edge varies within the recorded band.
            ("W25a", 2),
            ("W25b", 2),
            ("W30a", 2),
            ("W30b", 2),
        ]),
        "{divergences:?}"
    );
}

#[test]
fn window_band_contains_hits_and_misses_across_the_follow_up_runs() {
    let mut pooled_hits = 0;
    let mut pooled_misses = 0;
    for name in ["run-3.json", "run-4.json"] {
        let requests = load(name);
        let mut hits = 0;
        let mut misses = 0;
        for arm in requests
            .iter()
            .filter(|r| r["cell"].as_str().unwrap().starts_with('W') && r["step"] == 0)
        {
            let cell = arm["cell"].as_str().unwrap();
            let start = arm["startedAtMs"].as_f64().unwrap();
            for read in requests.iter().filter(|r| {
                r["cell"] == cell
                    && (r["method"] == "GET" || r["method"] == "DELETE")
                    && r["step"] != 0
            }) {
                let age = read["startedAtMs"].as_f64().unwrap() - start;
                let hit = read["status"] == 404 && read["latency"] == "fast";
                if name == "run-4.json" && age >= 10_250.0 {
                    assert!(!hit, "{name} {cell}: hit at {age} ms");
                }
                // Ages here come from the masked start times, a few tens of ms after the recorder's own ages;
                // the band reaches run 3's W50 hits (about 10.53 s and 10.59 s in these times).
                if (10_250.0..=10_600.0).contains(&age) {
                    if hit {
                        hits += 1;
                    } else {
                        misses += 1;
                    }
                }
            }
        }
        assert!(misses > 0, "{name}: no misses in the band");
        if name == "run-3.json" {
            assert!(hits > 0, "{name}: no hits in the band");
        } else {
            assert_eq!(hits, 0, "{name}: unexpected hit in the band");
        }
        pooled_hits += hits;
        pooled_misses += misses;
    }
    assert!(pooled_hits > 0 && pooled_misses > 0);
}

#[test]
fn seven_second_recent_success_exempts_in_both_runs() {
    for name in ["run-3.json", "run-4.json"] {
        let requests = load(name);
        for cell in ["E200-7a", "E200-7b"] {
            let rows: Vec<Value> = requests
                .iter()
                .filter(|r| r["cell"] == cell)
                .cloned()
                .collect();
            let final_get = rows.iter().rev().find(|r| r["method"] == "GET").unwrap();
            assert_eq!(final_get["step"], 5);
            assert_eq!(final_get["status"], 200);
            assert_eq!(final_get["latency"], "slow");
            let (checked, divergences) = replay(&rows);
            assert_eq!(checked, rows.len());
            assert!(
                !divergences.contains(&(cell.to_owned(), 5)),
                "{name} {cell}"
            );
        }
    }
}

#[test]
fn the_recordings_hold_hits_on_get_patch_and_delete_and_misses_on_fresh_connections() {
    // A guard against an empty replay: the model has something to be right about.
    for name in ["run-1.json", "run-2.json"] {
        let requests = load(name);
        let hits: Vec<&Value> = requests
            .iter()
            .filter(|r| r["status"] == 404 && r["latency"] == "fast")
            .collect();
        for method in ["GET", "PATCH", "DELETE"] {
            assert!(
                hits.iter().any(|r| r["method"] == method),
                "{name} {method}"
            );
        }
        assert!(
            requests
                .iter()
                .filter(|r| r["conn"] == "fresh")
                .all(|r| r["latency"] == "slow"),
            "{name}: a fresh connection never hit"
        );
    }
}

#[test]
fn follow_up_recordings_are_not_empty() {
    for name in ["run-3.json", "run-4.json"] {
        assert!(!load(name).is_empty(), "{name}");
    }
}
