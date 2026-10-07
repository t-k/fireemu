//! Deterministic opaque wire IDs; the broker's delivery identity stays internal.
use crate::PubSubProfile;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const PAYLOAD_BYTES: usize = 147;
const STREAM_PAYLOAD_BYTES: usize = 142;

fn encode(seed: u64, length: usize) -> String {
    URL_SAFE_NO_PAD.encode(fireemu_core_pubsub::wire_ack::encode(
        seed,
        length == STREAM_PAYLOAD_BYTES,
    ))
}

pub(crate) fn wire(id: &str, policy: PubSubProfile) -> String {
    wire_with_length(id, policy, PAYLOAD_BYTES)
}

pub(crate) fn stream_wire(id: &str, policy: PubSubProfile) -> String {
    wire_with_length(id, policy, STREAM_PAYLOAD_BYTES)
}

fn wire_with_length(id: &str, policy: PubSubProfile, length: usize) -> String {
    if policy == PubSubProfile::Emulator {
        return id.to_owned();
    }
    id.strip_prefix("ack-")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .map_or_else(|| id.to_owned(), |seed| encode(seed, length))
}

pub(crate) fn decode(id: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(id).ok()?;
    if ![PAYLOAD_BYTES, STREAM_PAYLOAD_BYTES].contains(&bytes.len()) {
        return None;
    }
    let seed = fireemu_core_pubsub::wire_ack::decode(&bytes)?;
    (encode(seed, bytes.len()) == id).then(|| format!("ack-{seed:016x}"))
}

// Streaming keeps its existing unknown-ID semantics while decoding its own issued IDs.
pub(crate) fn internal(id: &str, policy: PubSubProfile) -> String {
    if policy == PubSubProfile::Strict {
        decode(id).unwrap_or_else(|| id.to_owned())
    } else {
        id.to_owned()
    }
}
