//! Deterministic opaque wire IDs; the broker's delivery identity stays internal.
use crate::PubSubProfile;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const PAYLOAD_BYTES: usize = 147;

fn encode(seed: u64) -> String {
    let mut bytes = [0u8; PAYLOAD_BYTES];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    for (index, byte) in bytes[8..].iter_mut().enumerate() {
        let offset = u64::try_from(index).expect("bounded token payload");
        let mixed = seed.rotate_left(u32::try_from(index % 64).expect("bounded rotation"))
            ^ offset.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        *byte = mixed.to_le_bytes()[index % 8];
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn wire(id: &str, policy: PubSubProfile) -> String {
    if policy == PubSubProfile::Emulator {
        return id.to_owned();
    }
    id.strip_prefix("ack-")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .map_or_else(|| id.to_owned(), encode)
}

pub(crate) fn decode(id: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(id).ok()?;
    if bytes.len() != PAYLOAD_BYTES {
        return None;
    }
    let seed = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    (encode(seed) == id).then(|| format!("ack-{seed:016x}"))
}

// Streaming keeps its existing unknown-ID semantics while decoding its own issued IDs.
pub(crate) fn internal(id: &str, policy: PubSubProfile) -> String {
    if policy == PubSubProfile::Strict {
        decode(id).unwrap_or_else(|| id.to_owned())
    } else {
        id.to_owned()
    }
}
