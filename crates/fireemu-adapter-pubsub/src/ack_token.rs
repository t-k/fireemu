//! Deterministic opaque wire IDs; the broker's delivery identity stays internal.
use crate::PagingPolicy;
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

pub(crate) fn wire(id: &str, policy: PagingPolicy) -> String {
    if policy == PagingPolicy::Emulator {
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
pub(crate) fn internal(id: &str, policy: PagingPolicy) -> String {
    if policy == PagingPolicy::Strict {
        decode(id).unwrap_or_else(|| id.to_owned())
    } else {
        id.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn opaque_ack_codec_is_injective_and_preserves_internal_identity(first in any::<u64>(), second in any::<u64>()) {
            let raw = format!("ack-{first:016x}");
            let encoded = wire(&raw,PagingPolicy::Strict);
            prop_assert_eq!(encoded.len(),196);
            prop_assert!(encoded.bytes().all(|byte|byte.is_ascii_alphanumeric() || byte==b'-' || byte==b'_'));
            prop_assert_eq!(decode(&encoded),Some(raw.clone()));
            prop_assert_eq!(wire(&raw,PagingPolicy::Emulator),raw);
            prop_assert_eq!(encoded==encode(second),first==second);
            let padded = format!("{encoded}=");
            prop_assert!(decode(&padded).is_none());
            let mut corrupt = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            corrupt[8] ^= 1;
            prop_assert!(decode(&URL_SAFE_NO_PAD.encode(corrupt)).is_none());
        }
    }
    #[test]
    fn wrong_length_foreign_and_noncanonical_ack_tokens_are_refused() {
        for id in [
            "",
            "not-an-ack-id",
            "ack-0123456789abcdef",
            &"x".repeat(195),
            &"x".repeat(197),
        ] {
            assert!(decode(id).is_none());
        }
        assert_eq!(internal("unknown", PagingPolicy::Strict), "unknown");
    }
}
