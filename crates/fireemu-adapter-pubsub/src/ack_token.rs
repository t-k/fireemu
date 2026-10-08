//! Deterministic opaque wire IDs; the broker's delivery identity stays internal.
use crate::PagingPolicy;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;

const PAYLOAD_BYTES: usize = 147;
const REST_PAYLOAD_BYTES: usize = 146;

fn encode(seed: u64, compact: bool) -> String {
    let mut bytes = [0u8; PAYLOAD_BYTES];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    for (index, byte) in bytes[8..].iter_mut().enumerate() {
        let offset = u64::try_from(index).expect("bounded token payload");
        let mixed = seed.rotate_left(u32::try_from(index % 64).expect("bounded rotation"))
            ^ offset.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        *byte = mixed.to_le_bytes()[index % 8];
    }
    if compact {
        // Keep truncated legacy payloads outside the compact REST format domain.
        bytes[8] ^= 0x80;
        URL_SAFE_NO_PAD.encode(&bytes[..REST_PAYLOAD_BYTES])
    } else {
        URL_SAFE_NO_PAD.encode(bytes)
    }
}

pub(crate) fn wire(id: &str, policy: PagingPolicy) -> String {
    wire_format(id, policy, false)
}

pub(crate) fn rest_wire(id: &str, policy: PagingPolicy) -> String {
    wire_format(id, policy, true)
}

fn wire_format(id: &str, policy: PagingPolicy, compact: bool) -> String {
    if policy == PagingPolicy::Emulator {
        return id.to_owned();
    }
    id.strip_prefix("ack-")
        .and_then(|value| u64::from_str_radix(value, 16).ok())
        .map_or_else(|| id.to_owned(), |seed| encode(seed, compact))
}

pub(crate) fn decode(id: &str) -> Option<String> {
    let bytes = URL_SAFE_NO_PAD.decode(id).ok()?;
    if ![PAYLOAD_BYTES, REST_PAYLOAD_BYTES].contains(&bytes.len()) {
        return None;
    }
    let seed = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    (encode(seed, bytes.len() == REST_PAYLOAD_BYTES) == id).then(|| format!("ack-{seed:016x}"))
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
            prop_assert_eq!(encoded==encode(second, false),first==second);
            let padded = format!("{encoded}=");
            prop_assert!(decode(&padded).is_none());
            let mut corrupt = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
            corrupt[8] ^= 1;
            prop_assert!(decode(&URL_SAFE_NO_PAD.encode(corrupt)).is_none());
        }
    }
    proptest! {
        #[test]
        fn compact_rest_ack_is_canonical_injective_and_legacy_compatible(
            first in any::<u64>(), second in any::<u64>(), position in 0usize..REST_PAYLOAD_BYTES
        ) {
            let raw = format!("ack-{first:016x}");
            let compact = rest_wire(&raw, PagingPolicy::Strict);
            prop_assert_eq!(compact.len(), 195);
            prop_assert_eq!(decode(&compact), Some(raw.clone()));
            prop_assert_eq!(internal(&compact, PagingPolicy::Strict), raw.clone());
            prop_assert_eq!(rest_wire(&raw, PagingPolicy::Emulator), raw.clone());
            prop_assert_eq!(internal(&compact, PagingPolicy::Emulator), compact.clone());
            prop_assert_eq!(compact == encode(second, true), first == second);
            let legacy = wire(&raw, PagingPolicy::Strict);
            prop_assert_eq!(legacy.len(), 196);
            prop_assert_eq!(decode(&legacy), Some(raw));
            let legacy_bytes = URL_SAFE_NO_PAD.decode(&legacy).unwrap();
            prop_assert!(decode(&URL_SAFE_NO_PAD.encode(&legacy_bytes[..REST_PAYLOAD_BYTES])).is_none());
            let padded = format!("{compact}=");
            prop_assert!(decode(&padded).is_none());
            let mut corrupt = URL_SAFE_NO_PAD.decode(&compact).unwrap();
            corrupt[position] ^= 1;
            prop_assert!(decode(&URL_SAFE_NO_PAD.encode(corrupt)).is_none());
            for length in [0, 7, 8, 145, 148] {
                let mut resized = legacy_bytes.clone();
                resized.resize(length, 0);
                prop_assert!(decode(&URL_SAFE_NO_PAD.encode(resized)).is_none());
            }
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
