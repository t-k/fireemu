//! Canonical deterministic opaque ACK payloads; wire base64 belongs to the adapter.

/// Encodes a broker delivery seed in the observed unary or streaming payload width.
#[must_use]
pub fn encode(seed: u64, streaming: bool) -> Vec<u8> {
    let mut bytes = vec![0u8; if streaming { 142 } else { 147 }];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    for (index, byte) in bytes[8..].iter_mut().enumerate() {
        let offset = u64::try_from(index).expect("bounded payload");
        let mixed = seed.rotate_left(u32::try_from(index % 64).expect("bounded rotation"))
            ^ offset.wrapping_mul(0x9e37_79b9_7f4a_7c15);
        *byte = mixed.to_le_bytes()[index % 8];
    }
    bytes
}

/// Encodes the observed compact unary width without selecting when to issue it.
#[must_use]
pub fn encode_compact_unary(seed: u64) -> Vec<u8> {
    let mut bytes = encode(seed, false);
    bytes.truncate(146);
    // Keep truncated ordinary unary payloads outside the compact format domain.
    bytes[8] ^= 0x80;
    bytes
}

/// Decodes only complete canonical payloads in a supported format.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<u64> {
    if ![142, 146, 147].contains(&bytes.len()) {
        return None;
    }
    let seed = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    let canonical = if bytes.len() == 146 {
        encode_compact_unary(seed)
    } else {
        encode(seed, bytes.len() == 142)
    };
    (canonical == bytes).then_some(seed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn canonical_roundtrip_preserves_seed_and_width(seed in any::<u64>(), streaming in any::<bool>(), index in 8usize..147) {
            let bytes=encode(seed,streaming);
            prop_assert_eq!(bytes.len(),if streaming {142} else {147});
            prop_assert_eq!(decode(&bytes),Some(seed));
            let mut changed=bytes.clone();let position=index%bytes.len();changed[position]^=1;
            prop_assert_eq!(decode(&changed),None);
            prop_assert_eq!(decode(&bytes[..bytes.len()-1]),None);
            let mut extended=bytes;extended.push(0);prop_assert_eq!(decode(&extended),None);
        }
    }
}

#[cfg(test)]
mod compact_tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn compact_unary_payload_roundtrips_with_full_integrity(seed in any::<u64>(), position in 0usize..146) {
            let mut compact=encode(seed,false);
            compact.truncate(146);
            compact[8] ^= 0x80; // Distinct format domain: a truncated unary token is not compact.
            prop_assert_eq!(encode_compact_unary(seed),compact.clone());
            prop_assert_eq!(decode(&compact),Some(seed));
            let mut changed=compact.clone();changed[position]^=1;
            prop_assert_eq!(decode(&changed),None);
            for unsupported in [0usize,7,8,141,143,144,145,148] {
                let mut resized=compact.clone();resized.resize(unsupported,0);
                prop_assert_eq!(decode(&resized),None);
            }
        }
    }
}
