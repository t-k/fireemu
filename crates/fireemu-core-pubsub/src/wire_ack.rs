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

/// Decodes only complete canonical payloads in either supported width.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<u64> {
    if ![142, 147].contains(&bytes.len()) {
        return None;
    }
    let seed = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    (encode(seed, bytes.len() == 142) == bytes).then_some(seed)
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
