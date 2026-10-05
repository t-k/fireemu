//! An object's `etag` as production writes it.

/// An object's `etag` as production writes it: the standard base64 of a protobuf message with the
/// generation as field 1 and the metageneration as field 2, both varints (recorded, lean-v4: the
/// generation 1790789164648913 at metageneration 2 is `CNGTm8DplpcDEAI=`, at 3 `CNGTm8DplpcDEAM=`).
#[must_use]
pub fn production_etag(generation: u64, metageneration: u64) -> String {
    fn varint(mut value: u64, out: &mut Vec<u8>) {
        // A 64-bit value takes at most ten bytes, so at most nine continuation bytes precede the
        // last; the bound keeps a broken shift from growing the buffer without end.
        for _ in 0..9 {
            if value < 0x80 {
                break;
            }
            out.push(u8::try_from(value & 0x7f).unwrap_or(0) | 0x80);
            value >>= 7;
        }
        out.push(u8::try_from(value).unwrap_or(0));
    }
    let mut message = vec![0x08];
    varint(generation, &mut message);
    message.push(0x10);
    varint(metageneration, &mut message);
    crate::hash::base64(&message)
}

#[cfg(test)]
mod tests {
    use super::production_etag;

    #[test]
    fn the_etag_is_the_protobuf_of_generation_and_metageneration() {
        // Recorded, lean-v4: the resource of tokens.bin after create_token and delete_token.
        assert_eq!(
            production_etag(1_790_789_164_648_913, 2),
            "CNGTm8DplpcDEAI="
        );
        assert_eq!(
            production_etag(1_790_789_164_648_913, 3),
            "CNGTm8DplpcDEAM="
        );
        assert_eq!(production_etag(1, 1), "CAEQAQ==");
    }

    #[test]
    fn the_etag_varints_hold_at_every_length_up_to_ten_bytes() {
        // Values on either side of each seven-bit boundary and both ends of the 64-bit range,
        // computed with an independent encoder.
        for (generation, metageneration, expected) in [
            (127, 128, "CH8QgAE="),
            (16_383, 16_384, "CP9/EICAAQ=="),
            // One more byte at each power of 128: lengths 4 to 9 of the generation.
            (1_u64 << 21, 1, "CICAgAEQAQ=="),
            (1_u64 << 28, 1, "CICAgIABEAE="),
            (1_u64 << 35, 1, "CICAgICAARAB"),
            (1_u64 << 42, 1, "CICAgICAgAEQAQ=="),
            (1_u64 << 49, 1, "CICAgICAgIABEAE="),
            (1_u64 << 56, 1, "CICAgICAgICAARAB"),
            (1_u64 << 63, 2, "CICAgICAgICAgAEQAg=="),
            (u64::MAX, 1, "CP///////////wEQAQ=="),
            (1, u64::MAX, "CAEQ////////////AQ=="),
        ] {
            assert_eq!(
                production_etag(generation, metageneration),
                expected,
                "{generation} {metageneration}"
            );
        }
    }

    /// The recorded etags of the FE v5 production run (functions-events-formal-20261004T182904Z-
    /// a9621bfae74fe9bc, project fireemu-oracle-events), each with the generation and the
    /// metageneration the same frame names.
    #[test]
    fn the_etags_of_the_v5_storage_frames_are_the_protobuf_of_their_generation_and_metageneration()
    {
        // frame 6ac29fb70006ad918ea2a73d (a finalize), the first object of the run.
        assert_eq!(
            production_etag(1_791_139_765_427_541, 1),
            "CNW62MuDoZcDEAE="
        );
    }
}

#[cfg(test)]
mod properties {
    use super::production_etag;
    use proptest::prelude::*;

    /// An independent reading of the etag: base64 to bytes, then the two protobuf varint fields.
    fn decode(etag: &str) -> Option<(u64, u64)> {
        const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut bits = 0u32;
        let mut width = 0u32;
        let mut bytes = Vec::new();
        for c in etag.bytes().take_while(|&c| c != b'=') {
            bits = (bits << 6) | u32::try_from(ALPHABET.iter().position(|&a| a == c)?).ok()?;
            width += 6;
            if width >= 8 {
                width -= 8;
                bytes.push(u8::try_from((bits >> width) & 0xff).ok()?);
            }
        }
        let mut at = 0;
        let mut field = |tag: u8| -> Option<u64> {
            if *bytes.get(at)? != tag {
                return None;
            }
            at += 1;
            let mut value = 0u64;
            for shift in (0..70).step_by(7) {
                let byte = *bytes.get(at)?;
                at += 1;
                value |= u64::from(byte & 0x7f).checked_shl(shift)?;
                if byte & 0x80 == 0 {
                    return Some(value);
                }
            }
            None
        };
        let generation = field(0x08)?;
        let metageneration = field(0x10)?;
        (at == bytes.len()).then_some((generation, metageneration))
    }

    proptest! {
        #[test]
        fn the_etag_decodes_to_the_generation_and_metageneration(generation in any::<u64>(), metageneration in any::<u64>()) {
            let etag = production_etag(generation, metageneration);
            prop_assert_eq!(decode(&etag), Some((generation, metageneration)), "{}", etag);
        }

        #[test]
        fn a_production_sized_etag_is_sixteen_characters(generation in 1_000_000_000_000_000_u64..9_999_999_999_999_999, metageneration in 1_u64..128) {
            prop_assert_eq!(production_etag(generation, metageneration).len(), 16);
        }
    }
}
