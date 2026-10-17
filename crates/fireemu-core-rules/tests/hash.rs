//! Digest vectors for the `hashing` namespace.

use fireemu_core_rules::hash::{base64, crc32, crc32c, hex, md5, sha256};

#[test]
fn digests_match_the_published_test_vectors() {
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    assert_eq!(crc32c(b"123456789"), 0xE306_9283);
    assert_eq!(crc32(b""), 0);
    assert_eq!(
        hex(&md5(b"")).to_lowercase(),
        "d41d8cd98f00b204e9800998ecf8427e"
    );
    assert_eq!(
        hex(&md5(b"abc")).to_lowercase(),
        "900150983cd24fb0d6963f7d28e17f72"
    );
    assert_eq!(
        hex(&md5(b"The quick brown fox jumps over the lazy dog")).to_lowercase(),
        "9e107d9d372bb6826bd81d3542a419d6"
    );
    assert_eq!(
        hex(&sha256(b"")).to_lowercase(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex(&sha256(b"abc")).to_lowercase(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    // Two blocks.
    assert_eq!(
        hex(&sha256(
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        ))
        .to_lowercase(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
    // `toHexString()` prints uppercase and `toBase64()` uses the URL-safe alphabet, both
    // measured against the official runtime (`conformance/rules-matrix.json`, `encoding`).
    assert_eq!(hex(&md5(b"abc")), "900150983CD24FB0D6963F7D28E17F72");
    assert_eq!(
        base64(&sha256(b"abc")),
        "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0="
    );
    assert_eq!(base64(&[0xffu8, 0xfe]), "__4=");
}

#[test]
fn civil_dates_round_trip() {
    use fireemu_core_rules::civil::{
        civil_from_days, day_of_year, days_from_civil, is_valid_date, iso_weekday,
    };
    assert_eq!(days_from_civil(1970, 1, 1), 0);
    assert_eq!(days_from_civil(2000, 3, 1), 11_017);
    assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    assert_eq!(civil_from_days(-1), (1969, 12, 31));
    for days in [-800_000, -1, 0, 59, 60, 11_016, 20_000, 1_000_000] {
        let (y, m, d) = civil_from_days(days);
        assert_eq!(days_from_civil(y, m, d), days);
    }
    assert_eq!(iso_weekday(0), 4); // 1970-01-01 was a Thursday
    assert_eq!(iso_weekday(days_from_civil(2026, 8, 30)), 7); // Sunday
    assert_eq!(day_of_year(days_from_civil(2024, 12, 31)), 366);
    assert!(is_valid_date(2024, 2, 29));
    assert!(!is_valid_date(2023, 2, 29));
    assert!(!is_valid_date(2023, 13, 1));
}

// Use the non-reflected polynomial and reverse each input byte so the oracle does not share the production implementation's table or reflected recurrence.
fn crc32_reference(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        crc ^= u32::from(byte.reverse_bits()) << 24;
        for _ in 0..8 {
            crc = if crc & 0x8000_0000 == 0 {
                crc << 1
            } else {
                (crc << 1) ^ 0x04c1_1db7
            };
        }
    }
    (!crc).reverse_bits()
}

#[test]
fn crc32_matches_reference_for_every_short_input() {
    assert_eq!(crc32(&[]), 0);
    for first in 0..=u8::MAX {
        assert_eq!(crc32(&[first]), crc32_reference(&[first]));
        for second in 0..=u8::MAX {
            let data = [first, second];
            assert_eq!(crc32(&data), crc32_reference(&data), "{data:?}");
        }
    }
}

#[test]
fn crc32_matches_reference_at_length_and_alignment_boundaries() {
    let data: Vec<u8> = (0..8193)
        .map(|index| u8::try_from(index % 256).expect("remainder fits in u8"))
        .collect();
    for offset in 0..8 {
        for len in [
            0, 1, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 255, 256, 257, 4095, 4096,
            4097,
        ] {
            let bytes = &data[offset..offset + len];
            assert_eq!(
                crc32(bytes),
                crc32_reference(bytes),
                "offset={offset}, len={len}"
            );
        }
    }
    for byte in [0, 0xff, 0x80, 0x55] {
        let bytes = vec![byte; 8193];
        assert_eq!(crc32(&bytes), crc32_reference(&bytes));
    }
}

proptest::proptest! {
    #[test]
    fn crc32_matches_reference_for_arbitrary_bytes(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4097)) {
        proptest::prop_assert_eq!(crc32(&data), crc32_reference(&data));
    }
}
