//! Shared digest and encoding contract tests.

use fireemu_core_types::hash::{
    base64_standard, base64_url_safe, crc32c, hex_lower, hex_upper, md5, sha256, Crc32c, Md5,
    Sha256,
};

fn patterned_bytes(len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i.wrapping_mul(31) + 7).to_le_bytes()[0])
        .collect()
}

#[test]
fn digest_vectors_cover_padding_boundaries_and_large_inputs() {
    let cases = [
        (0, "d41d8cd98f00b204e9800998ecf8427e", 0x0000_0000),
        (55, "c9e512626618c9980ef21a96597af94c", 0xdab4_8fa4),
        (56, "ecde7caa08e9f5657c863df107cac60a", 0x8563_b7ae),
        (63, "2f0301069e1c40af7f6c8f843b1b13f2", 0xd701_3350),
        (64, "b6bf87c24b1bc334e2541387a92b981b", 0x2b1d_65d8),
        (65, "f168246f08b6134d66bd2a10343fa9f1", 0x1c1b_b57f),
        (
            3 * 1024 * 1024,
            "e2e39cd7ee527e009fe6b85482387a0f",
            0x1712_17c6,
        ),
    ];

    for (len, expected_md5, expected_crc32c) in cases {
        let bytes = patterned_bytes(len);
        assert_eq!(hex_lower(&md5(&bytes)), expected_md5, "MD5 length {len}");
        assert_eq!(crc32c(&bytes), expected_crc32c, "CRC32C length {len}");
    }
}

#[test]
fn incremental_digests_equal_one_shot_digests_across_chunk_boundaries() {
    let bytes = patterned_bytes(3 * 1024 * 1024);
    let mut md5_state = Md5::new();
    let mut crc32c_state = Crc32c::new();
    let mut sha256_state = Sha256::new();
    for chunk in bytes.chunks(997) {
        md5_state.update(chunk);
        crc32c_state.update(chunk);
        sha256_state.update(chunk);
    }

    assert_eq!(md5_state.finalize(), md5(&bytes));
    assert_eq!(crc32c_state.finalize(), crc32c(&bytes));
    assert_eq!(sha256_state.finalize(), sha256(&bytes));

    let mut short_updates = Md5::new();
    short_updates.update(b"abcde");
    short_updates.update(b"fgh");
    assert_eq!(short_updates.finalize(), md5(b"abcdefgh"));
}

#[test]
fn incremental_sha256_matches_one_shot_at_padding_boundaries() {
    for len in [0, 55, 56, 63, 64, 65] {
        let bytes = patterned_bytes(len);
        let mut digest = Sha256::new();
        for chunk in bytes.chunks(7) {
            digest.update(chunk);
        }
        assert_eq!(digest.finalize(), sha256(&bytes), "SHA-256 length {len}");
    }
}

#[test]
fn sha256_and_encodings_keep_their_public_contracts() {
    assert_eq!(
        hex_lower(&sha256(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(hex_upper(&[0x0a, 0xff]), "0AFF");
    assert_eq!(base64_standard(&[0xff, 0xfe]), "//4=");
    assert_eq!(base64_url_safe(&[0xff, 0xfe]), "__4=");
}

#[test]
#[ignore = "release-only throughput acceptance"]
fn thirty_megabytes_of_storage_checksums_finish_within_the_upload_budget() {
    let bytes = patterned_bytes(30 * 1024 * 1024);
    let started = std::time::Instant::now();
    std::hint::black_box(md5(std::hint::black_box(&bytes)));
    std::hint::black_box(crc32c(std::hint::black_box(&bytes)));
    let elapsed = started.elapsed();
    eprintln!("30 MiB MD5 plus CRC32C: {elapsed:?}");
    assert!(
        elapsed < std::time::Duration::from_millis(100),
        "30 MiB of MD5 and CRC32C took {elapsed:?}"
    );
}

// A bit-stream oracle deliberately avoids the encoder's three-byte grouping.
fn reference_base64(bytes: &[u8], alphabet: &[u8; 64]) -> String {
    let mut output = String::new();
    let mut value = 0usize;
    let mut bits = 0;
    for byte in bytes {
        for shift in (0..8).rev() {
            value = (value << 1) | usize::from((byte >> shift) & 1);
            bits += 1;
            if bits == 6 {
                output.push(char::from(alphabet[value]));
                value = 0;
                bits = 0;
            }
        }
    }
    if bits != 0 {
        output.push(char::from(alphabet[value << (6 - bits)]));
    }
    while output.len() % 4 != 0 {
        output.push('=');
    }
    output
}

fn assert_base64_matches_reference(bytes: &[u8]) {
    assert_eq!(
        base64_standard(bytes),
        reference_base64(
            bytes,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        )
    );
    assert_eq!(
        base64_url_safe(bytes),
        reference_base64(
            bytes,
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        )
    );
}

#[test]
fn base64_exhaustive_zero_one_and_two_byte_inputs() {
    assert_base64_matches_reference(&[]);
    for first in 0..=u8::MAX {
        assert_base64_matches_reference(&[first]);
        for second in 0..=u8::MAX {
            assert_base64_matches_reference(&[first, second]);
        }
    }
}

#[test]
fn base64_group_and_buffer_boundaries_match_reference() {
    for len in (0..=128).chain([1023, 1024, 1025, 65535, 65536, 65537]) {
        assert_base64_matches_reference(&patterned_bytes(len));
        assert_base64_matches_reference(&vec![255; len]);
    }
}

proptest::proptest! {
    #[test]
    fn base64_random_bytes_match_independent_bit_stream(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..8192)) {
        assert_base64_matches_reference(&bytes);
    }
}
