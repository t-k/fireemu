//! Shared digest and encoding contract tests.

use fireemu_core_types::hash::{
    base64_standard, base64_url_safe, crc32c, hex_lower, hex_upper, md5, sha256, Crc32c, Md5,
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
    for chunk in bytes.chunks(997) {
        md5_state.update(chunk);
        crc32c_state.update(chunk);
    }

    assert_eq!(md5_state.finalize(), md5(&bytes));
    assert_eq!(crc32c_state.finalize(), crc32c(&bytes));

    let mut short_updates = Md5::new();
    short_updates.update(b"abcde");
    short_updates.update(b"fgh");
    assert_eq!(short_updates.finalize(), md5(b"abcdefgh"));
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
