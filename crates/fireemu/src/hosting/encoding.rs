//! Content-Encoding for the strict profile: gzip, as the production recording shows it (rows
//! `v01.gz-*` of runs 658bb2 and 9a8d57, corpus `conformance/src/hosting-production`).
//!
//! Production answers a compressible file with `Content-Encoding: gzip` when the request accepts
//! gzip, keeps the file's own `ETag` (a gzip answer carries no suffix; only a Brotli answer's tag
//! ends in `-br`), keeps `Vary: x-fh-requested-host, accept-encoding` on every answer, and leaves
//! an incompressible type (`v01.gz-png-gzip`) alone. Brotli is not produced here: a request that
//! accepts only `br` is answered as identity, a declared difference.

use std::io::Read;

/// The largest file strict compresses. A bigger one is answered as identity: the whole answer is
/// built in memory, because the length of a gzip body is known only once it is compressed.
pub(super) const MAX_GZIP_INPUT: u64 = 32 * 1024 * 1024;

/// Whether a file of `length` bytes is within what strict compresses: not empty (an empty file is
/// left alone) and not above [`MAX_GZIP_INPUT`].
pub(super) fn within_limit(length: u64) -> bool {
    length > 0 && length <= MAX_GZIP_INPUT
}

/// Whether `Accept-Encoding` accepts gzip: the first `gzip` member has a quality above zero.
/// `x-gzip`, `*` and every other coding do not count (production recorded only `gzip` and `br`);
/// a quality that is not a number from 0 to 1 refuses the member.
pub(super) fn accepts_gzip(header: Option<&str>) -> bool {
    let Some(header) = header else {
        return false;
    };
    for member in header.split(',') {
        let mut parts = member.split(';');
        if !parts
            .next()
            .unwrap_or("")
            .trim()
            .eq_ignore_ascii_case("gzip")
        {
            continue;
        }
        let quality = parts.find_map(|parameter| {
            let (name, value) = parameter.split_once('=')?;
            name.trim().eq_ignore_ascii_case("q").then(|| value.trim())
        });
        return quality.is_none_or(|value| quality_thousandths(value).is_some_and(|q| q > 0));
    }
    false
}

/// An RFC 9110 `qvalue` in thousandths: `0` to `0.999` or `1` to `1.000`, or `None` for any other
/// text.
fn quality_thousandths(text: &str) -> Option<u16> {
    let (whole, fraction) = text.split_once('.').map_or((text, ""), |(w, f)| (w, f));
    if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits: u16 = format!("{fraction:0<3}").parse().ok()?;
    match whole {
        "0" => Some(digits),
        "1" if digits == 0 => Some(1000),
        _ => None,
    }
}

/// The first `size` bytes of `source` compressed as one gzip member at the default level, or the error that reading
/// them gave (a source shorter than `size` is an error). The same input always gives the same
/// output: the header carries no time and no file name. Blocking: callers run it on a blocking thread.
pub(super) fn gzip_reader(source: impl Read, size: u64) -> std::io::Result<Vec<u8>> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let copied = std::io::copy(&mut source.take(size), &mut encoder)?;
    if copied != size {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            "Hosting asset changed while compressing",
        ));
    }
    encoder.finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        gzip_reader(bytes, bytes.len() as u64).expect("a slice reads")
    }

    fn gunzip(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .read_to_end(&mut out)
            .expect("a gzip member");
        out
    }

    #[test]
    fn accept_encoding_forms() {
        let yes = [
            "gzip",
            "GZIP",
            " gzip ",
            "gzip, br",
            "br, gzip",
            "br;q=0, gzip",
            "gzip;q=1",
            "gzip;q=0.5",
            "gzip; q=0.001",
            "gzip;level=1",
            "deflate, gzip;q=0.2",
            "gzip;Q=1",
        ];
        for form in yes {
            assert!(accepts_gzip(Some(form)), "{form:?} accepts gzip");
        }
        let no = [
            "",
            "identity",
            "br",
            "*",
            "x-gzip",
            "gzipx",
            "xgzip",
            "gzip;q=0",
            "gzip;q=0.0",
            "gzip; q=0.000",
            "gzip;q=abc",
            "gzip;q=",
            "gzip;q=2",
            "gzip;q=-1",
            "gzip;q=1.5",
            "gzip;q=0.0001",
            "gzip;q=0, gzip",
            "br;q=1, deflate",
        ];
        for form in no {
            assert!(!accepts_gzip(Some(form)), "{form:?} does not accept gzip");
        }
        assert!(!accepts_gzip(None));
    }

    #[test]
    fn the_limit_is_one_byte_to_thirty_two_mebibytes() {
        assert!(!within_limit(0));
        assert!(within_limit(1));
        assert!(within_limit(32 * 1024 * 1024));
        assert!(!within_limit(32 * 1024 * 1024 + 1));
        assert!(!within_limit(u64::MAX));
    }

    #[test]
    fn gzip_output_is_one_deterministic_member_with_no_time() {
        let body = "The quick brown fox jumps over the lazy dog.\n".repeat(100);
        let packed = gzip(body.as_bytes());
        // magic, deflate, no flags, mtime zero
        assert_eq!(&packed[..8], &[0x1f, 0x8b, 8, 0, 0, 0, 0, 0]);
        assert_eq!(gunzip(&packed), body.as_bytes());
        assert_eq!(packed, gzip(body.as_bytes()));
        // 4,500 bytes of a repeated line: the recorded production answer is 93 bytes
        assert_eq!(packed.len(), 93);
        assert_eq!(gunzip(&gzip(b"")), b"");
    }

    #[test]
    fn gzip_reader_takes_exactly_size_bytes() {
        let data: Vec<u8> = (0..=255u8).cycle().take(10_000).collect();
        assert_eq!(gunzip(&gzip_reader(&data[..], 10_000).unwrap()), data);
        assert_eq!(gunzip(&gzip_reader(&data[..], 100).unwrap()), &data[..100]);
        assert_eq!(gunzip(&gzip_reader(&data[..], 0).unwrap()), b"");
        // a source that is shorter than the size is an error, never a short answer
        assert!(gzip_reader(&data[..50], 51).is_err());
    }

    /// One `Accept-Encoding` member: a coding and an optional quality text.
    fn member() -> impl Strategy<Value = (String, Option<String>)> {
        (
            prop_oneof![
                Just("gzip".to_owned()),
                Just("GZip".to_owned()),
                Just("br".to_owned()),
                Just("identity".to_owned()),
                Just("*".to_owned()),
                Just("deflate".to_owned()),
                "[a-z-]{1,8}",
            ],
            prop_oneof![
                Just(None),
                Just(Some("0".to_owned())),
                Just(Some("0.000".to_owned())),
                Just(Some("1".to_owned())),
                Just(Some("0.5".to_owned())),
                Just(Some("0.001".to_owned())),
                Just(Some("x".to_owned())),
                Just(Some(String::new())),
            ],
        )
    }

    proptest! {
        /// The decision follows the first gzip member and nothing else.
        #[test]
        fn accepts_gzip_follows_the_first_gzip_member(
            members in proptest::collection::vec(member(), 0..6),
            spaces in "[ ]{0,2}",
        ) {
            let text = members
                .iter()
                .map(|(coding, quality)| match quality {
                    Some(q) => format!("{spaces}{coding};{spaces}q={q}"),
                    None => format!("{spaces}{coding}"),
                })
                .collect::<Vec<_>>()
                .join(", ");
            let expected = members
                .iter()
                .find(|(coding, _)| coding.eq_ignore_ascii_case("gzip"))
                .is_some_and(|(_, quality)| {
                    matches!(quality.as_deref(), None | Some("1" | "0.5" | "0.001"))
                });
            prop_assert_eq!(accepts_gzip(Some(&text)), expected, "{}", text);
        }

        #[test]
        fn accepts_gzip_never_panics(text in "\\PC{0,64}") {
            let _ = accepts_gzip(Some(&text));
        }

        #[test]
        fn gzip_round_trips_and_is_deterministic(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
        ) {
            let packed = gzip(&data);
            prop_assert_eq!(&packed[..4], &[0x1f, 0x8b, 8, 0][..]);
            prop_assert_eq!(&packed[4..8], &[0, 0, 0, 0][..]);
            prop_assert_eq!(gunzip(&packed), data.clone());
            prop_assert_eq!(gzip_reader(&data[..], data.len() as u64).unwrap(), packed);
        }
    }
}
