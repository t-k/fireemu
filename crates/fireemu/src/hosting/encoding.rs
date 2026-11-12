//! Content-Encoding for the strict profile: gzip, as the production recordings show it (rows
//! `v01.gz-*` of runs 658bb2 and 9a8d57; rows `v14.*` and `v15.*` of the follow-up runs 11ae6c and
//! 1c6a4c; corpora `conformance/src/hosting-production`).
//!
//! What production does, read from the rows: it looks for the text `gzip` (and `br`) in the
//! `Accept-Encoding` header as a plain, case-sensitive substring. The header `x-gzip` and
//! `gzip;q=0` get gzip, `GZIP`, `*`, `deflate` and `identity` get none, and a header with `br` gets
//! Brotli. It compresses any content type (an image, a zip and a font as well as text) when the
//! compressed body is smaller: files of 1 and 10 bytes are left alone, files of 100 bytes and more
//! (to the 4,500 recorded) are compressed. A `Content-Encoding` header set by a `headers` rule is
//! not served. The `ETag` stays the file's own. A `Range` is taken over the compressed body.
//!
//! Brotli is not produced here (a declared difference): a request that accepts only `br` is answered
//! as identity, one that accepts both as gzip.

use std::io::Read;

/// The largest file strict compresses. A bigger one is answered as identity: the whole answer is
/// built in memory, because the length of a gzip body is known only once it is compressed.
pub(super) const MAX_GZIP_INPUT: u64 = 32 * 1024 * 1024;

/// Whether a file of `length` bytes is within what strict compresses: not empty (an empty file is
/// left alone) and not above [`MAX_GZIP_INPUT`].
pub(super) fn within_limit(length: u64) -> bool {
    length > 0 && length <= MAX_GZIP_INPUT
}

/// Whether a compressed body of `packed` bytes is sent for a file of `original` bytes: only when it
/// is smaller (`v15.size-0001` and `-0010` are identity, `-0100` and up are gzip).
pub(super) fn pays_off(packed: u64, original: u64) -> bool {
    packed < original
}

/// [`accepts_gzip`] over every `Accept-Encoding` line of a request: several lines are one
/// comma-separated list (RFC 9110), so `br` on one line and `gzip` on the next accepts gzip.
pub(super) fn accepts_gzip_in(headers: &hyper::HeaderMap) -> bool {
    let lines: Vec<&str> = headers
        .get_all(hyper::header::ACCEPT_ENCODING)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .collect();
    !lines.is_empty() && accepts_gzip(Some(&lines.join(", ")))
}

/// Whether `Accept-Encoding` holds the text `gzip`, as production reads it (`v15.ae-*`): `gzip`,
/// `x-gzip` and `gzip;q=0` do, `GZIP`, `*`, `deflate`, `identity` and an absent header do not.
pub(super) fn accepts_gzip(header: Option<&str>) -> bool {
    header.is_some_and(|value| value.contains("gzip"))
}

/// The `OS` byte of the gzip header: production's is `0x13` (`v15.ae-range`).
const GZIP_OS: u8 = 0x13;

/// The first `size` bytes of `source` compressed as one gzip member at the default level, or the error that reading
/// them gave (a source shorter than `size` is an error). The same input always gives the same
/// output: the header carries no time and no file name. Blocking: callers run it on a blocking thread.
pub(super) fn gzip_reader(source: impl Read, size: u64) -> std::io::Result<Vec<u8>> {
    let mut encoder = flate2::GzBuilder::new()
        .operating_system(GZIP_OS)
        .write(Vec::new(), flate2::Compression::default());
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
        // the rows v15.ae-* and v01.gz-* of the recordings, then the same rule on other forms
        let yes = [
            "gzip",
            "x-gzip",
            "gzip;q=0",
            "gzip, deflate, br",
            "br, gzip",
            "br;q=0, gzip",
            "gzip;q=0.5",
            " gzip ",
            "deflate, gzip",
            "xgzip",
            "gzip;level=1",
        ];
        for form in yes {
            assert!(accepts_gzip(Some(form)), "{form:?} holds gzip");
        }
        let no = [
            "",
            "identity",
            "br",
            "*",
            "deflate",
            "GZIP",
            "Gzip",
            "gzi",
            "zip",
            "br;q=1, deflate",
        ];
        for form in no {
            assert!(!accepts_gzip(Some(form)), "{form:?} does not hold gzip");
        }
        assert!(!accepts_gzip(None));
    }

    #[test]
    fn a_compressed_body_is_sent_only_when_it_is_smaller() {
        // v15.size-*: 1 and 10 bytes stay, 100 bytes and more are compressed
        assert!(!pays_off(21, 1));
        assert!(!pays_off(30, 10));
        assert!(pays_off(73, 100));
        assert!(pays_off(93, 4500));
        assert!(!pays_off(100, 100));
        assert!(pays_off(99, 100));
        assert!(!pays_off(0, 0));
    }

    #[test]
    fn every_accept_encoding_line_is_one_list() {
        let request = |lines: &[&[u8]]| {
            let mut headers = hyper::HeaderMap::new();
            for line in lines {
                headers.append(
                    hyper::header::ACCEPT_ENCODING,
                    hyper::header::HeaderValue::from_bytes(line).unwrap(),
                );
            }
            headers
        };
        assert!(!accepts_gzip_in(&request(&[])));
        assert!(accepts_gzip_in(&request(&[b"gzip"])));
        assert!(accepts_gzip_in(&request(&[b"br", b"gzip"])));
        assert!(accepts_gzip_in(&request(&[
            b"deflate",
            b"br;q=0",
            b"gzip;q=1"
        ])));
        assert!(!accepts_gzip_in(&request(&[b"br", b"deflate"])));
        // a quality is not read (`v15.ae-gzip-q0`): the text `gzip` is enough, on any line
        assert!(accepts_gzip_in(&request(&[b"gzip;q=0"])));
        assert!(accepts_gzip_in(&request(&[b"br", b"GZIP", b"x-gzip"])));
        assert!(!accepts_gzip_in(&request(&[b"br", b"GZIP"])));
        // a line that is not text is skipped, the others still count
        assert!(accepts_gzip_in(&request(&[b"\xff", b"gzip"])));
        assert!(!accepts_gzip_in(&request(&[b"\xff"])));
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
        // flags `XFL` 0 and `OS` 0x13, the ten bytes production's header is (`v15.ae-range` is `bytes=0-9`
        // of its gzip body, and the digest of those ten bytes is that of this header)
        assert_eq!(&packed[8..10], &[0, 0x13]);
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

    proptest! {
        /// The decision is the plain substring test and nothing else.
        #[test]
        fn accepts_gzip_is_the_substring_test(text in "[a-zA-Z;=,0-9 *.-]{0,40}") {
            prop_assert_eq!(accepts_gzip(Some(&text)), text.contains("gzip"));
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
            prop_assert_eq!(&packed[4..10], &[0, 0, 0, 0, 0, 0x13][..]);
            prop_assert_eq!(gunzip(&packed), data.clone());
            prop_assert_eq!(gzip_reader(&data[..], data.len() as u64).unwrap(), packed);
        }
    }
}
