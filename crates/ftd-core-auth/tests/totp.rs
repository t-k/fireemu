//! RFC 4226 / RFC 6238 test vectors and base32 round trips.

use ftd_core_auth::base32::{decode, encode};
use ftd_core_auth::totp::{hotp, time_step, totp_at, TotpParams};
use ftd_core_types::time::LogicalInstant;

const RFC_SECRET: &[u8] = b"12345678901234567890";

#[test]
fn rfc4226_hotp_vectors() {
    let expected = [
        755_224, 287_082, 359_152, 969_429, 338_314, 254_676, 287_922, 162_583, 399_871, 520_489,
    ];
    for (counter, want) in expected.iter().enumerate() {
        assert_eq!(
            hotp(RFC_SECRET, counter as u64, 6),
            *want,
            "counter {counter}"
        );
    }
}

#[test]
fn rfc6238_sha1_vectors_eight_digits() {
    let params = TotpParams {
        period_seconds: 30,
        digits: 8,
    };
    for (unix, want) in [
        (59, 94_287_082),
        (1_111_111_109, 7_081_804),
        (1_111_111_111, 14_050_471),
        (1_234_567_890, 89_005_924),
        (2_000_000_000, 69_279_037),
        (20_000_000_000, 65_353_130),
    ] {
        let at = LogicalInstant::from_unix_seconds(unix);
        assert_eq!(totp_at(RFC_SECRET, &params, at), want, "t={unix}");
    }
}

#[test]
fn time_step_boundaries_on_the_virtual_clock() {
    let p = TotpParams {
        period_seconds: 30,
        digits: 6,
    };
    let t = LogicalInstant::from_unix_seconds(1_788_004_860);
    assert_eq!(time_step(&p, t), 59_600_162);
    assert_eq!(
        time_step(
            &p,
            t.checked_add(ftd_core_types::time::LogicalDuration::from_seconds(29))
                .unwrap()
        ),
        59_600_162
    );
    assert_eq!(
        time_step(
            &p,
            t.checked_add(ftd_core_types::time::LogicalDuration::from_seconds(30))
                .unwrap()
        ),
        59_600_163
    );
    // Negative instants (before the Unix epoch) clamp to step 0 rather than wrapping.
    assert_eq!(time_step(&p, LogicalInstant::from_unix_seconds(-1)), 0);
}

#[test]
fn base32_round_trip_and_rfc4648_vectors() {
    assert_eq!(encode(b""), "");
    assert_eq!(encode(b"f"), "MY======");
    assert_eq!(encode(b"fo"), "MZXQ====");
    assert_eq!(encode(b"foo"), "MZXW6===");
    assert_eq!(encode(b"foob"), "MZXW6YQ=");
    assert_eq!(encode(b"fooba"), "MZXW6YTB");
    assert_eq!(encode(b"foobar"), "MZXW6YTBOI======");
    assert_eq!(decode("MZXW6YTBOI======").unwrap(), b"foobar");
    assert_eq!(
        decode("mzxw6ytboi").unwrap(),
        b"foobar",
        "lowercase and unpadded input is accepted"
    );
    assert!(decode("MZXW6YTB0I").is_err(), "0 is not a base32 digit");
    let secret = RFC_SECRET;
    assert_eq!(decode(&encode(secret)).unwrap(), secret);
}
