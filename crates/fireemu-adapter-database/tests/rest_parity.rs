//! REST answers checked against the production recording RTDB-REST-20261104-01 (rows `r1-rest`
//! and `r2-rest`, identical in both rounds) and against the official emulator
//! (firebase-database-emulator v4.11.2, the jar firebase-tools 15.28.2 runs), probed offline on
//! 2026-11-04. Where the jar answered like production, both profiles answer that way. Where
//! they differ (the `writeSizeLimit` refusal text and a malformed escape in the path), the
//! strict profile (`production_shapes`) answers as production and the emulator profile as the
//! jar. The near misses come from the same jar probe.

#![allow(clippy::too_many_lines)]

use std::sync::{Arc, Mutex};

use fireemu_adapter_database::rest::{Database, Handled, HttpRequest, HttpResponse, RestOptions};
use fireemu_adapter_database::server::{serve, ServerConfig};
use proptest::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const NOW: i64 = 1_792_408_481_564;

/// The two profiles: the emulator profile (`false`) and strict (`true`).
const PROFILES: [bool; 2] = [false, true];

/// The setup-mix body of the recording.
const MIX: &str = r#"{"a":{".value":3,".priority":2},"b":{".value":"x",".priority":"p"},"c":{".value":true,".priority":1},"d":{"h":1,".priority":3},"e":7,"f":"abc"}"#;
const MIX_PLAIN: &str = r#"{"a":3,"b":"x","c":true,"d":{"h":1},"e":7,"f":"abc"}"#;
const TIMEOUT_FORMAT: &str =
    "timeout must contain length and unit (s/seconds/min/minutes), such as 1s, 2seconds, or 3min";

fn options(strict: bool) -> RestOptions {
    RestOptions {
        production_shapes: strict,
        ..RestOptions::default()
    }
}

fn db(strict: bool) -> Database {
    Database::new(options(strict), 42)
}

fn send(
    db: &mut Database,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> HttpResponse {
    let request = HttpRequest {
        method: method.to_owned(),
        target: target.to_owned(),
        headers: headers
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
        body: body.as_bytes().to_vec(),
    };
    match db.handle(&request, NOW) {
        Handled::Response { response, .. } => response,
        Handled::Stream { .. } => panic!("unexpected stream for {method} {target}"),
    }
}

fn get(db: &mut Database, target: &str) -> (u16, String) {
    let response = send(db, "GET", target, &[], "");
    (response.status, String::from_utf8(response.body).unwrap())
}

fn header<'a>(response: &'a HttpResponse, name: &str) -> Option<&'a str> {
    response
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The recorder's allowlist, without `content-length` (the HTTP layer adds it from the body,
/// except where a test below asks for it explicitly).
const RECORDED: [&str; 6] = [
    "etag",
    "content-type",
    "cache-control",
    "access-control-allow-origin",
    "access-control-expose-headers",
    "content-disposition",
];

fn recorded(response: &HttpResponse) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = RECORDED
        .iter()
        .filter_map(|name| header(response, name).map(|v| ((*name).to_owned(), v.to_owned())))
        .collect();
    out.sort();
    out
}

fn json_headers() -> Vec<(String, String)> {
    let mut out = vec![
        ("access-control-allow-origin".to_owned(), "*".to_owned()),
        ("cache-control".to_owned(), "no-cache".to_owned()),
        (
            "content-type".to_owned(),
            "application/json; charset=utf-8".to_owned(),
        ),
    ];
    out.sort();
    out
}

fn with(mut headers: Vec<(String, String)>, extra: &[(&str, &str)]) -> Vec<(String, String)> {
    headers.extend(
        extra
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned())),
    );
    headers.sort();
    headers
}

fn error(message: &str) -> String {
    format!(
        "{{\n  \"error\" : \"{}\"\n}}\n",
        message.replace('"', "\\\"")
    )
}

fn seeded(strict: bool) -> Database {
    let mut db = db(strict);
    assert_eq!(
        send(&mut db, "PUT", "/s/mix.json?ns=p", &[], MIX).status,
        200
    );
    db
}

// ---------------------------------------------------------------------------------------
// timeout (production r1/r2 timeout-5s, timeout-5, timeout-abc, timeout-0s; jar == production)

#[test]
fn the_recorded_timeout_answers_in_both_profiles() {
    for strict in PROFILES {
        let mut db = seeded(strict);
        for (query, status, body) in [
            ("timeout=5s", 200, MIX_PLAIN.to_owned()),
            ("timeout=5", 400, error(TIMEOUT_FORMAT)),
            ("timeout=abc", 400, error(TIMEOUT_FORMAT)),
            ("timeout=0s", 400, error("timeout must be positive")),
        ] {
            let response = send(
                &mut db,
                "GET",
                &format!("/s/mix.json?ns=p&{query}"),
                &[],
                "",
            );
            assert_eq!(response.status, status, "strict={strict} {query}");
            assert_eq!(
                recorded(&response),
                json_headers(),
                "strict={strict} {query}"
            );
            let text = String::from_utf8(response.body).unwrap();
            assert_eq!(text, body, "strict={strict} {query}");
        }
        // The recorded byte lengths.
        assert_eq!(error(TIMEOUT_FORMAT).len(), 110);
        assert_eq!(error("timeout must be positive").len(), 43);
    }
}

#[test]
fn timeout_follows_the_scala_duration_grammar_of_the_official_emulator() {
    let too_long = error("timeout must not be longer than 15 minutes");
    let positive = error("timeout must be positive");
    let format = error(TIMEOUT_FORMAT);
    let accepted = [
        "1seconds",
        "2seconds",
        "3min",
        "1minutes",
        "1second",
        "1minute",
        "1m",
        "1ms",
        "5sec",
        "5secs",
        "5mins",
        "1.5s",
        "0.5s",
        "900s",
        "15min",
        "15minutes",
        "900000ms",
        "900000000000ns",
        "%205s",
        "5%20s",
        "5s%20",
        "5%20m",
        "5%09s",
        "%015s",
        // `+` is a space in this value (the jar decodes it so), `%2B` is the sign.
        "+5s",
        "%2B5s",
        "05s",
        "1e1s",
        "5.s",
        ".5s",
        "5e-1s",
        "0x1p3s",
        "0x10p0s",
        "1ns",
        "0.5ns",
        "0.6ns",
        "1%C2%B5s",
        "1micro",
        "1micros",
        "1nanos",
        "1milli",
        "1millis",
        "1millisecond",
        "1.0e0min",
        "00000000000000000000000000001s",
        // Java's whitespace (an em space, a unit separator), hexadecimal doubles, the edges.
        "5%E2%80%83s",
        "5%1Cs",
        "0x1p-1s",
        "0X1P3s",
        "0x.8p1s",
        "0x1.8p1s",
        "0x384p0s",
        "0x1.c2p9s",
    ];
    let refused = [
        ("1h", &too_long),
        ("1hr", &too_long),
        ("1hrs", &too_long),
        ("1hours", &too_long),
        ("1d", &too_long),
        ("1day", &too_long),
        ("1days", &too_long),
        ("901s", &too_long),
        ("16min", &too_long),
        ("3600s", &too_long),
        ("900001ms", &too_long),
        ("900000000001ns", &too_long),
        ("999999999s", &too_long),
        ("2147483647s", &too_long),
        ("2147483648s", &too_long),
        ("9007199254740993ns", &too_long),
        ("9223372036854775807ns", &too_long),
        // 2^63 ns exactly, read as a double, is still a duration.
        ("9223372036.854775807s", &too_long),
        ("4611686018427387904ns", &too_long),
        ("9007199254740993%C2%B5s", &too_long),
        ("0x385p0s", &too_long),
        ("0x1.c21p9s", &too_long),
        ("0x1p10s", &too_long),
        ("-9007199254740993ns", &positive),
        ("-9223372036854775807ns", &positive),
        ("-9007199254740993%C2%B5s", &positive),
        ("-0x1p3s", &positive),
        ("0x1p-31s", &positive),
        // A figure space and the no-break spaces are not Java whitespace.
        ("5%E2%80%87s", &format),
        ("5%C2%A0s", &format),
        ("5%C2%85s", &format),
        ("-%2B5s", &format),
        ("%2B-5s", &format),
        ("-1e19s", &format),
        ("0xp1s", &format),
        ("0x1ps", &format),
        ("0x1p1x1s", &format),
        ("0x1p-1x1s", &format),
        ("0xgp1s", &format),
        ("-1s", &positive),
        ("-0s", &positive),
        ("0min", &positive),
        ("0seconds", &positive),
        ("0.1ns", &positive),
        ("1e-400s", &positive),
        ("-1e-400s", &positive),
        ("0.0000000001s", &positive),
        ("5", &format),
        ("abc", &format),
        ("", &format),
        ("s", &format),
        ("5S", &format),
        ("5MIN", &format),
        ("1Min", &format),
        ("1sS", &format),
        ("5ss", &format),
        ("5s5", &format),
        ("0x5s", &format),
        ("1us", &format),
        ("1e1", &format),
        ("1.5", &format),
        ("1dd", &format),
        ("NaNs", &format),
        ("Infinitys", &format),
        ("Inf", &format),
        ("%2BInf", &format),
        ("PlusInf", &format),
        ("MinusInf", &format),
        ("-Inf", &format),
        ("5%2Bs", &format),
        ("5_000s", &format),
        ("5,0s", &format),
        ("%D9%A5s", &format),
        ("1e400s", &format),
        ("99999999999999999999s", &format),
        ("9223372036854775808ns", &format),
    ];
    for strict in PROFILES {
        let mut db = seeded(strict);
        for value in accepted {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                (200, MIX_PLAIN.to_owned()),
                "strict={strict} timeout={value}"
            );
        }
        for (value, body) in refused {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                (400, body.clone()),
                "strict={strict} timeout={value}"
            );
        }
        // Beyond the 2^63 - 1 ns a Scala duration holds: the jar's own 500.
        for value in [
            "9223372036854775807s",
            "2147483647min",
            "-9007199254740992d",
            "-9223372036854775808ns",
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                (500, error("Unexpected server error")),
                "strict={strict} timeout={value}"
            );
        }
    }
}

#[test]
fn timeout_is_checked_on_plain_reads_only() {
    for strict in PROFILES {
        let mut db = seeded(strict);
        // Writes ignore it, whatever it says.
        for (method, body, answer) in [
            ("PUT", r#"{"k":1}"#, r#"{"k":1}"#),
            ("PATCH", r#"{"k":1}"#, r#"{"k":1}"#),
            ("DELETE", "", "null"),
        ] {
            for value in ["5", "0s", "5s"] {
                let response = send(
                    &mut db,
                    method,
                    &format!("/s/tw.json?ns=p&timeout={value}"),
                    &[],
                    body,
                );
                assert_eq!(
                    (response.status, String::from_utf8(response.body).unwrap()),
                    (200, answer.to_owned()),
                    "strict={strict} {method} timeout={value}"
                );
            }
        }
        let post = send(&mut db, "POST", "/s/tw.json?ns=p&timeout=5", &[], "1");
        assert_eq!(post.status, 200);
        // A conditional read and a shallow read ignore it too.
        let conditional = send(
            &mut db,
            "GET",
            "/s/mix.json?ns=p&timeout=0s",
            &[("if-none-match", "\"x\"")],
            "",
        );
        assert_eq!(conditional.status, 200, "strict={strict}");
        assert_eq!(
            get(&mut db, "/s/mix.json?ns=p&timeout=0s&shallow=true"),
            (
                200,
                r#"{"e":true,"f":true,"a":true,"b":true,"c":true,"d":true}"#.to_owned()
            )
        );
        // A read through the method override is a read.
        let overridden = send(
            &mut db,
            "POST",
            "/s/mix.json?ns=p&timeout=5",
            &[("X-HTTP-Method-Override", "GET")],
            "",
        );
        assert_eq!(overridden.status, 400);
        // Other output options do not hide it.
        for extra in [
            "print=silent",
            "format=export",
            "download=x",
            "print=pretty",
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout=0s&{extra}")),
                (400, error("timeout must be positive")),
                "strict={strict} {extra}"
            );
        }
        let etag = send(
            &mut db,
            "GET",
            "/s/mix.json?ns=p&timeout=5",
            &[("X-Firebase-ETag", "true")],
            "",
        );
        assert_eq!(etag.status, 400);
        assert_eq!(header(&etag, "ETag"), None);
    }
}

#[test]
fn timeout_comes_after_the_query_bounds_and_before_the_limits_rules_and_index() {
    let format = error(TIMEOUT_FORMAT);
    for strict in PROFILES {
        let mut db = seeded(strict);
        for (query, body) in [
            ("timeout=5&format=bad", error("Export format must be export if present")),
            ("timeout=5&orderBy=bad", error("orderBy must be a valid JSON encoded path")),
            (
                "timeout=5&limitToFirst=1",
                error("orderBy must be defined when other query parameters are defined"),
            ),
            (
                "timeout=5&orderBy=%22%24key%22&startAt=1",
                error("Provided key index type is invalid, must be string"),
            ),
            (
                "timeout=5&orderBy=%22%24priority%22&startAt=1&startAfter=1",
                error("Only one of startAfter and startAt may be specified"),
            ),
            (
                "timeout=5&orderBy=%22%24priority%22&equalTo=1&startAt=1",
                error("equalTo cannot be specified in addition to startAfter, startAt, endAt, or endBefore"),
            ),
            (
                "timeout=5&orderBy=%22%24priority%22&startAt=%7Bx",
                error("Constraint index field must be a JSON primitive"),
            ),
            ("timeout=5&orderBy=%22%24key%22&limitToFirst=x", format.clone()),
            ("timeout=5&orderBy=%22%24priority%22&limitToFirst=0", format.clone()),
            (
                "timeout=5&orderBy=%22%24priority%22&limitToFirst=1&limitToLast=1",
                format.clone(),
            ),
            ("timeout=5&orderBy=%22%24key%22&limitToFirst=1", format.clone()),
            // Before the index check.
            ("timeout=5&orderBy=%22zz%22", format.clone()),
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&{query}")),
                (400, body),
                "strict={strict} {query}"
            );
        }
        // The bounds come before the limits, timeout or not.
        assert_eq!(
            get(
                &mut db,
                "/s/mix.json?ns=p&orderBy=%22%24key%22&limitToFirst=x&startAt=1"
            ),
            (
                400,
                error("Provided key index type is invalid, must be string")
            )
        );
        assert_eq!(
            get(
                &mut db,
                "/s/mix.json?ns=p&orderBy=%22%24key%22&limitToFirst=1&limitToLast=1&startAt=1"
            ),
            (
                400,
                error("Provided key index type is invalid, must be string")
            )
        );
        assert_eq!(
            get(
                &mut db,
                "/s/mix.json?ns=p&orderBy=%22%24key%22&endAt=1&startAt=%22a%22,%22b%22"
            ),
            (400, error("Too many parameters for key index"))
        );
    }
}

#[test]
fn timeout_comes_before_the_rules() {
    for strict in PROFILES {
        let mut db = seeded(strict);
        let rules = r#"{"rules":{".read":false,".write":false}}"#;
        let loaded = send(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=p",
            &[("Authorization", "Bearer owner")],
            rules,
        );
        assert_eq!(loaded.status, 200);
        assert_eq!(
            get(&mut db, "/s/mix.json?ns=p&timeout=0s"),
            (400, error("timeout must be positive")),
            "strict={strict}"
        );
        assert_eq!(get(&mut db, "/s/mix.json?ns=p&timeout=5s").0, 401);
    }
}

/// A reference for the accepted timeouts: a decimal length and a unit of the table, the
/// whole within (0, 15 min] after rounding to whole nanoseconds.
fn reference_nanos(length: f64, unit: &str) -> Option<f64> {
    let per = match unit {
        "d" | "day" | "days" => 86_400e9,
        "h" | "hr" | "hrs" | "hour" | "hours" => 3_600e9,
        "m" | "min" | "mins" | "minute" | "minutes" => 60e9,
        "s" | "sec" | "secs" | "second" | "seconds" => 1e9,
        "ms" | "milli" | "millis" | "millisecond" | "milliseconds" => 1e6,
        "\u{b5}s" | "micro" | "micros" | "microsecond" | "microseconds" => 1e3,
        "ns" | "nano" | "nanos" | "nanosecond" | "nanoseconds" => 1.0,
        _ => return None,
    };
    Some((per * length).round())
}

const UNITS: [&str; 36] = [
    "d",
    "day",
    "days",
    "h",
    "hr",
    "hrs",
    "hour",
    "hours",
    "m",
    "min",
    "mins",
    "minute",
    "minutes",
    "s",
    "sec",
    "secs",
    "second",
    "seconds",
    "ms",
    "milli",
    "millis",
    "millisecond",
    "milliseconds",
    "\u{b5}s",
    "micro",
    "micros",
    "microsecond",
    "microseconds",
    "ns",
    "nano",
    "nanos",
    "nanosecond",
    "nanoseconds",
    "S",
    "Min",
    "us",
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn timeouts_are_judged_by_length_and_unit(
        whole in 0u32..2_000,
        fraction in prop::option::of(0u32..1000),
        negative in any::<bool>(),
        unit in prop::sample::select(UNITS.to_vec()),
        spaces in prop::collection::vec(0usize..8, 0..3),
    ) {
        let mut text = format!("{}{whole}", if negative { "-" } else { "" });
        if let Some(fraction) = fraction {
            text = format!("{text}.{fraction:03}");
        }
        text.push_str(unit);
        // Whitespace anywhere is dropped before the text is read.
        let mut spaced: Vec<char> = text.chars().collect();
        for at in spaces {
            spaced.insert(at.min(spaced.len()), ' ');
        }
        let spaced: String = spaced.into_iter().collect();
        let length: f64 = text.trim_end_matches(|c: char| c.is_alphabetic()).parse().unwrap();
        let expected = match reference_nanos(length, unit) {
            None => (400, error(TIMEOUT_FORMAT)),
            Some(nanos) if nanos <= 0.0 => (400, error("timeout must be positive")),
            Some(nanos) if nanos > 900e9 => (400, error("timeout must not be longer than 15 minutes")),
            Some(_) => (200, "1".to_owned()),
        };
        let encoded = spaced.replace(' ', "%20").replace('\u{b5}', "%C2%B5");
        for strict in PROFILES {
            let mut db = db(strict);
            send(&mut db, "PUT", "/t.json?ns=p", &[], "1");
            prop_assert_eq!(get(&mut db, &format!("/t.json?ns=p&timeout={encoded}")), expected.clone(), "{}", text);
        }
    }
}

// ---------------------------------------------------------------------------------------
// writeSizeLimit (production r1/r2 wsl-foo, wsl-10: production != jar)

#[test]
fn the_write_size_limit_refusal_lists_the_values_in_each_profiles_order() {
    let production = "writeSizeLimit should be one of {tiny, large, small, medium, unlimited}";
    let jar = "writeSizeLimit should be one of {medium, tiny, large, unlimited, small}";
    for strict in PROFILES {
        let expected = error(if strict { production } else { jar });
        assert_eq!(expected.len(), 90);
        let mut db = db(strict);
        for value in ["foo", "10", "TINY", ""] {
            for (method, body) in [
                ("PUT", r#"{"k":1}"#),
                ("PATCH", r#"{"k":1}"#),
                ("POST", "1"),
                ("DELETE", ""),
            ] {
                let response = send(
                    &mut db,
                    method,
                    &format!("/wl.json?ns=p&writeSizeLimit={value}"),
                    &[],
                    body,
                );
                assert_eq!(response.status, 400, "strict={strict} {method} {value}");
                assert_eq!(recorded(&response), json_headers());
                assert_eq!(String::from_utf8(response.body).unwrap(), expected);
            }
        }
        for value in ["tiny", "small", "medium", "large", "unlimited"] {
            let response = send(
                &mut db,
                "PUT",
                &format!("/wl.json?ns=p&writeSizeLimit={value}"),
                &[],
                r#"{"k":1}"#,
            );
            assert_eq!(response.status, 200, "strict={strict} {value}");
        }
        // It comes before disableTriggers, the conditional headers and the query.
        for (method, query, headers) in [
            ("PUT", "writeSizeLimit=foo&disableTriggers=x", &[][..]),
            ("PATCH", "writeSizeLimit=foo", &[("if-match", "x")][..]),
            ("POST", "writeSizeLimit=foo", &[("if-none-match", "x")][..]),
            ("PUT", "writeSizeLimit=foo&orderBy=1", &[][..]),
            ("PUT", "writeSizeLimit=foo&format=bad", &[][..]),
        ] {
            let response = send(
                &mut db,
                method,
                &format!("/wl.json?ns=p&{query}"),
                headers,
                "1",
            );
            assert_eq!(
                String::from_utf8(response.body).unwrap(),
                expected,
                "strict={strict} {method} {query}"
            );
        }
    }
}

#[test]
fn reads_ignore_write_size_limit_and_writes_ignore_format() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/w.json?ns=p", &[], "1");
        for value in ["foo", "TINY", ""] {
            assert_eq!(
                get(&mut db, &format!("/w.json?ns=p&writeSizeLimit={value}")),
                (200, "1".to_owned()),
                "strict={strict}"
            );
        }
        let overridden = send(
            &mut db,
            "POST",
            "/w.json?ns=p&writeSizeLimit=foo",
            &[("X-HTTP-Method-Override", "GET")],
            "",
        );
        assert_eq!(overridden.status, 200);
        // The read still checks format.
        assert_eq!(
            get(&mut db, "/w.json?ns=p&writeSizeLimit=foo&format=bad"),
            (400, error("Export format must be export if present"))
        );
        for (method, body, answer) in [
            ("PUT", "2", "2"),
            ("PATCH", r#"{"a":1}"#, r#"{"a":1}"#),
            ("DELETE", "", "null"),
        ] {
            let response = send(&mut db, method, "/f.json?ns=p&format=bad", &[], body);
            assert_eq!(
                (response.status, String::from_utf8(response.body).unwrap()),
                (200, answer.to_owned()),
                "strict={strict} {method}"
            );
        }
        assert_eq!(
            send(&mut db, "POST", "/f.json?ns=p&format=bad", &[], "1").status,
            200
        );
    }
}

// ---------------------------------------------------------------------------------------
// The member order of a ranged query (production r1/r2 order-priority-range; jar == production)

#[test]
fn a_ranged_query_without_a_limit_answers_in_query_order() {
    for strict in PROFILES {
        let mut db = seeded(strict);
        let response = send(
            &mut db,
            "GET",
            "/s/mix.json?ns=p&orderBy=%22%24priority%22&startAt=1&endAt=2",
            &[],
            "",
        );
        assert_eq!(response.status, 200);
        assert_eq!(recorded(&response), json_headers());
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            r#"{"c":true,"a":3}"#
        );
        for (query, body) in [
            (
                "orderBy=%22%24priority%22&startAt=0&endAt=10",
                r#"{"c":true,"a":3,"d":{"h":1}}"#,
            ),
            (
                "orderBy=%22%24priority%22&startAt=1",
                r#"{"c":true,"a":3,"d":{"h":1},"b":"x"}"#,
            ),
            // Five members: the order of a Scala hash map.
            (
                "orderBy=%22%24priority%22&endAt=3",
                r#"{"e":7,"f":"abc","a":3,"c":true,"d":{"h":1}}"#,
            ),
            (
                "orderBy=%22%24priority%22&startAfter=1",
                r#"{"a":3,"d":{"h":1},"b":"x"}"#,
            ),
            (
                "orderBy=%22%24priority%22&endBefore=3",
                r#"{"e":7,"f":"abc","c":true,"a":3}"#,
            ),
            (
                "orderBy=%22%24priority%22&startAt=1,%22b%22&endAt=3",
                r#"{"c":true,"a":3,"d":{"h":1}}"#,
            ),
            ("orderBy=%22%24priority%22&startAt=%22a%22", r#"{"b":"x"}"#),
            ("orderBy=%22%24priority%22&equalTo=1", r#"{"c":true}"#),
            (
                "orderBy=%22%24key%22&startAt=%22b%22&endAt=%22e%22",
                r#"{"b":"x","c":true,"d":{"h":1},"e":7}"#,
            ),
            // A limit answers in key order, as does a query that only orders.
            (
                "orderBy=%22%24priority%22&startAt=1&endAt=3&limitToFirst=3",
                r#"{"a":3,"c":true,"d":{"h":1}}"#,
            ),
            (
                "orderBy=%22%24priority%22&startAt=1&endAt=3&limitToLast=2",
                r#"{"a":3,"d":{"h":1}}"#,
            ),
            (
                "orderBy=%22%24priority%22&limitToFirst=4",
                r#"{"a":3,"c":true,"e":7,"f":"abc"}"#,
            ),
            ("orderBy=%22%24priority%22", MIX_PLAIN),
            (
                "orderBy=%22%24priority%22&startAt=1&endAt=2&format=export",
                r#"{"c":{".value":true,".priority":1.0},"a":{".value":3,".priority":2.0}}"#,
            ),
            (
                "orderBy=%22%24priority%22&startAt=1&endAt=2&print=pretty",
                "{\n  \"c\" : true,\n  \"a\" : 3\n}\n",
            ),
            (
                "orderBy=%22%24priority%22&startAt=1&endAt=2&callback=cb",
                r#"/**/ cb({"c":true,"a":3});"#,
            ),
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&{query}")),
                (200, body.to_owned()),
                "strict={strict} {query}"
            );
        }
    }
}

#[test]
fn ranged_queries_of_five_or_more_members_answer_in_hash_order() {
    let big: String = format!(
        "{{{}}}",
        (1..=8)
            .map(|i| format!(r#""k{i}":{{".value":{i},".priority":{}}}"#, 10 - i))
            .collect::<Vec<_>>()
            .join(",")
    );
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/big.json?ns=p", &[], &big);
        send(
            &mut db,
            "PUT",
            "/nul.json?ns=p",
            &[],
            r#"{"p":0,"q":1,"r":2,"s":3,"t":4,"u":5}"#,
        );
        send(
            &mut db,
            "PUT",
            "/nul2.json?ns=p",
            &[],
            r#"{"p":0,"q":1,"r":2,"s":{".value":3,".priority":1},"t":{".value":4,".priority":2},"u":{".value":5,".priority":"x"}}"#,
        );
        send(
            &mut db,
            "PUT",
            "/ints.json?ns=p",
            &[],
            r#"{"-1":1,"01":2,"2147483648":3,"10":4,"2":5,"a":6,"B":7}"#,
        );
        send(
            &mut db,
            "PUT",
            "/ch.json?ns=p",
            &[],
            r#"{"a":{"n":3},"b":{"n":1},"c":{"n":2},"d":{"n":"x"},"e":{"m":1}}"#,
        );
        send(
            &mut db,
            "PUT",
            "/.settings/rules.json?ns=p",
            &[("Authorization", "Bearer owner")],
            r#"{"rules":{".read":true,".write":true,"ch":{".indexOn":["n"]},"nul2":{".indexOn":[".value"]}}}"#,
        );
        for (target, body) in [
            (
                "/big.json?orderBy=%22%24priority%22&startAt=0",
                r#"{"k2":2,"k5":5,"k6":6,"k7":7,"k1":1,"k4":4,"k3":3,"k8":8}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&startAt=5",
                r#"{"k2":2,"k5":5,"k1":1,"k4":4,"k3":3}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&startAt=6",
                r#"{"k4":4,"k3":3,"k2":2,"k1":1}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&endAt=100",
                r#"{"k2":2,"k5":5,"k6":6,"k7":7,"k1":1,"k4":4,"k3":3,"k8":8}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&limitToFirst=6",
                r#"{"k3":3,"k4":4,"k5":5,"k6":6,"k7":7,"k8":8}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&limitToLast=6",
                r#"{"k1":1,"k2":2,"k3":3,"k4":4,"k5":5,"k6":6}"#,
            ),
            (
                "/big.json?orderBy=%22%24priority%22&startAt=0&limitToFirst=6",
                r#"{"k3":3,"k4":4,"k5":5,"k6":6,"k7":7,"k8":8}"#,
            ),
            (
                "/big.json?orderBy=%22%24key%22&startAt=%22k2%22",
                r#"{"k2":2,"k5":5,"k6":6,"k7":7,"k4":4,"k3":3,"k8":8}"#,
            ),
            (
                "/big.json?orderBy=%22%24key%22&startAt=%22k2%22&limitToFirst=7",
                r#"{"k2":2,"k3":3,"k4":4,"k5":5,"k6":6,"k7":7,"k8":8}"#,
            ),
            (
                "/nul.json?orderBy=%22%24priority%22&equalTo=null",
                r#"{"s":3,"t":4,"u":5,"q":1,"p":0,"r":2}"#,
            ),
            (
                "/nul.json?orderBy=%22%24priority%22&equalTo=null&limitToFirst=6",
                r#"{"p":0,"q":1,"r":2,"s":3,"t":4,"u":5}"#,
            ),
            (
                "/nul.json?orderBy=%22%24key%22&startAt=%22p%22",
                r#"{"s":3,"t":4,"u":5,"q":1,"p":0,"r":2}"#,
            ),
            // startAt null alone selects everything and answers as an unbounded query.
            (
                "/nul.json?orderBy=%22%24priority%22&startAt=null",
                r#"{"p":0,"q":1,"r":2,"s":3,"t":4,"u":5}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24priority%22&startAt=null",
                r#"{"p":0,"q":1,"r":2,"s":3,"t":4,"u":5}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24priority%22&endAt=null",
                r#"{"p":0,"q":1,"r":2}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24priority%22&startAt=null,%22q%22",
                r#"{"s":3,"t":4,"u":5,"q":1,"r":2}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24priority%22&endAt=%22z%22",
                r#"{"s":3,"t":4,"u":5,"q":1,"p":0,"r":2}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24priority%22&startAt=false",
                r#"{"s":3,"t":4,"u":5}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24value%22&startAt=null",
                r#"{"p":0,"q":1,"r":2,"s":3,"t":4,"u":5}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24value%22&startAt=false",
                r#"{"s":3,"t":4,"u":5,"q":1,"p":0,"r":2}"#,
            ),
            (
                "/nul2.json?orderBy=%22%24value%22&endAt=100",
                r#"{"s":3,"t":4,"u":5,"q":1,"p":0,"r":2}"#,
            ),
            (
                "/ch.json?orderBy=%22n%22&startAt=null",
                r#"{"a":{"n":3},"b":{"n":1},"c":{"n":2},"d":{"n":"x"},"e":{"m":1}}"#,
            ),
            ("/ch.json?orderBy=%22n%22&endAt=null", r#"{"e":{"m":1}}"#),
            (
                "/ch.json?orderBy=%22n%22&startAt=1",
                r#"{"b":{"n":1},"c":{"n":2},"a":{"n":3},"d":{"n":"x"}}"#,
            ),
            (
                "/ints.json?orderBy=%22%24key%22&startAt=%22-1%22",
                r#"{"2147483648":3,"a":6,"10":4,"B":7,"2":5,"-1":1,"01":2}"#,
            ),
        ] {
            assert_eq!(
                get(&mut db, &format!("{target}&ns=p")),
                (200, body.to_owned()),
                "strict={strict} {target}"
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// A ranged query answers the members a query that only orders would, in query order
    /// (priority, then key) while there are at most four of them.
    #[test]
    fn ranged_answers_are_the_ordered_members_permuted(
        priorities in prop::collection::btree_map("[a-h]", prop::option::of(0i32..5), 1..8),
        start in 0i32..5,
        span in 0i32..5,
    ) {
        let body = format!(
            "{{{}}}",
            priorities
                .iter()
                .map(|(key, priority)| match priority {
                    Some(p) => format!(r#""{key}":{{".value":1,".priority":{p}}}"#),
                    None => format!(r#""{key}":1"#),
                })
                .collect::<Vec<_>>()
                .join(",")
        );
        let end = start + span;
        let mut in_range: Vec<(i32, &String)> = priorities
            .iter()
            .filter_map(|(key, priority)| priority.filter(|p| (start..=end).contains(p)).map(|p| (p, key)))
            .collect();
        in_range.sort();
        for strict in PROFILES {
            let mut db = db(strict);
            send(&mut db, "PUT", "/r.json?ns=p", &[], &body);
            let (status, text) = get(&mut db, &format!("/r.json?ns=p&orderBy=%22%24priority%22&startAt={start}&endAt={end}"));
            prop_assert_eq!(status, 200);
            let keys: Vec<String> = if text == "{}" {
                Vec::new()
            } else {
                text.trim_start_matches('{').trim_end_matches('}').split(',')
                    .map(|member| member.split(':').next().unwrap().trim_matches('"').to_owned())
                    .collect()
            };
            let mut sorted_keys = keys.clone();
            sorted_keys.sort();
            let mut expected: Vec<String> = in_range.iter().map(|(_, k)| (*k).clone()).collect();
            let query_order = expected.clone();
            expected.sort();
            prop_assert_eq!(&sorted_keys, &expected);
            if keys.len() <= 4 {
                prop_assert_eq!(&keys, &query_order);
            }
        }
    }
}

// ---------------------------------------------------------------------------------------
// shallow with a query (production r1/r2 shallow-limit; jar == production)

#[test]
fn a_shallow_read_pages_its_keys_with_limit_to_first_and_start_after() {
    for strict in PROFILES {
        let mut db = seeded(strict);
        let response = send(
            &mut db,
            "GET",
            "/s/mix.json?ns=p&shallow=true&limitToFirst=1",
            &[],
            "",
        );
        assert_eq!(response.status, 200);
        assert_eq!(recorded(&response), json_headers());
        assert_eq!(String::from_utf8(response.body).unwrap(), r#"{"a":true}"#);
        let all = r#"{"e":true,"f":true,"a":true,"b":true,"c":true,"d":true}"#;
        for (query, status, body) in [
            ("limitToFirst=3", 200, r#"{"a":true,"b":true,"c":true}"#.to_owned()),
            ("limitToFirst=1&format=export", 200, r#"{"a":true}"#.to_owned()),
            ("limitToFirst=1&print=pretty", 200, "{\n  \"a\" : true\n}\n".to_owned()),
            ("startAfter=b&limitToFirst=2", 200, r#"{"c":true,"d":true}"#.to_owned()),
            ("startAfter=b", 200, r#"{"c":true,"d":true,"e":true,"f":true}"#.to_owned()),
            // The bound is the raw text, not JSON.
            ("startAfter=%22c%22", 200, all.to_owned()),
            ("startAfter=", 200, all.to_owned()),
            ("startAfter=f", 200, "null".to_owned()),
            ("startAfter=%7Bx", 200, "null".to_owned()),
            // equalTo and endBefore are ignored.
            ("equalTo=%22c%22", 200, all.to_owned()),
            ("equalTo=%7Bx", 200, all.to_owned()),
            ("endBefore=%22c%22", 200, all.to_owned()),
            ("", 200, all.to_owned()),
            ("limitToFirst=x", 400, error("limitToFirst must be an integer")),
            ("limitToFirst=0", 400, error("limitToFirst must be positive")),
            ("limitToFirst=-1", 400, error("limitToFirst must be positive")),
            ("limitToFirst=x&limitToLast=1", 400, error("limitToFirst must be an integer")),
            ("limitToFirst=x&startAt=1", 400, error("limitToFirst must be an integer")),
            ("limitToLast=1", 400, error("limitToLast not supported for with shallow GET")),
            ("limitToLast=x", 400, error("limitToLast not supported for with shallow GET")),
            ("limitToFirst=1&limitToLast=1", 400, error("limitToLast not supported for with shallow GET")),
            ("startAt=1&limitToLast=1", 400, error("limitToLast not supported for with shallow GET")),
            ("endAt=1&limitToLast=1", 400, error("limitToLast not supported for with shallow GET")),
            ("startAt=1", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("startAt=%22b%22&limitToFirst=2", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("equalTo=1&startAt=1", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("startAfter=1&startAt=1", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("endAt=1&startAt=1", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("endAt=%22c%22", 400, error("endAt not supported for with shallow GET, use limitToFirst")),
            ("orderBy=%22%24key%22&limitToLast=1", 400, error("limitToLast not supported for with shallow GET")),
            ("orderBy=%22%24key%22&startAt=1", 400, error("startAt not supported for with shallow GET, use startAfter")),
            ("orderBy=%22%24key%22", 400, error("orderBy not supported for with shallow GET, keys are returned in lexicographical order")),
            ("orderBy=bad", 400, error("orderBy not supported for with shallow GET, keys are returned in lexicographical order")),
            ("orderBy=%22%24value%22&limitToFirst=1", 400, error("orderBy not supported for with shallow GET, keys are returned in lexicographical order")),
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&shallow=true&{query}")),
                (status, body),
                "strict={strict} {query}"
            );
        }
        // Only `true` in any case makes a read shallow.
        for value in ["TRUE", "True", "tRuE"] {
            assert_eq!(
                get(
                    &mut db,
                    &format!("/s/mix.json?ns=p&shallow={value}&limitToFirst=1")
                ),
                (200, r#"{"a":true}"#.to_owned())
            );
        }
        for value in ["yes", "1", "", "false", "FALSE"] {
            assert_eq!(
                get(
                    &mut db,
                    &format!("/s/mix.json?ns=p&shallow={value}&limitToFirst=1")
                ),
                (
                    400,
                    error("orderBy must be defined when other query parameters are defined")
                ),
                "shallow={value}"
            );
        }
        assert_eq!(
            get(&mut db, "/s/mix.json?ns=p&shallow=yes"),
            (200, MIX_PLAIN.to_owned())
        );
        // A leaf and a missing location.
        send(&mut db, "PUT", "/s/leaf.json?ns=p", &[], r#""t""#);
        assert_eq!(
            get(&mut db, "/s/leaf.json?ns=p&shallow=true&limitToFirst=1"),
            (200, r#""t""#.to_owned())
        );
        assert_eq!(
            get(&mut db, "/s/none.json?ns=p&shallow=true&limitToFirst=1"),
            (200, "null".to_owned())
        );
    }
}

#[test]
fn shallow_keys_come_in_the_order_of_a_scala_map() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(
            &mut db,
            "PUT",
            "/ints.json?ns=p",
            &[],
            r#"{"-1":1,"01":2,"2147483648":3,"10":4,"2":5,"a":6,"B":7}"#,
        );
        send(
            &mut db,
            "PUT",
            "/k4.json?ns=p",
            &[],
            r#"{"10":1,"2":1,"a":1,"01":1}"#,
        );
        send(
            &mut db,
            "PUT",
            "/q5.json?ns=p",
            &[],
            r#"{"a":{".value":1,".priority":3},"b":{".value":1,".priority":1},"c":{".value":1,".priority":2},"d":1,"e":1}"#,
        );
        send(
            &mut db,
            "PUT",
            "/sp.json?ns=p",
            &[],
            r#"{"a":1,"b":2,".priority":5}"#,
        );
        send(
            &mut db,
            "PUT",
            "/sp5.json?ns=p",
            &[],
            r#"{"a":1,"b":2,"c":3,"d":4,"e":5,".priority":5}"#,
        );
        send(
            &mut db,
            "PUT",
            "/pl.json?ns=p",
            &[],
            r#"{".value":1,".priority":5}"#,
        );
        for (target, body) in [
            (
                "/ints.json?shallow=true",
                r#"{"2147483648":true,"a":true,"10":true,"B":true,"2":true,"-1":true,"01":true}"#,
            ),
            // A page sorts the keys as strings.
            (
                "/ints.json?shallow=true&limitToFirst=3",
                r#"{"-1":true,"01":true,"10":true}"#,
            ),
            (
                "/ints.json?shallow=true&limitToFirst=6",
                r#"{"2147483648":true,"10":true,"B":true,"2":true,"-1":true,"01":true}"#,
            ),
            (
                "/k4.json?shallow=true",
                r#"{"01":true,"2":true,"10":true,"a":true}"#,
            ),
            (
                "/k4.json?shallow=true&limitToFirst=4",
                r#"{"01":true,"10":true,"2":true,"a":true}"#,
            ),
            (
                "/k4.json?shallow=true&startAfter=1",
                r#"{"10":true,"2":true,"a":true}"#,
            ),
            (
                "/q5.json?shallow=true",
                r#"{"e":true,"a":true,"b":true,"c":true,"d":true}"#,
            ),
            (
                "/q5.json?shallow=true&limitToFirst=2",
                r#"{"a":true,"b":true}"#,
            ),
            // The export format's priority mark is one of the entries.
            (
                "/sp.json?shallow=true&format=export",
                r#"{".priority":true,"a":true,"b":true}"#,
            ),
            (
                "/sp5.json?shallow=true&format=export",
                r#"{"e":true,".priority":true,"a":true,"b":true,"c":true,"d":true}"#,
            ),
            (
                "/sp5.json?shallow=true&format=export&limitToFirst=2",
                r#"{".priority":true,"a":true}"#,
            ),
            (
                "/sp5.json?shallow=true&format=export&limitToFirst=4",
                r#"{".priority":true,"a":true,"b":true,"c":true}"#,
            ),
            (
                "/sp5.json?shallow=true&format=export&limitToFirst=5",
                r#"{".priority":true,"a":true,"b":true,"c":true,"d":true}"#,
            ),
            (
                "/sp5.json?shallow=true&limitToFirst=5",
                r#"{"e":true,"a":true,"b":true,"c":true,"d":true}"#,
            ),
            ("/sp5/a.json?shallow=true&format=export", "1"),
            ("/pl.json?shallow=true&format=export", "1"),
            ("/pl.json?shallow=true&format=export&limitToFirst=1", "1"),
        ] {
            assert_eq!(
                get(&mut db, &format!("{target}&ns=p")),
                (200, body.to_owned()),
                "strict={strict} {target}"
            );
        }
    }
}

// ---------------------------------------------------------------------------------------
// ETags (production r1/r2 etag-get, etag-inm-match, etag-inm-put; jar == production)

const ETAG_X1: &str = "LkoDN24bwRWG2p4jGZoe8M/Acf8=";

#[test]
fn a_put_with_if_none_match_answers_its_etag() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/s/etag.json?ns=p", &[], r#"{"x":1}"#);
        let tag = send(
            &mut db,
            "GET",
            "/s/etag.json?ns=p",
            &[("x-firebase-etag", "true")],
            "",
        );
        assert_eq!(header(&tag, "ETag"), Some(ETAG_X1));
        let put = send(
            &mut db,
            "PUT",
            "/s/etag2.json?ns=p",
            &[("if-none-match", ETAG_X1)],
            r#"{"x":1}"#,
        );
        assert_eq!(put.status, 200);
        assert_eq!(
            recorded(&put),
            with(
                json_headers(),
                &[("etag", ETAG_X1), ("access-control-expose-headers", "ETag")]
            )
        );
        assert_eq!(String::from_utf8(put.body).unwrap(), r#"{"x":1}"#);
        // Neighbours from the jar.
        let pretty = send(
            &mut db,
            "PUT",
            "/s/e3.json?ns=p&print=pretty",
            &[("if-none-match", "\"q\"")],
            r#"{"x":1}"#,
        );
        assert_eq!(
            (pretty.status, header(&pretty, "ETag")),
            (200, Some(ETAG_X1))
        );
        assert_eq!(
            String::from_utf8(pretty.body).unwrap(),
            "{\n  \"x\" : 1\n}\n"
        );
        let null = send(
            &mut db,
            "PUT",
            "/s/e7.json?ns=p",
            &[("if-none-match", "\"q\"")],
            "null",
        );
        assert_eq!(
            (null.status, header(&null, "ETag")),
            (200, Some("null_etag"))
        );
        let callback = send(
            &mut db,
            "PUT",
            "/s/e4.json?ns=p&callback=cb",
            &[("if-none-match", "\"q\"")],
            r#"{"x":1}"#,
        );
        assert_eq!(
            (callback.status, header(&callback, "ETag")),
            (200, Some(ETAG_X1))
        );
        // Silent: answered 204 with the ETag.
        let silent = send(
            &mut db,
            "PUT",
            "/s/e5.json?ns=p&print=silent",
            &[("if-none-match", "\"q\"")],
            r#"{"x":1}"#,
        );
        assert_eq!(silent.status, 204);
        assert_eq!(header(&silent, "ETag"), Some(ETAG_X1));
        assert!(silent.body.is_empty());
        // A matching tag: 412 with the current value and no ETag, silent or not.
        for query in ["", "&print=silent"] {
            let failed = send(
                &mut db,
                "PUT",
                &format!("/s/etag.json?ns=p{query}"),
                &[("if-none-match", ETAG_X1)],
                r#"{"x":2}"#,
            );
            assert_eq!(failed.status, 412, "{query}");
            assert_eq!(header(&failed, "ETag"), None);
            assert_eq!(String::from_utf8(failed.body).unwrap(), r#"{"x":1}"#);
        }
        // if-match keeps its own answers: no ETag on success, refused when silent.
        let matched = send(
            &mut db,
            "PUT",
            "/s/etag.json?ns=p",
            &[("if-match", ETAG_X1)],
            r#"{"x":1}"#,
        );
        assert_eq!((matched.status, header(&matched, "ETag")), (200, None));
        let silent_match = send(
            &mut db,
            "PUT",
            "/s/etag.json?ns=p&print=silent",
            &[("if-match", ETAG_X1)],
            r#"{"x":1}"#,
        );
        assert_eq!(silent_match.status, 400);
        let silent_delete = send(
            &mut db,
            "DELETE",
            "/s/etag.json?ns=p&print=silent",
            &[("if-match", ETAG_X1)],
            "",
        );
        assert_eq!(silent_delete.status, 400);
        // A plain PUT has none, and the other methods refuse if-none-match.
        let plain = send(&mut db, "PUT", "/s/e6.json?ns=p", &[], r#"{"x":1}"#);
        assert_eq!(header(&plain, "ETag"), None);
        for method in ["POST", "PATCH", "DELETE"] {
            let refused = send(
                &mut db,
                method,
                "/s/e6.json?ns=p",
                &[("if-none-match", "\"q\"")],
                r#"{"x":1}"#,
            );
            assert_eq!(refused.status, 400, "{method}");
        }
        // A read with a query or shallow and a condition is still refused.
        for query in ["print=silent", "shallow=true", "orderBy=%22%24key%22"] {
            let refused = send(
                &mut db,
                "GET",
                &format!("/s/etag.json?ns=p&{query}"),
                &[("if-none-match", "\"q\"")],
                "",
            );
            assert_eq!(refused.status, 400, "{query}");
        }
    }
}

#[test]
fn a_not_modified_answer_follows_the_output_options() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/s/etag.json?ns=p", &[], r#"{"x":1}"#);
        for (query, content_type, disposition) in [
            ("", "application/json; charset=utf-8", None),
            ("&print=pretty", "application/json; charset=utf-8", None),
            ("&format=export", "application/json; charset=utf-8", None),
            ("&timeout=5", "application/json; charset=utf-8", None),
            (
                "&callback=cb",
                "application/javascript; charset=utf-8",
                None,
            ),
            (
                "&download=f",
                "application/octet-stream; charset=utf-8",
                Some("attachment; filename=\"f\""),
            ),
        ] {
            let response = send(
                &mut db,
                "GET",
                &format!("/s/etag.json?ns=p{query}"),
                &[("if-none-match", ETAG_X1)],
                "",
            );
            assert_eq!(response.status, 304, "{query}");
            assert_eq!(
                header(&response, "Content-Type"),
                Some(content_type),
                "{query}"
            );
            assert_eq!(
                header(&response, "Content-Disposition"),
                disposition,
                "{query}"
            );
            assert_eq!(header(&response, "Cache-Control"), Some("no-cache"));
            assert_eq!(header(&response, "Access-Control-Allow-Origin"), Some("*"));
            assert_eq!(header(&response, "Content-Length"), Some("0"));
            assert_eq!(header(&response, "ETag"), None);
            assert_eq!(header(&response, "X-Content-Type-Options"), None);
            assert!(response.body.is_empty());
        }
        let missing = send(
            &mut db,
            "GET",
            "/s/none.json?ns=p",
            &[("if-none-match", "null_etag")],
            "",
        );
        assert_eq!(missing.status, 304);
    }
}

// ---------------------------------------------------------------------------------------
// The PATCH echo (production r1/r2 emptied-patch; jar == production)

#[test]
fn the_patch_echo_keeps_the_request_order_at_every_level() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(
            &mut db,
            "PUT",
            "/s/emptied.json?ns=p",
            &[],
            r#"{"b":{"c":1}}"#,
        );
        let response = send(
            &mut db,
            "PATCH",
            "/s/emptied.json?ns=p",
            &[],
            r#"{"b/c":null,"b/.priority":1}"#,
        );
        assert_eq!(response.status, 200);
        assert_eq!(recorded(&response), json_headers());
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            r#"{"b":{"c":null,".priority":1}}"#
        );
        send(&mut db, "PUT", "/s/pe11.json?ns=p", &[], r#"{"b":{"c":1}}"#);
        send(&mut db, "PUT", "/s/pe10.json?ns=p", &[], r#"{"b":{"c":1}}"#);
        for (target, body, answer) in [
            ("/s/pe11.json?print=pretty", r#"{"b/c":null,"b/.priority":1}"#, "{\n  \"b\" : {\n    \"c\" : null,\n    \".priority\" : 1\n  }\n}\n"),
            ("/s/pe10.json?", r#"{"b/.priority":1,"b/c":2}"#, r#"{"b":{".priority":1,"c":2}}"#),
            ("/s/o1.json?", r#"{"z":1,"a":2,"m/x":3}"#, r#"{"z":1,"a":2,"m":{"x":3}}"#),
            ("/s/o2.json?", r#"{"b/z":1,"b/a":2,"a":3}"#, r#"{"b":{"z":1,"a":2},"a":3}"#),
            ("/s/o5.json?", r#"{"x/y/z":1,"x/a":2,"x/y/b":3}"#, r#"{"x":{"y":{"z":1,"b":3},"a":2}}"#),
            // A value sent as an object keeps the stored order.
            ("/s/o7.json?", r#"{"b/c":{"q":1,"a":2},"b/a":1}"#, r#"{"b":{"c":{"a":2,"q":1},"a":1}}"#),
            ("/s/pe1.json?print=pretty", r#"{"z":1,"a":{"q":1,"b":2},"m/x":3}"#, "{\n  \"z\" : 1,\n  \"a\" : {\n    \"b\" : 2,\n    \"q\" : 1\n  },\n  \"m\" : {\n    \"x\" : 3\n  }\n}\n"),
            ("/s/pe2.json?callback=cb", r#"{"z":1,"a":2,"m/x":3}"#, r#"/**/ cb({"z":1,"a":2,"m":{"x":3}});"#),
            // Five or more entries: a Scala hash map, at each level.
            ("/s/pe3.json?", r#"{"e":1,"d":2,"c":3,"b":4,"a":5}"#, r#"{"e":1,"a":5,"b":4,"c":3,"d":2}"#),
            ("/s/pe4.json?", r#"{"b/e":1,"b/d":2,"b/c":3,"b/b":4,"b/a":5}"#, r#"{"b":{"e":1,"a":5,"b":4,"c":3,"d":2}}"#),
            ("/s/pe5.json?", r#"{"x/e":1,"y":2,"x/c":3,"z":4,"x/a":5}"#, r#"{"y":2,"x":{"c":3,"e":1,"a":5},"z":4}"#),
            ("/s/pe6.json?", r#"{"b/c":1,"a":2,"b/d":3}"#, r#"{"b":{"c":1,"d":3},"a":2}"#),
            ("/s/pe7.json?format=export", r#"{"z":1,"a":2}"#, r#"{"z":1,"a":2}"#),
            ("/s/pe9.json?download=x", r#"{"z":1,"a":2}"#, r#"{"z":1,"a":2}"#),
            ("/s/pe12.json?", r#"{"a/b/c":1,"a/a":2,"a/b/a":3,"0":4}"#, r#"{"a":{"b":{"c":1,"a":3},"a":2},"0":4}"#),
            ("/s/pe13.json?", r#"{"10":1,"2":2,"a":3}"#, r#"{"10":1,"2":2,"a":3}"#),
        ] {
            let response = send(&mut db, "PATCH", &format!("{target}&ns=p"), &[], body);
            assert_eq!(
                (response.status, String::from_utf8(response.body).unwrap()),
                (200, answer.to_owned()),
                "strict={strict} {target} {body}"
            );
        }
        let silent = send(
            &mut db,
            "PATCH",
            "/s/pe14.json?ns=p&print=silent",
            &[],
            r#"{"z":1}"#,
        );
        assert_eq!((silent.status, silent.body.len()), (204, 0));
    }
}

// ---------------------------------------------------------------------------------------
// A malformed percent escape (production r1/r2 malformed-zz: production != jar)

const PRODUCTION_BAD_REQUEST: &str = "{\n    \"error\" : \"Bad request.\"\n}\n";

#[test]
fn a_malformed_escape_in_the_path_answers_each_profiles_shape() {
    assert_eq!(PRODUCTION_BAD_REQUEST.len(), 33);
    for strict in PROFILES {
        let mut db = db(strict);
        for (method, target) in [
            ("GET", "/s/bad%zz.json?ns=p"),
            ("PUT", "/s/bad%zz.json?ns=p"),
            ("GET", "/s/bad%.json?ns=p"),
            ("GET", "/s/bad%a.json?ns=p"),
            ("DELETE", "/x%zz?ns=p"),
        ] {
            let response = send(&mut db, method, target, &[], "1");
            assert_eq!(response.status, 400, "{target}");
            let text = String::from_utf8(response.body.clone()).unwrap();
            if strict {
                assert_eq!(
                    recorded(&response),
                    vec![(
                        "content-type".to_owned(),
                        "application/octet-stream".to_owned()
                    )],
                    "{target}"
                );
                assert_eq!(text, PRODUCTION_BAD_REQUEST);
            } else {
                assert_eq!(
                    recorded(&response),
                    vec![
                        ("access-control-allow-origin".to_owned(), "*".to_owned()),
                        (
                            "content-type".to_owned(),
                            "application/json; charset=utf-8".to_owned()
                        ),
                    ],
                    "{target}"
                );
                assert_eq!(text, error("Bad Request"));
            }
        }
        // In the query only: the official emulator's answer in both profiles (production
        // was not recorded there).
        for target in ["/ok.json?ns=p&x=%zz", "/ok.json?ns=p%zz"] {
            let response = send(&mut db, "GET", target, &[], "");
            assert_eq!(response.status, 400);
            assert_eq!(
                recorded(&response),
                vec![
                    ("access-control-allow-origin".to_owned(), "*".to_owned()),
                    (
                        "content-type".to_owned(),
                        "application/json; charset=utf-8".to_owned()
                    ),
                ]
            );
            assert_eq!(
                String::from_utf8(response.body).unwrap(),
                error("Bad Request")
            );
        }
        // Well-formed escapes are untouched.
        assert_eq!(
            send(&mut db, "PUT", "/s/ok%41.json?ns=p", &[], "1").status,
            200
        );
        assert_eq!(get(&mut db, "/s/okA.json?ns=p"), (200, "1".to_owned()));
    }
}

// ---------------------------------------------------------------------------------------
// Over a socket: the lengths the HTTP layer writes.

async fn start(strict: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let database = Arc::new(Mutex::new(Database::new(options(strict), 3)));
    let config = ServerConfig {
        clock: Arc::new(|| 1_000),
        ..ServerConfig::default()
    };
    tokio::spawn(serve(listener, database, config));
    address
}

async fn exchange(address: &str, method: &str, target: &str, headers: &str, body: &str) -> String {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let request = format!(
        "{method} {target} HTTP/1.1\r\nHost: {address}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).await.unwrap();
    response
}

fn head_lines(response: &str) -> Vec<String> {
    let head = response.split("\r\n\r\n").next().unwrap();
    let mut lines: Vec<String> = head
        .lines()
        .skip(1)
        .map(str::to_ascii_lowercase)
        .filter(|line| !line.starts_with("date:") && !line.starts_with("connection:"))
        .collect();
    lines.sort();
    lines
}

#[tokio::test]
async fn over_http_a_not_modified_answer_has_a_zero_content_length() {
    for strict in PROFILES {
        let address = start(strict).await;
        exchange(&address, "PUT", "/s/etag.json?ns=p", "", r#"{"x":1}"#).await;
        let response = exchange(
            &address,
            "GET",
            "/s/etag.json?ns=p",
            &format!("if-none-match: {ETAG_X1}\r\n"),
            "",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 304"), "{response}");
        assert_eq!(
            head_lines(&response),
            vec![
                "access-control-allow-origin: *",
                "cache-control: no-cache",
                "content-length: 0",
                "content-type: application/json; charset=utf-8",
            ],
            "strict={strict}"
        );
        assert!(response.ends_with("\r\n\r\n"));
        // The recorded silent DELETE keeps no length (production r1/r2 print-silent-delete).
        let silent = exchange(&address, "DELETE", "/s/etag.json?ns=p&print=silent", "", "").await;
        assert!(silent.starts_with("HTTP/1.1 204"), "{silent}");
        assert!(
            !head_lines(&silent)
                .iter()
                .any(|l| l.starts_with("content-length")),
            "{silent}"
        );
    }
}

#[tokio::test]
async fn over_http_a_malformed_escape_answers_the_recorded_bytes() {
    for strict in PROFILES {
        let address = start(strict).await;
        let response = exchange(&address, "GET", "/s/bad%zz.json?ns=p", "", "").await;
        assert!(response.starts_with("HTTP/1.1 400"), "{response}");
        let body = response.split("\r\n\r\n").nth(1).unwrap();
        if strict {
            assert_eq!(
                head_lines(&response),
                vec![
                    "content-length: 33",
                    "content-type: application/octet-stream"
                ]
            );
            assert_eq!(body, PRODUCTION_BAD_REQUEST);
        } else {
            assert_eq!(
                head_lines(&response),
                vec![
                    "access-control-allow-origin: *",
                    "content-length: 30",
                    "content-type: application/json; charset=utf-8",
                ]
            );
            assert_eq!(body, error("Bad Request"));
        }
    }
}

// ---------------------------------------------------------------------------------------
// Review round 2 (2026-11-04): neighbours probed against the jar, no production recording.

/// The jar decodes `+` in the `timeout` value as a space, which `Duration` then drops; `%2B`
/// stays a plus.
#[test]
fn timeout_reads_a_plus_as_a_space() {
    let format = error(TIMEOUT_FORMAT);
    for strict in PROFILES {
        let mut db = seeded(strict);
        for value in ["5s+", "1+min", "5+s", "+5s", "+1+min+", "%2B5s"] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                (200, MIX_PLAIN.to_owned()),
                "strict={strict} timeout={value}"
            );
        }
        for value in ["+", "5%2Bs", "-%2B5s", "%2B-5s", "1%2Bmin"] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                (400, format.clone()),
                "strict={strict} timeout={value}"
            );
        }
    }
}

/// Lengths at the rounding edge (Java's `Math.round`, half up, no `+0.5` error) and
/// hexadecimal lengths whose mantissa or exponent would overflow a double on the way.
#[test]
fn timeout_rounds_and_scales_like_java() {
    let positive = error("timeout must be positive");
    let format = error(TIMEOUT_FORMAT);
    let long_one_second = format!("0x1{}p-1024s", "0".repeat(256));
    let long_one_second_more = format!("0x1{}p-1200s", "0".repeat(300));
    let long_tiny = format!("0x1{}p-1201s", "0".repeat(300));
    for strict in PROFILES {
        let mut db = seeded(strict);
        for (value, expected) in [
            ("0.49999999999999994ns", (400, positive.clone())),
            ("0.5ns", (200, MIX_PLAIN.to_owned())),
            ("0.50000000000000006ns", (200, MIX_PLAIN.to_owned())),
            ("1.4999999999999998ns", (200, MIX_PLAIN.to_owned())),
            ("0x0p1024s", (400, positive.clone())),
            ("0x0p1100s", (400, positive.clone())),
            ("0x0p3000s", (400, positive.clone())),
            ("-0x0p3000s", (400, positive.clone())),
            ("0x0p99999999999999999999s", (400, positive.clone())),
            ("0x1p-99999999999999999999s", (400, positive.clone())),
            ("0x1p99999999999999999999s", (400, format.clone())),
            ("0x1p1023s", (400, format.clone())),
            ("0x1p1024s", (400, format.clone())),
            ("0x1p-1074s", (400, positive.clone())),
            ("0x.8p-1ns", (400, positive.clone())),
            ("0x.7ffffffffffffcp-1ns", (400, positive.clone())),
            (
                "0x0.0000000000000000000001p88s",
                (200, MIX_PLAIN.to_owned()),
            ),
            (
                "0x00000000000000000000000000000001p0s",
                (200, MIX_PLAIN.to_owned()),
            ),
            // 2^53 + 1 ns is a tie at double precision: alone it rounds to even (2^53, a
            // double length, too long); a non-zero digit far behind it rounds it up past
            // 2^53, where Scala reads the text as a long and fails.
            (
                "0x20000000000001p0ns",
                (400, error("timeout must not be longer than 15 minutes")),
            ),
            ("0x20000000000001.0000001p0ns", (400, format.clone())),
            ("0x20000000000001.0111111p0ns", (400, format.clone())),
            (
                "0x20000000000001.0000000p0ns",
                (400, error("timeout must not be longer than 15 minutes")),
            ),
            ("0x20000000000003p0ns", (400, format.clone())),
            (long_one_second.as_str(), (200, MIX_PLAIN.to_owned())),
            (long_one_second_more.as_str(), (200, MIX_PLAIN.to_owned())),
            (long_tiny.as_str(), (200, MIX_PLAIN.to_owned())),
        ] {
            assert_eq!(
                get(&mut db, &format!("/s/mix.json?ns=p&timeout={value}")),
                expected,
                "strict={strict} timeout={value}"
            );
        }
    }
}

/// The rounding itself, on the nanoseconds read: the double just below 1.5 ns rounds down and
/// 1.5 ns up, half up as Java's `Math.round` (the HTTP answers above only say loaded or not).
#[test]
fn timeout_nanoseconds_round_half_up() {
    use fireemu_adapter_database::request::duration_nanos;
    for (value, nanos) in [
        ("0.49999999999999994ns", 0),
        ("0.5ns", 1),
        ("1.4999999999999998ns", 1),
        ("1.5ns", 2),
        ("2.5ns", 3),
        ("2.4999999999999996ns", 2),
    ] {
        assert_eq!(duration_nanos(value), Ok(nanos), "{value}");
    }
}

/// A `+` in a query value other than `timeout` stays a plus in both profiles, so
/// `equalTo="a+b"` finds the key `a+b`. The jar (probed 2026-11-04) decodes it as a space and
/// answers `{"a b":1}`; production recorded neither, so fireemu keeps its answer (the open
/// issue on the jar probe's REST leftovers, item 1).
#[test]
fn a_plus_in_equal_to_stays_a_plus() {
    for strict in PROFILES {
        let mut db = db(strict);
        assert_eq!(
            send(&mut db, "PUT", "/pl.json?ns=p", &[], r#"{"a b":1,"a+b":2}"#).status,
            200
        );
        for (query, body) in [
            ("equalTo=%22a+b%22", r#"{"a+b":2}"#),
            ("equalTo=%22a%2Bb%22", r#"{"a+b":2}"#),
            ("equalTo=%22a%20b%22", r#"{"a b":1}"#),
        ] {
            assert_eq!(
                get(
                    &mut db,
                    &format!("/pl.json?ns=p&orderBy=%22%24key%22&{query}")
                ),
                (200, body.to_owned()),
                "strict={strict} {query}"
            );
        }
    }
}

/// Java's `Math.round` for a positive length: half up, decided on the exact fraction.
fn java_round(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Nanosecond lengths next to a half: only the exact fraction decides.
    #[test]
    fn nanosecond_halves_round_half_up(whole in 0u32..4, step in -3i32..=3) {
        let mut value = f64::from(whole) + 0.5;
        for _ in 0..step.unsigned_abs() {
            value = if step > 0 { value.next_up() } else { value.next_down() };
        }
        let expected = if java_round(value) <= 0.0 {
            (400, error("timeout must be positive"))
        } else {
            (200, "1".to_owned())
        };
        for strict in PROFILES {
            let mut db = db(strict);
            send(&mut db, "PUT", "/t.json?ns=p", &[], "1");
            prop_assert_eq!(get(&mut db, &format!("/t.json?ns=p&timeout={value:?}ns")), expected.clone(), "{:?}", value);
        }
    }

    /// A hexadecimal length is exact whatever its spelling: `1` followed by `zeros` hex
    /// zeros and the exponent that brings it back to 2^`power` seconds, or a zero mantissa.
    #[test]
    fn hexadecimal_lengths_scale_exactly(zeros in 0usize..300, power in -40i32..=40, zero in any::<bool>()) {
        let digit = if zero { "0" } else { "1" };
        let exponent = i64::from(power) - 4 * i64::try_from(zeros).unwrap();
        let text = format!("0x{digit}{}p{exponent}s", "0".repeat(zeros));
        let nanos = if zero { 0.0 } else { java_round(1e9 * 2f64.powi(power)) };
        // Beyond 2^63 ns a Scala duration does not hold it: the jar's 500 (0x1p34s, probed).
        #[allow(clippy::cast_precision_loss)]
        let expected = if nanos > i64::MAX as f64 {
            (500, error("Unexpected server error"))
        } else if nanos <= 0.0 {
            (400, error("timeout must be positive"))
        } else if nanos > 900e9 {
            (400, error("timeout must not be longer than 15 minutes"))
        } else {
            (200, "1".to_owned())
        };
        for strict in PROFILES {
            let mut db = db(strict);
            send(&mut db, "PUT", "/t.json?ns=p", &[], "1");
            prop_assert_eq!(get(&mut db, &format!("/t.json?ns=p&timeout={text}")), expected.clone(), "{}", text);
        }
    }
}

/// `X-Firebase-ETag: true` adds the `ETag` to the answers of conditional requests, as the jar
/// does; a write's answer carries the `ETag` of what was written (POST: the new child).
#[test]
fn conditional_answers_carry_the_etag_when_asked() {
    let both = [("etag", ETAG_X1), ("access-control-expose-headers", "ETag")];
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/s/etag.json?ns=p", &[], r#"{"x":1}"#);
        for asked in ["true", "TRUE"] {
            let not_modified = send(
                &mut db,
                "GET",
                "/s/etag.json?ns=p",
                &[("if-none-match", ETAG_X1), ("x-firebase-etag", asked)],
                "",
            );
            assert_eq!(not_modified.status, 304);
            assert_eq!(
                recorded(&not_modified),
                with(json_headers(), &both),
                "strict={strict} {asked}"
            );
            assert_eq!(header(&not_modified, "Content-Length"), Some("0"));
        }
        let callback = send(
            &mut db,
            "GET",
            "/s/etag.json?ns=p&callback=cb",
            &[("if-none-match", ETAG_X1), ("x-firebase-etag", "true")],
            "",
        );
        assert_eq!(
            (callback.status, header(&callback, "ETag")),
            (304, Some(ETAG_X1))
        );
        let not_asked = send(
            &mut db,
            "GET",
            "/s/etag.json?ns=p",
            &[("if-none-match", ETAG_X1), ("x-firebase-etag", "false")],
            "",
        );
        assert_eq!((not_asked.status, header(&not_asked, "ETag")), (304, None));
        for query in ["", "&print=silent"] {
            let failed = send(
                &mut db,
                "PUT",
                &format!("/s/etag.json?ns=p{query}"),
                &[("if-none-match", ETAG_X1), ("x-firebase-etag", "true")],
                r#"{"x":2}"#,
            );
            assert_eq!(failed.status, 412, "{query}");
            assert_eq!(
                recorded(&failed),
                with(json_headers(), &both),
                "strict={strict} {query}"
            );
            assert_eq!(String::from_utf8(failed.body).unwrap(), r#"{"x":1}"#);
        }
        // The neighbours that already carried it.
        let read = send(
            &mut db,
            "GET",
            "/s/etag.json?ns=p",
            &[("if-none-match", "\"q\""), ("x-firebase-etag", "true")],
            "",
        );
        assert_eq!((read.status, header(&read, "ETag")), (200, Some(ETAG_X1)));
        let mismatch = send(
            &mut db,
            "PUT",
            "/s/etag.json?ns=p",
            &[("if-match", "\"q\""), ("x-firebase-etag", "true")],
            r#"{"x":3}"#,
        );
        assert_eq!(
            (mismatch.status, header(&mismatch, "ETag")),
            (412, Some(ETAG_X1))
        );
        let matched = send(
            &mut db,
            "PUT",
            "/s/etag.json?ns=p",
            &[("if-match", ETAG_X1), ("x-firebase-etag", "true")],
            r#"{"x":1}"#,
        );
        assert_eq!(
            (matched.status, header(&matched, "ETag")),
            (200, Some(ETAG_X1))
        );
        let deleted = send(
            &mut db,
            "DELETE",
            "/s/etag.json?ns=p",
            &[("if-match", ETAG_X1), ("x-firebase-etag", "true")],
            "",
        );
        assert_eq!(
            (deleted.status, header(&deleted, "ETag")),
            (200, Some("null_etag"))
        );
        // POST: the ETag of the new child's value.
        let posted = send(
            &mut db,
            "POST",
            "/s/p.json?ns=p",
            &[("x-firebase-etag", "true")],
            "1",
        );
        assert_eq!(posted.status, 200);
        assert_eq!(
            header(&posted, "ETag"),
            Some("YPVfR2bXt/lcDjiQZ8pOkAd3qkQ=")
        );
        assert_eq!(
            header(&posted, "Access-Control-Expose-Headers"),
            Some("ETag")
        );
        let plain_post = send(&mut db, "POST", "/s/p.json?ns=p", &[], "1");
        assert_eq!(header(&plain_post, "ETag"), None);
    }
}

#[tokio::test]
async fn over_http_a_not_modified_answer_with_its_etag() {
    for strict in PROFILES {
        let address = start(strict).await;
        exchange(&address, "PUT", "/s/etag.json?ns=p", "", r#"{"x":1}"#).await;
        let response = exchange(
            &address,
            "GET",
            "/s/etag.json?ns=p",
            &format!("if-none-match: {ETAG_X1}\r\nx-firebase-etag: true\r\n"),
            "",
        )
        .await;
        assert!(response.starts_with("HTTP/1.1 304"), "{response}");
        assert_eq!(
            head_lines(&response),
            vec![
                "access-control-allow-origin: *".to_owned(),
                "access-control-expose-headers: etag".to_owned(),
                "cache-control: no-cache".to_owned(),
                "content-length: 0".to_owned(),
                "content-type: application/json; charset=utf-8".to_owned(),
                format!("etag: {}", ETAG_X1.to_ascii_lowercase()),
            ],
            "strict={strict}"
        );
    }
}

/// A ranged query over array-like children answers an object; a limit or a query that only
/// orders keeps the array (jar).
#[test]
fn ranged_queries_over_an_array_answer_an_object() {
    for strict in PROFILES {
        let mut db = db(strict);
        send(&mut db, "PUT", "/arr.json?ns=p", &[], "[10,20,30,40]");
        send(&mut db, "PUT", "/arr6.json?ns=p", &[], "[1,2,3,4,5,6]");
        for (target, body) in [
            (
                "/arr.json?orderBy=%22%24key%22&startAt=%220%22",
                r#"{"0":10,"1":20,"2":30,"3":40}"#,
            ),
            (
                "/arr.json?orderBy=%22%24key%22&limitToFirst=4",
                "[10,20,30,40]",
            ),
            ("/arr.json?orderBy=%22%24key%22", "[10,20,30,40]"),
            (
                "/arr6.json?orderBy=%22%24key%22&startAt=%220%22",
                r#"{"4":5,"5":6,"1":2,"0":1,"2":3,"3":4}"#,
            ),
            (
                "/arr.json?shallow=true",
                r#"{"0":true,"1":true,"2":true,"3":true}"#,
            ),
        ] {
            assert_eq!(
                get(&mut db, &format!("{target}&ns=p")),
                (200, body.to_owned()),
                "strict={strict} {target}"
            );
        }
    }
}
