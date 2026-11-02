//! PCT-1 for the `WebChannel` surface: `form_decode`, which decodes both the channel query
//! string (`serve.rs`) and the forward-channel form body, shares the escape definition of
//! `fireemu_core_types::codec`.
//!
//! The surface is lenient: a malformed escape stays literal rather than being refused, and
//! `+` is a space. Only what an escape is changes: two ASCII hexadecimal digits, so `%+f`
//! is no longer read as the byte 0x0F.

use fireemu_adapter_grpc::webchannel::{form_decode, parse_form};
use proptest::prelude::*;

/// The decoder this surface had before it moved to the shared codec, kept verbatim as the
/// oracle. It also reports whether it took a two-character group that is not two
/// hexadecimal digits as an escape, which `u8::from_str_radix` does for a leading `+`.
fn previous_form_decode(s: &str) -> (String, bool) {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut took_signed_escape = false;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Some(b) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
            {
                if !bytes[i + 1..i + 3].iter().all(u8::is_ascii_hexdigit) {
                    took_signed_escape = true;
                }
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    (
        String::from_utf8_lossy(&out).into_owned(),
        took_signed_escape,
    )
}

/// Characters that exercise every branch: escapes, signs, hex and non-hex digits, the
/// pair separators, and a multi-byte character so a group can straddle a char boundary.
fn interesting_char() -> impl Strategy<Value = char> {
    prop_oneof![
        3 => Just('%'),
        2 => Just('+'),
        1 => Just('-'),
        3 => prop::sample::select(vec!['0', '7', '9', 'a', 'f', 'A', 'F']),
        1 => prop::sample::select(vec!['g', 'z', 'G', ' ', '&', '=']),
        1 => prop::sample::select(vec!['é', '😀']),
        1 => any::<char>(),
    ]
}

fn interesting_input() -> impl Strategy<Value = String> {
    prop_oneof![
        3 => prop::collection::vec(interesting_char(), 0..16)
            .prop_map(|chars| chars.into_iter().collect()),
        1 => any::<String>(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// Every input the previous decoder read without a signed escape decodes to the same
    /// string, and every input where it did take one now decodes differently. Together:
    /// the outcome changes exactly for inputs holding `%+X` with `X` hexadecimal at a
    /// position the decoder reaches as an escape.
    #[test]
    fn form_decode_changes_only_signed_escapes(input in interesting_input()) {
        let (previous, took_signed_escape) = previous_form_decode(&input);
        let current = form_decode(&input);
        if took_signed_escape {
            prop_assert_ne!(current, previous);
        } else {
            prop_assert_eq!(current, previous);
        }
    }
}

#[test]
fn a_signed_escape_stays_literal_in_a_webchannel_form() {
    // `%+f` is not an escape: the percent sign stays, and the plus is a form space.
    assert_eq!(form_decode("%+f"), "% f");
    assert_eq!(form_decode("%+0A"), "% 0A");
    // `%zz`, a lone `%` and a truncated escape stay literal, as before.
    assert_eq!(form_decode("%zz"), "%zz");
    assert_eq!(form_decode("%"), "%");
    assert_eq!(form_decode("%4"), "%4");
    // A sequence that is not UTF-8 is replaced, not refused, as before.
    assert_eq!(form_decode("%FF"), "\u{FFFD}");
    // `%2B` is a plus and `+` is a space.
    assert_eq!(form_decode("a%2Bb+c"), "a+b c");
}

#[test]
fn a_channel_query_with_a_signed_escape_keeps_it_literal() {
    let params = parse_form("VER=8&database=projects%2Fdemo-app&token=ab%+fcd&k%+1=v");
    assert_eq!(params["VER"], "8");
    assert_eq!(params["database"], "projects/demo-app");
    assert_eq!(params["token"], "ab% fcd");
    assert_eq!(params["k% 1"], "v");
}
