//! Shared configuration values and duration diagnostics; no clocks or network operations.
use crate::label_value::is_label_value_char;
use crate::{PubSubError, Result};
use fireemu_core_types::time::LogicalDuration;
use std::fmt::Write as _;

/// Formats service diagnostics in hours, minutes and seconds, preserving subsecond precision.
#[must_use]
pub fn human_duration(duration: LogicalDuration) -> String {
    let nanos = duration.as_nanos();
    let sign = if nanos < 0 { "-" } else { "" };
    let nanos = nanos.abs();
    let seconds = nanos / 1_000_000_000;
    let fraction = nanos % 1_000_000_000;
    let hours = seconds / 3600;
    let minutes = seconds % 3600 / 60;
    let seconds = seconds % 60;
    let mut value = sign.to_owned();
    if hours > 0 {
        write!(value, "{hours}h").expect("writing to String cannot fail");
    }
    if minutes > 0 {
        write!(value, "{minutes}m").expect("writing to String cannot fail");
    }
    if fraction > 0 {
        let fraction = format!("{fraction:09}").trim_end_matches('0').to_owned();
        write!(value, "{seconds}.{fraction}s").expect("writing to String cannot fail");
    } else if seconds > 0 || value == sign {
        write!(value, "{seconds}s").expect("writing to String cannot fail");
    }
    value
}

/// Validates a requested topic or subscription retention duration against the service bounds.
pub fn validate_retention(duration: LogicalDuration) -> Result<()> {
    if duration < LogicalDuration::from_seconds(600)
        || duration > LogicalDuration::from_seconds(2_678_400)
    {
        return Err(PubSubError::invalid_argument(format!("The value for message retention duration is out of bounds. You passed {} in the request, but the value must be between 10m and 744h.", human_duration(duration))));
    }
    Ok(())
}

/// Validates resource labels before strict-profile mutations. Emulator admission remains permissive.
pub fn validate_labels(labels: &std::collections::BTreeMap<String, String>) -> Result<()> {
    for (key, value) in labels {
        let first = key.chars().next();
        let letter = |ch: char| ch.is_alphabetic() && !ch.is_uppercase();
        if first.is_none_or(|ch| !letter(ch)) {
            let first = first.map_or_else(String::new, |ch| ch.to_string());
            return Err(PubSubError::invalid_argument(format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels"; key "{key}" does not conform to regular expression "[\p{{Ll}}\p{{Lo}}][\p{{Ll}}\p{{Lo}}\p{{N}}_-]{{0,62}}"; first character "{first}" is not a non-uppercased letter (Unicode character class Ll or Lo))."#
            )));
        }
        let key_length = key.chars().count();
        if key_length > 63 {
            return Err(PubSubError::invalid_argument(format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels"; key "{key}" exceeds maximum character length 63 with a length of {key_length})."#
            )));
        }
        if !key
            .chars()
            .all(|ch| letter(ch) || ch.is_numeric() || matches!(ch, '_' | '-'))
        {
            return Err(PubSubError::invalid_argument(format!(
                "Invalid label key: {key}."
            )));
        }
        if value.chars().count() > 63 {
            return Err(PubSubError::invalid_argument(format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels.{key}"; value "{value}" exceeds maximum value length 63 with a length of {})."#,
                value.chars().count()
            )));
        }
        if let Some((position, character)) = value
            .chars()
            .enumerate()
            .find(|&(_, ch)| !is_label_value_char(ch))
        {
            return Err(PubSubError::invalid_argument(format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels.{key}"; value "{value}" does not conform to regular expression "[\p{{Ll}}\p{{Lo}}\p{{N}}_-]{{0,63}}"; character "{character}" at position {position} is not a non-uppercased letter (Unicode character class Ll or Lo), digit, hyphen, or underscore)."#
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn unobserved_unicode_label_classes_retain_the_local_approximation(suffix in "[a-z0-9_-]{0,12}") {
            // These representatives are local debt, not observed production admission.
            for (class, first) in [("Ll", '\u{00e9}'), ("Lo", '\u{4e2d}'), ("Lt", '\u{01c5}'), ("Lm", '\u{02b0}'), ("Nl", '\u{2160}'), ("Mn", '\u{0345}')] {
                let key = format!("{first}{suffix}");
                let expected = first.is_alphabetic() && !first.is_uppercase();
                prop_assert_eq!(validate_labels(&[(key, String::new())].into()).is_ok(), expected, "Unicode class {}", class);
            }
        }
    }

    proptest! {
        #[test]
        fn invalid_value_character_and_position_match_the_regex_reference(value in "\\PC{0,63}") {
            let reference = regex::Regex::new(r"[^\p{Ll}\p{Lo}\p{N}_-]").expect("the pattern is valid");
            let result = validate_labels(&[("env".to_owned(), value.clone())].into());
            match reference.find(&value) {
                None => prop_assert!(result.is_ok()),
                Some(found) => {
                    let position = value[..found.start()].chars().count();
                    let message = result.unwrap_err().message().to_owned();
                    let expected = format!(
                        r#"character "{}" at position {position} is not"#,
                        found.as_str()
                    );
                    prop_assert!(message.contains(&expected), "{message}");
                }
            }
        }
    }

    #[test]
    fn recorded_decomposed_label_value_reports_the_invalid_scalar() {
        let error =
            validate_labels(&[("env".to_owned(), "e\u{0301}".to_owned())].into()).unwrap_err();
        assert_eq!(
            error.message(),
            concat!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels.env"; value ""#,
                "e\u{0301}",
                r#"" does not conform to regular expression "[\p{Ll}\p{Lo}\p{N}_-]{0,63}"; character "́" at position 1 is not a non-uppercased letter (Unicode character class Ll or Lo), digit, hyphen, or underscore)."#
            )
        );
    }

    #[test]
    fn recorded_overlong_label_key_reports_its_scalar_length() {
        let key = "k".repeat(64);
        let error = validate_labels(&[(key.clone(), String::new())].into()).unwrap_err();
        assert_eq!(
            error.message(),
            format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels"; key "{key}" exceeds maximum character length 63 with a length of 64)."#
            )
        );
    }

    #[test]
    fn label_values_follow_exact_unicode_categories_without_normalization() {
        for (value, accepted) in [
            ("", true),
            ("é", true),
            ("中", true),
            ("١", true),
            ("Ⅰ", true),
            ("²", true),
            ("_-", true),
            ("A", false),
            ("ǅ", false),
            ("ʰ", false),
            ("\u{0345}", false),
            ("e\u{0301}", false),
        ] {
            assert_eq!(
                validate_labels(&[("env".to_owned(), value.to_owned())].into()).is_ok(),
                accepted,
                "value {value:?}"
            );
        }
        let value = "é".repeat(64);
        let error = validate_labels(&[("env".to_owned(), value.clone())].into()).unwrap_err();
        assert_eq!(
            error.message(),
            format!(
                r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels.env"; value "{value}" exceeds maximum value length 63 with a length of 64)."#
            )
        );
        assert!(validate_labels(&[("env".to_owned(), "é".repeat(63))].into()).is_ok());
    }

    proptest! {
        #![proptest_config(proptest::test_runner::Config::with_cases(64))]
        #[test]
        fn unicode_label_value_reports_first_invalid_scalar_position(
            prefix in proptest::collection::vec(prop::sample::select(vec!['é', '中', '١', 'Ⅰ', '²', 'a', '_', '-']), 0..12),
            invalid in prop::sample::select(vec!['\u{0301}', 'A', 'ǅ', 'ʰ', '\u{0345}']),
            suffix in "[a-z0-9_-]{0,12}",
        ) {
            let position = prefix.len();
            let prefix: String = prefix.into_iter().collect();
            let accepted_value = format!("{prefix}{suffix}");
            prop_assert!(validate_labels(&[("env".to_owned(), accepted_value)].into()).is_ok());
            let value = format!("{prefix}{invalid}{suffix}A");
            let error = validate_labels(&[("env".to_owned(), value.clone())].into()).unwrap_err();
            let expected = format!(r#"You have passed an invalid argument to the service (argument=Invalid labels: Invalid field "labels.env"; value "{value}" does not conform to regular expression "[\p{{Ll}}\p{{Lo}}\p{{N}}_-]{{0,63}}"; character "{invalid}" at position {position} is not a non-uppercased letter (Unicode character class Ll or Lo), digit, hyphen, or underscore)."#);
            prop_assert_eq!(error.message(), expected);
        }
    }

    #[test]
    fn label_key_and_value_bounds_are_exact() {
        for (key_length, value_length, accepted) in [(63, 63, true), (64, 0, false), (1, 64, false)]
        {
            assert_eq!(
                validate_labels(&[("a".repeat(key_length), "b".repeat(value_length))].into())
                    .is_ok(),
                accepted
            );
        }
    }

    #[test]
    fn unobserved_later_invalid_label_keys_keep_the_local_diagnostic() {
        for key in ["a.b".to_owned(), "aB".to_owned()] {
            let error = validate_labels(&[(key.clone(), String::new())].into()).unwrap_err();
            assert_eq!(error.message(), format!("Invalid label key: {key}."));
        }
    }
    proptest! {
        #[test]
        fn retention_admission_matches_reference_interval(nanos in -1_i128..=2_678_401_000_000_000_i128) {
            prop_assert_eq!(validate_retention(LogicalDuration::from_nanos(nanos)).is_ok(),(600_000_000_000..=2_678_400_000_000_000).contains(&nanos));
        }
        #[test]
        fn ascii_label_keys_follow_recorded_pattern(key in "[a-zA-Z0-9_-]{0,70}",value in "[a-z]{0,70}") {
            let expected=!key.is_empty() && key.len()<=63 && key.as_bytes()[0].is_ascii_lowercase() && key.bytes().all(|ch| ch.is_ascii_lowercase()||ch.is_ascii_digit()||ch==b'_'||ch==b'-') && value.len()<=63;
            prop_assert_eq!(validate_labels(&[(key,value)].into()).is_ok(),expected);
        }
        #[test]
        fn human_duration_has_lossless_component_codec(nanos in -3_000_000_000_000_000_i128..=3_000_000_000_000_000_i128) {
            let formatted=human_duration(LogicalDuration::from_nanos(nanos));
            let negative=formatted.starts_with('-');
            let mut remaining=formatted.trim_start_matches('-');
            let mut decoded=0_i128;
            for (suffix,multiplier) in [('h',3_600_000_000_000_i128),('m',60_000_000_000)] {
                if let Some((component,rest))=remaining.split_once(suffix) { decoded+=component.parse::<i128>().unwrap()*multiplier;remaining=rest; }
            }
            if !remaining.is_empty() {
                let seconds=remaining.strip_suffix('s').unwrap();
                let (seconds,fraction)=seconds.split_once('.').unwrap_or((seconds,""));
                decoded+=seconds.parse::<i128>().unwrap()*1_000_000_000;
                if !fraction.is_empty() {decoded+=format!("{fraction:0<9}").parse::<i128>().unwrap();}
            }
            prop_assert_eq!(if negative {-decoded} else {decoded},nanos);
        }
    }
}
