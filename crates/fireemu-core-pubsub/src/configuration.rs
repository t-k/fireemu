//! Shared configuration values and duration diagnostics; no clocks or network operations.
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
        if key.chars().count() > 63
            || !key
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
        for key in ["a.b".to_owned(), "aB".to_owned(), "a".repeat(64)] {
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
