//! The region of a phone number, for the project's SMS region policy (`smsRegionConfig`).
//!
//! Production refuses a code for a number of a region its policy does not allow (sandbox
//! recording 2026-09-25, AUTH-CONFIG-SDK `other-fields`). fireemu names the region of the
//! North American Numbering Plan by area code and of other numbers by calling code; a calling
//! code shared by several regions, or one missing from the table, has no region, and the
//! policy then refuses nothing.

use serde_json::Value;

/// Canadian area codes of the North American Numbering Plan.
const CANADA: &[&str] = &[
    "204", "226", "236", "249", "250", "257", "263", "289", "306", "343", "354", "365", "367",
    "368", "382", "387", "403", "416", "418", "428", "431", "437", "438", "450", "460", "468",
    "474", "506", "514", "519", "548", "579", "581", "584", "587", "600", "604", "613", "622",
    "639", "647", "672", "683", "705", "709", "742", "753", "778", "780", "782", "807", "819",
    "825", "867", "873", "879", "902", "905", "942",
];

/// The other regions of the North American Numbering Plan by area code.
const NANP_REGIONS: &[(&str, &str)] = &[
    ("242", "BS"),
    ("246", "BB"),
    ("264", "AI"),
    ("268", "AG"),
    ("284", "VG"),
    ("340", "VI"),
    ("345", "KY"),
    ("441", "BM"),
    ("473", "GD"),
    ("649", "TC"),
    ("658", "JM"),
    ("664", "MS"),
    ("670", "MP"),
    ("671", "GU"),
    ("684", "AS"),
    ("721", "SX"),
    ("758", "LC"),
    ("767", "DM"),
    ("784", "VC"),
    ("787", "PR"),
    ("809", "DO"),
    ("829", "DO"),
    ("849", "DO"),
    ("868", "TT"),
    ("869", "KN"),
    ("876", "JM"),
    ("939", "PR"),
];

/// Calling codes that belong to one region.
const CALLING_CODES: &[(&str, &str)] = &[
    ("20", "EG"),
    ("27", "ZA"),
    ("30", "GR"),
    ("31", "NL"),
    ("32", "BE"),
    ("33", "FR"),
    ("34", "ES"),
    ("36", "HU"),
    ("40", "RO"),
    ("41", "CH"),
    ("43", "AT"),
    ("45", "DK"),
    ("46", "SE"),
    ("48", "PL"),
    ("49", "DE"),
    ("51", "PE"),
    ("52", "MX"),
    ("53", "CU"),
    ("54", "AR"),
    ("55", "BR"),
    ("56", "CL"),
    ("57", "CO"),
    ("58", "VE"),
    ("60", "MY"),
    ("62", "ID"),
    ("63", "PH"),
    ("64", "NZ"),
    ("65", "SG"),
    ("66", "TH"),
    ("81", "JP"),
    ("82", "KR"),
    ("84", "VN"),
    ("86", "CN"),
    ("90", "TR"),
    ("91", "IN"),
    ("92", "PK"),
    ("93", "AF"),
    ("94", "LK"),
    ("95", "MM"),
    ("98", "IR"),
    ("234", "NG"),
    ("254", "KE"),
    ("351", "PT"),
    ("352", "LU"),
    ("353", "IE"),
    ("354", "IS"),
    ("380", "UA"),
    ("420", "CZ"),
    ("421", "SK"),
    ("852", "HK"),
    ("853", "MO"),
    ("855", "KH"),
    ("880", "BD"),
    ("886", "TW"),
    ("966", "SA"),
    ("971", "AE"),
    ("972", "IL"),
    ("974", "QA"),
];

/// The region of an E.164 number, or `None` when fireemu cannot name it.
pub(super) fn region_of(number: &str) -> Option<&'static str> {
    let digits = number.strip_prefix('+')?;
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if let Some(national) = digits.strip_prefix('1') {
        if national.len() != 10 {
            return None;
        }
        let area = national.get(..3)?;
        if CANADA.contains(&area) {
            return Some("CA");
        }
        return Some(
            NANP_REGIONS
                .iter()
                .find(|(code, _)| *code == area)
                .map_or("US", |(_, region)| region),
        );
    }
    CALLING_CODES
        .iter()
        .find(|(code, _)| digits.starts_with(code))
        .map(|(_, region)| *region)
}

/// Whether a written SMS region policy refuses a code for `number`. A new project's
/// `allowlistOnly: {}` refuses nothing, as production sends codes under it; an allowlist
/// refuses a region it does not name, a default allowance the regions it disallows.
pub(super) fn policy_refuses(policy: &Value, number: &str) -> bool {
    let Some(region) = region_of(number) else {
        return false;
    };
    let names = |list: Option<&Value>| {
        list.and_then(Value::as_array)
            .is_some_and(|regions| regions.iter().any(|r| r.as_str() == Some(region)))
    };
    if let Some(allowlist) = policy.get("allowlistOnly") {
        let allowed = allowlist.get("allowedRegions");
        return allowed
            .and_then(Value::as_array)
            .is_some_and(|regions| !regions.is_empty())
            && !names(allowed);
    }
    policy
        .get("allowByDefault")
        .is_some_and(|default| names(default.get("disallowedRegions")))
}

#[cfg(test)]
mod tests {
    use super::{policy_refuses, region_of};
    use serde_json::json;

    #[test]
    fn regions_are_named_by_area_and_calling_code() {
        assert_eq!(region_of("+16505550101"), Some("US"));
        assert_eq!(region_of("+14165550100"), Some("CA"));
        assert_eq!(region_of("+17875550100"), Some("PR"));
        assert_eq!(region_of("+819012345678"), Some("JP"));
        assert_eq!(region_of("+447700900000"), None);
        assert_eq!(region_of("16505550101"), None);
        assert_eq!(region_of("+1650"), None);
    }

    #[test]
    fn policies_refuse_only_the_regions_they_exclude() {
        let us = "+16505550101";
        assert!(!policy_refuses(&json!({"allowlistOnly": {}}), us));
        assert!(policy_refuses(
            &json!({"allowlistOnly": {"allowedRegions": ["JP"]}}),
            us
        ));
        assert!(!policy_refuses(
            &json!({"allowlistOnly": {"allowedRegions": ["US"]}}),
            us
        ));
        assert!(policy_refuses(
            &json!({"allowByDefault": {"disallowedRegions": ["US"]}}),
            us
        ));
        assert!(!policy_refuses(&json!({"allowByDefault": {}}), us));
        assert!(!policy_refuses(
            &json!({"allowlistOnly": {"allowedRegions": ["JP"]}}),
            "+447700900000"
        ));
    }
}
