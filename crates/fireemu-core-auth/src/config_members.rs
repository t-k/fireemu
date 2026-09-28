//! Project configuration members fireemu keeps so that they read back as written, without
//! interpreting all of them itself: `notification`, `mobileLinksConfig`, `smsRegionConfig`,
//! `recaptchaConfig`, `monitoring` and `autodeleteAnonymousUsers` (AUTH-CONFIG-SDK).
//!
//! Each member is held as the canonical JSON text of its value, so this crate needs no JSON
//! dependency; the Identity Toolkit adapter validates a value before storing it and reads the
//! members that change behaviour (reCAPTCHA, SMS regions) back from here. A member that was
//! never written is absent and reads as production's initial value.

use std::collections::BTreeMap;

/// Written project configuration members, by their Admin v2 member name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredConfigMembers {
    members: BTreeMap<String, String>,
}

impl StoredConfigMembers {
    /// The JSON text written for `member`, if any.
    #[must_use]
    pub fn get(&self, member: &str) -> Option<&str> {
        self.members.get(member).map(String::as_str)
    }

    /// Writes `member` (`Some` JSON text) or clears it back to its initial value (`None`).
    pub fn set(&mut self, member: &str, json: Option<String>) {
        match json {
            Some(json) => {
                self.members.insert(member.to_owned(), json);
            }
            None => {
                self.members.remove(member);
            }
        }
    }

    /// Every written member and its JSON text, in member-name order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.members.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::StoredConfigMembers;

    #[test]
    fn members_read_back_as_written_and_clear_to_absent() {
        let mut members = StoredConfigMembers::default();
        assert_eq!(members.get("mobileLinksConfig"), None);
        members.set(
            "mobileLinksConfig",
            Some(r#"{"domain":"HOSTING_DOMAIN"}"#.to_owned()),
        );
        members.set("autodeleteAnonymousUsers", Some("true".to_owned()));
        assert_eq!(
            members.get("mobileLinksConfig"),
            Some(r#"{"domain":"HOSTING_DOMAIN"}"#)
        );
        assert_eq!(
            members.iter().map(|(k, _)| k).collect::<Vec<_>>(),
            ["autodeleteAnonymousUsers", "mobileLinksConfig"]
        );
        members.set("mobileLinksConfig", None);
        assert_eq!(members.get("mobileLinksConfig"), None);
        assert_ne!(members, StoredConfigMembers::default());
    }
}
