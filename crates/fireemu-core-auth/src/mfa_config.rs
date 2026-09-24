//! The project's multi-factor configuration (Identity Toolkit Admin v2 `Config.mfa`).
//!
//! A project starts with MFA disabled, as production does (sandbox read 2026-09-23). The Admin
//! config API replaces the whole value; which values production accepts is decided by the
//! adapter from the AUTH-MFA recordings, this module only holds a validated value and answers
//! what it enables.

/// `mfa.state` and a provider config's `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MfaConfigState {
    /// `DISABLED` (and the state a new project reads back).
    #[default]
    Disabled,
    /// `ENABLED`.
    Enabled,
    /// `MANDATORY`.
    Mandatory,
}

impl MfaConfigState {
    /// Whether the state lets a factor be used.
    #[must_use]
    pub const fn is_on(self) -> bool {
        matches!(self, Self::Enabled | Self::Mandatory)
    }
}

/// `mfa.providerConfigs[].totpProviderConfig` with its entry's `state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TotpProviderConfig {
    /// The entry's `state`.
    pub state: MfaConfigState,
    /// `adjacentIntervals`: accepted steps on either side of the current one. `None` when the
    /// entry has no `totpProviderConfig` member.
    pub adjacent_intervals: Option<u8>,
}

/// `Config.mfa`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MfaProjectConfig {
    /// `mfa.state`.
    pub state: MfaConfigState,
    /// `mfa.enabledProviders` contains `PHONE_SMS`.
    pub phone_sms: bool,
    /// The TOTP entry of `mfa.providerConfigs`, if any.
    pub totp: Option<TotpProviderConfig>,
}

impl MfaProjectConfig {
    /// Whether SMS second factors are enabled.
    #[must_use]
    pub const fn sms_enabled(&self) -> bool {
        self.state.is_on() && self.phone_sms
    }

    /// Whether TOTP second factors are enabled.
    #[must_use]
    pub fn totp_enabled(&self) -> bool {
        self.state.is_on() && self.totp.is_some_and(|totp| totp.state.is_on())
    }

    /// The configured TOTP window, when TOTP is enabled with one.
    #[must_use]
    pub fn totp_window(&self) -> Option<u8> {
        self.totp
            .filter(|_| self.totp_enabled())
            .and_then(|totp| totp.adjacent_intervals)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const fn totp(state: MfaConfigState, adjacent_intervals: Option<u8>) -> TotpProviderConfig {
        TotpProviderConfig {
            state,
            adjacent_intervals,
        }
    }

    #[test]
    fn a_new_project_enables_no_second_factor() {
        let config = MfaProjectConfig::default();
        assert_eq!(config.state, MfaConfigState::Disabled);
        assert!(!config.sms_enabled());
        assert!(!config.totp_enabled());
        assert_eq!(config.totp_window(), None);
    }

    #[test]
    fn a_provider_counts_only_while_the_project_state_is_on() {
        for (state, on) in [
            (MfaConfigState::Disabled, false),
            (MfaConfigState::Enabled, true),
            (MfaConfigState::Mandatory, true),
        ] {
            let config = MfaProjectConfig {
                state,
                phone_sms: true,
                totp: Some(totp(MfaConfigState::Enabled, Some(5))),
            };
            assert_eq!(config.sms_enabled(), on, "{state:?}");
            assert_eq!(config.totp_enabled(), on, "{state:?}");
            assert_eq!(config.totp_window(), on.then_some(5), "{state:?}");
        }
    }

    #[test]
    fn totp_needs_its_own_entry_to_be_on() {
        let base = MfaProjectConfig {
            state: MfaConfigState::Enabled,
            phone_sms: true,
            totp: None,
        };
        assert!(base.sms_enabled());
        assert!(!base.totp_enabled());
        let disabled = MfaProjectConfig {
            totp: Some(totp(MfaConfigState::Disabled, Some(5))),
            ..base.clone()
        };
        assert!(!disabled.totp_enabled());
        assert_eq!(disabled.totp_window(), None);
        let without_window = MfaProjectConfig {
            totp: Some(totp(MfaConfigState::Enabled, None)),
            ..base
        };
        assert!(without_window.totp_enabled());
        assert_eq!(without_window.totp_window(), None);
    }
}
