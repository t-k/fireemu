//! HTTP shell (`AUTH-CORE-1`, `AUTH-MFA-TOTP-1`): the Identity Toolkit REST subset used by the
//! Firebase client and Admin SDKs, served over hyper. Handlers are pure functions over JSON so
//! that every flow is testable without a socket; [`server`] is the thin network glue.

pub mod control;
pub mod identity_toolkit;
pub mod server;
pub mod storage;
pub mod storage_server;
