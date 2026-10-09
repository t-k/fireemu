//! Resource-local unconditional Pub/Sub policies used by dead-letter forwarding.

use crate::{PubSubError, Result};

/// One unconditional resource-local role binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyBinding {
    /// Predefined or unrelated role retained by policy read-modify-write.
    pub role: String,
    /// Exact member identifiers; forwarding never impersonates the local caller.
    pub members: Vec<String>,
}

/// The supported policy response subset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePolicy {
    /// Baseline policies omit version; unconditional writes normalize to version one.
    pub version: Option<u32>,
    /// Unconditional bindings in caller order.
    pub bindings: Vec<PolicyBinding>,
    /// Opaque compare-and-swap token bound to this resource incarnation and revision.
    pub etag: String,
}

#[derive(Debug)]
pub(crate) struct PolicyState {
    incarnation: u32,
    revision: u64,
    policy: ResourcePolicy,
}

impl PolicyState {
    pub(crate) fn new(incarnation: u32) -> Self {
        Self {
            incarnation,
            revision: 0,
            policy: ResourcePolicy {
                version: None,
                bindings: Vec::new(),
                etag: etag(&incarnation.to_be_bytes()[1..]),
            },
        }
    }

    pub(crate) fn get(&self) -> ResourcePolicy {
        self.policy.clone()
    }

    pub(crate) fn set(
        &mut self,
        expected: &str,
        version: Option<u32>,
        bindings: Vec<PolicyBinding>,
    ) -> Result<ResourcePolicy> {
        if expected != self.policy.etag {
            return Err(PubSubError::failed_precondition(
                "resource policy etag does not match",
            ));
        }
        if !matches!(version, None | Some(0 | 1 | 3)) {
            return Err(PubSubError::invalid_argument(
                "unsupported resource policy version",
            ));
        }
        let revision = self
            .revision
            .checked_add(1)
            .filter(|n| *n < (1_u64 << 48))
            .ok_or_else(|| {
                PubSubError::resource_exhausted("resource policy revision space exhausted")
            })?;
        let mut bytes = Vec::with_capacity(9);
        bytes.extend_from_slice(&self.incarnation.to_be_bytes()[1..]);
        bytes.extend_from_slice(&revision.to_be_bytes()[2..]);
        self.revision = revision;
        self.policy = ResourcePolicy {
            version: Some(1),
            bindings,
            etag: etag(&bytes),
        };
        Ok(self.get())
    }

    pub(crate) fn grants(&self, role: &str, member: &str) -> bool {
        self.policy
            .bindings
            .iter()
            .any(|binding| binding.role == role && binding.members.iter().any(|m| m == member))
    }
}

fn etag(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for triple in bytes.chunks_exact(3) {
        let n = (u32::from(triple[0]) << 16) | (u32::from(triple[1]) << 8) | u32::from(triple[2]);
        for shift in [18, 12, 6, 0] {
            result.push(char::from(ALPHABET[((n >> shift) & 63) as usize]));
        }
    }
    result
}
