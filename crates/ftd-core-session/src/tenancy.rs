//! Which session owns which project and bucket (spec 14: sessions are isolated by
//! project). A session other than the default one registers its project, optionally
//! extra bucket names and the API keys its client SDKs send; the default session owns
//! every project, bucket and key nobody registered.

use std::collections::{BTreeMap, BTreeSet};

/// The registered sessions' projects, buckets and API keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenancy {
    default_project: String,
    /// Registered project → its extra buckets.
    buckets: BTreeMap<String, BTreeSet<String>>,
    /// API key → registered project.
    api_keys: BTreeMap<String, String>,
}

/// What one session owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope {
    /// One registered project: its databases, buckets and users.
    Project(String),
    /// Everything except the registered projects (the default session).
    AllExcept(BTreeSet<String>),
}

impl Scope {
    /// Whether `project` belongs to this scope.
    #[must_use]
    pub fn owns_project(&self, project: &str) -> bool {
        match self {
            Self::Project(p) => p == project,
            Self::AllExcept(registered) => !registered.contains(project),
        }
    }

    /// Whether this is the default session's scope.
    #[must_use]
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::AllExcept(_))
    }

    /// The single project of a project scope.
    #[must_use]
    pub fn project(&self) -> Option<&str> {
        match self {
            Self::Project(p) => Some(p),
            Self::AllExcept(_) => None,
        }
    }
}

/// The conventional default buckets of a project.
#[must_use]
pub fn conventional_bucket_project(bucket: &str) -> Option<&str> {
    bucket
        .strip_suffix(".appspot.com")
        .or_else(|| bucket.strip_suffix(".firebasestorage.app"))
        .filter(|p| !p.is_empty())
}

impl Tenancy {
    /// A tenancy with only the default project.
    #[must_use]
    pub fn new(default_project: &str) -> Self {
        Self {
            default_project: default_project.to_owned(),
            buckets: BTreeMap::new(),
            api_keys: BTreeMap::new(),
        }
    }

    /// The default project.
    #[must_use]
    pub fn default_project(&self) -> &str {
        &self.default_project
    }

    /// Registers `project` with extra buckets and API keys; `Err` names the conflict (the
    /// default project, an already registered project, a bucket or key owned elsewhere).
    pub fn register(
        &mut self,
        project: &str,
        buckets: &[String],
        api_keys: &[String],
    ) -> Result<(), String> {
        if project == self.default_project {
            return Err("the default project cannot be registered".to_owned());
        }
        if self.buckets.contains_key(project) {
            return Err(format!("project {project:?} is already registered"));
        }
        for b in buckets {
            let owner = self.project_of_bucket(b);
            if owner != self.default_project && owner != project {
                return Err(format!("bucket {b:?} belongs to project {owner:?}"));
            }
            if conventional_bucket_project(b).is_some_and(|p| p != project) {
                return Err(format!("bucket {b:?} is another project's default bucket"));
            }
        }
        for k in api_keys {
            if let Some(owner) = self.api_keys.get(k) {
                return Err(format!("API key {k:?} belongs to project {owner:?}"));
            }
        }
        self.buckets
            .insert(project.to_owned(), buckets.iter().cloned().collect());
        for k in api_keys {
            self.api_keys.insert(k.clone(), project.to_owned());
        }
        Ok(())
    }

    /// Forgets a registered project; `false` when it was not registered.
    pub fn unregister(&mut self, project: &str) -> bool {
        self.api_keys.retain(|_, p| p != project);
        self.buckets.remove(project).is_some()
    }

    /// Whether `project` is a registered (non-default) session project.
    #[must_use]
    pub fn is_registered(&self, project: &str) -> bool {
        self.buckets.contains_key(project)
    }

    /// The registered projects.
    #[must_use]
    pub fn registered(&self) -> BTreeSet<String> {
        self.buckets.keys().cloned().collect()
    }

    /// The buckets a registered project declared (its conventional ones are implied).
    #[must_use]
    pub fn declared_buckets(&self, project: &str) -> Vec<String> {
        self.buckets
            .get(project)
            .map(|b| b.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// The project a bucket belongs to: a conventional name (`{p}.appspot.com`,
    /// `{p}.firebasestorage.app`) of the default or a registered project names that
    /// project; a bucket a session declared names its project; anything else is the
    /// default project's.
    #[must_use]
    pub fn project_of_bucket(&self, bucket: &str) -> &str {
        if let Some(p) = conventional_bucket_project(bucket) {
            if p == self.default_project {
                return &self.default_project;
            }
            if let Some((registered, _)) = self.buckets.get_key_value(p) {
                return registered;
            }
        }
        self.buckets
            .iter()
            .find(|(_, b)| b.contains(bucket))
            .map_or(&self.default_project, |(p, _)| p)
    }

    /// The registered project an API key was declared for.
    #[must_use]
    pub fn project_of_api_key(&self, key: &str) -> Option<&str> {
        self.api_keys.get(key).map(String::as_str)
    }

    /// The scope of the session owning `project`.
    #[must_use]
    pub fn scope_of(&self, project: &str) -> Scope {
        if self.is_registered(project) {
            Scope::Project(project.to_owned())
        } else {
            self.default_scope()
        }
    }

    /// The default session's scope.
    #[must_use]
    pub fn default_scope(&self) -> Scope {
        Scope::AllExcept(self.registered())
    }
}

/// The tenancy shared by every adapter.
pub type SharedTenancy = std::sync::Arc<std::sync::RwLock<Tenancy>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buckets_and_keys_resolve_to_their_session() {
        let mut t = Tenancy::new("demo-a");
        t.register("demo-b", &["shared-b".to_owned()], &["key-b".to_owned()])
            .unwrap();
        assert_eq!(t.project_of_bucket("demo-a.appspot.com"), "demo-a");
        assert_eq!(t.project_of_bucket("demo-b.firebasestorage.app"), "demo-b");
        assert_eq!(t.project_of_bucket("shared-b"), "demo-b");
        assert_eq!(t.project_of_bucket("anything-else"), "demo-a");
        // A conventional name of an unregistered project is the default session's.
        assert_eq!(t.project_of_bucket("demo-c.appspot.com"), "demo-a");
        assert_eq!(t.project_of_api_key("key-b"), Some("demo-b"));
        assert_eq!(t.project_of_api_key("key-a"), None);
        assert!(t.scope_of("demo-b").owns_project("demo-b"));
        assert!(!t.default_scope().owns_project("demo-b"));
        assert!(t.default_scope().owns_project("demo-c"));
        assert!(t.unregister("demo-b"));
        assert_eq!(t.project_of_bucket("shared-b"), "demo-a");
        assert_eq!(t.project_of_api_key("key-b"), None);
    }

    #[test]
    fn registration_conflicts_are_refused() {
        let mut t = Tenancy::new("demo-a");
        assert!(t.register("demo-a", &[], &[]).is_err());
        t.register("demo-b", &["b1".to_owned()], &["k".to_owned()])
            .unwrap();
        assert!(t.register("demo-b", &[], &[]).is_err());
        assert!(t.register("demo-c", &["b1".to_owned()], &[]).is_err());
        assert!(t.register("demo-c", &[], &["k".to_owned()]).is_err());
        assert!(t
            .register("demo-c", &["demo-b.appspot.com".to_owned()], &[])
            .is_err());
        assert!(t
            .register("demo-c", &["demo-c.appspot.com".to_owned()], &[])
            .is_ok());
    }
}
