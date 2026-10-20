//! Realtime Database Security Rules from `firebase.json`, as firebase-tools 15.28.2 loads
//! them: each file into its instance at startup, where a file that does not load stops the
//! start, and again whenever the file changes, where a file that does not load keeps the
//! rules in force and says why. Also the credentials the database reads: the profile's
//! administrators and the ID tokens fireemu's Auth accepts (coordinator ruling Q-R6).

use std::sync::{Arc, Mutex, PoisonError};

use fireemu_adapter_database::rest::{Credentials, Database};
use fireemu_core_auth::jwt::{
    decode_token, verify_rules_token_for_project, RulesTokenPolicy, TokenAcceptance,
};
use fireemu_core_auth::store::AuthRegistry;
use fireemu_core_types::time::LogicalInstant;

use crate::config::RuntimeConfig;

/// The project a database instance belongs to: `<project>-default-rtdb` is its project's
/// default instance, and any other instance (a named one from `firebase.json`, or one a
/// client names) belongs to the daemon's project, as the configuration assumes.
pub(crate) fn project_of_instance<'a>(instance: &'a str, daemon_project: &'a str) -> &'a str {
    instance
        .strip_suffix("-default-rtdb")
        .filter(|project| !project.is_empty())
        .unwrap_or(daemon_project)
}

/// The credentials of the profile: under `strict` only `owner` is an administrator. An
/// `auth=` ID token is a user when fireemu's Auth verifies it as a token of the instance's
/// project, against that project's store (its tenant's, for a tenant token), with
/// `auth.allowUnsignedIdTokens` deciding unsigned tokens, as Firestore verifies them (review M5).
pub(crate) fn credentials(cfg: &RuntimeConfig, registry: &Arc<AuthRegistry>) -> Credentials {
    let policy = RulesTokenPolicy::new(cfg.token_acceptance, cfg.auth_allow_unsigned_id_tokens);
    let registry = Arc::clone(registry);
    let daemon_project = cfg.auth_project.clone();
    Credentials {
        strict: cfg.token_acceptance == TokenAcceptance::Verified,
        id_tokens: Some(Arc::new(move |token: &str, instance: &str, now: i64| {
            let project = project_of_instance(instance, &daemon_project);
            let default = registry.default_store();
            let tenant = {
                let store = default.lock().ok()?;
                decode_token(token, store.signer())
                    .ok()
                    .and_then(|decoded| {
                        let tenant = decoded.payload.get("firebase")?.get("tenant")?;
                        tenant.as_str().map(str::to_owned)
                    })
            };
            let store = match tenant {
                Some(tenant) => registry.tenant_store(project, &tenant)?,
                None => registry.store_for(project).unwrap_or(default),
            };
            let store = store.lock().ok()?;
            let decoded = verify_rules_token_for_project(
                token,
                &store,
                LogicalInstant::from_nanos(i128::from(now) * 1_000_000),
                policy,
                project,
            )
            .ok()?;
            // A token of another project is never a user here, whichever store verified it.
            let audience = decoded.payload.get("aud")?.as_str()?;
            (audience == project).then_some(decoded.payload_json)
        })),
    }
}

/// How often a rules file is looked at for a change.
const SCAN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(750);

/// A path as firebase-tools shows it: relative to the working directory when it is below it.
fn shown(path: &str) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| {
            std::path::Path::new(path)
                .strip_prefix(cwd)
                .ok()
                .map(|relative| relative.to_string_lossy().into_owned())
        })
        .unwrap_or_else(|| path.to_owned())
}

/// Loads every `(instance, file)` in order, and answers the text loaded from each. The error
/// is the one firebase-tools stops with.
pub(crate) fn load_initial(
    database: &Mutex<Database>,
    files: &[(String, String)],
    now_millis: i64,
) -> Result<Vec<String>, String> {
    let mut database = database.lock().unwrap_or_else(PoisonError::into_inner);
    let mut texts = Vec::with_capacity(files.len());
    for (instance, path) in files {
        let loaded = std::fs::read_to_string(path)
            .map_err(|error| error.to_string())
            .and_then(|text| {
                database.load_rules(instance, &text, now_millis)?;
                Ok(text)
            });
        if let Err(error) = &loaded {
            return Err(format!(
                "Failed to load initial Realtime Database rules:\n{}:{}",
                shown(path),
                error.trim()
            ));
        }
        texts.extend(loaded);
    }
    Ok(texts)
}

/// Watches every file and loads it again into its instance when it changes; `loaded` is the
/// text each was loaded from. The watchers end with the database.
pub(crate) fn start_reload_supervisors(
    database: &Arc<Mutex<Database>>,
    files: &[(String, String)],
    loaded: &[String],
    clock: &Arc<dyn Fn() -> i64 + Send + Sync>,
) {
    for ((instance, path), loaded) in files.iter().zip(loaded) {
        let weak = Arc::downgrade(database);
        let clock = Arc::clone(clock);
        let instance = instance.clone();
        let path = path.clone();
        // The file as first observed counts as loaded only when it holds the text that was
        // loaded; a change between the load and this look is loaded at the first scan
        // (review S4).
        let mut observed = crate::watched_file(&path)
            .ok()
            .filter(|(_, _, bytes)| bytes.as_slice() == loaded.as_bytes())
            .map(|(stamp, signature, _)| (stamp, signature));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SCAN_INTERVAL).await;
                if weak.strong_count() == 0 {
                    return;
                }
                let Ok((stamp, signature, bytes)) = crate::watched_file_off_thread(&path).await
                else {
                    continue;
                };
                if !crate::watched_file_changed(
                    observed.map(|(stamp, _)| stamp),
                    observed.map(|(_, signature)| signature),
                    stamp,
                    signature,
                ) {
                    continue;
                }
                let unchanged = observed.is_some_and(|(_, seen)| seen == signature);
                observed = Some((stamp, signature));
                if unchanged {
                    continue;
                }
                let Some(database) = weak.upgrade() else {
                    return;
                };
                eprintln!("note: database: change detected, updating rules for {instance}");
                let loaded = String::from_utf8(bytes)
                    .map_err(|error| error.to_string())
                    .and_then(|text| {
                        database
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .load_rules(&instance, &text, clock())
                    });
                match loaded {
                    Ok(()) => eprintln!("note: database: rules updated for {instance}"),
                    Err(error) => eprintln!(
                        "warning: database: {}:{}\nwarning: database: failed to update rules for {instance}; the previous rules stay in force",
                        shown(&path),
                        error.trim()
                    ),
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fireemu_adapter_database::rest::{Handled, HttpRequest, RestOptions};

    fn read(database: &Mutex<Database>, ns: &str) -> u16 {
        let request = HttpRequest {
            method: "GET".to_owned(),
            target: format!("/.json?ns={ns}"),
            headers: Vec::new(),
            body: Vec::new(),
        };
        match database.lock().unwrap().handle(&request, 0) {
            Handled::Response { response, .. } => response.status,
            Handled::Stream { .. } => panic!("stream"),
        }
    }

    fn temp(name: &str, text: &str) -> (tempdir::Dir, String) {
        let dir = tempdir::Dir::new(name);
        let path = dir.path().join("database.rules.json");
        std::fs::write(&path, text).unwrap();
        let path = path.to_string_lossy().into_owned();
        (dir, path)
    }

    mod tempdir {
        /// A directory removed when dropped.
        pub struct Dir(std::path::PathBuf);

        impl Dir {
            pub fn new(name: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "fireemu-database-rules-{name}-{}",
                    std::process::id()
                ));
                let _ = std::fs::remove_dir_all(&path);
                std::fs::create_dir_all(&path).unwrap();
                Self(path)
            }

            pub fn path(&self) -> &std::path::Path {
                &self.0
            }
        }

        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[test]
    fn files_load_into_their_instances_in_order_and_a_bad_one_stops_the_start() {
        let (_closed_dir, closed) = temp("closed", r#"{"rules":{".read":false}}"#);
        let (_open_dir, open) = temp("open", r#"{"rules":{".read":true}}"#);
        let database = Mutex::new(Database::new(RestOptions::default(), 1));
        load_initial(
            &database,
            &[
                ("a".to_owned(), closed.clone()),
                ("b".to_owned(), closed.clone()),
                ("b".to_owned(), open.clone()),
            ],
            0,
        )
        .unwrap();
        assert_eq!(read(&database, "a"), 401);
        // A later file for the same instance replaces the earlier one.
        assert_eq!(read(&database, "b"), 200);
        // Other instances have no rules.
        assert_eq!(read(&database, "c"), 200);

        let (_bad_dir, bad) = temp("bad", r#"{"rules":{".read":"auth.foo()"}}"#);
        let error = load_initial(&database, &[("a".to_owned(), bad.clone())], 0).unwrap_err();
        assert!(
            error.starts_with("Failed to load initial Realtime Database rules:\n"),
            "{error}"
        );
        assert!(
            error.ends_with(":1:20: Type error: Function call on target that is not a function."),
            "{error}"
        );
        let missing = format!("{bad}.missing");
        let error = load_initial(&database, &[("a".to_owned(), missing.clone())], 0).unwrap_err();
        assert!(error.contains(&missing), "{error}");
        let error = load_initial(&database, &[("bad.name".to_owned(), open)], 0).unwrap_err();
        assert!(
            error.ends_with(":Invalid Firebase database name"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_change_between_the_load_and_the_watch_is_loaded() {
        let (_dir, path) = temp("between", r#"{"rules":{".read":true}}"#);
        let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 1)));
        let files = [("b".to_owned(), path.clone())];
        let texts = load_initial(&database, &files, 0).unwrap();
        std::fs::write(&path, r#"{"rules":{".read":false}}"#).unwrap();
        start_reload_supervisors(
            &database,
            &files,
            &texts,
            &(Arc::new(|| 0_i64) as Arc<dyn Fn() -> i64 + Send + Sync>),
        );
        for _ in 0..100 {
            if read(&database, "b") == 401 {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("the change made before the watch was not loaded");
    }

    #[tokio::test]
    async fn a_changed_file_is_loaded_again_and_a_bad_change_keeps_the_rules() {
        let (_dir, path) = temp("reload", r#"{"rules":{".read":true}}"#);
        let database = Arc::new(Mutex::new(Database::new(RestOptions::default(), 1)));
        let files = [("r".to_owned(), path.clone())];
        let texts = load_initial(&database, &files, 0).unwrap();
        start_reload_supervisors(
            &database,
            &files,
            &texts,
            &(Arc::new(|| 0_i64) as Arc<dyn Fn() -> i64 + Send + Sync>),
        );
        let wait_for = |status: u16| {
            let database = Arc::clone(&database);
            async move {
                for _ in 0..100 {
                    if read(&database, "r") == status {
                        return true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                false
            }
        };
        std::fs::write(&path, r#"{"rules":{".read":false}}"#).unwrap();
        assert!(wait_for(401).await, "the change was not loaded");
        std::fs::write(&path, r#"{"rules":{".read":"auth.foo()"}}"#).unwrap();
        tokio::time::sleep(SCAN_INTERVAL * 3).await;
        assert_eq!(read(&database, "r"), 401, "a bad change replaced the rules");
        assert_eq!(
            database.lock().unwrap().rules_text("r"),
            r#"{"rules":{".read":false}}"#
        );
        std::fs::write(&path, r#"{"rules":{".read":true}}"#).unwrap();
        assert!(
            wait_for(200).await,
            "a good change after a bad one was not loaded"
        );
    }
}
