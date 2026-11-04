//! Realtime Database Security Rules from `firebase.json`, as firebase-tools 15.28.2 loads
//! them: each file into its instance at startup, where a file that does not load stops the
//! start, and again whenever the file changes, where a file that does not load keeps the
//! rules in force and says why. Also the credentials the database reads: the profile's
//! administrators and the ID tokens fireemu's Auth accepts (coordinator ruling Q-R6).

use std::sync::{Arc, Mutex, PoisonError};

use fireemu_adapter_database::rest::{Credentials, Database};
use fireemu_core_auth::jwt::{
    base64url_decode, decode_token, is_unsigned_token, verify_rules_token_for_project, JwtError,
    RulesTokenPolicy, TokenAcceptance,
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
/// The official emulator admits an unsigned mock token whatever project it names, and so does
/// the emulator profile while unsigned tokens are admitted: such a token is checked against the
/// project it names (review S7). Signed tokens, and every token under strict, keep the binding.
pub(crate) fn credentials(cfg: &RuntimeConfig, registry: &Arc<AuthRegistry>) -> Credentials {
    let policy = RulesTokenPolicy::new(cfg.token_acceptance, cfg.auth_allow_unsigned_id_tokens);
    let registry = Arc::clone(registry);
    let daemon_project = cfg.auth_project.clone();
    let strict = cfg.token_acceptance == TokenAcceptance::Verified;
    let any_mock_audience = !strict && cfg.auth_allow_unsigned_id_tokens;
    Credentials {
        strict,
        id_tokens: Some(Arc::new(move |token: &str, instance: &str, now: i64| {
            let default = registry.default_store();
            let (tenant, audience) = {
                let store = default.lock().ok()?;
                let decoded = decode_token(token, store.signer()).ok();
                let claim = |path: &[&str]| {
                    let mut value = decoded.as_ref()?.payload.get(path[0])?;
                    for key in &path[1..] {
                        value = value.get(key)?;
                    }
                    value.as_str().map(str::to_owned)
                };
                (claim(&["firebase", "tenant"]), claim(&["aud"]))
            };
            let unsigned_mock = any_mock_audience && is_unsigned_token(token);
            if unsigned_mock && audience.is_none() {
                // The official emulator reads an unsigned token's claims unverified: one that
                // names a subject is that user even without `aud` (review r6 S16b). The emulator
                // profile does the same; a session signer refuses unsigned tokens altogether.
                let store = default.lock().ok()?;
                if store.signer().is_some() {
                    return None;
                }
                let decoded = decode_token(token, None).ok()?;
                decoded.sub()?;
                return Some(decoded.payload_json);
            }
            let project = match &audience {
                Some(audience) if unsigned_mock => audience,
                _ => project_of_instance(instance, &daemon_project),
            };
            let store = match tenant {
                Some(tenant) => registry.tenant_store(project, &tenant)?,
                None => registry.store_for(project).unwrap_or(default),
            };
            let store = store.lock().ok()?;
            let verified = verify_rules_token_for_project(
                token,
                &store,
                LogicalInstant::from_nanos(i128::from(now) * 1_000_000),
                policy,
                project,
            );
            let no_signer = store.signer().is_none();
            drop(store);
            let decoded = match verified {
                Ok(decoded) => decoded,
                // The official emulator reads the claims of a signed token it cannot verify
                // (G10 rows auth-rs256 and auth-hs256: jar 200). The emulator profile does the
                // same when it admits unsigned tokens and issues none of its own signatures;
                // see `unverified_signed_claims`.
                Err(JwtError::UnsupportedAlgorithm(alg)) if any_mock_audience && no_signer => {
                    let (claims, tenant) = unverified_signed_claims(token, &alg, project, now)?;
                    // The token is routed as an unsigned one is: a tenant it names must exist
                    // (a missing or deleted tenant leaves it nobody).
                    if let Some(tenant) = tenant {
                        registry.tenant_store(project, &tenant)?;
                    }
                    return Some(claims);
                }
                Err(_) => return None,
            };
            // A token of another project is never a user here, whichever store verified it.
            let audience = decoded.payload.get("aud")?.as_str()?;
            (audience == project).then_some(decoded.payload_json)
        })),
    }
}

/// The claims of an `RS256` or `HS256` token the emulator profile cannot verify, read as the
/// official emulator reads them (jar 4.11.2, G10 rows auth-rs256 and auth-hs256): unverified.
/// Kept to the recorded shape: a non-empty signature, a payload that is a JSON object, an `aud`
/// that names the instance's own project, and an `exp` still in the future. The answer is the
/// claims text with the tenant the token names, if any; the claims still have to name a subject
/// and an issue time to make a user, and the caller routes the tenant. Nothing else is admitted.
fn unverified_signed_claims(
    token: &str,
    alg: &str,
    project: &str,
    now: i64,
) -> Option<(String, Option<String>)> {
    if !matches!(alg, "RS256" | "HS256") {
        return None;
    }
    let mut parts = token.split('.');
    let (Some(_), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return None;
    };
    if signature.is_empty() {
        return None;
    }
    let text = String::from_utf8(base64url_decode(payload).ok()?).ok()?;
    let claims: serde_json::Value = serde_json::from_str(&text).ok()?;
    let claims = claims.as_object()?;
    let live = claims.get("exp")?.as_i64()?.checked_mul(1000)? > now;
    if !live || claims.get("aud")?.as_str()? != project {
        return None;
    }
    let tenant = claims
        .get("firebase")
        .and_then(|firebase| firebase.get("tenant"))
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    Some((text, tenant))
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

    /// The recorded shape of an unverifiable signed token (G10 rows auth-rs256, auth-hs256), and
    /// each edge of it: the claims are read only with a non-empty signature, an `exp` strictly
    /// after now, and an `aud` equal to the project.
    #[test]
    fn an_unverifiable_signed_token_is_read_only_in_the_recorded_shape() {
        use fireemu_core_auth::jwt::base64url_encode;
        let token = |alg: &str, claims: &str, signature: &str| {
            format!(
                "{}.{}.{signature}",
                base64url_encode(format!(r#"{{"alg":"{alg}"}}"#).as_bytes()),
                base64url_encode(claims.as_bytes())
            )
        };
        let own = r#"{"aud":"p","sub":"u","iat":1,"exp":100}"#;
        let now = 99_999;
        let read = |alg: &str, claims: &str, signature: &str, project: &str, now: i64| {
            unverified_signed_claims(&token(alg, claims, signature), alg, project, now)
        };
        for alg in ["RS256", "HS256"] {
            assert_eq!(
                read(alg, own, "c2ln", "p", now),
                Some((own.to_owned(), None)),
                "{alg}"
            );
            // exp is strictly in the future: now = exp * 1000 is expired.
            assert!(read(alg, own, "c2ln", "p", 100_000).is_none(), "{alg}");
            assert!(read(alg, own, "c2ln", "p", 100_001).is_none(), "{alg}");
            assert!(read(alg, own, "", "p", now).is_none(), "{alg}");
            assert!(read(alg, own, "c2ln", "q", now).is_none(), "{alg}");
        }
        assert!(read("ES256", own, "c2ln", "p", now).is_none());
        assert!(read("none", own, "c2ln", "p", now).is_none());
        // The tenant a token names is handed to the caller, which routes it.
        let tenanted = r#"{"aud":"p","sub":"u","iat":1,"exp":100,"firebase":{"tenant":"acme"}}"#;
        assert_eq!(
            read("HS256", tenanted, "c2ln", "p", now),
            Some((tenanted.to_owned(), Some("acme".to_owned())))
        );
        let untenanted = r#"{"aud":"p","exp":100,"firebase":{"tenant":7}}"#;
        assert_eq!(
            read("RS256", untenanted, "c2ln", "p", now).map(|c| c.1),
            Some(None)
        );
        assert!(read(
            "RS256",
            r#"{"aud":"p","sub":"u","iat":1}"#,
            "c2ln",
            "p",
            now
        )
        .is_none());
        assert!(read("RS256", r#"{"aud":7,"exp":100}"#, "c2ln", "p", now).is_none());
        assert!(read("RS256", "[1]", "c2ln", "p", now).is_none());
        assert!(unverified_signed_claims("a.b", "RS256", "p", now).is_none());
        assert!(unverified_signed_claims("a.b.c.d", "RS256", "p", now).is_none());
        // exp * 1000 must not overflow.
        assert!(read(
            "RS256",
            r#"{"aud":"p","exp":9223372036854775807}"#,
            "c2ln",
            "p",
            now
        )
        .is_none());
    }

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
