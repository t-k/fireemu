//! The project configuration's `blockingFunctions` as production answers it
//! (AUTH-TENANT-BLOCKING recording 2026-09-28, config#config-blocking): the strict profile names
//! every event with a function under its Cloud Functions URL and the time its trigger last
//! changed, and an update may write back what a read answered. The emulator profile keeps its
//! own form.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle_with, AuthBlockingHook, AuthQueryLimits, AuthState, BlockingAuthTrigger,
    BlockingFunctionFailure, ClientApiKeyPolicy, FakeCustomTokenExpiry, IdpContinuationPolicy,
    RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::AuthStore;
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const CONFIG: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config";
const UPDATED: i64 = 1_788_004_000;

/// Keeps the bridge-form settings it is given and lists a trigger for each event whose
/// setting names a function (`fireemu://functions/demo-app/{region}/{function}`).
struct ListingHook {
    settings: Arc<Mutex<Value>>,
}

impl AuthBlockingHook for ListingHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("no Auth request runs a function here")
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some("demo-app")
    }

    fn blocking_auth_settings(&self) -> Option<Value> {
        Some(self.settings.lock().unwrap().clone())
    }

    fn validate_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        let triggers = settings.get("triggers").and_then(Value::as_object);
        for trigger in triggers.into_iter().flat_map(|triggers| triggers.values()) {
            if trigger.is_null() {
                continue;
            }
            let object = trigger.as_object().ok_or("trigger")?;
            if object.keys().any(|key| key != "functionUri") {
                return Err("unsupported field".to_owned());
            }
            let uri = object["functionUri"].as_str().ok_or("uri")?;
            if !uri.starts_with("fireemu://functions/demo-app/") {
                return Err(format!("not a local function: {uri}"));
            }
        }
        Ok(())
    }

    fn update_blocking_auth_settings(&self, settings: &Value) -> Result<(), String> {
        self.validate_blocking_auth_settings(settings)?;
        *self.settings.lock().unwrap() = settings.clone();
        Ok(())
    }

    fn blocking_auth_triggers(&self) -> Vec<BlockingAuthTrigger> {
        let settings = self.settings.lock().unwrap();
        BlockingAuthEvent::ALL
            .into_iter()
            .filter_map(|event| {
                let uri = settings["triggers"][event.as_str()]["functionUri"].as_str()?;
                let mut parts = uri
                    .strip_prefix("fireemu://functions/demo-app/")?
                    .split('/');
                let region = parts.next()?.to_owned();
                let function = parts.next()?.to_owned();
                Some(BlockingAuthTrigger {
                    event,
                    function,
                    region,
                    update_time: LogicalInstant::from_unix_seconds(UPDATED),
                })
            })
            .collect()
    }
}

fn state(strict: bool, settings: Value) -> (AuthState, Arc<Mutex<Value>>) {
    let settings = Arc::new(Mutex::new(settings));
    let state = AuthState {
        store: Arc::new(Mutex::new(AuthStore::new(
            "demo-app",
            SplitMix64::new(5),
            TotpPolicy::default(),
        ))),
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: Some(Arc::new(ListingHook {
            settings: settings.clone(),
        })),
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: None,
        allow_routed_projects: false,
        stateless_refresh_tokens: !strict,
        idp_continuations: IdpContinuationPolicy::Disabled,
        query_limits: if strict {
            AuthQueryLimits::ProductionBounded
        } else {
            AuthQueryLimits::EmulatorUnbounded
        },
        client_api_key: ClientApiKeyPolicy::Optional,
        fake_custom_token_expiry: FakeCustomTokenExpiry::Ignore,
        custom_token_trust: None,
        idp_assertions: fireemu_adapter_http::identity_toolkit::IdpAssertionPolicy::Fixture,
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    (state, settings)
}

fn admin(state: &AuthState, method: &str, path: &str, body: &Value) -> (u16, Value) {
    let headers = RequestHeaders {
        authorization: Some("Bearer owner".to_owned()),
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    };
    let r = handle_with(state, method, path, &headers, body);
    (r.status, r.body)
}

fn deployed() -> Value {
    json!({"triggers": {
        "beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/atbBeforeCreate"},
        "beforeSignIn": null,
        "beforeSendEmail": {"functionUri": "fireemu://functions/demo-app/europe-west1/atbBeforeSendEmail"},
    }})
}

/// The strict answer: each function under its Cloud Functions URL with its trigger's update
/// time, no disabled event, and `forwardInboundCredentials` naming only enabled tokens.
#[test]
fn the_strict_profile_answers_blocking_functions_as_production() {
    let (s, _) = state(true, deployed());
    let (status, config) = admin(&s, "GET", CONFIG, &Value::Null);
    assert_eq!(status, 200, "{config}");
    let time = LogicalInstant::from_unix_seconds(UPDATED)
        .to_rfc3339()
        .unwrap();
    assert_eq!(
        config["blockingFunctions"],
        json!({
            "triggers": {
                "beforeCreate": {
                    "functionUri": "https://us-central1-demo-app.cloudfunctions.net/atbBeforeCreate",
                    "updateTime": time,
                },
                "beforeSendEmail": {
                    "functionUri": "https://europe-west1-demo-app.cloudfunctions.net/atbBeforeSendEmail",
                    "updateTime": time,
                },
            },
            "forwardInboundCredentials": {},
        })
    );

    let mut forwarding = deployed();
    forwarding["forwardInboundCredentials"] =
        json!({"idToken": true, "accessToken": false, "refreshToken": false});
    let (s, _) = state(true, forwarding);
    let (_, config) = admin(&s, "GET", CONFIG, &Value::Null);
    assert_eq!(
        config["blockingFunctions"]["forwardInboundCredentials"],
        json!({"idToken": true})
    );

    // Nothing deployed or configured: nothing to name.
    let (s, _) = state(true, json!({}));
    let (_, config) = admin(&s, "GET", CONFIG, &Value::Null);
    assert_eq!(config["blockingFunctions"], json!({}));
}

/// What a strict read answered can be written back: the URL names the local function again and
/// the output-only `updateTime` is dropped; a URL of another project or host is refused.
#[test]
fn a_strict_update_takes_back_what_a_read_answered() {
    let (s, settings) = state(true, deployed());
    let (_, config) = admin(&s, "GET", CONFIG, &Value::Null);
    let (status, updated) = admin(
        &s,
        "PATCH",
        &format!("{CONFIG}?updateMask=blockingFunctions"),
        &json!({"blockingFunctions": config["blockingFunctions"]}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(updated["blockingFunctions"], config["blockingFunctions"]);
    let stored = settings.lock().unwrap().clone();
    assert_eq!(
        stored["triggers"]["beforeSendEmail"],
        json!({"functionUri": "fireemu://functions/demo-app/europe-west1/atbBeforeSendEmail"})
    );

    let (status, updated) = admin(
        &s,
        "PATCH",
        &format!("{CONFIG}?updateMask=blockingFunctions.triggers.beforeSignIn"),
        &json!({"blockingFunctions": {"triggers": {"beforeSignIn": {
            "functionUri": "https://asia-northeast1-demo-app.cloudfunctions.net/atbBeforeSignIn",
            "updateTime": "2026-09-28T00:00:00Z",
        }}}}),
    );
    assert_eq!(status, 200, "{updated}");
    assert_eq!(
        settings.lock().unwrap()["triggers"]["beforeSignIn"],
        json!({"functionUri": "fireemu://functions/demo-app/asia-northeast1/atbBeforeSignIn"})
    );

    for uri in [
        "https://us-central1-other-app.cloudfunctions.net/atbBeforeCreate",
        "https://us-central1-demo-app.example.com/atbBeforeCreate",
        "https://us-central1-demo-app.cloudfunctions.net/a/b",
        "https://-demo-app.cloudfunctions.net/atbBeforeCreate",
        "http://us-central1-demo-app.cloudfunctions.net/atbBeforeCreate",
        // Security review of 2026-09-28: userinfo, a port, a query or fragment, other paths,
        // case, no path, and a name with a control character stay unmapped and are refused.
        "https://u@us-central1-demo-app.cloudfunctions.net/f",
        "https://us-central1-demo-app.cloudfunctions.net:443/f",
        "https://us-central1-demo-app.cloudfunctions.net/f?x=1",
        "https://us-central1-demo-app.cloudfunctions.net/f#x",
        "https://us-central1-demo-app.cloudfunctions.net/f/",
        "https://us-central1-demo-app.cloudfunctions.net/%2Ff",
        "https://us-central1-demo-app.cloudfunctions.net/..",
        "HTTPS://us-central1-demo-app.cloudfunctions.net/f",
        "https://US-CENTRAL1-DEMO-APP.CLOUDFUNCTIONS.NET/f",
        "https://us-central1-demo-app.cloudfunctions.net",
        "https://us-central1-demo-app.cloudfunctions.net/f\u{0}",
        "https://us-central1-demo-app.cloudfunctions.net/f\n",
        "fireemu://functions/other-app/us-central1/f",
    ] {
        let (status, refused) = admin(
            &s,
            "PATCH",
            &format!("{CONFIG}?updateMask=blockingFunctions.triggers.beforeCreate"),
            &json!({"blockingFunctions": {"triggers": {"beforeCreate": {"functionUri": uri}}}}),
        );
        assert_eq!(status, 400, "{uri}: {refused}");
    }
    let (status, refused) = admin(
        &s,
        "PATCH",
        &format!("{CONFIG}?updateMask=blockingFunctions.triggers.beforeCreate"),
        &json!({"blockingFunctions": {"triggers": {"beforeCreate": {
            "functionUri": "https://us-central1-demo-app.cloudfunctions.net/atbBeforeCreate",
            "updateTime": 7,
        }}}}),
    );
    assert_eq!(status, 400, "{refused}");
}

/// The emulator profile answers the bridge's own form, names no email or SMS event and refuses
/// an `updateTime` or a Cloud Functions URL, as before.
#[test]
fn the_emulator_profile_keeps_its_own_form() {
    let mut settings = deployed();
    settings["triggers"]
        .as_object_mut()
        .unwrap()
        .remove("beforeSendEmail");
    let (s, _) = state(false, settings.clone());
    let (_, config) = admin(&s, "GET", CONFIG, &Value::Null);
    assert_eq!(config["blockingFunctions"], settings);
    for trigger in [
        json!({"beforeSendEmail": {"functionUri": "fireemu://functions/demo-app/us-central1/f"}}),
        json!({"beforeCreate": {"functionUri": "fireemu://functions/demo-app/us-central1/f", "updateTime": "2026-09-28T00:00:00Z"}}),
        json!({"beforeCreate": {"functionUri": "https://us-central1-demo-app.cloudfunctions.net/f"}}),
    ] {
        let (status, refused) = admin(
            &s,
            "PATCH",
            &format!("{CONFIG}?updateMask=blockingFunctions.triggers"),
            &json!({"blockingFunctions": {"triggers": trigger}}),
        );
        assert_eq!(status, 400, "{trigger}: {refused}");
    }
}

/// Accepts any settings, so the adapter's own validation is what refuses.
struct PermissiveHook;

impl AuthBlockingHook for PermissiveHook {
    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        unreachable!("no Auth request runs a function here")
    }

    fn blocking_auth_project(&self) -> Option<&str> {
        Some("demo-app")
    }

    fn blocking_auth_settings(&self) -> Option<Value> {
        Some(json!({}))
    }

    fn validate_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Ok(())
    }

    fn update_blocking_auth_settings(&self, _settings: &Value) -> Result<(), String> {
        Ok(())
    }
}

/// The emulator profile's request validation itself refuses an `updateTime`, which only the
/// strict profile takes back from a read (closure review, suggested test).
#[test]
fn the_emulator_profile_refuses_an_update_time_before_the_bridge_sees_it() {
    for (strict, expected) in [(false, 400), (true, 200)] {
        let (mut s, _) = state(strict, json!({}));
        s.blocking = Some(Arc::new(PermissiveHook));
        let (status, body) = admin(
            &s,
            "PATCH",
            &format!("{CONFIG}?updateMask=blockingFunctions.triggers.beforeCreate"),
            &json!({"blockingFunctions": {"triggers": {"beforeCreate": {
                "functionUri": "fireemu://functions/demo-app/us-central1/f",
                "updateTime": "2026-09-28T00:00:00Z",
            }}}}),
        );
        assert_eq!(status, expected, "strict {strict}: {body}");
    }
}
