//! Identity Platform's `beforeSendEmail` blocking event (AUTH-TENANT-BLOCKING recording
//! 2026-09-28, program `atb/blocking/send`): production runs it before a password reset or an
//! email sign-in mail, on the client and the Admin route, in a project and in a tenant, and a
//! refusal answers the request. The official Auth emulator has no email event, so only the
//! strict profile runs it.

use std::sync::{Arc, Mutex};

use fireemu_adapter_http::identity_toolkit::{
    handle_with, AuthBlockingContext, AuthBlockingHook, AuthQueryLimits, AuthState,
    BlockingFunctionCode, BlockingFunctionFailure, ClientApiKeyPolicy, FakeCustomTokenExpiry,
    IdpContinuationPolicy, RequestHeaders,
};
use fireemu_core_auth::mfa::TotpPolicy;
use fireemu_core_auth::store::{AuthRegistry, AuthStore};
use fireemu_core_functions::manifest::BlockingAuthEvent;
use fireemu_core_session::clock::VirtualClock;
use fireemu_core_types::determinism::SplitMix64;
use fireemu_core_types::time::LogicalInstant;
use serde_json::{json, Value};

const V1: &str = "/identitytoolkit.googleapis.com/v1";
const V2: &str = "/identitytoolkit.googleapis.com/v2";
const CONTINUE: &str = "https://demo-app.firebaseapp.com/finish";

/// One mail the hook saw: the project, the address and the kind of mail.
type Mail = (String, Option<String>, Option<String>);

/// A named request and the mail it should run the event for.
type MailCase<'a> = (&'a str, Box<dyn Fn() -> (u16, Value) + 'a>, Mail);

/// Records every `beforeSendEmail` it runs and refuses a mail to an address starting `refused`.
struct SendEmailHook {
    mails: Arc<Mutex<Vec<Mail>>>,
    handles_send_email: bool,
}

impl AuthBlockingHook for SendEmailHook {
    fn handles(&self, event: BlockingAuthEvent) -> bool {
        event == BlockingAuthEvent::BeforeSendEmail && self.handles_send_email
    }

    fn invoke(
        &self,
        _event: BlockingAuthEvent,
        _user: &fireemu_core_auth::store::UserRecord,
    ) -> Result<Value, BlockingFunctionFailure> {
        Ok(json!({}))
    }

    fn invoke_before_send_email(
        &self,
        project: &str,
        context: &AuthBlockingContext,
    ) -> Result<Option<Value>, BlockingFunctionFailure> {
        self.mails.lock().unwrap().push((
            project.to_owned(),
            context.email.clone(),
            context.email_type.clone(),
        ));
        if context
            .email
            .as_deref()
            .is_some_and(|email| email.starts_with("refused"))
        {
            return Err(BlockingFunctionFailure::from_function(
                BlockingFunctionCode::PermissionDenied,
                "mail refused",
            )
            .unwrap());
        }
        // What the function answers changes nothing (send#reset-mail-blocked).
        Ok(Some(json!({"recaptchaActionOverride": "BLOCK"})))
    }
}

fn state(strict: bool, handles_send_email: bool) -> (AuthState, Arc<Mutex<Vec<Mail>>>) {
    let store = Arc::new(Mutex::new(AuthStore::new(
        "demo-app",
        SplitMix64::new(5),
        TotpPolicy::default(),
    )));
    let registry = Arc::new(AuthRegistry::new("demo-app", store.clone()));
    let mails = Arc::new(Mutex::new(Vec::new()));
    let state = AuthState {
        store,
        clock: Arc::new(Mutex::new(VirtualClock::new(
            LogicalInstant::from_unix_seconds(1_788_004_860),
        ))),
        wall_clock: None,
        totp_extension_enabled: false,
        barrier: None,
        events: None,
        notices: None,
        blocking: Some(Arc::new(SendEmailHook {
            mails: mails.clone(),
            handles_send_email,
        })),
        operation_gate: Arc::new(Mutex::new(())),
        control_token: None,
        registry: Some(registry),
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
        app_check: None,
        app_check_policy: None,
        tenancy: None,
    };
    let (status, body) = admin(
        &state,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=multiTenant.allowTenants,signIn.email",
        &json!({
            "multiTenant": {"allowTenants": true},
            "signIn": {"email": {"enabled": true, "passwordRequired": false}},
        }),
    );
    assert_eq!(status, 200, "{body}");
    (state, mails)
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

fn client(state: &AuthState, path: &str, body: &Value) -> (u16, Value) {
    let headers = RequestHeaders {
        authorization: None,
        origin: None,
        content_type: Some("application/json".to_owned()),
        host: Some("127.0.0.1:9099".to_owned()),
        app_check: Vec::new(),
        peer_ip: None,
    };
    let r = handle_with(state, "POST", path, &headers, body);
    (r.status, r.body)
}

fn create_account(state: &AuthState, accounts: &str, email: &str) -> Value {
    let (status, created) = admin(
        state,
        "POST",
        accounts,
        &json!({"email": email, "password": "hunter22"}),
    );
    assert_eq!(status, 200, "{created}");
    created
}

fn create_tenant(state: &AuthState) -> String {
    let (status, tenant) = admin(
        state,
        "POST",
        &format!("{V2}/projects/demo-app/tenants"),
        &json!({"displayName": "send", "allowPasswordSignup": true, "enableEmailLinkSignin": true}),
    );
    assert_eq!(status, 200, "{tenant}");
    tenant["name"]
        .as_str()
        .and_then(|name| name.rsplit('/').next())
        .unwrap()
        .to_owned()
}

/// The outstanding action codes of the project and of `tenant`.
fn codes(state: &AuthState, tenant: &str) -> std::collections::BTreeSet<String> {
    let registry = state.registry.as_ref().unwrap();
    [
        state.store.clone(),
        registry.tenant_store("demo-app", tenant).unwrap(),
    ]
    .iter()
    .flat_map(|store| {
        store
            .lock()
            .unwrap()
            .oob_codes()
            .into_iter()
            .map(|code| code.code.clone())
            .collect::<Vec<_>>()
    })
    .collect()
}

fn mail(email: &str, email_type: &str) -> Mail {
    (
        "demo-app".to_owned(),
        Some(email.to_owned()),
        Some(email_type.to_owned()),
    )
}

/// Every path a password reset or an email sign-in mail takes runs the event once, naming the
/// project, the address and the kind of mail, and neither a user nor a tenant
/// (send#link-mail-echo-in-tenant names the project).
#[test]
fn every_mail_path_runs_before_send_email_in_the_strict_profile() {
    let (s, mails) = state(true, true);
    create_account(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        "reset@example.com",
    );
    let tenant = create_tenant(&s);
    create_account(
        &s,
        &format!("{V1}/projects/demo-app/tenants/{tenant}/accounts"),
        "tenant-reset@example.com",
    );
    let send = format!("{V1}/accounts:sendOobCode");
    let admin_send = format!("{V1}/projects/demo-app/accounts:sendOobCode");
    let cases: [MailCase; 6] = [
        (
            "client reset",
            Box::new(|| {
                client(
                    &s,
                    &send,
                    &json!({"requestType": "PASSWORD_RESET", "email": "reset@example.com"}),
                )
            }),
            mail("reset@example.com", "PASSWORD_RESET"),
        ),
        (
            "admin reset link",
            Box::new(|| {
                admin(
                    &s,
                    "POST",
                    &admin_send,
                    &json!({"requestType": "PASSWORD_RESET", "email": "reset@example.com", "returnOobLink": true}),
                )
            }),
            mail("reset@example.com", "PASSWORD_RESET"),
        ),
        (
            "client sign-in link",
            Box::new(|| {
                client(
                    &s,
                    &send,
                    &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "continueUrl": CONTINUE}),
                )
            }),
            mail("link@example.com", "EMAIL_SIGN_IN"),
        ),
        (
            "admin sign-in link",
            Box::new(|| {
                admin(
                    &s,
                    "POST",
                    &admin_send,
                    &json!({"requestType": "EMAIL_SIGNIN", "email": "link@example.com", "continueUrl": CONTINUE, "returnOobLink": true}),
                )
            }),
            mail("link@example.com", "EMAIL_SIGN_IN"),
        ),
        (
            "tenant sign-in link",
            Box::new(|| {
                client(
                    &s,
                    &send,
                    &json!({"requestType": "EMAIL_SIGNIN", "email": "tenant-link@example.com", "tenantId": tenant}),
                )
            }),
            mail("tenant-link@example.com", "EMAIL_SIGN_IN"),
        ),
        (
            "tenant reset",
            Box::new(|| {
                client(
                    &s,
                    &send,
                    &json!({"requestType": "PASSWORD_RESET", "email": "tenant-reset@example.com", "tenantId": tenant}),
                )
            }),
            mail("tenant-reset@example.com", "PASSWORD_RESET"),
        ),
    ];
    for (path, send, expected) in cases {
        mails.lock().unwrap().clear();
        let before = codes(&s, &tenant);
        let (status, body) = send();
        assert_eq!(status, 200, "{path}: {body}");
        assert_eq!(*mails.lock().unwrap(), vec![expected], "{path}");
        assert!(
            !codes(&s, &tenant).is_subset(&before),
            "{path}: the mail's code is created"
        );
    }
}

/// A refusal answers the request with the function's error and sends nothing
/// (send#reset-mail-refused and the echo rows).
#[test]
fn a_refused_mail_answers_the_function_error_and_creates_no_code() {
    let (s, mails) = state(true, true);
    create_account(
        &s,
        &format!("{V1}/projects/demo-app/accounts"),
        "refused@example.com",
    );
    let tenant = create_tenant(&s);
    let refused = "BLOCKING_FUNCTION_ERROR_RESPONSE : HTTP Cloud Function returned an error: {\"error\":{\"message\":\"mail refused\",\"status\":\"PERMISSION_DENIED\"}}";
    for (path, body, privileged) in [
        (
            "client reset",
            json!({"requestType": "PASSWORD_RESET", "email": "refused@example.com"}),
            false,
        ),
        (
            "admin reset link",
            json!({"requestType": "PASSWORD_RESET", "email": "refused@example.com", "returnOobLink": true}),
            true,
        ),
        (
            "client sign-in link",
            json!({"requestType": "EMAIL_SIGNIN", "email": "refused-link@example.com", "continueUrl": CONTINUE}),
            false,
        ),
        (
            "tenant sign-in link",
            json!({"requestType": "EMAIL_SIGNIN", "email": "refused-link@example.com", "tenantId": tenant}),
            false,
        ),
    ] {
        let before = codes(&s, &tenant);
        let (status, answer) = if privileged {
            admin(
                &s,
                "POST",
                &format!("{V1}/projects/demo-app/accounts:sendOobCode"),
                &body,
            )
        } else {
            client(&s, &format!("{V1}/accounts:sendOobCode"), &body)
        };
        assert_eq!(status, 400, "{path}: {answer}");
        assert_eq!(answer["error"]["message"], refused, "{path}");
        assert_eq!(codes(&s, &tenant), before, "{path}: no code");
    }
    assert_eq!(mails.lock().unwrap().len(), 4);
}

/// No event runs where production sends no password reset or sign-in mail: an email
/// verification (send#verify-mail-echo answered 200 for the echo address), an unknown address
/// under improved email privacy, a function that does not handle the event, or the emulator
/// profile (the official Auth emulator has no email event).
#[test]
fn no_event_runs_without_a_reset_or_sign_in_mail_or_in_the_emulator_profile() {
    let (s, mails) = state(true, true);
    let (status, created) = client(
        &s,
        &format!("{V1}/accounts:signUp"),
        &json!({"email": "refused-verify@example.com", "password": "hunter22", "returnSecureToken": true}),
    );
    assert_eq!(status, 200, "{created}");
    let (status, body) = client(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "VERIFY_EMAIL", "idToken": created["idToken"]}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = admin(
        &s,
        "PATCH",
        "/identitytoolkit.googleapis.com/admin/v2/projects/demo-app/config?updateMask=emailPrivacyConfig.enableImprovedEmailPrivacy",
        &json!({"emailPrivacyConfig": {"enableImprovedEmailPrivacy": true}}),
    );
    assert_eq!(status, 200, "{body}");
    let (status, body) = client(
        &s,
        &format!("{V1}/accounts:sendOobCode"),
        &json!({"requestType": "PASSWORD_RESET", "email": "refused-unknown@example.com"}),
    );
    assert_eq!(status, 200, "{body}");
    assert!(
        mails.lock().unwrap().is_empty(),
        "{:?}",
        mails.lock().unwrap()
    );

    for (strict, handles) in [(true, false), (false, true)] {
        let (s, mails) = state(strict, handles);
        create_account(
            &s,
            &format!("{V1}/projects/demo-app/accounts"),
            "refused@example.com",
        );
        let (status, body) = client(
            &s,
            &format!("{V1}/accounts:sendOobCode"),
            &json!({"requestType": "PASSWORD_RESET", "email": "refused@example.com"}),
        );
        assert_eq!(status, 200, "strict {strict}, handles {handles}: {body}");
        assert!(
            mails.lock().unwrap().is_empty(),
            "strict {strict}, handles {handles}"
        );
    }
}
