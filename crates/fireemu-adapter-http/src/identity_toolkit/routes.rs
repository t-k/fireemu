//! The one route table of the Identity Toolkit surface.
//!
//! Every path this adapter serves is described exactly once here: its method, its shape, its
//! privilege class, the bounded operation label App Check observations carry, and the handler
//! it dispatches to. Admission, authorization, observation and dispatch all read this table,
//! so a route cannot be dispatched without a label, and a label cannot name a route that is
//! not dispatched (`AUTH-ROUTE-01`, `AUTH-ROUTE-03`, `AUTH-ROUTE-05`).
//!
//! Paths that match nothing are 404 and carry the bounded `unknown` label; known paths with
//! another method are 405 (`AUTH-ROUTE-04`).

/// `concat!` with the v1 prefix, spelled once.
macro_rules! concat_v1 {
    ($s:literal) => {
        concat!("/identitytoolkit.googleapis.com/v1/", $s)
    };
}
/// `concat!` with the v2 prefix, spelled once.
macro_rules! concat_v2 {
    ($s:literal) => {
        concat!("/identitytoolkit.googleapis.com/v2/", $s)
    };
}
/// The privilege class of a route (specification sections 12.2 and 13.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RouteClass {
    /// Public-key discovery; carries no state and needs no credential.
    Jwks,
    /// `/emulator/v1/projects/{p}/...`: the inspection routes tests read codes from; a
    /// browser origin must present the control token.
    Emulator,
    /// `/identitytoolkit.googleapis.com/v1/projects/{p}...`: the Admin SDK routes; the
    /// owner credential is required.
    Admin,
    /// Everything a client SDK calls; App Check protects these under enforcement.
    EndUser,
}

/// What a route's path looks like.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Pattern {
    /// The whole path, byte for byte.
    Exact(&'static str),
    /// `{prefix}{project}{suffix}` where `project` is one non-empty segment (no `/`).
    Project {
        /// Everything before the project segment.
        prefix: &'static str,
        /// Everything after it, including its leading `/` or `:`.
        suffix: &'static str,
    },
    /// `{prefix}{project}/tenants/{tenant}{suffix}`.
    Tenant {
        /// Everything before the project segment.
        prefix: &'static str,
        /// Everything after the tenant segment.
        suffix: &'static str,
    },
}

/// How a path matched a pattern.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match<'a> {
    /// It did not.
    No,
    /// An exact pattern matched (no project segment).
    Exact,
    /// A project pattern matched with this project segment.
    Project(&'a str),
    /// A project and tenant pattern matched.
    Tenant(&'a str, &'a str),
}

impl Match<'_> {
    const fn is_hit(self) -> bool {
        !matches!(self, Self::No)
    }
}

impl Pattern {
    /// Whether `path` has this shape, and the project segment it names when it does.
    fn matches(self, path: &str) -> Match<'_> {
        match self {
            Self::Exact(p) => {
                if p == path {
                    Match::Exact
                } else {
                    Match::No
                }
            }
            Self::Project { prefix, suffix } => {
                let Some(rest) = path.strip_prefix(prefix) else {
                    return Match::No;
                };
                let Some(project) = rest.strip_suffix(suffix) else {
                    return Match::No;
                };
                if project.is_empty() || project.contains('/') {
                    Match::No
                } else {
                    Match::Project(project)
                }
            }
            Self::Tenant { prefix, suffix } => {
                let Some(rest) = path.strip_prefix(prefix) else {
                    return Match::No;
                };
                let Some((project, rest)) = rest.split_once("/tenants/") else {
                    return Match::No;
                };
                let Some(tenant) = rest.strip_suffix(suffix) else {
                    return Match::No;
                };
                if project.is_empty()
                    || project.contains('/')
                    || tenant.is_empty()
                    || tenant.contains('/')
                {
                    Match::No
                } else {
                    Match::Tenant(project, tenant)
                }
            }
        }
    }
}

/// The handler a route dispatches to. Every variant is named by exactly one row of
/// [`ROUTES`]; `Handler::ALL` lets the exhaustiveness test prove it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Handler {
    Jwks,
    SignUp,
    SignInWithPassword,
    SignInWithCustomToken,
    Lookup,
    Update,
    Delete,
    SendOobCode,
    ResetPassword,
    SignInWithEmailLink,
    SendVerificationCode,
    SignInWithPhoneNumber,
    SignInWithIdp,
    CreateAuthUri,
    Projects,
    RecaptchaParams,
    MfaEnrollmentStart,
    MfaEnrollmentFinalize,
    MfaEnrollmentWithdraw,
    MfaSignInStart,
    MfaSignInFinalize,
    Token,
    AdminCreate,
    AdminLookup,
    AdminUpdate,
    AdminDelete,
    AdminBatchGet,
    AdminBatchCreate,
    AdminBatchDelete,
    AdminQuery,
    AdminSendOobCode,
    AdminCreateSessionCookie,
    TenantCreate,
    TenantList,
    TenantGet,
    TenantUpdate,
    TenantDelete,
    AdminGetProjectConfig,
    AdminUpdateProjectConfig,
    EmulatorOobCodes,
    EmulatorVerificationCodes,
    EmulatorClearAccounts,
    EmulatorGetConfig,
    EmulatorPatchConfig,
}

impl Handler {
    /// Every handler, for the exhaustiveness test.
    #[cfg(test)]
    pub(crate) const ALL: &'static [Self] = &[
        Self::Jwks,
        Self::SignUp,
        Self::SignInWithPassword,
        Self::SignInWithCustomToken,
        Self::Lookup,
        Self::Update,
        Self::Delete,
        Self::SendOobCode,
        Self::ResetPassword,
        Self::SignInWithEmailLink,
        Self::SendVerificationCode,
        Self::SignInWithPhoneNumber,
        Self::SignInWithIdp,
        Self::CreateAuthUri,
        Self::Projects,
        Self::RecaptchaParams,
        Self::MfaEnrollmentStart,
        Self::MfaEnrollmentFinalize,
        Self::MfaEnrollmentWithdraw,
        Self::MfaSignInStart,
        Self::MfaSignInFinalize,
        Self::Token,
        Self::AdminCreate,
        Self::AdminLookup,
        Self::AdminUpdate,
        Self::AdminDelete,
        Self::AdminBatchGet,
        Self::AdminBatchCreate,
        Self::AdminBatchDelete,
        Self::AdminQuery,
        Self::AdminSendOobCode,
        Self::AdminCreateSessionCookie,
        Self::TenantCreate,
        Self::TenantList,
        Self::TenantGet,
        Self::TenantUpdate,
        Self::TenantDelete,
        Self::AdminGetProjectConfig,
        Self::AdminUpdateProjectConfig,
        Self::EmulatorOobCodes,
        Self::EmulatorVerificationCodes,
        Self::EmulatorClearAccounts,
        Self::EmulatorGetConfig,
        Self::EmulatorPatchConfig,
    ];
}

/// One row of the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Route {
    /// The one method the route accepts (`GET`, `POST`, `PATCH`, `DELETE`).
    pub method: &'static str,
    /// The path shape.
    pub pattern: Pattern,
    /// Privilege class.
    pub class: RouteClass,
    /// The bounded operation label observations carry. Never `unknown`.
    pub operation: &'static str,
    /// The handler.
    pub handler: Handler,
}

const ADMIN: &str = "/identitytoolkit.googleapis.com/v1/projects/";
const ADMIN_V2: &str = "/identitytoolkit.googleapis.com/v2/projects/";
const ADMIN_CONFIG: &str = "/identitytoolkit.googleapis.com/admin/v2/projects/";
const EMULATOR: &str = "/emulator/v1/projects/";

/// The label bucket of a path this runtime does not serve.
pub(crate) const UNKNOWN_OPERATION: &str = "unknown";

const fn end_user(
    method: &'static str,
    path: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Exact(path),
        class: RouteClass::EndUser,
        operation,
        handler,
    }
}

const fn admin(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Project {
            prefix: ADMIN,
            suffix,
        },
        class: RouteClass::Admin,
        operation,
        handler,
    }
}

const fn tenant_admin(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Tenant {
            prefix: ADMIN,
            suffix,
        },
        class: RouteClass::Admin,
        operation,
        handler,
    }
}

const fn admin_v2(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Project {
            prefix: ADMIN_V2,
            suffix,
        },
        class: RouteClass::Admin,
        operation,
        handler,
    }
}

const fn admin_config(method: &'static str, operation: &'static str, handler: Handler) -> Route {
    Route {
        method,
        pattern: Pattern::Project {
            prefix: ADMIN_CONFIG,
            suffix: "/config",
        },
        class: RouteClass::Admin,
        operation,
        handler,
    }
}

const fn tenant_v2(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Tenant {
            prefix: ADMIN_V2,
            suffix,
        },
        class: RouteClass::Admin,
        operation,
        handler,
    }
}

const fn emulator(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Project {
            prefix: EMULATOR,
            suffix,
        },
        class: RouteClass::Emulator,
        operation,
        handler,
    }
}

/// The tenant-scoped inspection routes (`/emulator/v1/projects/{p}/tenants/{t}/...`) the
/// official emulator serves for accounts, oobCodes and verificationCodes.
const fn emulator_tenant(
    method: &'static str,
    suffix: &'static str,
    operation: &'static str,
    handler: Handler,
) -> Route {
    Route {
        method,
        pattern: Pattern::Tenant {
            prefix: EMULATOR,
            suffix,
        },
        class: RouteClass::Emulator,
        operation,
        handler,
    }
}

const fn jwks(path: &'static str) -> Route {
    Route {
        method: "GET",
        pattern: Pattern::Exact(path),
        class: RouteClass::Jwks,
        operation: "jwks",
        handler: Handler::Jwks,
    }
}

/// The table. Order matters only for readability: patterns are disjoint.
pub(crate) const ROUTES: &[Route] = &[
    jwks("/.well-known/jwks.json"),
    jwks("/www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com"),
    // End-user routes (specification section 13.3 publishes these labels).
    end_user(
        "POST",
        concat_v1!("accounts:signUp"),
        "accounts:signUp",
        Handler::SignUp,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:signInWithPassword"),
        "accounts:signInWithPassword",
        Handler::SignInWithPassword,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:signInWithCustomToken"),
        "accounts:signInWithCustomToken",
        Handler::SignInWithCustomToken,
    ),
    end_user(
        "POST",
        "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken",
        "accounts:signInWithCustomToken",
        Handler::SignInWithCustomToken,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:lookup"),
        "accounts:lookup",
        Handler::Lookup,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:update"),
        "accounts:update",
        Handler::Update,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:delete"),
        "accounts:delete",
        Handler::Delete,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:sendOobCode"),
        "accounts:sendOobCode",
        Handler::SendOobCode,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:resetPassword"),
        "accounts:resetPassword",
        Handler::ResetPassword,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:signInWithEmailLink"),
        "accounts:signInWithEmailLink",
        Handler::SignInWithEmailLink,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:sendVerificationCode"),
        "accounts:sendVerificationCode",
        Handler::SendVerificationCode,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:signInWithPhoneNumber"),
        "accounts:signInWithPhoneNumber",
        Handler::SignInWithPhoneNumber,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:signInWithIdp"),
        "accounts:signInWithIdp",
        Handler::SignInWithIdp,
    ),
    end_user(
        "POST",
        concat_v1!("accounts:createAuthUri"),
        "accounts:createAuthUri",
        Handler::CreateAuthUri,
    ),
    end_user("GET", concat_v1!("projects"), "projects", Handler::Projects),
    end_user(
        "GET",
        concat_v1!("recaptchaParams"),
        "recaptchaParams",
        Handler::RecaptchaParams,
    ),
    end_user(
        "POST",
        concat_v2!("accounts/mfaEnrollment:start"),
        "mfaEnrollment:start",
        Handler::MfaEnrollmentStart,
    ),
    end_user(
        "POST",
        concat_v2!("accounts/mfaEnrollment:finalize"),
        "mfaEnrollment:finalize",
        Handler::MfaEnrollmentFinalize,
    ),
    end_user(
        "POST",
        concat_v2!("accounts/mfaEnrollment:withdraw"),
        "mfaEnrollment:withdraw",
        Handler::MfaEnrollmentWithdraw,
    ),
    end_user(
        "POST",
        concat_v2!("accounts/mfaSignIn:start"),
        "mfaSignIn:start",
        Handler::MfaSignInStart,
    ),
    end_user(
        "POST",
        concat_v2!("accounts/mfaSignIn:finalize"),
        "mfaSignIn:finalize",
        Handler::MfaSignInFinalize,
    ),
    end_user(
        "POST",
        "/securetoken.googleapis.com/v1/token",
        "securetoken:token",
        Handler::Token,
    ),
    // Admin SDK routes, project-scoped.
    admin("POST", "/accounts", "admin/accounts", Handler::AdminCreate),
    admin(
        "POST",
        "/accounts:lookup",
        "admin/accounts:lookup",
        Handler::AdminLookup,
    ),
    admin(
        "POST",
        "/accounts:update",
        "admin/accounts:update",
        Handler::AdminUpdate,
    ),
    admin(
        "POST",
        "/accounts:delete",
        "admin/accounts:delete",
        Handler::AdminDelete,
    ),
    admin(
        "GET",
        "/accounts:batchGet",
        "admin/accounts:batchGet",
        Handler::AdminBatchGet,
    ),
    admin(
        "POST",
        "/accounts:batchCreate",
        "admin/accounts:batchCreate",
        Handler::AdminBatchCreate,
    ),
    admin(
        "POST",
        "/accounts:batchDelete",
        "admin/accounts:batchDelete",
        Handler::AdminBatchDelete,
    ),
    admin(
        "POST",
        "/accounts:query",
        "admin/accounts:query",
        Handler::AdminQuery,
    ),
    admin(
        "POST",
        "/accounts:sendOobCode",
        "admin/accounts:sendOobCode",
        Handler::AdminSendOobCode,
    ),
    admin(
        "POST",
        ":createSessionCookie",
        "admin/createSessionCookie",
        Handler::AdminCreateSessionCookie,
    ),
    tenant_admin("POST", "/accounts", "tenant/accounts", Handler::AdminCreate),
    tenant_admin(
        "POST",
        "/accounts:lookup",
        "tenant/accounts:lookup",
        Handler::AdminLookup,
    ),
    tenant_admin(
        "POST",
        "/accounts:update",
        "tenant/accounts:update",
        Handler::AdminUpdate,
    ),
    tenant_admin(
        "POST",
        "/accounts:delete",
        "tenant/accounts:delete",
        Handler::AdminDelete,
    ),
    tenant_admin(
        "GET",
        "/accounts:batchGet",
        "tenant/accounts:batchGet",
        Handler::AdminBatchGet,
    ),
    tenant_admin(
        "POST",
        "/accounts:batchCreate",
        "tenant/accounts:batchCreate",
        Handler::AdminBatchCreate,
    ),
    tenant_admin(
        "POST",
        "/accounts:batchDelete",
        "tenant/accounts:batchDelete",
        Handler::AdminBatchDelete,
    ),
    tenant_admin(
        "POST",
        "/accounts:query",
        "tenant/accounts:query",
        Handler::AdminQuery,
    ),
    tenant_admin(
        "POST",
        "/accounts:sendOobCode",
        "tenant/accounts:sendOobCode",
        Handler::AdminSendOobCode,
    ),
    tenant_admin(
        "POST",
        ":createSessionCookie",
        "tenant/createSessionCookie",
        Handler::AdminCreateSessionCookie,
    ),
    admin_v2("POST", "/tenants", "tenants:create", Handler::TenantCreate),
    admin_v2("GET", "/tenants", "tenants:list", Handler::TenantList),
    tenant_v2("GET", "", "tenants:get", Handler::TenantGet),
    tenant_v2("PATCH", "", "tenants:update", Handler::TenantUpdate),
    tenant_v2("DELETE", "", "tenants:delete", Handler::TenantDelete),
    admin_config("GET", "config:get", Handler::AdminGetProjectConfig),
    admin_config("PATCH", "config:update", Handler::AdminUpdateProjectConfig),
    // Emulator inspection routes.
    emulator(
        "GET",
        "/oobCodes",
        "emulator/oobCodes",
        Handler::EmulatorOobCodes,
    ),
    emulator(
        "GET",
        "/verificationCodes",
        "emulator/verificationCodes",
        Handler::EmulatorVerificationCodes,
    ),
    emulator(
        "DELETE",
        "/accounts",
        "emulator/accounts",
        Handler::EmulatorClearAccounts,
    ),
    emulator_tenant(
        "GET",
        "/oobCodes",
        "emulator/oobCodes",
        Handler::EmulatorOobCodes,
    ),
    emulator_tenant(
        "GET",
        "/verificationCodes",
        "emulator/verificationCodes",
        Handler::EmulatorVerificationCodes,
    ),
    emulator_tenant(
        "DELETE",
        "/accounts",
        "emulator/accounts",
        Handler::EmulatorClearAccounts,
    ),
    emulator(
        "GET",
        "/config",
        "emulator/config",
        Handler::EmulatorGetConfig,
    ),
    emulator(
        "PATCH",
        "/config",
        "emulator/config",
        Handler::EmulatorPatchConfig,
    ),
];

/// The outcome of resolving a request against the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Resolution<'a> {
    /// A route, and the project its path names (when the pattern has one).
    Matched {
        /// The row.
        route: &'static Route,
        /// The project segment.
        project: Option<&'a str>,
        /// Tenant segment for a tenant-scoped route.
        tenant: Option<&'a str>,
    },
    /// The path is known but not with this method.
    MethodNotAllowed {
        /// The class of the route the path belongs to.
        class: RouteClass,
        /// The project segment.
        project: Option<&'a str>,
        /// Tenant segment for a tenant-scoped route.
        tenant: Option<&'a str>,
    },
    /// No row matches the path.
    NotFound,
}

/// Resolves `method` and `path` (without its query) against the table.
pub(crate) fn resolve<'a>(method: &str, path: &'a str) -> Resolution<'a> {
    let mut known: Option<(RouteClass, Option<&'a str>, Option<&'a str>)> = None;
    for route in ROUTES {
        let hit = route.pattern.matches(path);
        if hit.is_hit() {
            let (project, tenant) = match hit {
                Match::Project(p) => (Some(p), None),
                Match::Tenant(p, t) => (Some(p), Some(t)),
                Match::No | Match::Exact => (None, None),
            };
            if route.method == method {
                return Resolution::Matched {
                    route,
                    project,
                    tenant,
                };
            }
            known.get_or_insert((route.class, project, tenant));
        }
    }
    match known {
        Some((class, project, tenant)) => Resolution::MethodNotAllowed {
            class,
            project,
            tenant,
        },
        None => Resolution::NotFound,
    }
}

/// The class a path belongs to whatever its method, for the privilege checks that run before
/// dispatch (a wrong-method request to an Admin path is still refused as an Admin request
/// when it lacks the owner credential). `None` for a path no row matches.
pub(crate) fn class_of(path: &str) -> Option<(RouteClass, Option<&str>)> {
    ROUTES.iter().find_map(|r| match r.pattern.matches(path) {
        Match::No => None,
        Match::Exact => Some((r.class, None)),
        Match::Project(p) | Match::Tenant(p, _) => Some((r.class, Some(p))),
    })
}

/// The bounded operation label of `path`, for observations: the label of any row matching
/// the path, else [`UNKNOWN_OPERATION`].
pub(crate) fn operation_of(path: &str) -> &'static str {
    ROUTES
        .iter()
        .find(|r| r.pattern.matches(path).is_hit())
        .map_or(UNKNOWN_OPERATION, |r| r.operation)
}

/// Project and optional tenant named by a scoped route.
pub(crate) fn scoped_target(path: &str) -> Option<(&str, Option<&str>)> {
    ROUTES.iter().find_map(|r| match r.pattern.matches(path) {
        Match::Project(project) => Some((project, None)),
        Match::Tenant(project, tenant) => Some((project, Some(tenant))),
        Match::No | Match::Exact => None,
    })
}

#[cfg(test)]
mod tests {
    //! The invariants of the table itself (`AUTH-ROUTE-01`, `-02`, `-05`): every handler is
    //! dispatched by exactly one row, every row has a bounded non-`unknown` label, and no two
    //! rows share a method and a pattern. Deleting a row, blanking a label or duplicating a
    //! path fails here before any request is served.

    use std::collections::BTreeSet;

    use super::{
        class_of, operation_of, resolve, Handler, Pattern, Resolution, RouteClass, ROUTES,
        UNKNOWN_OPERATION,
    };

    #[test]
    fn every_handler_is_dispatched_by_at_least_one_row() {
        for handler in Handler::ALL {
            let rows = ROUTES.iter().filter(|r| r.handler == *handler).count();
            assert!(rows > 0, "{handler:?} must have a route row");
        }
    }

    #[test]
    fn every_row_has_a_bounded_label_and_a_unique_method_and_pattern() {
        let mut seen = BTreeSet::new();
        for route in ROUTES {
            assert_ne!(route.operation, UNKNOWN_OPERATION, "{route:?}");
            assert!(!route.operation.is_empty(), "{route:?}");
            assert!(
                matches!(route.method, "GET" | "POST" | "PATCH" | "DELETE"),
                "{route:?}"
            );
            assert!(
                seen.insert((route.method, route.pattern)),
                "duplicate row {route:?}"
            );
            match route.pattern {
                Pattern::Project { prefix, suffix } => {
                    assert!(prefix.ends_with('/') && !suffix.is_empty(), "{route:?}");
                }
                Pattern::Tenant { prefix, .. } => assert!(prefix.ends_with('/'), "{route:?}"),
                Pattern::Exact(_) => {}
            }
        }
    }

    #[test]
    fn end_user_labels_are_the_published_canonical_operation_names() {
        for route in ROUTES.iter().filter(|r| r.class == RouteClass::EndUser) {
            let Pattern::Exact(path) = route.pattern else {
                panic!("end-user routes are exact paths: {route:?}");
            };
            let tail = path.rsplit('/').next().unwrap_or(path);
            assert!(
                route.operation == tail
                    || route.operation == "securetoken:token"
                    || (path
                        == "/www.googleapis.com/identitytoolkit/v3/relyingparty/verifyCustomToken"
                        && route.operation == "accounts:signInWithCustomToken")
                    || path.contains("/v2/accounts/"),
                "label {} does not name {path}",
                route.operation
            );
            assert_eq!(operation_of(path), route.operation);
        }
    }

    #[test]
    fn unknown_paths_and_wrong_methods_resolve_distinctly() {
        assert_eq!(
            resolve(
                "POST",
                "/identitytoolkit.googleapis.com/v1/accounts:notARoute"
            ),
            Resolution::NotFound
        );
        assert_eq!(
            operation_of("/identitytoolkit.googleapis.com/v1/accounts:notARoute"),
            UNKNOWN_OPERATION
        );
        assert_eq!(class_of("/nothing"), None);
        assert!(matches!(
            resolve("GET", "/identitytoolkit.googleapis.com/v1/accounts:signUp"),
            Resolution::MethodNotAllowed {
                class: RouteClass::EndUser,
                project: None,
                tenant: None
            }
        ));
        assert!(matches!(
            resolve(
                "PUT",
                "/identitytoolkit.googleapis.com/v1/projects/demo-app/accounts:lookup"
            ),
            Resolution::MethodNotAllowed {
                class: RouteClass::Admin,
                project: Some("demo-app"),
                tenant: None
            }
        ));
        assert!(matches!(
            resolve("POST", "/identitytoolkit.googleapis.com/v1/projects/demo-app:createSessionCookie"),
            Resolution::Matched { route, project: Some("demo-app"), tenant: None } if route.handler == Handler::AdminCreateSessionCookie
        ));
        assert!(matches!(
            resolve("PATCH", "/emulator/v1/projects/demo-app/config"),
            Resolution::Matched { route, project: Some("demo-app"), tenant: None } if route.handler == Handler::EmulatorPatchConfig
        ));
        assert!(matches!(
            resolve(
                "POST",
                "/identitytoolkit.googleapis.com/v1/projects/demo-app/tenants/customer-a/accounts:lookup"
            ),
            Resolution::Matched {
                route,
                project: Some("demo-app"),
                tenant: Some("customer-a")
            } if route.handler == Handler::AdminLookup
        ));
        // A project segment is exactly one segment.
        assert_eq!(
            resolve("GET", "/emulator/v1/projects/a/b/config"),
            Resolution::NotFound
        );
        assert_eq!(
            resolve("GET", "/emulator/v1/projects//config"),
            Resolution::NotFound
        );
    }
}
