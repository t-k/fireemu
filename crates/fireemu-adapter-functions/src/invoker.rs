//! Who may call a function's public URL.
//!
//! In production a function is reachable by whoever Cloud Run IAM lets in. An HTTP function with
//! `invoker: "public"` (the default of `onRequest` and every callable) admits anyone. One that
//! names `invoker: "private"` or a list of service accounts, and every task-queue function (its
//! queue's service account is the only invoker), answers a request without an IAM-authorised
//! identity token with 403 from the front end, before the function ever runs. Fireemu used to
//! record `invoker` and serve every function to every caller, so a test could not see the 403
//! that a browser or a `fetch` without a token gets in production.
//!
//! The check applies to the **public function URL only**. Everything Fireemu itself starts goes
//! around it: task dispatch, Cloud Scheduler delivery, events and blocking functions reach the
//! runner directly, and the console and control API (`POST /v1/functions/{name}:invoke`,
//! `:enqueue`) present the control token as the project owner's credential
//! ([`OWNER_TOKEN_HEADER`]).
//!
//! What cannot be reproduced locally is Google's verification of the identity token and the
//! IAM check of its subject. A bearer token shaped like a signed JWT is accepted as the
//! credential of an authorised invoker (the same permissive reading the Eventarc listener takes
//! by default), a bearer that is not a JWT is refused with 401, and a request with no bearer is
//! refused with 403. That keeps the bug a developer needs to see (a call without credentials to
//! a function that is not public) and leaves the unreproducible part to production.

use fireemu_core_functions::manifest::{FunctionSpec, Trigger};

/// The header the console and the control API use to present the owner's credential: the control
/// token. It is removed before a request reaches the runner.
pub const OWNER_TOKEN_HEADER: &str = "x-fireemu-owner-token";

/// How a function's public URL is guarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Access {
    /// Anyone may call it.
    Public,
    /// Only an authorised invoker may call it.
    Restricted,
}

/// What to do with a request to a function's public URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Forward it.
    Allow,
    /// 403: no credential for a function that is not public.
    Forbidden,
    /// 401: a bearer credential that cannot be an identity token.
    Unauthenticated,
}

/// The access rule of one function.
///
/// An HTTP or callable function is public unless its `invoker` list is non-empty and does not
/// contain `public`. A task-queue function is never public: its trigger carries no `invoker`
/// that firebase-tools would open to `allUsers`. Every other trigger has no public URL at all.
#[must_use]
pub fn access_of(function: &FunctionSpec) -> Access {
    match function.trigger {
        Trigger::Http { .. } => {
            let invokers = &function.platform_options.invokers;
            if invokers.is_empty() || invokers.iter().any(|invoker| invoker == "public") {
                Access::Public
            } else {
                Access::Restricted
            }
        }
        Trigger::TaskQueue { .. } => Access::Restricted,
        _ => Access::Public,
    }
}

/// Whether `token` has the shape of a signed JWT: three non-empty base64url segments.
#[must_use]
pub fn is_jwt_shaped(token: &str) -> bool {
    let mut segments = token.split('.');
    let shaped = |segment: Option<&str>| {
        segment.is_some_and(|s| {
            !s.is_empty()
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
    };
    shaped(segments.next())
        && shaped(segments.next())
        && shaped(segments.next())
        && segments.next().is_none()
}

/// Judges a request. `owner` says the owner credential matched; `authorization` is every
/// `Authorization` field instance in wire order.
#[must_use]
pub fn decide(access: Access, owner: bool, authorization: &[String]) -> Decision {
    if access == Access::Public || owner {
        return Decision::Allow;
    }
    let [value] = authorization else {
        return if authorization.is_empty() {
            Decision::Forbidden
        } else {
            Decision::Unauthenticated
        };
    };
    let bearer = value
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim());
    match bearer {
        Some(token) if is_jwt_shaped(token) => Decision::Allow,
        // Not a bearer credential at all (Basic, an empty value) reads as no credential: the
        // front end only recognises identity tokens, and the call is refused as unauthorised.
        None => Decision::Forbidden,
        Some(_) => Decision::Unauthenticated,
    }
}

/// The 403 page the Google front end answers for a function that is not public.
///
/// UNRECORDED: no production observation of this answer is stored in the repository. The text
/// is the front end's own page for an IAM refusal as it is documented and widely reproduced,
/// not a measured shape; replace it when a sandbox run records one.
#[must_use]
pub fn forbidden_page(path: &str) -> String {
    let escaped = path
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;");
    format!(
        "<html><head>\n<meta http-equiv=\"content-type\" content=\"text/html;charset=utf-8\">\n\
         <title>403 Forbidden</title>\n</head>\n<body text=#000000 bgcolor=#ffffff>\n\
         <h1>Error: Forbidden</h1>\n<h2>Your client does not have permission to get URL \
         <code>{escaped}</code> from this server.</h2>\n<h2></h2>\n</body></html>\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn jwt() -> String {
        "aGVhZGVy.cGF5bG9hZA.c2ln".to_owned()
    }

    #[test]
    fn jwt_shape_needs_three_non_empty_base64url_segments() {
        assert!(is_jwt_shaped(&jwt()));
        // base64url uses '-' and '_' where base64 uses '+' and '/'.
        assert!(is_jwt_shaped("a-b.c_d.e-_f"));
        assert!(is_jwt_shaped("-.-._"));
        for bad in [
            "", "a", "a.b", "a.b.", ".b.c", "a..c", "a.b.c.d", "a b.c.d", "a.b.c=", "a+b.c.d",
        ] {
            assert!(!is_jwt_shaped(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_restricted_function_needs_the_owner_or_a_jwt_shaped_bearer() {
        let bearer = format!("Bearer {}", jwt());
        let cases: [(&[String], bool, Decision); 8] = [
            (&[], false, Decision::Forbidden),
            (&[], true, Decision::Allow),
            (std::slice::from_ref(&bearer), false, Decision::Allow),
            (
                &["bearer not-a-jwt".to_owned()],
                false,
                Decision::Unauthenticated,
            ),
            (
                &["Basic dXNlcjpwYXNz".to_owned()],
                false,
                Decision::Forbidden,
            ),
            (
                &[bearer.clone(), bearer.clone()],
                false,
                Decision::Unauthenticated,
            ),
            (&["Bearer ".to_owned()], false, Decision::Unauthenticated),
            (&["Bearer not-a-jwt".to_owned()], true, Decision::Allow),
        ];
        for (authorization, owner, expected) in cases {
            assert_eq!(
                decide(Access::Restricted, owner, authorization),
                expected,
                "{authorization:?} owner={owner}"
            );
        }
    }

    #[test]
    fn the_forbidden_page_names_the_path_and_escapes_it() {
        let page = forbidden_page("/demo/us-central1/<fn>");
        assert!(page.contains("<title>403 Forbidden</title>"));
        assert!(page.contains("<code>/demo/us-central1/&lt;fn&gt;</code>"));
    }

    proptest! {
        /// A public function admits every request, whatever it carries.
        #[test]
        fn public_always_allows(owner in any::<bool>(), values in proptest::collection::vec(".{0,40}", 0..3)) {
            prop_assert_eq!(decide(Access::Public, owner, &values), Decision::Allow);
        }

        /// The owner credential admits a restricted function whatever else is sent.
        #[test]
        fn the_owner_always_allows(values in proptest::collection::vec(".{0,40}", 0..3)) {
            prop_assert_eq!(decide(Access::Restricted, true, &values), Decision::Allow);
        }

        /// Without the owner credential a restricted function is entered only through exactly one
        /// bearer field that is JWT-shaped; no field at all is 403 and everything else that
        /// names a bearer is 401.
        #[test]
        fn restricted_allows_only_one_jwt_bearer(
            scheme in "(?i:bearer)|Basic|Token",
            token in "[A-Za-z0-9_.=+-]{0,24}",
            repeat in 1usize..3,
        ) {
            let value = format!("{scheme} {token}");
            let values = vec![value; repeat];
            let decision = decide(Access::Restricted, false, &values);
            let bearer = scheme.eq_ignore_ascii_case("bearer");
            if repeat == 1 && bearer && is_jwt_shaped(token.trim()) {
                prop_assert_eq!(decision, Decision::Allow);
            } else {
                prop_assert_ne!(decision, Decision::Allow);
            }
            if repeat == 1 && !bearer {
                prop_assert_eq!(decision, Decision::Forbidden);
            }
        }
    }
}
