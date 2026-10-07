//! Authentication admission for the loopback endpoint; see docs/pubsub-authentication.md.

use axum::body::Body;
use axum::extract::State;
use axum::http::{header::AUTHORIZATION, HeaderMap, Request, Uri};
use axum::middleware::Next;
use axum::response::Response;

use crate::PagingPolicy;

pub(crate) const INVALID_CREDENTIAL_MESSAGE: &str = "Request had invalid authentication credentials. Expected OAuth 2 access token, login cookie or other valid authentication credential. See https://developers.google.com/identity/sign-in/web/devconsole-project.";

fn credential_rejected(policy: PagingPolicy, headers: &HeaderMap, uri: &Uri) -> bool {
    // There is no trusted Google OAuth verifier. A present credential is unsupported,
    // including empty, duplicated and undecodable values; it is never anonymous.
    policy == PagingPolicy::Strict
        && (headers.contains_key(AUTHORIZATION)
            || headers.contains_key("x-goog-api-key")
            || uri.query().is_some_and(|query| {
                query.split('&').any(|pair| {
                    let name = pair.split_once('=').map_or(pair, |(name, _)| name);
                    crate::rest::decode_query(name)
                        .is_ok_and(|name| matches!(name.as_str(), "access_token" | "key"))
                })
            }))
}

pub(crate) async fn authenticate(
    State(policy): State<PagingPolicy>,
    request: Request<Body>,
    next: Next,
) -> Response {
    if credential_rejected(policy, request.headers(), request.uri()) {
        if native_request(request.uri().path()) {
            return tonic::Status::unauthenticated(INVALID_CREDENTIAL_MESSAGE).into_http::<Body>();
        }
        return crate::rest::unauthenticated(request.method(), request.uri().path(), policy);
    }
    next.run(request).await
}

fn native_request(path: &str) -> bool {
    path.starts_with("/google.pubsub.v1.Publisher/")
        || path.starts_with("/google.pubsub.v1.Subscriber/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn local_verification_matches_absent_header_reference(
            values in prop::collection::vec(prop::collection::vec(0x20u8..=0xff, 0..80), 0..5),
            unrelated in prop::collection::vec("[a-z0-9]{0,30}", 0..5),
        ) {
            let mut headers = HeaderMap::new();
            for value in &unrelated {
                headers.append("x-unrelated", HeaderValue::from_str(value).unwrap());
            }
            for value in &values {
                let value = value.iter().copied().filter(|byte| *byte != 0x7f).collect::<Vec<_>>();
                headers.append(AUTHORIZATION, HeaderValue::from_bytes(&value).unwrap());
            }
            prop_assert_eq!(credential_rejected(PagingPolicy::Strict, &headers, &Uri::from_static("/")), !values.is_empty());
            prop_assert!(!credential_rejected(PagingPolicy::Emulator, &headers, &Uri::from_static("/")));
        }

        #[test]
        fn credential_carriers_match_presence_reference(
            carrier in 0usize..12, value in "[a-zA-Z0-9%+._-]{0,32}", api_key in any::<bool>(),
        ) {
            let names = ["access_token", "key", "%61ccess_token", "%6bey", "access%5ftoken", "Access_token", "Key", "access-token", "key_suffix", "api_key", "access+token", "%ff"];
            let uri: Uri = format!("/v1/projects/demo-app/topics/t?unrelated={value}&{}={value}", names[carrier]).parse().unwrap();
            let mut headers = HeaderMap::new();
            if api_key { headers.append("X-Goog-Api-Key", HeaderValue::from_static("")); }
            prop_assert_eq!(credential_rejected(PagingPolicy::Strict, &headers, &uri), api_key || carrier < 5);
            prop_assert!(!credential_rejected(PagingPolicy::Emulator, &headers, &uri));
        }

        #[test]
        fn native_routing_uses_service_path_not_payload_or_similar_prefix(
            method in "[A-Za-z]{1,32}", prefix in "[a-z]{1,20}",
        ) {
            prop_assert!(native_request(&format!("/google.pubsub.v1.Publisher/{method}")), "native Publisher path");
            prop_assert!(native_request(&format!("/google.pubsub.v1.Subscriber/{method}")), "native Subscriber path");
            prop_assert!(!native_request(&format!("/{prefix}/google.pubsub.v1.Publisher/{method}")), "prefixed path");
            prop_assert!(!native_request(&format!("/google.pubsub.v1.Publisher{method}")), "missing separator");
            prop_assert!(!native_request(&format!("/v1/projects/{prefix}/topics/{method}")), "REST path");
        }
    }
}
