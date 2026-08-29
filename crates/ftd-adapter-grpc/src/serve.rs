//! One listener, two protocols: gRPC (HTTP/2, `application/grpc`) and the REST JSON API
//! (HTTP/1.1 or HTTP/2) share the Firestore port, as the official Emulator does.

use std::convert::Infallible;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::combinators::UnsyncBoxBody;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;
use tonic::codegen::Service;
use tonic::Status;

use crate::rest::{RestRequest, RestResponse, RestState};

/// Maximum accepted REST request body.
pub const MAX_REST_BODY_BYTES: usize = 10 * 1024 * 1024;

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type OutBody = UnsyncBoxBody<Bytes, BoxError>;

fn json_response(r: &RestResponse) -> Response<OutBody> {
    let text = serde_json::to_vec(&r.body).unwrap_or_default();
    Response::builder()
        .status(r.status)
        .header("content-type", "application/json; charset=utf-8")
        .body(
            Full::new(Bytes::from(text))
                .map_err(|e: Infallible| match e {})
                .boxed_unsync(),
        )
        .unwrap_or_else(|_| {
            Response::new(
                Full::new(Bytes::new())
                    .map_err(|e: Infallible| match e {})
                    .boxed_unsync(),
            )
        })
}

async fn rest_call(state: Arc<RestState>, req: Request<Incoming>) -> Response<OutBody> {
    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or("").to_owned();
    let authorization = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let collected = Limited::new(req.into_body(), MAX_REST_BODY_BYTES)
        .collect()
        .await;
    let body = match collected {
        Err(_) => {
            return json_response(&RestResponse {
                status: 413,
                body: serde_json::json!({"error": {"code": 413, "message": "request body too large", "status": "INVALID_ARGUMENT"}}),
            })
        }
        Ok(c) => {
            let bytes = c.to_bytes();
            if bytes.is_empty() {
                serde_json::Value::Object(serde_json::Map::new())
            } else {
                match serde_json::from_slice(&bytes) {
                    Ok(v) => v,
                    Err(e) => {
                        return json_response(&crate::rest::error_response(
                            &Status::invalid_argument(format!("invalid JSON body: {e}")),
                        ))
                    }
                }
            }
        }
    };
    let response = state.handle(&RestRequest {
        method,
        path,
        query,
        authorization,
        body,
    });
    json_response(&response)
}

fn is_grpc(req: &Request<Incoming>) -> bool {
    req.headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.starts_with("application/grpc"))
}

/// Serves gRPC and REST on `listener` until the task is aborted.
pub async fn serve_multiplexed<S>(
    listener: TcpListener,
    grpc: S,
    rest: Arc<RestState>,
) -> std::io::Result<()>
where
    S: Service<
            Request<tonic::body::Body>,
            Response = Response<tonic::body::Body>,
            Error = Infallible,
        > + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    loop {
        let (stream, _) = listener.accept().await?;
        let grpc = grpc.clone();
        let rest = rest.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<Incoming>| {
                let mut grpc = grpc.clone();
                let rest = rest.clone();
                async move {
                    if is_grpc(&req) {
                        let req = req.map(|b| {
                            tonic::body::Body::new(b.map_err(|e| Status::internal(e.to_string())))
                        });
                        let response = grpc.call(req).await?;
                        Ok::<_, Infallible>(
                            response.map(|b| b.map_err(|e| Box::new(e) as BoxError).boxed_unsync()),
                        )
                    } else {
                        Ok(rest_call(rest, req).await)
                    }
                }
            });
            // Connection errors are per-client; the accept loop keeps running.
            let _ = auto::Builder::new(TokioExecutor::new())
                .serve_connection(io, svc)
                .await;
        });
    }
}
