//! Bounded loopback push delivery for Pub/Sub subscriptions.
//!
//! The official emulator accepts push configuration and sends ordinary HTTP POST requests. The
//! local emulator keeps the same acknowledgement boundary while restricting endpoints to the
//! loopback interface so a test fixture cannot turn a local publish into an arbitrary outbound
//! request.

use std::fmt::Write as _;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use fireemu_core_pubsub::{ReceivedMessage, SubscriptionName};

const PUSH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone)]
struct Endpoint {
    host: String,
    port: u16,
    authority: String,
    path: String,
}

fn parse_endpoint(value: &str) -> Result<Endpoint, String> {
    let rest = value
        .strip_prefix("http://")
        .ok_or_else(|| "push endpoint must use http://".to_owned())?;
    if rest.is_empty()
        || rest
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n' | b' ' | b'\t'))
    {
        return Err("push endpoint is malformed".to_owned());
    }
    let (authority, path) = rest
        .split_once('/')
        .map_or((rest, String::from("/")), |(host, path)| {
            (host, format!("/{path}"))
        });
    if authority.is_empty() || authority.contains('@') || path.contains('#') {
        return Err("push endpoint is malformed".to_owned());
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let end = bracketed
            .find(']')
            .ok_or_else(|| "push endpoint has an invalid IPv6 host".to_owned())?;
        let host = &bracketed[..end];
        let suffix = &bracketed[end + 1..];
        let port = suffix.strip_prefix(':').map_or(Ok(80), |port| {
            port.parse::<u16>()
                .map_err(|_| "push endpoint has an invalid port".to_owned())
        })?;
        (host, port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Err("IPv6 push endpoints must use brackets".to_owned());
        }
        (
            host,
            port.parse::<u16>()
                .map_err(|_| "push endpoint has an invalid port".to_owned())?,
        )
    } else {
        (authority, 80)
    };
    if !matches!(host, "127.0.0.1" | "localhost" | "::1") {
        return Err("push endpoint must resolve to loopback".to_owned());
    }
    Ok(Endpoint {
        host: host.to_owned(),
        port,
        authority: authority.to_owned(),
        path,
    })
}

pub(crate) fn validate_endpoint(value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Ok(());
    }
    parse_endpoint(value).map(|_| ())
}

pub(crate) async fn deliver(
    endpoint: &str,
    subscription: &SubscriptionName,
    received: &ReceivedMessage,
) -> Result<(), String> {
    let endpoint = parse_endpoint(endpoint)?;
    let body = push_body(subscription, received);
    tokio::task::spawn_blocking(move || deliver_blocking(&endpoint, &body))
        .await
        .map_err(|error| format!("push worker failed: {error}"))?
}

fn deliver_blocking(endpoint: &Endpoint, body: &str) -> Result<(), String> {
    let address = (endpoint.host.as_str(), endpoint.port);
    let stream = TcpStream::connect_timeout(
        &address
            .to_socket_addrs()
            .map_err(|error| format!("push endpoint lookup failed: {error}"))?
            .next()
            .ok_or_else(|| "push endpoint has no address".to_owned())?,
        PUSH_TIMEOUT,
    )
    .map_err(|error| format!("push endpoint connection failed: {error}"))?;
    stream
        .set_read_timeout(Some(PUSH_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(PUSH_TIMEOUT)))
        .map_err(|error| format!("push endpoint timeout setup failed: {error}"))?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        endpoint.path,
        endpoint.authority,
        body.len(),
        body
    );
    let mut stream = stream;
    stream
        .write_all(request.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|error| format!("push endpoint write failed: {error}"))?;
    let mut response = Vec::new();
    stream
        .take((MAX_RESPONSE_BYTES + 1) as u64)
        .read_to_end(&mut response)
        .map_err(|error| format!("push endpoint read failed: {error}"))?;
    if response.len() > MAX_RESPONSE_BYTES {
        return Err("push endpoint response is too large".to_owned());
    }
    let line = response
        .split(|byte| *byte == b'\n')
        .next()
        .and_then(|line| std::str::from_utf8(line).ok())
        .ok_or_else(|| "push endpoint returned an invalid response".to_owned())?;
    let status = line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| "push endpoint returned an invalid status".to_owned())?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(format!("push endpoint returned HTTP {status}"))
    }
}

fn push_body(subscription: &SubscriptionName, received: &ReceivedMessage) -> String {
    let stored = &received.message;
    let mut attributes = String::from("{");
    for (index, (key, value)) in stored.message.attributes.iter().enumerate() {
        if index > 0 {
            attributes.push(',');
        }
        attributes.push('"');
        json_escape_into(&mut attributes, key);
        attributes.push_str("\":\"");
        json_escape_into(&mut attributes, value);
        attributes.push('"');
    }
    attributes.push('}');
    let publish_time = stored
        .publish_time
        .to_rfc3339()
        .unwrap_or_else(|_| stored.publish_time.to_string());
    let ordering_key = if stored.message.ordering_key.is_empty() {
        String::new()
    } else {
        format!(
            ",\"orderingKey\":\"{}\"",
            json_escape(&stored.message.ordering_key)
        )
    };
    format!(
        "{{\"message\":{{\"data\":\"{}\",\"messageId\":\"{}\",\"publishTime\":\"{}\",\"attributes\":{}{}}},\"subscription\":\"{}\"}}",
        base64(&stored.message.data),
        json_escape(&stored.message_id),
        json_escape(&publish_time),
        attributes,
        ordering_key,
        json_escape(&subscription.to_full()),
    )
}

fn json_escape(value: &str) -> String {
    let mut output = String::new();
    json_escape_into(&mut output, value);
    output
}

fn json_escape_into(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                let _ = write!(output, "\\u{:04x}", character as u32);
            }
            character => output.push(character),
        }
    }
}

fn base64(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or(0);
        let third = chunk.get(2).copied().unwrap_or(0);
        output.push(TABLE[usize::from(first >> 2)] as char);
        output.push(TABLE[usize::from(((first & 0x03) << 4) | (second >> 4))] as char);
        output.push(if chunk.len() > 1 {
            TABLE[usize::from(((second & 0x0f) << 2) | (third >> 6))] as char
        } else {
            '='
        });
        output.push(if chunk.len() > 2 {
            TABLE[usize::from(third & 0x3f)] as char
        } else {
            '='
        });
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{base64, parse_endpoint, push_body};
    use fireemu_core_pubsub::{PubsubMessage, ReceivedMessage, StoredMessage, SubscriptionName};
    use fireemu_core_types::time::LogicalInstant;
    use std::sync::Arc;

    #[test]
    fn endpoint_validation_is_loopback_only_and_does_not_follow_redirects() {
        assert!(parse_endpoint("http://127.0.0.1:8080/push").is_ok());
        assert!(parse_endpoint("http://localhost/push").is_ok());
        assert!(parse_endpoint("https://127.0.0.1:8080/push").is_err());
        assert!(parse_endpoint("http://169.254.169.254/latest").is_err());
        assert!(parse_endpoint("http://127.0.0.1:8080/a#redirect").is_err());
    }

    #[test]
    fn push_body_uses_pubsub_base64_and_subscription_shape() {
        let subscription = SubscriptionName::new("demo-app", "push").unwrap();
        let received = ReceivedMessage {
            ack_id: "ack".to_owned(),
            message: Arc::new(StoredMessage {
                message_id: "7".to_owned(),
                publish_time: LogicalInstant::from_unix_seconds(1_700_000_000),
                message: PubsubMessage {
                    data: b"hello".to_vec(),
                    ..Default::default()
                },
            }),
            delivery_attempt: 1,
        };
        let body = push_body(&subscription, &received);
        assert!(body.contains("\"data\":\"aGVsbG8=\""));
        assert!(body.contains("projects/demo-app/subscriptions/push"));
        assert_eq!(base64(b""), "");
    }
}
