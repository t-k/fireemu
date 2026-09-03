//! Streaming request-body collection with a caller-supplied byte limit.

use std::error::Error;
use std::fmt;

use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, LengthLimitError, Limited};

/// A bounded body could not be collected.
///
/// The error intentionally retains neither the body error nor any body bytes. Product adapters
/// map the category to their existing response contract without risking request-data disclosure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CollectBodyError {
    /// More than the caller's declared byte limit arrived.
    TooLarge,
    /// The transport failed before the body completed.
    Read,
}

impl fmt::Display for CollectBodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("request body exceeds its byte limit"),
            Self::Read => f.write_str("request body could not be read"),
        }
    }
}

impl Error for CollectBodyError {}

/// Collects `body` while enforcing `limit` as bytes arrive.
///
/// A chunked body is accepted when its cumulative data length fits. Trailers consume no data
/// budget. The returned error carries no transport details or request bytes.
pub async fn collect_limited<B>(body: B, limit: usize) -> Result<Bytes, CollectBodyError>
where
    B: Body<Data = Bytes>,
    B::Error: Into<Box<dyn Error + Send + Sync>>,
{
    Limited::new(body, limit)
        .collect()
        .await
        .map(http_body_util::Collected::to_bytes)
        .map_err(|error| {
            if error.downcast_ref::<LengthLimitError>().is_some() {
                CollectBodyError::TooLarge
            } else {
                CollectBodyError::Read
            }
        })
}

#[cfg(test)]
mod tests {
    use std::io;

    use http_body::Frame;
    use http_body_util::{Full, StreamBody};

    use super::{collect_limited, CollectBodyError};

    #[tokio::test]
    async fn byte_limit_accepts_both_boundaries_and_rejects_the_next_byte() {
        assert_eq!(
            collect_limited(Full::new(bytes::Bytes::from_static(b"123")), 4)
                .await
                .unwrap(),
            "123"
        );
        assert_eq!(
            collect_limited(Full::new(bytes::Bytes::from_static(b"1234")), 4)
                .await
                .unwrap(),
            "1234"
        );
        assert_eq!(
            collect_limited(Full::new(bytes::Bytes::from_static(b"12345")), 4).await,
            Err(CollectBodyError::TooLarge)
        );
    }

    #[tokio::test]
    async fn chunked_data_and_trailers_share_the_same_bounded_contract() {
        let frames: Vec<Result<Frame<bytes::Bytes>, io::Error>> = vec![
            Ok(Frame::data(bytes::Bytes::from_static(b"12"))),
            Ok(Frame::trailers(http::HeaderMap::from_iter([(
                http::header::SERVER,
                http::HeaderValue::from_static("test"),
            )]))),
            Ok(Frame::data(bytes::Bytes::from_static(b"34"))),
        ];
        let body = StreamBody::new(tokio_stream::iter(frames));
        assert_eq!(collect_limited(body, 4).await.unwrap(), "1234");
    }

    #[tokio::test]
    async fn transport_errors_are_classified_without_retaining_their_message() {
        let sentinel = "private-body-error-sentinel";
        let frames = vec![Err::<Frame<bytes::Bytes>, _>(io::Error::other(sentinel))];
        let error = collect_limited(StreamBody::new(tokio_stream::iter(frames)), 4)
            .await
            .unwrap_err();
        assert_eq!(error, CollectBodyError::Read);
        assert!(!format!("{error:?} {error}").contains(sentinel));
    }
}
