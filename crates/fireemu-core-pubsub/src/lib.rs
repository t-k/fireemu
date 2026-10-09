//! std-only Cloud Pub/Sub emulator state machine.
//!
//! This crate owns the topic/subscription/message domain of the Pub/Sub emulator: resource
//! name validation, message validation, subscription filters, the per-subscription delivery
//! state machine (ack deadlines, redelivery, ordering keys, dead-letter forwarding, seek) and
//! the registry that routes a publish to every matching subscription. It reproduces the
//! documented subset of the official Google Cloud Pub/Sub emulator. Strict mode additionally enforces finite resource-local IAM for dead-letter forwarding. Multi-day wall-clock expiration and `BigQuery` delivery remain outside this subset.
//!
//! The crate is std-only (ADR-001): it takes no external dependencies beyond
//! [`fireemu_core_types`]. It reads no clock and opens no sockets — every time-dependent
//! operation takes an explicit [`fireemu_core_types::time::LogicalInstant`], and identifiers
//! come from the daemon seed, so redelivery timing and message / ack ids are reproducible on
//! the virtual clock and `await-idle` stays deterministic. The HTTP/gRPC surface lives in the
//! `fireemu-adapter-pubsub` crate, mirroring the Firestore and Storage core/adapter split.

pub mod configuration;
pub mod error;
pub mod filter;
pub mod iam;
pub mod message;
pub mod name;
pub mod pagination;
pub mod state;
pub mod subscription;

pub use error::{Code, PubSubError, Result};
pub use filter::Filter;
pub use fireemu_core_types::pubsub_message_id::{
    pubsub_message_id, BROKER_SPAN as MESSAGE_ID_SPAN,
};
pub use iam::{PolicyBinding, ResourcePolicy};
pub use message::{PubsubMessage, StoredMessage};
pub use name::{SubscriptionName, TopicName};
pub use state::{DeadLetterForward, PreparedPublication, PubSubState, PullResult, Snapshot};
pub use subscription::{
    DeadLetterPolicy, ExpirationPolicy, PushConfig, ReceivedMessage, RetryPolicy,
    SubscriptionConfig, SubscriptionState, SubscriptionUpdate,
};
