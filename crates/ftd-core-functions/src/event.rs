//! `CloudEvents` attributes of the events firebase-testd delivers (the payload JSON is built
//! by the runtime shell from the document / object it already encodes for the APIs).

use crate::manifest::{DocumentEvent, ObjectEvent};

/// `CloudEvents` context attributes (spec version 1.0) with the extensions the Firebase SDKs
/// read (`document`, `database`, `namespace`, `project`, `location`, `bucket`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventAttributes {
    /// `type`.
    pub event_type: String,
    /// `source`.
    pub source: String,
    /// `subject`.
    pub subject: Option<String>,
    /// Extension attributes in the order they are emitted.
    pub extensions: Vec<(String, String)>,
}

/// Attributes of a Firestore document event.
#[must_use]
pub fn firestore_attributes(
    project: &str,
    database: &str,
    document_path: &str,
    kind: DocumentEvent,
    location: &str,
) -> EventAttributes {
    EventAttributes {
        event_type: kind.event_type().to_owned(),
        source: format!("//firestore.googleapis.com/projects/{project}/databases/{database}"),
        subject: Some(format!("documents/{document_path}")),
        extensions: vec![
            ("project".into(), project.to_owned()),
            ("database".into(), database.to_owned()),
            ("namespace".into(), "(default)".into()),
            ("document".into(), document_path.to_owned()),
            ("location".into(), location.to_owned()),
        ],
    }
}

/// Attributes of a Storage object event.
#[must_use]
pub fn storage_attributes(bucket: &str, object_name: &str, kind: ObjectEvent) -> EventAttributes {
    EventAttributes {
        event_type: kind.event_type().to_owned(),
        source: format!("//storage.googleapis.com/projects/_/buckets/{bucket}"),
        subject: Some(format!("objects/{object_name}")),
        extensions: vec![("bucket".into(), bucket.to_owned())],
    }
}

/// Attributes of a scheduled run.
#[must_use]
pub fn schedule_attributes(project: &str, region: &str, function: &str) -> EventAttributes {
    EventAttributes {
        event_type: "google.cloud.scheduler.job.v1.executed".to_owned(),
        source: format!("//cloudscheduler.googleapis.com/projects/{project}/locations/{region}/jobs/firebase-schedule-{function}-{region}"),
        subject: None,
        extensions: Vec::new(),
    }
}
