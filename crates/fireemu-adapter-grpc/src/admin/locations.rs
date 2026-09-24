//! `projects/{p}/locations`: the Firestore location catalog (scope decision C3).
//!
//! The catalog is production's own list, observed on the date the snapshot names; a location
//! production adds later is a recorded difference until the snapshot is refreshed.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde_json::{json, Value};

use crate::rest::RestResponse;

const SNAPSHOT: &str = include_str!("locations.json");

struct Location {
    id: String,
    display_name: String,
    labels: Value,
}

fn catalog() -> &'static [Location] {
    static CATALOG: OnceLock<Vec<Location>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let snapshot: Value = serde_json::from_str(SNAPSHOT).unwrap_or(Value::Null);
        snapshot["locations"]
            .as_array()
            .map(|all| {
                all.iter()
                    .map(|l| Location {
                        id: l["locationId"].as_str().unwrap_or_default().to_owned(),
                        display_name: l["displayName"].as_str().unwrap_or_default().to_owned(),
                        labels: l["labels"].clone(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    })
}

/// Whether production offers a Firestore database in `location`.
#[must_use]
pub fn exists(location: &str) -> bool {
    catalog().iter().any(|l| l.id == location)
}

fn resource(project: &str, location: &Location) -> Value {
    json!({
        "name": format!("projects/{project}/locations/{}", location.id),
        "labels": location.labels,
        "metadata": {"@type": "type.googleapis.com/google.firestore.admin.v1.LocationMetadata"},
        "locationId": location.id,
        "displayName": location.display_name,
    })
}

pub(crate) fn list(project: &str, _params: &BTreeMap<String, Vec<String>>) -> RestResponse {
    let locations: Vec<Value> = catalog().iter().map(|l| resource(project, l)).collect();
    RestResponse {
        status: 200,
        body: json!({ "locations": locations }),
    }
}

pub(crate) fn get(project: &str, location: &str) -> RestResponse {
    match catalog().iter().find(|l| l.id == location) {
        Some(found) => RestResponse {
            status: 200,
            body: resource(project, found),
        },
        None => super::rest::error(
            tonic::Code::NotFound,
            "Requested entity was not found.",
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_snapshot_parses_and_knows_the_sandbox_locations() {
        assert!(super::catalog().len() >= 40);
        assert!(super::exists("us-central1"));
        assert!(super::exists("nam5"));
        assert!(!super::exists("nowhere-1"));
    }
}
