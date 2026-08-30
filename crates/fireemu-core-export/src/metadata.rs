//! `firebase-export-metadata.json`: the manifest at the root of an export directory.
//!
//! The pinned shape is the one `firebase-tools@15.28.2` writes in
//! `src/emulator/hubExport.ts`: a `version` naming the CLI that wrote the export and one
//! optional section per product, each with the CLI or emulator `version` that produced it
//! and a `path` relative to the directory. Firestore additionally names its
//! `metadata_file`, because the Firestore emulator is handed that file rather than the
//! directory.
//!
//! ```json
//! {
//!   "version": "15.28.2",
//!   "firestore": {
//!     "version": "1.22.0",
//!     "path": "firestore_export",
//!     "metadata_file": "firestore_export/firestore_export.overall_export_metadata"
//!   },
//!   "auth": { "version": "15.28.2", "path": "auth_export" },
//!   "storage": { "version": "15.28.2", "path": "storage_export" }
//! }
//! ```
//!
//! A section fireemu does not serve is not silently dropped: [`ExportMetadata::parse`] keeps
//! every recognized section, and the caller decides what a Realtime Database or SQL Connect
//! section means for the run (`fireemu` refuses the run rather than importing part of it).

use fireemu_core_types::json::{parse, JsonValue};

use crate::json::Json;

/// The manifest file name, as upstream `HubExport.METADATA_FILE_NAME`.
pub const METADATA_FILE_NAME: &str = "firebase-export-metadata.json";

/// The directory name each product's section uses by default.
pub const FIRESTORE_PATH: &str = "firestore_export";
/// The Auth section's default directory name.
pub const AUTH_PATH: &str = "auth_export";
/// The Storage section's default directory name.
pub const STORAGE_PATH: &str = "storage_export";
/// The Realtime Database section's directory name (fireemu never writes one).
pub const DATABASE_PATH: &str = "database_export";
/// The SQL Connect section's directory name (fireemu never writes one).
pub const DATACONNECT_PATH: &str = "dataconnect_export";

/// The file the Firestore section points its `metadata_file` at, inside `path`.
pub const FIRESTORE_OVERALL_METADATA: &str = "firestore_export.overall_export_metadata";

/// Every product an official export can carry a section for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Product {
    /// Cloud Firestore.
    Firestore,
    /// Firebase Authentication.
    Auth,
    /// Cloud Storage for Firebase.
    Storage,
    /// Realtime Database: a deferred product fireemu does not serve.
    Database,
    /// SQL Connect (Data Connect): a deferred product fireemu does not serve.
    DataConnect,
}

impl Product {
    /// The manifest key of the product.
    #[must_use]
    pub fn key(self) -> &'static str {
        match self {
            Self::Firestore => "firestore",
            Self::Auth => "auth",
            Self::Storage => "storage",
            Self::Database => "database",
            Self::DataConnect => "dataconnect",
        }
    }

    /// The name the product is known by on the command line and in `--only`.
    #[must_use]
    pub fn cli_name(self) -> &'static str {
        match self {
            Self::Firestore => "firestore",
            Self::Auth => "auth",
            Self::Storage => "storage",
            Self::Database => "database (Realtime Database)",
            Self::DataConnect => "dataconnect (SQL Connect)",
        }
    }

    /// Whether fireemu can import and export this product's section.
    #[must_use]
    pub fn is_served(self) -> bool {
        matches!(self, Self::Firestore | Self::Auth | Self::Storage)
    }

    /// Every product, in the order the official CLI writes them.
    #[must_use]
    pub fn all() -> [Product; 5] {
        [
            Self::Firestore,
            Self::Database,
            Self::Auth,
            Self::Storage,
            Self::DataConnect,
        ]
    }
}

/// One product's section of the manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Section {
    /// The emulator or CLI version that wrote the section.
    pub version: String,
    /// The section directory, relative to the export directory.
    pub path: String,
    /// Firestore only: the overall export metadata file, relative to the export directory.
    pub metadata_file: Option<String>,
}

/// The manifest member fireemu writes its own extension sections under.
///
/// The official CLI reads only the members it knows (`hubExport.ts` picks
/// `metadata.firestore`, `metadata.auth`, ... by name), so an extra member is carried
/// through an official import and export untouched. fireemu uses exactly one: the Firestore
/// databases other than `(default)`, which the official managed export has no place for --
/// its request is hard-coded to `projects/{p}/databases/(default)`. Writing them into the
/// official `firestore_export` section would produce a directory the official emulator
/// silently mis-imports; writing them here means the official suite reads the default
/// database and fireemu reads all of them.
pub const EXTENSION_KEY: &str = "fireemu";

/// The extension sections, keyed by database id.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Extension {
    /// The fireemu version that wrote them.
    pub version: String,
    /// One Firestore section per named database, in database order.
    pub firestore_databases: Vec<(String, Section)>,
}

/// The parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExportMetadata {
    /// The `version` member: the CLI version that wrote the export.
    pub version: String,
    /// The sections present, in product order.
    pub sections: Vec<(Product, Section)>,
    /// fireemu's own sections, when the export carries any.
    pub extension: Option<Extension>,
}

/// Why a manifest was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataError(pub String);

impl core::fmt::Display for MetadataError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for MetadataError {}

impl ExportMetadata {
    /// A manifest written by `version` with no sections yet.
    #[must_use]
    pub fn new(version: impl Into<String>) -> Self {
        Self {
            version: version.into(),
            sections: Vec::new(),
            extension: None,
        }
    }

    /// Adds a Firestore section for a database other than `(default)`.
    pub fn set_named_database(
        &mut self,
        fireemu_version: &str,
        database: impl Into<String>,
        section: Section,
    ) {
        let extension = self.extension.get_or_insert_with(|| Extension {
            version: fireemu_version.to_owned(),
            firestore_databases: Vec::new(),
        });
        let database = database.into();
        extension.firestore_databases.retain(|(d, _)| *d != database);
        extension.firestore_databases.push((database, section));
        extension.firestore_databases.sort_by(|a, b| a.0.cmp(&b.0));
    }

    /// The Firestore sections of the databases other than `(default)`.
    #[must_use]
    pub fn named_databases(&self) -> &[(String, Section)] {
        self.extension
            .as_ref()
            .map_or(&[], |e| e.firestore_databases.as_slice())
    }

    /// Adds or replaces a product's section, keeping the official product order.
    pub fn set(&mut self, product: Product, section: Section) {
        self.sections.retain(|(p, _)| *p != product);
        self.sections.push((product, section));
        let order = Product::all();
        self.sections
            .sort_by_key(|(p, _)| order.iter().position(|o| o == p).unwrap_or(usize::MAX));
    }

    /// The section of `product`, when the manifest has one.
    #[must_use]
    pub fn section(&self, product: Product) -> Option<&Section> {
        self.sections
            .iter()
            .find(|(p, _)| *p == product)
            .map(|(_, s)| s)
    }

    /// Every section of a product fireemu does not serve.
    #[must_use]
    pub fn deferred(&self) -> Vec<Product> {
        self.sections
            .iter()
            .map(|(p, _)| *p)
            .filter(|p| !p.is_served())
            .collect()
    }

    /// Parses `firebase-export-metadata.json`.
    pub fn parse(text: &str) -> Result<Self, MetadataError> {
        let value = parse(text).map_err(|e| MetadataError(e.to_string()))?;
        let JsonValue::Object(_) = &value else {
            return Err(MetadataError(
                "the export manifest is not a JSON object".to_owned(),
            ));
        };
        let version = value
            .get("version")
            .and_then(JsonValue::as_str)
            .ok_or_else(|| {
                MetadataError("the export manifest has no string \"version\"".to_owned())
            })?
            .to_owned();
        let mut metadata = Self::new(version);
        for product in Product::all() {
            let Some(section) = value.get(product.key()) else {
                continue;
            };
            metadata.set(product, parse_section(product, section)?);
        }
        if let Some(extension) = value.get(EXTENSION_KEY) {
            if !matches!(extension, JsonValue::Object(_)) {
                return Err(MetadataError(format!(
                    "the {EXTENSION_KEY} section of the export manifest is not an object"
                )));
            }
            let mut databases = Vec::new();
            if let Some(JsonValue::Array(items)) = extension.get("firestoreDatabases") {
                for item in items {
                    let database = item
                        .get("database")
                        .and_then(JsonValue::as_str)
                        .ok_or_else(|| {
                            MetadataError(format!(
                                "a {EXTENSION_KEY}.firestoreDatabases entry has no string \"database\""
                            ))
                        })?
                        .to_owned();
                    if database.is_empty() || database == "(default)" {
                        return Err(MetadataError(format!(
                            "the {EXTENSION_KEY} section names the database {database:?}, which belongs in the official firestore section"
                        )));
                    }
                    databases.push((database, parse_section(Product::Firestore, item)?));
                }
            }
            metadata.extension = Some(Extension {
                version: extension
                    .get("version")
                    .and_then(JsonValue::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                firestore_databases: databases,
            });
        }
        Ok(metadata)
    }

    /// The manifest as the text an export directory holds.
    #[must_use]
    pub fn to_json(&self) -> String {
        let mut doc = Json::object();
        doc.insert("version", Json::string(&self.version));
        for (product, section) in &self.sections {
            let mut node = Json::object();
            node.insert("version", Json::string(&section.version));
            node.insert("path", Json::string(&section.path));
            node.insert_some(
                "metadata_file",
                section.metadata_file.as_ref().map(Json::string),
            );
            doc.insert(product.key(), node);
        }
        if let Some(extension) = &self.extension {
            if !extension.firestore_databases.is_empty() {
                let mut node = Json::object();
                node.insert("version", Json::string(&extension.version));
                node.insert(
                    "firestoreDatabases",
                    Json::Array(
                        extension
                            .firestore_databases
                            .iter()
                            .map(|(database, section)| {
                                let mut entry = Json::object();
                                entry.insert("database", Json::string(database));
                                entry.insert("path", Json::string(&section.path));
                                entry.insert_some(
                                    "metadata_file",
                                    section.metadata_file.as_ref().map(Json::string),
                                );
                                entry
                            })
                            .collect(),
                    ),
                );
                doc.insert(EXTENSION_KEY, node);
            }
        }
        doc.to_pretty()
    }
}

fn parse_section(product: Product, value: &JsonValue) -> Result<Section, MetadataError> {
    let JsonValue::Object(_) = value else {
        return Err(MetadataError(format!(
            "the {} section of the export manifest is not an object",
            product.key()
        )));
    };
    let path = value
        .get("path")
        .and_then(JsonValue::as_str)
        .ok_or_else(|| {
            MetadataError(format!(
                "the {} section of the export manifest has no string \"path\"",
                product.key()
            ))
        })?
        .to_owned();
    if path.is_empty() || path.starts_with('/') || path.split('/').any(|part| part == "..") {
        return Err(MetadataError(format!(
            "the {} section of the export manifest names the path {path:?}, which is not inside the export directory",
            product.key()
        )));
    }
    let version = value
        .get("version")
        .and_then(JsonValue::as_str)
        .unwrap_or_default()
        .to_owned();
    let metadata_file = match value.get("metadata_file") {
        Some(JsonValue::String(s)) => {
            if s.starts_with('/') || s.split('/').any(|part| part == "..") {
                return Err(MetadataError(format!(
                    "the {} section of the export manifest names the metadata file {s:?}, which is not inside the export directory",
                    product.key()
                )));
            }
            Some(s.clone())
        }
        Some(_) => {
            return Err(MetadataError(format!(
                "the {} section of the export manifest has a non-string \"metadata_file\"",
                product.key()
            )))
        }
        None => None,
    };
    Ok(Section {
        version,
        path,
        metadata_file,
    })
}

#[cfg(test)]
mod tests {
    use super::{ExportMetadata, Product, Section};

    /// The manifest of the recorded official fixture, verbatim.
    const OFFICIAL: &str = r#"{
  "version": "15.28.2",
  "firestore": {
    "version": "1.22.0",
    "path": "firestore_export",
    "metadata_file": "firestore_export/firestore_export.overall_export_metadata"
  },
  "auth": {
    "version": "15.28.2",
    "path": "auth_export"
  },
  "storage": {
    "version": "15.28.2",
    "path": "storage_export"
  }
}"#;

    #[test]
    fn the_recorded_official_manifest_parses_into_its_three_sections() {
        let parsed = ExportMetadata::parse(OFFICIAL).expect("the official manifest parses");
        assert_eq!(parsed.version, "15.28.2");
        let firestore = parsed
            .section(Product::Firestore)
            .expect("a firestore section");
        assert_eq!(firestore.path, "firestore_export");
        assert_eq!(
            firestore.metadata_file.as_deref(),
            Some("firestore_export/firestore_export.overall_export_metadata")
        );
        assert_eq!(firestore.version, "1.22.0");
        assert_eq!(
            parsed.section(Product::Auth).map(|s| s.path.as_str()),
            Some("auth_export")
        );
        assert_eq!(
            parsed.section(Product::Storage).map(|s| s.path.as_str()),
            Some("storage_export")
        );
        assert!(parsed.section(Product::Database).is_none());
        assert!(parsed.deferred().is_empty());
    }

    #[test]
    fn a_manifest_fireemu_writes_reparses_identically() {
        let parsed = ExportMetadata::parse(OFFICIAL).expect("the official manifest parses");
        let again = ExportMetadata::parse(&parsed.to_json()).expect("the written manifest parses");
        assert_eq!(parsed, again);
    }

    #[test]
    fn a_realtime_database_section_is_reported_as_deferred() {
        let text =
            r#"{"version":"15.28.2","database":{"version":"4.11.2","path":"database_export"}}"#;
        let parsed = ExportMetadata::parse(text).expect("the manifest parses");
        assert_eq!(parsed.deferred(), vec![Product::Database]);
    }

    #[test]
    fn a_data_connect_section_is_reported_as_deferred() {
        let text = r#"{"version":"15.28.2","dataconnect":{"version":"15.28.2","path":"dataconnect_export"}}"#;
        let parsed = ExportMetadata::parse(text).expect("the manifest parses");
        assert_eq!(parsed.deferred(), vec![Product::DataConnect]);
    }

    #[test]
    fn a_manifest_without_a_version_is_refused() {
        assert!(ExportMetadata::parse(r#"{"auth":{"path":"auth_export"}}"#).is_err());
    }

    #[test]
    fn a_section_without_a_path_is_refused() {
        assert!(ExportMetadata::parse(r#"{"version":"1","auth":{"version":"1"}}"#).is_err());
    }

    #[test]
    fn a_section_that_escapes_the_export_directory_is_refused() {
        for path in ["/etc", "../outside", "auth_export/../.."] {
            let text = format!(r#"{{"version":"1","auth":{{"path":"{path}"}}}}"#);
            assert!(
                ExportMetadata::parse(&text).is_err(),
                "the path {path:?} must be refused"
            );
        }
    }

    #[test]
    fn a_manifest_that_is_not_json_is_refused_with_its_offset() {
        assert!(ExportMetadata::parse("{\"version\": ").is_err());
        assert!(ExportMetadata::parse("[]").is_err());
    }

    #[test]
    fn a_named_database_section_round_trips_under_the_fireemu_extension() {
        let mut metadata = ExportMetadata::new("15.28.2");
        metadata.set(
            Product::Firestore,
            Section {
                version: "1.22.0".to_owned(),
                path: "firestore_export".to_owned(),
                metadata_file: Some("firestore_export/x".to_owned()),
            },
        );
        metadata.set_named_database(
            "0.1.0",
            "analytics",
            Section {
                version: "0.1.0".to_owned(),
                path: "firestore_export_analytics".to_owned(),
                metadata_file: Some("firestore_export_analytics/x".to_owned()),
            },
        );
        let text = metadata.to_json();
        assert!(text.contains("\"fireemu\""));
        let again = ExportMetadata::parse(&text).expect("the written manifest parses");
        assert_eq!(again.named_databases().len(), 1);
        assert_eq!(again.named_databases()[0].0, "analytics");
        assert_eq!(
            again.named_databases()[0].1.path,
            "firestore_export_analytics"
        );
        // The official section is untouched by the extension.
        assert_eq!(
            again.section(Product::Firestore).map(|s| s.path.as_str()),
            Some("firestore_export")
        );
    }

    #[test]
    fn a_manifest_without_the_extension_reports_no_named_databases() {
        let parsed = ExportMetadata::parse(OFFICIAL).expect("the official manifest parses");
        assert!(parsed.named_databases().is_empty());
        assert!(!parsed.to_json().contains("fireemu"));
    }

    #[test]
    fn an_extension_that_names_the_default_database_is_refused() {
        let text = r#"{"version":"1","fireemu":{"version":"0.1.0","firestoreDatabases":[{"database":"(default)","path":"x"}]}}"#;
        assert!(ExportMetadata::parse(text).is_err());
        let empty = r#"{"version":"1","fireemu":{"firestoreDatabases":[{"path":"x"}]}}"#;
        assert!(ExportMetadata::parse(empty).is_err());
        assert!(ExportMetadata::parse(r#"{"version":"1","fireemu":[]}"#).is_err());
    }

    #[test]
    fn sections_are_written_in_the_official_product_order() {
        let mut metadata = ExportMetadata::new("0.1.0");
        metadata.set(
            Product::Storage,
            Section {
                version: "0.1.0".to_owned(),
                path: "storage_export".to_owned(),
                metadata_file: None,
            },
        );
        metadata.set(
            Product::Firestore,
            Section {
                version: "1.22.0".to_owned(),
                path: "firestore_export".to_owned(),
                metadata_file: Some("firestore_export/x".to_owned()),
            },
        );
        metadata.set(
            Product::Auth,
            Section {
                version: "0.1.0".to_owned(),
                path: "auth_export".to_owned(),
                metadata_file: None,
            },
        );
        let keys: Vec<&str> = metadata.sections.iter().map(|(p, _)| p.key()).collect();
        assert_eq!(keys, vec!["firestore", "auth", "storage"]);
    }
}
