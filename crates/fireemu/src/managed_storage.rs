//! Managed export and import (`databases.exportDocuments` / `importDocuments`) over the daemon's
//! Storage emulator: the bridge between the Admin API in `fireemu-adapter-grpc`, which has no
//! Storage dependency, and `fireemu-core-export`'s managed layout.
//!
//! A bucket exists for an export when it is one of the project's default buckets or already
//! holds an object: the Storage emulator, like the official one, has no bucket resource of its
//! own, and creating one is the Storage parent's concern, not this one's. Because nothing ties
//! an emulated bucket to a project, the first project whose export or import uses a bucket owns
//! it here, and another project's default bucket is never usable: one project's export cannot
//! write into, nor its import read from, a bucket another project uses.

use std::sync::Arc;

use fireemu_adapter_grpc::admin::managed::{
    ExportJob, ExportOutcome, ImportJob, ImportOutcome, ImportRefusal, ImportedDocument,
    ManagedDocument, ManagedStorage,
};
use fireemu_adapter_http::storage::StorageState;
use fireemu_core_export::firestore::ExportDocument;
use fireemu_core_export::managed::{
    partitions, read_managed_output, read_overall, read_partition_outputs, write_managed_export,
    Partition,
};
use fireemu_core_storage::name::{BucketName, ObjectName};
use fireemu_core_storage::store::{NewMetadata, Precondition};
use fireemu_core_types::determinism::Clock;

/// The most output bytes one managed import reads.
const MAX_IMPORT_OUTPUT_BYTES: u64 = 1 << 30;

/// The most documents one managed import decodes and holds before writing them.
const MAX_IMPORT_DOCUMENTS: usize = 1_000_000;

/// The project a default bucket (`<project>.appspot.com`, `<project>.firebasestorage.app`)
/// belongs to.
fn default_bucket_project(bucket: &str) -> Option<&str> {
    bucket
        .strip_suffix(".appspot.com")
        .or_else(|| bucket.strip_suffix(".firebasestorage.app"))
}

/// Which project uses each bucket for managed exports and imports.
#[derive(Default)]
struct BucketOwners(std::sync::Mutex<std::collections::BTreeMap<String, String>>);

impl BucketOwners {
    /// Whether `project` may use `bucket`, which then belongs to it if no project used it yet.
    fn claim(&self, project: &str, bucket: &str) -> bool {
        if let Some(owner) = default_bucket_project(bucket) {
            return owner == project;
        }
        let mut owners = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        owners
            .entry(bucket.to_owned())
            .or_insert_with(|| project.to_owned())
            == project
    }
}

/// An output file name a partition metadata may name: a file in the partition's directory.
fn output_name_is_local(name: &str) -> bool {
    !name.is_empty()
        && !name.contains(['/', '\\'])
        && name != "."
        && name != ".."
        && !name.chars().any(char::is_control)
}

/// What one import has read: each output object at most once, within a byte budget, so a
/// crafted metadata cannot make it decode the same object again and again.
#[derive(Default)]
struct ImportBudget {
    outputs: std::collections::BTreeSet<String>,
    bytes: u64,
    documents: usize,
}

impl ImportBudget {
    fn admit(&mut self, path: &str) -> Result<(), ImportRefusal> {
        if self.outputs.insert(path.to_owned()) {
            Ok(())
        } else {
            Err(ImportRefusal::Malformed(format!(
                "{path} is named by more than one partition"
            )))
        }
    }

    /// Counts one more decoded document.
    fn decoded(&mut self) -> Result<(), ImportRefusal> {
        self.documents += 1;
        if self.documents > MAX_IMPORT_DOCUMENTS {
            return Err(ImportRefusal::Malformed(format!(
                "the export holds more than the {MAX_IMPORT_DOCUMENTS} documents one import reads"
            )));
        }
        Ok(())
    }

    fn read(&mut self, bytes: usize) -> Result<(), ImportRefusal> {
        self.bytes = self
            .bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
        if self.bytes > MAX_IMPORT_OUTPUT_BYTES {
            return Err(ImportRefusal::Malformed(format!(
                "the export's outputs exceed the {MAX_IMPORT_OUTPUT_BYTES} bytes one import reads"
            )));
        }
        Ok(())
    }
}

/// [`ManagedStorage`] over a Storage emulator.
pub struct StorageBridge {
    storage: Arc<StorageState>,
    owners: BucketOwners,
}

impl StorageBridge {
    /// A bridge over `storage`.
    #[must_use]
    pub fn new(storage: Arc<StorageState>) -> Self {
        Self {
            storage,
            owners: BucketOwners::default(),
        }
    }

    fn now(&self) -> fireemu_core_types::time::LogicalInstant {
        self.storage
            .clock
            .lock()
            .map(|clock| clock.now())
            .unwrap_or(fireemu_core_types::time::LogicalInstant::UNIX_EPOCH)
    }

    fn read(&self, bucket: &str, name: &str) -> Option<Vec<u8>> {
        let bucket = BucketName::try_new(bucket).ok()?;
        let name = ObjectName::try_new(name).ok()?;
        let store = self.storage.store().ok()?;
        let meta = store.get(&bucket, &name)?;
        Some(store.bytes(meta).to_vec())
    }
}

fn join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_owned()
    } else {
        format!("{prefix}/{name}")
    }
}

/// The last segment of an object prefix: production names the overall metadata after it.
fn export_name(prefix: &str) -> &str {
    prefix.rsplit('/').next().unwrap_or(prefix)
}

impl ManagedStorage for StorageBridge {
    fn bucket_exists(&self, project: &str, bucket: &str) -> bool {
        // Another project's bucket answers as a missing one: production's words for a bucket
        // of another project were not observed.
        if default_bucket_project(bucket) == Some(project) {
            return true;
        }
        let Ok(name) = BucketName::try_new(bucket) else {
            return false;
        };
        self.storage
            .store()
            .is_ok_and(|store| store.buckets().contains(&name))
            && self.owners.claim(project, bucket)
    }

    fn export(&self, job: &ExportJob) -> Result<ExportOutcome, String> {
        let documents: Vec<ExportDocument> = job
            .documents
            .iter()
            .map(|d| ExportDocument {
                project: job.project.clone(),
                path: d.path.clone(),
                fields: d.fields.clone(),
            })
            .collect();
        let micros = |at: fireemu_core_types::time::LogicalInstant| {
            u64::try_from(at.as_nanos() / 1_000).unwrap_or(0)
        };
        let export = write_managed_export(
            export_name(&job.prefix),
            &job.database,
            &job.collection_ids,
            &job.namespace_ids,
            (micros(job.window.0), micros(job.window.1)),
            &documents,
        )
        .map_err(|e| e.to_string())?;
        let bucket = BucketName::try_new(job.bucket.clone()).map_err(|e| e.to_string())?;
        let now = self.now();
        let mut store = self.storage.store().map_err(|(_, message)| message)?;
        for (name, bytes) in export.files {
            let object =
                ObjectName::try_new(join(&job.prefix, &name)).map_err(|e| e.to_string())?;
            store
                .put(
                    &bucket,
                    &object,
                    bytes,
                    NewMetadata::default(),
                    Precondition::default(),
                    now,
                )
                .map_err(|e| e.to_string())?;
        }
        Ok(ExportOutcome {
            documents: export.documents,
            bytes: export.bytes,
        })
    }

    fn import(&self, job: &ImportJob) -> Result<ImportOutcome, ImportRefusal> {
        let name = export_name(&job.prefix);
        let overall_name = join(&job.prefix, &format!("{name}.overall_export_metadata"));
        // A bucket another project uses is not readable to this one: it answers as absent.
        let readable = self.owners.claim(&job.project, &job.bucket);
        let Some(overall) = readable
            .then(|| self.read(&job.bucket, &overall_name))
            .flatten()
        else {
            return Err(ImportRefusal::MissingMetadata(format!(
                "/{}/{overall_name}",
                job.bucket
            )));
        };
        let entries =
            read_overall(&overall).map_err(|e| ImportRefusal::Malformed(e.to_string()))?;
        let wanted = partitions(&job.collection_ids, &job.namespace_ids);
        let requested_all = job.collection_ids.is_empty() && job.namespace_ids.is_empty();
        let selected: Vec<_> = entries
            .iter()
            .filter(|entry| requested_all || wanted.contains(&entry.partition))
            .collect();
        if !requested_all
            && wanted
                .iter()
                .any(|w| !entries.iter().any(|e| &e.partition == w))
        {
            return Err(ImportRefusal::KindsUnavailable);
        }
        let mut documents = Vec::new();
        let mut bytes: u64 = 0;
        let mut budget = ImportBudget::default();
        for entry in selected {
            if let Partition::Namespace(_) = entry.partition {
                continue;
            }
            let metadata = self
                .read(&job.bucket, &join(&job.prefix, &entry.metadata_file))
                .ok_or_else(|| {
                    ImportRefusal::Malformed(format!("{} is missing", entry.metadata_file))
                })?;
            let directory = entry.metadata_file.rsplit_once('/').map_or("", |(d, _)| d);
            for output in read_partition_outputs(&metadata)
                .map_err(|e| ImportRefusal::Malformed(e.to_string()))?
            {
                if !output_name_is_local(&output) {
                    return Err(ImportRefusal::Malformed(format!(
                        "{} names the output {output:?} outside its directory",
                        entry.metadata_file
                    )));
                }
                let path = join(&job.prefix, &join(directory, &output));
                budget.admit(&path)?;
                let content = self
                    .read(&job.bucket, &path)
                    .ok_or_else(|| ImportRefusal::Malformed(format!("{output} is missing")))?;
                budget.read(content.len())?;
                for entity in read_managed_output(&content)
                    .map_err(|e| ImportRefusal::Malformed(e.to_string()))?
                {
                    documents.push(ImportedDocument {
                        document: ManagedDocument {
                            path: entity.document.path,
                            fields: entity.document.fields,
                        },
                        project: entity.document.project,
                        database: entity.database,
                    });
                    budget.decoded()?;
                }
            }
            bytes = bytes.saturating_add(entry.bytes);
        }
        Ok(ImportOutcome { documents, bytes })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bucket_belongs_to_the_first_project_that_uses_it() {
        let owners = BucketOwners::default();
        assert!(owners.claim("a", "shared"));
        assert!(owners.claim("a", "shared"));
        assert!(!owners.claim("b", "shared"), "another project's bucket");
        assert!(owners.claim("b", "b.appspot.com"));
        assert!(
            !owners.claim("a", "b.appspot.com"),
            "another project's default bucket"
        );
        assert!(!owners.claim("a", "b.firebasestorage.app"));
    }

    #[test]
    fn an_output_name_stays_in_its_partition_directory() {
        assert!(output_name_is_local("output-0"));
        for name in ["", ".", "..", "../x", "x/y", "/abs", "a\\b", "a\nb"] {
            assert!(!output_name_is_local(name), "{name:?}");
        }
    }

    #[test]
    fn an_import_reads_each_output_once_and_within_its_budget() {
        let mut budget = ImportBudget::default();
        assert!(budget.admit("x/all/output-0").is_ok());
        assert!(matches!(
            budget.admit("x/all/output-0"),
            Err(ImportRefusal::Malformed(_))
        ));
        assert!(budget.read(1024).is_ok());
        budget.documents = MAX_IMPORT_DOCUMENTS - 1;
        assert!(budget.decoded().is_ok());
        assert!(budget.decoded().is_err());
        let too_much = usize::try_from(MAX_IMPORT_OUTPUT_BYTES).unwrap();
        assert!(matches!(
            budget.read(too_much),
            Err(ImportRefusal::Malformed(_))
        ));
    }
}
