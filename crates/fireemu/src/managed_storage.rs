//! Managed export and import (`databases.exportDocuments` / `importDocuments`) over the daemon's
//! Storage emulator: the bridge between the Admin API in `fireemu-adapter-grpc`, which has no
//! Storage dependency, and `fireemu-core-export`'s managed layout.
//!
//! A bucket exists for an export when it is one of the project's default buckets or already
//! holds an object: the Storage emulator, like the official one, has no bucket resource of its
//! own, and creating one is the Storage parent's concern, not this one's.

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

/// [`ManagedStorage`] over a Storage emulator.
pub struct StorageBridge {
    storage: Arc<StorageState>,
}

impl StorageBridge {
    /// A bridge over `storage`.
    #[must_use]
    pub fn new(storage: Arc<StorageState>) -> Self {
        Self { storage }
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
        if bucket == format!("{project}.appspot.com")
            || bucket == format!("{project}.firebasestorage.app")
        {
            return true;
        }
        let Ok(name) = BucketName::try_new(bucket) else {
            return false;
        };
        self.storage
            .store()
            .is_ok_and(|store| store.buckets().contains(&name))
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
        let Some(overall) = self.read(&job.bucket, &overall_name) else {
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
                let path = join(&job.prefix, &join(directory, &output));
                let content = self
                    .read(&job.bucket, &path)
                    .ok_or_else(|| ImportRefusal::Malformed(format!("{output} is missing")))?;
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
                }
            }
            bytes = bytes.saturating_add(entry.bytes);
        }
        Ok(ImportOutcome { documents, bytes })
    }
}
