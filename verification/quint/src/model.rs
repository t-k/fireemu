//! Registry for every Quint model in the formal verification authority.

/// Whether Quint checks a property over one state or over an execution trace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyKind {
    /// A state invariant checked by the model checker.
    Invariant,
    /// A temporal property checked over an execution trace.
    Temporal,
}

/// One property exposed by a registered Quint model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDescriptor {
    /// Stable property name used by Quint and traceability artifacts.
    pub name: &'static str,
    /// Checker mode used for this property.
    pub kind: PropertyKind,
    /// Backend diagnostic name expected when the property is violated.
    pub diagnostic_name: &'static str,
}

/// One stable bounded model-checking input recorded in evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundDescriptor {
    /// Stable bound name.
    pub name: &'static str,
    /// Canonical finite value description.
    pub value: &'static str,
}

/// Metadata required to check and connect one Quint model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelDescriptor {
    /// Stable model name.
    pub name: &'static str,
    /// Quint source path relative to `verification/quint`.
    pub spec: &'static str,
    /// Quint module passed to the checker.
    pub main: &'static str,
    /// TLC configuration path relative to `verification/quint`.
    pub config: &'static str,
    /// Mutation manifest path relative to `verification/quint`.
    pub mutation_manifest: &'static str,
    /// Safety and temporal properties owned by the model.
    pub properties: &'static [PropertyDescriptor],
    /// Transition actions whose coverage must be demonstrated.
    pub actions: &'static [&'static str],
    /// Production files exercised by Quint Connect.
    pub production_sources: &'static [&'static str],
    /// Finite model-checking bounds.
    pub bounds: &'static [BoundDescriptor],
    /// Deterministic scenario names.
    pub scenarios: &'static [&'static str],
    /// Production-derived fields checked by conformance projections.
    pub projection_fields: &'static [&'static str],
    /// Rust driver path relative to the repository root.
    pub driver: &'static str,
    /// Quint Connect test path relative to the repository root.
    pub connect_test: &'static str,
    /// Additional model-specific inputs that evidence must bind.
    pub additional_evidence_inputs: &'static [&'static str],
}

impl ModelDescriptor {
    /// Resolves one configured property without accepting an undeclared check.
    pub fn property(&self, name: &str) -> Result<&'static PropertyDescriptor, String> {
        self.properties
            .iter()
            .find(|property| property.name == name)
            .ok_or_else(|| format!("unknown property {name} for Quint model {}", self.name))
    }
}

const fn invariant(name: &'static str) -> PropertyDescriptor {
    PropertyDescriptor {
        name,
        kind: PropertyKind::Invariant,
        diagnostic_name: "q_inv",
    }
}

const fn temporal(name: &'static str) -> PropertyDescriptor {
    PropertyDescriptor {
        name,
        kind: PropertyKind::Temporal,
        diagnostic_name: "temporal properties",
    }
}

const MODELS: &[ModelDescriptor] = &[
    ModelDescriptor {
        name: "AtomicCommitOutbox",
        spec: "specs/AtomicCommitOutbox.qnt",
        main: "AtomicCommitOutboxProof",
        config: "configs/AtomicCommitOutbox.json",
        mutation_manifest: "mutations/AtomicCommitOutbox.json",
        properties: &[
            invariant("TypeOK"),
            invariant("AtomicCommit"),
            invariant("OutboxCompleteness"),
            invariant("NoPartialTransaction"),
            invariant("ConflictNeverCommits"),
        ],
        actions: &[
            "Begin",
            "StageWrite",
            "StageOutbox",
            "DetectConflict",
            "Commit",
            "Abort",
        ],
        production_sources: &[
            "crates/fireemu-core-firestore/src/store.rs",
            "crates/fireemu-adapter-grpc/src/local.rs",
        ],
        bounds: &[
            BoundDescriptor {
                name: "Docs",
                value: "{d1,d2}",
            },
            BoundDescriptor {
                name: "MaxVersion",
                value: "2",
            },
        ],
        scenarios: &["commit", "conflict", "abort"],
        projection_fields: &["documents", "outbox", "transactionState"],
        driver: "verification/quint/src/atomic_commit_outbox.rs",
        connect_test: "verification/quint/tests/atomic_commit_outbox_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "AtomicExportPublication",
        spec: "specs/AtomicExportPublication.qnt",
        main: "AtomicExportPublicationProof",
        config: "configs/AtomicExportPublication.json",
        mutation_manifest: "mutations/AtomicExportPublication.json",
        properties: &[
            invariant("TypeOK"),
            invariant("NoPartialPublication"),
            invariant("PublicationRequiresCompletePrivateStage"),
            invariant("RefusalPreservesPublicArtifact"),
            invariant("PublishedArtifactIsPrivate"),
            invariant("AtomicExportPublication"),
        ],
        actions: &["Create", "Write", "Complete", "Swap", "Refuse", "Publish"],
        production_sources: &["crates/fireemu/src/import_export.rs"],
        bounds: &[BoundDescriptor {
            name: "Domain",
            value: "finite-enumerated",
        }],
        scenarios: &["publish", "refuse", "replace"],
        projection_fields: &["publicArtifact", "privateStage", "stageComplete"],
        driver: "verification/quint/src/atomic_export_publication.rs",
        connect_test: "verification/quint/tests/atomic_export_publication_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "AuthTotp",
        spec: "specs/AuthTotp.qnt",
        main: "AuthTotpProof",
        config: "configs/AuthTotp.json",
        mutation_manifest: "mutations/AuthTotp.json",
        properties: &[
            invariant("TypeOK"),
            invariant("NoTotpCodeReuse"),
            invariant("NoSecondFactorWithoutEnrollment"),
            invariant("AcceptedOnlyWithinWindow"),
            invariant("EnrollmentAcceptedBeforeExpiry"),
            temporal("EnrollmentEventuallyFinalizesOrExpires"),
        ],
        actions: &[
            "Tick",
            "StartEnrollment",
            "FinalizeEnrollment",
            "ExpireEnrollment",
            "Verify",
        ],
        production_sources: &[
            "crates/fireemu-core-auth/src/store.rs",
            "crates/fireemu-core-auth/src/mfa.rs",
            "crates/fireemu-core-auth/src/totp.rs",
        ],
        bounds: &[
            BoundDescriptor {
                name: "MaxStep",
                value: "4",
            },
            BoundDescriptor {
                name: "Window",
                value: "1",
            },
            BoundDescriptor {
                name: "SessionTtl",
                value: "2",
            },
        ],
        scenarios: &["enroll", "expire", "verify", "rejectReuse"],
        projection_fields: &["step", "enrollment", "accepted", "usedCodes"],
        driver: "verification/quint/src/auth_totp.rs",
        connect_test: "verification/quint/tests/auth_totp_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "AwaitIdle",
        spec: "specs/AwaitIdle.qnt",
        main: "AwaitIdleProof",
        config: "configs/AwaitIdle.json",
        mutation_manifest: "mutations/AwaitIdle.json",
        properties: &[
            invariant("TypeOK"),
            invariant("NoFalseIdle"),
            invariant("CoveredReservationsBlock"),
            invariant("NoIdentityReuse"),
            invariant("FenceClosedToNewExternalWork"),
            invariant("FenceLifecycleMonotonic"),
            temporal("FencedWorkStaysTerminal"),
            temporal("AwaitIdleEventuallyReturns"),
        ],
        actions: &[
            "BeginExternal",
            "CompleteLeaf",
            "CompleteWithReservation",
            "EnqueueChild",
            "RequestFence",
            "ReturnIdle",
        ],
        production_sources: &[
            "crates/fireemu-core-session/src/idle.rs",
            "crates/fireemu-adapter-functions/src/runtime.rs",
            "crates/fireemu-adapter-http/src/control.rs",
        ],
        bounds: &[
            BoundDescriptor {
                name: "Items",
                value: "{i1,i2,i3}",
            },
            BoundDescriptor {
                name: "MaxDepth",
                value: "1",
            },
            BoundDescriptor {
                name: "IgnoreTextIndex",
                value: "{false,true}",
            },
        ],
        scenarios: &["leaf", "reservation", "fence", "ignoreTextIndex"],
        projection_fields: &["fence", "inFlight", "reservations", "returned"],
        driver: "verification/quint/src/await_idle.rs",
        connect_test: "verification/quint/tests/await_idle_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "EventDelivery",
        spec: "specs/EventDelivery.qnt",
        main: "EventDeliveryProof",
        config: "configs/EventDelivery.json",
        mutation_manifest: "mutations/EventDelivery.json",
        properties: &[
            invariant("TypeOK"),
            invariant("AttemptsBounded"),
            invariant("DeadLetterOnlyAfterExhaustion"),
            invariant("LegalStateTransitions"),
            invariant("AttemptsChangeOnlyOnStart"),
            invariant("StaleDiscardRequiresOlderEpoch"),
            invariant("RetryDeadlineMatchesPolicy"),
            invariant("RetryRequiresDeadline"),
            PropertyDescriptor {
                name: "NoTerminalRegression",
                kind: PropertyKind::Temporal,
                diagnostic_name: "eventdeliveryproof_eventdelivery_noterminalregression",
            },
            PropertyDescriptor {
                name: "TimeNeverDecreases",
                kind: PropertyKind::Temporal,
                diagnostic_name: "eventdeliveryproof_eventdelivery_timeneverdecreases",
            },
            temporal("EventEventuallyTerminates"),
        ],
        actions: &[
            "Lease",
            "Start",
            "Succeed",
            "Fail",
            "RetryDue",
            "Interrupt",
            "Cancel",
            "Tick",
            "Reset",
            "DiscardStale",
        ],
        production_sources: &[
            "crates/fireemu-core-events/src/state.rs",
            "crates/fireemu-core-events/src/retry.rs",
        ],
        bounds: &[
            BoundDescriptor {
                name: "Events",
                value: "{e1,e2}",
            },
            BoundDescriptor {
                name: "MaxAttempts",
                value: "3",
            },
            BoundDescriptor {
                name: "MaxEpoch",
                value: "1",
            },
            BoundDescriptor {
                name: "InitialTime",
                value: "100",
            },
            BoundDescriptor {
                name: "MaxTime",
                value: "120",
            },
            BoundDescriptor {
                name: "BaseBackoff",
                value: "1",
            },
            BoundDescriptor {
                name: "MaxBackoff",
                value: "4",
            },
        ],
        scenarios: &[
            "success",
            "retryTiming",
            "interrupt",
            "staleDiscard",
            "cancel",
        ],
        projection_fields: &[
            "state",
            "attempts",
            "maxAttempts",
            "capturedEpoch",
            "currentEpoch",
            "terminal",
            "cancelled",
            "stale",
            "now",
            "retryAt",
            "baseBackoff",
            "maxBackoff",
        ],
        driver: "verification/quint/src/event_delivery.rs",
        connect_test: "verification/quint/tests/event_delivery_connect.rs",
        additional_evidence_inputs: &[
            "crates/fireemu-core-events/Cargo.toml",
            "crates/fireemu-core-events/src/event.rs",
            "crates/fireemu-core-types/Cargo.toml",
            "crates/fireemu-core-types/src/ids.rs",
            "crates/fireemu-core-types/src/time.rs",
            "verification/quint/tests/event_delivery_evidence.rs",
        ],
    },
    ModelDescriptor {
        name: "RegexAuthorization",
        spec: "specs/RegexAuthorization.qnt",
        main: "RegexAuthorizationProof",
        config: "configs/RegexAuthorization.json",
        mutation_manifest: "mutations/RegexAuthorization.json",
        properties: &[invariant("TypeOK"), invariant("ExhaustionNeverAllows")],
        actions: &["Evaluate"],
        production_sources: &[
            "crates/fireemu-core-rules/src/eval.rs",
            "crates/fireemu-core-rules/src/parse.rs",
            "crates/fireemu-core-rules/src/regex.rs",
            "crates/fireemu-core-rules/src/value.rs",
        ],
        bounds: &[BoundDescriptor {
            name: "OutcomesAndNegations",
            value: "all-finite-combinations",
        }],
        scenarios: &[
            "matched",
            "notMatched",
            "stepExhausted",
            "depthExhausted",
            "parentNegated",
            "nestedNegated",
        ],
        projection_fields: &["decision", "denialClass"],
        driver: "verification/quint/src/regex_authorization.rs",
        connect_test: "verification/quint/tests/regex_authorization_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "RulesetActivation",
        spec: "specs/RulesetActivation.qnt",
        main: "RulesetActivationProof",
        config: "configs/RulesetActivation.json",
        mutation_manifest: "mutations/RulesetActivation.json",
        properties: &[
            invariant("TypeOK"),
            invariant("ActivationRequiresAllChecks"),
            invariant("FailedCandidateNeverActivates"),
            invariant("RequestVersionIsImmutable"),
            invariant("ActiveVersionChangesAtomically"),
            invariant("AtomicRulesetActivation"),
        ],
        actions: &[
            "Create",
            "Parse",
            "Compile",
            "Check",
            "Reject",
            "Activate",
            "StartRequest",
            "ProgressRequest",
            "FinishRequest",
        ],
        production_sources: &[
            "crates/fireemu-core-rules/src/runtime.rs",
            "crates/fireemu-adapter-grpc/src/rules.rs",
        ],
        bounds: &[
            BoundDescriptor {
                name: "Requests",
                value: "{r1,r2}",
            },
            BoundDescriptor {
                name: "Versions",
                value: "{v1,v2}",
            },
        ],
        scenarios: &["activate", "reject", "pinRequest"],
        projection_fields: &["activeVersion", "generation", "requestVersion"],
        driver: "verification/quint/src/ruleset_activation.rs",
        connect_test: "verification/quint/tests/ruleset_activation_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "SessionEpoch",
        spec: "specs/SessionEpoch.qnt",
        main: "SessionEpochProof",
        config: "configs/SessionEpoch.json",
        mutation_manifest: "mutations/SessionEpoch.json",
        properties: &[
            invariant("TypeOK"),
            invariant("EpochIsolation"),
            invariant("WorkCapturedOnlyWhileActive"),
            temporal("EpochNeverDecreases"),
            temporal("ResetEventuallyActivatesNewEpoch"),
        ],
        actions: &[
            "Activate",
            "BeginReset",
            "CompleteReset",
            "BeginClose",
            "CompleteClose",
            "CaptureWork",
            "ApplyWork",
            "DiscardWork",
        ],
        production_sources: &["crates/fireemu-core-session/src/session.rs"],
        bounds: &[
            BoundDescriptor {
                name: "Workers",
                value: "{w1,w2}",
            },
            BoundDescriptor {
                name: "MaxEpoch",
                value: "2",
            },
        ],
        scenarios: &["activate", "reset", "close", "discardStale"],
        projection_fields: &["state", "epoch", "workEpochResult"],
        driver: "verification/quint/src/session_epoch.rs",
        connect_test: "verification/quint/tests/session_epoch_connect.rs",
        additional_evidence_inputs: &[],
    },
    ModelDescriptor {
        name: "StorageGeneration",
        spec: "specs/StorageGeneration.qnt",
        main: "StorageGenerationProof",
        config: "configs/StorageGeneration.json",
        mutation_manifest: "mutations/StorageGeneration.json",
        properties: &[
            invariant("TypeOK"),
            invariant("GenerationMonotonicity"),
            invariant("GenerationNeverReused"),
            invariant("MetadataOnlyPreservesGeneration"),
            invariant("RestorePreservesGenerationHighWater"),
        ],
        actions: &[
            "PutData",
            "PatchMetadata",
            "Delete",
            "CaptureSnapshot",
            "RestoreSnapshot",
            "ImportData",
        ],
        production_sources: &["crates/fireemu-core-storage/src/store.rs"],
        bounds: &[
            BoundDescriptor {
                name: "MaxGeneration",
                value: "3",
            },
            BoundDescriptor {
                name: "MaxMetageneration",
                value: "3",
            },
            BoundDescriptor {
                name: "ImportedGeneration",
                value: "2",
            },
        ],
        scenarios: &[
            "write",
            "metadata",
            "deleteThenPut",
            "snapshotRestore",
            "importRestore",
        ],
        projection_fields: &[
            "generation",
            "metageneration",
            "highWater",
            "exists",
            "issued",
        ],
        driver: "verification/quint/src/storage_generation.rs",
        connect_test: "verification/quint/tests/storage_generation_connect.rs",
        additional_evidence_inputs: &[],
    },
];

/// Iterates over every model in stable authority order.
pub fn all_models() -> impl Iterator<Item = &'static ModelDescriptor> {
    MODELS.iter()
}

/// Resolves a model by its stable name.
pub fn model(name: &str) -> Result<&'static ModelDescriptor, String> {
    MODELS
        .iter()
        .find(|descriptor| descriptor.name == name)
        .ok_or_else(|| format!("unknown Quint model {name}"))
}
