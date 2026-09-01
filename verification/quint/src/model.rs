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
    },
    ModelDescriptor {
        name: "EventDelivery",
        spec: "specs/EventDelivery.qnt",
        main: "EventDeliveryProof",
        config: "specs/tlc-config.json",
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
            temporal("TimeNeverDecreases"),
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
            "crates/fireemu-core-rules/src/regex.rs",
        ],
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
        ],
        production_sources: &["crates/fireemu-core-storage/src/store.rs"],
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
