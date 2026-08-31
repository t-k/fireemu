------------------------- MODULE StorageGeneration -------------------------
(***************************************************************************)
(* Object data generations draw from a global high-water allocator.         *)
(* Snapshot restore may replace visible state but never rewinds allocation. *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS MaxGeneration, MaxMetageneration

VARIABLES highWater,
          liveGeneration,
          metageneration,
          issued,
          snapshotCaptured,
          snapshotLiveGeneration,
          snapshotMetageneration,
          snapshotHighWater,
          previousHighWater,
          previousLiveGeneration,
          previousMetageneration,
          previousIssued,
          lastAction

vars == <<highWater, liveGeneration, metageneration, issued, snapshotCaptured,
          snapshotLiveGeneration, snapshotMetageneration, snapshotHighWater,
          previousHighWater, previousLiveGeneration, previousMetageneration,
          previousIssued, lastAction>>

Actions == {"Init", "PutData", "PatchMetadata", "Delete", "CaptureSnapshot",
             "RestoreSnapshot"}

TypeOK ==
    /\ highWater \in 0..MaxGeneration
    /\ liveGeneration \in 0..MaxGeneration
    /\ metageneration \in 0..MaxMetageneration
    /\ issued \subseteq 1..MaxGeneration
    /\ snapshotCaptured \in BOOLEAN
    /\ snapshotLiveGeneration \in 0..MaxGeneration
    /\ snapshotMetageneration \in 0..MaxMetageneration
    /\ snapshotHighWater \in 0..MaxGeneration
    /\ previousHighWater \in 0..MaxGeneration
    /\ previousLiveGeneration \in 0..MaxGeneration
    /\ previousMetageneration \in 0..MaxMetageneration
    /\ previousIssued \subseteq 1..MaxGeneration
    /\ lastAction \in Actions
    /\ (liveGeneration = 0 => metageneration = 0)
    /\ (liveGeneration # 0 => liveGeneration \in issued)

Init ==
    /\ highWater = 0
    /\ liveGeneration = 0
    /\ metageneration = 0
    /\ issued = {}
    /\ snapshotCaptured = FALSE
    /\ snapshotLiveGeneration = 0
    /\ snapshotMetageneration = 0
    /\ snapshotHighWater = 0
    /\ previousHighWater = highWater
    /\ previousLiveGeneration = liveGeneration
    /\ previousMetageneration = metageneration
    /\ previousIssued = issued
    /\ lastAction = "Init"

Record(action) ==
    /\ previousHighWater' = highWater
    /\ previousLiveGeneration' = liveGeneration
    /\ previousMetageneration' = metageneration
    /\ previousIssued' = issued
    /\ lastAction' = action

PutData ==
    /\ highWater < MaxGeneration
    /\ highWater' = highWater + 1
    /\ liveGeneration' = highWater + 1
    /\ metageneration' = 1
    /\ issued' = issued \cup {highWater + 1}
    /\ Record("PutData")
    /\ UNCHANGED <<snapshotCaptured, snapshotLiveGeneration,
                    snapshotMetageneration, snapshotHighWater>>

PatchMetadata ==
    /\ liveGeneration # 0
    /\ metageneration < MaxMetageneration
    /\ metageneration' = metageneration + 1
    /\ Record("PatchMetadata")
    /\ UNCHANGED <<highWater, liveGeneration, issued, snapshotCaptured,
                    snapshotLiveGeneration, snapshotMetageneration,
                    snapshotHighWater>>

Delete ==
    /\ liveGeneration # 0
    /\ liveGeneration' = 0
    /\ metageneration' = 0
    /\ Record("Delete")
    /\ UNCHANGED <<highWater, issued, snapshotCaptured, snapshotLiveGeneration,
                    snapshotMetageneration, snapshotHighWater>>

CaptureSnapshot ==
    /\ ~snapshotCaptured
    /\ snapshotCaptured' = TRUE
    /\ snapshotLiveGeneration' = liveGeneration
    /\ snapshotMetageneration' = metageneration
    /\ snapshotHighWater' = highWater
    /\ Record("CaptureSnapshot")
    /\ UNCHANGED <<highWater, liveGeneration, metageneration, issued>>

RestoreSnapshot ==
    /\ snapshotCaptured
    /\ liveGeneration' = snapshotLiveGeneration
    /\ metageneration' = snapshotMetageneration
    /\ highWater' = IF highWater >= snapshotHighWater THEN highWater ELSE snapshotHighWater
    /\ Record("RestoreSnapshot")
    /\ UNCHANGED <<issued, snapshotCaptured, snapshotLiveGeneration,
                    snapshotMetageneration, snapshotHighWater>>

Next ==
    \/ PutData
    \/ PatchMetadata
    \/ Delete
    \/ CaptureSnapshot
    \/ RestoreSnapshot

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
GenerationMonotonicity == highWater >= previousHighWater

GenerationNeverReused ==
    lastAction = "PutData" => liveGeneration \notin previousIssued

MetadataOnlyPreservesGeneration ==
    lastAction = "PatchMetadata" =>
        /\ liveGeneration = previousLiveGeneration
        /\ metageneration = previousMetageneration + 1

RestorePreservesGenerationHighWater ==
    lastAction = "RestoreSnapshot" =>
        /\ highWater >= previousHighWater
        /\ issued = previousIssued
=============================================================================
