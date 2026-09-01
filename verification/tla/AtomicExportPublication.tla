-------------------- MODULE AtomicExportPublication --------------------
(***************************************************************************)
(* An export is built in a private sibling and becomes public in one step. *)
(* A build failure or a replaced target leaves the prior public artifact.  *)
(***************************************************************************)

VARIABLES stage,
          targetIdentity,
          publicArtifact,
          stagePrivate,
          publicPrivate,
          previousStage,
          previousTargetIdentity,
          previousPublicArtifact,
          previousStagePrivate,
          previousPublicPrivate,
          lastAction

vars == <<stage, targetIdentity, publicArtifact, stagePrivate, publicPrivate,
          previousStage, previousTargetIdentity, previousPublicArtifact,
          previousStagePrivate, previousPublicPrivate, lastAction>>

Stages == {"Absent", "Created", "Partial", "Complete"}
TargetIdentities == {"Original", "Changed"}
PublicArtifacts == {"Old", "New", "Partial"}
Actions == {"Init", "Create", "Write", "Complete", "Swap", "Refuse", "Publish"}

TypeOK ==
    /\ stage \in Stages
    /\ targetIdentity \in TargetIdentities
    /\ publicArtifact \in PublicArtifacts
    /\ stagePrivate \in BOOLEAN
    /\ publicPrivate \in BOOLEAN
    /\ previousStage \in Stages
    /\ previousTargetIdentity \in TargetIdentities
    /\ previousPublicArtifact \in PublicArtifacts
    /\ previousStagePrivate \in BOOLEAN
    /\ previousPublicPrivate \in BOOLEAN
    /\ lastAction \in Actions

Init ==
    /\ stage = "Absent"
    /\ targetIdentity = "Original"
    /\ publicArtifact = "Old"
    /\ stagePrivate = FALSE
    /\ publicPrivate = TRUE
    /\ previousStage = stage
    /\ previousTargetIdentity = targetIdentity
    /\ previousPublicArtifact = publicArtifact
    /\ previousStagePrivate = stagePrivate
    /\ previousPublicPrivate = publicPrivate
    /\ lastAction = "Init"

Record(action) ==
    /\ previousStage' = stage
    /\ previousTargetIdentity' = targetIdentity
    /\ previousPublicArtifact' = publicArtifact
    /\ previousStagePrivate' = stagePrivate
    /\ previousPublicPrivate' = publicPrivate
    /\ lastAction' = action

Create ==
    /\ stage = "Absent"
    /\ stage' = "Created"
    /\ stagePrivate' = TRUE
    /\ Record("Create")
    /\ UNCHANGED <<targetIdentity, publicArtifact, publicPrivate>>

Write ==
    /\ stage = "Created"
    /\ stage' = "Partial"
    /\ Record("Write")
    /\ UNCHANGED <<targetIdentity, publicArtifact, stagePrivate, publicPrivate>>

Complete ==
    /\ stage = "Partial"
    /\ stage' = "Complete"
    /\ Record("Complete")
    /\ UNCHANGED <<targetIdentity, publicArtifact, stagePrivate, publicPrivate>>

Swap ==
    /\ stage \in {"Created", "Partial", "Complete"}
    /\ targetIdentity = "Original"
    /\ targetIdentity' = "Changed"
    /\ Record("Swap")
    /\ UNCHANGED <<stage, publicArtifact, stagePrivate, publicPrivate>>

Refuse ==
    /\ stage \in {"Created", "Partial", "Complete"}
    /\ stage' = "Absent"
    /\ stagePrivate' = FALSE
    /\ Record("Refuse")
    /\ UNCHANGED <<targetIdentity, publicArtifact, publicPrivate>>

Publish ==
    /\ stage = "Complete"
    /\ targetIdentity = "Original"
    /\ stagePrivate
    /\ stage' = "Absent"
    /\ publicArtifact' = "New"
    /\ publicPrivate' = stagePrivate
    /\ stagePrivate' = FALSE
    /\ Record("Publish")
    /\ UNCHANGED targetIdentity

Next == Create \/ Write \/ Complete \/ Swap \/ Refuse \/ Publish

Spec == Init /\ [][Next]_vars

NoPartialPublication == publicArtifact \in {"Old", "New"}

PublicationRequiresCompletePrivateStage ==
    lastAction = "Publish" =>
        /\ previousStage = "Complete"
        /\ previousTargetIdentity = "Original"
        /\ previousStagePrivate

RefusalPreservesPublicArtifact ==
    lastAction = "Refuse" =>
        /\ publicArtifact = previousPublicArtifact
        /\ publicPrivate = previousPublicPrivate

PublishedArtifactIsPrivate == publicArtifact = "New" => publicPrivate

AtomicExportPublication ==
    /\ NoPartialPublication
    /\ PublicationRequiresCompletePrivateStage
    /\ RefusalPreservesPublicArtifact
    /\ PublishedArtifactIsPrivate
===========================================================================
