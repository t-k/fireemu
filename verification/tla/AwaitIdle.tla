------------------------------ MODULE AwaitIdle ------------------------------
(***************************************************************************)
(* The await-idle fence (spec 10.5, INV-IDLE-001..005, LIVE-IDLE-001).     *)
(*                                                                         *)
(* Work items are causal: a running item may spawn a child.  Between the   *)
(* parent's completion and the child's enqueue the parent holds a          *)
(* reservation, which must count as active work.  Text Index builds are    *)
(* fenced by default and may only be ignored by explicit option.           *)
(*                                                                         *)
(* Properties                                                              *)
(*   INV-IDLE-001  NoFalseIdle                                             *)
(*   INV-IDLE-002  NoIdentityReuse                                         *)
(*   INV-IDLE-003  FenceClosedToNewExternalWork                            *)
(*   INV-IDLE-004  FenceLifecycleMonotonic                                 *)
(*   INV-IDLE-005  CoveredReservationsBlock                                *)
(*   LIVE-IDLE-001 AwaitIdleEventuallyReturns                              *)
(***************************************************************************)
EXTENDS Naturals, FiniteSets

CONSTANTS Items,          \* universe of work item identities
          MaxDepth,       \* causal depth bound (children only below this depth)
          IgnoreTextIndex \* await-idle option: TRUE = IdleWaitPolicy::Ignore

Kinds == {"commit", "event", "invocation", "textIndexBuild"}

VARIABLES active,     \* set of active items
          reserved,   \* set of items whose parent completed but child is not enqueued yet
          kind,       \* kind[i]
          depth,      \* depth[i]
          used,       \* items ever allocated
          fenced,     \* items covered by the current fence (causally derived included)
          fenceState, \* "none" | "waiting" | "returned"
          previousUsed,
          previousFenceState,
          lastAction,
          lastTarget

vars == <<active, reserved, kind, depth, used, fenced, fenceState,
          previousUsed, previousFenceState, lastAction, lastTarget>>

Actions == {"Init", "BeginExternal", "CompleteLeaf", "CompleteWithReservation",
             "EnqueueChild", "RequestFence", "ReturnIdle"}

Fenced(i) == \/ kind[i] # "textIndexBuild"
             \/ ~IgnoreTextIndex

\* Covered reservations are always blocking. Active work may be ignored by kind.
Blocking == (reserved \cap fenced) \cup {i \in active : i \in fenced /\ Fenced(i)}

TypeOK ==
    /\ active \subseteq Items
    /\ reserved \subseteq Items
    /\ kind \in [Items -> Kinds]
    /\ depth \in [Items -> 0..MaxDepth]
    /\ used \subseteq Items
    /\ fenced \subseteq Items
    /\ fenceState \in {"none", "waiting", "returned"}
    /\ previousUsed \subseteq Items
    /\ previousFenceState \in {"none", "waiting", "returned"}
    /\ lastAction \in Actions
    /\ lastTarget \subseteq Items
    /\ Cardinality(lastTarget) <= 1

Init ==
    /\ active = {}
    /\ reserved = {}
    /\ kind = [i \in Items |-> "commit"]
    /\ depth = [i \in Items |-> 0]
    /\ used = {}
    /\ fenced = {}
    /\ fenceState = "none"
    /\ previousUsed = used
    /\ previousFenceState = fenceState
    /\ lastAction = "Init"
    /\ lastTarget = {}

Record(action, target) ==
    /\ previousUsed' = used
    /\ previousFenceState' = fenceState
    /\ lastAction' = action
    /\ lastTarget' = target

\* Fresh identities not yet promised to a pending reservation. In the real system child IDs
\* are unbounded; the bounded model must never let a reservation starve for lack of an ID.
FreshAvailable == Cardinality(Items \ used) > Cardinality(reserved)

\* External input: only before the fence is requested (liveness assumption).
BeginExternal(i, k) ==
    /\ fenceState = "none"
    /\ i \notin used
    /\ FreshAvailable
    /\ active' = active \cup {i}
    /\ used' = used \cup {i}
    /\ kind' = [kind EXCEPT ![i] = k]
    /\ depth' = [depth EXCEPT ![i] = 0]
    /\ Record("BeginExternal", {i})
    /\ UNCHANGED <<reserved, fenced, fenceState>>

\* Completion without a child.
CompleteLeaf(i) ==
    /\ i \in active
    /\ active' = active \ {i}
    /\ Record("CompleteLeaf", {i})
    /\ UNCHANGED <<reserved, kind, depth, used, fenced, fenceState>>

\* Completion that will spawn a child: hold a reservation until the child is enqueued.
CompleteWithReservation(i) ==
    /\ i \in active
    /\ depth[i] < MaxDepth
    /\ FreshAvailable
    /\ active' = active \ {i}
    /\ reserved' = reserved \cup {i}
    /\ Record("CompleteWithReservation", {i})
    /\ UNCHANGED <<kind, depth, used, fenced, fenceState>>

\* The child is enqueued and the reservation released atomically. A child of a fenced
\* parent is fenced (causal tree).
EnqueueChild(p, c, k) ==
    /\ p \in reserved
    /\ c \notin used
    /\ reserved' = reserved \ {p}
    /\ active' = active \cup {c}
    /\ used' = used \cup {c}
    /\ kind' = [kind EXCEPT ![c] = k]
    /\ depth' = [depth EXCEPT ![c] = depth[p] + 1]
    /\ fenced' = IF p \in fenced THEN fenced \cup {c} ELSE fenced
    /\ Record("EnqueueChild", {c})
    /\ UNCHANGED fenceState

EnqueueAnyChild(p, c) == \E k \in Kinds: EnqueueChild(p, c, k)

RequestFence ==
    /\ fenceState = "none"
    /\ fenceState' = "waiting"
    /\ fenced' = active \cup reserved
    /\ Record("RequestFence", {})
    /\ UNCHANGED <<active, reserved, kind, depth, used>>

ReturnIdle ==
    /\ fenceState = "waiting"
    /\ Blocking = {}
    /\ fenceState' = "returned"
    /\ Record("ReturnIdle", {})
    /\ UNCHANGED <<active, reserved, kind, depth, used, fenced>>

Next ==
    \/ RequestFence
    \/ ReturnIdle
    \/ \E i \in Items, k \in Kinds: BeginExternal(i, k)
    \/ \E i \in Items: CompleteLeaf(i) \/ CompleteWithReservation(i)
    \/ \E p \in Items, c \in Items: EnqueueAnyChild(p, c)

Fairness ==
    /\ \A i \in Items: WF_vars(CompleteLeaf(i) \/ CompleteWithReservation(i))
    /\ \A p \in Items, c \in Items: WF_vars(EnqueueAnyChild(p, c))
    /\ WF_vars(ReturnIdle)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* INV-IDLE-001: the return transition observes no blocking work.
NoFalseIdle == lastAction = "ReturnIdle" => Blocking = {}

CoveredReservationsBlock == reserved \cap fenced \subseteq Blocking

NoIdentityReuse ==
    IF lastAction \in {"BeginExternal", "EnqueueChild"}
    THEN /\ lastTarget \cap previousUsed = {}
         /\ used = previousUsed \cup lastTarget
    ELSE used = previousUsed

FenceClosedToNewExternalWork ==
    lastAction = "BeginExternal" => previousFenceState = "none"

FenceLifecycleMonotonic ==
    \/ previousFenceState = "none" /\ fenceState \in {"none", "waiting"}
    \/ previousFenceState = "waiting" /\ fenceState \in {"waiting", "returned"}
    \/ previousFenceState = "returned" /\ fenceState = "returned"

\* Stronger form: after the fence returns, fenced items never become active again.
FencedWorkStaysTerminal ==
    [][fenceState = "returned" => Blocking' = {}]_vars

\* LIVE-IDLE-001
AwaitIdleEventuallyReturns == (fenceState = "waiting") ~> (fenceState = "returned")
=============================================================================
