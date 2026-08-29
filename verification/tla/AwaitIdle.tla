------------------------------ MODULE AwaitIdle ------------------------------
(***************************************************************************)
(* The await-idle fence (spec 10.5, INV-IDLE-001, LIVE-IDLE-001).          *)
(*                                                                         *)
(* Work items are causal: a running item may spawn a child.  Between the   *)
(* parent's completion and the child's enqueue the parent holds a          *)
(* reservation, which must count as active work.  Text Index builds are    *)
(* fenced by default and may only be ignored by explicit option.           *)
(*                                                                         *)
(* Properties                                                              *)
(*   INV-IDLE-001  NoFalseIdle                                             *)
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
          fenceState  \* "none" | "waiting" | "returned"

vars == <<active, reserved, kind, depth, used, fenced, fenceState>>

Fenced(i) == \/ kind[i] # "textIndexBuild"
             \/ ~IgnoreTextIndex

\* Active work that the fence must wait for.
Blocking == {i \in (active \cup reserved) : i \in fenced /\ Fenced(i)}

TypeOK ==
    /\ active \subseteq Items
    /\ reserved \subseteq Items
    /\ kind \in [Items -> Kinds]
    /\ depth \in [Items -> 0..MaxDepth]
    /\ used \subseteq Items
    /\ fenced \subseteq Items
    /\ fenceState \in {"none", "waiting", "returned"}

Init ==
    /\ active = {}
    /\ reserved = {}
    /\ kind \in [Items -> Kinds]
    /\ depth = [i \in Items |-> 0]
    /\ used = {}
    /\ fenced = {}
    /\ fenceState = "none"

\* Fresh identities not yet promised to a pending reservation. In the real system child IDs
\* are unbounded; the bounded model must never let a reservation starve for lack of an ID.
FreshAvailable == Cardinality(Items \ used) > Cardinality(reserved)

\* External input: only before the fence is requested (liveness assumption).
BeginExternal(i) ==
    /\ fenceState = "none"
    /\ i \notin used
    /\ FreshAvailable
    /\ active' = active \cup {i}
    /\ used' = used \cup {i}
    /\ depth' = [depth EXCEPT ![i] = 0]
    /\ UNCHANGED <<reserved, kind, fenced, fenceState>>

\* Completion without a child.
CompleteLeaf(i) ==
    /\ i \in active
    /\ active' = active \ {i}
    /\ UNCHANGED <<reserved, kind, depth, used, fenced, fenceState>>

\* Completion that will spawn a child: hold a reservation until the child is enqueued.
CompleteWithReservation(i) ==
    /\ i \in active
    /\ depth[i] < MaxDepth
    /\ FreshAvailable
    /\ active' = active \ {i}
    /\ reserved' = reserved \cup {i}
    /\ UNCHANGED <<kind, depth, used, fenced, fenceState>>

\* The child is enqueued and the reservation released atomically. A child of a fenced
\* parent is fenced (causal tree).
EnqueueChild(p, c) ==
    /\ p \in reserved
    /\ c \notin used
    /\ reserved' = reserved \ {p}
    /\ active' = active \cup {c}
    /\ used' = used \cup {c}
    /\ depth' = [depth EXCEPT ![c] = depth[p] + 1]
    /\ fenced' = IF p \in fenced THEN fenced \cup {c} ELSE fenced
    /\ UNCHANGED <<kind, fenceState>>

RequestFence ==
    /\ fenceState = "none"
    /\ fenceState' = "waiting"
    /\ fenced' = active \cup reserved
    /\ UNCHANGED <<active, reserved, kind, depth, used>>

ReturnIdle ==
    /\ fenceState = "waiting"
    /\ Blocking = {}
    /\ fenceState' = "returned"
    /\ UNCHANGED <<active, reserved, kind, depth, used, fenced>>

Next ==
    \/ RequestFence
    \/ ReturnIdle
    \/ \E i \in Items: BeginExternal(i) \/ CompleteLeaf(i) \/ CompleteWithReservation(i)
    \/ \E p \in Items, c \in Items: EnqueueChild(p, c)

Fairness ==
    /\ \A i \in Items: WF_vars(CompleteLeaf(i) \/ CompleteWithReservation(i))
    /\ \A p \in Items, c \in Items: WF_vars(EnqueueChild(p, c))
    /\ WF_vars(ReturnIdle)

Spec == Init /\ [][Next]_vars /\ Fairness

-----------------------------------------------------------------------------
\* INV-IDLE-001: once idle has been returned, no fenced work is active or reserved.
NoFalseIdle == fenceState = "returned" => Blocking = {}

\* Stronger form: after the fence returns, fenced items never become active again.
FencedWorkStaysTerminal ==
    [][fenceState = "returned" => Blocking' = {}]_vars

\* LIVE-IDLE-001
AwaitIdleEventuallyReturns == (fenceState = "waiting") ~> (fenceState = "returned")
=============================================================================
