------------------------ MODULE EventDeliveryTrace ------------------------
EXTENDS EventDelivery

CONSTANT TraceScenario

TraceGoalReached ==
    CASE TraceScenario = "success" ->
            \E e \in Events: state[e] = "Succeeded" /\ epoch = 0
      [] TraceScenario = "retry-exhaustion" ->
            \E e \in Events: state[e] = "DeadLettered" /\ epoch = 0
      [] TraceScenario = "stale-discard" ->
            \E e \in Events: state[e] = "DiscardedStaleEpoch" /\ epoch = 1
      [] TraceScenario = "cancel" ->
            \E e \in Events:
                /\ state[e] = "Cancelled"
                /\ lastAction = "Cancel"
                /\ previousState[e] = "Leased"
                /\ epoch = 0
      [] OTHER -> FALSE

TraceGoalNotReached == ~TraceGoalReached
=============================================================================
