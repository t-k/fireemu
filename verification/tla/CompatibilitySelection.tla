----------------------- MODULE CompatibilitySelection -----------------------
EXTENDS FiniteSets, Naturals

CONSTANTS DefaultProject, RoutedProjects, Nodes, ExplicitNode

ASSUME DefaultProject \notin RoutedProjects
ASSUME Cardinality(RoutedProjects) > 0
ASSUME ExplicitNode \in Nodes

Projects == {DefaultProject} \union RoutedProjects

VARIABLES userProjects, lockedProjects, authDecision, automaticNode, explicitNode, phase

vars == <<userProjects, lockedProjects, authDecision, automaticNode, explicitNode, phase>>

NodeCapability == [
  node \in Nodes |->
    CASE node = "node22old" -> FALSE
      [] node = "node20new" -> TRUE
      [] OTHER -> TRUE
]

NodeRequested == [
  node \in Nodes |->
    CASE node = "node20new" -> FALSE
      [] OTHER -> TRUE
]

NodeOrder == [
  node \in Nodes |->
    CASE node = "node22old" -> 1
      [] node = "node20new" -> 2
      [] OTHER -> 3
]

BetterNode(left, right) ==
  /\ left \in Nodes
  /\ right \in Nodes
  /\ \/ NodeCapability[left] /\ ~NodeCapability[right]
     \/ NodeCapability[left] = NodeCapability[right]
        /\ NodeRequested[left] /\ ~NodeRequested[right]
     \/ NodeCapability[left] = NodeCapability[right]
        /\ NodeRequested[left] = NodeRequested[right]
        /\ NodeOrder[left] < NodeOrder[right]

AutomaticChoice ==
  CHOOSE node \in Nodes : \A other \in Nodes : ~BetterNode(other, node)

Init ==
  /\ userProjects = {}
  /\ lockedProjects = {}
  /\ authDecision = "pending"
  /\ automaticNode = "pending"
  /\ explicitNode = "pending"
  /\ phase = "setup"

AddUser(project) ==
  /\ phase \in {"setup", "scanning"}
  /\ project \in Projects
  /\ project \notin lockedProjects
  /\ userProjects' = userProjects \union {project}
  /\ UNCHANGED <<lockedProjects, authDecision, automaticNode, explicitNode, phase>>

RemoveUser(project) ==
  /\ phase \in {"setup", "scanning"}
  /\ project \in Projects
  /\ project \notin lockedProjects
  /\ userProjects' = userProjects \ {project}
  /\ UNCHANGED <<lockedProjects, authDecision, automaticNode, explicitNode, phase>>

BeginExchange ==
  /\ phase = "setup"
  /\ phase' = "scanning"
  /\ UNCHANGED <<userProjects, lockedProjects, authDecision, automaticNode, explicitNode>>

LockProject(project) ==
  /\ phase = "scanning"
  /\ project \in Projects \ lockedProjects
  /\ lockedProjects' = lockedProjects \union {project}
  /\ UNCHANGED <<userProjects, authDecision, automaticNode, explicitNode, phase>>

Exchange ==
  /\ phase = "scanning"
  /\ lockedProjects = Projects
  /\ authDecision' =
       IF Cardinality(userProjects) = 0
       THEN DefaultProject
       ELSE IF Cardinality(userProjects) = 1
            THEN CHOOSE project \in userProjects : TRUE
            ELSE "deny"
  /\ automaticNode' = AutomaticChoice
  /\ explicitNode' = ExplicitNode
  /\ phase' = "done"
  /\ UNCHANGED <<userProjects, lockedProjects>>

Done ==
  /\ phase = "done"
  /\ UNCHANGED vars

Next ==
  \/ \E project \in Projects : AddUser(project)
  \/ \E project \in Projects : RemoveUser(project)
  \/ BeginExchange
  \/ \E project \in Projects : LockProject(project)
  \/ Exchange
  \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ userProjects \subseteq Projects
  /\ lockedProjects \subseteq Projects
  /\ authDecision \in Projects \union {"pending", "deny"}
  /\ automaticNode \in Nodes \union {"pending"}
  /\ explicitNode \in Nodes \union {"pending"}
  /\ phase \in {"setup", "scanning", "done"}

UniqueUserRoutesToItsProject ==
  phase = "done" /\ Cardinality(userProjects) = 1
  => authDecision \in userProjects

UnknownUserUsesDefault ==
  phase = "done" /\ Cardinality(userProjects) = 0
  => authDecision = DefaultProject

AmbiguousUserIsDenied ==
  phase = "done" /\ Cardinality(userProjects) > 1
  => authDecision = "deny"

AutomaticSelectionIsCapable ==
  phase = "done" /\ (\E node \in Nodes : NodeCapability[node])
  => NodeCapability[automaticNode]

RequestedNodeBreaksCapabilityTies ==
  phase = "done"
  /\ (\E node \in Nodes : NodeCapability[node] /\ NodeRequested[node])
  => NodeRequested[automaticNode]

ExplicitSelectionIsStable ==
  phase = "done" => explicitNode = ExplicitNode

=============================================================================
