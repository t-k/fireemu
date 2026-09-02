----------------------- MODULE CompatibilitySelection -----------------------
EXTENDS FiniteSets, Naturals

CONSTANTS DefaultProject, RoutedProjects, StoreIds, DefaultStore, Nodes, ExplicitNode

ASSUME DefaultProject \notin RoutedProjects
ASSUME Cardinality(RoutedProjects) > 0
ASSUME DefaultStore \in StoreIds
ASSUME ExplicitNode \in Nodes

Projects == {DefaultProject} \union RoutedProjects
NoStore == "none"

VARIABLES storeOf, userProjects, lockedProjects, authDecision, automaticNode, explicitNode, phase

vars == <<storeOf, userProjects, lockedProjects, authDecision, automaticNode, explicitNode, phase>>

InstalledProjects == {project \in Projects : storeOf[project] # NoStore}

InstalledStoreIds == {storeOf[project] : project \in InstalledProjects}

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
  /\ storeOf = [project \in Projects |->
       IF project = DefaultProject THEN DefaultStore ELSE NoStore]
  /\ userProjects = {}
  /\ lockedProjects = {}
  /\ authDecision = "pending"
  /\ automaticNode = "pending"
  /\ explicitNode = "pending"
  /\ phase = "setup"

InstallRouted(project, store) ==
  /\ phase = "setup"
  /\ project \in RoutedProjects
  /\ storeOf[project] = NoStore
  /\ store \in StoreIds \ InstalledStoreIds
  /\ storeOf' = [storeOf EXCEPT ![project] = store]
  /\ UNCHANGED <<userProjects, lockedProjects, authDecision, automaticNode, explicitNode, phase>>

RejectAliasedInstall(project, source) ==
  /\ phase = "setup"
  /\ project \in RoutedProjects
  /\ storeOf[project] = NoStore
  /\ source \in InstalledProjects
  /\ UNCHANGED vars

AddUser(project) ==
  /\ phase \in {"setup", "scanning"}
  /\ project \in InstalledProjects
  /\ project \notin lockedProjects
  /\ userProjects' = userProjects \union {project}
  /\ UNCHANGED <<storeOf, lockedProjects, authDecision, automaticNode, explicitNode, phase>>

RemoveUser(project) ==
  /\ phase \in {"setup", "scanning"}
  /\ project \in InstalledProjects
  /\ project \notin lockedProjects
  /\ userProjects' = userProjects \ {project}
  /\ UNCHANGED <<storeOf, lockedProjects, authDecision, automaticNode, explicitNode, phase>>

BeginExchange ==
  /\ phase = "setup"
  /\ phase' = "scanning"
  /\ UNCHANGED <<storeOf, userProjects, lockedProjects, authDecision, automaticNode, explicitNode>>

LockProject(project) ==
  /\ phase = "scanning"
  /\ project \in InstalledProjects \ lockedProjects
  /\ lockedProjects' = lockedProjects \union {project}
  /\ UNCHANGED <<storeOf, userProjects, authDecision, automaticNode, explicitNode, phase>>

Exchange ==
  /\ phase = "scanning"
  /\ lockedProjects = InstalledProjects
  /\ authDecision' =
       IF Cardinality(userProjects) = 0
       THEN DefaultProject
       ELSE IF Cardinality(userProjects) = 1
            THEN CHOOSE project \in userProjects : TRUE
            ELSE "deny"
  /\ automaticNode' = AutomaticChoice
  /\ explicitNode' = ExplicitNode
  /\ phase' = "done"
  /\ UNCHANGED <<storeOf, userProjects, lockedProjects>>

Done ==
  /\ phase = "done"
  /\ UNCHANGED vars

Next ==
  \/ \E project \in RoutedProjects, store \in StoreIds : InstallRouted(project, store)
  \/ \E project \in RoutedProjects, source \in Projects : RejectAliasedInstall(project, source)
  \/ \E project \in InstalledProjects : AddUser(project)
  \/ \E project \in InstalledProjects : RemoveUser(project)
  \/ BeginExchange
  \/ \E project \in InstalledProjects : LockProject(project)
  \/ Exchange
  \/ Done

Spec == Init /\ [][Next]_vars

TypeOK ==
  /\ storeOf \in [Projects -> StoreIds \union {NoStore}]
  /\ storeOf[DefaultProject] = DefaultStore
  /\ userProjects \subseteq InstalledProjects
  /\ lockedProjects \subseteq InstalledProjects
  /\ authDecision \in Projects \union {"pending", "deny"}
  /\ automaticNode \in Nodes \union {"pending"}
  /\ explicitNode \in Nodes \union {"pending"}
  /\ phase \in {"setup", "scanning", "done"}

NoStoreAliases ==
  \A left, right \in InstalledProjects :
    storeOf[left] = storeOf[right] => left = right

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
