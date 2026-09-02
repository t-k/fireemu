// Compatibility auth routing and Functions Node selection.

module CompatibilitySelectionProof {
  pure val PROJECTS = Set("default", "worker-a", "worker-b")
  pure val ROUTED = Set("worker-a", "worker-b")
  pure val STORES = Set("store-default", "store-a", "store-b")
  pure val NODES = Set("node22old", "node20new", "node22new")

  var storeOf: str -> str
  var userProjects: Set[str]
  var lockedProjects: Set[str]
  var authDecision: str
  var automaticNode: str
  var explicitNode: str
  var phase: str

  def installed(project: str): bool = storeOf.get(project) != "none"
  pure def capable(node: str): bool = node != "node22old"
  pure def requested(node: str): bool = node != "node20new"

  action init = all {
    storeOf' = Map(
      "default" -> "store-default",
      "worker-a" -> "none",
      "worker-b" -> "none"
    ),
    userProjects' = Set(),
    lockedProjects' = Set(),
    authDecision' = "pending",
    automaticNode' = "pending",
    explicitNode' = "pending",
    phase' = "setup",
  }

  action installRouted(project, store) = all {
    phase == "setup",
    project.in(ROUTED),
    storeOf.get(project) == "none",
    store.in(STORES),
    PROJECTS.forall(other => not(installed(other)) or storeOf.get(other) != store),
    storeOf' = storeOf.set(project, store),
    userProjects' = userProjects,
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }

  action rejectAliasedInstall = all {
    phase == "setup",
    storeOf' = storeOf,
    userProjects' = userProjects,
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }

  action addUser(project) = all {
    phase.in(Set("setup", "scanning")),
    installed(project),
    not(project.in(lockedProjects)),
    storeOf' = storeOf,
    userProjects' = userProjects.union(Set(project)),
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }

  action removeUser(project) = all {
    phase.in(Set("setup", "scanning")),
    installed(project),
    not(project.in(lockedProjects)),
    storeOf' = storeOf,
    userProjects' = userProjects.exclude(Set(project)),
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }

  action beginExchange = all {
    phase == "setup",
    storeOf' = storeOf,
    userProjects' = userProjects,
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = "scanning",
  }

  action lockProject(project) = all {
    phase == "scanning",
    installed(project),
    not(project.in(lockedProjects)),
    storeOf' = storeOf,
    userProjects' = userProjects,
    lockedProjects' = lockedProjects.union(Set(project)),
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }

  action exchange = all {
    phase == "scanning",
    lockedProjects == PROJECTS.filter(installed),
    storeOf' = storeOf,
    userProjects' = userProjects,
    lockedProjects' = lockedProjects,
    authDecision' = if (userProjects.size() == 0) "default"
      else if (userProjects.size() == 1) {
        if ("default".in(userProjects)) "default"
        else if ("worker-a".in(userProjects)) "worker-a" else "worker-b"
      } else "deny",
    automaticNode' = "node22new",
    explicitNode' = "node22old",
    phase' = "done",
  }

  action InstallRouted = { nondet project = ROUTED.oneOf() nondet store = STORES.oneOf() installRouted(project, store) }
  action RejectAliasedInstall = rejectAliasedInstall
  action AddUser = { nondet project = PROJECTS.oneOf() addUser(project) }
  action RemoveUser = { nondet project = PROJECTS.oneOf() removeUser(project) }
  action BeginExchange = beginExchange
  action LockProject = { nondet project = PROJECTS.oneOf() lockProject(project) }
  action Exchange = exchange
  action Done = all {
    phase == "done",
    storeOf' = storeOf,
    userProjects' = userProjects,
    lockedProjects' = lockedProjects,
    authDecision' = authDecision,
    automaticNode' = automaticNode,
    explicitNode' = explicitNode,
    phase' = phase,
  }
  action step = any { InstallRouted, RejectAliasedInstall, AddUser, RemoveUser, BeginExchange, LockProject, Exchange, Done }

  val TypeOK = and {
    storeOf.keys() == PROJECTS,
    PROJECTS.forall(project => storeOf.get(project).in(STORES.union(Set("none")))),
    storeOf.get("default") == "store-default",
    userProjects.subseteq(PROJECTS.filter(installed)),
    lockedProjects.subseteq(PROJECTS.filter(installed)),
    authDecision.in(PROJECTS.union(Set("pending", "deny"))),
    automaticNode.in(NODES.union(Set("pending"))),
    explicitNode.in(NODES.union(Set("pending"))),
    phase.in(Set("setup", "scanning", "done")),
  }

  val NoStoreAliases = PROJECTS.forall(left => PROJECTS.forall(right =>
    not(installed(left)) or not(installed(right)) or storeOf.get(left) != storeOf.get(right) or left == right
  ))
  val UniqueUserRoutesToItsProject = (phase == "done" and userProjects.size() == 1)
    .implies(authDecision.in(userProjects))
  val UnknownUserUsesDefault = (phase == "done" and userProjects.size() == 0)
    .implies(authDecision == "default")
  val AmbiguousUserIsDenied = (phase == "done" and userProjects.size() > 1)
    .implies(authDecision == "deny")
  val AutomaticSelectionIsCapable = (phase == "done").implies(capable(automaticNode))
  val RequestedNodeBreaksCapabilityTies = (phase == "done").implies(requested(automaticNode))
  val ExplicitSelectionIsStable = (phase == "done").implies(explicitNode == "node22old")
}

module CompatibilitySelectionConnect {
  type Observable = {
    lastCase: str,
    authDecision: str,
    automaticNode: str,
    explicitNode: str,
    storeAliases: bool,
  }
  type ActionTaken = { tag: str, value: { case: str } }
  pure val CASES = Set("default", "unique", "ambiguous", "concurrentMove", "alias", "capability", "runtime", "engine", "explicit")
  var observable: Observable
  var actionTaken: ActionTaken

  pure def expected(case: str): Observable = {
    lastCase: case,
    authDecision: if (case == "unique") "worker-a"
      else if (case == "concurrentMove") "worker-b"
      else if (case == "ambiguous") "deny" else "default",
    automaticNode: if (case == "runtime") "node20new" else "node22new",
    explicitNode: "node22old",
    storeAliases: false,
  }

  action init = all {
    observable' = { lastCase: "none", authDecision: "pending", automaticNode: "pending", explicitNode: "pending", storeAliases: false },
    actionTaken' = { tag: "init", value: { case: "none" } },
  }
  action evaluateCase(case) = all {
    observable.lastCase == "none",
    case.in(CASES),
    observable' = expected(case),
    actionTaken' = { tag: "Evaluate", value: { case: case } },
  }
  action Evaluate = { nondet case = CASES.oneOf() evaluateCase(case) }
  action step = Evaluate
}

module CompatibilitySelectionScenarios {
  import CompatibilitySelectionConnect.*
  run default = init.then(evaluateCase("default"))
  run unique = init.then(evaluateCase("unique"))
  run ambiguous = init.then(evaluateCase("ambiguous"))
  run concurrentMove = init.then(evaluateCase("concurrentMove"))
  run alias = init.then(evaluateCase("alias"))
  run capability = init.then(evaluateCase("capability"))
  run runtime = init.then(evaluateCase("runtime"))
  run engine = init.then(evaluateCase("engine"))
  run explicit = init.then(evaluateCase("explicit"))
}
