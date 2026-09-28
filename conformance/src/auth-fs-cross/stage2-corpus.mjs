// The static guard of the AUTH-FS-CROSS stage-2 program: what it may address, who it may act
// as, and that every stage-2 condition is observed through every transport the closure names.

import { STAGE2_CONDITIONS, STAGE2_PRINCIPALS, STAGE2_TENANTS } from "./programs-stage2.mjs";
import { RULESET_IDS } from "./stage2-rulesets.mjs";

const DOC = /^afc2-[a-z]+\/[a-z0-9-]+$/;
const COLLECTION = /^afc2-[a-z]+$/;
const NAME = /^[a-z0-9-]+$/;
const SDK_OPS = new Set([
  "signIn",
  "signOut",
  "refreshToken",
  "listen",
  "unlisten",
  "write",
  "writeLater",
  "remove",
  "offline",
  "online",
  "transaction",
  "continueTransaction",
]);
const AUTH_ACTIONS = new Set([
  "refresh",
  "revoke",
  "disable",
  "delete-account",
  "claims",
  "delete-tenant",
]);
const TRANSPORTS = new Set(["node-sdk", "browser"]);
/** The closure's transport names as this program's clients and streams spell them. */
const CLOSURE_TRANSPORT = { "node-sdk": "node-sdk", grpc: "grpc", "browser-webchannel": "browser" };
/** A sleep longer than this is a mistake: the window's long waits are the expiry probes. */
const SLEEP_LIMIT_MS = 5 * 60_000;
const WINDOW_LIMIT_MS = 60_000;
/** No client may be allowed more requests, or connections, than these. */
const WIRE_CAP_LIMIT = 300;
const CONNECTION_CAP_LIMIT = 100;

const fail = (where, message) => {
  throw new Error(`${where}: ${message}`);
};

function checkDoc(where, path) {
  if (typeof path !== "string" || !DOC.test(path))
    fail(where, `${path} is not a document of this lane (afc2-*)`);
}

/**
 * Refuses a program that could address anything but this lane's documents, act as an unknown
 * principal, use a client, stream, listener or mark before it exists, or leave a condition
 * without a row on one of its transports. Returns what the program costs in harness calls.
 */
export function validateStage2(program, { principals = STAGE2_PRINCIPALS, closure } = {}) {
  if (!/^auth-fs-cross\/stage2\/[a-z0-9-]+$/.test(program.id)) fail(program.id, "bad program id");
  if (!RULESET_IDS.includes(program.ruleset))
    fail(program.id, `unknown ruleset ${program.ruleset}`);
  for (const slot of program.tenants)
    if (!STAGE2_TENANTS.includes(slot)) fail(program.id, `unknown tenant slot ${slot}`);
  for (const name of program.principals) {
    const spec = principals[name];
    if (!spec) fail(program.id, `unknown principal ${name}`);
    if (spec.provider !== "admin-password")
      fail(name, "stage-2 principals are administrator-created password accounts");
    if (spec.tenant !== undefined && !program.tenants.includes(spec.tenant))
      fail(name, `unknown tenant slot ${spec.tenant}`);
  }
  for (const { doc } of program.seed) checkDoc(`${program.id} seed`, doc);

  const known = new Set(program.principals);
  const deleted = new Set();
  const deletedTenants = new Set();
  const streams = new Map();
  const clients = new Map();
  const marks = new Set();
  const commands = new Set();
  const rows = new Set();
  const covered = new Map(STAGE2_CONDITIONS.map((c) => [c, new Set()]));
  const cost = { commits: 1, reads: 0, rows: 0, maxWire: 0, maxConnections: 0 };

  const principal = (where, name) => {
    if (!known.has(name)) fail(where, `unknown principal ${name}`);
    if (deleted.has(name)) fail(where, `principal ${name} is used after its deletion`);
    const slot = principals[name].tenant;
    if (slot && deletedTenants.has(slot)) fail(where, `tenant ${slot} is used after its deletion`);
  };
  const openClient = (where, name) => {
    const client = clients.get(name);
    if (!client || client.closed) fail(where, `client ${name} is not open`);
    return client;
  };
  /** The transport of one listener reference, which must exist and be open. */
  const listenerTransport = (where, ref) => {
    if (ref.startsWith("grpc-")) {
      if (!streams.has(ref)) fail(where, `stream ${ref} is not open`);
      return "grpc";
    }
    const [name, listener] = ref.split("/");
    const client = openClient(where, name);
    if (!client.listeners.has(listener)) fail(where, `listener ${ref} does not exist`);
    return client.transport;
  };
  const conditionsOf = (where, step) => {
    const list = step.conditions ?? (step.condition ? [step.condition] : []);
    if (list.length === 0) fail(where, "a row names its condition");
    for (const c of list) if (!covered.has(c)) fail(where, `unknown condition ${c}`);
    return list;
  };
  const row = (where, step, transports) => {
    if (!NAME.test(step.id.replaceAll("/", "-"))) fail(where, `bad row id ${step.id}`);
    if (rows.has(step.id)) fail(where, `duplicate row ${step.id}`);
    rows.add(step.id);
    cost.rows += 1;
    for (const c of conditionsOf(where, step)) for (const t of transports) covered.get(c).add(t);
  };
  const windowOf = (where, step) => {
    if (step.windowMs !== undefined && !(step.windowMs > 0 && step.windowMs <= WINDOW_LIMIT_MS))
      fail(where, `window ${step.windowMs} out of range`);
  };

  /** One expiry probe group: its offset, how it is timed, and what it probes. */
  function expiryProbes(where, step) {
    if (!(step.plus >= -300 && step.plus <= 120)) fail(where, `plus ${step.plus} out of range`);
    if (step.align !== undefined && step.align !== "latest")
      fail(where, `unknown alignment ${step.align}`);
    if (!Array.isArray(step.probes) || step.probes.length === 0)
      fail(where, "an expiry group probes something");
    const transports = new Set();
    for (const probe of step.probes) {
      if (probe.token.principal !== undefined) {
        if (!known.has(probe.token.principal))
          fail(where, `unknown principal ${probe.token.principal}`);
      } else openClient(where, probe.token.client);
      checkDoc(where, probe.write.doc);
      for (const ref of probe.observe) transports.add(listenerTransport(where, ref));
      cost.commits += 1;
    }
    row(where, step, transports);
  }

  program.steps.forEach((step, index) => {
    const where = `${program.id}#${index}(${step.do})`;
    if (step.do === "close-all" && index !== program.steps.length - 1)
      fail(where, "close-all ends the program");
    if (step.mark !== undefined) {
      if (marks.has(step.mark)) fail(where, `duplicate mark ${step.mark}`);
      marks.add(step.mark);
    }
    switch (step.do) {
      case "stream": {
        if (!/^grpc-[a-z0-9-]+$/.test(step.name) || streams.has(step.name))
          fail(where, `bad or duplicate stream ${step.name}`);
        principal(where, step.as);
        if (!Array.isArray(step.targets) || step.targets.length === 0 || step.targets.length > 2)
          fail(where, "a stream has one or two targets");
        for (const target of step.targets) {
          if (target.document) checkDoc(where, target.document);
          else if (!COLLECTION.test(target.collection ?? ""))
            fail(where, `${target.collection} is not a collection of this lane`);
        }
        streams.set(step.name, { as: step.as });
        return;
      }
      case "client":
        if (!NAME.test(step.client) || clients.has(step.client))
          fail(where, `bad or duplicate client ${step.client}`);
        if (!TRANSPORTS.has(step.transport)) fail(where, `unknown transport ${step.transport}`);
        if (!(Number.isInteger(step.wireCap) && step.wireCap > 0 && step.wireCap <= WIRE_CAP_LIMIT))
          fail(where, `wire cap ${step.wireCap} out of range`);
        cost.maxWire += step.wireCap;
        if (
          !(
            Number.isInteger(step.connectionCap) &&
            step.connectionCap > 0 &&
            step.connectionCap <= CONNECTION_CAP_LIMIT
          )
        )
          fail(where, `connection cap ${step.connectionCap} out of range`);
        cost.maxConnections += step.connectionCap;
        clients.set(step.client, { transport: step.transport, listeners: new Set() });
        return;
      case "sdk": {
        const client = openClient(where, step.client);
        if (!SDK_OPS.has(step.op)) fail(where, `unknown op ${step.op}`);
        if (step.commandId !== undefined) {
          if (commands.has(step.commandId)) fail(where, `duplicate command ${step.commandId}`);
          commands.add(step.commandId);
        }
        if (step.op === "signIn") principal(where, step.as);
        if (step.op === "listen") {
          if (!NAME.test(step.name) || client.listeners.has(step.name))
            fail(where, `bad or duplicate listener ${step.name}`);
          if (step.path) checkDoc(where, step.path);
          else if (!COLLECTION.test(step.collection ?? ""))
            fail(where, `${step.collection} is not a collection of this lane`);
          client.listeners.add(step.name);
        }
        if (step.op === "writeLater" || step.op === "write" || step.op === "remove")
          checkDoc(where, step.path);
        if (step.op === "transaction") {
          for (const path of step.reads) checkDoc(where, path);
          checkDoc(where, step.write.path);
          if (step.await !== false || !step.commandId)
            fail(where, "a transaction is sent without waiting and awaited by its command id");
        }
        return;
      }
      case "await": {
        const client = openClient(where, step.client);
        if (step.event === "result") {
          if (!commands.has(step.commandId)) fail(where, `unknown command ${step.commandId}`);
          if (step.since !== undefined && !marks.has(step.since))
            fail(where, `unknown mark ${step.since}`);
          if (step.id !== undefined) row(where, step, [client.transport]);
        } else if (step.event !== "transaction-read") fail(where, `unknown event ${step.event}`);
        return;
      }
      case "probe":
      case "observe": {
        windowOf(where, step);
        if (step.do === "probe") {
          if (!Array.isArray(step.writes) || step.writes.length === 0)
            fail(where, "a probe commits at least one document");
          for (const { doc } of step.writes) checkDoc(where, doc);
          cost.commits += 1;
        }
        if (step.since !== undefined && !marks.has(step.since))
          fail(where, `unknown mark ${step.since}`);
        const transports = new Set((step.observe ?? []).map((r) => listenerTransport(where, r)));
        for (const name of step.clients ?? []) transports.add(openClient(where, name).transport);
        if (transports.size === 0) fail(where, "an observation watches something");
        row(where, step, transports);
        return;
      }
      case "server":
        // The client whose writes the owner's read shows (its cap marks the row too).
        if (step.client !== undefined) openClient(where, step.client);
        for (const doc of step.docs) checkDoc(where, doc);
        cost.reads += step.docs.length;
        row(where, step, []);
        return;
      case "auth":
        if (!AUTH_ACTIONS.has(step.action)) fail(where, `unknown action ${step.action}`);
        if (step.action === "delete-tenant") {
          if (!program.tenants.includes(step.tenant)) fail(where, `unknown tenant ${step.tenant}`);
          deletedTenants.add(step.tenant);
        } else {
          principal(where, step.principal);
          if (step.action === "delete-account") deleted.add(step.principal);
        }
        return;
      case "sleep":
        if (!(step.ms > 0 && step.ms <= SLEEP_LIMIT_MS))
          fail(where, `sleep ${step.ms} out of range`);
        return;
      case "expiry-probes":
        expiryProbes(where, step);
        return;
      case "expiry-groups":
        if (!Array.isArray(step.groups) || step.groups.length === 0)
          fail(where, "expiry groups name at least one group");
        for (const group of step.groups) expiryProbes(`${where}/${group.id}`, group);
        return;
      case "close-client":
        openClient(where, step.client).closed = true;
        return;
      case "close-all":
        // How each listener ended is recorded, but it covers no transport by itself.
        row(where, step, []);
        return;
      default:
        fail(where, `unknown step ${step.do}`);
    }
  });
  if (program.steps.at(-1)?.do !== "close-all") fail(program.id, "the program ends with close-all");

  for (const [condition, transports] of covered) {
    if (transports.size === 0) fail(condition, "has no row");
    const required = closure?.[condition] ?? [];
    for (const name of required) {
      const transport = CLOSURE_TRANSPORT[name];
      if (!transport) fail(condition, `unknown closure transport ${name}`);
      if (!transports.has(transport)) fail(condition, `no row observes it through ${name}`);
    }
  }
  return cost;
}

/** The closure's transports per stage-2 condition, from the frozen closure JSON. */
export function closureTransports(closureJson) {
  return Object.fromEntries(
    closureJson.conditions
      .filter(({ stage }) => stage === 2)
      .map(({ conditionId, observation }) => [conditionId, observation.transports]),
  );
}
