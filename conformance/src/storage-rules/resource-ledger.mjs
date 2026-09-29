import { REQUIRES_REGISTRY } from "./predicates.mjs";
import { plain } from "./shape.mjs";

// What the run has done to each owned resource and what it may therefore do next. This slice covers the 344 owned
// objects: baseline absence, writes attempted (a mutation is never attempted twice, whatever ID carries it), the latest
// readback, and the guards that read them. A create whose answer is unknown is never owned. Guards for anything else
// (Firestore documents, sessions, Rules resources, witnesses, credentials, inputs) are reported as unresolved so no
// caller can read a `go` as more than it is. The ledger sends nothing and keeps no value that could be a secret.
const bad = (message) => { throw new Error(message); };
const OBJECT_TOKENS = new Set(["owned-namespace-and-absence", "confirmed-write-history-and-current-version", "delete-not-attempted", "object-not-absent-per-latest-readback", "resource-started-and-provenance-matches"]);
const READ_KINDS = new Set(["gcs-metadata-read", "gcs-media-read"]);

export function createResourceLedger(options) {
  const fail = () => bad("invalid resource ledger options");
  if (!plain(options) || Reflect.ownKeys(options).length !== 1 || !Object.hasOwn(options, "manifest")) fail();
  const manifest = Object.getOwnPropertyDescriptor(options, "manifest")?.value;
  if (!manifest || manifest.sendAuthorized !== false || !Array.isArray(manifest.resources?.objects) || manifest.resources.objects.length === 0) fail();
  const objects = new Map(manifest.resources.objects.map((name) => [name, {
    name, baselineAbsent: false, foreign: false, started: false, writes: 0, deleteAttempted: false, uncertainCreate: false, uncertainOther: false,
    confirmedWrite: false, latest: "unknown", generation: null, metageneration: null, seedGeneration: null,
  }]));
  const mutations = new Set();

  function recordFor(row) {
    if (!row || typeof row !== "object" || typeof row.id !== "string" || !plain(row.request)) bad("invalid resource ledger row");
    const name = row.request.objectName;
    if (typeof name !== "string" || !objects.has(name)) bad("unowned resource");
    return objects.get(name);
  }
  // Session start, query and cancel rows belong to the session, not to the object; a finalize writes the object.
  const isSessionControl = (row) => ["start", "query", "cancel"].includes(row?.request?.headers?.["x-goog-upload-command"]);
  const isObjectRow = (row) => row?.service === "storage" && typeof row?.request?.objectName === "string" && !isSessionControl(row);
  const verbOf = (row) => {
    const { method, operation } = row.request;
    if (!["POST", "PATCH", "PUT", "DELETE"].includes(method)) return null;
    return operation === "delete" || method === "DELETE" ? "delete" : operation === "patch" || method === "PATCH" ? "patch" : "create";
  };
  const mutationKey = (row, verb) => (verb === "delete" ? `object|${row.request.objectName}|delete` : `object|${row.request.objectName}|${verb}|${row.id}`);

  function recordIntent(row) {
    if (!isObjectRow(row)) return;
    const object = recordFor(row);
    const verb = verbOf(row);
    if (verb === null) return;
    const key = mutationKey(row, verb);
    if (mutations.has(key)) bad("mutation already attempted");
    mutations.add(key);
    object.started = true;
    object.writes++;
    object.latest = "unknown";
    if (verb === "delete") object.deleteAttempted = true;
  }

  function recordOutcome(row, outcome) {
    if (!isObjectRow(row)) return;
    const object = recordFor(row);
    const uncertain = plain(outcome) && Reflect.ownKeys(outcome).length === 1 && outcome.uncertain === true;
    if (!uncertain && (!plain(outcome) || Reflect.ownKeys(outcome).length !== 3 || typeof outcome.kind !== "string" || typeof outcome.verdict !== "string" || !plain(outcome.facts))) bad("invalid resource ledger outcome");
    const verb = verbOf(row);
    if (uncertain) {
      if (verb === "create") object.uncertainCreate = true;
      else if (verb !== null) object.uncertainOther = true;
      object.latest = "unknown";
      return;
    }
    const { kind, verdict, facts } = outcome;
    if (READ_KINDS.has(kind)) {
      if (verdict === "absent") {
        object.latest = "absent"; object.generation = null; object.metageneration = null;
        if (!object.started && !object.foreign) object.baselineAbsent = true;
      } else if (verdict === "present") {
        object.latest = "present";
        if (typeof facts.generation === "string") object.generation = facts.generation;
        if (typeof facts.metageneration === "string") object.metageneration = facts.metageneration;
        if (!object.started) { object.foreign = true; object.baselineAbsent = false; }
      } else object.latest = "unknown";
      return;
    }
    if (verb === "create" && kind === "gcs-seed-upload") {
      if (verdict === "accepted" && typeof facts.generation === "string") {
        object.latest = "present"; object.generation = facts.generation; object.metageneration = facts.metageneration ?? null; object.confirmedWrite = true;
        if (object.seedGeneration === null) object.seedGeneration = facts.generation;
      } else { object.uncertainCreate = true; object.latest = "unknown"; }
      return;
    }
    if (verb === "delete") {
      if (verdict !== "accepted") object.uncertainOther = true;
      object.latest = "unknown";
      return;
    }
    if (verb !== null) {
      if (verdict === "unexpected") object.uncertainOther = true;
      object.latest = "unknown";
    }
  }

  const owned = (object) => object.baselineAbsent && !object.foreign && !object.uncertainCreate;
  const HANDLERS = {
    // A write needs the object shown absent first; a read that carries the token is the read that shows it (its verdict is then required to be absent).
    "owned-namespace-and-absence": (object, row) => (row.request.method === "GET" ? true : owned(object) && object.latest === "absent"),
    "confirmed-write-history-and-current-version": (object) => object.started && !object.uncertainCreate && object.latest === "present" && object.generation !== null,
    "delete-not-attempted": (object) => !object.deleteAttempted,
    // Nothing to remove is a skip; only an object the run touched whose state is now unknown is a doubt that stops the run.
    "object-not-absent-per-latest-readback": (object) => (object.latest === "present" ? true : object.latest === "absent" || !object.started ? false : "unknown"),
    "resource-started-and-provenance-matches": (object) => object.started,
  };

  function evaluate(row) {
    if (!row || typeof row !== "object" || !Array.isArray(row.requires) || typeof row.id !== "string") bad("invalid resource ledger row");
    const tokens = row.requires.filter((token) => Object.hasOwn(REQUIRES_REGISTRY, token));
    // Some tokens name a guard for every resource kind; this ledger answers them for objects only.
    const handled = isObjectRow(row) ? tokens.filter((token) => OBJECT_TOKENS.has(token)) : [];
    const unresolved = tokens.filter((token) => !handled.includes(token));
    const failed = [];
    let skip = false;
    if (handled.length > 0) {
      const object = recordFor(row);
      for (const token of handled) {
        const result = HANDLERS[token](object, row);
        if (result === true) continue;
        const outcome = result === "unknown" ? "stop" : REQUIRES_REGISTRY[token].onFalse;
        failed.push(Object.freeze({ token, outcome }));
        if (outcome === "skip") skip = true;
      }
    } else if (isObjectRow(row)) recordFor(row);
    const decision = skip ? "skip" : failed.some((entry) => entry.outcome === "stop") ? "stop" : "go";
    return Object.freeze({ decision, failed: Object.freeze(failed), unresolved: Object.freeze(unresolved) });
  }

  return Object.freeze({
    recordIntent, recordOutcome, evaluate,
    object(name) {
      if (typeof name !== "string" || !objects.has(name)) bad("unowned resource");
      const o = objects.get(name);
      return Object.freeze({ name, owned: owned(o), deletable: owned(o) && o.started && o.latest === "present" && !o.uncertainOther, started: o.started, latest: o.latest, generation: o.generation, metageneration: o.metageneration, seedGeneration: o.seedGeneration, deleteAttempted: o.deleteAttempted });
    },
    tokens: () => Object.freeze([...OBJECT_TOKENS].sort()),
    /** Names of objects the run started and has not proven absent again; each needs recovery or a delete. */
    residual: () => Object.freeze([...objects.values()].filter((o) => (o.started || o.foreign) && !(o.latest === "absent" && !o.uncertainCreate)).map((o) => o.name)),
    snapshot: () => Object.freeze({ objects: objects.size, started: [...objects.values()].filter((o) => o.started).length, mutations: mutations.size }),
  });
}
