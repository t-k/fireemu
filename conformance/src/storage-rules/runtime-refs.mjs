import { createHash } from "node:crypto";
import { acceptanceKindOf } from "./acceptance.mjs";
import { isTimestamp } from "./acceptance-core.mjs";

// Run-time values that only exist after an accepted response: object generations and metagenerations, Firestore update
// times, Ruleset names (and the paths derived from them) and list page tokens. A value is bound to the run only through
// a declared producer row and becomes resolvable, by a declared consumer only, after its proof is durable. The proof
// carries a salted digest, never the value. Auth fixtures, OAuth bodies and session URLs are outside this store.
export const RUNTIME_REF_KINDS = Object.freeze(["generation", "metageneration", "update-time", "ruleset-name", "ruleset-path", "page-token"]);
const QUERY_PROJECT = "fireemu-oracle-query";
const GRAMMARS = Object.freeze({
  generation: (value) => /^[1-9]\d{0,18}$/.test(value),
  metageneration: (value) => /^[1-9]\d{0,18}$/.test(value),
  "update-time": (value) => isTimestamp(value),
  "ruleset-name": (value) => new RegExp(`^projects/${QUERY_PROJECT}/rulesets/[A-Za-z0-9_-]{1,128}$`).test(value),
  "page-token": (value) => /^[A-Za-z0-9._~+/=-]{1,2048}$/.test(value),
});
const RULESET_ID = "[A-Za-z0-9_-]{1,128}";
/** Whether a value is well formed for one runtime reference kind; `ruleset-path` is the `/v1/` form of a `ruleset-name`. */
export function isValidRefValue(type, value) {
  if (typeof value !== "string") return false;
  if (type === "ruleset-path") return new RegExp(`^/v1/projects/${QUERY_PROJECT}/rulesets/${RULESET_ID}$`).test(value);
  return Object.hasOwn(GRAMMARS, type) && GRAMMARS[type](value);
}
const SUPERSEDABLE = new Set(["generation", "metageneration", "update-time"]);
const bad = (message) => { throw new Error(message); };
const own = (target, key) => Object.hasOwn(target, key);
const PRODUCER_KINDS = new Map([["gcs-seed-upload", "accepted"], ["gcs-patch", "accepted"], ["gcs-metadata-read", "present"]]);

function closedRecord(value, keys, message) {
  if (!value || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) bad(message);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) bad(message);
  for (const key of keys) {
    const field = Object.getOwnPropertyDescriptor(value, key);
    if (!field?.enumerable || !Object.hasOwn(field, "value")) bad(message);
  }
}

// The corpus's Firestore programs name two values in their own shape. They are the same facts, but each one is pinned to
// the step whose response must have produced it.
const NATIVE_REFS = Object.freeze({
  "firestore-update-time": Object.freeze({ type: "update-time", key: "documentName", field: "updateTime" }),
  "gcs-object-generation": Object.freeze({ type: "generation", key: "objectName", field: "generation" }),
});
function referenceOf(value) {
  if (!value || typeof value !== "object") return null;
  if (value.kind === "runtime-reference" && RUNTIME_REF_KINDS.includes(value.type) && typeof value.key === "string") return { type: value.type, key: value.key, fromStep: null };
  if (Object.hasOwn(NATIVE_REFS, value.kind)) {
    const native = NATIVE_REFS[value.kind];
    if (value.field === native.field && typeof value[native.key] === "string" && value[native.key] !== "" && typeof value.fromStep === "string" && value.fromStep !== "") return { type: native.type, key: value[native.key], fromStep: value.fromStep };
  }
  return null;
}

function collectReferences(row) {
  const found = [];
  const visit = (value) => {
    if (value && typeof value === "object") {
      const reference = referenceOf(value);
      if (reference) found.push(reference);
      for (const inner of Object.values(value)) visit(inner);
    }
  };
  visit(row.request);
  return found;
}

/** Derive who may produce and who may consume each declared reference from the full manifest. */
export function buildRefTables(manifest) {
  const consumers = Object.fromEntries(RUNTIME_REF_KINDS.map((type) => [type, {}]));
  const producers = Object.fromEntries(RUNTIME_REF_KINDS.map((type) => [type, {}]));
  const deleters = new Set();
  const pinned = {};
  const pinnedSteps = {};
  const byStep = new Map(manifest.rows.map((row) => [`${row.programId}\0${row.request?.id}`, row]));
  const add = (table, type, key, value) => { (table[type][key] ??= []); if (!table[type][key].some((entry) => JSON.stringify(entry) === JSON.stringify(value))) table[type][key].push(value); };
  for (const row of manifest.rows) {
    for (const reference of collectReferences(row)) {
      add(consumers, reference.type, reference.key, row.id);
      if (row.request.method === "DELETE" && ["generation", "update-time"].includes(reference.type)) deleters.add(`${reference.type}|${reference.key}|${row.id}`);
      if (reference.fromStep !== null) {
        const producer = byStep.get(`${row.programId}\0${reference.fromStep}`);
        if (!producer || producer.id === row.id || producer.request.credential !== "admin") bad("invalid reference tables");
        const verdict = reference.type === "generation" ? PRODUCER_KINDS.get(acceptanceKindOf(producer)) : "accepted";
        if (!verdict) bad("invalid reference tables");
        pinned[`${reference.type}|${reference.key}|${row.id}`] = producer.id;
        pinnedSteps[`${reference.type}|${reference.key}|${row.id}`] = reference.fromStep;
        add(producers, reference.type, reference.key, { operationId: producer.id, verdict });
      }
      if (reference.type === "page-token") {
        const match = /^(.*\/)([1-9]\d*)$/.exec(row.id);
        if (!match || Number(match[2]) < 2) bad("invalid reference tables");
        add(producers, "page-token", reference.key, { operationId: `${match[1]}${Number(match[2]) - 1}`, verdict: "accepted" });
      }
      if (reference.type === "ruleset-name") add(producers, "ruleset-name", reference.key, { operationId: `ruleset/${reference.key}/create`, verdict: "accepted" });
    }
  }
  const objectNames = new Set([...Object.keys(consumers.generation), ...Object.keys(consumers.metageneration)]);
  const documentNames = new Set(Object.keys(consumers["update-time"]));
  for (const row of manifest.rows) {
    const { objectName, documentName, credential } = row.request;
    if (row.stage !== "subject" && row.stage !== "comparison" && credential === "admin" && objectNames.has(objectName)) {
      const verdict = PRODUCER_KINDS.get(acceptanceKindOf(row));
      if (verdict) for (const type of ["generation", "metageneration"]) if (own(consumers[type], objectName)) add(producers, type, objectName, { operationId: row.id, verdict });
    }
    if (row.service === "firestore" && documentNames.has(documentName) && ["GET", "POST", "PATCH"].includes(row.request.method)) {
      add(producers, "update-time", documentName, { operationId: row.id, verdict: "accepted" });
    }
  }
  for (const type of RUNTIME_REF_KINDS) {
    for (const key of Object.keys(consumers[type])) Object.freeze(consumers[type][key]);
    for (const key of Object.keys(producers[type])) { for (const entry of producers[type][key]) Object.freeze(entry); Object.freeze(producers[type][key]); }
    Object.freeze(consumers[type]); Object.freeze(producers[type]);
  }
  return Object.freeze({ consumers: Object.freeze(consumers), producers: Object.freeze(producers), deleters: Object.freeze([...deleters].sort()), pinned: Object.freeze(pinned), pinnedSteps: Object.freeze(pinnedSteps) });
}

const digest = (salt, type, key, value) => createHash("sha256").update([salt, type, key, value].join("\0")).digest("hex");

/** A store of durable, consumer-checked runtime values. Inputs are validated as closed records. */
export function createRuntimeRefStore(options) {
  const fail = () => bad("invalid runtime reference store options");
  closedRecord(options, ["tables", "runId", "digestSalt", "writeProof"], "invalid runtime reference store options");
  const { tables, runId, digestSalt, writeProof } = options;
  if (typeof runId !== "string" || !/^[a-z0-9][a-z0-9-]{0,47}$/.test(runId) || typeof digestSalt !== "string" || !/^[0-9a-f]{64}$/.test(digestSalt) || typeof writeProof !== "function") fail();
  if (!tables || !tables.consumers || !tables.producers || !Array.isArray(tables.deleters) || RUNTIME_REF_KINDS.some((type) => !tables.consumers[type] || !tables.producers[type])) fail();
  const deleters = new Set(tables.deleters);
  const values = new Map();
  const byProducer = new Map();
  let busy = false;
  let uncertain = false;

  function readRef(reference, message, allowNative = false) {
    if (allowNative && reference && typeof reference === "object" && Object.hasOwn(NATIVE_REFS, reference.kind)) {
      const native = referenceOf(reference);
      if (!native) bad(message);
      return { type: native.type, key: native.key };
    }
    closedRecord(reference, ["kind", "type", "key", "resolveOnlyAfterDurableProof"], message);
    if (reference.kind !== "runtime-reference" || reference.resolveOnlyAfterDurableProof !== true || !RUNTIME_REF_KINDS.includes(reference.type) || typeof reference.key !== "string" || reference.key === "" || reference.key.length > 1024) bad(message);
    return { type: reference.type, key: reference.key };
  }

  async function bind(input) {
    if (uncertain) bad("runtime reference store is uncertain");
    if (busy) bad("runtime reference store is busy");
    const fail = () => bad("invalid runtime reference bind");
    closedRecord(input, ["ref", "value", "provenance"], "invalid runtime reference bind");
    const { type, key } = readRef(input.ref, "invalid runtime reference bind");
    const { value } = input;
    const provenance = input.provenance;
    closedRecord(provenance, ["operationId", "attempt", "verdict", "deletable"], "invalid runtime reference bind");
    if (type === "ruleset-path" || !own(tables.consumers[type], key) || typeof value !== "string" || !GRAMMARS[type](value)) fail();
    if (typeof provenance.operationId !== "string" || !Number.isSafeInteger(provenance.attempt) || provenance.attempt < 1 || typeof provenance.deletable !== "boolean") fail();
    const allowed = tables.producers[type][key] ?? [];
    if (!allowed.some((entry) => entry.operationId === provenance.operationId && entry.verdict === provenance.verdict)) fail();
    const id = `${type}\0${key}`;
    const current = values.get(id);
    if (current && (!SUPERSEDABLE.has(type) || provenance.attempt <= current.attempt)) fail();
    const proof = { runId, type, key, operationId: provenance.operationId, attempt: provenance.attempt, valueSha256: digest(digestSalt, type, key, value) };
    busy = true;
    try {
      await writeProof(Object.freeze(proof));
    } catch (error) {
      uncertain = true;
      throw error;
    } finally {
      busy = false;
    }
    const entry = Object.freeze({ value, attempt: provenance.attempt, deletable: provenance.deletable, used: false, valueSha256: proof.valueSha256, operationId: provenance.operationId });
    values.set(id, entry);
    byProducer.set(`${id}\0${provenance.operationId}`, entry);
  }

  function resolve(reference, consumerRowId) {
    if (uncertain) bad("runtime reference store is uncertain");
    const fail = () => bad("invalid runtime reference resolve");
    const { type, key } = readRef(reference, "invalid runtime reference resolve", true);
    if (typeof consumerRowId !== "string" || !tables.consumers[type][key]?.includes(consumerRowId)) fail();
    const derived = type === "ruleset-path";
    const pin = tables.pinned?.[`${type}|${key}|${consumerRowId}`];
    if (Object.hasOwn(reference, "fromStep") ? pin === undefined || reference.fromStep !== tables.pinnedSteps?.[`${type}|${key}|${consumerRowId}`] : pin !== undefined) fail();
    const id = `${derived ? "ruleset-name" : type}\0${key}`;
    const entry = pin === undefined ? values.get(id) : byProducer.get(`${id}\0${pin}`);
    if (!entry) bad("reference is not bound");
    if (deleters.has(`${type}|${key}|${consumerRowId}`) && !entry.deletable) bad("reference is not deletable");
    if (type === "page-token") {
      if (entry.used) bad("reference already used");
      values.set(`${type}\0${key}`, Object.freeze({ ...entry, used: true }));
    }
    return derived ? `/v1/${entry.value}` : entry.value;
  }

  return Object.freeze({
    bind,
    resolve,
    state: () => Object.freeze({
      uncertain,
      bound: Object.freeze([...values].map(([id, entry]) => {
        const [type, key] = id.split("\0");
        return Object.freeze({ type, key, attempt: entry.attempt, deletable: entry.deletable, used: entry.used, valueSha256: entry.valueSha256 });
      })),
    }),
  });
}
