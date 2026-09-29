import { createHash } from "node:crypto";
import { createStage3RequestCounter } from "./request-counter.mjs";

// The only object that holds the real transport. A request leaves through it only after its intent is durable and its
// reservation is durable, exactly once per reservation, for the target that was captured, in the mode its ID belongs to.
// A capture failure after a send poisons the gate: no request of any kind follows. Credential headers are added here,
// at the last step, and never reach the capture journal. The gate performs no retry and decides nothing about a response.
const CREDENTIAL_HEADERS = new Set(["authorization", "x-goog-user-project"]);
const bad = (message) => { throw new Error(message); };
const plain = (value) => value !== null && typeof value === "object" && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;

function closedRecord(value, keys, message) {
  if (!plain(value) || Reflect.ownKeys(value).length !== keys.length || !keys.every((key) => { const field = Object.getOwnPropertyDescriptor(value, key); return field?.enumerable && Object.hasOwn(field, "value"); })) bad(message);
}
const isFunction = (value) => typeof value === "function";

export function createDispatchGate(options) {
  const fail = () => bad("invalid dispatch gate options");
  closedRecord(options, ["reservations", "capture", "transport", "targets", "credentials", "preflightIds", "admission"], "invalid dispatch gate options");
  const { reservations, capture, transport, targets, credentials, preflightIds, admission } = options;
  if (![reservations?.onStarted, reservations?.onReserve, reservations?.onTerminal, capture?.writeIntent, capture?.writeResponse, capture?.writeNote, capture?.snapshot, transport?.send, targets?.verify, credentials?.headersFor, admission?.check, admission?.begin, transport?.validate].every(isFunction)) fail();
  let armed = null;
  let busy = false;
  let poisoned = false;
  let admissionRefused = false;
  let httpBudget = 0;
  const counter = createStage3RequestCounter({
    preflightIds,
    onStarted: (row) => reservations.onStarted(row),
    onReserve: async (row) => { armed = null; await reservations.onReserve(row); armed = Object.freeze({ operationId: row.operationId, phase: row.phase }); },
    onTerminal: (row) => reservations.onTerminal(row),
  });
  // The live approval is proved again before every request, reads included: a revocation must stop the very next request.
  async function admitted() {
    let seen;
    try { seen = await admission.check(); } catch (error) { admissionRefused = true; throw error; }
    if (seen?.admitted !== true) { admissionRefused = true; bad("admission refused: no admission"); }
  }
  const modeOf = (phase) => ({ preflight: "preflight", normal: "normal", recovery: "recovery" })[phase];

  function credentialHeaders(prepared) {
    const headers = credentials.headersFor(prepared.credential, Object.freeze({ project: prepared.project }));
    if (!plain(headers)) bad("invalid credential headers");
    const out = {};
    for (const [name, value] of Object.entries(headers)) {
      if (!CREDENTIAL_HEADERS.has(name) || typeof value !== "string" || !/^[\x20-\x7e]{1,4096}$/.test(value)) bad("invalid credential headers");
      // The quota project is the project the target names; a provider (or row data behind it) cannot bill another one.
      if (name === "x-goog-user-project" && value !== prepared.project) bad("invalid credential headers");
      out[name] = value;
    }
    return out;
  }

  async function send(prepared, meta) {
    if (poisoned) bad("dispatch gate is poisoned");
    if (busy) bad("concurrent dispatch is forbidden");
    busy = true;
    try {
      closedRecord(meta, ["phase", "mutationKey", "accept"], "invalid dispatch request");
      const { phase, mutationKey, accept } = meta;
      if (!targets.verify(prepared) || !modeOf(phase) || (mutationKey !== null && typeof mutationKey !== "string") || (phase === "preflight" ? !isFunction(accept) : accept !== null)) bad("invalid dispatch request");
      const operationId = prepared.rowId;
      if (counter.snapshot().mode !== modeOf(phase) || operationId.startsWith("recovery/") !== (phase === "recovery") || operationId.startsWith("preflight/") !== (phase === "preflight")) bad("request phase does not match the counter");
      // A target the transport would refuse is stopped here, before anything is admitted, written or counted.
      try { transport.validate({ url: prepared.spec.url, method: prepared.spec.method, headers: prepared.spec.headers, body: prepared.spec.body }); } catch { bad("request not sent: the transport refuses the target"); }
      if (capture.snapshot().uncertain) bad("capture journal is uncertain");
      await admitted();
      await capture.writeIntent({ operationId, phase, targetSha256: prepared.targetSha256, redactedTarget: prepared.redacted, mutationKey });
      let dispatched = false;
      let received = null;
      const attempt = async () => {
        if (armed === null || armed.operationId !== operationId || armed.phase !== phase) bad("dispatch is not armed");
        armed = null;
        if (!targets.verify(prepared)) bad("target changed after its intent");
        const headers = { ...prepared.spec.headers, ...credentialHeaders(prepared) };
        dispatched = true;
        let answer;
        // The transport's own refusal of its input means nothing left: that is "not sent", not an uncertain outcome.
        try { answer = await transport.send({ url: prepared.spec.url, method: prepared.spec.method, headers, body: prepared.spec.body }); } catch (error) { if (error?.notSent === true) dispatched = false; throw error; }
        // Only the status, the raw headers and the bytes travel on; timing and any other field of the transport stay behind.
        received = Object.freeze({ status: answer.status, rawHeaders: answer.rawHeaders, bytes: answer.bytes });
        return received;
      };
      let raw;
      try {
        raw = phase === "preflight" ? await counter.sendPreflight(operationId, attempt, accept) : await counter.send(operationId, attempt);
      } catch (error) {
        if (received !== null) {
          // The response arrived but the counter refused it (a preflight check): keep what came back, then report the refusal.
          try { await capture.writeResponse({ operationId, attempt: counter.snapshot().requests, response: { status: received.status, rawHeaders: received.rawHeaders, bytes: received.bytes } }); } catch { poisoned = true; }
          throw error;
        }
        await capture.writeNote({ operationId, text: `request ${dispatched ? "outcome unknown" : "not sent"}: ${String(error?.message ?? "error").slice(0, 200)}` }).catch(() => { poisoned = true; });
        if (!dispatched) throw error;
        throw new Error("request outcome uncertain");
      }
      const attemptNumber = counter.snapshot().requests;
      try {
        await capture.writeResponse({ operationId, attempt: attemptNumber, response: { status: raw.status, rawHeaders: raw.rawHeaders, bytes: raw.bytes } });
      } catch {
        poisoned = true;
        throw new Error("capture failed after send");
      }
      return Object.freeze({ raw: Object.freeze({ status: raw.status, rawHeaders: raw.rawHeaders, bytes: raw.bytes }), attempt: attemptNumber });
    } finally { busy = false; }
  }

  // The seam for the modules that carry their own request bodies and credentials (the credential cache and the credential
  // session). Their sends run through the same counter, admission and durable intent as every other request, one at a time,
  // and the real transport is reachable only inside an armed, counted attempt, once per attempt. They capture no response
  // themselves: what they learn they record as digests, never as the token-bearing answer.
  async function delegatedSend(operationId, attempt, accept, preflight) {
    if (poisoned) bad("dispatch gate is poisoned");
    if (busy) bad("concurrent dispatch is forbidden");
    busy = true;
    try {
      if (typeof operationId !== "string" || !isFunction(attempt) || (preflight && !isFunction(accept))) bad("invalid delegated request");
      if (capture.snapshot().uncertain) bad("capture journal is uncertain");
      await admitted();
      const phase = preflight ? "preflight" : counter.snapshot().mode;
      if (!modeOf(phase)) bad("delegated request outside a request mode");
      await capture.writeIntent({ operationId, phase, targetSha256: createHash("sha256").update(`delegated:${operationId}`).digest("hex"), redactedTarget: `delegated ${operationId}`, mutationKey: null });
      const armedAttempt = async () => {
        if (armed === null || armed.operationId !== operationId || armed.phase !== phase) bad("dispatch is not armed");
        armed = null;
        httpBudget = 1;
        try { return await attempt(); } finally { httpBudget = 0; }
      };
      return preflight ? await counter.sendPreflight(operationId, armedAttempt, accept) : await counter.send(operationId, armedAttempt);
    } finally { busy = false; }
  }
  const delegated = Object.freeze({
    counter: Object.freeze({
      send: (operationId, attempt) => delegatedSend(operationId, attempt, null, false),
      sendPreflight: (operationId, attempt, accept) => delegatedSend(operationId, attempt, accept, true),
      snapshot: () => Object.freeze({ ...counter.snapshot() }),
      enterRecovery: () => counter.enterRecovery(),
    }),
    http: async (spec) => {
      if (httpBudget !== 1) bad("http outside a delegated attempt or more than one request in it");
      httpBudget = 0;
      return transport.send(spec);
    },
  });

  return Object.freeze({
    delegated,
    // The run's first admission also marks the run started (the recording budget); every later request only re-checks.
    start: async (input) => {
      let seen;
      try { seen = await admission.begin(); } catch (error) { admissionRefused = true; throw error; }
      if (seen?.admitted !== true) { admissionRefused = true; bad("admission refused: no admission"); }
      return counter.start(input);
    },
    admit: () => counter.admit(),
    enterRecovery: () => counter.enterRecovery(),
    finish: (outcome) => counter.finish(outcome),
    send,
    snapshot: () => Object.freeze({ ...counter.snapshot(), poisoned, busy, admissionRefused }),
  });
}
