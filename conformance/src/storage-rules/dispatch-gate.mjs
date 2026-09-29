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
  closedRecord(options, ["reservations", "capture", "transport", "targets", "credentials", "preflightIds"], "invalid dispatch gate options");
  const { reservations, capture, transport, targets, credentials, preflightIds } = options;
  if (![reservations?.onStarted, reservations?.onReserve, reservations?.onTerminal, capture?.writeIntent, capture?.writeResponse, capture?.writeNote, capture?.snapshot, transport?.send, targets?.verify, credentials?.headersFor].every(isFunction)) fail();
  let armed = null;
  let busy = false;
  let poisoned = false;
  const counter = createStage3RequestCounter({
    preflightIds,
    onStarted: (row) => reservations.onStarted(row),
    onReserve: async (row) => { armed = null; await reservations.onReserve(row); armed = Object.freeze({ operationId: row.operationId, phase: row.phase }); },
    onTerminal: (row) => reservations.onTerminal(row),
  });
  const modeOf = (phase) => ({ preflight: "preflight", normal: "normal", recovery: "recovery" })[phase];

  function credentialHeaders(credential) {
    const headers = credentials.headersFor(credential);
    if (!plain(headers)) bad("invalid credential headers");
    const out = {};
    for (const [name, value] of Object.entries(headers)) {
      if (!CREDENTIAL_HEADERS.has(name) || typeof value !== "string" || !/^[\x20-\x7e]{1,4096}$/.test(value)) bad("invalid credential headers");
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
      if (capture.snapshot().uncertain) bad("capture journal is uncertain");
      await capture.writeIntent({ operationId, phase, targetSha256: prepared.targetSha256, redactedTarget: prepared.redacted, mutationKey });
      let dispatched = false;
      let received = null;
      const attempt = async () => {
        if (armed === null || armed.operationId !== operationId || armed.phase !== phase) bad("dispatch is not armed");
        armed = null;
        if (!targets.verify(prepared)) bad("target changed after its intent");
        const headers = { ...prepared.spec.headers, ...credentialHeaders(prepared.credential) };
        dispatched = true;
        const answer = await transport.send({ url: prepared.spec.url, method: prepared.spec.method, headers, body: prepared.spec.body });
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

  return Object.freeze({
    start: (input) => counter.start(input),
    admit: () => counter.admit(),
    enterRecovery: () => counter.enterRecovery(),
    finish: (outcome) => counter.finish(outcome),
    send,
    snapshot: () => Object.freeze({ ...counter.snapshot(), poisoned, busy }),
  });
}
