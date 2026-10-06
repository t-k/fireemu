// Adapted from comparison-v8-final's row replay/bindings and PAGING-RECREATE's exact-status judge.
import { isDeepStrictEqual } from "node:util";
import { createIamOwnership, readPolicy } from "./iam.mjs";
import { createOwnership } from "./names.mjs";
import { timestampFromWire } from "./grpc.mjs";

export const CASE_IDS = Object.freeze([
  "deleted-cursor",
  "stream-push-open",
  "stream-invalid-ack",
  "stream-invalid-deadline",
  "stream-invalid-initial",
  "dlq-no-grant",
  "rest-layout-routes",
  "dlq-grant-window",
]);
const STATUSES =
  "OK CANCELLED UNKNOWN INVALID_ARGUMENT DEADLINE_EXCEEDED NOT_FOUND ALREADY_EXISTS PERMISSION_DENIED RESOURCE_EXHAUSTED FAILED_PRECONDITION ABORTED OUT_OF_RANGE UNIMPLEMENTED INTERNAL UNAVAILABLE DATA_LOSS UNAUTHENTICATED".split(
    " ",
  );
const UNSURE = new Set([1, 2, 4, 10, 12, 13, 14, 15]);
export const canonicalStatus = (value) =>
  typeof value === "number" ? (STATUSES[value] ?? null) : STATUSES.includes(value) ? value : null;
const result = (verdict, reason, extra = {}) => ({ verdict, reason, ...extra });
const userMaps = new Set(["attributes", "labels", "tags"]);
const idShape = (value, digits = false) =>
  (digits ? /^\d+$/ : /^[A-Za-z0-9_-]+={0,2}$/).test(value)
    ? { format: "valid", width: value.length, padding: value.match(/=*$/)[0].length }
    : { invalidIdentifier: value };

export function normalizeBody(value, key = "", user = false, aliases = new Map()) {
  if (user) return value;
  if (
    ["publishTime", "expireTime"].includes(key) &&
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    try {
      return normalizeBody(timestampFromWire(value), key, false, aliases);
    } catch {
      return { invalidTimestamp: value };
    }
  }
  if (Array.isArray(value)) {
    const normalized = value.map((v) => normalizeBody(v, key, false, aliases));
    if (
      ["topics", "subscriptions", "snapshots"].includes(key) &&
      value.every((v) => typeof v?.name === "string")
    )
      return normalized.toSorted((a, b) => a.name.localeCompare(b.name));
    return normalized;
  }
  if (value && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .toSorted()
        .map((k) => [k, normalizeBody(value[k], k, userMaps.has(k), aliases)]),
    );
  if (typeof value !== "string") return value;
  if (
    [
      "messageId",
      "messageIds",
      "ackId",
      "ackIds",
      "modifyDeadlineAckIds",
      "nextPageToken",
    ].includes(key)
  ) {
    const kind = key.startsWith("messageId")
      ? "message"
      : key === "nextPageToken"
        ? "cursor"
        : "ack";
    const identity = `${kind}:${value}`;
    if (!aliases.has(identity)) aliases.set(identity, aliases.size);
    return { ...idShape(value, kind === "message"), alias: aliases.get(identity) };
  }
  if (["publishTime", "expireTime"].includes(key)) {
    const match = /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d{1,9}))?Z$/.exec(value);
    return match && Number.isFinite(Date.parse(value))
      ? { timestamp: true, precision: match[2]?.length ?? 0 }
      : { invalidTimestamp: value };
  }
  return value;
}

export function judgeRow(expected, actual) {
  if (expected.op === "getIamPolicy" || expected.op === "setIamPolicy") {
    let valid = false;
    try {
      readPolicy(expected.response?.body);
      valid = expected.response?.status === 200 && expected.response?.unknown !== true;
    } catch {
      /* Structural refusal remains needs-review. */
    }
    return result("NOT_COMPARABLE", `IAM needs-review; structure ${valid ? "valid" : "invalid"}`);
  }
  if (!actual || actual.notReplayed)
    return result("NOT_COMPARABLE", actual?.reason ?? "replay missing");
  const a = expected.response,
    b = actual.response;
  if (!a || !b || expected.unknown || a.unknown || actual.unknown || b.unknown)
    return result("NOT_COMPARABLE", "unknown response");
  if (expected.transport === "grpc") {
    const source = canonicalStatus(a.code),
      local = canonicalStatus(b.code);
    if (
      !source ||
      !local ||
      UNSURE.has(STATUSES.indexOf(source)) ||
      UNSURE.has(STATUSES.indexOf(local))
    )
      return result("NOT_COMPARABLE", "unknown native status");
    if (source !== local) return result("DIVERGES", "native status gap");
    if (a.message !== b.message)
      return result(
        expected.request?.afterReceive ? "NOT_COMPARABLE" : "DIVERGES",
        "native detail gap; embedded identities require review for a causal followup",
      );
  } else {
    if (
      ![a.status, b.status].every(
        (s) => Number.isInteger(s) && s >= 200 && s < 500 && !(s >= 300 && s < 400) && s !== 499,
      ) ||
      a.body?.raw !== undefined ||
      b.body?.raw !== undefined
    )
      return result("NOT_COMPARABLE", "unknown HTTP response");
    if (a.status !== b.status) return result("DIVERGES", "HTTP status gap");
  }
  if (!isDeepStrictEqual(normalizeBody(a.body), normalizeBody(b.body)))
    return result("DIVERGES", "body shape gap");
  if (expected.op === "streamingPull") {
    for (const key of ["inboundFrames", "outboundFrames", "followUpSent"])
      if (a[key] !== b[key]) return result("DIVERGES", `native ${key} gap`);
  }
  if (expected.transport === "rest") {
    const bytes = (response) =>
      response.bodyBytes ??
      (response.contentLength === undefined ? undefined : Number(response.contentLength));
    if (![bytes(a), bytes(b)].every((n) => Number.isSafeInteger(n) && n >= 0))
      return result("NOT_COMPARABLE", "recorded wire length missing");
    if (bytes(a) !== bytes(b)) return result("DIVERGES", "wire length gap");
    return result("MATCH", "recorded semantic shape and wire length match", {
      layout: "length-match-only",
    });
  }
  return result("MATCH", "recorded semantic shape matches");
}

export function createBindings() {
  const forward = new Map(),
    reverse = new Map(),
    invalid = new Set();
  const key = (kind, value) => `${kind}:${value}`;
  function bind(kind, source, local) {
    if (typeof source !== "string" || !source || typeof local !== "string" || !local)
      throw new Error("invalid binding value");
    const a = key(kind, source),
      b = key(kind, local);
    const prior = forward.get(a),
      owner = reverse.get(b);
    if ((prior !== undefined && prior !== local) || (owner !== undefined && owner !== source)) {
      invalid.add(a);
      if (owner !== undefined) invalid.add(key(kind, owner));
      forward.delete(a);
      return false;
    }
    if (invalid.has(a)) return false;
    forward.set(a, local);
    reverse.set(b, source);
    return true;
  }
  function get(kind, source) {
    const a = key(kind, source);
    if (invalid.has(a) || !forward.has(a))
      throw new Error(`missing or conflicting ${kind} binding`);
    return forward.get(a);
  }
  function linkPublish(publication, source, local) {
    const ids = source?.messageIds,
      actual = local?.messageIds;
    if (
      !Array.isArray(ids) ||
      !Array.isArray(actual) ||
      ids.length !== publication.messages?.length ||
      actual.length !== ids.length ||
      new Set(ids).size !== ids.length ||
      new Set(actual).size !== actual.length
    )
      throw new Error("ambiguous publish binding");
    ids.forEach((id, i) => {
      if (!bind("message", id, actual[i])) throw new Error("conflicting publish binding");
    });
  }
  function linkReceive(source, local) {
    for (const original of source?.receivedMessages ?? []) {
      const id = get("message", original.message?.messageId);
      const matches = (local?.receivedMessages ?? []).filter((v) => v.message?.messageId === id);
      if (
        matches.length !== 1 ||
        !isDeepStrictEqual(original.message?.data, matches[0].message?.data) ||
        !isDeepStrictEqual(original.message?.attributes, matches[0].message?.attributes)
      )
        throw new Error("ambiguous received message binding");
      if (!bind("ack", original.ackId, matches[0].ackId))
        throw new Error("conflicting ACK binding");
    }
  }
  function linkCursor(source, local) {
    if (source?.nextPageToken === undefined) return;
    const names = (body) =>
      (body.topics ?? body.subscriptions ?? body.snapshots ?? []).map((v) =>
        typeof v === "string" ? v : v.name,
      );
    if (!isDeepStrictEqual(names(source), names(local)))
      throw new Error("cursor requires identical ordered page");
    if (!bind("cursor", source.nextPageToken, local.nextPageToken))
      throw new Error("conflicting cursor binding");
  }
  function rewrite(value, field = "", user = false) {
    if (user) return value;
    if (Array.isArray(value)) return value.map((v) => rewrite(v, field));
    if (value && typeof value === "object")
      return Object.fromEntries(
        Object.entries(value).map(([k, v]) => [k, rewrite(v, k, userMaps.has(k))]),
      );
    if (typeof value === "string" && ["ackId", "ackIds"].includes(field)) return get("ack", value);
    if (typeof value === "string" && field === "pageToken") return get("cursor", value);
    return value;
  }
  function request(row) {
    if (
      row.case === "stream-invalid-ack/grpc" &&
      row.request.frames?.[1]?.ackIds?.[0] === "invalid-ack-for-stream-observation"
    )
      return structuredClone(row.request);
    const rewritten = rewrite(structuredClone(row.request));
    if (rewritten.path) {
      const url = new URL(rewritten.path, "http://127.0.0.1");
      const token = url.searchParams.get("pageToken");
      if (token) {
        url.searchParams.set("pageToken", get("cursor", token));
        rewritten.path = `${url.pathname}${url.search}`;
      }
    }
    return rewritten;
  }
  return { bind, get, linkPublish, linkReceive, linkCursor, request };
}

export function completeTrace(id, requests) {
  const ops = requests.map((r) => r.op).join(",");
  if (id === "deleted-cursor")
    return ops === "createTopic,createTopic,createTopic,listTopics,deleteTopic,listTopics";
  if (id.startsWith("stream-"))
    return (
      ops ===
      (id === "stream-invalid-deadline"
        ? "createTopic,createSubscription,publish,streamingPull"
        : "createTopic,createSubscription,streamingPull")
    );
  if (id === "rest-layout-routes")
    return /^createTopic,createSubscription,publish,createSnapshot,(pull,){1,3}acknowledge,seek$/.test(
      ops,
    );
  const prefix = [
    "createTopic",
    "createTopic",
    "createSubscription",
    "createSubscription",
    "getSubscription",
  ];
  if (id === "dlq-grant-window")
    prefix.push(
      "getIamPolicy",
      "setIamPolicy",
      "getIamPolicy",
      "getIamPolicy",
      "setIamPolicy",
      "getIamPolicy",
    );
  prefix.push("publish");
  if (!prefix.every((op, index) => requests[index]?.op === op)) return false;
  let index = prefix.length;
  const source = requests[index]?.request?.path;
  if (!source?.endsWith("-source:pull")) return false;
  const sink = source.replace(/-source:pull$/, "-sink:pull");
  const poll = (path, followup = null) => {
    const row = requests[index++];
    if (
      row?.op !== "pull" ||
      row.request?.path !== path ||
      row.request.body?.maxMessages !== 1 ||
      (path === source && row.request.body.returnImmediately !== false)
    )
      return false;
    const messages = row.response?.body?.receivedMessages ?? [];
    if (!Array.isArray(messages) || messages.length > 1) return false;
    if (messages.length && followup) {
      const next = requests[index++];
      if (
        next?.op !== followup ||
        next.request?.path !== path.replace(/:pull$/, `:${followup}`) ||
        !isDeepStrictEqual(next.request.body?.ackIds, [messages[0].ackId]) ||
        (followup === "modifyAckDeadline" && next.request.body.ackDeadlineSeconds !== 0)
      )
        return false;
    }
    return true;
  };
  for (let n = 0; n < 9; n += 1) if (!poll(source, "modifyAckDeadline")) return false;
  for (let n = 0; n < 36; n += 1) if (!poll(sink, "acknowledge")) return false;
  return poll(source) && index === requests.length;
}

export function recordedRequestInstant(row) {
  const end = Date.parse(row.at);
  if (!Number.isFinite(end) || !Number.isSafeInteger(row.ms) || row.ms < 0)
    throw new Error("invalid recorded request time or duration");
  return end - row.ms;
}

export function recordingTimingDebts(capture) {
  const debts = [];
  const starts = capture.filter((row) => row.note === "run-start");
  const ends = capture.filter((row) => row.note === "run-end");
  if (
    starts.length !== 1 ||
    ends.length !== 1 ||
    capture[0] !== starts[0] ||
    capture.at(-1) !== ends[0]
  )
    debts.push("run boundary does not enclose recording");
  let previousAt = -Infinity;
  let previousRequestEnd = Date.parse(starts[0]?.at);
  for (const row of capture) {
    const at = Date.parse(row.at);
    if (!Number.isFinite(at) || at < previousAt) debts.push("capture timestamp chronology invalid");
    previousAt = at;
    if (row.request === undefined || row.response === undefined) continue;
    try {
      const start = recordedRequestInstant(row);
      const boundary = capture.find(
        (entry) =>
          entry.note === "case-start" && entry.case?.split("/")[0] === row.case?.split("/")[0],
      );
      if (boundary && start < Date.parse(boundary.at))
        debts.push("case request time containment invalid");
      if (!Number.isFinite(previousRequestEnd) || start < previousRequestEnd)
        debts.push("recorded request start chronology invalid");
      previousRequestEnd = at;
    } catch (error) {
      debts.push(error.message);
    }
  }
  return [...new Set(debts)];
}

export async function compareRecording(
  { capture, issued, iam },
  { replay, frameVerified = () => false } = {},
) {
  const bindings = createBindings(),
    rows = [],
    debts = recordingTimingDebts(capture);
  const invalidTiming = debts.length > 0;
  const metadata = capture.find((r) => r.note === "run-start");
  if (metadata?.suite !== "stream-dlq-v2") debts.push("missing stream-dlq-v2 run metadata");
  const sent = new Map();
  for (const entry of issued) {
    if (entry.phase === "sent") {
      if (!entry.requestId || sent.has(entry.requestId))
        debts.push("invalid issued request identity");
      sent.set(entry.requestId, { ...entry, answered: false });
    } else if (entry.phase === "answered") {
      const intent = sent.get(entry.requestId);
      if (
        !intent ||
        intent.answered ||
        ["name", "action", "transport"].some((k) => intent[k] !== entry[k])
      )
        debts.push("unjoined issued answer");
      else {
        intent.answered = true;
        intent.answerAt = entry.at;
        intent.kind = entry.kind;
        if (!["ok", "error", "conflict"].includes(entry.kind))
          debts.push("uncertain issued answer");
      }
    } else if (entry.phase !== "resolved") debts.push("unknown issued phase");
  }
  if ([...sent.values()].some((e) => !e.answered)) debts.push("issued request unanswered");
  const resourceOf = (row) =>
    row.request.body?.name ??
    row.request.body?.snapshot ??
    decodeURIComponent(row.request.path?.split("?")[0]?.slice(4) ?? "");
  for (const intent of sent.values()) {
    const exchanges = capture.filter(
      (row) =>
        row.request &&
        row.response &&
        /^(create|delete)/.test(row.op) &&
        resourceOf(row) === intent.name &&
        row.transport === intent.transport &&
        (row.op.startsWith("create") ? "create" : "delete") === intent.action,
    );
    if (exchanges.length !== 1) {
      debts.push("issued intent has no unique captured exchange");
      continue;
    }
    const at = Date.parse(exchanges[0].at),
      before = Date.parse(intent.at),
      after = Date.parse(intent.answerAt);
    if (![at, before, after].every(Number.isFinite) || before > at || at > after)
      debts.push("issued/capture ordering invalid");
    const row = exchanges[0],
      response = row.response;
    const success =
      row.transport === "rest"
        ? response.status >= 200 && response.status < 300
        : canonicalStatus(response.code) === "OK";
    const conflict =
      row.transport === "rest"
        ? response.status === 409
        : canonicalStatus(response.code) === "ALREADY_EXISTS";
    const expectedKind =
      row.unknown || response.unknown
        ? "unknown"
        : success
          ? "ok"
          : conflict
            ? "conflict"
            : "error";
    if (intent.kind !== expectedKind) debts.push("contradictory issued/capture answer");
  }
  let iamStructure = "empty";
  try {
    const ownership = createOwnership({ project: metadata?.project, runId: metadata?.runId });
    const manager = createIamOwnership({
      journal: {
        write() {
          throw new Error("read-only IAM replay");
        },
      },
      assertOwned: ownership.assertOwned,
      replay: iam,
    });
    iamStructure = manager.outstanding().length ? "outstanding" : "valid";
  } catch {
    iamStructure = "invalid";
  }
  let prior = 0;
  for (const original of capture.filter(
    (r) => r.request !== undefined && r.response !== undefined,
  )) {
    const id = original.case?.split("/")[0];
    if (!CASE_IDS.includes(id)) continue;
    if (!Number.isSafeInteger(original.n) || original.n <= prior)
      debts.push("capture sequence invalid");
    prior = original.n;
    let judgment;
    const dispatch = capture.filter(
      (r) =>
        r.note === "request-dispatch" &&
        r.case === original.case &&
        r.step === original.step &&
        r.op === original.op &&
        r.transport === original.transport,
    );
    if (dispatch.length !== 1 || capture.indexOf(dispatch[0]) >= capture.indexOf(original))
      debts.push("request dispatch provenance incomplete");
    if (/^(get|set)IamPolicy$/.test(original.op)) judgment = judgeRow(original);
    else if (invalidTiming)
      judgment = result("NOT_COMPARABLE", "recording timing provenance invalid");
    else {
      try {
        if (/^create|^delete/.test(original.op)) {
          const name =
            original.request.body?.name ??
            original.request.body?.snapshot ??
            decodeURIComponent(original.request.path?.split("?")[0]?.slice(4) ?? "");
          const action = original.op.startsWith("create") ? "create" : "delete";
          const candidates = [...sent.values()].filter(
            (e) => e.name === name && e.action === action && e.transport === original.transport,
          );
          if (candidates.length !== 1 || !candidates[0].answered)
            throw new Error("missing unambiguous issued provenance");
          const response = original.response;
          const success =
            original.transport === "rest"
              ? response.status >= 200 && response.status < 300
              : canonicalStatus(response.code) === "OK";
          const conflict =
            original.transport === "rest"
              ? response.status === 409
              : canonicalStatus(response.code) === "ALREADY_EXISTS";
          const kind =
            original.unknown || response.unknown
              ? "unknown"
              : success
                ? "ok"
                : conflict
                  ? "conflict"
                  : "error";
          if (candidates[0].kind !== kind || candidates[0].consumed)
            throw new Error("contradictory or reused issued answer");
          candidates[0].consumed = true;
        }
        const frames = capture.filter(
          (f) => f.note === "stream-frame" && f.case === original.case && f.step === original.step,
        );
        if (
          original.op === "streamingPull" &&
          (!frames.length || frames.some((f) => !frameVerified(f)))
        )
          throw new Error("native raw frame provenance missing");
        const actual = await replay(original, bindings.request(original), {
          bindings,
          frames,
          dispatch: dispatch[0],
        });
        judgment = judgeRow(original, actual);
        if (original.op === "publish" && original.response.status === 200)
          bindings.linkPublish(original.request.body, original.response.body, actual.response.body);
        if (original.op === "pull" && original.response.status === 200)
          bindings.linkReceive(original.response.body, actual.response.body);
        if (original.op.startsWith("list") && original.response.status === 200)
          bindings.linkCursor(original.response.body, actual.response.body);
        if (actual.frames && judgment.verdict !== "NOT_COMPARABLE") {
          if (frames.length !== actual.frames.length)
            judgment = result("DIVERGES", "native frame count gap");
          else
            for (let i = 0; i < frames.length; i += 1) {
              if (
                frames[i].direction !== actual.frames[i].direction ||
                frames[i].bodyBytes !== actual.frames[i].bodyBytes ||
                !isDeepStrictEqual(
                  normalizeBody(frames[i].body),
                  normalizeBody(actual.frames[i].body),
                )
              )
                judgment = result("DIVERGES", "native frame shape or wire length gap");
            }
        }
      } catch (error) {
        judgment =
          judgment?.verdict === "DIVERGES"
            ? { ...judgment, debt: error.message }
            : result("NOT_COMPARABLE", error.message);
      }
    }
    rows.push({
      case: id,
      n: original.n,
      op: original.op,
      provenance: original.provenance ?? { run: metadata?.runId ?? original.runId, n: original.n },
      ...judgment,
    });
  }
  const cases = CASE_IDS.map((id) => {
    const scoped = rows.filter((r) => r.case === id),
      reasons = [...debts];
    const starts = capture.filter((r) => r.note === "case-start" && r.case?.split("/")[0] === id);
    const ends = capture.filter((r) => r.note === "case-end" && r.case?.split("/")[0] === id);
    if (starts.length !== 1 || ends.length !== 1 || ends[0].outcome !== "completed")
      reasons.push("case boundary incomplete or observation aborted");
    const requests = capture.filter((r) => r.case?.split("/")[0] === id && r.request && r.response);
    if (!completeTrace(id, requests)) reasons.push("required case request trace missing");
    if (
      starts.length === 1 &&
      ends.length === 1 &&
      requests.some(
        (r) =>
          capture.indexOf(r) <= capture.indexOf(starts[0]) ||
          capture.indexOf(r) >= capture.indexOf(ends[0]),
      )
    )
      reasons.push("request outside case boundary");
    if (id === "dlq-grant-window") reasons.push(`IAM needs-review; journal ${iamStructure}`);
    const verdict = scoped.some((r) => r.verdict === "DIVERGES")
      ? "DIVERGES"
      : reasons.length || scoped.some((r) => r.verdict === "NOT_COMPARABLE")
        ? "NOT_COMPARABLE"
        : "MATCH";
    return {
      case: id,
      verdict,
      reasons: [
        ...new Set([
          ...reasons,
          ...scoped.filter((r) => r.verdict !== "MATCH").map((r) => r.reason),
        ]),
      ],
      comparedRows: scoped.length,
    };
  });
  return {
    schema: 1,
    suite: "stream-dlq-v2",
    profile: "strict",
    sourceEvidence: metadata?.target ?? "unspecified",
    cases,
    rows,
    iam: { assessment: "needs-review", structure: iamStructure, localRequests: 0 },
    layoutClaim:
      "Recorded lengths only; equal lengths do not establish byte-exact layout or headers.",
    compatibilityPromotion: false,
  };
}
