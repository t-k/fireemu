import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { open, lstat, mkdir } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { DELEGATION_SUBJECTS, scanRevocations } from "./ledger-revocation.mjs";
import {
  NATIVE_PROJECT,
  nativeClosed,
  nativeDigest,
  nativeRef,
  nativeSnapshot,
} from "./management-native-manifest.mjs";
import { validateNativeManifest, buildNativeSchedule } from "./management-native-schedule.mjs";
import { createTargetBuilder } from "./target.mjs";
import { RUNTIME_REF_KINDS, createRuntimeRefStore } from "./runtime-refs.mjs";
import { createResourceLedger } from "./resource-ledger.mjs";
import { readResponse } from "./acceptance-core.mjs";
import { RULES_CLASSIFIERS } from "./acceptance-rules.mjs";
import { createCaptureJournal } from "./capture-journal.mjs";
import { createReservationJournal } from "./reservation-journal.mjs";
import { createRecordingUsage } from "./recording-usage.mjs";
import { withProjectLocks } from "./project-locks.mjs";
import { leaseTransport, confirmCleanClose } from "./locked-run.mjs";
import { markCleanResult } from "./results.mjs";
import { quotaProjectRequired } from "./quota-project.mjs";

// The full approval deliberately remains fixed to its original projects/counts. This separate narrow validator keeps
// its actor, delegation, envelope, pins, revocation and fresh ledger rules without pretending to be a full packet.
const PINS = [
  "packetSha256",
  "sourceCommit",
  "sourceTree",
  "runnerSha256",
  "manifestSha256",
  "fixtureSchemaSha256",
];
const COORDINATOR = "Claude（委任。枠の内の承認し直し）";
const DELEGATED_ENVELOPE_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const DELEGATION_REFERENCE = `2026-09-28 ${DELEGATION_SUBJECTS.send}`;
const plain = (value) => value !== null && Object.getPrototypeOf(value) === Object.prototype;
const fail = (message) => {
  throw new Error(message);
};
function closedRecord(value, keys, label) {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype)
    throw new Error(`invalid ${label} data`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key)))
    throw new Error(`invalid ${label} data`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value"))
      throw new Error(`invalid ${label} data`);
  }
}

function dataArray(value, label) {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > 1000
  )
    throw new Error(`invalid ${label} data`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) throw new Error(`invalid ${label} data`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (key === "length") continue;
    if (
      typeof key !== "string" ||
      !/^(?:0|[1-9]\d*)$/.test(key) ||
      Number(key) >= value.length ||
      !descriptor?.enumerable ||
      !Object.hasOwn(descriptor, "value")
    ) {
      throw new Error(`invalid ${label} data`);
    }
  }
}

function ledgerRows(text, subject, skipLines) {
  return text.split("\n").flatMap((line, index) => {
    if (skipLines.has(index + 1)) return [];
    const columns = line.split("|").map((value) => value.trim());
    if (![subject, `${subject} envelope`].includes(columns[1])) return [];
    if (
      columns.length !== 5 ||
      !/^- \d{4}-\d{2}-\d{2}$/.test(columns[0]) ||
      !columns[3] ||
      !columns[4]
    ) {
      throw new Error("malformed target ledger row");
    }
    const fields = Object.create(null);
    for (const entry of columns[2].split(";")) {
      const separator = entry.indexOf("=");
      const key = entry.slice(0, separator).trim();
      const value = entry.slice(separator + 1).trim();
      if (separator < 1 || (key !== "根拠" && !/^[A-Za-z][A-Za-z0-9]*$/.test(key)) || !value)
        throw new Error("malformed target ledger row");
      if (Object.hasOwn(fields, key)) throw new Error("duplicate ledger field");
      fields[key] = value;
    }
    return [{ line: index + 1, subject: columns[1], fields, actor: columns[3] }];
  });
}

function hasOwnerDelegation(text, delegationSubject) {
  const rows = text
    .split("\n")
    .map((line) => line.split("|").map((column) => column.trim()))
    .filter((columns) => columns[1] === delegationSubject);
  if (rows.length !== 1) return false;
  const columns = rows[0];
  if (
    columns.length !== 5 ||
    columns[0] !== "- 2026-09-28" ||
    !columns[3].startsWith("オーナー") ||
    !columns[4]
  )
    return false;
  const decisions = columns[2].split(";").flatMap((entry) => {
    const separator = entry.indexOf("=");
    return separator >= 1 && entry.slice(0, separator).trim() === "decision"
      ? [entry.slice(separator + 1).trim()]
      : [];
  });
  return decisions.length === 1 && decisions[0] === "APPROVE";
}

/** Validate local approval bindings only; this does not authorize or perform a send. */
export function validateNativeApproval(options) {
  closedRecord(
    options,
    ["ledgerText", "packet", "review", "manifest", "current", "nowSeconds"],
    "approval options",
  );
  const { ledgerText, packet, review, current, nowSeconds } = options;
  const manifest = validateNativeManifest(options.manifest);
  if (typeof ledgerText !== "string" || ledgerText.includes("\0"))
    throw new Error("invalid approval options data");
  closedRecord(
    packet,
    [
      "taskId",
      "packetName",
      ...PINS,
      "projects",
      "maxRequests",
      "reserveUsd",
      "runId",
      "baselineSha256",
      "perRecordingCap",
    ],
    "packet",
  );
  if (
    packet.taskId !== "STORAGE-RULES" ||
    typeof packet.packetName !== "string" ||
    !/^[a-z0-9][a-z0-9.-]{0,63}$/.test(packet.packetName) ||
    PINS.some(
      (key) =>
        typeof packet[key] !== "string" ||
        !(["sourceCommit", "sourceTree"].includes(key) ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/).test(
          packet[key],
        ),
    )
  )
    throw new Error("invalid packet data");
  dataArray(packet.projects, "packet project");
  if (packet.projects.some((project) => typeof project !== "string"))
    throw new Error("invalid packet project data");
  closedRecord(
    review,
    ["verdict", "must", "should", ...PINS, "envelopeId", "withinEnvelope"],
    "review",
  );
  dataArray(review.must, "review");
  dataArray(review.should, "review");
  const limits = { projects: [NATIVE_PROJECT], maxRequests: manifest.counts.total * 2 };
  if (
    packet.projects.length !== limits.projects.length ||
    packet.projects.some((project, index) => project !== limits.projects[index]) ||
    packet.maxRequests !== limits.maxRequests ||
    !Number.isFinite(packet.reserveUsd) ||
    packet.reserveUsd <= 0 ||
    packet.reserveUsd > 10 ||
    packet.perRecordingCap !== manifest.counts.total ||
    packet.runId !== manifest.runId ||
    packet.sourceCommit !== manifest.sourceCommit ||
    packet.sourceTree !== manifest.sourceTree ||
    packet.manifestSha256 !== manifest.manifestSha256 ||
    packet.baselineSha256 !== manifest.baselineSha256
  )
    throw new Error("runner limit mismatch");
  nativeClosed(
    current,
    [
      "kind",
      "go",
      "runId",
      "packetSha256",
      "sourceCommit",
      "sourceTree",
      "manifestSha256",
      "baselineSha256",
      "evidenceSha256",
      "validationSha256",
      "expiresAt",
      "baselineObservedAt",
    ],
    "current admission",
  );
  if (
    !["MOCK_CURRENT_ADMISSION", "ROOT_ACTUAL_CURRENT_ADMISSION"].includes(current.kind) ||
    current.go !== "GO" ||
    !Number.isSafeInteger(nowSeconds) ||
    !Number.isSafeInteger(current.expiresAt) ||
    current.expiresAt <= nowSeconds ||
    current.baselineObservedAt !== manifest.baseline.observedAt ||
    nowSeconds < current.baselineObservedAt ||
    nowSeconds - current.baselineObservedAt > manifest.limits.deadlineSeconds ||
    current.runId !== packet.runId ||
    current.packetSha256 !== packet.packetSha256 ||
    current.sourceCommit !== packet.sourceCommit ||
    current.sourceTree !== packet.sourceTree ||
    current.manifestSha256 !== packet.manifestSha256 ||
    current.baselineSha256 !== packet.baselineSha256 ||
    !/^[a-f0-9]{64}$/.test(current.evidenceSha256) ||
    !/^[a-f0-9]{64}$/.test(current.validationSha256)
  )
    throw new Error("fresh ROOT current E/V/GO required");
  if (
    review.verdict !== "APPROVE" ||
    !Array.isArray(review.must) ||
    review.must.length !== 0 ||
    !Array.isArray(review.should) ||
    review.should.length !== 0
  )
    throw new Error("clean APPROVE review required");
  if (PINS.some((key) => review[key] !== packet[key])) throw new Error("review pin mismatch");
  const subject = `${packet.taskId} ${packet.packetName}`;
  const revocations = scanRevocations({
    ledgerText,
    taskId: packet.taskId,
    pins: Object.fromEntries(PINS.map((key) => [key, packet[key]])),
    envelopeId: review.envelopeId,
  });
  if (revocations.lane.length > 0) throw new Error("approval revoked");
  const rows = ledgerRows(ledgerText, subject, new Set(revocations.consumed));
  if (rows.some((row) => row.fields.decision === "REVOKED")) throw new Error("approval revoked");
  const decision = rows.findLast((row) => row.subject === subject && row.fields.decision);
  if (
    !decision ||
    decision.fields.decision !== "APPROVE" ||
    (!decision.actor.startsWith("オーナー（") && decision.actor !== COORDINATOR)
  ) {
    throw new Error("matching owner approval required");
  }
  if (PINS.some((key) => decision.fields[key] !== packet[key]))
    throw new Error("decision pin mismatch");
  // A global revocation stops the lane only when it was written after the decision row this check selected; an earlier one is superseded.
  if (revocations.global.some((line) => line > decision.line)) throw new Error("approval revoked");
  if (decision.actor !== COORDINATOR) {
    if (review.envelopeId !== null || review.withinEnvelope !== false)
      throw new Error("direct review envelope mismatch");
    return Object.freeze({
      status: "APPROVAL_BOUND_LOCAL_ONLY",
      sendAuthorized: false,
      decisionLine: decision.line,
      envelopeId: null,
    });
  }
  if (revocations.delegation.length > 0)
    throw new Error("delegated envelope authority required: delegation revoked");
  const envelopeId = decision.fields.envelopeId;
  const envelopes = rows.filter(
    (row) => row.subject === `${subject} envelope` && row.fields.envelopeId === envelopeId,
  );
  if (envelopes.length > 1) throw new Error("ambiguous owner envelope");
  const envelope = envelopes[0];
  if (
    !envelope ||
    !envelopeId ||
    envelope.line >= decision.line ||
    (!envelope.actor.startsWith("オーナー（") && envelope.actor !== DELEGATED_ENVELOPE_ACTOR)
  )
    throw new Error("preceding owner envelope required");
  if (["writes", "iamConfig", "retries"].some((key) => !Object.hasOwn(envelope.fields, key)))
    throw new Error("invalid owner envelope schema");
  if (envelope.fields.decision && envelope.fields.decision !== "APPROVE")
    throw new Error("owner envelope not approved");
  if (review.envelopeId !== envelopeId || review.withinEnvelope !== true)
    throw new Error("in-envelope review required");
  if (
    !/^[1-9]\d*$/.test(envelope.fields.maxRequests) ||
    !Number.isSafeInteger(Number(envelope.fields.maxRequests)) ||
    !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(envelope.fields.reserveUsd) ||
    !Number.isFinite(Number(envelope.fields.reserveUsd)) ||
    Number(envelope.fields.reserveUsd) <= 0
  )
    throw new Error("invalid envelope bound");
  if (envelope.actor === DELEGATED_ENVELOPE_ACTOR) {
    if (
      envelope.fields["根拠"] !== DELEGATION_REFERENCE ||
      !Object.values(DELEGATION_SUBJECTS).every((delegationSubject) =>
        hasOwnerDelegation(ledgerText, delegationSubject),
      )
    )
      throw new Error("delegated envelope authority required");
    if (Number(envelope.fields.reserveUsd) > 10)
      throw new Error("delegated envelope exceeds US$10");
  }
  if (
    envelope.fields.project !== packet.projects.join(",") ||
    Number(envelope.fields.maxRequests) < packet.maxRequests ||
    Number(envelope.fields.reserveUsd) < packet.reserveUsd
  )
    throw new Error("packet exceeds owner envelope");
  return Object.freeze({
    status: "APPROVAL_BOUND_LOCAL_ONLY",
    sendAuthorized: false,
    decisionLine: decision.line,
    envelopeLine: envelope.line,
    envelopeId,
  });
}

/** A ROOT-injected refresh body; its getters and parser never perform hidden HTTP or create accounts. */
export function createOwnerOnlyProvider(options) {
  nativeClosed(options, ["refreshBody", "nowSeconds", "digestSalt"], "owner provider");
  if (
    !Buffer.isBuffer(options.refreshBody) ||
    options.refreshBody.length > 8192 ||
    typeof options.nowSeconds !== "function" ||
    !/^[a-f0-9]{64}$/.test(options.digestSalt)
  )
    fail("invalid owner provider");
  const body = Buffer.from(options.refreshBody),
    form = new URLSearchParams(body.toString("utf8"));
  if (
    [...form.keys()].length !== 4 ||
    new Set(form.keys()).size !== 4 ||
    !["grant_type", "client_id", "client_secret", "refresh_token"].every((key) => form.has(key)) ||
    form.get("grant_type") !== "refresh_token" ||
    ["client_id", "client_secret", "refresh_token"].some(
      (key) => !form.get(key) || /[\r\n\0]/.test(form.get(key)),
    )
  )
    fail("closed owner OAuth body required");
  let owner = null;
  return Object.freeze({
    prepare: () => ({
      url: "https://oauth2.googleapis.com/token",
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
      body: Buffer.from(body),
    }),
    install(raw) {
      const value = raw.status === 200 ? JSON.parse(raw.bytes.toString("utf8")) : null;
      if (
        !plain(value) ||
        typeof value.access_token !== "string" ||
        !/^[!-~]{20,4096}$/.test(value.access_token) ||
        value.token_type !== "Bearer" ||
        !Number.isSafeInteger(value.expires_in) ||
        value.expires_in <= 60 ||
        value.expires_in > 7200
      )
        fail("owner refresh outcome unknown");
      owner = { token: value.access_token, expiresAt: options.nowSeconds() + value.expires_in };
      return {
        status: "OWNER_OAUTH_COUNTED",
        sendAuthorized: false,
        expiresAt: owner.expiresAt,
        tokenSha256: createHmac("sha256", Buffer.from(options.digestSalt, "hex"))
          .update("storage-native-owner-token\0")
          .update(owner.token)
          .digest("hex"),
      };
    },
    fresh: () => owner !== null && owner.expiresAt - options.nowSeconds() > 60,
    headersFor(credential, context) {
      if (credential === "anonymous") return {};
      if (
        credential !== "admin" ||
        context.project !== NATIVE_PROJECT ||
        !owner ||
        owner.expiresAt - options.nowSeconds() <= 60
      )
        fail("owner credential unavailable");
      return {
        authorization: `Bearer ${owner.token}`,
        ...(context.quotaProject ? { "x-goog-user-project": NATIVE_PROJECT } : {}),
      };
    },
  });
}

/** Derived narrow caps are enforced before effects; the reused reservation journal records its legacy ceiling. */
export function createNativeGate(options) {
  nativeClosed(
    options,
    [
      "manifest",
      "admission",
      "reservations",
      "capture",
      "targets",
      "provider",
      "lease",
      "transport",
      "nowSeconds",
    ],
    "native gate",
  );
  const manifest = validateNativeManifest(options.manifest),
    { admission, reservations, capture, targets, provider, lease, nowSeconds } = options;
  const transport = leaseTransport(lease, options.transport),
    rows = new Map(manifest.rows.map((row) => [row.id, row]));
  const preflight = manifest.rows.filter((row) => row.phase === "preflight").map((row) => row.id);
  let mode = "not-started",
    busy = false,
    unknown = false,
    poisoned = false,
    refused = false,
    requests = 0,
    normal = 0,
    recovery = 0,
    startedAt = null;
  const used = new Set();
  function check() {
    if (
      busy ||
      poisoned ||
      unknown ||
      refused ||
      !["preflight", "normal", "recovery"].includes(mode)
    )
      fail("native gate unavailable");
    if (nowSeconds() - startedAt > manifest.limits.deadlineSeconds)
      fail("native deadline exhausted");
  }
  async function admitted() {
    let result;
    try {
      result = await admission.check();
    } catch (error) {
      refused = true;
      throw error;
    }
    if (result?.admitted !== true) {
      refused = true;
      fail("native admission refused");
    }
  }
  async function dispatch(id, prepared, credential) {
    check();
    busy = true;
    let durableStarted = false;
    try {
      const row = rows.get(id);
      if (!row || row.phase !== mode || (row.kind === "owner-credential") !== credential)
        fail("undeclared native phase or route");
      if (used.has(id)) fail("duplicate used native ID");
      if (
        requests >= manifest.counts.total ||
        (mode === "recovery"
          ? recovery >= manifest.counts.recovery
          : normal >= manifest.counts.normal)
      )
        fail("derived native cap exhausted");
      const spec = credential ? provider.prepare(row) : prepared.spec;
      if (
        credential
          ? spec.url !== "https://oauth2.googleapis.com/token" ||
            spec.method !== "POST" ||
            !Buffer.isBuffer(spec.body)
          : !targets.verify(prepared) ||
            prepared.rowId !== id ||
            prepared.project !== NATIVE_PROJECT ||
            prepared.credential !== row.request.credential
      )
        fail("closed native target required");
      transport.validate(spec);
      await admitted();
      if (capture.snapshot().uncertain) fail("capture journal uncertain");
      used.add(id);
      durableStarted = true;
      await capture.writeIntent({
        operationId: id,
        phase: mode,
        targetSha256: credential
          ? nativeDigest([spec.url, spec.method, nativeDigest(spec.body)])
          : prepared.targetSha256,
        redactedTarget: credential ? "POST https://oauth2.googleapis.com/token" : prepared.redacted,
        mutationKey: row.request.method === "GET" || credential ? null : `native/${id}`,
      });
      if (credential) await capture.writeDelegatedTarget({ operationId: id, ...spec });
      await reservations.onReserve({ attempt: requests + 1, operationId: id, phase: mode });
      requests++;
      if (mode === "recovery") recovery++;
      else normal++;
      let raw;
      try {
        const headers = credential
          ? spec.headers
          : {
              ...spec.headers,
              ...provider.headersFor(prepared.credential, {
                project: NATIVE_PROJECT,
                quotaProject: quotaProjectRequired(spec),
              }),
            };
        const response = await transport.send({ ...spec, headers });
        raw = nativeSnapshot(response, "observed native response");
        nativeClosed(raw, ["status", "rawHeaders", "bytes"], "observed native response");
      } catch {
        unknown = true;
        await capture.writeNote({
          operationId: id,
          text: "counted request outcome unknown; never retry",
        });
        fail("native transport outcome unknown");
      }
      try {
        await capture.writeResponse({ operationId: id, attempt: requests, response: raw });
      } catch {
        poisoned = true;
        fail("native capture failed after effect");
      }
      if (credential) {
        let proof;
        try {
          proof = provider.install(raw);
        } catch {
          unknown = true;
          fail("owner refresh outcome unknown");
        }
        await capture.writeCredentialProof({ ...proof, operationId: id, attempt: requests });
      }
      return { raw, attempt: requests, row };
    } catch (error) {
      if (durableStarted && !unknown) poisoned = true;
      throw error;
    } finally {
      busy = false;
    }
  }
  return Object.freeze({
    async start() {
      if (mode !== "not-started" || busy || refused) fail("native gate already started");
      busy = true;
      try {
        const seen = await admission.begin();
        if (seen?.admitted !== true) fail("native admission refused");
        await reservations.onStarted({
          runId: manifest.runId,
          ...manifest.legacyReservationCeiling,
          preflightIds: preflight,
        });
        startedAt = nowSeconds();
        mode = "preflight";
        await capture.writeNote({
          operationId: null,
          text: JSON.stringify({
            kind: "NARROW_DERIVED_CAP",
            cap: manifest.counts,
            legacyReservationCeiling: manifest.legacyReservationCeiling,
            accountProof: manifest.accountProof,
          }),
        });
      } catch (error) {
        refused = true;
        throw error;
      } finally {
        busy = false;
      }
    },
    send: (prepared) => dispatch(prepared.rowId, prepared, false),
    sendCredential: (id) => dispatch(id, null, true),
    admit() {
      check();
      if (mode !== "preflight" || preflight.some((id) => !used.has(id)))
        fail("native preflight incomplete");
      mode = "normal";
    },
    enterRecovery() {
      check();
      if (mode !== "normal") fail("native recovery already entered");
      mode = "recovery";
    },
    async finish(outcome) {
      check();
      busy = true;
      try {
        await reservations.onTerminal({
          outcome,
          requests,
          normal,
          recovery,
          maxRequests: manifest.legacyReservationCeiling.maxRequests,
        });
        mode = "closed";
      } catch (error) {
        poisoned = true;
        throw error;
      } finally {
        busy = false;
      }
    },
    markUnknown() {
      unknown = true;
    },
    snapshot: () => ({
      mode,
      requests,
      normal,
      recovery,
      used: [...used],
      unknown,
      poisoned,
      refused,
      derivedCap: manifest.counts,
      legacyReservationCeiling: manifest.legacyReservationCeiling,
    }),
  });
}

export async function runNativeRecordCommand({ out = () => {} } = {}) {
  out("HOLD: fresh ROOT admission and live capability are unavailable");
  return 3;
}

/** Preserve the transport frame verbatim; timing has its own receipt and grants no authority. */
export function projectNativeTransportResponse(response) {
  const frame = nativeSnapshot(response, "native transport frame");
  nativeClosed(
    frame,
    ["status", "rawHeaders", "bytes", "startedAtMs", "finishedAtMs"],
    "native transport frame",
  );
  if (
    !Number.isInteger(frame.status) ||
    frame.status < 100 ||
    frame.status > 599 ||
    !Buffer.isBuffer(frame.bytes) ||
    frame.bytes.length > 2 * 1024 * 1024 ||
    !Array.isArray(frame.rawHeaders) ||
    frame.rawHeaders.length % 2 ||
    frame.rawHeaders.some((value) => typeof value !== "string" || /[\r\n]/.test(value)) ||
    frame.rawHeaders.reduce((sum, value) => sum + Buffer.byteLength(value) + 2, 0) > 32 * 1024 ||
    !Number.isSafeInteger(frame.startedAtMs) ||
    frame.startedAtMs < 0 ||
    !Number.isSafeInteger(frame.finishedAtMs) ||
    frame.finishedAtMs < frame.startedAtMs
  )
    fail("unknown native transport frame");
  return Object.freeze({
    raw: Object.freeze({ status: frame.status, rawHeaders: frame.rawHeaders, bytes: frame.bytes }),
    timing: Object.freeze({ startedAtMs: frame.startedAtMs, finishedAtMs: frame.finishedAtMs }),
  });
}

const STABLE = ["content-type", "content-length", "x-content-type-options", "cache-control"];
export function nativeRawRecord(raw) {
  if (
    !plain(raw) ||
    !Number.isInteger(raw.status) ||
    raw.status < 100 ||
    raw.status > 599 ||
    !Buffer.isBuffer(raw.bytes) ||
    raw.bytes.length > 2 * 1024 * 1024 ||
    !Array.isArray(raw.rawHeaders) ||
    raw.rawHeaders.length % 2 ||
    raw.rawHeaders.some((v) => typeof v !== "string" || /[\r\n]/.test(v))
  )
    fail("unknown native response");
  const headers = Object.fromEntries(STABLE.map((key) => [key, null]));
  for (let i = 0; i < raw.rawHeaders.length; i += 2) {
    const key = raw.rawHeaders[i].toLowerCase();
    if (STABLE.includes(key)) {
      if (headers[key] !== null) fail("duplicate stable header");
      headers[key] = raw.rawHeaders[i + 1];
    }
  }
  if (headers["content-length"] !== null && headers["content-length"] !== String(raw.bytes.length))
    fail("native response byte length");
  return {
    status: raw.status,
    bodyBytes: raw.bytes.length,
    bodySha256: nativeDigest(raw.bytes),
    bodyBase64: raw.bytes.toString("base64"),
    headers,
  };
}
const sameRaw = (a, b) => nativeDigest(nativeRawRecord(a)) === nativeDigest(nativeRawRecord(b));
const rawBody = (raw) => JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(raw.bytes));
const googleAbsent = (raw) => {
  const b = rawBody(raw);
  return (
    raw.status === 404 && plain(b?.error) && b.error.code === 404 && b.error.status === "NOT_FOUND"
  );
};

function validateResponseContracts(manifest, contracts) {
  nativeClosed(
    contracts,
    [
      "allowed",
      "denied",
      "noRelease",
      "adminMedia",
      "objectDelete",
      "prefixEmpty",
      "metadataAbsence",
      "mediaAbsence",
    ],
    "native response contracts",
  );
  for (const key of ["allowed", "denied", "noRelease", "adminMedia", "objectDelete", "prefixEmpty"])
    nativeRawRecord(contracts[key]);
  for (const key of ["allowed", "adminMedia"])
    if (contracts[key].status !== 200 || !contracts[key].bytes.equals(Buffer.from("next")))
      fail("literal owned media contract required");
  for (const [key, status] of [
    ["denied", 403],
    ["noRelease", 400],
  ]) {
    const raw = contracts[key],
      body = rawBody(raw);
    if (
      raw.status !== status ||
      !plain(body?.error) ||
      body.error.code !== status ||
      typeof body.error.message !== "string" ||
      !body.error.message ||
      !nativeRawRecord(raw).headers["content-type"]?.startsWith("application/json")
    )
      fail("typed Firebase rejection contract required");
  }
  if (contracts.objectDelete.status !== 204 || contracts.objectDelete.bytes.length !== 0)
    fail("typed object deletion contract required");
  const empty = rawBody(contracts.prefixEmpty);
  if (
    contracts.prefixEmpty.status !== 200 ||
    !plain(empty) ||
    Object.keys(empty).some((key) => key !== "items") ||
    (empty.items !== undefined && (!Array.isArray(empty.items) || empty.items.length))
  )
    fail("complete empty prefix contract required");
  for (const key of ["metadataAbsence", "mediaAbsence"])
    nativeClosed(contracts[key], manifest.resources.objects, `native ${key} contracts`);
  for (const name of manifest.resources.objects) {
    const metadata = contracts.metadataAbsence[name],
      media = contracts.mediaAbsence[name];
    nativeRawRecord(metadata);
    nativeRawRecord(media);
    if (
      !googleAbsent(metadata) ||
      typeof rawBody(metadata).error.message !== "string" ||
      !rawBody(metadata).error.message
    )
      fail("typed metadata absence contract required");
    if (
      media.status !== 404 ||
      !media.bytes.equals(Buffer.from(`No such object: ${manifest.bucket}/${name}`))
    )
      fail("typed media absence contract required");
  }
}

function nativeTables(manifest) {
  const consumers = Object.fromEntries(RUNTIME_REF_KINDS.map((k) => [k, {}])),
    producers = Object.fromEntries(RUNTIME_REF_KINDS.map((k) => [k, {}])),
    deleters = [];
  for (const row of manifest.rows) {
    const visit = (value) => {
      if (value && typeof value === "object") {
        if (value.kind === "runtime-reference") {
          (consumers[value.type][value.key] ??= []).push(row.id);
          if (row.request.method === "DELETE" && value.type === "generation")
            deleters.push(`${value.type}|${value.key}|${row.id}`);
        }
        for (const v of Object.values(value)) visit(v);
      }
    };
    visit(row.request);
  }
  for (const name of manifest.resources.objects)
    if (consumers.generation[name])
      producers.generation[name] = manifest.rows
        .filter((r) => r.resource === name && ["seed", "metadata"].includes(r.kind))
        .map((row) => ({
          operationId: row.id,
          verdict: row.kind === "seed" ? "accepted" : "present",
        }));
  producers["ruleset-name"].A = [{ operationId: "ruleset/A/create", verdict: "accepted" }];
  if (manifest.baseline.kind === "present")
    producers["ruleset-name"].baseline = [
      { operationId: "preflight/release/bucket", verdict: "present" },
    ];
  for (const row of manifest.rows.filter((r) => r.kind === "rules-list"))
    if (consumers["page-token"][row.listBase])
      (producers["page-token"][row.listBase] ??= []).push({
        operationId: row.id,
        verdict: "accepted",
      });
  return { consumers, producers, deleters, pinned: {}, pinnedSteps: {} };
}

/** Exercise the real narrow controller with supplied IO; synthetic captures never become production closure proofs. */
export function createNativeDriver(options) {
  nativeClosed(
    options,
    [
      "manifest",
      "gate",
      "targets",
      "refs",
      "objects",
      "capture",
      "provider",
      "wait",
      "nowSeconds",
      "responseContracts",
      "evidenceKind",
    ],
    "native driver",
  );
  const manifest = validateNativeManifest(options.manifest),
    schedule = buildNativeSchedule(manifest),
    { gate, targets, refs, objects, capture, provider, wait, nowSeconds } = options,
    responseContracts = nativeSnapshot(options.responseContracts, "native response contracts");
  if (
    options.evidenceKind !== "SYNTHETIC_ONLY" ||
    typeof wait !== "function" ||
    typeof nowSeconds !== "function"
  )
    fail("live native capability unavailable");
  validateResponseContracts(manifest, responseContracts);
  const rows = new Map(manifest.rows.map((r) => [r.id, r])),
    evidence = [],
    rawById = new Map(),
    metadata = new Map(),
    baselineDecisions = new Map();
  let runStarted = false,
    recoveryStarted = false,
    condition = false,
    failed = false,
    sourceOwned = false,
    sourceName = null,
    published = false,
    restored = false,
    sourceAbsent = false,
    restoredSettled = false,
    finished = null;
  const deleted = new Set(),
    absences = new Map(),
    initialRulesets = new Map(),
    finalRulesets = new Map();
  const owner = {};
  async function bind(type, key, value, row, attempt, verdict, deletable = false) {
    await refs.bind({
      ref: nativeRef(type, key),
      value,
      provenance: { operationId: row.id, attempt, verdict, deletable },
    });
  }
  function requireRaw(raw, expected, label) {
    if (!expected || !sameRaw(raw, expected)) fail(`${label} native bytes or stable headers`);
  }
  function metadataOf(raw, row) {
    const b = rawBody(raw);
    if (
      raw.status !== 200 ||
      !plain(b) ||
      b.name !== row.resource ||
      b.bucket !== manifest.bucket ||
      typeof b.generation !== "string" ||
      !/^[1-9]\d{0,18}$/.test(b.generation)
    )
      fail("owned metadata success required");
    return b;
  }
  function rule(kind, row, raw) {
    const result = RULES_CLASSIFIERS[kind](row, readResponse(raw));
    if (result.verdict === "unexpected") fail("unknown Rules response");
    return result;
  }
  function requireBaseline(raw, row) {
    const r = rule("rules-release-read", row, raw);
    if (
      manifest.baseline.kind === "absent"
        ? r.verdict !== "absent"
        : r.verdict !== "present" ||
          r.facts.releaseName !== manifest.baseline.release.name ||
          r.facts.rulesetName !== manifest.baseline.release.rulesetName ||
          (row.kind === "release-baseline" &&
            r.facts.updateTime !== manifest.baseline.release.updateTime)
    )
      fail("packet baseline mismatch");
    return r;
  }
  async function credentials(row) {
    if (row.request.credential !== "admin" || provider.fresh()) return;
    const phase = gate.snapshot().mode;
    const id = manifest.rows.find(
      (r) =>
        r.kind === "owner-credential" && r.phase === phase && !gate.snapshot().used.includes(r.id),
    )?.id;
    if (!id) fail("explicit owner credential cap exhausted");
    await gate.sendCredential(id);
  }
  async function send(id) {
    const row = rows.get(id);
    if (!row) fail("undeclared native step");
    if (row.kind === "owner-credential") return gate.sendCredential(id);
    await credentials(row);
    const prepared = targets.prepare(row, (ref, consumer) => refs.resolve(ref, consumer));
    const { raw, attempt } = await gate.send(prepared);
    const record = nativeRawRecord(raw);
    evidence.push({
      id,
      phase: row.phase,
      kind: row.kind,
      requestSha256: prepared.targetSha256,
      attempt,
      response: record,
    });
    rawById.set(id, raw);
    let outcome = { kind: row.kind, verdict: "accepted", facts: { status: raw.status } };
    try {
      if (row.kind === "userinfo") {
        const b = rawBody(raw);
        if (raw.status !== 200 || !plain(b) || typeof b.id !== "string" || b.id.length === 0)
          fail("owner userinfo unknown");
      } else if (row.kind === "bucket") {
        if (raw.status !== 200 || rawBody(raw).name !== manifest.bucket)
          fail("bucket preflight mismatch");
      } else if (row.kind === "release-baseline") {
        outcome = requireBaseline(raw, row);
        if (id === "preflight/release/bucket" && manifest.baseline.kind === "present")
          await bind(
            "ruleset-name",
            "baseline",
            outcome.facts.rulesetName,
            row,
            attempt,
            "present",
            false,
          );
      } else if (row.kind === "release-absent") {
        outcome = rule("rules-release-read", row, raw);
        if (outcome.verdict !== "absent") fail("release absence required");
      } else if (row.kind === "baseline-source") {
        outcome = rule("rules-ruleset-read", row, raw);
        if (
          outcome.verdict !== "present" ||
          outcome.facts.rulesetName !== manifest.baseline.release.rulesetName ||
          outcome.facts.sourceSha256 !== nativeDigest(manifest.baseline.source)
        )
          fail("baseline source mismatch");
      } else if (row.kind === "rules-list") {
        outcome = rule("rules-list-page", row, raw);
        if (outcome.verdict !== "accepted") fail("Rules page unknown");
        const list = row.phase === "preflight" ? initialRulesets : finalRulesets;
        for (const entry of outcome.facts.rulesets) {
          if (list.has(entry.name)) fail("duplicate Rules inventory entry");
          list.set(entry.name, entry.services);
        }
        if (outcome.facts.hasNextPage && rows.has(`${row.listBase}/${row.page + 1}`))
          await bind(
            "page-token",
            row.listBase,
            outcome.facts.nextPageToken,
            row,
            attempt,
            "accepted",
          );
      } else if (row.kind === "metadata-absent" || row.kind === "media-absent") {
        const expected =
          responseContracts[row.kind === "metadata-absent" ? "metadataAbsence" : "mediaAbsence"][
            row.resource
          ];
        requireRaw(raw, expected, "typed owned absence");
        outcome = {
          kind: row.kind === "metadata-absent" ? "gcs-metadata-read" : "gcs-media-read",
          verdict: "absent",
          facts: { status: raw.status },
        };
        if (id.includes("cleanup/")) {
          const set = absences.get(row.resource) ?? new Set();
          set.add(row.kind);
          absences.set(row.resource, set);
        }
      } else if (row.kind === "seed") {
        const b = metadataOf(raw, row);
        outcome = {
          kind: "gcs-seed-upload",
          verdict: "accepted",
          facts: { status: 200, generation: b.generation },
        };
        await bind("generation", row.resource, b.generation, row, attempt, "accepted", true);
      } else if (row.kind === "metadata") {
        const b = metadataOf(raw, row);
        const saved = metadata.get(row.resource);
        if (saved && !sameRaw(saved, raw)) fail("owned metadata continuity");
        metadata.set(row.resource, raw);
        outcome = {
          kind: "gcs-metadata-read",
          verdict: "present",
          facts: { status: 200, generation: b.generation },
        };
        await bind(
          "generation",
          row.resource,
          b.generation,
          row,
          attempt,
          "present",
          objects.object(row.resource).owned,
        );
      } else if (row.kind === "media") {
        requireRaw(raw, responseContracts.adminMedia, "owned Admin media");
        outcome = { kind: "gcs-media-read", verdict: "present", facts: { status: 200 } };
      } else if (row.kind === "decision") {
        if (id.startsWith("baseline/")) {
          if (manifest.baseline.kind === "absent")
            requireRaw(raw, responseContracts.noRelease, "baseline no-release");
          else if (raw.status === 200) requireRaw(raw, responseContracts.allowed, "baseline allow");
          else requireRaw(raw, responseContracts.denied, "baseline deny");
          baselineDecisions.set(row.resource, raw);
        } else {
          const expected = row.settleBase?.includes("baseline")
            ? baselineDecisions.get(row.resource)
            : row.resource === manifest.resources.objects[0]
              ? responseContracts.allowed
              : responseContracts.denied;
          if (
            row.settleBase &&
            !sameRaw(raw, expected) &&
            [responseContracts.allowed, responseContracts.denied, responseContracts.noRelease].some(
              (known) => sameRaw(raw, known),
            )
          )
            outcome.verdict = "not-yet";
          else requireRaw(raw, expected, "installed or restored witness");
        }
      } else if (row.kind === "valid-test" || row.kind === "invalid-test") {
        outcome = rule("rules-test", row, raw);
        if (
          row.kind === "valid-test"
            ? outcome.verdict !== "accepted"
            : outcome.verdict !== "rejected"
        )
          fail("invalid refusal or valid acceptance missing");
        if (row.kind === "invalid-test" && raw.status === 200) {
          const issues = rawBody(raw).issues;
          if (
            !issues.some(
              (issue) =>
                issue.severity === "ERROR" &&
                issue.sourcePosition.fileName === "storage.rules" &&
                Number.isSafeInteger(issue.sourcePosition.line) &&
                issue.sourcePosition.line > 0 &&
                Number.isSafeInteger(issue.sourcePosition.column) &&
                issue.sourcePosition.column > 0,
            )
          )
            fail("invalid positioned ERROR missing");
        }
      } else if (row.kind === "source-create") {
        outcome = rule("rules-ruleset-create", row, raw);
        if (
          outcome.verdict !== "accepted" ||
          initialRulesets.has(outcome.facts.rulesetName) ||
          outcome.facts.sourceSha256 !== manifest.sources.A.sha256
        )
          fail("owned A create proof required");
        sourceOwned = true;
        sourceName = outcome.facts.rulesetName;
        await bind("ruleset-name", "A", sourceName, row, attempt, "accepted", true);
      } else if (row.kind === "source-read") {
        outcome = rule("rules-ruleset-read", row, raw);
        if (
          !sourceOwned ||
          outcome.verdict !== "present" ||
          outcome.facts.rulesetName !== sourceName ||
          outcome.facts.sourceSha256 !== manifest.sources.A.sha256
        )
          fail("owned A source authority");
      } else if (row.kind === "release-publish") {
        outcome = rule(
          manifest.baseline.kind === "absent" ? "rules-release-create" : "rules-release-patch",
          row,
          raw,
        );
        if (outcome.verdict !== "accepted" || outcome.facts.rulesetName !== sourceName)
          fail("A publication identity mismatch");
        published = true;
      } else if (row.kind === "release-identity" || row.kind === "release-guard") {
        outcome = rule("rules-release-read", row, raw);
        if (
          !sourceOwned ||
          outcome.verdict !== "present" ||
          outcome.facts.rulesetName !== sourceName ||
          outcome.facts.releaseName !== manifest.releaseName
        )
          fail("guarded A release mismatch");
      } else if (row.kind === "release-restore") {
        outcome = rule(
          manifest.baseline.kind === "absent" ? "rules-release-delete" : "rules-release-patch",
          row,
          raw,
        );
        if (
          outcome.verdict !== "accepted" ||
          (manifest.baseline.kind === "present" &&
            outcome.facts.rulesetName !== manifest.baseline.release.rulesetName)
        )
          fail("baseline restore effect unknown");
      } else if (row.kind === "release-restored") {
        outcome = requireBaseline(raw, row);
        restored = true;
      } else if (row.kind === "source-delete") {
        if (!sourceOwned || !restored || !restoredSettled || sourceAbsent)
          fail("unowned or referenced Ruleset delete");
        outcome = rule("rules-ruleset-delete", row, raw);
        if (outcome.verdict !== "accepted") fail("Ruleset delete unknown");
      } else if (row.kind === "source-absent") {
        outcome = rule("rules-ruleset-read", row, raw);
        if (outcome.verdict !== "absent") fail("typed Ruleset absence required");
        sourceAbsent = true;
      } else if (row.kind === "object-delete") {
        if (!objects.object(row.resource).owned || deleted.has(row.resource))
          fail("owned object delete guard");
        requireRaw(raw, responseContracts.objectDelete, "object delete");
        deleted.add(row.resource);
      } else if (row.kind === "prefix-empty")
        requireRaw(raw, responseContracts.prefixEmpty, "complete owned prefix empty");
      else fail("unclassified native step");
      objects.recordOutcome(row, outcome);
      await capture.writeFacts({
        operationId: id,
        kind: outcome.kind,
        verdict: outcome.verdict,
        facts: outcome.facts,
      });
      return outcome;
    } catch (error) {
      gate.markUnknown();
      throw error;
    }
  }
  async function step(entry) {
    if (entry.kind === "pages") {
      for (const id of entry.ids) {
        const out = await send(id);
        if (!out.facts.hasNextPage) return;
      }
      fail("finite Rules page budget exhausted");
    } else if (entry.kind === "settle") {
      let consecutive = 0;
      for (let i = 0; i < entry.ids.length; i += 2) {
        let complete = true;
        for (const id of entry.ids.slice(i, i + 2)) {
          try {
            if ((await send(id)).verdict !== "accepted") complete = false;
          } catch (error) {
            if (gate.snapshot().unknown) throw error;
            complete = false;
          }
        }
        consecutive = complete ? consecutive + 1 : 0;
        if (consecutive === 2) {
          if (entry.group.includes("baseline")) restoredSettled = true;
          return;
        }
        if (i + 2 < entry.ids.length) await wait(manifest.limits.intervalMs);
      }
      fail("finite complete settle budget exhausted");
    } else {
      const row = rows.get(entry.ids[0]);
      if (row.request.method !== "GET" && row.kind !== "owner-credential") {
        const decision = objects.evaluate(row);
        if (
          decision.decision !== "go" ||
          (row.kind === "object-delete" && !objects.object(row.resource).deletable)
        )
          fail("resource mutation guard");
        objects.recordIntent(row);
      }
      await send(row.id);
    }
  }
  function installedPreserved() {
    const ids = [
      "release",
      "source",
      ...manifest.resources.objects.flatMap((_, i) => [
        `${i === 0 ? "allow" : "deny"}/metadata`,
        `${i === 0 ? "allow" : "deny"}/media`,
        `${i === 0 ? "allow" : "deny"}/decision`,
      ]),
    ];
    if (
      ids.some(
        (id) =>
          !rawById.has(`before/${id}`) ||
          !rawById.has(`after/${id}`) ||
          !sameRaw(rawById.get(`before/${id}`), rawById.get(`after/${id}`)),
      )
    )
      fail("installed before/after proof missing or changed");
  }
  function cleanupProof() {
    if (
      !restored ||
      !restoredSettled ||
      !sourceAbsent ||
      objects.residual().length ||
      manifest.resources.objects.some((name) => absences.get(name)?.size !== 2) ||
      nativeDigest([...initialRulesets].toSorted()) !== nativeDigest([...finalRulesets].toSorted())
    )
      fail("typed cleanup incomplete");
  }
  async function conclude(status) {
    cleanupProof();
    await gate.finish(status);
    const result = Object.freeze({
      status,
      evidenceKind: "SYNTHETIC_ONLY",
      supplementPassed: condition,
      closureReady: false,
      parentClaim: false,
      evidence: Object.freeze([...evidence]),
      usage: gate.snapshot(),
      accountProof: manifest.accountProof,
      manifestSha256: manifest.manifestSha256,
    });
    finished = markCleanResult(result, owner);
    return result;
  }
  return Object.freeze({
    async run() {
      if (runStarted) fail("native run already attempted");
      runStarted = true;
      await gate.start();
      try {
        for (const entry of schedule.preflight) await step(entry);
        gate.admit();
        for (const entry of schedule.normal) {
          if (entry.ids.includes("restore/guard")) {
            installedPreserved();
            condition = true;
          }
          await step(entry);
        }
        return await conclude("finished");
      } catch (error) {
        failed = true;
        await capture
          .writeNote({
            operationId: null,
            text: `native STOP: ${String(error.message).slice(0, 500)}`,
          })
          .catch(() => {});
        return Object.freeze({
          status: "needs-recovery",
          evidenceKind: "SYNTHETIC_ONLY",
          supplementPassed: false,
          closureReady: false,
          parentClaim: false,
          reason: error.message,
          evidence: [...evidence],
          usage: gate.snapshot(),
        });
      }
    },
    async recover() {
      if (!failed || recoveryStarted) fail("one recovery only");
      recoveryStarted = true;
      if (gate.snapshot().unknown || gate.snapshot().poisoned || !sourceOwned || !published)
        fail("unknown or unowned recovery retains lock");
      gate.enterRecovery();
      for (const entry of schedule.recovery) await step(entry);
      return conclude("recovered");
    },
    confirmCleanClose(lease, result) {
      if (result !== finished) fail("foreign clean result");
      confirmCleanClose(lease, result, owner);
    },
    snapshot: () => ({
      runStarted,
      recoveryStarted,
      condition,
      failed,
      sourceOwned,
      published,
      restored,
      sourceAbsent,
      objects: objects.snapshot(),
      usage: gate.snapshot(),
    }),
  });
}

/** No built-in production sender or credential-file loader is exposed by this source slice. */
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.exitCode = await runNativeRecordCommand({
    out: (line) => process.stderr.write(`${line}\n`),
  });

/** Bind the narrow driver, fixed entry, transport and independent test models by their actual bytes. */
export function nativeRunnerDigest() {
  return nativeDigest(
    Object.fromEntries(
      [
        "./management-native-manifest.mjs",
        "./management-native-schedule.mjs",
        "./management-native-record.mjs",
        "../storage-rules-management-native.test.mjs",
        "./management-native-entry.mjs",
        "./http-transport.mjs",
        "../storage-rules-management-native-entry.test.mjs",
      ].map((path) => [path, nativeDigest(readFileSync(new URL(path, import.meta.url)))]),
    ),
  );
}

/** Offline-only assembly. The live CLI remains null: these supplied mocks do not authorize production. */
export async function withNativeMockRecording(options, use) {
  nativeClosed(
    options,
    [
      "manifest",
      "packet",
      "review",
      "readLedger",
      "readCurrent",
      "directory",
      "lockOptions",
      "usagePath",
      "transport",
      "clock",
      "refreshBody",
      "responseContracts",
    ],
    "native mock assembly",
  );
  const manifest = validateNativeManifest(options.manifest),
    { readLedger, readCurrent, directory } = options,
    packet = nativeSnapshot(options.packet, "native packet"),
    review = nativeSnapshot(options.review, "native review"),
    responseContracts = nativeSnapshot(options.responseContracts, "native response contracts"),
    refreshBody = nativeSnapshot(options.refreshBody, "owner refresh bytes");
  nativeClosed(options.clock, ["nowSeconds", "sleep"], "native clock");
  const clock = Object.freeze({ nowSeconds: options.clock.nowSeconds, sleep: options.clock.sleep });
  nativeClosed(clock, ["nowSeconds", "sleep"], "native clock");
  if (
    typeof use !== "function" ||
    [readLedger, readCurrent, clock.nowSeconds, clock.sleep].some((fn) => typeof fn !== "function")
  )
    fail("invalid native mock assembly");
  if (
    packet.runnerSha256 !== nativeRunnerDigest() ||
    packet.fixtureSchemaSha256 !== nativeDigest(responseContracts)
  )
    fail("native source or fixture receipt mismatch");
  validateResponseContracts(manifest, responseContracts);
  const usage = createRecordingUsage({
    path: options.usagePath,
    packetSha256: packet.packetSha256,
  });
  const lockOptions = {
    ...options.lockOptions,
    projects: [NATIVE_PROJECT],
    taskId: packet.taskId,
    packetId: packet.packetName,
    sourceCommit: manifest.sourceCommit,
  };
  return withProjectLocks(lockOptions, async (lease) => {
    let refused = false,
      begun = false;
    const check = async () => {
      if (refused) fail("native admission permanently refused");
      try {
        const current = nativeSnapshot(await readCurrent(), "fresh current admission");
        if (current.kind !== "MOCK_CURRENT_ADMISSION")
          fail("mock assembly does not accept live ROOT capability");
        validateNativeApproval({
          ledgerText: await readLedger(),
          packet,
          review,
          manifest,
          current,
          nowSeconds: clock.nowSeconds(),
        });
        if ((await lease.verifyHeld()) !== true) fail("native query project lock lost");
        return { admitted: true };
      } catch (error) {
        refused = true;
        throw error;
      }
    };
    const admission = {
      check,
      async begin() {
        if (begun) fail("native admission already begun");
        begun = true;
        const seen = await check(),
          before = await usage.startedRunIds();
        if (before.includes(manifest.runId) || before.length >= 2)
          fail("native recording usage exhausted");
        await usage.markStarted(manifest.runId);
        if (!(await usage.startedRunIds()).includes(manifest.runId))
          fail("native usage marker not durable");
        return seen;
      },
    };
    const requestIds = manifest.rows.map((row) => row.id),
      preflightIds = manifest.rows.filter((row) => row.phase === "preflight").map((row) => row.id);
    const digestSalt = createHash("sha256")
      .update(`synthetic-native-only:${manifest.manifestSha256}`)
      .digest("hex");
    let reservations, capture;
    try {
      reservations = await createReservationJournal({
        directory,
        runId: manifest.runId,
        sourceCommit: manifest.sourceCommit,
        manifestDigest: manifest.manifestSha256,
        requestIds,
        preflightIds,
        io: { open, lstat },
      });
      capture = await createCaptureJournal({
        directory,
        runId: manifest.runId,
        sourceCommit: manifest.sourceCommit,
        manifestDigest: manifest.manifestSha256,
        digestSalt,
        requestIds,
        io: { open, lstat, mkdir },
      });
      const refs = createRuntimeRefStore({
        tables: nativeTables(manifest),
        runId: manifest.runId,
        digestSalt,
        writeProof: (proof) => capture.writeProof(proof),
      });
      const objects = createResourceLedger({ manifest }),
        underlying = createTargetBuilder({ manifest, digestSalt }),
        canonical = new Map(manifest.rows.map((row) => [row.id, row])),
        issued = new WeakSet();
      const targets = Object.freeze({
        prepare(row, resolve) {
          const actual = canonical.get(row.id);
          if (!actual || nativeDigest(row) !== nativeDigest(actual))
            fail("noncanonical native target row");
          const prepared = underlying.prepare(actual, resolve);
          issued.add(prepared);
          return prepared;
        },
        verify: (prepared) => issued.has(prepared) && underlying.verify(prepared),
      });
      const provider = createOwnerOnlyProvider({
        refreshBody,
        nowSeconds: clock.nowSeconds,
        digestSalt,
      });
      const gate = createNativeGate({
        manifest,
        admission,
        reservations,
        capture,
        targets,
        provider,
        lease,
        transport: options.transport,
        nowSeconds: clock.nowSeconds,
      });
      const driver = createNativeDriver({
        manifest,
        gate,
        targets,
        refs,
        objects,
        capture,
        provider,
        wait: clock.sleep,
        nowSeconds: clock.nowSeconds,
        responseContracts,
        evidenceKind: "SYNTHETIC_ONLY",
      });
      await capture.writeCredentialProof({
        status: "AUTH_ACCOUNT_NO_CREATION",
        sendAuthorized: false,
        accountApiRequests: 0,
      });
      return await use(
        Object.freeze({
          manifest,
          run: () => driver.run(),
          recover: () => driver.recover(),
          snapshot: () => driver.snapshot(),
          confirmCleanClose: (result) => driver.confirmCleanClose(lease, result),
        }),
      );
    } finally {
      await capture?.close();
      await reservations?.close();
    }
  });
}
