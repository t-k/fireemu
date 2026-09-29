import { DELEGATION_SUBJECTS, scanRevocations } from "../storage-rules/ledger-revocation.mjs";

// The approval for the stage 2b IAM grant: the same ledger rules as the stage 3 approval (an owner decision or a
// delegated envelope followed by a matching version line, with every revocation spelling stopping it), but for one
// recording of at most 8 requests on the query project alone and a US$1 reserve. The check is copied rather than shared so the stage 3
// approval module, which is reviewed and pinned, stays untouched.
const PINS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const COORDINATOR = "Claude（委任。枠の内の承認し直し）";
const DELEGATED_ENVELOPE_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const DELEGATION_REFERENCE = `2026-09-28 ${DELEGATION_SUBJECTS.send}`;
export const IAM_RECORDINGS_PER_APPROVAL = 1;
export const IAM_APPROVAL_LIMITS = Object.freeze({ projects: Object.freeze(["fireemu-oracle-query"]), maxRequests: 8, reserveUsd: 1 });

function closedRecord(value, keys, label) {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype) throw new Error(`invalid ${label} data`);
  const actual = Reflect.ownKeys(value);
  if (actual.length !== keys.length || actual.some((key) => !keys.includes(key))) throw new Error(`invalid ${label} data`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (!descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) throw new Error(`invalid ${label} data`);
  }
}

function dataArray(value, label) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > 1000) throw new Error(`invalid ${label} data`);
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) throw new Error(`invalid ${label} data`);
  for (const key of keys) {
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (key === "length") continue;
    if (typeof key !== "string" || !/^(?:0|[1-9]\d*)$/.test(key) || Number(key) >= value.length || !descriptor?.enumerable || !Object.hasOwn(descriptor, "value")) {
      throw new Error(`invalid ${label} data`);
    }
  }
}

function ledgerRows(text, subject, skipLines) {
  return text.split("\n").flatMap((line, index) => {
    if (skipLines.has(index + 1)) return [];
    const columns = line.split("|").map((value) => value.trim());
    if (![subject, `${subject} envelope`].includes(columns[1])) return [];
    if (columns.length !== 5 || !/^- \d{4}-\d{2}-\d{2}$/.test(columns[0]) || !columns[3] || !columns[4]) {
      throw new Error("malformed target ledger row");
    }
    const fields = Object.create(null);
    for (const entry of columns[2].split(";")) {
      const separator = entry.indexOf("=");
      const key = entry.slice(0, separator).trim();
      const value = entry.slice(separator + 1).trim();
      if (separator < 1 || (key !== "根拠" && !/^[A-Za-z][A-Za-z0-9]*$/.test(key)) || !value) throw new Error("malformed target ledger row");
      if (Object.hasOwn(fields, key)) throw new Error("duplicate ledger field");
      fields[key] = value;
    }
    return [{ line: index + 1, subject: columns[1], fields, actor: columns[3] }];
  });
}

function hasOwnerDelegation(text, delegationSubject) {
  const rows = text.split("\n").map((line) => line.split("|").map((column) => column.trim()))
    .filter((columns) => columns[1] === delegationSubject);
  if (rows.length !== 1) return false;
  const columns = rows[0];
  if (columns.length !== 5 || columns[0] !== "- 2026-09-28" || !columns[3].startsWith("オーナー") || !columns[4]) return false;
  const decisions = columns[2].split(";").flatMap((entry) => {
    const separator = entry.indexOf("=");
    return separator >= 1 && entry.slice(0, separator).trim() === "decision" ? [entry.slice(separator + 1).trim()] : [];
  });
  return decisions.length === 1 && decisions[0] === "APPROVE";
}

/** Validate local approval bindings only; this does not authorize or perform a send. */
export function validateIamApproval(options) {
  closedRecord(options, ["ledgerText", "packet", "review"], "approval options");
  const { ledgerText, packet, review } = options;
  if (typeof ledgerText !== "string" || ledgerText.includes("\0")) throw new Error("invalid approval options data");
  closedRecord(packet, ["taskId", "packetName", ...PINS, "projects", "maxRequests", "reserveUsd"], "packet");
  if (
    packet.taskId !== "STORAGE-RULES" || typeof packet.packetName !== "string" || !/^[a-z0-9][a-z0-9.-]{0,63}$/.test(packet.packetName) ||
    PINS.some((key) => typeof packet[key] !== "string" || !(key === "sourceCommit" ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/).test(packet[key]))
  ) throw new Error("invalid packet data");
  dataArray(packet.projects, "packet project");
  if (packet.projects.some((project) => typeof project !== "string")) throw new Error("invalid packet project data");
  closedRecord(review, ["verdict", "must", "should", ...PINS, "envelopeId", "withinEnvelope"], "review");
  dataArray(review.must, "review");
  dataArray(review.should, "review");
  const limits = IAM_APPROVAL_LIMITS;
  if (
    packet.projects.length !== limits.projects.length || packet.projects.some((project, index) => project !== limits.projects[index]) ||
    packet.maxRequests !== limits.maxRequests || packet.reserveUsd !== limits.reserveUsd
  ) throw new Error("runner limit mismatch");
  if (
    review.verdict !== "APPROVE" || !Array.isArray(review.must) || review.must.length !== 0 ||
    !Array.isArray(review.should) || review.should.length !== 0
  ) throw new Error("clean APPROVE review required");
  if (PINS.some((key) => review[key] !== packet[key])) throw new Error("review pin mismatch");
  const subject = `${packet.taskId} ${packet.packetName}`;
  const revocations = scanRevocations({ ledgerText, taskId: packet.taskId, pins: Object.fromEntries(PINS.map((key) => [key, packet[key]])), envelopeId: review.envelopeId });
  if (revocations.lane.length > 0) throw new Error("approval revoked");
  const rows = ledgerRows(ledgerText, subject, new Set(revocations.consumed));
  if (rows.some((row) => row.fields.decision === "REVOKED")) throw new Error("approval revoked");
  const decision = rows.findLast((row) => row.subject === subject && row.fields.decision);
  if (!decision || decision.fields.decision !== "APPROVE" || (!decision.actor.startsWith("オーナー（") && decision.actor !== COORDINATOR)) {
    throw new Error("matching owner approval required");
  }
  if (PINS.some((key) => decision.fields[key] !== packet[key])) throw new Error("decision pin mismatch");
  // A global revocation stops the lane only when it was written after the decision row this check selected; an earlier one is superseded.
  if (revocations.global.some((line) => line > decision.line)) throw new Error("approval revoked");
  if (decision.actor !== COORDINATOR) {
    if (review.envelopeId !== null || review.withinEnvelope !== false) throw new Error("direct review envelope mismatch");
    return Object.freeze({ status: "APPROVAL_BOUND_LOCAL_ONLY", sendAuthorized: false, decisionLine: decision.line, envelopeId: null });
  }
  if (revocations.delegation.length > 0) throw new Error("delegated envelope authority required: delegation revoked");
  const envelopeId = decision.fields.envelopeId;
  const envelopes = rows.filter((row) => row.subject === `${subject} envelope` && row.fields.envelopeId === envelopeId);
  if (envelopes.length > 1) throw new Error("ambiguous owner envelope");
  const envelope = envelopes[0];
  if (!envelope || !envelopeId || envelope.line >= decision.line || (!envelope.actor.startsWith("オーナー（") && envelope.actor !== DELEGATED_ENVELOPE_ACTOR)) throw new Error("preceding owner envelope required");
  if (["writes", "iamConfig", "retries"].some((key) => !Object.hasOwn(envelope.fields, key))) throw new Error("invalid owner envelope schema");
  if (envelope.fields.decision && envelope.fields.decision !== "APPROVE") throw new Error("owner envelope not approved");
  if (review.envelopeId !== envelopeId || review.withinEnvelope !== true) throw new Error("in-envelope review required");
  if (
    !/^[1-9]\d*$/.test(envelope.fields.maxRequests) || !Number.isSafeInteger(Number(envelope.fields.maxRequests)) ||
    !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(envelope.fields.reserveUsd) ||
    !Number.isFinite(Number(envelope.fields.reserveUsd)) || Number(envelope.fields.reserveUsd) <= 0
  ) throw new Error("invalid envelope bound");
  if (envelope.actor === DELEGATED_ENVELOPE_ACTOR) {
    if (envelope.fields["根拠"] !== DELEGATION_REFERENCE || !Object.values(DELEGATION_SUBJECTS).every((delegationSubject) => hasOwnerDelegation(ledgerText, delegationSubject))) throw new Error("delegated envelope authority required");
    if (Number(envelope.fields.reserveUsd) > 10) throw new Error("delegated envelope exceeds US$10");
  }
  if (
    envelope.fields.project !== packet.projects.join(",") ||
    Number(envelope.fields.maxRequests) < packet.maxRequests ||
    Number(envelope.fields.reserveUsd) < packet.reserveUsd
  ) throw new Error("packet exceeds owner envelope");
  return Object.freeze({ status: "APPROVAL_BOUND_LOCAL_ONLY", sendAuthorized: false, decisionLine: decision.line, envelopeLine: envelope.line, envelopeId });
}
