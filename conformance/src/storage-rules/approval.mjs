import { DRAFT_REQUEST_LIMITS } from "./request-counter.mjs";

const PINS = ["packetSha256", "sourceCommit", "runnerSha256", "manifestSha256", "fixtureSchemaSha256"];
const COORDINATOR = "Claude（委任。枠の内の承認し直し）";
export const DRAFT_STAGE3_APPROVAL_LIMITS = Object.freeze({
  projects: Object.freeze(["fireemu-oracle-idp", "fireemu-oracle-query"]),
  maxRequests: DRAFT_REQUEST_LIMITS.maxRequests * 2,
  reserveUsd: 2,
});

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

function ledgerRows(text, subject) {
  return text.split("\n").flatMap((line, index) => {
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
      if (separator < 1 || !/^[A-Za-z][A-Za-z0-9]*$/.test(key) || !value) throw new Error("malformed target ledger row");
      if (Object.hasOwn(fields, key)) throw new Error("duplicate ledger field");
      fields[key] = value;
    }
    return [{ line: index + 1, subject: columns[1], fields, actor: columns[3] }];
  });
}

/** Validate local approval bindings only; this does not authorize or perform a send. */
export function validatePresendApproval(options) {
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
  const limits = DRAFT_STAGE3_APPROVAL_LIMITS;
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
  const rows = ledgerRows(ledgerText, subject);
  if (rows.some((row) => row.fields.decision === "REVOKED")) throw new Error("approval revoked");
  const decision = rows.findLast((row) => row.subject === subject && row.fields.decision);
  if (!decision || decision.fields.decision !== "APPROVE" || (!decision.actor.startsWith("オーナー（") && decision.actor !== COORDINATOR)) {
    throw new Error("matching owner approval required");
  }
  if (PINS.some((key) => decision.fields[key] !== packet[key])) throw new Error("decision pin mismatch");
  if (decision.actor !== COORDINATOR) {
    if (review.envelopeId !== null || review.withinEnvelope !== false) throw new Error("direct review envelope mismatch");
    return Object.freeze({ status: "APPROVAL_BOUND_LOCAL_ONLY", sendAuthorized: false, decisionLine: decision.line, envelopeId: null });
  }
  const envelopeId = decision.fields.envelopeId;
  const envelopes = rows.filter((row) => row.subject === `${subject} envelope` && row.fields.envelopeId === envelopeId);
  if (envelopes.length > 1) throw new Error("ambiguous owner envelope");
  const envelope = envelopes[0];
  if (!envelope || !envelopeId || envelope.line >= decision.line || !envelope.actor.startsWith("オーナー（")) throw new Error("preceding owner envelope required");
  if (["writes", "iamConfig", "retries"].some((key) => !Object.hasOwn(envelope.fields, key))) throw new Error("invalid owner envelope schema");
  if (envelope.fields.decision && envelope.fields.decision !== "APPROVE") throw new Error("owner envelope not approved");
  if (review.envelopeId !== envelopeId || review.withinEnvelope !== true) throw new Error("in-envelope review required");
  if (
    !/^[1-9]\d*$/.test(envelope.fields.maxRequests) || !Number.isSafeInteger(Number(envelope.fields.maxRequests)) ||
    !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(envelope.fields.reserveUsd) ||
    !Number.isFinite(Number(envelope.fields.reserveUsd)) || Number(envelope.fields.reserveUsd) <= 0
  ) throw new Error("invalid envelope bound");
  if (
    envelope.fields.project !== packet.projects.join(",") ||
    Number(envelope.fields.maxRequests) < packet.maxRequests ||
    Number(envelope.fields.reserveUsd) < packet.reserveUsd
  ) throw new Error("packet exceeds owner envelope");
  return Object.freeze({ status: "APPROVAL_BOUND_LOCAL_ONLY", sendAuthorized: false, decisionLine: decision.line, envelopeLine: envelope.line, envelopeId });
}
