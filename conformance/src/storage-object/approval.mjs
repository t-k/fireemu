const PINS = [
  "packetSha256",
  "sourceCommit",
  "runnerSha256",
  "planSha256",
  "corpusSha256",
  "rulesSourceSha256",
];
const COORDINATOR = "Claude（委任。枠の内の承認し直し）";
const DELEGATED_ENVELOPE_ACTOR = "Claude（委任。オーナーの裁量の委任 2026-09-28）";
const DELEGATION_SUBJECT = "調整役への委任（本番の送信）";
const DELEGATION_REFERENCE = `2026-09-28 ${DELEGATION_SUBJECT}`;
const ENVELOPE_DELEGATION_SUBJECT = "調整役への委任（枠の承認）";
const normalizeRevocation = (text) => text.normalize("NFKC").toLowerCase();
const revocationTerms = Object.freeze({
  task: normalizeRevocation("STORAGE-OBJECT"),
  delegationPrefix: normalizeRevocation("調整役への委任"),
  marker: normalizeRevocation("REVOKED"),
});

function envelopeReferences(line) {
  return [
    ...line.matchAll(/\benvelopeid\s*=\s*([a-z0-9][a-z0-9._-]{0,127})(?=[\s;|()、。,]|$)/g),
  ].map((match) => match[1]);
}

/** Revocations are checked before parsing positive rows, including malformed and corrected rows. */
function rejectRelatedRevocations(text, packet, envelopeId) {
  const lines = text.split("\n").map(normalizeRevocation);
  const currentPacket = normalizeRevocation(packet.packetSha256);
  const currentSource = normalizeRevocation(packet.sourceCommit);
  const currentEnvelope = typeof envelopeId === "string" ? normalizeRevocation(envelopeId) : null;
  const knownEnvelopes = new Set(
    lines
      .filter(
        (line) => !line.includes(revocationTerms.marker) && line.includes(revocationTerms.task),
      )
      .flatMap(envelopeReferences),
  );
  for (const line of lines) {
    if (!line.includes(revocationTerms.marker)) continue;
    const hexadecimal = line.match(/[a-f0-9]+/g) ?? [];
    const envelopes = envelopeReferences(line);
    if (
      hexadecimal.includes(currentPacket) ||
      hexadecimal.some(
        (value) => value.length >= 8 && value.length <= 40 && currentSource.startsWith(value),
      ) ||
      (currentEnvelope !== null && (line.match(/[a-z0-9._-]+/g) ?? []).includes(currentEnvelope))
    )
      throw new Error("approval revoked");
    if (!line.includes(revocationTerms.task)) continue;
    const otherPacket = [
      ...line.matchAll(/\bpacketsha256\s*=\s*([a-f0-9]{64})(?=[\s;|()、。,]|$)/g),
    ].some((match) => match[1] !== currentPacket);
    const otherEnvelope = envelopes.some(
      (value) => value !== currentEnvelope && knownEnvelopes.has(value),
    );
    if (!otherPacket && !otherEnvelope) throw new Error("approval revoked");
  }
}

function rejectDelegationRevocations(text) {
  if (
    text.split("\n").some((line) => {
      const normalized = normalizeRevocation(line);
      return (
        normalized.includes(revocationTerms.delegationPrefix) &&
        normalized.includes(revocationTerms.marker)
      );
    })
  )
    throw new Error("owner delegation revoked");
}

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

function dataArray(value) {
  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype ||
    value.length > 1000
  )
    throw new Error("invalid review data");
  const keys = Reflect.ownKeys(value);
  if (keys.length !== value.length + 1) throw new Error("invalid review data");
  for (const key of keys) {
    if (key === "length") continue;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    if (
      typeof key !== "string" ||
      !/^(?:0|[1-9]\d*)$/.test(key) ||
      Number(key) >= value.length ||
      !descriptor?.enumerable ||
      !Object.hasOwn(descriptor, "value")
    )
      throw new Error("invalid review data");
  }
}

function validLimits(value) {
  return (
    typeof value.projectId === "string" &&
    /^[a-z][a-z0-9-]{2,61}$/.test(value.projectId) &&
    Number.isSafeInteger(value.maxRequests) &&
    value.maxRequests > 0 &&
    typeof value.reserveUsd === "number" &&
    Number.isFinite(value.reserveUsd) &&
    value.reserveUsd > 0
  );
}

function ledgerRows(text, subject) {
  return text.split("\n").flatMap((line, index) => {
    const columns = line.split("|").map((value) => value.trim());
    if (![subject, `${subject} envelope`].includes(columns[1])) return [];
    if (normalizeRevocation(line).includes(revocationTerms.marker)) return [];
    if (
      columns.length !== 5 ||
      !/^- \d{4}-\d{2}-\d{2}$/.test(columns[0]) ||
      !columns[3] ||
      !columns[4]
    )
      throw new Error("malformed target ledger row");
    const fields = Object.create(null);
    for (const entry of columns[2].split(";")) {
      const separator = entry.indexOf("=");
      const key = entry.slice(0, separator).trim(),
        value = entry.slice(separator + 1).trim();
      if (separator < 1 || (!/^[A-Za-z][A-Za-z0-9]*$/.test(key) && key !== "根拠") || !value)
        throw new Error("malformed target ledger row");
      if (Object.hasOwn(fields, key)) throw new Error("duplicate ledger field");
      fields[key] = value;
    }
    return [{ line: index + 1, subject: columns[1], fields, actor: columns[3] }];
  });
}

function ownerDelegationLine(ledgerText, subject, envelopeLine) {
  let basisLine = null;
  for (const [index, line] of ledgerText.split("\n").entries()) {
    const columns = line.split("|").map((value) => value.trim());
    if (columns[1] !== subject) continue;
    if (
      columns.length !== 5 ||
      !/^- \d{4}-\d{2}-\d{2}$/.test(columns[0]) ||
      !columns[2] ||
      !columns[3] ||
      !columns[4]
    )
      throw new Error("malformed owner delegation basis");
    if (/\bREVOKED\b/.test(columns[2])) throw new Error("owner delegation revoked");
    if (
      columns[0] === "- 2026-09-28" &&
      columns[3].startsWith("オーナー") &&
      columns[2].split(";")[0].trim() === "decision=APPROVE" &&
      index + 1 < envelopeLine
    )
      basisLine = index + 1;
  }
  if (basisLine === null) throw new Error("owner delegation basis required");
  return basisLine;
}

/** Bind supplied local approval records; the production caller must separately verify actual pins and its send assignment. */
export function validatePresendApproval(options) {
  closedRecord(options, ["ledgerText", "packet", "review", "runner"], "approval options");
  const { ledgerText, packet, review, runner } = options;
  if (typeof ledgerText !== "string" || ledgerText.includes("\0"))
    throw new Error("invalid approval options data");
  closedRecord(
    packet,
    ["taskId", "packetName", ...PINS, "projectId", "maxRequests", "reserveUsd"],
    "packet",
  );
  closedRecord(runner, ["projectId", "maxRequests", "reserveUsd"], "runner");
  if (
    !validLimits(packet) ||
    packet.taskId !== "STORAGE-OBJECT" ||
    typeof packet.packetName !== "string" ||
    !/^[a-z0-9][a-z0-9.-]{0,63}$/.test(packet.packetName) ||
    PINS.some(
      (key) =>
        typeof packet[key] !== "string" ||
        !(key === "sourceCommit" ? /^[a-f0-9]{40}$/ : /^[a-f0-9]{64}$/).test(packet[key]),
    )
  )
    throw new Error("invalid packet data");
  if (!validLimits(runner)) throw new Error("invalid runner data");
  if (["projectId", "maxRequests", "reserveUsd"].some((key) => packet[key] !== runner[key]))
    throw new Error("runner limit mismatch");
  closedRecord(
    review,
    ["verdict", "must", "should", ...PINS, "envelopeId", "withinEnvelope"],
    "review",
  );
  dataArray(review.must);
  dataArray(review.should);
  if (review.verdict !== "APPROVE" || review.must.length || review.should.length)
    throw new Error("clean APPROVE review required");
  if (PINS.some((key) => review[key] !== packet[key])) throw new Error("review pin mismatch");
  rejectRelatedRevocations(ledgerText, packet, review.envelopeId);
  const subject = `${packet.taskId} ${packet.packetName}`;
  const rows = ledgerRows(ledgerText, subject);
  const decision = rows.findLast((row) => row.subject === subject && row.fields.decision);
  if (
    !decision ||
    decision.fields.decision !== "APPROVE" ||
    (!decision.actor.startsWith("オーナー（") && decision.actor !== COORDINATOR)
  )
    throw new Error("matching owner approval required");
  if (PINS.some((key) => decision.fields[key] !== packet[key]))
    throw new Error("decision pin mismatch");
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
  const envelopeId = decision.fields.envelopeId;
  const envelopes = rows.filter(
    (row) => row.subject === `${subject} envelope` && row.fields.envelopeId === envelopeId,
  );
  if (envelopes.length > 1) throw new Error("ambiguous owner envelope");
  const envelope = envelopes[0];
  if (
    !envelope ||
    typeof envelopeId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(envelopeId) ||
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
  const maximum = Number(envelope.fields.maxRequests),
    reservation = Number(envelope.fields.reserveUsd);
  if (
    !/^[1-9]\d*$/.test(envelope.fields.maxRequests) ||
    !Number.isSafeInteger(maximum) ||
    !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(envelope.fields.reserveUsd) ||
    !Number.isFinite(reservation) ||
    reservation <= 0
  )
    throw new Error("invalid envelope bound");
  let delegationLine = null,
    envelopeDelegationLine = null;
  if (envelope.actor === DELEGATED_ENVELOPE_ACTOR) {
    if (envelope.fields["根拠"] !== DELEGATION_REFERENCE)
      throw new Error("exact delegation reference required");
    rejectDelegationRevocations(ledgerText);
    delegationLine = ownerDelegationLine(ledgerText, DELEGATION_SUBJECT, envelope.line);
    envelopeDelegationLine = ownerDelegationLine(
      ledgerText,
      ENVELOPE_DELEGATION_SUBJECT,
      envelope.line,
    );
    if (reservation > 10) throw new Error("delegated envelope reservation exceeds USD10");
  }
  for (const limits of [packet, runner]) {
    if (
      limits.projectId !== envelope.fields.project ||
      limits.maxRequests > maximum ||
      limits.reserveUsd > reservation
    )
      throw new Error("packet or runner exceeds owner envelope");
  }
  return Object.freeze({
    status: "APPROVAL_BOUND_LOCAL_ONLY",
    sendAuthorized: false,
    decisionLine: decision.line,
    envelopeLine: envelope.line,
    envelopeId,
    ...(delegationLine === null ? {} : { delegationLine, envelopeDelegationLine }),
  });
}
