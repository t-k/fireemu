import { createHash } from "node:crypto";
import { isDeepStrictEqual as same } from "node:util";
import { ackWireProjection } from "../pubsub-observation/compare-core.mjs";
import { CAPS } from "./plan.mjs";

const PROPOSAL = "71bd68a98cc6914915719dc499c616be2ecf518b18e71c51b5add7e3c16920d4";
const OWNER = "a94f604cf2213de67b9413281cc50a5dfb3083348fc71e80f60013d1c07a9228";
const INDEX = "5af9b45bce6882fb869b37dd721c9ae57908b14964909ee9793dc8515ef8c31d";
const SOURCES = new Map([
  [
    "971:386",
    { bytes: 787, sha256: "d1db86c1d7c3318cd2b40cbd335777236cb855154988ea1eef8f902a50e0db3b" },
  ],
  [
    "977:388",
    { bytes: 530, sha256: "2aee9dfd9ff3a1e7bed4ceea39d4292b8749f250eafe3b845b8f6cf312fd50b5" },
  ],
]);
const SECOND_OWNER = "d15612429b4ac1c5f88d5c1b020cedc0bce13f331aa7a85b20e89e4a3ac3d004";
const SECOND_INDEX = "7e5f79100f723fb033057b77c2798c754dbda713f40948dabea58b9793579e36";
const SECOND_SOURCES = new Map([
  [
    "968:385",
    { bytes: 790, sha256: "cd459de271afff8b63678f8d1940e1d5b4d46b052de4c9fb2c40243cf8f4c526" },
  ],
  [
    "974:387",
    { bytes: 534, sha256: "2741050e6592762f032b4923f7d9df064a93d19a5149bc35641212382420996d" },
  ],
]);
const hash = (body) => createHash("sha256").update(body).digest("hex");
const good = (reply) =>
  reply?.ok === true &&
  reply.unknown !== true &&
  (reply.status === 200 || (reply.status === undefined && reply.code === "OK"));
const bound = (body, reply) =>
  Buffer.isBuffer(body) &&
  body.length <= CAPS.metadataBytesEachDirection &&
  body.length === reply?.bodyBytes &&
  hash(body) === reply.bodySha256;
function prefix(value) {
  const bytes = [];
  do {
    bytes.push((value % 128) | (value > 127 ? 128 : 0));
    value = Math.floor(value / 128);
  } while (value);
  return Buffer.from(bytes).toString("hex");
}
function length(hex) {
  return [...Buffer.from(hex, "hex")].reduce((n, b, i) => n + (b & 127) * 128 ** i, 0);
}

// Reuse the existing generated-field projection; this leaf changes only the one
// empty env value node and its mathematically necessary containing length.
function projection(raw) {
  const proof = ackWireProjection(raw, "response", true);
  let target = 0;
  for (const [i, received] of proof.fields.entries()) {
    if (received.number !== 1 || received.wire !== 2 || !received.fields)
      throw Error("Unknown response field");
    const messages = received.fields.filter((f) => f.number === 2);
    if (messages.length !== 1 || received.fields.some((f) => ![1, 2, 3].includes(f.number)))
      throw Error("Received message structure");
    const message = messages[0];
    if (message.fields.some((f) => ![1, 2, 3, 4, 5].includes(f.number)))
      throw Error("Unknown message field");
    const keys = new Set();
    for (const attribute of message.fields.filter((f) => f.number === 2)) {
      if (attribute.wire !== 2 || typeof attribute.value !== "string")
        throw Error("Attribute wire type");
      const entry = ackWireProjection(Buffer.from(attribute.value, "hex"), "attribute").fields;
      const keyFields = entry.filter((f) => f.number === 1),
        valueFields = entry.filter((f) => f.number === 2);
      if (
        keyFields.length !== 1 ||
        valueFields.length > 1 ||
        entry.some((f) => ![1, 2].includes(f.number) || f.wire !== 2)
      )
        throw Error("Duplicate or unknown attribute field");
      const keyRaw = Buffer.from(keyFields[0].value, "hex"),
        key = keyRaw.toString("utf8");
      if (!key || !Buffer.from(key).equals(keyRaw) || keys.has(key))
        throw Error("Missing, invalid or duplicate attribute key");
      keys.add(key);
      if (i === 1 && key === "env") {
        target++;
        if (valueFields.length && valueFields[0].bytes !== 0)
          throw Error("Nonempty scoped attribute value");
        if (valueFields.length) {
          if (
            entry.length !== 2 ||
            entry[0].number !== 1 ||
            entry[1].number !== 2 ||
            !attribute.value.endsWith("1200")
          )
            throw Error("Scoped entry layout");
          const previousPrefixBytes = attribute.prefix.length / 2;
          attribute.value = attribute.value.slice(0, -4);
          attribute.bytes -= 2;
          attribute.prefix = prefix(attribute.bytes);
          const delta = -2 + attribute.prefix.length / 2 - previousPrefixBytes;
          message.prefix = prefix(length(message.prefix) + delta);
        }
      }
    }
  }
  if (target !== 1) throw Error("Scoped empty attribute missing");
  return proof.fields;
}

export function compareEmptyAttributeValueDisposition({
  input,
  cell,
  source,
  actual,
  sourceBody,
  localBody,
  disposition,
}) {
  const second = input?.metadata?.runId === "45298b949da0";
  const expected = (second ? SECOND_SOURCES : SOURCES).get(`${source?.n}:${source?.requestId}`);
  if (
    (!second && input?.metadata?.runId !== "567e1cd860a1") ||
    cell?.id !== "N7" ||
    source?.method !== "Pull" ||
    source.transport !== "grpc" ||
    !expected
  )
    return null;
  const result = {
    owner: second ? 1210 : 1209,
    sourceN: source.n,
    sourceRequestId: source.requestId,
    scope:
      "One empty env value-field presence and required ancestor lengths; existing generated-field proofs remain separate",
    physicalVerdict: "DIVERGES",
    parentClosureReady: false,
  };
  const finish = (verdict, reason) => ({ ...result, verdict, reason });
  if (
    disposition?.owner1209?.proposalSha256 !== PROPOSAL ||
    (second
      ? disposition?.owner1210?.rowSha256WithLf !== SECOND_OWNER
      : disposition.owner1209.rowSha256WithLf !== OWNER) ||
    disposition.proofIndexSha256 !== (second ? SECOND_INDEX : INDEX) ||
    !same(disposition.cells, ["N7"]) ||
    !["runId", "sourceHead", "packetSha256", "descriptorSha256"].every(
      (k) => input.metadata[k] !== undefined && disposition.source?.[k] === input.metadata[k],
    ) ||
    !["binarySha256", "inputsSha256"].every(
      (k) =>
        /^[a-f0-9]{64}$/.test(input.runtimeInputs?.[k] ?? "") &&
        disposition.runtimeInputs?.[k] === input.runtimeInputs[k],
    )
  )
    return finish(
      "NOT_COMPARABLE",
      "Owner, recovery proof, recording or runtime binding unavailable",
    );
  if (
    !good(source.reply) ||
    !good(actual) ||
    !bound(sourceBody, source.reply) ||
    !bound(localBody, actual) ||
    sourceBody.length !== expected.bytes ||
    hash(sourceBody) !== expected.sha256
  )
    return finish("NOT_COMPARABLE", "Known original source and actual raw body pins required");
  result.sourceBody = { bytes: sourceBody.length, sha256: hash(sourceBody) };
  result.localBody = { bytes: localBody.length, sha256: hash(localBody) };
  result.physicalVerdict = sourceBody.equals(localBody) ? "MATCH" : "DIVERGES";
  try {
    return finish(
      same(projection(sourceBody), projection(localBody)) ? "MATCH" : "DIVERGES",
      "Only the scoped empty value and derived lengths are normalized",
    );
  } catch {
    return finish("DIVERGES", "Wire structure, scoped entry or retained fields differ");
  }
}
