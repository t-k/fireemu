import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { buildCorpus } from "./corpus.mjs";

export const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
export const fixtureDigest = (binding) =>
  sha256(
    Buffer.from(
      JSON.stringify({
        binding,
        seedBase64: Buffer.from("next").toString("base64"),
        managementPrograms: buildCorpus(binding).managementPrograms,
      }),
    ),
  );
export const STABLE_HEADERS = Object.freeze([
  "content-type",
  "content-length",
  "x-content-type-options",
  "cache-control",
]);
const DIGEST = /^[a-f0-9]{64}$/;
const fail = (message) => {
  throw new Error(`invalid management evidence: ${message}`);
};
const exact = (a, b) => JSON.stringify(a) === JSON.stringify(b);
function record(value, keys, label) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    !exact(Object.keys(value).toSorted(), keys.toSorted())
  )
    fail(label);
}
export function validateBinding(binding) {
  record(binding, ["bucket", "prefix", "uidA", "uidB"], "binding");
  if (
    Object.values(binding).some((v) => typeof v !== "string" || !v || /[\r\n\0]/.test(v)) ||
    !/^STORAGE-RULES\/[a-z0-9-]+\/$/.test(binding.prefix)
  )
    fail("binding values");
}
export function managementSteps(binding) {
  validateBinding(binding);
  const [compile] = buildCorpus(binding).managementPrograms;
  const rows = [];
  const add = (id, kind, caller, dialect, sourceRef = null) =>
    rows.push({ id, kind, caller, dialect, sourceRef });
  for (const position of ["preflight/release/entry", "release/final"])
    for (const scope of ["bucket", "bucketless"])
      add(`${position}/${scope}`, "absence", "admin", "control");
  add("management/prefix-empty", "storage", "admin", "gcs");
  add("compile/release/before", "absence", "admin", "control");
  for (const source of compile.validSources)
    add(`compile/${source.ref}`, "compile", "admin", "control", source.ref);
  add(
    "compile/invalid/storage-expression",
    "rejection",
    "admin",
    "control",
    compile.invalidSource.ref,
  );
  add("compile/release/after-invalid", "absence", "admin", "control");
  for (const s of ["A", "B"]) {
    add(`release/${s}/after`, "identity", "admin", "control", `release-switch/${s}`);
    for (const index of [3, 4])
      for (const stage of [
        "before-metadata",
        "before-media",
        "subject",
        "after-metadata",
        "after-media",
      ]) {
        add(
          `management/${s}/control-${index}/${stage}`,
          stage.includes("metadata") ? "metadata" : "storage",
          stage === "subject" ? "user-a" : "admin",
          stage === "subject" ? "firebase" : "gcs",
        );
      }
  }
  for (const position of ["entry", "final"])
    for (const stage of position === "entry"
      ? ["subject", "after-metadata", "after-media"]
      : ["before-metadata", "before-media", "subject", "after-metadata", "after-media"]) {
      add(
        `management/no-release/${position}/${stage}`,
        stage.includes("metadata") ? "metadata" : "storage",
        stage === "subject" ? "user-a" : "admin",
        stage === "subject" ? "firebase" : "gcs",
      );
    }
  for (const index of [3, 4, 5])
    for (const stage of [
      "baseline-metadata",
      "baseline-media",
      "seed",
      "seed-metadata",
      "seed-media",
      "cleanup-metadata",
      "delete",
      "absence-metadata",
      "absence-media",
    ]) {
      add(
        `management/control-${index}/${stage}`,
        stage.includes("metadata") || stage === "seed" ? "metadata" : "storage",
        "admin",
        "gcs",
      );
    }
  return rows;
}
export function captureResponse(response) {
  if (
    !Buffer.isBuffer(response.bytes) ||
    !Number.isInteger(response.status) ||
    response.status < 200 ||
    response.status >= 500 ||
    (response.status >= 300 && response.status < 400)
  )
    fail("incomplete response");
  const headers = Object.fromEntries(STABLE_HEADERS.map((key) => [key, response.headers.get(key)]));
  return {
    status: response.status,
    bodyBytes: response.bytes.length,
    bodySha256: sha256(response.bytes),
    bodyBase64: response.bytes.toString("base64"),
    headers,
  };
}
function validateResponse(response) {
  record(
    response,
    ["status", "bodyBytes", "bodySha256", "bodyBase64", "headers"],
    "response schema",
  );
  record(response.headers, STABLE_HEADERS, "stable headers");
  if (Object.values(response.headers).some((v) => v !== null && typeof v !== "string"))
    fail("header values");
  const bytes = Buffer.from(response.bodyBase64 ?? "", "base64");
  if (
    typeof response.bodyBase64 !== "string" ||
    bytes.toString("base64") !== response.bodyBase64 ||
    !DIGEST.test(response.bodySha256) ||
    sha256(bytes) !== response.bodySha256 ||
    bytes.length !== response.bodyBytes ||
    !Number.isInteger(response.status) ||
    response.status < 200 ||
    response.status >= 500 ||
    (response.status >= 300 && response.status < 400)
  )
    fail("response bytes/status");
  if (
    response.headers["content-length"] !== null &&
    response.headers["content-length"] !== String(bytes.length)
  )
    fail("content length");
}
function validateRows(rows, binding, production) {
  const steps = managementSteps(binding);
  if (
    !Array.isArray(rows) ||
    rows.length !== steps.length ||
    new Set(rows.map((r) => r?.id)).size !== rows.length
  )
    fail("closed step count");
  const indexed = new Map(rows.map((r) => [r.id, r]));
  const sources = new Map(
    buildCorpus(binding).managementPrograms[0].validSources.map((s) => [s.ref, s.sha256]),
  );
  sources.set(
    "invalid/storage-expression",
    sha256(buildCorpus(binding).managementPrograms[0].invalidSource.content),
  );
  for (const step of steps) {
    const row = indexed.get(step.id);
    record(
      row,
      [
        "id",
        "kind",
        "caller",
        "dialect",
        "sourceRef",
        "sourceSha256",
        "response",
        "effect",
        "evidence",
      ],
      `row ${step.id}`,
    );
    for (const key of ["id", "kind", "caller", "sourceRef"])
      if (row[key] !== step[key]) fail(`row ${key}: ${step.id}`);
    if (
      row.dialect !== (production && step.dialect === "control" ? "firebase-rules" : step.dialect)
    )
      fail(`dialect: ${step.id}`);
    if (row.sourceSha256 !== (step.sourceRef ? sources.get(step.sourceRef) : null))
      fail(`source digest: ${step.id}`);
    validateResponse(row.response);
    if (!production && ["compile", "identity"].includes(step.kind)) {
      const snapshot = JSON.parse(Buffer.from(row.response.bodyBase64, "base64").toString("utf8"));
      if (
        row.response.status !== 200 ||
        snapshot.loaded !== true ||
        typeof snapshot.source !== "string" ||
        sha256(snapshot.source) !== row.sourceSha256
      )
        fail("installed source readback");
    }
    record(
      row.evidence,
      production ? ["runId", "sequence", "operationId"] : ["ordinal"],
      "row evidence",
    );
    if (
      (production &&
        (typeof row.evidence.runId !== "string" ||
          !Number.isSafeInteger(row.evidence.sequence) ||
          row.evidence.sequence <= 0 ||
          row.evidence.operationId !== row.id)) ||
      (!production && (!Number.isSafeInteger(row.evidence.ordinal) || row.evidence.ordinal <= 0))
    )
      fail("row provenance");
    if (step.kind === "compile" || step.kind === "identity") {
      record(row.effect, ["sourceAccepted"], "source effect");
      if (row.effect.sourceAccepted !== true) fail(`source refused: ${step.id}`);
    } else if (step.kind === "rejection") {
      record(row.effect, ["rejected"], "invalid effect");
      if (row.effect.rejected !== true || (!production && row.response.status !== 400))
        fail("invalid accepted");
    } else if (step.kind === "absence") {
      record(row.effect, ["absent"], "absence effect");
      if (row.effect.absent !== true) fail("release present");
    } else if (step.kind === "metadata") {
      record(row.effect, ["stateSha256"], "metadata effect");
      if (
        !DIGEST.test(row.effect.stateSha256) ||
        row.effect.stateSha256 !== row.response.bodySha256
      )
        fail("metadata digest");
    } else if (row.effect !== null) fail("storage effect");
  }
  return indexed;
}
const LOCAL_ONLY_IDS = [
  "before-identity",
  "before-allow",
  "before-deny",
  "invalid",
  "after-identity",
  "after-allow",
  "after-deny",
];
export function compareManagement(local, production, receipt) {
  try {
    record(
      local,
      ["schemaVersion", "kind", "profile", "binding", "provenance", "rows", "errors", "localOnly"],
      "local schema",
    );
    record(
      production,
      [
        "schemaVersion",
        "kind",
        "runId",
        "sourceCommit",
        "journalSha256",
        "binding",
        "rows",
        "gaps",
        "unjudgedHeaders",
      ],
      "production schema",
    );
    record(
      receipt,
      ["schemaVersion", "profile", "binding", "localProvenance", "production"],
      "receipt schema",
    );
    record(
      local.provenance,
      [
        "binarySha256",
        "binarySourceCommit",
        "collectorSha256",
        "judgeSha256",
        "corpusSha256",
        "fixtureSha256",
        "configSha256",
      ],
      "local provenance",
    );
    record(receipt.production, ["runId", "sourceCommit", "journalSha256"], "production receipt");
    if (
      [local.schemaVersion, production.schemaVersion, receipt.schemaVersion].some((v) => v !== 1) ||
      local.kind !== "local-management" ||
      production.kind !== "production-management-projection" ||
      local.profile !== "strict" ||
      receipt.profile !== "strict" ||
      !exact(local.binding, production.binding) ||
      !exact(local.binding, receipt.binding) ||
      !exact(local.provenance, receipt.localProvenance) ||
      !exact(receipt.production, {
        runId: production.runId,
        sourceCommit: production.sourceCommit,
        journalSha256: production.journalSha256,
      })
    )
      fail("stale/profile/binding receipt");
    for (const [key, value] of Object.entries(local.provenance))
      if (!(key === "binarySourceCommit" ? /^[a-f0-9]{40}$/ : DIGEST).test(value))
        fail("provenance digest");
    if (
      !/^[a-f0-9]{40}$/.test(production.sourceCommit) ||
      !DIGEST.test(production.journalSha256) ||
      !Array.isArray(local.errors) ||
      local.errors.length ||
      !Array.isArray(production.gaps) ||
      !Array.isArray(production.unjudgedHeaders)
    )
      fail("errors or production binding");
    if (
      !Array.isArray(local.localOnly) ||
      !exact(
        local.localOnly.map((r) => r.id),
        LOCAL_ONLY_IDS,
      )
    )
      fail("local atomicity steps");
    for (const row of local.localOnly) {
      record(row, ["id", "scope", "response", "sourceSha256"], "local-only row");
      if (row.scope !== "LOCAL_ONLY") fail("local-only scope");
      validateResponse(row.response);
    }
    const atomic = local.localOnly;
    for (const row of [atomic[0], atomic[4]]) {
      const snapshot = JSON.parse(Buffer.from(row.response.bodyBase64, "base64").toString("utf8"));
      if (
        row.response.status !== 200 ||
        snapshot.loaded !== true ||
        typeof snapshot.source !== "string" ||
        sha256(snapshot.source) !== row.sourceSha256
      )
        fail("atomic installed source readback");
    }
    if (
      atomic[0].sourceSha256 !== atomic[4].sourceSha256 ||
      !DIGEST.test(atomic[0].sourceSha256) ||
      atomic[1].response.status !== 200 ||
      atomic[2].response.status !== 403 ||
      atomic[3].response.status !== 400 ||
      atomic[5].response.bodySha256 !== atomic[1].response.bodySha256 ||
      atomic[5].response.status !== 200 ||
      atomic[6].response.bodySha256 !== atomic[2].response.bodySha256 ||
      atomic[6].response.status !== 403
    )
      fail("local invalid atomicity");
    if (local.provenance.fixtureSha256 !== fixtureDigest(local.binding)) fail("fixture bytes");
    const l = validateRows(local.rows, local.binding, false),
      p = validateRows(production.rows, production.binding, true);
    for (const row of production.rows)
      if (row.evidence.runId !== production.runId) fail("foreign production row");
    const decisions = [
      "management/A/control-3/subject",
      "management/A/control-4/subject",
      "management/B/control-3/subject",
      "management/B/control-4/subject",
    ];
    for (const index of [l, p]) {
      for (const [i, id] of decisions.entries())
        if (index.get(id).response.status !== [200, 403, 403, 200][i]) fail("switch decision");
      for (const source of ["A", "B"])
        for (const i of [3, 4]) {
          const prefix = `management/${source}/control-${i}/`;
          if (
            !exact(
              index.get(`${prefix}before-metadata`).effect,
              index.get(`${prefix}after-metadata`).effect,
            ) ||
            !exact(
              index.get(`${prefix}before-media`).response,
              index.get(`${prefix}after-media`).response,
            )
          )
            fail("Admin switch state changed");
        }
      for (const position of ["entry", "final"]) {
        const prefix = `management/no-release/${position}/`;
        if (index.get(`${prefix}subject`).response.status !== 400) fail("no-release status");
        const beforeMeta =
          position === "entry" ? "management/control-5/seed-metadata" : `${prefix}before-metadata`;
        const beforeMedia =
          position === "entry" ? "management/control-5/seed-media" : `${prefix}before-media`;
        if (
          !exact(index.get(beforeMeta).effect, index.get(`${prefix}after-metadata`).effect) ||
          !exact(index.get(beforeMedia).response, index.get(`${prefix}after-media`).response)
        )
          fail("Admin no-release state changed");
      }
      const ordinal = (id) => index.get(id).evidence.ordinal ?? index.get(id).evidence.sequence;
      const ordered = (ids) => {
        if (!ids.every((id, i) => i === 0 || ordinal(id) > ordinal(ids[i - 1])))
          fail("required effect order");
      };
      ordered([
        "release/A/after",
        ...decisions.slice(0, 2),
        "release/B/after",
        ...decisions.slice(2),
        "management/no-release/final/subject",
      ]);
      ordered([
        "compile/release/before",
        ...buildCorpus(local.binding).managementPrograms[0].validSources.map(
          (s) => `compile/${s.ref}`,
        ),
        "compile/invalid/storage-expression",
        "compile/release/after-invalid",
      ]);
      for (const source of ["A", "B"])
        for (const i of [3, 4])
          ordered(
            ["before-metadata", "before-media", "subject", "after-metadata", "after-media"].map(
              (stage) => `management/${source}/control-${i}/${stage}`,
            ),
          );
      for (const i of [3, 4, 5]) {
        ordered(
          [
            "baseline-metadata",
            "baseline-media",
            "seed",
            "seed-metadata",
            "seed-media",
            "cleanup-metadata",
            "delete",
            "absence-metadata",
            "absence-media",
          ].map((stage) => `management/control-${i}/${stage}`),
        );
        for (const stage of ["baseline-metadata", "baseline-media"])
          if (index.get(`management/control-${i}/${stage}`).response.status !== 404)
            fail("baseline absence");
      }
      const empty = JSON.parse(
        Buffer.from(index.get("management/prefix-empty").response.bodyBase64, "base64").toString(
          "utf8",
        ),
      );
      if (
        index.get("management/prefix-empty").response.status !== 200 ||
        (empty.items && (!Array.isArray(empty.items) || empty.items.length)) ||
        empty.nextPageToken
      )
        fail("prefix not empty");
      for (const i of [3, 4, 5])
        for (const stage of ["absence-metadata", "absence-media"])
          if (index.get(`management/control-${i}/${stage}`).response.status !== 404)
            fail("cleanup absence");
    }
    const mismatches = [];
    for (const step of managementSteps(local.binding)) {
      const a = l.get(step.id),
        b = p.get(step.id);
      if (step.kind === "storage" && !exact(a.response, b.response))
        mismatches.push({
          id: step.id,
          kind: "STORAGE_BYTES_OR_HEADERS",
          local: a.response,
          production: b.response,
        });
    }
    return {
      pairedEffectsMatch: mismatches.length === 0,
      closureReady: false,
      mismatches,
      gaps: [
        "MISSING_PRODUCTION_INVALID_INSTALLED_IDENTITY_AND_EFFECTIVE_WITNESS",
        ...production.gaps,
      ],
      unjudgedHeaders: production.unjudgedHeaders,
    };
  } catch (error) {
    return {
      pairedEffectsMatch: false,
      closureReady: false,
      mismatches: [{ kind: "INVALID_EVIDENCE", message: error.message }],
      gaps: [],
      unjudgedHeaders: [],
    };
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [localPath, productionPath, receiptPath, outputPath] = process.argv.slice(2);
  if (!outputPath)
    throw new Error(
      "usage: management-compare.mjs local.json production.json receipt.json output.json",
    );
  const result = compareManagement(
    ...[localPath, productionPath, receiptPath].map((p) => JSON.parse(readFileSync(p))),
  );
  writeFileSync(outputPath, `${JSON.stringify(result, null, 2)}\n`);
  process.exitCode = result.pairedEffectsMatch ? 0 : 1;
}
