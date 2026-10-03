import { createHash } from "node:crypto";
import { buildManagementPrograms } from "./management_programs.mjs";

export const NATIVE_PROJECT = "fireemu-oracle-query";
export const ORIGINAL_COMPILE_CHECK =
  "The Storage service declaration and Storage-specific method or wildcard rules used by this corpus have production compile acceptance; a deliberately invalid Storage rule is refused without changing the effective release.";
export const nativeDigest = (value) =>
  createHash("sha256")
    .update(typeof value === "string" || Buffer.isBuffer(value) ? value : JSON.stringify(value))
    .digest("hex");
export function nativeClosed(value, keys, label = "native input") {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== keys.length ||
    keys.some(
      (key) =>
        !Object.getOwnPropertyDescriptor(value, key)?.enumerable ||
        !Object.hasOwn(Object.getOwnPropertyDescriptor(value, key), "value"),
    )
  )
    throw new Error(`invalid ${label}`);
}
const freeze = (value) => {
  if (value && typeof value === "object") {
    Object.values(value).forEach(freeze);
    Object.freeze(value);
  }
  return value;
};
export const nativeRef = (type, key) => ({
  kind: "runtime-reference",
  type,
  key,
  resolveOnlyAfterDurableProof: true,
});
const RULES = "https://firebaserules.googleapis.com";
const GCS = "https://storage.googleapis.com";
const FIREBASE = "https://firebasestorage.googleapis.com";

/** A dedicated closed inventory; all network attempts, including owner refreshes, have unique rows. */
export function buildNativeManifest(input) {
  nativeClosed(input, [
    "runId",
    "sourceCommit",
    "sourceTree",
    "bucket",
    "baseline",
    "limits",
    "priorCompileProofs",
  ]);
  const p = structuredClone(input);
  if (
    !/^[a-z0-9][a-z0-9-]{0,47}$/.test(p.runId) ||
    !/^[a-f0-9]{40}$/.test(p.sourceCommit) ||
    !/^[a-f0-9]{40}$/.test(p.sourceTree) ||
    p.bucket !== "fireemu-oracle-query.firebasestorage.app"
  )
    throw new Error("invalid native binding");
  nativeClosed(p.limits, [
    "settleCycles",
    "intervalMs",
    "listPages",
    "credentialAttempts",
    "deadlineSeconds",
  ]);
  const { settleCycles, intervalMs, listPages, credentialAttempts, deadlineSeconds } = p.limits;
  if (
    ![settleCycles, intervalMs, listPages, credentialAttempts, deadlineSeconds].every(
      Number.isSafeInteger,
    ) ||
    settleCycles < 2 ||
    settleCycles > 30 ||
    intervalMs < 1 ||
    intervalMs > 10000 ||
    listPages < 1 ||
    listPages > 10 ||
    credentialAttempts < 1 ||
    credentialAttempts > 8 ||
    deadlineSeconds < 1 ||
    deadlineSeconds > 1800
  )
    throw new Error("invalid native limits");
  const releaseName = `projects/${NATIVE_PROJECT}/releases/firebase.storage/${p.bucket}`;
  const bucketlessName = `projects/${NATIVE_PROJECT}/releases/firebase.storage`;
  if (p.baseline.kind === "absent") {
    nativeClosed(p.baseline, ["kind", "observedAt", "bucketAbsent", "bucketlessAbsent"]);
    if (p.baseline.bucketAbsent !== true || p.baseline.bucketlessAbsent !== true)
      throw new Error("unknown baseline");
  } else if (p.baseline.kind === "present") {
    nativeClosed(p.baseline, ["kind", "observedAt", "release", "source", "bucketlessAbsent"]);
    nativeClosed(p.baseline.release, ["name", "rulesetName", "updateTime"]);
    if (
      p.baseline.release.name !== releaseName ||
      !/^projects\/fireemu-oracle-query\/rulesets\/[A-Za-z0-9_-]{1,128}$/.test(
        p.baseline.release.rulesetName,
      ) ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/.test(p.baseline.release.updateTime) ||
      typeof p.baseline.source !== "string" ||
      p.baseline.source.length === 0 ||
      Buffer.byteLength(p.baseline.source) > 256 * 1024 ||
      p.baseline.bucketlessAbsent !== true
    )
      throw new Error("invalid present baseline");
  } else throw new Error("unknown baseline");
  if (!Number.isSafeInteger(p.baseline.observedAt) || p.baseline.observedAt <= 0)
    throw new Error("invalid baseline time");
  if (!Array.isArray(p.priorCompileProofs) || p.priorCompileProofs.length !== 2)
    throw new Error("missing original compile evidence");
  p.priorCompileProofs.forEach((proof, i) => {
    nativeClosed(proof, ["runId", "journalSha256", "validSourceCount"]);
    if (
      proof.runId !== `stage3-20260930${i === 0 ? "c" : "d"}` ||
      !/^[a-f0-9]{64}$/.test(proof.journalSha256) ||
      proof.validSourceCount !== 338
    )
      throw new Error("invalid original compile evidence");
  });
  const binding = {
    bucket: p.bucket,
    prefix: `STORAGE-RULES/${p.runId}/`,
    project: NATIVE_PROJECT,
  };
  const programs = buildManagementPrograms(binding, [], []),
    a = programs[1],
    invalid = programs[0].invalidSource;
  const rows = [];
  const add = (id, kind, partition, phase, request, extra = {}) =>
    rows.push({
      id,
      kind,
      partition,
      phase,
      family: phase === "preflight" ? "preflight" : "native-management",
      service:
        request.origin === RULES
          ? "firebase-rules"
          : request.origin === GCS || request.origin === FIREBASE
            ? "storage"
            : "credential",
      programId: "installed-invalid",
      stage: kind === "decision" ? "subject" : "support",
      requires: [],
      request: {
        id,
        project: NATIVE_PROJECT,
        credential: "admin",
        query: {},
        body: null,
        ...request,
      },
      ...extra,
    });
  const r = (id, kind, partition, phase, method, path, body = null, extra = {}) =>
    add(id, kind, partition, phase, { origin: RULES, method, path, body }, extra);
  const object = (id, kind, partition, phase, name, method = "GET", subject = false) =>
    add(
      id,
      kind,
      partition,
      phase,
      {
        origin: subject ? FIREBASE : GCS,
        method,
        path: `/${subject ? "v0" : "storage/v1"}/b/${p.bucket}/o/${encodeURIComponent(name)}`,
        objectName: name,
        credential: subject ? "anonymous" : "admin",
        query:
          kind === "media" || kind === "media-absent" || kind === "decision"
            ? { alt: "media" }
            : method === "DELETE"
              ? { ifGenerationMatch: nativeRef("generation", name) }
              : {},
      },
      { resource: name },
    );
  const list = (base, partition, phase) => {
    for (let i = 1; i <= (phase === "preflight" ? 1 : listPages); i++)
      add(
        `${base}/${i}`,
        "rules-list",
        partition,
        phase,
        {
          origin: RULES,
          method: "GET",
          path: `/v1/projects/${NATIVE_PROJECT}/rulesets`,
          query: {
            pageSize: "100",
            ...(i === 1 ? {} : { pageToken: nativeRef("page-token", base) }),
          },
        },
        { listBase: base, page: i },
      );
  };
  const credential = (phase, i) =>
    add(
      `${phase === "preflight" ? "preflight/" : phase === "recovery" ? "recovery/" : ""}credential/owner/${i}`,
      "owner-credential",
      "C",
      phase,
      {
        origin: "https://oauth2.googleapis.com",
        method: "POST",
        path: "/token",
        credential: "adc-refresh",
      },
      { providerAttempt: i },
    );
  credential("preflight", 1);
  for (let i = 1; i <= credentialAttempts; i++) {
    credential("normal", i);
    credential("recovery", i);
  }
  add("preflight/owner-userinfo", "userinfo", "P", "preflight", {
    origin: "https://www.googleapis.com",
    method: "GET",
    path: "/oauth2/v2/userinfo",
  });
  add("preflight/bucket", "bucket", "P", "preflight", {
    origin: GCS,
    method: "GET",
    path: `/storage/v1/b/${p.bucket}`,
  });
  r("preflight/release/bucket", "release-baseline", "P", "preflight", "GET", `/v1/${releaseName}`);
  r(
    "preflight/release/bucketless",
    "release-absent",
    "P",
    "preflight",
    "GET",
    `/v1/${bucketlessName}`,
  );
  if (p.baseline.kind === "present")
    add("preflight/baseline/source", "baseline-source", "P", "preflight", {
      origin: RULES,
      method: "GET",
      path: null,
      pathReference: nativeRef("ruleset-path", "baseline"),
    });
  list("preflight/rulesets", "P", "preflight");
  for (const [role, name] of [
    ["allow", a.objectA],
    ["deny", a.objectB],
  ]) {
    object(`seed/${role}/absence-metadata`, "metadata-absent", "F", "normal", name);
    object(`seed/${role}/absence-media`, "media-absent", "F", "normal", name);
    add(
      `seed/${role}/create`,
      "seed",
      "F",
      "normal",
      {
        origin: GCS,
        method: "POST",
        path: `/upload/storage/v1/b/${p.bucket}/o`,
        objectName: name,
        query: { name, uploadType: "media", ifGenerationMatch: "0" },
        body: { base64: Buffer.from("next").toString("base64") },
        headers: { "content-type": "application/octet-stream" },
      },
      { resource: name },
    );
    object(`seed/${role}/metadata`, "metadata", "F", "normal", name);
    object(`seed/${role}/media`, "media", "F", "normal", name);
    object(`baseline/${role}/decision`, "decision", "F", "normal", name, "GET", true);
  }
  r("source/A/test", "valid-test", "F", "normal", "POST", `/v1/projects/${NATIVE_PROJECT}:test`, {
    json: { source: { files: [{ name: "storage.rules", content: a.sourceA }] } },
  });
  r(
    "ruleset/A/create",
    "source-create",
    "F",
    "normal",
    "POST",
    `/v1/projects/${NATIVE_PROJECT}/rulesets`,
    { json: { source: { files: [{ name: "storage.rules", content: a.sourceA }] } } },
  );
  const source = (id, kind, partition, phase, key = "A") =>
    add(id, kind, partition, phase, {
      origin: RULES,
      method: "GET",
      path: null,
      pathReference: nativeRef("ruleset-path", key),
    });
  source("source/A/read", "source-read", "F", "normal");
  r("publish/guard", "release-baseline", "F", "normal", "GET", `/v1/${releaseName}`);
  r(
    "publish/A",
    "release-publish",
    "F",
    "normal",
    p.baseline.kind === "absent" ? "POST" : "PATCH",
    p.baseline.kind === "absent" ? `/v1/projects/${NATIVE_PROJECT}/releases` : `/v1/${releaseName}`,
    {
      json:
        p.baseline.kind === "absent"
          ? { name: releaseName, rulesetName: nativeRef("ruleset-name", "A") }
          : {
              release: { name: releaseName, rulesetName: nativeRef("ruleset-name", "A") },
              updateMask: "rulesetName",
            },
    },
  );
  const settle = (base, partition, phase) => {
    for (let cycle = 1; cycle <= settleCycles; cycle++)
      for (const [role, name] of [
        ["allow", a.objectA],
        ["deny", a.objectB],
      ]) {
        object(`${base}/${cycle}/${role}`, "decision", partition, phase, name, "GET", true);
        rows.at(-1).cycle = cycle;
        rows.at(-1).settleBase = base;
      }
  };
  settle("settle/A", "S", "normal");
  const snapshots = (side) => {
    r(`${side}/release`, "release-identity", "F", "normal", "GET", `/v1/${releaseName}`);
    source(`${side}/source`, "source-read", "F", "normal");
    for (const [role, name] of [
      ["allow", a.objectA],
      ["deny", a.objectB],
    ])
      for (const kind of ["metadata", "media", "decision"])
        object(`${side}/${role}/${kind}`, kind, "F", "normal", name, "GET", kind === "decision");
  };
  snapshots("before");
  r("invalid/test", "invalid-test", "F", "normal", "POST", `/v1/projects/${NATIVE_PROJECT}:test`, {
    json: { source: { files: [{ name: "storage.rules", content: invalid.content }] } },
  });
  snapshots("after");
  const cleanup = (phase) => {
    const base = phase === "recovery" ? "recovery/" : "";
    r(`${base}restore/guard`, "release-guard", "F", phase, "GET", `/v1/${releaseName}`);
    r(
      `${base}restore/apply`,
      "release-restore",
      "F",
      phase,
      p.baseline.kind === "absent" ? "DELETE" : "PATCH",
      `/v1/${releaseName}`,
      p.baseline.kind === "absent"
        ? null
        : {
            json: {
              release: { name: releaseName, rulesetName: nativeRef("ruleset-name", "baseline") },
              updateMask: "rulesetName",
            },
          },
    );
    r(`${base}restore/bucket`, "release-restored", "F", phase, "GET", `/v1/${releaseName}`);
    r(`${base}restore/bucketless`, "release-absent", "F", phase, "GET", `/v1/${bucketlessName}`);
    if (p.baseline.kind === "present")
      source(`${base}restore/source`, "baseline-source", "F", phase, "baseline");
    settle(`${base}settle/baseline`, phase === "recovery" ? "R" : "T", phase);
    source(`${base}cleanup/A/guard`, "source-read", "F", phase);
    add(`${base}cleanup/A/delete`, "source-delete", "F", phase, {
      origin: RULES,
      method: "DELETE",
      path: null,
      pathReference: nativeRef("ruleset-path", "A"),
    });
    source(`${base}cleanup/A/absence`, "source-absent", "F", phase);
    for (const [role, name] of [
      ["allow", a.objectA],
      ["deny", a.objectB],
    ]) {
      object(`${base}cleanup/${role}/guard`, "metadata", "F", phase, name);
      object(`${base}cleanup/${role}/delete`, "object-delete", "F", phase, name, "DELETE");
      object(`${base}cleanup/${role}/absence-metadata`, "metadata-absent", "F", phase, name);
      object(`${base}cleanup/${role}/absence-media`, "media-absent", "F", phase, name);
    }
    add(`${base}cleanup/prefix-empty`, "prefix-empty", "Q", phase, {
      origin: GCS,
      method: "GET",
      path: `/storage/v1/b/${p.bucket}/o`,
      query: { prefix: binding.prefix, maxResults: "1000" },
    });
    list(`${base}cleanup/rulesets`, "Q", phase);
  };
  cleanup("normal");
  cleanup("recovery");
  for (const row of rows)
    if (row.phase === "recovery" && row.partition !== "C") row.partition = "R";
  for (const row of rows) {
    if (row.kind === "seed") row.requires = ["owned-namespace-and-absence"];
    if (row.kind === "object-delete")
      row.requires = [
        "confirmed-write-history-and-current-version",
        "delete-not-attempted",
        "object-not-absent-per-latest-readback",
      ];
  }
  const partitions = Object.fromEntries(
    ["P", "F", "S", "T", "Q", "R", "C"].map((key) => [
      key,
      rows.filter((row) => row.partition === key).length,
    ]),
  );
  const counts = {
    partitions,
    total: rows.length,
    normal: rows.filter((row) => row.phase !== "recovery").length,
    recovery: rows.filter((row) => row.phase === "recovery").length,
  };
  if (
    new Set(rows.map((row) => row.id)).size !== rows.length ||
    counts.total > 6648 ||
    counts.normal > 4648 ||
    counts.recovery > 2000
  )
    throw new Error("invalid native inventory");
  const value = {
    schemaVersion: 1,
    kind: "installed-invalid-native-manifest",
    sendAuthorized: false,
    closureReady: false,
    originalCheck: ORIGINAL_COMPILE_CHECK,
    endpointClaim:
      "invalid Rules:test with installed A; no invalid Rules:create or publication claim",
    ...p,
    binding,
    releaseName,
    bucketlessName,
    baselineSha256: nativeDigest(p.baseline),
    sources: { A: { content: a.sourceA, sha256: nativeDigest(a.sourceA) }, invalid },
    resources: { objects: [a.objectA, a.objectB], documents: [], accounts: [] },
    accountProof: { status: "NO_CREATION", accountApiRequests: 0 },
    rows,
    counts,
    legacyReservationCeiling: { maxRequests: 6648, recoveryReserve: 2000 },
    priorCompileProofs: p.priorCompileProofs,
  };
  value.manifestSha256 = nativeDigest(value);
  return freeze(value);
}
