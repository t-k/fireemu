import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import { relative, resolve, sep } from "node:path";

const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const digestPattern = /^[0-9a-f]{64}$/;
const dependencyTypes = {
  "fs-transaction-p13b-comparator-source-v1":
    "tools/compat-broad/fs-write-txn/fs_txn_compare_local.py",
  "fs-transaction-p13b-table-source-v1": "tools/compat-broad/fs-write-txn/fs_txn_table_p13b.py",
};
const loadedDocuments = new WeakMap();
const supported = {
  "fs-transaction-recorded-observations-v1": {
    parent: "FS-TRANSACTION",
    path: "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-observations-v1.json",
  },
  "fs-transaction-recorded-comparison-preparation-v1": {
    parent: "FS-TRANSACTION",
    path: "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-comparison-v1.json",
  },
  "storage-rules-comparison-v1": {
    parent: "STORAGE-RULES",
    path: "spec/compatibility/closure/evidence/STORAGE-RULES-comparison.json",
  },
};

function closed(value, keys, label) {
  assert.ok(
    value && typeof value === "object" && !Array.isArray(value),
    `${label}: object required`,
  );
  assert.deepEqual(Object.keys(value).toSorted(), [...keys].toSorted(), `${label}: closed fields`);
}

function checkedReference(parent, ref) {
  closed(ref, ["recordType", "recordPath", "recordSha256"], "evidence reference");
  const kind = supported[ref.recordType];
  assert.ok(kind && kind.parent === parent, "unsupported parent or record type");
  assert.equal(
    ref.recordPath,
    kind.path,
    "record path must name the admitted public producer type",
  );
  assert.match(ref.recordSha256, digestPattern, "record SHA-256");
}

function checkBinding(parent, binding) {
  closed(
    binding,
    [
      "inventoryPath",
      "inventorySha256",
      "records",
      "dependencies",
      "finalProduct",
      "independentReview",
    ],
    "current binding",
  );
  assert.equal(
    binding.inventoryPath,
    `spec/compatibility/closure/${parent}.json`,
    "current inventory path",
  );
  assert.match(binding.inventorySha256, digestPattern, "current inventory SHA-256");
  assert.ok(Array.isArray(binding.records), "record references required");
  const seen = new Set();
  for (const ref of binding.records) {
    checkedReference(parent, ref);
    assert.ok(!seen.has(ref.recordPath), "duplicate evidence reference");
    seen.add(ref.recordPath);
  }
  assert.ok(Array.isArray(binding.dependencies), "typed dependencies required");
  const requiredTypes = new Set();
  if (binding.records.some((ref) => ref.recordType.startsWith("fs-transaction-")))
    requiredTypes.add("fs-transaction-p13b-table-source-v1");
  if (
    binding.records.some(
      (ref) => ref.recordType === "fs-transaction-recorded-comparison-preparation-v1",
    )
  )
    requiredTypes.add("fs-transaction-p13b-comparator-source-v1");
  const dependencySet = new Set();
  for (const ref of binding.dependencies) {
    closed(ref, ["sourceType", "sourcePath", "sourceSha256"], "dependency reference");
    assert.ok(requiredTypes.has(ref.sourceType), "unadmitted dependency type");
    assert.equal(ref.sourcePath, dependencyTypes[ref.sourceType], "admitted dependency path");
    assert.match(ref.sourceSha256, digestPattern, "dependency SHA-256");
    assert.ok(!dependencySet.has(ref.sourceType), "duplicate dependency reference");
    dependencySet.add(ref.sourceType);
  }
  assert.deepEqual(dependencySet, requiredTypes, "required typed dependency set");
  // No current final-product or independent-review producer has been published in this slice.
  // A retained partial comparison cannot occupy either slot, even with an approval string.
  for (const [slot, ref] of [
    ["final product", binding.finalProduct],
    ["independent review", binding.independentReview],
  ]) {
    if (ref !== null) {
      checkedReference(parent, ref);
      throw new Error(`${slot}: this record type does not prove the required artifact and review`);
    }
  }
}

function checkDependencyPaths(records) {
  const observed = records.get("fs-transaction-recorded-observations-v1");
  if (observed)
    assert.equal(
      observed.corpora?.[0]?.table,
      dependencyTypes["fs-transaction-p13b-table-source-v1"],
      "admitted dependency path",
    );
  const prepared = records.get("fs-transaction-recorded-comparison-preparation-v1");
  if (prepared) {
    assert.equal(
      prepared.producer?.path,
      dependencyTypes["fs-transaction-p13b-comparator-source-v1"],
      "admitted dependency path",
    );
    assert.equal(
      prepared.producer?.tablePath,
      dependencyTypes["fs-transaction-p13b-table-source-v1"],
      "admitted dependency path",
    );
  }
}

/** Read only the exact admitted public inputs. Private records and authority are never opened. */
export function loadCurrentBinding(root, parent, binding, documents) {
  checkBinding(parent, binding);
  const actualRoot = realpathSync(root);
  const origin = loadedDocuments.get(documents) ?? { root: actualRoot, dependencies: new Map() };
  assert.equal(origin.root, actualRoot, "loaded repository root mismatch");
  const read = (path) => {
    const target = resolve(actualRoot, path);
    assert.ok(lstatSync(target).isFile(), `${path}: regular file required`);
    const actual = realpathSync(target);
    assert.ok(!relative(actualRoot, actual).startsWith(`..${sep}`), `${path}: escaped repository`);
    documents.set(path, readFileSync(actual));
  };
  for (const path of [binding.inventoryPath, ...binding.records.map((ref) => ref.recordPath)])
    read(path);
  checkDependencyPaths(
    new Map(
      binding.records.map((ref) => [
        ref.recordType,
        parseStrictJson(documents.get(ref.recordPath)),
      ]),
    ),
  );
  for (const ref of binding.dependencies) read(ref.sourcePath);
  for (const ref of binding.dependencies) {
    const actualSha256 = sha(documents.get(ref.sourcePath));
    assert.equal(actualSha256, ref.sourceSha256, "loaded dependency SHA-256 mismatch");
    origin.dependencies.set(ref.sourcePath, actualSha256);
  }
  loadedDocuments.set(documents, origin);
}

export function parseStrictJson(input) {
  let text;
  try {
    text =
      typeof input === "string" ? input : new TextDecoder("utf-8", { fatal: true }).decode(input);
  } catch {
    throw new Error("JSON input must be valid UTF-8");
  }
  const document = JSON.parse(text);
  let offset = 0;
  const whitespace = () => {
    while (/\s/.test(text[offset] ?? "") && offset < text.length) offset++;
  };
  const string = () => {
    const start = offset++;
    while (text[offset] !== '"') {
      if (text[offset] === "\\") offset++;
      offset++;
    }
    offset++;
    return JSON.parse(text.slice(start, offset));
  };
  const value = () => {
    whitespace();
    if (text[offset] === "{") {
      offset++;
      const keys = new Set();
      whitespace();
      while (text[offset] !== "}") {
        const key = string();
        if (keys.has(key)) throw new Error(`duplicate JSON key ${key}`);
        keys.add(key);
        whitespace();
        offset++;
        value();
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
        whitespace();
      }
      offset++;
    } else if (text[offset] === "[") {
      offset++;
      whitespace();
      while (text[offset] !== "]") {
        value();
        whitespace();
        if (text[offset] !== ",") break;
        offset++;
      }
      offset++;
    } else if (text[offset] === '"') string();
    else while (offset < text.length && !/[\s,}\]]/.test(text[offset])) offset++;
  };
  value();
  return document;
}

function p13bDigest(value) {
  const canonical = (item) => {
    if (Array.isArray(item)) return item.map(canonical);
    if (item !== null && typeof item === "object")
      return Object.fromEntries(
        Object.keys(item)
          .toSorted()
          .map((key) => [key, canonical(item[key])]),
      );
    return item;
  };
  return createHash("sha256")
    .update(JSON.stringify(canonical(value)))
    .digest("hex");
}

function verifyP13bObservations(observed) {
  closed(
    observed,
    [
      "schemaVersion",
      "kind",
      "parent",
      "condition",
      "coverage",
      "authorizesProduction",
      "promotionReady",
      "decodedSemanticsValidated",
      "rawRestWireLayoutValidated",
      "normalization",
      "remainingBoundaries",
      "corpora",
    ],
    "P13b observation record",
  );
  assert.equal(observed.schemaVersion, 1);
  assert.equal(observed.kind, "fs-transaction-recorded-observations-v1");
  assert.equal(observed.parent, "FS-TRANSACTION");
  assert.equal(observed.condition, "FS-TRANSACTION/retry-token-lifecycle");
  assert.equal(observed.coverage, "PARTIAL");
  assert.equal(observed.authorizesProduction, false);
  assert.equal(observed.promotionReady, false);
  assert.equal(observed.decodedSemanticsValidated, true);
  assert.equal(observed.rawRestWireLayoutValidated, false);
  assert.equal(observed.corpora.length, 1);
  const corpus = observed.corpora[0];
  closed(
    corpus,
    [
      "program",
      "table",
      "tableSourceDigest",
      "corpusDigest",
      "sourceCommit",
      "freezeSha256",
      "packetSha256",
      "originalRunnerSha256",
      "originalRunnerFiles",
      "historicalInstalledRuntimeInputsValidated",
      "agree",
      "recipes",
      "retryConsequences",
      "semantics",
      "projection",
      "recordings",
    ],
    "P13b recorded corpus",
  );
  assert.equal(corpus.program, "FS-TRANSACTION-P13B-RETRY-ANSWERS");
  assert.equal(corpus.sourceCommit, "2991d2f1e055407badaaac2e9edab688d42c9d1a");
  assert.equal(
    corpus.tableSourceDigest,
    "6716e049745af5532b837e7c9c06c199f92c8f253c2cb7341dbf7b4a299ce468",
  );
  assert.equal(
    corpus.corpusDigest,
    "3c91e4695ace7cccb5089f3c8fc88425f1393ee40a13c28f97bf15ac05a63751",
  );
  assert.equal(
    corpus.freezeSha256,
    "9c7ff93d46ebecdf6f4e312bee443de1eea57b666499599879f7c4b96983f132",
  );
  assert.equal(
    corpus.packetSha256,
    "c3274163a581342d288a0a9c1448f724258f72f106e9506c8758ec79c1526dc7",
  );
  assert.equal(
    corpus.originalRunnerSha256,
    "7211a1ab2296db4e0712399a17b4ab26fad2beb953b44135475f58513921ec35",
  );
  assert.equal(corpus.historicalInstalledRuntimeInputsValidated, "UNKNOWN");
  const sites = ["setup/absence-a", "setup/create-a"];
  for (const [chain, names] of [
    ["rt1", ["begin", "read-a", "rollback", "retry-begin", "writer", "first-read", "commit"]],
    ["rt2", ["begin", "read-a", "retry-idle"]],
    ["rt3", ["begin", "read-a", "rollback-idle", "retry-after-rollback"]],
    [
      "rt4",
      [
        "begin",
        "read-a",
        ...Array.from({ length: 9 }, (_, index) => `keepalive-${index + 1}`),
        "live-read",
        "retry-lifetime",
      ],
    ],
  ])
    sites.push(...names.map((name) => `rest/${chain}/${name}`));
  sites.push("final/post-read-a");
  assert.deepEqual(
    corpus.recipes.map(({ id }) => id),
    sites,
  );
  assert.equal(new Set(sites).size, 30);
  assert.deepEqual(Object.keys(corpus.semantics.steps), sites);
  for (const recipe of corpus.recipes) {
    const row = corpus.semantics.steps[recipe.id];
    assert.equal(row.transport, recipe.transport);
    assert.equal(row.rpc, recipe.rpc);
    assert.equal(row.caseId, recipe.caseId);
    if (recipe.transport === "rest") {
      assert.equal(row.code, 0);
      assert.equal(row.http, 200);
      assert.equal(row.details, "");
    }
  }
  const cases = [
    "rest/rt1-rollback",
    "rest/rt1-writer",
    "rest/rt1-first-read",
    "rest/rt1-commit",
    "rest/rt2-retry-idle",
    "rest/rt3-rollback-idle",
    "rest/rt3-retry-after-rollback",
    "rest/rt4-retry-lifetime",
  ];
  assert.deepEqual(
    corpus.projection.cases.map(({ caseId }) => caseId),
    cases,
  );
  for (const row of corpus.projection.cases) {
    assert.equal(row.transport, "rest");
    assert.equal(row.code, 0);
    assert.equal(row.details, "");
  }
  assert.equal(corpus.projection.reads.length, 17);
  assert.equal(corpus.agree, true);
  assert.equal(corpus.recordings.length, 2);
  assert.deepEqual(
    corpus.recordings.map(({ sha256 }) => sha256),
    [
      "0c3d167857686716f8d2ecb0b65e37cd82e3fab04676e8c8ebe0c2fc2b5d22d5",
      "1621e5c5822245d65da750d139d879c6c07a1d41e187790341ff5232de6be8cd",
    ],
  );
  for (const [index, recording] of corpus.recordings.entries()) {
    assert.equal(recording.recording, index + 1);
    assert.equal(recording.complete, true);
    assert.equal(recording.graphComplete, true);
    assert.equal(recording.cleanupAbsent, true);
    assert.equal(recording.openTokens, 0);
    assert.equal(recording.unknownOutcomes, 0);
    assert.equal(recording.requests, 45);
    assert.deepEqual(recording.phaseRequests, {
      credential: 1,
      documentCleanup: 3,
      management: 6,
      observation: 30,
      tokenCleanup: 5,
    });
    assert.deepEqual(recording.transportObservations, { rest: 8 });
    assert.equal(recording.semanticDigest, p13bDigest(corpus.semantics));
    assert.equal(recording.projectionDigest, p13bDigest(corpus.projection));
    assert.equal(recording.issuedTokensDistinct, true);
    assert.equal(recording.nativeLifecycle.length, 38);
    assert.deepEqual(
      recording.nativeLifecycle.map(({ sequence }) => sequence),
      Array.from({ length: 38 }, (_, n) => n),
    );
    assert.deepEqual(
      new Set(recording.nativeLifecycle.map(({ site }) => site)),
      new Set([...sites, ...Object.keys(corpus.semantics.cleanupSteps)]),
    );
    for (const row of recording.nativeLifecycle) {
      assert.equal(row.complete, true);
      assert.equal(row.ipcComplete, true);
      assert.equal(row.childReaped, true);
      assert.equal(row.workerExitCode, 0);
      assert.equal(row.dispatchedRequests, 1);
    }
    const waits = new Map(recording.waits.map((entry) => [entry.site, entry]));
    assert.equal(waits.size, 13);
    assert.equal(recording.waitsDigest, p13bDigest(recording.waits));
    for (const site of ["rest/rt2/retry-idle", "rest/rt3/rollback-idle"]) {
      assert.ok(waits.get(site).idleInterval.lowerSeconds >= 130);
      assert.ok(waits.get(site).totalAgeInterval.upperSeconds < 270);
    }
    assert.ok(waits.get("rest/rt4/retry-lifetime").totalAgeInterval.lowerSeconds > 275);
    assert.ok(waits.get("rest/rt4/retry-lifetime").idleInterval.upperSeconds < 120);
    assert.equal(recording.recordedRuntime.nodeVersion, "v24.14.0");
    assert.equal(recording.recordedRuntime.pythonVersion, "3.12.13");
    assert.equal(
      recording.recordedRuntime.workerSha256,
      "4047804796a8a7dd4319c70f6bbe8aa3c38873ef57047761e6a1f5629b1dfea5",
    );
    assert.equal(
      recording.recordedRuntime.lockSha256,
      "04f7f2526af7ce07ca39ceffd0712eec9b5e5e212503c7cb791ab5021a49dc60",
    );
  }
  const retrySites = [
    "rest/rt1/retry-begin",
    "rest/rt2/retry-idle",
    "rest/rt3/retry-after-rollback",
    "rest/rt4/retry-lifetime",
  ];
  for (const [index, site] of retrySites.entries()) {
    const recipe = corpus.recipes.find(({ id }) => id === site);
    assert.equal(recipe.retryOf, `t${index + 1}`);
    assert.equal(recipe.tokenOutput, `t${index + 1}r`);
    assert.deepEqual(corpus.retryConsequences[index], {
      site,
      namedToken: recipe.retryOf,
      issuedToken: recipe.tokenOutput,
      issuedDifferent: true,
    });
  }
  const steps = corpus.semantics.steps;
  assert.equal(steps["rest/rt1/first-read"].read.state, "rest-rt1-writer");
  assert.equal(
    steps["rest/rt1/first-read"].versions["/updateTime"].rank,
    steps["rest/rt1/writer"].versions["/writeResults/0/updateTime"].rank,
  );
  assert.equal(steps["final/post-read-a"].read.state, "rest-rt1-commit");
  assert.equal(
    steps["final/post-read-a"].versions["/updateTime"].rank,
    steps["rest/rt1/commit"].versions["/writeResults/0/updateTime"].rank,
  );
  assert.equal(corpus.projection.expectedStates.a, "rest-rt1-commit");
  assert.equal(corpus.semantics.tokens.t1r.state, "committed");
  assert.equal(corpus.semantics.tokens.t4.state, "released-refused");
  assert.deepEqual(Object.keys(corpus.semantics.cleanupSteps), [
    "cleanup/token/t2",
    "cleanup/token/t2r",
    "cleanup/token/t3r",
    "cleanup/token/t4",
    "cleanup/token/t4r",
    "cleanup/read/a",
    "cleanup/delete/a",
    "cleanup/verify/a",
  ]);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4"].code, 10);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4"].http, 409);
  assert.equal(
    corpus.semantics.cleanupSteps["cleanup/token/t4"].details,
    "The referenced transaction has expired or is no longer valid.",
  );
  assert.equal(corpus.semantics.cleanupSteps["cleanup/token/t4r"].code, 0);
  assert.equal(corpus.semantics.cleanupSteps["cleanup/verify/a"].code, 5);
  assert.deepEqual(corpus.semantics.cleanup, { absent: true });
  assert.equal(
    new Set(corpus.recordings.map((r) => r.recording)).size,
    2,
    "native identities must differ",
  );
  assert.equal(new Set(corpus.recordings.map((r) => r.sha256)).size, 2, "native bytes must differ");
  return corpus;
}

function verifyP13bPreparation(compared, corpus, dependencies) {
  closed(
    compared,
    [
      "schemaVersion",
      "kind",
      "parent",
      "condition",
      "coverage",
      "promotionReady",
      "authorizesProduction",
      "status",
      "productionRequests",
      "capturedReplays",
      "requiredReplays",
      "artifact",
      "preparationBaseCommit",
      "producer",
      "plannedReplays",
      "corpora",
      "remainingBoundaries",
      "dependency",
    ],
    "published preparation",
  );
  closed(
    compared.producer,
    [
      "path",
      "sha256",
      "tablePath",
      "tableSha256",
      "tableSourceCommit",
      "currentTableSha256",
      "tableBinding",
    ],
    "preparation producer",
  );
  assert.equal(
    compared.preparationBaseCommit,
    "e57a78e0f5c4852894d14fad31438b2fa9d681e0",
    "preparation provenance",
  );
  assert.equal(
    compared.producer.tableBinding,
    "Original frozen bytes must be materialized without rewriting recording sourceDigest; the current table differs only in its module docstring.",
  );
  assert.deepEqual(compared.remainingBoundaries, [
    "Raw REST bodyBytes, content-length and received member-order layout were not retained; decoded semantic equality is partial proof.",
    "Historical installed runtime input currency cannot be independently established from the retained packet and decoded receipts; it remains UNKNOWN.",
    "Representative gRPC retry snapshot and idle/lifetime consequences, remaining original boundaries, the official emulator gate, all 18 frozen conditions and parent closure review remain open.",
    "Four source-bound normal artifact comparisons remain pending; frozen nominal 260-second lifetime waits may not reproduce the recorded 279-to-283-second age with faster local RPCs.",
  ]);
  assert.equal(
    compared.dependency,
    "ROOT must provide a source-bound normal artifact and exact current runtime proof. A normal runtime wave is not a final whole-tree artifact. The unchanged comparator project-diagnostic context and actual lifetime age must be checked before claiming agreement; unresolved differences remain RED.",
  );
  assert.ok(Array.isArray(compared.plannedReplays), "planned replay array required");
  for (const replay of compared.plannedReplays)
    closed(replay, ["profile", "recording", "productionFileSha256"], "preparation replay");
  assert.ok(Array.isArray(compared.corpora), "preparation corpora required");
  for (const recorded of compared.corpora)
    closed(recorded, ["program", "results"], "preparation corpus");
  assert.equal(compared.schemaVersion, 1);
  assert.equal(compared.kind, "fs-transaction-recorded-comparison-preparation-v1");
  assert.equal(compared.parent, "FS-TRANSACTION");
  assert.equal(compared.condition, "FS-TRANSACTION/retry-token-lifecycle");
  assert.equal(compared.coverage, "PARTIAL");
  assert.equal(compared.authorizesProduction, false);
  assert.equal(compared.promotionReady, false);
  assert.equal(compared.status, "PENDING_FINAL_ARTIFACT_REPLAY");
  assert.equal(compared.artifact, null);
  assert.equal(compared.productionRequests, 0);
  assert.equal(compared.capturedReplays, 0);
  assert.equal(compared.requiredReplays, 4);
  assert.deepEqual(compared.corpora, [{ program: corpus.program, results: [] }]);
  assert.deepEqual(
    compared.plannedReplays.map(({ profile, recording }) => `${profile}/${recording}`),
    ["strict/1", "strict/2", "emulator/1", "emulator/2"],
  );
  for (const replay of compared.plannedReplays)
    assert.equal(replay.productionFileSha256, corpus.recordings[replay.recording - 1].sha256);
  assert.equal(compared.producer.sha256, dependencies.get(compared.producer.path));
  assert.equal(compared.producer.tableSha256, corpus.tableSourceDigest);
  assert.equal(compared.producer.tableSourceCommit, corpus.sourceCommit);
  assert.equal(compared.producer.currentTableSha256, dependencies.get(corpus.table));
  assert.notEqual(compared.producer.currentTableSha256, corpus.tableSourceDigest);
}

function verifyHistoricalRules(comparison) {
  closed(
    comparison,
    ["kind", "divergenceClasses", "artifactSha256", "fixtureSha256", "summary", "rows"],
    "historical Rules comparison",
  );
  assert.equal(comparison.kind, "storage-rules-comparison-v1");
  assert.equal(
    comparison.artifactSha256,
    "075593e8e7f528b2f318fd121f67bf539b4a1f7cf039b3fb9e980b49c9a936f7",
  );
  assert.equal(
    comparison.fixtureSha256,
    "0ef2d20dfcfa90df183db90c107f74af0bd25cefe14a24256fbe3e3213d235b4",
  );
  closed(comparison.summary, ["MATCH", "RECORDED_DIVERGENCE"], "historical summary");
  assert.ok(Array.isArray(comparison.rows));
  assert.equal(comparison.rows.length, 3641, "original historical row population");
  assert.equal(
    new Set(comparison.rows.map((r) => r.row)).size,
    comparison.rows.length,
    "each historical row once",
  );
  const counts = { MATCH: 0, RECORDED_DIVERGENCE: 0 };
  for (const row of comparison.rows) {
    const recorded = row.status === "RECORDED_DIVERGENCE";
    closed(
      row,
      recorded ? ["row", "status", "divergence"] : ["row", "status"],
      "historical comparison row",
    );
    assert.ok(typeof row.row === "string" && row.row.length > 0);
    assert.ok(Object.hasOwn(counts, row.status), "unexplained historical comparison status");
    if (recorded) {
      assert.equal(
        row.divergence,
        "firestore-adapter-content-type",
        "exact historical divergence class",
      );
      assert.match(
        row.row,
        /^firestore-program\/(?:firestore-budget-repeat|firestore-budget-three|firestore-budget-two|firestore-exists-transition|firestore-get-transition)\//,
        "historical divergence family",
      );
    }
    counts[row.status]++;
  }
  assert.deepEqual(counts, comparison.summary, "actual row summary");
  assert.deepEqual(
    counts,
    { MATCH: 3583, RECORDED_DIVERGENCE: 58 },
    "preserve historical divergence scope",
  );
  assert.deepEqual(comparison.divergenceClasses, {
    "firestore-adapter-content-type":
      "Firestore program rows read the Firestore adapter, whose JSON content type is outside the Storage framing",
  });
  return {
    observedCases: comparison.rows.length,
    matchedCases: counts.MATCH,
    recordedDivergences: counts.RECORDED_DIVERGENCE,
    artifactSha256: comparison.artifactSha256,
  };
}

function obligationFacets(parent, original) {
  const facets = [];
  for (const condition of original.conditions) {
    const kind = condition.conditionId.endsWith("/final-artifact-regression")
      ? "FINAL_PRODUCT"
      : condition.conditionId.endsWith("/closure-review")
        ? "CLEAN_REVIEW"
        : condition.evidenceType === "fireemu-only"
          ? "LOCAL_PRODUCT"
          : "PRODUCTION_BEHAVIOR";
    facets.push({ facetId: `${condition.conditionId}::${kind.toLowerCase()}`, kind });
    if (["STORAGE-OBJECT", "STORAGE-RULES"].includes(parent) && kind === "FINAL_PRODUCT")
      facets.push({
        facetId: `${condition.conditionId}::official_comparison`,
        kind: "OFFICIAL_COMPARISON",
      });
  }
  facets.push({
    facetId: `${parent}::emulator-profile-contract`,
    kind: "EMULATOR_PROFILE_CONTRACT",
  });
  return facets;
}

/** Evaluate retained facts against original obligations. A partial fact is never closure authority. */
export function evaluateCurrentParent({
  root,
  parent,
  originalInventory,
  currentInventory,
  currentBinding,
  documents,
}) {
  checkBinding(parent, currentBinding);
  const origin = loadedDocuments.get(documents);
  assert.ok(root && origin, "loaded repository root required");
  assert.equal(realpathSync(root), origin.root, "loaded repository root mismatch");
  const dependencies = new Map();
  for (const ref of currentBinding.dependencies) {
    const bytes = documents.get(ref.sourcePath);
    assert.ok(bytes, "actual dependency bytes missing");
    assert.equal(sha(bytes), ref.sourceSha256, "actual dependency bytes differ");
    assert.equal(
      origin.dependencies.get(ref.sourcePath),
      ref.sourceSha256,
      "loaded dependency SHA-256 mismatch",
    );
    dependencies.set(ref.sourcePath, ref.sourceSha256);
  }
  assert.equal(originalInventory.parent, parent);
  assert.equal(currentInventory.parent, parent);
  const inventoryBytes = documents.get(currentBinding.inventoryPath);
  assert.ok(inventoryBytes, "current inventory bytes missing");
  assert.equal(
    sha(inventoryBytes),
    currentBinding.inventorySha256,
    "current inventory bytes differ",
  );
  assert.deepEqual(
    parseStrictJson(inventoryBytes),
    currentInventory,
    "current inventory object differs from actual bytes",
  );
  for (const field of [
    "scopeDecisions",
    "inventoryState",
    "inventoryStatus",
    "freezeState",
    "observationContract",
  ])
    if (Object.hasOwn(originalInventory, field))
      assert.deepEqual(
        currentInventory[field],
        originalInventory[field],
        `original ${parent}/${field}`,
      );
  if (originalInventory.profileComparison) {
    assert.equal(
      currentInventory.profileComparison?.profile,
      originalInventory.profileComparison.profile,
    );
    assert.equal(
      currentInventory.profileComparison?.note,
      originalInventory.profileComparison.note,
      "original emulator profile contract",
    );
  }
  assert.deepEqual(
    currentInventory.conditions.map((c) => c.conditionId).toSorted(),
    originalInventory.conditions.map((c) => c.conditionId).toSorted(),
    "original condition IDs",
  );
  const current = new Map(currentInventory.conditions.map((c) => [c.conditionId, c]));
  for (const condition of originalInventory.conditions)
    for (const field of [
      "source",
      "recipeIds",
      "checks",
      "cases",
      "evidenceType",
      "verification",
      "observation",
    ])
      if (Object.hasOwn(condition, field))
        assert.deepEqual(
          current.get(condition.conditionId)[field],
          condition[field],
          `original ${condition.conditionId}/${field}`,
        );
  const loaded = new Map();
  for (const ref of currentBinding.records) {
    const bytes = documents.get(ref.recordPath);
    assert.ok(bytes, `${ref.recordPath}: actual record bytes missing`);
    assert.equal(sha(bytes), ref.recordSha256, `${ref.recordPath}: record bytes differ`);
    const record = parseStrictJson(bytes);
    assert.equal(record.kind, ref.recordType, "actual record kind differs");
    loaded.set(ref.recordType, record);
  }
  const records = [];
  const missing = [];
  const observed = loaded.get("fs-transaction-recorded-observations-v1");
  const prepared = loaded.get("fs-transaction-recorded-comparison-preparation-v1");
  checkDependencyPaths(loaded);
  if (observed) {
    const corpus = verifyP13bObservations(observed);
    records.push({
      recordType: observed.kind,
      scope: observed.coverage,
      nativeRecordings: corpus.recordings.length,
      observedCases: corpus.projection.cases.length,
      rawWireValidated: observed.rawRestWireLayoutValidated,
      installedRuntimeCurrency: corpus.historicalInstalledRuntimeInputsValidated,
    });
    missing.push(
      "P13b raw REST wire and representative gRPC remain unobserved",
      `P13b historical installed runtime currency: ${corpus.historicalInstalledRuntimeInputsValidated}`,
    );
    if (prepared) {
      verifyP13bPreparation(prepared, corpus, dependencies);
      records.push({
        recordType: prepared.kind,
        scope: prepared.coverage,
        capturedReplays: prepared.capturedReplays,
        requiredReplays: prepared.requiredReplays,
      });
      missing.push(
        `P13b current source-bound comparisons: ${prepared.capturedReplays}/${prepared.requiredReplays}`,
      );
    } else missing.push("P13b current source-bound comparison record missing");
  } else if (prepared) throw new Error("P13b preparation requires the recorded observations");
  const rules = loaded.get("storage-rules-comparison-v1");
  if (rules) {
    records.push({
      recordType: rules.kind,
      scope: "HISTORICAL_ROWS",
      ...verifyHistoricalRules(rules),
    });
    missing.push(
      "Rules rows lack current source, runner, build, native lifecycle and review binding",
      "Rules management compile/release/no-release witnesses require current actual comparisons",
    );
  }
  // Only the typed validators above construct facts. Input status and approval fields are ignored.
  // These particular producer types retain subsets/history and prove no entire original facet.
  const provenFacets = new Map(records.flatMap((record) => record.originalFacetProofs ?? []));
  const facets = obligationFacets(parent, originalInventory).map((shape) => {
    const evidence = provenFacets.get(shape.facetId) ?? null;
    return Object.assign({}, shape, { state: evidence === null ? "OPEN" : "VERIFIED", evidence });
  });
  for (const facet of facets.filter((f) => f.kind !== "OFFICIAL_COMPARISON" && f.evidence === null))
    missing.push(`${facet.facetId}: complete ${facet.kind.toLowerCase()} evidence missing`);
  if (currentBinding.finalProduct === null) missing.push("current final product receipt missing");
  if (currentBinding.independentReview === null)
    missing.push("current independent review receipt missing");
  const mandatory = facets.filter((f) => f.kind !== "OFFICIAL_COMPARISON");
  const eligible =
    mandatory.length > 0 && mandatory.every((f) => f.state === "VERIFIED" && f.evidence !== null);
  assert.ok(
    currentInventory.parentStatus !== "COMPAT_VERIFIED" || eligible,
    `${parent}: current declaration has no complete actual evidence`,
  );
  return {
    parent,
    facets,
    dependencies: currentBinding.dependencies
      .map((ref) => Object.assign({}, ref))
      .toSorted((a, b) => a.sourcePath.localeCompare(b.sourcePath, "en")),
    records: records.toSorted((a, b) => a.recordType.localeCompare(b.recordType, "en")),
    missing: [...new Set(missing)].toSorted(),
    eligible,
  };
}
