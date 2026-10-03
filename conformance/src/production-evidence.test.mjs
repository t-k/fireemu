import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { loadCurrentBinding as loadFixtureBinding } from "./production-evidence.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const modulePath = resolve(root, "conformance/src/production-evidence.mjs");
const sha = (bytes) => createHash("sha256").update(bytes).digest("hex");
const paths = {
  observations: "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-observations-v1.json",
  preparation: "spec/compatibility/broad-runs/fs-transaction-p13b-recorded-comparison-v1.json",
  rules: "spec/compatibility/closure/evidence/STORAGE-RULES-comparison.json",
};
const api = async () => {
  assert.ok(existsSync(modulePath), "publish the actual production evidence validator");
  return import(modulePath);
};
const fixture = (parent = "FS-TRANSACTION") => {
  const inventoryPath = `spec/compatibility/closure/${parent}.json`;
  const documents = new Map();
  const read = (path) => {
    const bytes = readFileSync(resolve(root, path));
    documents.set(path, bytes);
    return JSON.parse(bytes);
  };
  const currentInventory = read(inventoryPath);
  const originalInventory = read(
    `spec/compatibility/official-compatibility/history/e57a78e0/${parent}.json`,
  );
  const recordPaths =
    parent === "FS-TRANSACTION"
      ? [paths.observations, paths.preparation]
      : parent === "STORAGE-RULES"
        ? [paths.rules]
        : [];
  const records = recordPaths.map((recordPath) => {
    const document = read(recordPath);
    return { recordType: document.kind, recordPath, recordSha256: sha(documents.get(recordPath)) };
  });
  const value = {
    root,
    parent,
    originalInventory,
    currentInventory,
    documents,
    currentBinding: {
      inventoryPath,
      inventorySha256: sha(documents.get(inventoryPath)),
      records,
      dependencies:
        parent === "FS-TRANSACTION"
          ? [
              [
                "fs-transaction-p13b-comparator-source-v1",
                "tools/compat-broad/fs-write-txn/fs_txn_compare_local.py",
              ],
              [
                "fs-transaction-p13b-table-source-v1",
                "tools/compat-broad/fs-write-txn/fs_txn_table_p13b.py",
              ],
            ].map(([sourceType, sourcePath]) => ({
              sourceType,
              sourcePath,
              sourceSha256: sha(readFileSync(resolve(root, sourcePath))),
            }))
          : [],
      finalProduct: null,
      independentReview: null,
    },
  };
  loadFixtureBinding(root, parent, value.currentBinding, documents);
  return value;
};
const replaceRecord = (value, path, change) => {
  const record = JSON.parse(value.documents.get(path));
  change(record);
  const bytes = Buffer.from(`${JSON.stringify(record)}\n`);
  value.documents.set(path, bytes);
  value.currentBinding.records.find((ref) => ref.recordPath === path).recordSha256 = sha(bytes);
};

test("actual P13b files expose native partial coverage and four missing current replays", async () => {
  const { evaluateCurrentParent } = await api();
  const result = evaluateCurrentParent(fixture());
  assert.equal(result.eligible, false);
  assert.equal(result.records.length, 2);
  const observed = result.records.find(
    (r) => r.recordType === "fs-transaction-recorded-observations-v1",
  );
  assert.equal(observed.nativeRecordings, 2);
  assert.equal(observed.observedCases, 8);
  assert.equal(observed.rawWireValidated, false);
  assert.equal(observed.installedRuntimeCurrency, "UNKNOWN");
  assert.ok(result.missing.some((reason) => reason.includes("0/4")));
  assert.ok(result.missing.some((reason) => reason.includes("final product")));
  assert.ok(result.missing.some((reason) => reason.includes("independent review")));
  assert.ok(result.facets.every((facet) => facet.state === "OPEN"));
});

test("actual old Storage rows retain their scope and cannot stand in for the current final product", async () => {
  const result = (await api()).evaluateCurrentParent(fixture("STORAGE-RULES"));
  assert.equal(result.eligible, false);
  assert.equal(result.records[0].observedCases, 3641);
  assert.equal(result.records[0].matchedCases, 3583);
  assert.equal(result.records[0].recordedDivergences, 58);
  assert.equal(
    result.records[0].artifactSha256,
    "075593e8e7f528b2f318fd121f67bf539b4a1f7cf039b3fb9e980b49c9a936f7",
  );
  assert.ok(result.missing.some((reason) => reason.includes("current source")));
  assert.ok(result.missing.some((reason) => reason.includes("management")));
});

test("historical recorded divergence requires its exact status-specific field", async () => {
  const value = fixture("STORAGE-RULES");
  replaceRecord(value, paths.rules, (document) => {
    for (const row of document.rows)
      if (row.status === "RECORDED_DIVERGENCE") delete row.divergence;
  });
  const { evaluateCurrentParent } = await api();
  assert.throws(() => evaluateCurrentParent(value), /closed fields/);
});

for (const [label, change] of [
  [
    "MATCH cannot carry divergence",
    (d) => {
      d.rows.find((r) => r.status === "MATCH").divergence = "firestore-adapter-content-type";
    },
  ],
  [
    "recorded divergence cannot carry arbitrary fields",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").extra = true;
    },
  ],
  [
    "divergence null is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = null;
    },
  ],
  [
    "divergence object is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = {};
    },
  ],
  [
    "divergence array is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = [];
    },
  ],
  [
    "divergence boolean is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = true;
    },
  ],
  [
    "divergence number is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = 1;
    },
  ],
  [
    "unknown divergence class is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").divergence = "invented";
    },
  ],
  [
    "different divergence family is refused",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").row = "case/not-recorded";
    },
  ],
  [
    "recorded row cannot become MATCH",
    (d) => {
      d.rows.find((r) => r.status === "RECORDED_DIVERGENCE").status = "MATCH";
    },
  ],
  [
    "unknown historical status is refused",
    (d) => {
      d.rows[0].status = "VERIFIED";
    },
  ],
  [
    "old comparison cannot claim a current artifact",
    (d) => {
      d.artifactSha256 = "0".repeat(64);
    },
  ],
]) {
  test(`historical closed schema: ${label}`, async () => {
    const value = fixture("STORAGE-RULES");
    replaceRecord(value, paths.rules, change);
    const { evaluateCurrentParent } = await api();
    assert.throws(() => evaluateCurrentParent(value));
  });
}

test("file-backed references reject wrong bytes, paths, duplicates and unknown schemas", async () => {
  const { evaluateCurrentParent } = await api();
  for (const change of [
    (v) => {
      v.currentBinding.records[0].recordSha256 = "0".repeat(64);
    },
    (v) => {
      v.currentBinding.inventorySha256 = "0".repeat(64);
    },
    (v) => {
      v.currentBinding.records[0].recordPath = "../outside.json";
    },
    (v) => {
      v.currentBinding.records.push(structuredClone(v.currentBinding.records[0]));
    },
    (v) => {
      v.currentBinding.records[0].recordType = "invented-final-VERIFIED";
    },
    (v) => {
      v.currentBinding.approved = true;
    },
    (v) => {
      v.currentBinding.records[0].recordPath = "spec/compatibility/production-parent-registry.json";
    },
  ]) {
    const value = fixture();
    change(value);
    assert.throws(() => evaluateCurrentParent(value));
  }
});

test("recorded native identity, unknown outcomes and partial boundaries cannot be rewritten", async () => {
  const { evaluateCurrentParent } = await api();
  for (const change of [
    (d) => {
      d.corpora[0].recordings[1].sha256 = d.corpora[0].recordings[0].sha256;
    },
    (d) => {
      d.corpora[0].recordings[1].recording = 1;
    },
    (d) => {
      d.corpora[0].recordings[1].recording = 3;
    },
    (d) => {
      d.corpora[0].recordings[0].unknownOutcomes = 1;
    },
    (d) => {
      d.corpora[0].recordings[0].nativeLifecycle[0].ipcComplete = false;
    },
    (d) => {
      d.coverage = "COMPLETE";
    },
    (d) => {
      d.corpora[0].historicalInstalledRuntimeInputsValidated = true;
    },
    (d) => {
      d.rawRestWireLayoutValidated = true;
    },
    (d) => {
      d.corpora[0].projection.cases.pop();
    },
  ]) {
    const value = fixture();
    replaceRecord(value, paths.observations, change);
    assert.throws(() => evaluateCurrentParent(value));
  }
});

test("fake final and review refs cannot turn source-only status into admission", async () => {
  const { evaluateCurrentParent } = await api();
  for (const slot of ["finalProduct", "independentReview"]) {
    const value = fixture();
    value.currentBinding[slot] = structuredClone(value.currentBinding.records[0]);
    assert.throws(() => evaluateCurrentParent(value), /final|review|record type/);
  }
});

for (const role of ["producer", "table"]) {
  test(`dependency confinement refuses a JSON-selected external ${role} before reading it`, async () => {
    const { evaluateCurrentParent } = await api();
    const value = fixture();
    const directory = mkdtempSync(resolve(tmpdir(), "fireemu-dependency-sentinel-"));
    try {
      const sentinel = resolve(directory, "nonsecret.txt");
      const bytes = Buffer.from("Nonsecret dependency witness\n");
      writeFileSync(sentinel, bytes);
      if (role === "producer")
        replaceRecord(value, paths.preparation, (d) => {
          d.producer.path = relative(root, sentinel);
          d.producer.sha256 = sha(bytes);
        });
      else {
        replaceRecord(value, paths.observations, (d) => {
          d.corpora[0].table = relative(root, sentinel);
        });
        replaceRecord(value, paths.preparation, (d) => {
          d.producer.currentTableSha256 = sha(bytes);
        });
      }
      assert.throws(() => evaluateCurrentParent(value), /admitted dependency path/);
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });
}

test("dependency confinement rejects a caller root different from the loaded repository", async () => {
  const { evaluateCurrentParent, loadCurrentBinding } = await api();
  const value = fixture();
  loadCurrentBinding(root, value.parent, value.currentBinding, value.documents);
  const directory = mkdtempSync(resolve(tmpdir(), "fireemu-other-root-"));
  try {
    value.root = directory;
    assert.throws(() => evaluateCurrentParent(value), /loaded repository root/);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("dependency bindings reject missing, extra, duplicate, traversal and rewritten actual bytes", async () => {
  const { evaluateCurrentParent } = await api();
  for (const change of [
    (v) => {
      v.currentBinding.dependencies.pop();
    },
    (v) => {
      v.currentBinding.dependencies.push(structuredClone(v.currentBinding.dependencies[0]));
    },
    (v) => {
      v.currentBinding.dependencies[0].sourceType = "UNKNOWN";
    },
    (v) => {
      v.currentBinding.dependencies[0].sourcePath = "../outside.py";
    },
    (v) => {
      v.currentBinding.dependencies[0].extra = true;
    },
    (v) => {
      v.currentBinding.dependencies[0].sourceSha256 = "0".repeat(64);
    },
    (v) => {
      v.documents.set(
        v.currentBinding.dependencies[0].sourcePath,
        Buffer.from("different loaded bytes\n"),
      );
    },
    (v) => {
      const ref = v.currentBinding.dependencies[0];
      const bytes = Buffer.from("fabricated current source\n");
      v.documents.set(ref.sourcePath, bytes);
      ref.sourceSha256 = sha(bytes);
      replaceRecord(v, paths.preparation, (d) => {
        d.producer.sha256 = ref.sourceSha256;
      });
    },
  ]) {
    const value = fixture();
    change(value);
    assert.throws(() => evaluateCurrentParent(value));
  }
});

test("typed dependency roles reject substitution with other admitted public source bytes", async () => {
  const { evaluateCurrentParent } = await api();
  for (const role of ["producer", "corpus-table", "producer-table"]) {
    const value = fixture();
    const [comparator, table] = value.currentBinding.dependencies;
    if (role === "producer")
      replaceRecord(value, paths.preparation, (d) => {
        d.producer.path = table.sourcePath;
        d.producer.sha256 = table.sourceSha256;
      });
    else if (role === "producer-table")
      replaceRecord(value, paths.preparation, (d) => {
        d.producer.tablePath = comparator.sourcePath;
      });
    else {
      replaceRecord(value, paths.observations, (d) => {
        d.corpora[0].table = comparator.sourcePath;
      });
      replaceRecord(value, paths.preparation, (d) => {
        d.producer.currentTableSha256 = comparator.sourceSha256;
      });
    }
    assert.throws(() => evaluateCurrentParent(value), /admitted dependency path/);
  }
});

test("dependency loader uses the caller root and refuses file and directory symlink escapes", async () => {
  const { evaluateCurrentParent, loadCurrentBinding } = await api();
  const value = fixture();
  const directory = mkdtempSync(resolve(tmpdir(), "fireemu-confined-dependencies-"));
  const outside = mkdtempSync(resolve(tmpdir(), "fireemu-external-dependencies-"));
  try {
    for (const [path, bytes] of value.documents) {
      const target = resolve(directory, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, bytes);
    }
    const documents = new Map();
    loadCurrentBinding(directory, value.parent, value.currentBinding, documents);
    assert.equal(evaluateCurrentParent({ ...value, root: directory, documents }).records.length, 2);
    for (const ref of value.currentBinding.dependencies) {
      const target = resolve(directory, ref.sourcePath);
      const sentinel = resolve(outside, "sentinel.py");
      writeFileSync(sentinel, value.documents.get(ref.sourcePath));
      rmSync(target);
      symlinkSync(sentinel, target);
      assert.throws(
        () => loadCurrentBinding(directory, value.parent, value.currentBinding, new Map()),
        /regular file/,
      );
      rmSync(target);
      writeFileSync(target, value.documents.get(ref.sourcePath));
    }
    const parent = dirname(resolve(directory, value.currentBinding.dependencies[0].sourcePath));
    rmSync(parent, { recursive: true });
    for (const ref of value.currentBinding.dependencies)
      writeFileSync(
        resolve(outside, ref.sourcePath.split("/").at(-1)),
        value.documents.get(ref.sourcePath),
      );
    symlinkSync(outside, parent, "dir");
    assert.throws(
      () => loadCurrentBinding(directory, value.parent, value.currentBinding, new Map()),
      /escaped repository/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
    rmSync(outside, { recursive: true, force: true });
  }
});

test("published typed dependency and nested preparation schemas reject every unexpected field permutation", async () => {
  const { evaluateCurrentParent } = await api();
  let seed = 0x13b39701;
  for (let i = 0; i < 64; i++) {
    const value = fixture();
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    if (seed & 1) value.currentBinding.dependencies.reverse();
    const result = evaluateCurrentParent(value);
    assert.equal(result.eligible, false);
    assert.deepEqual(
      result.dependencies,
      evaluateCurrentParent(fixture()).dependencies,
      "dependency ordering must not change the report",
    );
    const level = seed % 4;
    replaceRecord(value, paths.preparation, (d) => {
      const target = [d, d.producer, d.plannedReplays[seed % 4], d.corpora[0]][level];
      target[`unknown_${i}`] = { status: "VERIFIED", complete: true };
    });
    assert.throws(() => evaluateCurrentParent(value), /closed fields/);
  }
});

for (const [label, change] of [
  [
    "unknown top-level receipt",
    (d) => {
      d.futureVerifiedReceipt = { kind: "UNKNOWN", complete: true };
    },
  ],
  [
    "unknown producer field",
    (d) => {
      d.producer.approval = "VERIFIED";
    },
  ],
  [
    "unknown replay field",
    (d) => {
      d.plannedReplays[0].complete = true;
    },
  ],
  [
    "unknown corpus field",
    (d) => {
      d.corpora[0].finalReview = "APPROVED";
    },
  ],
  [
    "omitted boundary field",
    (d) => {
      delete d.remainingBoundaries;
    },
  ],
  [
    "altered provenance",
    (d) => {
      d.preparationBaseCommit = "0".repeat(40);
    },
  ],
]) {
  test(`published preparation closed schema rejects ${label}`, async () => {
    const value = fixture();
    replaceRecord(value, paths.preparation, change);
    const { evaluateCurrentParent } = await api();
    assert.throws(() => evaluateCurrentParent(value), /closed fields|preparation provenance/);
  });
}

test("current facts preserve every original obligation and profile gate", async () => {
  const value = fixture();
  const result = (await api()).evaluateCurrentParent(value);
  assert.equal(result.facets.length, value.originalInventory.conditions.length + 1);
  assert.ok(result.facets.some((facet) => facet.kind === "EMULATOR_PROFILE_CONTRACT"));
  const rules = (await api()).evaluateCurrentParent(fixture("STORAGE-RULES"));
  assert.ok(rules.facets.some((facet) => facet.kind === "FINAL_PRODUCT"));
  assert.ok(rules.facets.some((facet) => facet.kind === "CLEAN_REVIEW"));
  assert.ok(rules.facets.some((facet) => facet.kind === "OFFICIAL_COMPARISON"));
});

test("current scope and profile declarations cannot discard the original contract", async () => {
  const { evaluateCurrentParent } = await api();
  for (const change of [
    (d) => {
      d.scopeDecisions.pop();
    },
    (d) => {
      d.profileComparison.note = "official-only; discard the profile contract";
    },
    (d) => {
      d.freezeState = "PROPOSED";
    },
  ]) {
    const value = fixture();
    change(value.currentInventory);
    const bytes = Buffer.from(JSON.stringify(value.currentInventory));
    value.documents.set(value.currentBinding.inventoryPath, bytes);
    value.currentBinding.inventorySha256 = sha(bytes);
    assert.throws(() => evaluateCurrentParent(value));
  }
});

test("declared VERIFIED conditions and review strings do not replace actual current proof", async () => {
  const value = fixture();
  value.currentInventory.parentStatus = "COMPAT_VERIFIED";
  value.currentInventory.closureReview.decision = "APPROVED";
  for (const condition of value.currentInventory.conditions) condition.status = "VERIFIED";
  const bytes = Buffer.from(JSON.stringify(value.currentInventory));
  value.documents.set(value.currentBinding.inventoryPath, bytes);
  value.currentBinding.inventorySha256 = sha(bytes);
  const { evaluateCurrentParent } = await api();
  assert.throws(() => evaluateCurrentParent(value), /no complete actual evidence/);
});

test("actual current declarations retain original representative gRPC and case coverage", async () => {
  const { evaluateCurrentParent } = await api();
  for (const parent of ["FS-TRANSACTION", "SCHEDULED-FUNCTIONS"]) {
    const value = fixture(parent);
    if (parent === "FS-TRANSACTION")
      value.currentInventory.conditions.find(
        (condition) => condition.observation?.representativeGrpc,
      ).observation.representativeGrpc = "Excluded without native evidence";
    else value.currentInventory.conditions.find((condition) => condition.cases?.length).cases.pop();
    const bytes = Buffer.from(JSON.stringify(value.currentInventory));
    value.documents.set(value.currentBinding.inventoryPath, bytes);
    value.currentBinding.inventorySha256 = sha(bytes);
    assert.throws(() => evaluateCurrentParent(value), /original/);
  }
});

test("an admitted record path remains exact even when replacement bytes are present", async () => {
  const { evaluateCurrentParent } = await api();
  const value = fixture();
  const ref = value.currentBinding.records[0];
  const alternate = "spec/compatibility/broad-runs/unreviewed-copy.json";
  value.documents.set(alternate, value.documents.get(ref.recordPath));
  ref.recordPath = alternate;
  assert.throws(() => evaluateCurrentParent(value), /admitted public producer type/);
});

test("actual loader reads current public bytes and refuses symlink substitution", async () => {
  const { loadCurrentBinding } = await api();
  const value = fixture();
  const directory = mkdtempSync(resolve(tmpdir(), "fireemu-production-evidence-"));
  try {
    for (const [path, bytes] of value.documents) {
      const target = resolve(directory, path);
      mkdirSync(dirname(target), { recursive: true });
      writeFileSync(target, bytes);
    }
    const loaded = new Map();
    loadCurrentBinding(directory, value.parent, value.currentBinding, loaded);
    assert.deepEqual(
      loaded,
      new Map(
        [
          value.currentBinding.inventoryPath,
          ...value.currentBinding.records.map((ref) => ref.recordPath),
          ...value.currentBinding.dependencies.map((ref) => ref.sourcePath),
        ].map((path) => [path, value.documents.get(path)]),
      ),
    );
    const path = resolve(directory, value.currentBinding.records[0].recordPath);
    const replacement = resolve(directory, "unreviewed.json");
    writeFileSync(replacement, loaded.get(value.currentBinding.records[0].recordPath));
    rmSync(path);
    symlinkSync(replacement, path);
    assert.throws(
      () => loadCurrentBinding(directory, value.parent, value.currentBinding, new Map()),
      /regular file/,
    );
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("seeded reference permutations preserve actual coverage and duplicate insertion is refused", async () => {
  const { evaluateCurrentParent } = await api();
  let seed = 0x21c09566;
  for (let i = 0; i < 64; i++) {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    const value = fixture();
    if (seed & 1) value.currentBinding.records.reverse();
    const result = evaluateCurrentParent(value);
    assert.equal(result.eligible, false);
    assert.equal(result.records.find((r) => r.nativeRecordings)?.nativeRecordings, 2);
    value.currentBinding.records.push(structuredClone(value.currentBinding.records[seed % 2]));
    assert.throws(() => evaluateCurrentParent(value), /duplicate/);
  }
});
