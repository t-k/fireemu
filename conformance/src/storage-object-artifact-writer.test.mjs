import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, lstatSync, rmSync, realpathSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { writeFileSync, existsSync, mkdirSync } from "node:fs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import * as standalone from "./storage-object/production-standalone-fail-stop.mjs";

const api = await import("./storage-object/production-artifact-writer.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const resources = {
  projectNumber: "123456789012",
  apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
  rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
};
const hash = (value) => createHash("sha256").update(value).digest("hex");
const operation = (recording) => `r${recording}/control/${"a".repeat(64)}`;
const kinds = [
  "intent",
  "journal",
  "control-proof",
  "owner-proof",
  "auth-proof",
  "rules-proof",
  "configuration-change",
  "ledger",
  "manifest",
  "export",
  "error",
];
function fixture(action) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-artifact-writer-")));
  const registry = createProductionSecretRegistry({
    maxValues: 128,
    maxUtf8Bytes: 131072,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry });
  let writer;
  try {
    const boundary = createProductionStandaloneFailStop({ directory, profile });
    assert.equal(typeof api.createProductionArtifactWriter, "function");
    writer = api.createProductionArtifactWriter({ directory, profile, boundary });
    return action({ directory, registry, profile, boundary, writer });
  } finally {
    writer?.close();
    registry.close();
    rmSync(directory, { recursive: true });
  }
}
for (const kind of kinds)
  test(`${kind} is privately persisted in both recordings and returns an original durable receipt`, () => {
    fixture(({ directory, registry, writer }) => {
      const secret = "SYNTHETIC_WRITER_SECRET_+/opaque";
      registry.register(secret);
      for (const recording of [1, 2])
        for (const copy of [
          secret,
          encodeURIComponent(secret),
          Buffer.from(secret).toString("base64"),
          Buffer.from(secret).toString("base64url"),
        ]) {
          const value = {
            recording,
            status: 200,
            body: { contentDisposition: copy },
            namespaceEmpty: true,
          };
          const before = JSON.stringify(value),
            operationId = operation(recording);
          const receipt = writer.write({ recording, operationId, kind, value });
          assert.equal(
            api.isProductionArtifactReceipt(receipt, { writer, recording, operationId, kind }),
            true,
          );
          for (const invalid of [{ ...receipt }, new Proxy(receipt, {}), null])
            assert.equal(
              api.isProductionArtifactReceipt(invalid, { writer, recording, operationId, kind }),
              false,
            );
          assert.equal(
            api.isProductionArtifactReceipt(receipt, {
              writer: { ...writer },
              recording,
              operationId,
              kind,
            }),
            false,
          );
          assert.equal(
            api.isProductionArtifactReceipt(receipt, {
              writer,
              recording: recording === 1 ? 2 : 1,
              operationId,
              kind,
            }),
            false,
          );
          assert.equal(
            api.isProductionArtifactReceipt(receipt, {
              writer,
              recording,
              operationId: operationId.replace(/a$/, "b"),
              kind,
            }),
            false,
          );
          const bytes = readFileSync(join(directory, receipt.file));
          assert.equal(hash(bytes), receipt.sha256);
          assert.equal(bytes.length, receipt.byteLength);
          assert.equal(lstatSync(join(directory, receipt.file)).mode & 0o777, 0o600);
          const saved = JSON.parse(bytes);
          assert.equal(saved.data.status, 200);
          assert.equal(saved.data.namespaceEmpty, true);
          for (const form of [
            secret,
            encodeURIComponent(secret),
            Buffer.from(secret).toString("base64"),
            Buffer.from(secret).toString("base64url"),
          ])
            assert.equal(bytes.includes(Buffer.from(form)), false);
          assert.equal(JSON.stringify(value), before);
        }
      assert.equal(readdirSync(directory).length, 8);
    });
  });
test("configuration binds original profile and boundary to the same owned directory without reading hooks", () => {
  fixture(({ directory, registry, profile, boundary }) => {
    const foreign = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-artifact-foreign-")));
    let hooks = 0;
    try {
      for (const supplied of [
        { directory, profile: { ...profile }, boundary },
        { directory, profile, boundary: { ...boundary } },
        { directory, profile, boundary: createProductionStandaloneFailStop({ directory }) },
        { directory: foreign, profile, boundary },
        { directory, profile, boundary, maxArtifacts: 1 },
        {
          directory,
          profile,
          get boundary() {
            hooks++;
            return boundary;
          },
        },
      ])
        assert.throws(
          () => api.createProductionArtifactWriter(supplied),
          /invalid production artifact writer/,
        );
      assert.equal(hooks, 0);
      assert.equal(registry.snapshot().closed, false);
      assert.deepEqual(readdirSync(directory), []);
      assert.deepEqual(readdirSync(foreign), []);
    } finally {
      rmSync(foreign, { recursive: true });
    }
  });
});
test("receipt proof rejects unknown or accessor fields without caller coercion", () => {
  fixture(({ writer }) => {
    const recording = 1,
      operationId = operation(recording),
      kind = "journal";
    const receipt = writer.write({ recording, operationId, kind, value: { status: 200 } });
    let hooks = 0;
    for (const proof of [
      { writer, recording, operationId, kind, extra: true },
      {
        get writer() {
          hooks++;
          return writer;
        },
        recording,
        operationId,
        kind,
      },
      new Proxy(
        { writer, recording, operationId, kind },
        {
          get() {
            hooks++;
            throw new Error();
          },
        },
      ),
    ])
      assert.equal(api.isProductionArtifactReceipt(receipt, proof), false);
    assert.equal(hooks, 0);
  });
});

for (const recording of [1, 2])
  test(`recording ${recording} persists exactly the checked compact JSON without adding a secret newline`, () => {
    fixture(({ directory, registry, writer }) => {
      registry.register(String.fromCharCode(10));
      const operationId = operation(recording),
        kind = "journal";
      const receipt = writer.write({ recording, operationId, kind, value: { status: 200 } });
      const bytes = readFileSync(join(directory, receipt.file));
      assert.equal(registry.openScan().hasSecretCopy(bytes.toString("utf8")), false);
      assert.equal(bytes.toString("utf8"), JSON.stringify(JSON.parse(bytes)));
      assert.equal(
        api.isProductionArtifactReceipt(receipt, { writer, recording, operationId, kind }),
        true,
      );
    });
  });

function child(fault, recording) {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-artifact-child-")));
  const directory = join(base, "owned"),
    marker = "FOREIGN_SYNTHETIC_FIXED";
  const originalDirectory = new URL("./storage-object/", import.meta.url);
  let moduleDirectory = originalDirectory;
  const moduleURL = (name) => new URL(`${name}.mjs`, moduleDirectory).href;
  if (fault === "counter-bound") {
    const modules = new Map();
    const bind = (url) => {
      if (modules.has(url.href)) return;
      assert.equal(url.href.startsWith(originalDirectory.href), true);
      const source = readFileSync(url, "utf8");
      modules.set(url.href, source);
      for (const match of source.matchAll(/(?:from\s*|import\s*\()\s*["'](\.[^"']+)["']/g))
        bind(new URL(match[1], url));
    };
    bind(new URL("production-artifact-writer.mjs", originalDirectory));
    // Every copied module uses one shared private identity closure.
    const copyDirectory = join(base, "counter-source");
    mkdirSync(copyDirectory, { mode: 0o700 });
    for (const [url, source] of modules) {
      const relative = fileURLToPath(url).slice(fileURLToPath(originalDirectory).length);
      const target = join(copyDirectory, relative);
      mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
      writeFileSync(target, source, { mode: 0o600 });
    }
    moduleDirectory = pathToFileURL(copyDirectory + "/");
    const source = modules.get(new URL("production-artifact-writer.mjs", originalDirectory).href);
    assert.equal(source.split("let sequence = 0,").length, 2);
    writeFileSync(
      new URL("production-artifact-writer.mjs", moduleDirectory),
      source.replace("let sequence = 0,", "let sequence = MAX_ARTIFACT_FILES - 1,"),
      { mode: 0o600 },
    );
  }
  const importedWriter = moduleURL("production-artifact-writer");
  const script = `
import fs from "node:fs";
import { createHash } from "node:crypto";
import { syncBuiltinESMExports } from "node:module";
import { createProductionArtifactWriter } from ${JSON.stringify(importedWriter)};
import { createProductionArtifactProfile } from ${JSON.stringify(moduleURL("production-artifact-policy"))};
import { createProductionSecretRegistry } from ${JSON.stringify(moduleURL("production-secret-registry"))};
import { createProductionStandaloneFailStop } from ${JSON.stringify(moduleURL("production-standalone-fail-stop"))};
import { buildProductionStage3DraftPlan } from ${JSON.stringify(moduleURL("stage3-plan"))};
const directory = ${JSON.stringify(directory)}, fault = ${JSON.stringify(fault)}, recording = ${recording};
const marker = ${JSON.stringify(marker)}, secret = "SYNTHETIC_CHILD_WRITER_SECRET_+/opaque";
fs.mkdirSync(directory, { mode: 0o700 });
fs.writeFileSync(directory + "/started.lock", "SYNTHETIC_STARTED_LEASE", { mode: 0o600 });
const registry = createProductionSecretRegistry({ maxValues: 128, maxUtf8Bytes: 131072, maxIndexNodes: 200000, maxScanCodeUnits: fault === "scan-uncheckable" ? 1 : 16777216 });
registry.register(secret);
const digest = value => createHash("sha256").update(value).digest("hex");
if (fault === "generated-type") registry.register("SHA256_OF_ORIGINAL_BYTES");
if (fault === "generated-data") registry.register(digest(secret));
if (fault === "generated-source") registry.register(digest(JSON.stringify({ status: 200, body: { contentDisposition: secret } })));
if (fault === "fatal-metadata") registry.register("NEEDS_RECOVERY");
const plan = buildProductionStage3DraftPlan({ projectId: "example-project", bucket: "example.appspot.com", runIds: ["recordone", "recordtwo"] });
const resources = { projectNumber: "123456789012", apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key", rulesetResource: "projects/example-project/rulesets/fixture-ruleset" };
const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry });
const boundary = createProductionStandaloneFailStop({ directory, profile });
const writer = createProductionArtifactWriter({ directory, profile, boundary });
const file = directory + "/artifact-000001-r" + recording + ".json";
if (fault === "exclusive") fs.writeFileSync(file, marker, { mode: 0o600 });
if (fault === "symlink") { fs.writeFileSync(directory + "/foreign", marker, { mode: 0o600 }); fs.symlinkSync(directory + "/foreign", file); }
if (fault === "closed") writer.close();
if (fault === "registry-closed") registry.close();
if (fault === "directory-before") { fs.renameSync(directory, directory + "-old"); fs.mkdirSync(directory, { mode: 0o700 }); }
const original = Object.fromEntries(["openSync", "writeSync", "fsyncSync", "closeSync", "lstatSync"].map(name => [name, fs[name]]));
let artifactFd = null, directoryFd = null, armed = true, writes = 0;
fs.openSync = function(path, flags, ...args) {
  const fd = original.openSync.call(fs, path, flags, ...args);
  if (String(path).includes("/artifact-")) artifactFd = fd;
  if (path === directory && artifactFd === null) directoryFd = fd;
  return fd;
};
fs.writeSync = function(fd, buffer, offset, length, ...args) {
  if (fd === artifactFd) {
    writes++;
    if (fault === "short") return original.writeSync.call(fs, fd, buffer, offset, Math.min(length, 7), ...args);
    if (armed && ["write-throw", "fatal-metadata", "zero", "negative", "excess", "nan"].includes(fault)) {
      armed = false;
      if (["write-throw", "fatal-metadata"].includes(fault)) throw new Error(secret);
      return fault === "zero" ? 0 : fault === "negative" ? -1 : fault === "excess" ? length + 1 : NaN;
    }
  }
  return original.writeSync.call(fs, fd, buffer, offset, length, ...args);
};
fs.fsyncSync = function(fd) {
  if (armed && fd === artifactFd) {
    if (fault === "file-fsync") { armed = false; throw new Error(secret); }
    if (fault === "hardlink") { armed = false; fs.linkSync(file, directory + "/artifact-link"); }
    if (fault === "mode") { armed = false; fs.chmodSync(file, 0o644); }
    if (fault === "path-replace") { armed = false; fs.unlinkSync(file); fs.writeFileSync(file, marker, { mode: 0o600 }); }
    if (fault === "path-replace-same-size") { armed = false; const length = fs.fstatSync(fd).size; fs.renameSync(file, directory + "/artifact-original"); fs.writeFileSync(file, marker.padEnd(length, " "), { mode: 0o600 }); }
  }
  if (armed && fd === directoryFd) {
    if (fault === "directory-fsync") { armed = false; throw new Error(secret); }
    if (fault === "file-during-directory-fsync") { armed = false; const length = fs.fstatSync(artifactFd).size; fs.renameSync(file, directory + "/artifact-original"); fs.writeFileSync(file, marker.padEnd(length, " "), { mode: 0o600 }); }
    if (fault === "directory-during-fsync") { armed = false; fs.renameSync(directory, directory + "-old"); fs.mkdirSync(directory, { mode: 0o700 }); fs.renameSync(directory + "-old" + file.slice(directory.length), file); }
  }
  return original.fsyncSync.call(fs, fd);
};
fs.lstatSync = function(path, ...args) {
  if (armed && fault === "late-mode" && path === file) { armed = false; fs.chmodSync(file, 0o644); }
  if (armed && fault === "late-hardlink" && path === file) { armed = false; fs.linkSync(file, directory + "/artifact-link"); }
  if (armed && fault === "late-size" && path === file) { armed = false; fs.appendFileSync(file, "FOREIGN_SYNTHETIC_FIXED"); }
  return original.lstatSync.call(fs, path, ...args);
};
fs.closeSync = function(fd) {
  const target = armed && ((fault === "file-close" && fd === artifactFd) || (fault === "directory-close" && fd === directoryFd));
  if (fd === artifactFd) artifactFd = null;
  if (fd === directoryFd) directoryFd = null;
  original.closeSync.call(fs, fd);
  if (target) { armed = false; throw new Error(secret); }
};
syncBuiltinESMExports();
const value = fault === "privacy-unknown" ? { metadata: { undeclared: secret } } : fault === "error-object" ? new Error(secret) : { status: 200, body: { contentDisposition: secret } };
const row = { recording, operationId: "r" + recording + "/control/" + "a".repeat(64), kind: "journal", value };
const receipt = writer.write(row);
if (fault === "counter-bound") writer.write(row);
fs.writeFileSync(${JSON.stringify(join(base, "after.json"))}, JSON.stringify({ writes, receipt }), { mode: 0o600 });
`;
  const scriptPath = join(base, "child.mjs");
  writeFileSync(scriptPath, script, { mode: 0o600 });
  try {
    const result = spawnSync(process.execPath, [scriptPath], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR },
      timeout: 5000,
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    if (fault === "short") {
      assert.equal(result.status, 0);
      const after = JSON.parse(readFileSync(join(base, "after.json")));
      assert.ok(after.writes > 1);
      const bytes = readFileSync(join(directory, after.receipt.file));
      assert.equal(hash(bytes), after.receipt.sha256);
    } else {
      assert.equal(result.status, 2);
      assert.equal(existsSync(join(base, "after.json")), false);
      assert.equal(
        existsSync(join(directory, "started.lock")) ||
          existsSync(join(directory + "-old", "started.lock")),
        true,
      );
      if (
        ![
          "directory-before",
          "directory-during-fsync",
          "privacy-unknown",
          "error-object",
          "registry-closed",
          "generated-type",
          "generated-data",
          "generated-source",
          "fatal-metadata",
          "scan-uncheckable",
        ].includes(fault)
      ) {
        const failure = JSON.parse(readFileSync(join(directory, `fatal-r${recording}.json`)));
        assert.deepEqual(Object.keys(failure), [
          "type",
          "state",
          "recording",
          "operationIdSha256",
          "reason",
          "providerKind",
        ]);
        assert.equal(failure.state, "NEEDS_RECOVERY");
        assert.equal(failure.reason, "PERSISTENCE_UNCERTAIN");
        assert.equal(failure.recording, recording);
      }
      if (["exclusive", "path-replace"].includes(fault))
        assert.equal(
          readFileSync(join(directory, `artifact-000001-r${recording}.json`), "utf8"),
          marker,
        );
      if (["path-replace-same-size", "file-during-directory-fsync"].includes(fault))
        assert.equal(
          readFileSync(join(directory, `artifact-000001-r${recording}.json`), "utf8"),
          marker.padEnd(readFileSync(join(directory, "artifact-original")).length, " "),
        );
      if (fault === "symlink")
        assert.equal(readFileSync(join(directory, "foreign"), "utf8"), marker);
      if (["privacy-unknown", "error-object"].includes(fault)) {
        const saved = JSON.parse(
          readFileSync(join(directory, `artifact-000001-r${recording}.json`)),
        );
        assert.equal(saved.mode, "COMMITMENT_ONLY");
        assert.equal(saved.taskSecretStatus, "UNAVAILABLE");
        assert.equal(saved.data, null);
      }
      if (
        [
          "privacy-unknown",
          "error-object",
          "registry-closed",
          "generated-type",
          "generated-data",
          "generated-source",
          "fatal-metadata",
          "scan-uncheckable",
        ].includes(fault)
      ) {
        assert.equal(existsSync(join(directory, `fatal-r${recording}.json`)), false);
        const audit = JSON.parse(readFileSync(join(directory, `privacy-r${recording}.json`)));
        assert.deepEqual(Object.keys(audit), ["reason", "timestamp", "runId"]);
        assert.equal(
          audit.reason,
          ["generated-type", "generated-data", "generated-source", "fatal-metadata"].includes(fault)
            ? "artifact-withheld-privacy"
            : "artifact-uncheckable",
        );
        assert.match(audit.timestamp, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
        assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
        if (
          [
            "registry-closed",
            "generated-type",
            "generated-data",
            "generated-source",
            "scan-uncheckable",
          ].includes(fault)
        )
          assert.equal(existsSync(join(directory, `artifact-000001-r${recording}.json`)), false);
      }
      if (fault === "counter-bound")
        assert.equal(existsSync(join(directory, `artifact-097024-r${recording}.json`)), true);
    }
  } finally {
    rmSync(base, { recursive: true });
  }
}
for (const fault of [
  "short",
  "write-throw",
  "zero",
  "negative",
  "excess",
  "nan",
  "file-fsync",
  "directory-fsync",
  "file-close",
  "directory-close",
  "hardlink",
  "mode",
  "late-mode",
  "late-hardlink",
  "late-size",
  "path-replace",
  "path-replace-same-size",
  "exclusive",
  "symlink",
  "directory-before",
  "directory-during-fsync",
  "file-during-directory-fsync",
  "privacy-unknown",
  "error-object",
  "generated-type",
  "generated-data",
  "generated-source",
  "fatal-metadata",
  "scan-uncheckable",
  "registry-closed",
  "closed",
  "counter-bound",
])
  for (const recording of [1, 2])
    test(`${fault} preserves the owned persistence boundary in recording ${recording}`, () =>
      child(fault, recording));

test("invalid write contexts fail with fixed metadata without input hooks or file creation", () => {
  fixture(({ writer, directory }) => {
    let hooks = 0;
    for (const row of [
      { recording: 3, operationId: operation(1), kind: "journal", value: {} },
      { recording: 1, operationId: operation(2), kind: "journal", value: {} },
      { recording: 1, operationId: "unbounded/source", kind: "journal", value: {} },
      {
        recording: 1,
        operationId: operation(1),
        kind: "journal",
        get value() {
          hooks++;
          return {};
        },
      },
      new Proxy(
        {},
        {
          get() {
            hooks++;
            throw new Error();
          },
        },
      ),
    ])
      assert.throws(
        () => writer.write(row),
        /invalid production artifact context|invalid capture input/,
      );
    assert.equal(hooks, 0);
    assert.deepEqual(readdirSync(directory), []);
  });
});

test("a bound original profile is required for audited standalone privacy failures", () => {
  fixture(({ directory, profile, boundary }) => {
    assert.equal(typeof standalone.productionStandaloneUsesArtifactProfile, "function");
    assert.equal(standalone.productionStandaloneUsesArtifactProfile(boundary, profile), true);
    assert.equal(
      standalone.productionStandaloneUsesArtifactProfile({ ...boundary }, profile),
      false,
    );
    assert.equal(
      standalone.productionStandaloneUsesArtifactProfile(boundary, { ...profile }),
      false,
    );
    const foreignBoundary = standalone.createProductionStandaloneFailStop({ directory, profile });
    assert.throws(
      () => api.createProductionArtifactWriter({ directory, profile, boundary: foreignBoundary }),
      /invalid production artifact inventory/,
    );
    const writer = api.createProductionArtifactWriter({ directory, profile, boundary });
    writer.close();
  });
});
