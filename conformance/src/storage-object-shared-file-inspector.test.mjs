import assert from "node:assert/strict";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
const api = await import("./storage-object/production-shared-file-inspector.mjs").catch((error) => {
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
const limits = {
  maxValues: 81,
  maxUtf8Bytes: 65536,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
function fixture(action) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-reader-")));
  fs.chmodSync(root, 0o700);
  const directory = join(root, "owned"),
    shared = join(root, "shared");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(shared, { mode: 0o700 });
  const registry = createProductionSecretRegistry(limits),
    profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    boundary = createProductionStandaloneFailStop({ directory, profile });
  const paths = [
    { kind: "owner-ledger", path: join(shared, "owner-decisions.md") },
    { kind: "sandbox-ledger", path: join(shared, "sandbox-oracles.md") },
  ];
  const contents = [
    Array.from({ length: 25 }, () => "needle").join("\n"),
    "safe\nalpha\nbeta\nend",
  ];
  for (let i = 0; i < paths.length; i++)
    fs.writeFileSync(paths[i].path, contents[i], { mode: 0o600 });
  try {
    assert.equal(typeof api.createProductionSharedFileInspector, "function");
    return action({ root, directory, shared, paths, contents, registry, profile, boundary });
  } finally {
    registry.close();
    fs.rmSync(root, { recursive: true });
  }
}
test("a shared inspection returns bounded original path-line reports without changing either shared inode or bytes", () =>
  fixture(({ directory, paths, contents, registry, profile, boundary }) => {
    registry.register("needle");
    registry.register("alpha\nbeta");
    const before = paths.map((row) => fs.lstatSync(row.path));
    const inspector = api.createProductionSharedFileInspector({
      directory,
      profile,
      boundary,
      files: paths,
    });
    const receipt = api.inspectProductionSharedFiles(inspector);
    const bytes = api.copyProductionSharedInspectionReportBytes(receipt, inspector),
      report = JSON.parse(bytes);
    assert.deepEqual(report, {
      type: "production-shared-privacy-report",
      files: [
        {
          path: paths[0].path,
          lineNumbers: Array.from({ length: 20 }, (_, i) => i + 1),
          matchedLineCount: 25,
          truncated: true,
        },
        { path: paths[1].path, lineNumbers: [2, 3], matchedLineCount: 2, truncated: false },
      ],
    });
    for (let i = 0; i < paths.length; i++) {
      assert.equal(fs.readFileSync(paths[i].path, "utf8"), contents[i]);
      assert.equal(fs.lstatSync(paths[i].path).ino, before[i].ino);
    }
    assert.equal(api.copyProductionSharedInspectionReportBytes({ ...receipt }, inspector), null);
    assert.equal(api.copyProductionSharedInspectionReportBytes(receipt, { ...inspector }), null);
    bytes.fill(0);
    assert.equal(api.copyProductionSharedInspectionReportBytes(receipt, inspector).at(0), 123);
  }));

for (const [name, secret, text, line] of [
  ["leading BOM credential", "\uFEFFsynthetic-bom-credential", "\uFEFFsynthetic-bom-credential", 1],
  ["BOM-only credential", "\uFEFF", "\uFEFF", 1],
  [
    "nonleading BOM credential",
    "\uFEFFsynthetic-bom-credential",
    "safe\n\uFEFFsynthetic-bom-credential",
    2,
  ],
]) {
  test(`a shared inspection preserves original UTF-8 bytes for ${name}`, () =>
    fixture(({ directory, paths, registry, profile, boundary }) => {
      const path = paths[0].path;
      fs.writeFileSync(path, text);
      const original = fs.readFileSync(path),
        before = fs.lstatSync(path);
      registry.register(secret);
      assert.equal(registry.openScan().hasSecretCopy(original.toString("utf8")), true);
      assert.ok(
        registry.openScan().findSecretCopyLines(original.toString("utf8")).matchedLineCount > 0,
      );
      const inspector = api.createProductionSharedFileInspector({
        directory,
        profile,
        boundary,
        files: [paths[0]],
      });
      const receipt = api.inspectProductionSharedFiles(inspector);
      const report = JSON.parse(api.copyProductionSharedInspectionReportBytes(receipt, inspector));
      assert.deepEqual(fs.readFileSync(path), original);
      assert.equal(fs.lstatSync(path).ino, before.ino);
      assert.equal(receipt.hasMatches, true, "a leading BOM remains part of the registered value");
      assert.deepEqual(report.files, [
        { path, lineNumbers: [line], matchedLineCount: 1, truncated: false },
      ]);
    }));
}

test("a later successful inspection revokes the earlier report receipt", () =>
  fixture(({ directory, paths, registry, profile, boundary }) => {
    registry.register("needle");
    const inspector = api.createProductionSharedFileInspector({
      directory,
      profile,
      boundary,
      files: paths,
    });
    const before = api.inspectProductionSharedFiles(inspector);
    assert.ok(api.copyProductionSharedInspectionReportBytes(before, inspector));
    const after = api.inspectProductionSharedFiles(inspector);
    assert.equal(api.copyProductionSharedInspectionReportBytes(before, inspector), null);
    assert.ok(api.copyProductionSharedInspectionReportBytes(after, inspector));
  }));
test("shared factories reject unknown fields, cloned capabilities, excessive paths and hooks", () =>
  fixture(({ directory, paths, profile, boundary }) => {
    const base = { directory, profile, boundary, files: paths };
    for (const input of [
      { ...base, profile: { ...profile } },
      { ...base, boundary: { ...boundary } },
      { ...base, extra: true },
      { ...base, files: [] },
      { ...base, files: [...paths, ...paths, ...paths] },
      { ...base, files: [paths[0], paths[0]] },
      { ...base, files: [{ ...paths[0], kind: "payload" }] },
      { ...base, files: [{ ...paths[0], maxBytes: 1 }] },
    ])
      assert.throws(
        () => api.createProductionSharedFileInspector(input),
        /invalid production shared file inspector/,
      );
    let hooks = 0;
    const input = { ...base };
    Object.defineProperty(input, "files", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => api.createProductionSharedFileInspector(input),
      /invalid production shared file inspector/,
    );
    assert.equal(hooks, 0);
  }));
test("shared read and transformed scan work accumulates across inspections without reset", () =>
  fixture(({ directory, paths, registry, profile, boundary }) => {
    registry.register("needle");
    const inspector = api.createProductionSharedFileInspector({
      directory,
      profile,
      boundary,
      files: paths,
    });
    let successes = 0,
      failed = false;
    for (let i = 0; i < 10000; i++) {
      try {
        api.inspectProductionSharedFiles(inspector);
        successes++;
      } catch (error) {
        assert.equal(error.message, "production shared files uncheckable");
        failed = true;
        break;
      }
    }
    assert.equal(failed, true);
    assert.ok(successes > 1);
    assert.throws(
      () => api.inspectProductionSharedFiles(inspector),
      /production shared files uncheckable/,
    );
  }));

function isolatedFault(mode) {
  const code = `
import assert from "node:assert/strict";
import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildProductionStage3DraftPlan } from ${JSON.stringify(new URL("./storage-object/stage3-plan.mjs", import.meta.url).href)};
import { createProductionSecretRegistry } from ${JSON.stringify(new URL("./storage-object/production-secret-registry.mjs", import.meta.url).href)};
import { createProductionArtifactProfile } from ${JSON.stringify(new URL("./storage-object/production-artifact-policy.mjs", import.meta.url).href)};
import { createProductionStandaloneFailStop } from ${JSON.stringify(new URL("./storage-object/production-standalone-fail-stop.mjs", import.meta.url).href)};
const mode = ${JSON.stringify(mode)};
const plan = ${JSON.stringify(plan)}, resources = ${JSON.stringify(resources)}, limits = ${JSON.stringify(limits)};
const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-fault-")));
fs.chmodSync(root, 0o700);
const directory = join(root, "owned"), shared = join(root, "shared"), path = join(shared, "ledger.md");
fs.mkdirSync(directory, {mode:0o700}); fs.mkdirSync(shared, {mode:0o700});
fs.writeFileSync(path, "needle\\nsecond", {mode:0o600});
const registry = createProductionSecretRegistry(limits);
registry.register("needle");
const profile = createProductionArtifactProfile({plan,resources,secretRegistry:registry});
const boundary = createProductionStandaloneFailStop({directory,profile});
const originals = Object.fromEntries(["openSync","readSync","closeSync"].map(k => [k,fs[k]]));
let inspector, api, fired=false, armed=false, fileFd, opens=[], reads=0, fileCloses=0;
fs.openSync = function(p,flags,...rest) {
 const fd=originals.openSync.call(this,p,flags,...rest);
 if (p===path && typeof flags==="number" && !(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR))) {fileFd=fd; opens.push(flags);}
 return fd;
};
fs.readSync = function(fd,buffer,offset,length,position) {
 if(fd!==fileFd) return originals.readSync.call(this,fd,buffer,offset,length,position);
 reads++;
 if(armed && mode==="read-zero") return 0;
 if(armed && mode==="read-overcount" && position===0) return length+1;
 if(armed && mode==="read-fraction") return 0.5;
 if(armed && mode==="eof-extra" && length===1 && position===fs.lstatSync(path).size) return 1;
 if(armed && !fired && mode==="append-during-read") {fired=true;fs.appendFileSync(path,"x");}
 if(armed && !fired && mode==="tamper-during-read") {fired=true;fs.writeFileSync(path,"needlf\\nsecond");}
 if(armed && !fired && mode==="replace-during-read") {fired=true;fs.renameSync(path,path+".original");fs.writeFileSync(path,"needle\\nsecond",{mode:0o600});}
 if(armed && !fired && mode==="reentrant") {fired=true;assert.throws(()=>api.inspectProductionSharedFiles(inspector),/production shared files uncheckable/);}
 return originals.readSync.call(this,fd,buffer,offset,mode==="short-read"?Math.min(3,length):length,position);
};
fs.closeSync = function(fd) {
 originals.closeSync.call(this,fd);
 if(fd===fileFd) {fileCloses++; if(armed && mode==="close-failure") throw new Error("fixture close failed");}
};
syncBuiltinESMExports();
try {
 api = await import(${JSON.stringify(new URL("./storage-object/production-shared-file-inspector.mjs", import.meta.url).href)});
 inspector=api.createProductionSharedFileInspector({directory,profile,boundary,files:[{kind:"owner-ledger",path}]});
 const previous=api.inspectProductionSharedFiles(inspector);
 armed=true;opens=[];reads=0;fileCloses=0;
 // Reset the injected behavior only after the baseline receipt for failure-revocation cases.
 if(armed && mode==="replace-before") {fs.renameSync(path,path+".original");fs.writeFileSync(path,"needle\\nsecond",{mode:0o600});}
 if(armed && mode==="symlink-before") {fs.renameSync(path,path+".original");fs.symlinkSync(path+".original",path);}
 if(armed && mode==="hardlink-before") fs.linkSync(path,path+".extra");
 if(armed && mode==="file-mode") fs.chmodSync(path,0o640);
 if(armed && mode==="parent-mode") fs.chmodSync(shared,0o750);
 if(armed && mode==="parent-replace") {fs.renameSync(shared,shared+".original");fs.mkdirSync(shared,{mode:0o700});fs.renameSync(join(shared+".original","ledger.md"),path);}
 if(armed && mode==="registry-closed") registry.close();
 if(armed && mode==="invalid-utf8") fs.writeFileSync(path,Buffer.from([0xc0,0xaf]));
 if(armed && mode==="oversize") fs.truncateSync(path,2097153);
 const baselineBytes=fs.readFileSync(path), baseline=fs.lstatSync(path);
 if(armed && mode==="short-read" || mode==="flags") {
  const receipt=api.inspectProductionSharedFiles(inspector);assert.equal(receipt.hasMatches,true);
  assert.equal(api.copyProductionSharedInspectionReportBytes(previous,inspector),null);
  assert.equal(opens.length,1);
  for(const flags of opens) {assert.ok(flags & fs.constants.O_NOFOLLOW);assert.ok(flags & fs.constants.O_NONBLOCK);assert.equal(flags & (fs.constants.O_WRONLY | fs.constants.O_RDWR | fs.constants.O_CREAT | fs.constants.O_TRUNC),0);}
  assert.equal(fileCloses,1);if(armed && mode==="short-read") assert.ok(reads>4);
 } else {
  assert.throws(()=>api.inspectProductionSharedFiles(inspector),/production shared files uncheckable/);
  assert.equal(api.copyProductionSharedInspectionReportBytes(previous,inspector),null);
  if(mode==="oversize") assert.equal(opens.length,0);
  assert.throws(()=>api.inspectProductionSharedFiles(inspector),/production shared files uncheckable/);
 }
 if(["append-during-read","tamper-during-read","replace-during-read"].includes(mode)) {assert.equal(fired,true);assert.equal(fs.readFileSync(path,"utf8"),mode==="append-during-read"?"needle\\nsecondx":mode==="tamper-during-read"?"needlf\\nsecond":"needle\\nsecond");} else {assert.deepEqual(fs.readFileSync(path),baselineBytes);assert.equal(fs.lstatSync(path).ino,baseline.ino);}
} finally {
 for(const [k,v] of Object.entries(originals)) fs[k]=v;
 syncBuiltinESMExports();registry.close();fs.rmSync(root,{recursive:true});
}
`;
  return spawnSync(process.execPath, ["--input-type=module", "-e", code], { encoding: "utf8" });
}
for (const mode of [
  "replace-before",
  "symlink-before",
  "hardlink-before",
  "file-mode",
  "parent-mode",
  "parent-replace",
  "registry-closed",
  "invalid-utf8",
  "oversize",
  "read-zero",
  "read-overcount",
  "read-fraction",
  "eof-extra",
  "append-during-read",
  "tamper-during-read",
  "replace-during-read",
  "reentrant",
  "close-failure",
  "short-read",
  "flags",
]) {
  test(`shared inspection preserves bytes and stops on ${mode}`, () => {
    const result = isolatedFault(mode);
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.status, 0, result.stderr);
  });
}

test("a shared inspector requires the original boundary-profile pair and rejects its owned output directory", () =>
  fixture(({ directory, paths, registry, profile, boundary }) => {
    const otherProfile = createProductionArtifactProfile({
      plan,
      resources,
      secretRegistry: registry,
    });
    assert.throws(
      () =>
        api.createProductionSharedFileInspector({
          directory,
          paths,
          profile: otherProfile,
          boundary,
          files: paths,
        }),
      /invalid production shared file inspector/,
    );
    assert.throws(
      () =>
        api.createProductionSharedFileInspector({
          directory,
          profile: otherProfile,
          boundary,
          files: paths,
        }),
      /invalid production shared file inspector/,
    );
    const path = join(directory, "shared-looking.md");
    fs.writeFileSync(path, "needle", { mode: 0o600 });
    assert.throws(
      () =>
        api.createProductionSharedFileInspector({
          directory,
          profile,
          boundary,
          files: [{ kind: "owner-ledger", path }],
        }),
      /invalid production shared file inspector/,
    );
  }));
