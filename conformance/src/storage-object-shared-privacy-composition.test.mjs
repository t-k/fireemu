import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
const modules = Object.fromEntries(
  [
    "stage3-plan",
    "production-secret-registry",
    "production-artifact-policy",
    "production-standalone-fail-stop",
    "production-artifact-writer",
    "production-artifact-inventory",
    "production-shared-file-inspector",
    "production-shared-report-file",
  ].map((name) => [name, new URL(`./storage-object/${name}.mjs`, import.meta.url).href]),
);
function fixture(recording, mode) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-sweep-")));
  fs.chmodSync(root, 0o700);
  const directory = join(root, "owned"),
    shared = join(root, "shared");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(shared, { mode: 0o700 });
  const paths = [join(shared, "owner.md"), join(shared, "sandbox.md")];
  const sharedBytes = [
    Array.from({ length: 25 }, () =>
      mode === "owned-only" || mode === "no-copy"
        ? "unrelated"
        : mode === "shared-only"
          ? "needle"
          : "sequence",
    ).join("\n"),
    mode === "no-copy"
      ? "unrelated\nend"
      : mode === "shared-only"
        ? "needle\nend"
        : "sequence\nend",
  ];
  for (let i = 0; i < paths.length; i++)
    fs.writeFileSync(paths[i], sharedBytes[i], { mode: 0o600 });
  const before = paths.map((path) => fs.lstatSync(path));
  const script = `
import fs from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import {buildProductionStage3DraftPlan} from ${JSON.stringify(modules["stage3-plan"])};
import {createProductionSecretRegistry} from ${JSON.stringify(modules["production-secret-registry"])};
import {createProductionArtifactProfile} from ${JSON.stringify(modules["production-artifact-policy"])};
import {createProductionStandaloneFailStop} from ${JSON.stringify(modules["production-standalone-fail-stop"])};
import {createProductionArtifactWriter} from ${JSON.stringify(modules["production-artifact-writer"])};
import {ensureProductionArtifactInventory,attachProductionSharedArtifactInspection,originalProductionArtifactInventoryWork} from ${JSON.stringify(modules["production-artifact-inventory"])};
import {createProductionSharedFileInspector,originalProductionSharedInspectorWork} from ${JSON.stringify(modules["production-shared-file-inspector"])};
import {createProductionSharedReportWriter,originalProductionSharedReportWriterContext} from ${JSON.stringify(modules["production-shared-report-file"])};
const root=${JSON.stringify(root)},directory=${JSON.stringify(directory)},paths=${JSON.stringify(paths)},recording=${recording},mode=${JSON.stringify(mode)};
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216});
const rawFs={open:fs.openSync,write:fs.writeSync,close:fs.closeSync};
registry.register("SYNTHETIC_UNRELATED_CREDENTIAL");
if(mode==="report-known-secret")registry.register("production-shared-privacy-report");
if(mode==="report-known-line-key")registry.register("lineNumbers");
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile});
const inventory=ensureProductionArtifactInventory({directory,profile,boundary});
const inspector=createProductionSharedFileInspector({directory,profile,boundary,files:paths.map((path,i)=>({path,kind:i?"sandbox-ledger":"owner-ledger"}))});
const reportWriter=createProductionSharedReportWriter({directory,profile,boundary,inspector});
attachProductionSharedArtifactInspection({inventory,inspector,reportWriter});
fs.writeFileSync(root+"/started-held","held",{mode:0o600});
const writer=createProductionArtifactWriter({directory,profile,boundary});
const row=writer.write({recording,operationId:"r"+recording+"/control/"+"a".repeat(64),kind:"journal",value:{type:"receipt",recording,sequence:1}});
fs.writeFileSync(root+"/saved.json",JSON.stringify(row),{mode:0o600});
if(mode==="shared-foreign") {fs.renameSync(paths[0],paths[0]+".original");fs.writeFileSync(paths[0],${JSON.stringify(sharedBytes[0])},{mode:0o600});}
if(mode==="shared-read-failure") {
 const originalOpen=fs.openSync,originalRead=fs.readSync;let target;
 fs.openSync=(path,...args)=>{const fd=originalOpen(path,...args);target=path===paths[0]?fd:undefined;return fd;};
 fs.readSync=(fd,...args)=>{if(fd===target)throw new Error("fixture shared read failed");return originalRead(fd,...args);};
}

if(mode==="report-existing")fs.writeFileSync(directory+"/privacy-shared-r"+recording+".json","foreign-existing-report",{mode:0o600});
if(["report-fsync-failure","report-write-zero","report-write-overcount","report-short-write","report-close-failure","report-dir-fsync","report-foreign","report-transient-foreign"].includes(mode)) {
 const originals=Object.fromEntries(["openSync","writeSync","fsyncSync","closeSync"].map(k=>[k,fs[k]]));let target,reportStarted=false,auditStarted=false;
 fs.openSync=(path,...args)=>{if(path===directory+"/privacy-r"+recording+".json")auditStarted=true;const fd=originals.openSync(path,...args);target=path.endsWith("privacy-shared-r"+recording+".json")?fd:undefined;if(target!==undefined){if(!reportStarted)fs.writeFileSync(root+"/report-open-flags",String(args[0]),{mode:0o600});reportStarted=true;target=fd;}return fd;};
 fs.writeSync=(fd,b,offset,length)=>{if(fd===target){if(mode==="report-write-zero")return 0;if(mode==="report-write-overcount")return length+1;if(mode==="report-short-write")return originals.writeSync(fd,b,offset,Math.min(length,3));}return originals.writeSync(fd,b,offset,length);};
 fs.fsyncSync=fd=>{if(fd===target && mode==="report-fsync-failure")throw new Error("fixture report fsync failed");if(mode==="report-dir-fsync"&&reportStarted&&fs.fstatSync(fd).isDirectory())throw new Error("fixture report directory fsync failed");if(["report-foreign","report-transient-foreign"].includes(mode)&&fd===target){const path=directory+"/privacy-shared-r"+recording+".json",bytes=fs.readFileSync(path);fs.renameSync(path,root+"/original-report");fs.writeFileSync(path,bytes,{mode:0o600});fs.writeFileSync(root+"/foreign-report-inode",String(fs.lstatSync(path).ino),{mode:0o600});}if(mode==="report-transient-foreign"&&reportStarted&&!auditStarted&&fs.fstatSync(fd).isDirectory()){const path=directory+"/privacy-shared-r"+recording+".json";fs.renameSync(path,root+"/foreign-report");fs.renameSync(root+"/original-report",path);fs.writeFileSync(root+"/transient-restored","bad",{mode:0o600});}return originals.fsyncSync(fd);};
 fs.closeSync=fd=>{originals.closeSync(fd);if(fd===target&&mode==="report-close-failure")throw new Error("fixture report close failed");};
}

const originalBytes=fs.readFileSync(directory+"/"+row.file);
const calculation=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216});
calculation.register("SYNTHETIC_UNRELATED_CREDENTIAL");
if(mode==="report-known-secret")calculation.register("production-shared-privacy-report");
if(mode==="report-known-line-key")calculation.register("lineNumbers");
calculation.register(mode==="shared-only"||mode==="no-copy"?"needle":"sequence");
const expectedOwnedScan=calculation.openScan();expectedOwnedScan.hasSecretCopy(originalBytes.toString("utf8"));
const expectedOwnedWork=originalBytes.length+expectedOwnedScan.snapshot().scanCodeUnits;calculation.close();
function saveWork(){
 const data=Buffer.from(JSON.stringify({inventory:originalProductionArtifactInventoryWork(inventory),shared:originalProductionSharedInspectorWork(inspector),report:originalProductionSharedReportWriterContext(reportWriter).work,expectedOwnedWork}));
 const fd=rawFs.open(root+"/final-work.json",fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL,0o600);rawFs.write(fd,data,0,data.length);rawFs.close(fd);
}
const priorOpen=fs.openSync;
fs.openSync=(path,...args)=>{if(path===directory+"/privacy-r"+recording+".json")saveWork();return priorOpen(path,...args);};
syncBuiltinESMExports();queueMicrotask(()=>fs.writeFileSync(root+"/after-microtask","bad"));
registry.register(mode==="shared-only"||mode==="no-copy"?"needle":"sequence");
if(mode==="no-copy")saveWork();
fs.writeFileSync(root+"/normal-return","bad");
`;
  try {
    const source = join(root, "child.mjs");
    fs.writeFileSync(source, script, { mode: 0o600 });
    const child = spawnSync(process.execPath, [source], {
      encoding: "utf8",
      env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
    });
    assert.equal(child.error, undefined);
    assert.equal(child.signal, null);
    assert.equal(child.status, mode === "no-copy" ? 0 : 2, child.stderr);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr, "");
    assert.equal(fs.existsSync(root + "/started-held"), true);
    for (const name of ["normal-return", "after-microtask", "end-row", "unlock"])
      assert.equal(
        fs.existsSync(root + "/" + name),
        mode === "no-copy" && ["normal-return", "after-microtask"].includes(name),
        name,
      );
    const work = JSON.parse(fs.readFileSync(root + "/final-work.json"));
    assert.equal(
      work.inventory,
      work.shared + work.expectedOwnedWork + work.report,
      "shared, owned and report work must share the original cumulative ceiling even after a failed read or persistence",
    );
    assert.ok(work.inventory <= 16777216);
    const row = JSON.parse(fs.readFileSync(root + "/saved.json"));
    assert.equal(
      fs.existsSync(join(directory, row.file)),
      ["shared-only", "no-copy"].includes(mode),
      "only trustworthy owned copies must be removed even when shared inspection fails",
    );
    for (let i = 0; i < paths.length; i++) {
      assert.equal(fs.readFileSync(paths[i], "utf8"), sharedBytes[i]);
      if (mode !== "shared-foreign" || i !== 0)
        assert.equal(fs.lstatSync(paths[i]).ino, before[i].ino);
    }
    if (mode === "no-copy") {
      assert.equal(fs.existsSync(join(directory, `privacy-r${recording}.json`)), false);
      assert.equal(fs.existsSync(join(directory, `privacy-shared-r${recording}.json`)), false);
      return;
    }
    const audit = JSON.parse(fs.readFileSync(join(directory, `privacy-r${recording}.json`)));
    assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
    assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
    const reportPath = join(directory, `privacy-shared-r${recording}.json`);
    if (["both", "owned-only", "shared-only", "report-short-write"].includes(mode)) {
      assert.equal(
        fs.existsSync(reportPath),
        true,
        "shared match must save its original closed path-line report before stop",
      );
      const report = JSON.parse(fs.readFileSync(reportPath));
      assert.deepEqual(report, {
        type: "production-shared-privacy-report",
        files:
          mode === "owned-only"
            ? [{ path: paths[1], lineNumbers: [1], matchedLineCount: 1, truncated: false }]
            : [
                {
                  path: paths[0],
                  lineNumbers: Array.from({ length: 20 }, (_, i) => i + 1),
                  matchedLineCount: 25,
                  truncated: true,
                },
                { path: paths[1], lineNumbers: [1], matchedLineCount: 1, truncated: false },
              ],
      });
      assert.equal(fs.lstatSync(reportPath).mode & 0o777, 0o600);
      assert.equal(audit.reason, "shared-file-secret-copy");
    } else if (["report-known-secret", "report-known-line-key"].includes(mode)) {
      assert.equal(fs.existsSync(reportPath), false);
      assert.equal(audit.reason, "shared-report-withheld-privacy");
    } else {
      assert.equal(
        audit.reason,
        mode.startsWith("report-")
          ? "shared-report-persistence-uncertain"
          : "shared-file-uncheckable",
      );
      if (mode === "report-existing")
        assert.equal(fs.readFileSync(reportPath, "utf8"), "foreign-existing-report");
      if (["report-foreign", "report-transient-foreign"].includes(mode)) {
        assert.equal(
          fs.lstatSync(reportPath).ino,
          Number(fs.readFileSync(root + "/foreign-report-inode", "utf8")),
        );
        assert.equal(fs.existsSync(root + "/original-report"), true);
        if (mode === "report-transient-foreign")
          assert.equal(
            fs.existsSync(root + "/transient-restored"),
            false,
            "an observed foreign inode must stop before directory fsync can restore it",
          );
      }
    }
    if (fs.existsSync(root + "/report-open-flags")) {
      const flags = Number(fs.readFileSync(root + "/report-open-flags", "utf8"));
      assert.ok(flags & fs.constants.O_EXCL);
      assert.ok(flags & fs.constants.O_NOFOLLOW);
      assert.ok(flags & fs.constants.O_CREAT);
      assert.equal(flags & fs.constants.O_TRUNC, 0);
    }
  } finally {
    fs.rmSync(root, { recursive: true });
  }
}
for (const recording of [1, 2])
  for (const mode of [
    "both",
    "owned-only",
    "shared-only",
    "no-copy",
    "report-known-secret",
    "shared-foreign",
    "shared-read-failure",
    "report-fsync-failure",
    "report-write-zero",
    "report-write-overcount",
    "report-short-write",
    "report-close-failure",
    "report-dir-fsync",
    "report-foreign",
    "report-transient-foreign",
    "report-existing",
    "report-known-line-key",
  ])
    test(`recording ${recording} collects owned and shared privacy before stopping on ${mode}`, () =>
      fixture(recording, mode));

async function localFixture(action) {
  const [plans, registries, profiles, boundaries, inventories, inspectors, reports] =
    await Promise.all([
      import("./storage-object/stage3-plan.mjs"),
      import("./storage-object/production-secret-registry.mjs"),
      import("./storage-object/production-artifact-policy.mjs"),
      import("./storage-object/production-standalone-fail-stop.mjs"),
      import("./storage-object/production-artifact-inventory.mjs"),
      import("./storage-object/production-shared-file-inspector.mjs"),
      import("./storage-object/production-shared-report-file.mjs"),
    ]);
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-bind-")));
  fs.chmodSync(root, 0o700);
  const directory = join(root, "owned"),
    shared = join(root, "shared");
  fs.mkdirSync(directory, { mode: 0o700 });
  fs.mkdirSync(shared, { mode: 0o700 });
  const path = join(shared, "owner.md");
  fs.writeFileSync(path, "needle", { mode: 0o600 });
  const registry = registries.createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  registry.register("needle");
  const plan = plans.buildProductionStage3DraftPlan({
      projectId: "example-project",
      bucket: "example.appspot.com",
      runIds: ["recordone", "recordtwo"],
    }),
    resources = {
      projectNumber: "123456789012",
      apiKeyResource: "projects/123456789012/locations/global/keys/fixture-key",
      rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
    };
  const profile = profiles.createProductionArtifactProfile({
      plan,
      resources,
      secretRegistry: registry,
    }),
    boundary = boundaries.createProductionStandaloneFailStop({ directory, profile });
  const inventory = inventories.ensureProductionArtifactInventory({ directory, profile, boundary }),
    inspector = inspectors.createProductionSharedFileInspector({
      directory,
      profile,
      boundary,
      files: [{ kind: "owner-ledger", path }],
    });
  const writer = () =>
    reports.createProductionSharedReportWriter({ directory, profile, boundary, inspector });
  try {
    return await action({
      root,
      directory,
      path,
      registry,
      profile,
      boundary,
      inventory,
      inspector,
      writer,
      inventories,
      inspectors,
      reports,
    });
  } finally {
    registry.close();
    fs.rmSync(root, { recursive: true });
  }
}
test("shared attachment and report factories reject clones, foreign original pairs, injected fields and getter hooks", () =>
  localFixture(
    ({
      directory,
      profile,
      boundary,
      inventory,
      inspector,
      writer,
      inventories,
      inspectors,
      reports,
    }) => {
      const reportWriter = writer(),
        base = { inventory, inspector, reportWriter };
      for (const input of [
        { ...base, inventory: { ...inventory } },
        { ...base, inspector: { ...inspector } },
        { ...base, reportWriter: { ...reportWriter } },
        { ...base, extra: true },
      ])
        assert.throws(
          () => inventories.attachProductionSharedArtifactInspection(input),
          /invalid production shared artifact inspection/,
        );
      let hooks = 0;
      const hook = { inventory, reportWriter };
      Object.defineProperty(hook, "inspector", {
        enumerable: true,
        get() {
          hooks++;
          throw new Error("fixture hook");
        },
      });
      assert.throws(
        () => inventories.attachProductionSharedArtifactInspection(hook),
        /invalid production shared artifact inspection/,
      );
      assert.equal(hooks, 0);
      const factory = { directory, profile, boundary, inspector };
      for (const input of [
        { ...factory, inspector: { ...inspector } },
        { ...factory, profile: { ...profile } },
        { ...factory, boundary: { ...boundary } },
        { ...factory, extra: true },
      ])
        assert.throws(
          () => reports.createProductionSharedReportWriter(input),
          /invalid production shared report writer/,
        );
      assert.equal(
        inspectors.productionSharedInspectorUsesArtifactContext(inspector, {
          directory,
          profile,
          boundary,
        }),
        true,
      );
      const otherInspector = inspectors.createProductionSharedFileInspector({
        directory,
        profile,
        boundary,
        files: [
          {
            kind: "owner-ledger",
            path: fs.realpathSync(join(directory, "..", "shared", "owner.md")),
          },
        ],
      });
      assert.throws(
        () =>
          inventories.attachProductionSharedArtifactInspection({
            ...base,
            inspector: otherInspector,
          }),
        /invalid production shared artifact inspection/,
      );
      inventories.attachProductionSharedArtifactInspection(base);
      assert.throws(
        () => inventories.attachProductionSharedArtifactInspection(base),
        /invalid production shared artifact inspection/,
      );
    },
  ));
test("shared and owned work accumulates in the same original broker allowance", () =>
  localFixture(
    async ({
      directory,
      path,
      registry,
      profile,
      boundary,
      inventory,
      inspector,
      writer,
      inventories,
      inspectors,
    }) => {
      fs.writeFileSync(path, "unrelated!");
      inventories.attachProductionSharedArtifactInspection({
        inventory,
        inspector,
        reportWriter: writer(),
      });
      registry.register("SYNTHETIC_UNKNOWN_FIRST");
      const first = inventories.originalProductionArtifactInventoryWork(inventory);
      assert.ok(first > 0);
      assert.equal(first, inspectors.originalProductionSharedInspectorWork(inspector));
      assert.equal(inventories.originalProductionArtifactInventoryWork({ ...inventory }), null);
      const producers = await import("./storage-object/production-artifact-writer.mjs");
      const producer = producers.createProductionArtifactWriter({ directory, profile, boundary });
      const row = producer.write({
        recording: 1,
        operationId: "r1/control/" + "a".repeat(64),
        kind: "journal",
        value: { type: "receipt", recording: 1, sequence: 1 },
      });
      const bytes = fs.readFileSync(join(directory, row.file));
      registry.register("SYNTHETIC_UNKNOWN_SECOND");
      const scan = registry.openScan();
      assert.equal(scan.hasSecretCopy(bytes.toString("utf8")), false);
      const ownedWork = bytes.length + scan.snapshot().scanCodeUnits;
      assert.equal(
        inventories.originalProductionArtifactInventoryWork(inventory),
        inspectors.originalProductionSharedInspectorWork(inspector) + ownedWork,
      );
      assert.equal(inspectors.originalProductionSharedInspectorWork(inspector), first * 2);
      assert.deepEqual(fs.readFileSync(join(directory, row.file)), bytes);
      const before = inventories.originalProductionArtifactInventoryWork(inventory);
      registry.register("SYNTHETIC_UNKNOWN_THIRD");
      assert.equal(
        inventories.originalProductionArtifactInventoryWork(inventory),
        before + first + ownedWork,
      );
    },
  ));

test("shared inspection rejects invalid caller allowances and charges failed stable reads", () =>
  localFixture(({ directory, path, profile, boundary, inspectors }) => {
    const create = () =>
      inspectors.createProductionSharedFileInspector({
        directory,
        profile,
        boundary,
        files: [{ kind: "owner-ledger", path }],
      });
    for (const allowance of [0, -1, NaN, Infinity, 0.5, 16777217, { remainingWork: 1 }]) {
      const inspector = create();
      assert.throws(
        () => inspectors.inspectProductionSharedFiles(inspector, allowance),
        /production shared files uncheckable/,
      );
      assert.equal(inspectors.originalProductionSharedInspectorWork(inspector), 0);
      assert.throws(
        () => inspectors.inspectProductionSharedFiles(inspector),
        /production shared files uncheckable/,
      );
    }
    for (const allowance of [1, 5]) {
      const inspector = create();
      assert.throws(
        () => inspectors.inspectProductionSharedFiles(inspector, allowance),
        /production shared files uncheckable/,
      );
      assert.equal(inspectors.originalProductionSharedInspectorWork(inspector), 0);
    }
    const inspector = create();
    fs.writeFileSync(path, Buffer.from([0xc0, 0xaf]));
    assert.throws(
      () => inspectors.inspectProductionSharedFiles(inspector, 128),
      /production shared files uncheckable/,
    );
    assert.equal(inspectors.originalProductionSharedInspectorWork(inspector), 2);
    assert.equal(inspectors.originalProductionSharedInspectorWork({ ...inspector }), null);
  }));

test("report writer accepts only a fresh original receipt, closed inputs and a finite original allowance", () =>
  localFixture(({ directory, inspector, writer, inspectors, reports }) => {
    const before = inspectors.inspectProductionSharedFiles(inspector),
      receipt = inspectors.inspectProductionSharedFiles(inspector);
    for (const input of [
      { receipt: { ...receipt }, recording: 1, remainingWork: 16777216 },
      { receipt: before, recording: 1, remainingWork: 16777216 },
      { receipt, recording: 3, remainingWork: 16777216 },
      { receipt, recording: 1, remainingWork: 0 },
      { receipt, recording: 1, remainingWork: 16777217 },
      { receipt, recording: 1, remainingWork: 16777216, bytes: Buffer.from("caller") },
    ])
      assert.throws(
        () => reports.writeProductionSharedPrivacyReport(writer(), input),
        /production shared report uncertain/,
      );
    let hooks = 0;
    const input = { recording: 1, remainingWork: 16777216 };
    Object.defineProperty(input, "receipt", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("fixture hook");
      },
    });
    assert.throws(
      () => reports.writeProductionSharedPrivacyReport(writer(), input),
      /production shared report uncertain/,
    );
    assert.equal(hooks, 0);
    assert.deepEqual(fs.readdirSync(directory), []);
  }));
test("report scanning consumes its original writer allowance across both recordings", () =>
  localFixture(({ directory, inspector, writer, inspectors, reports }) => {
    const reportWriter = writer();
    const first = inspectors.inspectProductionSharedFiles(inspector);
    const durable = reports.writeProductionSharedPrivacyReport(reportWriter, {
      receipt: first,
      recording: 1,
      remainingWork: 16777216,
    });
    assert.equal(durable.recording, 1);
    const binding = reports.originalProductionSharedReportFile(durable, reportWriter);
    assert.ok(binding, "the successful report returns its original private file receipt");
    assert.equal(binding.path, join(directory, durable.file));
    assert.equal(reports.originalProductionSharedReportFile({ ...durable }, reportWriter), null);
    const work = reports.originalProductionSharedReportWriterContext(reportWriter).work;
    assert.ok(work > 0);
    const second = inspectors.inspectProductionSharedFiles(inspector);
    assert.throws(
      () =>
        reports.writeProductionSharedPrivacyReport(reportWriter, {
          receipt: second,
          recording: 2,
          remainingWork: 16777216,
        }),
      /production shared report uncertain/,
    );
    assert.equal(fs.existsSync(join(directory, "privacy-shared-r2.json")), false);
    assert.equal(reports.originalProductionSharedReportWriterContext(reportWriter).work, work);
  }));

for (const recording of [1, 2])
  test(`recording ${recording} enrolls the owned shared report for later-secret removal`, () => {
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-shared-report-late-")));
    fs.chmodSync(root, 0o700);
    const directory = join(root, "owned"),
      shared = join(root, "shared");
    fs.mkdirSync(directory, { mode: 0o700 });
    fs.mkdirSync(shared, { mode: 0o700 });
    const path = join(shared, "owner.md");
    fs.writeFileSync(path, "needle", { mode: 0o600 });
    const original = fs.lstatSync(path);
    const code = `
import fs from "node:fs";
import {buildProductionStage3DraftPlan} from ${JSON.stringify(modules["stage3-plan"])};
import {createProductionSecretRegistry} from ${JSON.stringify(modules["production-secret-registry"])};
import {createProductionArtifactProfile} from ${JSON.stringify(modules["production-artifact-policy"])};
import {createProductionStandaloneFailStop} from ${JSON.stringify(modules["production-standalone-fail-stop"])};
import {createProductionSharedFileInspector,inspectProductionSharedFiles} from ${JSON.stringify(modules["production-shared-file-inspector"])};
import {createProductionSharedReportWriter,writeProductionSharedPrivacyReport} from ${JSON.stringify(modules["production-shared-report-file"])};
const directory=${JSON.stringify(directory)},root=${JSON.stringify(root)},path=${JSON.stringify(path)},recording=${recording};
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216});registry.register("needle");
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]}),resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile});
const inspector=createProductionSharedFileInspector({directory,profile,boundary,files:[{kind:"owner-ledger",path}]}),writer=createProductionSharedReportWriter({directory,profile,boundary,inspector}),receipt=inspectProductionSharedFiles(inspector);
const durable=writeProductionSharedPrivacyReport(writer,{receipt,recording,remainingWork:16777216});fs.writeFileSync(root+"/saved.json",JSON.stringify(durable),{mode:0o600});fs.writeFileSync(root+"/started-held","held",{mode:0o600});queueMicrotask(()=>fs.writeFileSync(root+"/after-microtask","bad"));registry.register("matchedLineCount");fs.writeFileSync(root+"/normal-return","bad");
`;
    try {
      const child = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
        encoding: "utf8",
      });
      assert.equal(child.error, undefined);
      assert.equal(child.signal, null);
      assert.equal(child.status, 2, child.stderr);
      assert.equal(child.stdout, "");
      assert.equal(child.stderr, "");
      const durable = JSON.parse(fs.readFileSync(join(root, "saved.json")));
      assert.equal(durable.type, "production-shared-report-durable");
      assert.equal(
        fs.existsSync(join(directory, durable.file)),
        false,
        "the original shared report must be removed on later discovery",
      );
      assert.equal(fs.readFileSync(path, "utf8"), "needle");
      assert.equal(fs.lstatSync(path).ino, original.ino);
      assert.equal(fs.existsSync(join(root, "started-held")), true);
      for (const name of ["normal-return", "after-microtask", "end-row", "unlock"])
        assert.equal(fs.existsSync(join(root, name)), false);
      const audit = JSON.parse(fs.readFileSync(join(directory, `privacy-r${recording}.json`)));
      assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
      assert.equal(audit.reason, "artifact-removed-late-secret");
      assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
    } finally {
      fs.rmSync(root, { recursive: true });
    }
  });
