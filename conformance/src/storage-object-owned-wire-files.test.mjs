import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { spawnSync } from "node:child_process";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
const api = await import("./storage-object/production-owned-wire-files.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
function fixture(action) {
  assert.equal(
    typeof api.createProductionWireFileWriter,
    "function",
    "owned wire file persistence is missing",
  );
  const directory = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-owned-wire-files-")));
  fs.chmodSync(directory, 0o700);
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
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry }),
    boundary = createProductionStandaloneFailStop({ directory, profile });
  try {
    action({ directory, plan, resources, registry, profile, boundary });
  } finally {
    registry.close();
    fs.rmSync(directory, { recursive: true });
  }
}
for (const recording of [1, 2]) {
  test(`owned recording ${recording} commits each original wire file once and proves its private receipt`, () =>
    fixture(({ directory, profile, boundary }) => {
      const operationId = `r${recording}/p1/${"a".repeat(64)}`;
      const writer = api.createProductionWireFileWriter({
        directory,
        profile,
        boundary,
        operationId,
        sequence: 1,
      });
      assert.equal(Object.isFrozen(writer.files), true);
      for (const kind of ["request", "intent", "response", "result"]) {
        const bytes = Buffer.from(JSON.stringify({ sequence: 1, type: `fixture-${kind}` }) + "\n");
        const receipt = writer.write(kind, bytes);
        assert.deepEqual(fs.readFileSync(writer.files[kind]), bytes);
        assert.equal(fs.statSync(writer.files[kind]).mode & 0o777, 0o600);
        assert.equal(receipt.sha256, hash(bytes));
        assert.equal(receipt.byteLength, bytes.length);
        assert.equal(api.isProductionWireFileReceipt(receipt, writer, kind), true);
        assert.equal(api.isProductionWireFileReceipt({ ...receipt }, writer, kind), false);
        assert.equal(api.isProductionWireFileReceipt(receipt, { ...writer }, kind), false);
        assert.equal(api.isProductionWireFileReceipt(receipt, writer, "unknown"), false);
      }
      assert.equal(fs.readdirSync(directory).length, 4);
    }));
}
test("wire file context rejects copied profiles, capabilities and unreviewed sequence or operation scope without hooks", () =>
  fixture(({ directory, profile, boundary, plan, resources, registry }) => {
    const base = {
      directory,
      profile,
      boundary,
      operationId: `r1/p1/${"a".repeat(64)}`,
      sequence: 1,
    };
    const otherProfile = createProductionArtifactProfile({
      plan,
      resources,
      secretRegistry: registry,
    });
    const foreign = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-owned-wire-foreign-")));
    fs.chmodSync(foreign, 0o700);
    try {
      for (const changes of [{ profile: otherProfile }, { directory: foreign }])
        assert.throws(
          () => api.createProductionWireFileWriter({ ...base, ...changes }),
          /^Error: invalid production wire file writer$/,
        );
      assert.deepEqual(fs.readdirSync(foreign), []);
    } finally {
      fs.rmSync(foreign, { recursive: true });
    }
    for (const changes of [
      { profile: { ...profile } },
      { boundary: { ...boundary } },
      { sequence: 0 },
      { sequence: 6001 },
      { operationId: `r3/p1/${"a".repeat(64)}` },
      { operationId: `r1/p27/${"a".repeat(64)}` },
      { extra: true },
    ])
      assert.throws(
        () => api.createProductionWireFileWriter({ ...base, ...changes }),
        /^Error: invalid production wire file writer$/,
      );
    let hooks = 0;
    const input = { ...base };
    Object.defineProperty(input, "profile", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("SYNTHETIC_GETTER");
      },
    });
    assert.throws(
      () => api.createProductionWireFileWriter(input),
      /^Error: invalid production wire file writer$/,
    );
    assert.equal(hooks, 0);
    const coercion = {
      toString() {
        hooks++;
        throw new Error("SYNTHETIC_COERCION");
      },
    };
    assert.throws(
      () => api.createProductionWireFileWriter({ ...base, operationId: coercion }),
      /^Error: invalid production wire file writer$/,
    );
    assert.equal(hooks, 0);
    assert.deepEqual(fs.readdirSync(directory), []);
  }));

function faultChild(fault, recording, kind) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-owned-wire-file-child-")));
  fs.chmodSync(root, 0o700);
  const directory = join(root, "capture"),
    scriptPath = join(root, "fixture.mjs");
  const moduleURL = (file) => new URL("./storage-object/" + file, import.meta.url).href;
  const script = `
import fs from "node:fs"; import { syncBuiltinESMExports } from "node:module";
import { createProductionWireFileWriter, isProductionWireFileReceipt } from ${JSON.stringify(moduleURL("production-owned-wire-files.mjs"))};
import { buildProductionStage3DraftPlan } from ${JSON.stringify(moduleURL("stage3-plan.mjs"))};
import { createProductionArtifactProfile } from ${JSON.stringify(moduleURL("production-artifact-policy.mjs"))};
import { createProductionStandaloneFailStop } from ${JSON.stringify(moduleURL("production-standalone-fail-stop.mjs"))};
import { createProductionSecretRegistry } from ${JSON.stringify(moduleURL("production-secret-registry.mjs"))};
import { MAX_RESPONSE_BODY_BYTES } from ${JSON.stringify(moduleURL("wire-limits.mjs"))};
const root=${JSON.stringify(root)}, directory=${JSON.stringify(directory)}, fault=${JSON.stringify(fault)},recording=${recording},kind=${JSON.stringify(kind)},marker="FOREIGN_SYNTHETIC_WIRE_FILE";
fs.mkdirSync(directory,{mode:0o700});fs.writeFileSync(directory+"/started.lock","SYNTHETIC_STARTED",{mode:0o600});
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:fault==="scan-bound"?1:16777216});
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile});
const writer=createProductionWireFileWriter({directory,profile,boundary,operationId:"r"+recording+"/p1/"+"a".repeat(64),sequence:fault==="sequence-end"?6000:1}),file=writer.files[kind];
const original=Object.fromEntries(["openSync","writeSync","fsyncSync","closeSync"].map(name=>[name,fs[name]]));
let fileFd,directoryFd,armed=true,writes=0,hooks=0,continued=false,returned=false;
process.on("exit",()=>fs.writeFileSync(root+"/metrics.json",JSON.stringify({writes,hooks,continued,returned}),{mode:0o600}));
if(fault==="exclusive")fs.writeFileSync(file,marker,{mode:0o600});
if(fault==="symlink"){fs.writeFileSync(directory+"/foreign",marker,{mode:0o600});fs.symlinkSync(directory+"/foreign",file);}
if(fault==="parent-before"){fs.renameSync(directory,directory+"-old");fs.mkdirSync(directory,{mode:0o700});}
if(fault==="registry-closed")registry.close();
if(fault==="secret-copy")registry.register("SYNTHETIC_FINAL_WIRE_SECRET");
fs.openSync=function(path,flags,...args){const fd=original.openSync(path,flags,...args);if(path===file)fileFd=fd;if(path===directory)directoryFd=fd;return fd;};
fs.writeSync=function(fd,buffer,offset,length,...args){
 if(fd===fileFd){writes++;if(fault==="short")return original.writeSync(fd,buffer,offset,Math.min(length,7),...args);
 if(armed&&["throw","zero","negative","nan","excess"].includes(fault)){armed=false;if(fault==="throw")throw new Error("SYNTHETIC_FINAL_WIRE_SECRET");if(["excess","nan"].includes(fault))original.writeSync(fd,buffer,offset,length,...args);return fault==="zero"?0:fault==="negative"?-1:fault==="excess"?length+1:NaN;}}
 return original.writeSync(fd,buffer,offset,length,...args);
};
function changeFile(mode){
 if(mode==="mode")fs.chmodSync(file,0o644);
 if(mode==="hardlink")fs.linkSync(file,directory+"/linked");
 if(mode==="size")fs.appendFileSync(file,marker);
 if(mode==="inode"){const length=fs.fstatSync(fileFd).size;fs.renameSync(file,directory+"/original");fs.writeFileSync(file,marker.padEnd(length," "),{mode:0o600});}
}
fs.fsyncSync=function(fd){
 if(armed&&fd===fileFd){if(fault==="file-fsync"){armed=false;throw new Error("SYNTHETIC_FINAL_WIRE_SECRET");}
 if(fault.startsWith("file-")&&["mode","hardlink","size","inode"].includes(fault.slice(5))){armed=false;changeFile(fault.slice(5));}}
 if(armed&&fd===directoryFd){if(fault==="directory-fsync"){armed=false;throw new Error("SYNTHETIC_FINAL_WIRE_SECRET");}
 if(fault.startsWith("post-")&&["mode","hardlink","size","inode"].includes(fault.slice(5))){armed=false;changeFile(fault.slice(5));}
 if(fault==="parent-during-fsync"){armed=false;fs.renameSync(directory,directory+"-old");fs.mkdirSync(directory,{mode:0o700});fs.renameSync(directory+"-old"+file.slice(directory.length),file);}}
 return original.fsyncSync(fd);
};
fs.closeSync=function(fd){const fail=armed&&((fault==="file-close"&&fd===fileFd)||(fault==="directory-close"&&fd===directoryFd));original.closeSync(fd);if(fail){armed=false;throw new Error("SYNTHETIC_FINAL_WIRE_SECRET");}};
syncBuiltinESMExports();
let bytes=Buffer.from(JSON.stringify({sequence:1,type:"fixture-wire",status:200})+"\\n");
if(fault==="secret-copy")bytes=Buffer.from(JSON.stringify({status:"SYNTHETIC_FINAL_WIRE_SECRET"})+"\\n");
if(["byte-limit","next-byte"].includes(fault))bytes=Buffer.from('"'+ ".".repeat(MAX_RESPONSE_BODY_BYTES-3+(fault==="next-byte"?1:0))+'"\\n');
if(fault==="buffer-hook"){bytes=Buffer.from(bytes);Object.defineProperty(bytes,"byteLength",{get(){hooks++;throw new Error("SYNTHETIC_HOOK");}});bytes.toString=()=>{hooks++;throw new Error("SYNTHETIC_HOOK");};}
if(fault==="buffer-proxy")bytes=new Proxy(bytes,{get(){hooks++;throw new Error("SYNTHETIC_HOOK");}});
if(fault==="empty")bytes=Buffer.alloc(0);
queueMicrotask(()=>{continued=true;});
const receipt=writer.write(kind,bytes);
if(fault==="duplicate")writer.write(kind,bytes);
returned=true;
fs.writeFileSync(root+"/after.json",JSON.stringify({receipt,original:isProductionWireFileReceipt(receipt,writer,kind)}),{mode:0o600});
registry.close();
`;
  fs.writeFileSync(scriptPath, script, { mode: 0o600 });
  try {
    const result = spawnSync(process.execPath, [scriptPath], {
      encoding: "utf8",
      timeout: 5000,
      env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR ?? tmpdir() },
    });
    assert.equal(result.error, undefined);
    assert.equal(result.signal, null);
    assert.equal(result.stdout, "");
    assert.equal(result.stderr, "");
    const metrics = JSON.parse(fs.readFileSync(join(root, "metrics.json")));
    assert.equal(metrics.hooks, 0);
    const successful = ["short", "byte-limit", "buffer-hook", "sequence-end"].includes(fault);
    assert.equal(result.status, successful ? 0 : 2);
    assert.equal(metrics.returned, successful);
    assert.equal(metrics.continued, successful);
    assert.equal(fs.existsSync(join(root, "after.json")), successful);
    assert.equal(
      fs.existsSync(join(directory, "started.lock")) ||
        fs.existsSync(join(directory + "-old", "started.lock")),
      true,
    );
    assert.equal(fs.existsSync(join(directory, "end.json")), false);
    const file = join(
      directory,
      (fault === "sequence-end" ? "006000" : "000001") + "-" + kind + ".json",
    );
    if (successful) {
      const after = JSON.parse(fs.readFileSync(join(root, "after.json"))),
        bytes = fs.readFileSync(file);
      assert.equal(after.original, true);
      assert.equal(after.receipt.sha256, hash(bytes));
      assert.equal(after.receipt.byteLength, bytes.length);
      if (fault === "short") assert.ok(metrics.writes > 1);
    } else if (["secret-copy", "scan-bound", "registry-closed"].includes(fault)) {
      assert.equal(fs.existsSync(file), false);
      const audit = JSON.parse(fs.readFileSync(join(directory, "privacy-r" + recording + ".json")));
      assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
      assert.equal(
        audit.reason,
        fault === "secret-copy" ? "artifact-withheld-privacy" : "artifact-uncheckable",
      );
      assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
    } else if (!["parent-before", "parent-during-fsync"].includes(fault)) {
      const fatal = JSON.parse(fs.readFileSync(join(directory, "fatal-r" + recording + ".json")));
      assert.equal(fatal.reason, "PERSISTENCE_UNCERTAIN");
      assert.equal(fatal.recording, recording);
    }
    if (fault === "exclusive")
      assert.equal(fs.readFileSync(file, "utf8"), "FOREIGN_SYNTHETIC_WIRE_FILE");
    if (fault === "symlink")
      assert.equal(
        fs.readFileSync(join(directory, "foreign"), "utf8"),
        "FOREIGN_SYNTHETIC_WIRE_FILE",
      );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
}
for (const fault of [
  "short",
  "throw",
  "zero",
  "negative",
  "nan",
  "excess",
  "file-fsync",
  "directory-fsync",
  "file-close",
  "directory-close",
  "file-mode",
  "file-hardlink",
  "file-size",
  "file-inode",
  "post-mode",
  "post-hardlink",
  "post-size",
  "post-inode",
  "exclusive",
  "symlink",
  "parent-before",
  "parent-during-fsync",
  "duplicate",
  "secret-copy",
  "scan-bound",
  "registry-closed",
  "buffer-hook",
  "buffer-proxy",
  "empty",
]) {
  for (const recording of [1, 2])
    for (const kind of ["request", "intent", "response", "result"])
      test(
        "owned " +
          kind +
          " recording " +
          recording +
          " checks " +
          fault +
          " without normal continuation on uncertain persistence",
        () => faultChild(fault, recording, kind),
      );
}
for (const fault of ["byte-limit", "next-byte", "sequence-end"])
  for (const recording of [1, 2])
    test("owned file recording " + recording + " checks exact " + fault + " boundary", () =>
      faultChild(fault, recording, "result"),
    );
