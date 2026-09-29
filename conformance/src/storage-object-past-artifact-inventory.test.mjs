import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const artifacts = [
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
const wires = ["request", "intent", "response", "result"];
const modules = Object.fromEntries(
  [
    ["writer", "production-artifact-writer.mjs"],
    ["wire", "production-owned-wire-files.mjs"],
    ["capture", "production-wire-capture.mjs"],
    ["coverage", "production-capture-coverage.mjs"],
    ["registry", "production-secret-registry.mjs"],
    ["profile", "production-artifact-policy.mjs"],
    ["boundary", "production-standalone-fail-stop.mjs"],
    ["plan", "stage3-plan.mjs"],
  ].map(([name, file]) => [name, new URL("./storage-object/" + file, import.meta.url).href]),
);
function fixture(recording, mode, artifactKinds, wireKinds) {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "fireemu-past-artifact-")));
  fs.chmodSync(root, 0o700);
  const directory = join(root, "capture");
  fs.mkdirSync(directory, { mode: 0o700 });
  const source = join(root, "child.mjs");
  const script = `
import fs from "node:fs";
import {syncBuiltinESMExports} from "node:module";
import {createProductionArtifactWriter} from ${JSON.stringify(modules.writer)};
import {createProductionWireFileWriter} from ${JSON.stringify(modules.wire)};
import {createProductionWireAttempt} from ${JSON.stringify(modules.capture)};
import {createProductionCaptureProfile} from ${JSON.stringify(modules.coverage)};
import {createProductionSecretRegistry,registerProductionSecretBatch} from ${JSON.stringify(modules.registry)};
import {createProductionArtifactProfile} from ${JSON.stringify(modules.profile)};
import {createProductionStandaloneFailStop} from ${JSON.stringify(modules.boundary)};
import {buildProductionStage3DraftPlan} from ${JSON.stringify(modules.plan)};
const root=${JSON.stringify(root)},directory=${JSON.stringify(directory)},recording=${recording},mode=${JSON.stringify(mode)},artifactKinds=${JSON.stringify(artifactKinds)},wireKinds=${JSON.stringify(wireKinds)};
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:mode==="work-budget"?12000:16777216});
registry.register("SYNTHETIC_UNRELATED_CREDENTIAL");
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile});
const operationId="r"+recording+"/control/"+"a".repeat(64);
fs.writeFileSync(root+"/started-held","held",{mode:0o600});
if(mode==="pending-artifact"||mode==="pending-wire") {
 const original=fs.writeSync;let armed=true;
 fs.writeSync=(fd,b,offset,length)=>{if(armed){armed=false;const saved=fs.readdirSync(directory).map(name=>({name,dev:fs.lstatSync(directory+"/"+name).dev,ino:fs.lstatSync(directory+"/"+name).ino}));fs.writeFileSync(root+"/saved.json",JSON.stringify(saved),{mode:0o600});queueMicrotask(()=>fs.writeFileSync(root+"/after-microtask","bad"));registry.register("sequence");}return original(fd,b,offset,length);};
 syncBuiltinESMExports();
}
if(artifactKinds.length){const writer=createProductionArtifactWriter({directory,profile,boundary});if(mode==="cross-recording")writer.write({recording:3-recording,operationId:"r"+(3-recording)+"/control/"+"b".repeat(64),kind:"journal",value:{type:"receipt",recording:3-recording,sequence:1}});for(const kind of artifactKinds)writer.write({recording,operationId,kind,value:{type:"receipt",recording,sequence:1}});}
if(wireKinds.length){const writer=createProductionWireFileWriter({directory,profile,boundary,operationId,sequence:1});for(const kind of wireKinds)writer.write(kind,Buffer.from(JSON.stringify(mode==="preserve-safe"&&kind==="intent"?"safe-prototype-bytes":mode==="batch"&&kind==="intent"?{type:"receipt"}:{sequence:1})));}
let attempt;
if(["discovered-wire","batch","batch-hash","batch-hash-reverse"].includes(mode)) {
 const url="https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned%2Fobject",wire=Buffer.from("GET / HTTP/1.1\\r\\n\\r\\n");
 attempt=createProductionWireAttempt({directory,sequence:2,request:{url,method:"GET",headers:[],body:Buffer.alloc(0),wire},metadata:{operationId,phase:"subject"},policy:{secretRegistry:registry,artifactProfile:profile,standaloneBoundary:boundary,captureProfile:createProductionCaptureProfile({kind:"storage",objectName:"owned/object",method:"GET",url,sessionPhase:null}),expectedBucket:"example.appspot.com",expectedObjectNames:["owned/object"]}});
 fs.writeFileSync(root+"/request-length",String(wire.length),{mode:0o600});
}
const saved=fs.readdirSync(directory).filter(n=>!n.startsWith("privacy-")).map(name=>({name,dev:fs.lstatSync(directory+"/"+name).dev,ino:fs.lstatSync(directory+"/"+name).ino}));
fs.writeFileSync(root+"/saved.json",JSON.stringify(saved),{mode:0o600});

const target=directory+"/"+saved[0]?.name;
if(mode==="foreign-inode") {const bytes=fs.readFileSync(target);fs.renameSync(target,root+"/original-owned");fs.writeFileSync(target,bytes,{mode:0o600});}
if(mode==="hardlink") fs.linkSync(target,root+"/linked-original");
if(mode==="symlink") {fs.renameSync(target,root+"/original-owned");fs.writeFileSync(root+"/foreign-file",JSON.stringify({sequence:1}),{mode:0o600});fs.symlinkSync(root+"/foreign-file",target);}
if(mode==="same-inode-edit") {const b=fs.readFileSync(target);b[b.length-2]=b[b.length-2]===48?49:48;fs.writeFileSync(target,b);}
if(mode==="parent-mode") fs.chmodSync(directory,0o755);
if(mode==="parent-inode") {fs.renameSync(directory,root+"/original-directory");fs.mkdirSync(directory,{mode:0o700});}
if(mode==="closed-registry") registry.close();
if(mode==="open-flags") {const original=fs.openSync;fs.openSync=(path,flags,...args)=>{if(path===target)fs.appendFileSync(root+"/read-flags.jsonl",JSON.stringify({flags})+String.fromCharCode(10),{mode:0o600});return original(path,flags,...args);};}
if(["read-zero","read-overcount","short-read"].includes(mode)) {const original=fs.readSync;fs.readSync=(fd,b,offset,length,position)=>mode==="read-zero"?0:mode==="read-overcount"?length+1:original(fd,b,offset,Math.min(3,length),position);}
if(mode==="eof-extra") {const original=fs.readSync;fs.readSync=(fd,b,offset,length,position)=>position>=fs.fstatSync(fd).size?1:original(fd,b,offset,length,position);}
if(mode==="unlink") {fs.unlinkSync=()=>{throw new Error("private unlink error");};}
if(mode==="directory-fsync") {const original=fs.fsyncSync;fs.fsyncSync=fd=>{if(fs.fstatSync(fd).isDirectory())throw new Error("private directory IO error");return original(fd);};}
if(mode==="read-close") {const original=fs.closeSync;let armed=true;fs.closeSync=fd=>{original(fd);if(armed){armed=false;throw new Error("private close error");}};}
syncBuiltinESMExports();
queueMicrotask(()=>fs.writeFileSync(root+"/after-microtask","bad"));
if(["discovered-wire","batch","batch-hash","batch-hash-reverse"].includes(mode)) {
 let values=mode==="batch"?["sequence","type"]:["sequence"];
 if(mode.startsWith("batch-hash")) {values=[JSON.parse(fs.readFileSync(attempt.files.request,"utf8")).requestWire.sha256,JSON.parse(fs.readFileSync(attempt.files.intent,"utf8")).boundary];if(mode.endsWith("reverse"))values.reverse();values=[values.join(",")];}
 const body=Buffer.from(JSON.stringify({name:"owned/object",downloadTokens:values}));
 const responseWire=Buffer.concat([Buffer.from("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n"),body]);
 attempt.appendResponse(responseWire);
 attempt.finish({complete:true,reason:null,status:200,finishConfirmed:true,socketReportedWrittenBytes:Number(fs.readFileSync(root+"/request-length","utf8")),requestReservedBytes:Number(fs.readFileSync(root+"/request-length","utf8")),responseObservedBytes:responseWire.length,rawResponseHeaders:["Content-Type","application/json"],responseBodyBase64:body.toString("base64")});
} else if(mode==="work-budget") {for(let i=0;i<64;i++)registry.register("fixture-unrelated-new-secret-"+"QZ".repeat(24)+i);}
else registry.register(mode==="short-digit"?"1":"sequence");
fs.writeFileSync(root+"/normal-return","bad");
`;
  try {
    fs.writeFileSync(source, script, { mode: 0o600 });
    const child = spawnSync(process.execPath, [source], {
      encoding: "utf8",
      timeout: 10000,
      env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 2, child.stderr);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr, "");
    assert.equal(fs.existsSync(root + "/started-held"), true);
    for (const name of ["normal-return", "after-microtask", "end-row", "unlock"])
      assert.equal(fs.existsSync(root + "/" + name), false, name);
    const saved = JSON.parse(fs.readFileSync(root + "/saved.json"));
    assert.ok(saved.length > 0);
    if (mode === "open-flags") {
      const flags = fs
        .readFileSync(root + "/read-flags.jsonl", "utf8")
        .trim()
        .split(String.fromCharCode(10))
        .map((line) => JSON.parse(line).flags);
      assert.equal(flags.length, 2);
      for (const value of flags) {
        assert.ok(value & fs.constants.O_NONBLOCK);
        assert.ok(value & fs.constants.O_NOFOLLOW);
      }
    }
    const uncertain = [
      "foreign-inode",
      "hardlink",
      "symlink",
      "same-inode-edit",
      "parent-mode",
      "parent-inode",
      "closed-registry",
      "read-zero",
      "read-overcount",
      "eof-extra",
      "unlink",
      "directory-fsync",
      "read-close",
      "work-budget",
      "pending-artifact",
      "pending-wire",
    ].includes(mode);
    if (!uncertain)
      for (const row of saved) {
        if (mode === "preserve-safe" && row.name.endsWith("-intent.json")) {
          assert.equal(
            fs.readFileSync(directory + "/" + row.name, "utf8"),
            JSON.stringify("safe-prototype-bytes"),
          );
          assert.equal(fs.lstatSync(directory + "/" + row.name).ino, row.ino);
        } else
          assert.equal(
            fs.existsSync(directory + "/" + row.name),
            false,
            row.name + " must be removed on later discovery",
          );
      }
    if (["foreign-inode", "symlink"].includes(mode)) {
      assert.equal(fs.existsSync(directory + "/" + saved[0].name), true);
      assert.equal(fs.existsSync(root + "/original-owned"), true);
    }
    if (mode === "foreign-inode")
      assert.notEqual(fs.lstatSync(directory + "/" + saved[0].name).ino, saved[0].ino);
    if (mode === "symlink")
      assert.equal(
        fs.readFileSync(root + "/foreign-file", "utf8"),
        JSON.stringify({ sequence: 1 }),
      );
    if (mode === "hardlink")
      assert.equal(fs.lstatSync(root + "/linked-original").ino, saved[0].ino);
    if (["read-zero", "read-overcount", "unlink", "read-close", "same-inode-edit"].includes(mode))
      assert.equal(fs.existsSync(directory + "/" + saved[0].name), true);
    if (mode === "parent-inode")
      assert.equal(fs.lstatSync(root + "/original-directory/" + saved[0].name).ino, saved[0].ino);
    if (["parent-mode", "parent-inode"].includes(mode)) {
      assert.equal(fs.existsSync(directory + "/privacy-r" + recording + ".json"), false);
      return;
    }
    const audit = JSON.parse(fs.readFileSync(directory + "/privacy-r" + recording + ".json"));
    assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
    assert.equal(
      audit.reason,
      uncertain ? "artifact-past-scan-uncertain" : "artifact-removed-late-secret",
    );
    assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
    assert.ok(Number.isFinite(Date.parse(audit.timestamp)));
    if (!uncertain)
      assert.equal(fs.readdirSync(directory).length, mode === "preserve-safe" ? 2 : 1);
  } finally {
    fs.rmSync(root, { recursive: true });
  }
}
for (const recording of [1, 2]) {
  for (const kind of artifacts)
    test(`recording ${recording} removes the original past ${kind} artifact before returning from secret registration`, () =>
      fixture(recording, "register", [kind], []));
  for (const kind of wires)
    test(`recording ${recording} removes the original past wire ${kind} before returning from secret registration`, () =>
      fixture(recording, "register", [], [kind]));
  test(`recording ${recording} discovers all response values before scanning and removing past files`, () =>
    fixture(recording, "batch", [], ["request", "intent"]));
  for (const mode of [
    "foreign-inode",
    "hardlink",
    "symlink",
    "same-inode-edit",
    "parent-mode",
    "parent-inode",
    "closed-registry",
    "read-zero",
    "read-overcount",
    "eof-extra",
    "unlink",
    "directory-fsync",
    "read-close",
    "short-read",
    "open-flags",
  ])
    test(`recording ${recording} owns the past-artifact ${mode} boundary`, () =>
      fixture(recording, mode, ["journal"], []));
  for (const mode of ["cross-recording", "work-budget", "short-digit"])
    test(`recording ${recording} preserves the ${mode} inventory contract`, () =>
      fixture(recording, mode, ["journal"], []));
  test(`recording ${recording} tracks the original pending artifact before the first write`, () =>
    fixture(recording, "pending-artifact", ["journal"], []));
  test(`recording ${recording} tracks the original pending wire before the first write`, () =>
    fixture(recording, "pending-wire", [], ["request"]));
  for (const mode of ["batch-hash", "batch-hash-reverse"])
    test(`recording ${recording} removes request hash and intent enum discovered together in ${mode}`, () =>
      fixture(recording, mode, [], []));
  test(`recording ${recording} preserves nonmatching original file bytes and inode`, () =>
    fixture(recording, "preserve-safe", [], ["request", "intent"]));
  test(`recording ${recording} removes all writer kinds after actual download-token discovery`, () =>
    fixture(recording, "discovered-wire", artifacts, wires));
}
