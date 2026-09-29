import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const modules = Object.fromEntries(
  [
    ["capture", "production-wire-capture.mjs"],
    ["profile", "production-artifact-policy.mjs"],
    ["boundary", "production-standalone-fail-stop.mjs"],
    ["registry", "production-secret-registry.mjs"],
    ["coverage", "production-capture-coverage.mjs"],
    ["plan", "stage3-plan.mjs"],
  ].map(([name, file]) => [name, new URL(`./storage-object/${file}`, import.meta.url).href]),
);
const cases = [
  ["request", "artifact-withheld-privacy"],
  ["intent", "artifact-withheld-privacy"],
  ["response", "artifact-withheld-privacy"],
  ["newline", "artifact-withheld-privacy"],
  ["discovery", "artifact-withheld-privacy"],
  ["later-sequence", "artifact-removed-late-secret"],
  ["unknown", "artifact-uncheckable"],
  ["scan", "artifact-uncheckable"],
];
for (const recording of [1, 2]) {
  for (const [mode, expectedReason] of cases) {
    test(`recording ${recording} owns the synchronous wire privacy stop for ${mode}`, () => {
      const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-wire-stop-")));
      fs.chmodSync(root, 0o700);
      const capture = join(root, "capture");
      fs.mkdirSync(capture, { mode: 0o700 });
      const childPath = join(root, "fixture.mjs");
      const childSource = `
import fs from "node:fs";
import { join } from "node:path";
import { createHash } from "node:crypto";
import { createProductionWireAttempt } from ${JSON.stringify(modules.capture)};
import { createProductionArtifactProfile } from ${JSON.stringify(modules.profile)};
import { createProductionStandaloneFailStop } from ${JSON.stringify(modules.boundary)};
import { createProductionSecretRegistry } from ${JSON.stringify(modules.registry)};
import { createProductionCaptureProfile } from ${JSON.stringify(modules.coverage)};
import { buildProductionStage3DraftPlan } from ${JSON.stringify(modules.plan)};
const mode=${JSON.stringify(mode)},recording=${recording},root=${JSON.stringify(root)},directory=${JSON.stringify(capture)};
const hash=(bytes)=>createHash("sha256").update(bytes).digest("hex");
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:mode==="scan"?1:16777216});
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry});
const boundary=createProductionStandaloneFailStop({directory,profile});
fs.writeFileSync(join(root,"started.json"),JSON.stringify({state:"started",recording}),{mode:0o600});
queueMicrotask(()=>fs.writeFileSync(join(root,"later-microtask.json"),"unexpected continuation"));
const requestWire=Buffer.from("GET / HTTP/1.1\\r\\n\\r\\n");
const body=["discovery","later-sequence"].includes(mode)?Buffer.from(JSON.stringify({name:"owned/object",downloadTokens:[mode==="later-sequence"?"sequence":"readUnits"]})):Buffer.from("{}");
const responseWire=Buffer.concat([Buffer.from("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n"),body]);
const secret=mode==="request"?hash(requestWire):mode==="intent"?"HTTP_PLAINTEXT_COMMITMENT_AND_SANITIZED_BODY":mode==="response"?hash(responseWire):mode==="newline"?"\\n":"SYNTHETIC_UNRELATED_CREDENTIAL";
registry.register(secret);
fs.writeFileSync(join(root,"synthetic-secret.json"),JSON.stringify({secret:mode==="later-sequence"?"sequence":mode==="discovery"?"readUnits":secret}),{mode:0o600});
const url="https://storage.googleapis.com/storage/v1/b/example.appspot.com/o/owned%2Fobject";
try {
 const attempt=createProductionWireAttempt({directory,sequence:1,request:{url,method:"GET",headers:[],body:Buffer.alloc(0),wire:requestWire},metadata:{operationId:"r"+recording+"/p1/"+"a".repeat(64),phase:"subject"},policy:{secretRegistry:registry,artifactProfile:profile,standaloneBoundary:boundary,captureProfile:createProductionCaptureProfile({kind:"storage",objectName:"owned/object",method:"GET",url,sessionPhase:null}),expectedBucket:"example.appspot.com",expectedObjectNames:["owned/object"]}});
 attempt.appendResponse(responseWire);
 attempt.finish({complete:mode!=="unknown",reason:mode==="unknown"?"WIRE_TRUNCATED":null,status:200,finishConfirmed:true,socketReportedWrittenBytes:requestWire.length,requestReservedBytes:requestWire.length,responseObservedBytes:responseWire.length,rawResponseHeaders:["Content-Type","application/json"],responseBodyBase64:body.toString("base64")});
} catch { /* Source-only comparison catches the legacy prototype to expose any normal continuation. */ }
fs.writeFileSync(join(root,"returned.json"),"unexpected continuation");
`;
      fs.writeFileSync(childPath, childSource, { mode: 0o600 });
      try {
        const child = spawnSync(process.execPath, [childPath], {
          cwd: root,
          encoding: "utf8",
          timeout: 5000,
          env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR ?? tmpdir() },
        });
        assert.equal(child.error, undefined);
        assert.equal(child.status, 2);
        assert.equal(child.stdout, "");
        assert.equal(child.stderr, "");
        assert.equal(fs.existsSync(join(root, "started.json")), true);
        assert.equal(fs.existsSync(join(root, "returned.json")), false);
        assert.equal(fs.existsSync(join(root, "later-microtask.json")), false);
        assert.equal(fs.existsSync(join(root, "ended.json")), false);
        assert.equal(fs.existsSync(join(root, "unlocked.json")), false);
        const auditPath = join(capture, `privacy-r${recording}.json`);
        assert.equal(fs.existsSync(auditPath), true, "a fixed source privacy audit is required");
        const audit = JSON.parse(fs.readFileSync(auditPath, "utf8"));
        assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
        assert.equal(audit.reason, expectedReason);
        assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
        assert.equal(Number.isFinite(Date.parse(audit.timestamp)), true);
        assert.equal(fs.statSync(auditPath).mode & 0o777, 0o600);
        const { secret } = JSON.parse(fs.readFileSync(join(root, "synthetic-secret.json"), "utf8"));
        for (const file of fs.readdirSync(capture)) {
          if (file.startsWith("privacy-")) continue;
          assert.equal(fs.readFileSync(join(capture, file), "utf8").includes(secret), false);
        }
      } finally {
        fs.rmSync(root, { recursive: true });
      }
    });
  }
}
