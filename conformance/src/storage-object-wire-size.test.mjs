import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
const moduleURL = (file) => new URL("./storage-object/" + file, import.meta.url).href;
for (const recording of [1, 2])
  for (const mode of [
    "raw-large",
    "replaced-large",
    "unknown-large",
    "scan-uncheckable",
    "metadata-collision",
  ]) {
    test(
      "recording " +
        recording +
        " bounds the " +
        mode +
        " wire representation before its final secret scan",
      () => {
        const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-wire-size-")));
        fs.chmodSync(root, 0o700);
        const script = `
import fs from "node:fs";import {createHash} from "node:crypto";
import {createProductionWireAttempt} from ${JSON.stringify(moduleURL("production-wire-capture.mjs"))};
import {createProductionCaptureProfile} from ${JSON.stringify(moduleURL("production-capture-coverage.mjs"))};
import {createProductionSecretRegistry} from ${JSON.stringify(moduleURL("production-secret-registry.mjs"))};
import {createProductionArtifactProfile} from ${JSON.stringify(moduleURL("production-artifact-policy.mjs"))};
import {createProductionStandaloneFailStop} from ${JSON.stringify(moduleURL("production-standalone-fail-stop.mjs"))};
import {buildProductionStage3DraftPlan} from ${JSON.stringify(moduleURL("stage3-plan.mjs"))};
import {buildCorpus} from ${JSON.stringify(moduleURL("corpus.mjs"))};
import {MAX_RESPONSE_BODY_BYTES,HTTP_RESPONSE_READ_UNIT_BYTES} from ${JSON.stringify(moduleURL("wire-limits.mjs"))};
const root=${JSON.stringify(root)},recording=${recording},mode=${JSON.stringify(mode)},directory=root+"/capture";fs.mkdirSync(directory,{mode:0o700});
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const objectName=buildCorpus({bucket:plan.bucket,prefix:plan.recordings[recording-1].prefix}).recipes[0].objects[0],url="https://storage.googleapis.com/storage/v1/b/"+plan.bucket+"/o/"+encodeURIComponent(objectName);
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:mode==="scan-uncheckable"?1:16777216});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"},profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile});
const token="SYNTHETIC_PADDING_DOWNLOAD_TOKEN",hash=bytes=>createHash("sha256").update(bytes).digest("hex");
registry.register(mode==="metadata-collision"?"SIZE_BOUND_COMMITMENT":"SYNTHETIC_UNRELATED_SECRET");
const metadata=JSON.stringify({kind:"storage#object",name:objectName,bucket:plan.bucket,generation:"1",metageneration:"1",size:"0",...(mode==="replaced-large"?{downloadTokens:[token]}:{}),...(mode==="unknown-large"?{unknownSchema:token}:{})});
const body=Buffer.from(metadata+" ".repeat(MAX_RESPONSE_BODY_BYTES-Buffer.byteLength(metadata)));
const requestWire=Buffer.from("GET / HTTP/1.1\\r\\n\\r\\n"),responseWire=Buffer.concat([Buffer.from("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\n\\r\\n"),body]);
let continued=false,returned=false;
process.on("exit",()=>fs.writeFileSync(root+"/metrics.json",JSON.stringify({continued,returned}),{mode:0o600}));
fs.writeFileSync(root+"/started.json","SYNTHETIC_STARTED",{mode:0o600});queueMicrotask(()=>{continued=true;});
const attempt=createProductionWireAttempt({directory,sequence:1,request:{url,method:"GET",headers:[],body:Buffer.alloc(0),wire:requestWire},metadata:{operationId:"r"+recording+"/p1/"+hash("fixture-large"),phase:"subject"},policy:{secretRegistry:registry,captureProfile:createProductionCaptureProfile({kind:"storage",objectName,method:"GET",url,sessionPhase:null}),expectedBucket:plan.bucket,expectedObjectNames:[objectName],artifactProfile:profile,standaloneBoundary:boundary}});
for(let offset=0;offset<responseWire.length;offset+=HTTP_RESPONSE_READ_UNIT_BYTES)attempt.appendResponse(responseWire.subarray(offset,offset+HTTP_RESPONSE_READ_UNIT_BYTES));
attempt.finish({complete:true,reason:null,status:200,finishConfirmed:true,socketReportedWrittenBytes:requestWire.length,requestReservedBytes:requestWire.length,responseObservedBytes:responseWire.length,rawResponseHeaders:["Content-Type","application/json"],responseBodyBase64:body.toString("base64")});
returned=true;fs.writeFileSync(root+"/after.json",JSON.stringify({bodySha256:hash(body),wireSha256:hash(responseWire),registry:registry.snapshot()}),{mode:0o600});registry.close();
`;
        const path = join(root, "fixture.mjs");
        fs.writeFileSync(path, script, { mode: 0o600 });
        try {
          const child = spawnSync(process.execPath, [path], {
            encoding: "utf8",
            timeout: 5000,
            env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR ?? tmpdir() },
          });
          assert.equal(child.error, undefined);
          assert.equal(child.signal, null);
          assert.equal(child.stdout, "");
          assert.equal(child.stderr, "");
          const normal = ["raw-large", "replaced-large"].includes(mode),
            metrics = JSON.parse(fs.readFileSync(join(root, "metrics.json")));
          assert.equal(child.status, normal ? 0 : 2);
          assert.equal(metrics.returned, normal);
          assert.equal(metrics.continued, normal);
          assert.equal(fs.existsSync(join(root, "started.json")), true);
          assert.equal(fs.existsSync(join(root, "end.json")), false);
          if (normal) {
            const after = JSON.parse(fs.readFileSync(join(root, "after.json"))),
              result = JSON.parse(fs.readFileSync(join(root, "capture", "000001-result.json")));
            assert.equal(result.complete, true);
            assert.equal(result.status, 200);
            assert.equal(result.response.mode, "COMMITMENT_ONLY");
            assert.equal(result.response.bodyBase64, null);
            assert.equal(result.response.originalByteLength, 2097152);
            assert.equal(result.response.originalSha256, after.bodySha256);
            assert.deepEqual(result.response.observation, {
              byteLength: 2097152,
              sha256: after.bodySha256,
            });
            assert.equal(result.responseWire.sha256, after.wireSha256);
            assert.equal(after.registry.failed, false);
            assert.equal(after.registry.closed, false);
            if (mode === "replaced-large") assert.equal(after.registry.values, 2);
            for (const name of fs.readdirSync(join(root, "capture"))) {
              const bytes = fs.readFileSync(join(root, "capture", name));
              assert.ok(bytes.length <= 2097152);
              assert.equal(bytes.includes(Buffer.from("SYNTHETIC_PADDING_DOWNLOAD_TOKEN")), false);
              assert.equal(fs.statSync(join(root, "capture", name)).mode & 0o777, 0o600);
            }
          } else {
            const audit = JSON.parse(
              fs.readFileSync(join(root, "capture", "privacy-r" + recording + ".json")),
            );
            assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
            assert.equal(
              audit.reason,
              mode === "metadata-collision" ? "artifact-withheld-privacy" : "artifact-uncheckable",
            );
            assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
            assert.equal(fs.existsSync(join(root, "after.json")), false);
          }
        } finally {
          fs.rmSync(root, { recursive: true });
        }
      },
    );
  }
