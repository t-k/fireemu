import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
const url = (file) => new URL(`./storage-object/${file}`, import.meta.url).href;
for (const recording of [1, 2]) {
  for (const mode of [
    "intent",
    "response",
    "discovery",
    "safe",
    "request-dir-fsync",
    "intent-dir-fsync",
    "response-dir-fsync",
    "result-dir-fsync",
  ]) {
    test(`recording ${recording} connects owned ${mode} capture to actual memory TLS dispatch`, () => {
      const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-owned-wire-privacy-")));
      fs.chmodSync(root, 0o700);
      const script = join(root, "fixture.mjs");
      const source = `
import fs from "node:fs"; import { join } from "node:path"; import tls from "node:tls"; import { Duplex } from "node:stream"; import { createHash } from "node:crypto"; import { syncBuiltinESMExports } from "node:module";
import { createProductionWireTransport } from ${JSON.stringify(url("production-wire-transport.mjs"))};
import { createProductionCredentialProviders } from ${JSON.stringify(url("production-provider-boundary.mjs"))};
import { createProductionSecretRegistry } from ${JSON.stringify(url("production-secret-registry.mjs"))};
import { createProductionArtifactProfile } from ${JSON.stringify(url("production-artifact-policy.mjs"))};
import { createProductionStandaloneFailStop } from ${JSON.stringify(url("production-standalone-fail-stop.mjs"))};
import { buildProductionStage3DraftPlan } from ${JSON.stringify(url("stage3-plan.mjs"))};
import { buildCorpus } from ${JSON.stringify(url("corpus.mjs"))};
const root=${JSON.stringify(root)},recording=${recording},mode=${JSON.stringify(mode)},directory=join(root,"capture");fs.mkdirSync(directory,{mode:0o700});
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216}),profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile}),providers=createProductionCredentialProviders({boundary,registry});
const step={...buildCorpus({bucket:plan.bucket,prefix:plan.recordings[recording-1].prefix}).recipes[0].steps.find(row=>row.id==="metadata"),credential:"none"};
const body=Buffer.from(JSON.stringify({name:step.objectName,generation:"1",...(mode==="discovery"?{downloadTokens:["readUnits"]}:{})}));
const responseWire=Buffer.concat([Buffer.from("HTTP/1.1 200 OK\\r\\nContent-Type: application/json\\r\\nContent-Length: "+body.length+"\\r\\nConnection: close\\r\\n\\r\\n"),body]);
const hash=bytes=>createHash("sha256").update(bytes).digest("hex"),secret=mode==="intent"?"HTTP_PLAINTEXT_COMMITMENT_AND_SANITIZED_BODY":mode==="response"?hash(responseWire):"SYNTHETIC_UNRELATED_CREDENTIAL";
registry.register(secret);let sockets=0,reservations=0,continued=false,unhandled=0,directoryFsyncs=0,fileFsyncs=0,responseOpenedBeforeSocket=false;
const io=Object.fromEntries(["openSync","fsyncSync","closeSync"].map(name=>[name,fs[name]])),fdKinds=new Map();let activeKind;
fs.openSync=function(path,flags,...args){const fd=io.openSync(path,flags,...args);const kind=/000001-(request|intent|response|result)[.]json$/.exec(String(path))?.[1];if(kind){activeKind=kind;fdKinds.set(fd,kind);if(kind==="response"&&sockets===0)responseOpenedBeforeSocket=true;}else if(path===directory)fdKinds.set(fd,"directory");return fd;};
fs.fsyncSync=function(fd){const kind=fdKinds.get(fd);if(kind==="directory"){directoryFsyncs++;if(mode===activeKind+"-dir-fsync")throw new Error("SYNTHETIC_DIRECTORY_FSYNC");}else if(kind)fileFsyncs++;return io.fsyncSync(fd);};
fs.closeSync=function(fd){fdKinds.delete(fd);return io.closeSync(fd);};syncBuiltinESMExports();
process.on("unhandledRejection",()=>{unhandled++;});process.on("exit",()=>fs.writeFileSync(join(root,"metrics.json"),JSON.stringify({sockets,reservations,continued,unhandled,directoryFsyncs,fileFsyncs,responseOpenedBeforeSocket}),{mode:0o600}));
tls.connect=options=>{
 sockets++;let bytes=Buffer.alloc(0),responded=false;
 const socket=new Duplex({read(){},write(chunk,encoding,done){bytes=Buffer.concat([bytes,chunk]);socket.bytesWritten+=chunk.length;const boundary=bytes.indexOf("\\r\\n\\r\\n");const count=/content-length: (\\d+)/i.exec(bytes.toString())?.[1];if(!responded&&boundary>=0&&bytes.length===boundary+4+Number(count)){responded=true;queueMicrotask(()=>{for(let offset=0;offset<responseWire.length;offset+=37)options.onread.callback(Math.min(37,responseWire.length-offset),responseWire.subarray(offset,offset+37));socket.push(null);});}done();}});
 Object.assign(socket,{bytesWritten:0,authorized:true,alpnProtocol:"http/1.1",encrypted:true,setTimeout(){return this;},setNoDelay(){return this;},setKeepAlive(){return this;}});queueMicrotask(()=>socket.emit("secureConnect"));return socket;
};
const wire=createProductionWireTransport({plan,resources,captureDirectory:directory,credentialProviders:providers,secretRegistry:registry,artifactProfile:profile,standaloneBoundary:boundary,onByteReserve:()=>{reservations++;},verifyAdmission:()=>true});
fs.writeFileSync(join(root,"started.json"),JSON.stringify({state:"started",recording}),{mode:0o600});
try{const response=await wire.fetchStorage(recording,step,{operationId:"r"+recording+"/p1/"+hash(step.id),accountingPhase:"subject"});fs.writeFileSync(join(root,"response-status.json"),JSON.stringify({status:response.status}),{mode:0o600});}catch{fs.writeFileSync(join(root,"caught.json"),"unexpected normal rejection");}
continued=true;await wire.close();fs.writeFileSync(join(root,"after.json"),"returned to caller");
`;
      fs.writeFileSync(script, source, { mode: 0o600 });
      try {
        const child = spawnSync(process.execPath, [script], {
          encoding: "utf8",
          cwd: root,
          timeout: 5000,
          env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR ?? tmpdir() },
        });
        assert.equal(child.error, undefined);
        assert.equal(child.stdout, "");
        assert.equal(child.stderr, "");
        const metrics = JSON.parse(fs.readFileSync(join(root, "metrics.json"), "utf8"));
        assert.equal(metrics.unhandled, 0);
        assert.equal(
          metrics.sockets,
          ["intent", "request-dir-fsync", "intent-dir-fsync"].includes(mode) ? 0 : 1,
        );
        assert.equal(metrics.continued, mode === "safe");
        assert.equal(fs.existsSync(join(root, "started.json")), true);
        assert.equal(fs.existsSync(join(root, "caught.json")), false);
        assert.equal(fs.existsSync(join(root, "after.json")), mode === "safe");
        assert.equal(child.status, mode === "safe" ? 0 : 2);
        if (mode === "safe") {
          assert.equal(metrics.directoryFsyncs, 4);
          assert.equal(metrics.fileFsyncs, 4);
          assert.equal(metrics.responseOpenedBeforeSocket, false);
          assert.equal(
            JSON.parse(fs.readFileSync(join(root, "response-status.json"), "utf8")).status,
            200,
          );
        } else if (mode.endsWith("-dir-fsync")) {
          const fatal = JSON.parse(
            fs.readFileSync(join(root, "capture", `fatal-r${recording}.json`), "utf8"),
          );
          assert.equal(fatal.reason, "PERSISTENCE_UNCERTAIN");
          assert.equal(fatal.recording, recording);
          assert.equal(fs.existsSync(join(root, "response-status.json")), false);
        } else {
          const audit = JSON.parse(
            fs.readFileSync(join(root, "capture", `privacy-r${recording}.json`), "utf8"),
          );
          assert.deepEqual(Object.keys(audit).toSorted(), ["reason", "runId", "timestamp"]);
          assert.equal(audit.reason, "artifact-withheld-privacy");
          assert.equal(audit.runId, recording === 1 ? "recordone" : "recordtwo");
          assert.equal(fs.existsSync(join(root, "response-status.json")), false);
        }
      } finally {
        fs.rmSync(root, { recursive: true });
      }
    });
  }
}
