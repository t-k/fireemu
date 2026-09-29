import assert from "node:assert/strict";
import fs from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
const url = (file) => new URL(`./storage-object/${file}`, import.meta.url).href;
test("owned wire binds the original providers, task profile and failure directory without caller hooks", () => {
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-owned-wire-")));
  fs.chmodSync(root, 0o700);
  const script = join(root, "fixture.mjs");
  const source = `
import fs from "node:fs"; import { join } from "node:path";
import { createProductionWireTransport } from ${JSON.stringify(url("production-wire-transport.mjs"))};
import { createProductionCredentialProviders } from ${JSON.stringify(url("production-provider-boundary.mjs"))};
import { createProductionSecretRegistry } from ${JSON.stringify(url("production-secret-registry.mjs"))};
import { createProductionArtifactProfile } from ${JSON.stringify(url("production-artifact-policy.mjs"))};
import { createProductionStandaloneFailStop } from ${JSON.stringify(url("production-standalone-fail-stop.mjs"))};
import { buildProductionStage3DraftPlan } from ${JSON.stringify(url("stage3-plan.mjs"))};
const root=${JSON.stringify(root)},directory=join(root,"capture"),otherDirectory=join(root,"other");for(const d of [directory,otherDirectory])fs.mkdirSync(d,{mode:0o700});
const plan=buildProductionStage3DraftPlan({projectId:"example-project",bucket:"example.appspot.com",runIds:["recordone","recordtwo"]});
const resources={projectNumber:"123456789012",apiKeyResource:"projects/123456789012/locations/global/keys/fixture-key",rulesetResource:"projects/example-project/rulesets/fixture-ruleset"};
const limits={maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216},registry=createProductionSecretRegistry(limits),otherRegistry=createProductionSecretRegistry(limits);
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),otherProfile=createProductionArtifactProfile({plan,resources,secretRegistry:registry});
const boundary=createProductionStandaloneFailStop({directory,profile}),foreignBoundary=createProductionStandaloneFailStop({directory:otherDirectory,profile}),legacyBoundary=createProductionStandaloneFailStop({directory});
const providers=createProductionCredentialProviders({boundary,registry}),foreignProviders=createProductionCredentialProviders({boundary:foreignBoundary,registry}),legacyProviders=createProductionCredentialProviders({boundary:legacyBoundary,registry});
const alternatePlan=buildProductionStage3DraftPlan({projectId:plan.projectId,bucket:plan.bucket,runIds:["recordthree","recordfour"]}),alternateProfile=createProductionArtifactProfile({plan:alternatePlan,resources,secretRegistry:registry}),alternateBoundary=createProductionStandaloneFailStop({directory,profile:alternateProfile}),alternateProviders=createProductionCredentialProviders({boundary:alternateBoundary,registry});
const base={plan,resources,captureDirectory:directory,credentialProviders:providers,secretRegistry:registry,artifactProfile:profile,standaloneBoundary:boundary,onByteReserve:()=>{},verifyAdmission:()=>true};
let hooks=0;const records=[],opened=[];
for (const [name,changes,accept] of [
 ["original",{},true],
 ["copied-profile",{artifactProfile:{...profile}},false],
 ["copied-boundary",{standaloneBoundary:{...boundary}},false],
 ["different-profile",{artifactProfile:otherProfile},false],
 ["different-registry",{secretRegistry:otherRegistry},false],
 ["foreign-boundary",{standaloneBoundary:foreignBoundary},false],
 ["foreign-providers",{credentialProviders:foreignProviders},false],
 ["paired-foreign-directory",{standaloneBoundary:foreignBoundary,credentialProviders:foreignProviders},false],
 ["alternate-run-ids",{artifactProfile:alternateProfile,standaloneBoundary:alternateBoundary,credentialProviders:alternateProviders},false],
 ["foreign-bucket-with-same-run-ids",{plan:buildProductionStage3DraftPlan({projectId:plan.projectId,bucket:"other.appspot.com",runIds:plan.recordings.map(row=>row.runId)})},false],
 ["foreign-project-with-same-run-ids",{plan:buildProductionStage3DraftPlan({projectId:"other-project",bucket:plan.bucket,runIds:plan.recordings.map(row=>row.runId)}),resources:{...resources,rulesetResource:"projects/other-project/rulesets/fixture-ruleset"}},false],
 ["legacy-providers",{credentialProviders:legacyProviders},false],
 ["legacy-boundary",{standaloneBoundary:legacyBoundary},false],
 ["missing-boundary",{standaloneBoundary:undefined},false],
 ["missing-profile",{artifactProfile:undefined},false],
 ["copied-providers",{credentialProviders:{...providers}},false],
 ["unbound-callbacks",{credentialProviders:undefined,ownerAuthorization:()=>"Bearer SYNTHETIC",accountAuthorization:()=>"Firebase SYNTHETIC"},false],
]) {
 let accepted=false,wire;try{wire=createProductionWireTransport({...base,...changes});accepted=true;}catch(error){if(error.message!=="invalid production wire configuration")throw error;}
 if(wire)opened.push(wire);records.push({name,accepted,expected:accept});
}
const config={...base};Object.defineProperty(config,"artifactProfile",{enumerable:true,get(){hooks++;throw new Error("SYNTHETIC_UNSAFE_GETTER");}});try{createProductionWireTransport(config);records.push({name:"accessor",accepted:true,expected:false});}catch{records.push({name:"accessor",accepted:false,expected:false});}
for(const wire of opened)await wire.close();
fs.writeFileSync(join(root,"results.json"),JSON.stringify({records,hooks}),{mode:0o600});
`;
  fs.writeFileSync(script, source, { mode: 0o600 });
  try {
    const child = spawnSync(process.execPath, [script], {
      encoding: "utf8",
      timeout: 5000,
      cwd: root,
      env: { PATH: process.env.PATH, TMPDIR: process.env.TMPDIR ?? tmpdir() },
    });
    assert.equal(child.error, undefined);
    assert.equal(child.status, 0);
    assert.equal(child.stdout, "");
    assert.equal(child.stderr, "");
    const { records, hooks } = JSON.parse(fs.readFileSync(join(root, "results.json"), "utf8"));
    assert.equal(records.length, 18);
    assert.equal(hooks, 0);
    assert.deepEqual(
      records.map(({ name, accepted }) => ({ name, accepted })),
      records.map(({ name, expected }) => ({ name, accepted: expected })),
    );
  } finally {
    fs.rmSync(root, { recursive: true });
  }
});
