import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  writeFileSync,
  existsSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createStage3WireBudget } from "./storage-object/wire-budget.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import {
  createStage3RequestCounter,
  claimStage3RecipeContext,
} from "./storage-object/request-counter.mjs";
import { createProductionSecretRegistry } from "./storage-object/production-secret-registry.mjs";
import { createProductionArtifactProfile } from "./storage-object/production-artifact-policy.mjs";
import { createProductionStandaloneFailStop } from "./storage-object/production-standalone-fail-stop.mjs";

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
const ids = [
  ...buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes,
  ...buildAuthCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    runId: plan.recordings[0].runId,
  }).recipes,
].map((row) => row.id);
async function fixture(action) {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-artifact-channels-")));
  chmodSync(directory, 0o700);
  const registry = createProductionSecretRegistry({
    maxValues: 81,
    maxUtf8Bytes: 65536,
    maxIndexNodes: 200000,
    maxScanCodeUnits: 16777216,
  });
  const profile = createProductionArtifactProfile({ plan, resources, secretRegistry: registry });
  const boundary = createProductionStandaloneFailStop({ directory, profile });
  try {
    const api = await import("./storage-object/production-artifact-channels.mjs");
    const channels = api.createProductionArtifactChannels({ directory, profile, boundary, plan });
    return await action({ api, channels, directory, registry, profile, boundary });
  } finally {
    registry.close();
    rmSync(directory, { recursive: true, force: true });
  }
}
function stored(directory) {
  return readdirSync(directory)
    .filter((name) => name.startsWith("artifact-"))
    .toSorted()
    .map((name) => JSON.parse(readFileSync(join(directory, name))));
}
function counterFor(channels) {
  return createStage3RequestCounter(plan, {
    onStart: channels.counter.onStart,
    onReserve: channels.counter.onReserve,
    recipeLifecycle: {
      recipeIds: ids,
      onBegin: channels.counter.onBegin,
      onFinish: channels.counter.onFinish,
      // This fixture inventories actual callback DTOs, not actual terminal proof.
      verifyTerminal: () => true,
    },
  });
}

test("source-owned channels persist actual counter DTOs across all 26 recipes and both recordings", async () => {
  await fixture(async ({ channels, directory }) => {
    const counter = counterFor(channels);
    await counter.start();
    for (const recording of [1, 2]) {
      if (recording === 2) await counter.startNextProductionRecording();
      for (const id of ids) {
        const token = await counter.beginRecipe(id),
          context = claimStage3RecipeContext(token, plan);
        await context.counter.start();
        await context.counter.send("fixture-operation", () => undefined);
        context.counter.beginCleanup();
        context.counter.close();
        await counter.finishRecipe(token);
      }
    }
    counter.close();
    const rows = stored(directory);
    assert.equal(rows.length, 158);
    assert.equal(rows.filter((row) => row.artifactKind === "ledger").length, 2);
    assert.equal(rows.filter((row) => row.artifactKind === "intent").length, 52);
    for (const recording of [1, 2])
      assert.equal(rows.filter((row) => row.data.recording === recording).length, 79);
    assert.equal(
      rows.every((row) => row.taskSecretStatus === "AVAILABLE"),
      true,
    );
  });
});

test("callback identity binds the original owner, role, recording and recipe without caller hooks", async () => {
  await fixture(({ api, channels, profile, boundary, directory }) => {
    assert.equal(
      api.productionArtifactChannelsUseContext(channels, { directory, profile, boundary, plan }),
      true,
    );
    assert.equal(
      api.productionArtifactChannelsUseContext(
        { ...channels },
        { directory, profile, boundary, plan },
      ),
      false,
    );
    const recording = channels.forRecording(1),
      recipe = channels.forRecipe(1, ids[0]);
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recording.onOwnerProof,
        channels,
        "owner-proof",
        1,
        null,
      ),
      true,
    );
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recording.onOwnerProof,
        channels,
        "auth-proof",
        1,
        null,
      ),
      false,
    );
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recording.onOwnerProof,
        channels,
        "owner-proof",
        2,
        null,
      ),
      false,
    );
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recipe.onJournal,
        channels,
        "storage-journal",
        1,
        ids[0],
      ),
      true,
    );
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recipe.onJournal,
        channels,
        "storage-journal",
        1,
        ids[1],
      ),
      false,
    );
    const other = api.createProductionArtifactChannels({ directory, profile, boundary, plan });
    assert.equal(
      api.isProductionArtifactChannelCallback(
        recipe.onJournal,
        other,
        "storage-journal",
        1,
        ids[0],
      ),
      false,
    );
    assert.equal(
      api.isProductionArtifactChannelCallback(
        (...args) => recipe.onJournal(...args),
        channels,
        "storage-journal",
        1,
        ids[0],
      ),
      false,
    );
    let hooks = 0;
    const proxy = new Proxy(recipe.onJournal, {
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.equal(
      api.isProductionArtifactChannelCallback(proxy, channels, "storage-journal", 1, ids[0]),
      false,
    );
    assert.equal(hooks, 0);
    assert.equal(channels.forRecording(1), recording);
    assert.equal(channels.forRecipe(1, ids[0]), recipe);
  });
});

test("the factory rejects a foreign plan, copied capability, injected writer and hidden input without hooks", async () => {
  await fixture(({ api, profile, boundary, directory, registry }) => {
    const changed = structuredClone(plan);
    changed.bucket = "other.appspot.com";
    for (const value of [
      { directory, profile, boundary, plan: changed },
      { directory, profile: { ...profile }, boundary, plan },
      { directory, profile, boundary: { ...boundary }, plan },
      {
        directory,
        profile,
        boundary,
        plan,
        writer: {
          write() {
            throw new Error("injection");
          },
        },
      },
    ])
      assert.throws(
        () => api.createProductionArtifactChannels(value),
        /invalid production artifact channels/,
      );
    let hooks = 0;
    const supplied = { directory, profile, boundary, plan };
    Object.defineProperty(supplied, "writer", {
      enumerable: true,
      get() {
        hooks++;
        throw new Error("hook");
      },
    });
    assert.throws(
      () => api.createProductionArtifactChannels(supplied),
      /invalid production artifact channels/,
    );
    assert.equal(hooks, 0);
    assert.equal(registry.snapshot().closed, false);
  });
});

test("Auth intent before request reservation and supplemental capture after later reads retain their actual roles", async () => {
  await fixture(async ({ channels, directory }) => {
    const counter = counterFor(channels);
    await counter.start();
    const r = channels.forRecording(1),
      authOperation = "r1/control/" + hash("fixture-auth-create");
    r.onAuthJournal({
      type: "production-auth-ownership",
      operationId: authOperation,
      accountRef: "fixture-account",
      accountMutation: "create",
    });
    await counter.send(authOperation, () => undefined);
    const token = await counter.beginRecipe(ids[0]),
      context = claimStage3RecipeContext(token, plan);
    const recipe = channels.forRecipe(1, ids[0]);
    await context.counter.start();
    await context.counter.send("fixture-mutation", () =>
      recipe.onJournal({
        bucket: plan.bucket,
        prefix: plan.recordings[0].prefix,
        name: plan.recordings[0].prefix + "fixture-object",
        operationId: "fixture-mutation",
        method: "POST",
      }),
    );
    await context.counter.send("later-metadata-absence", () => undefined);
    recipe.onCapture({
      operationId: "fixture-mutation",
      status: 204,
      headers: { authorization: "ignored-diagnostic-header" },
      bodyBase64: Buffer.from("diagnostic-body").toString("base64"),
    });
    const rows = stored(directory),
      diagnostic = rows.at(-1).data;
    assert.equal(rows[1].artifactKind, "journal");
    assert.equal(rows[2].artifactKind, "intent");
    assert.equal(diagnostic.status, 204);
    assert.equal(diagnostic.bodyByteLength, 15);
    assert.equal(Object.hasOwn(diagnostic, "sequence"), false);
    assert.equal(Object.hasOwn(diagnostic, "operationId"), false);
    assert.equal(JSON.stringify(rows).includes("diagnostic-body"), false);
    assert.equal(JSON.stringify(rows).includes("ignored-diagnostic-header"), false);
  });
});

test("actual wire budget reservations and control proof follow their durable request sequence", async () => {
  await fixture(async ({ channels, directory }) => {
    const counter = counterFor(channels);
    await counter.start();
    const budget = createStage3WireBudget(plan, { onReserve: channels.wire.onReserve });
    for (const [index, label] of ["first", "second"].entries()) {
      const operationId = "r1/control/" + hash(label);
      await counter.send(operationId, async () => {
        const attempt = await budget.reserve(operationId, 50);
        attempt.receive(20);
        attempt.finish();
        channels.forRecording(1).onControlProof({
          type: "production-control",
          slotId: "fixture-slot",
          recording: 1,
          phase: "subject",
          recipeId: null,
          placement: "recording-initial",
          operationId,
          sequence: index + 1,
          status: 200,
          bodyByteLength: 2,
          bodySha256: hash("{}"),
        });
      });
    }
    const rows = stored(directory);
    assert.equal(rows.length, 7);
    assert.deepEqual(
      rows.filter((row) => row.artifactKind === "control-proof").map((row) => row.data.sequence),
      [1, 2],
    );
  });
});

const failureModes = [
  "counter-sequence",
  "counter-semantic-without-recipe",
  "owner-recording",
  "auth-type",
  "auth-operation-recording",
  "rules-type",
  "configuration-foreign-recording",
  "unknown-proof-field",
  "foreign-vocabulary-field",
  "unreserved-storage-journal",
  "malformed-base64",
  "ambiguous-capture-id",
  "raw-and-commitment-body",
  "root-getter",
  "root-proxy",
  "raw-error",
  "fixed-error",
  "closed-channel",
  "file-fsync",
  "directory-fsync",
  "wire-duplicate-sequence",
  "recipe-operation-without-semantic",
];
for (const recording of [1, 2])
  for (const mode of failureModes) {
    test(`recording ${recording} synchronously stops the ${mode} artifact channel without hooks or continuation`, () => {
      const directory = realpathSync(mkdtempSync(join(tmpdir(), "fireemu-channel-stop-")));
      chmodSync(directory, 0o700);
      const source = join(directory, "child.mjs");
      const path = (name) => new URL("./storage-object/" + name, import.meta.url).href;
      const script = `
import * as fs from 'node:fs';
import {syncBuiltinESMExports} from 'node:module';
import {createProductionArtifactChannels} from ${JSON.stringify(path("production-artifact-channels.mjs"))};
import {createProductionArtifactProfile} from ${JSON.stringify(path("production-artifact-policy.mjs"))};
import {createProductionStandaloneFailStop} from ${JSON.stringify(path("production-standalone-fail-stop.mjs"))};
import {createProductionSecretRegistry} from ${JSON.stringify(path("production-secret-registry.mjs"))};
import {createStage3RequestCounter,claimStage3RecipeContext} from ${JSON.stringify(path("request-counter.mjs"))};
import {createHash} from 'node:crypto';
const plan=${JSON.stringify(plan)},resources=${JSON.stringify(resources)},ids=${JSON.stringify(ids)},directory=${JSON.stringify(directory)},recording=${recording},mode=${JSON.stringify(mode)};
const hash=value=>createHash('sha256').update(value).digest('hex');
const registry=createProductionSecretRegistry({maxValues:81,maxUtf8Bytes:65536,maxIndexNodes:200000,maxScanCodeUnits:16777216});
const profile=createProductionArtifactProfile({plan,resources,secretRegistry:registry}),boundary=createProductionStandaloneFailStop({directory,profile}),channels=createProductionArtifactChannels({directory,profile,boundary,plan});
const counter=createStage3RequestCounter(plan,{onStart:channels.counter.onStart,onReserve:channels.counter.onReserve,recipeLifecycle:{recipeIds:ids,onBegin:channels.counter.onBegin,onFinish:channels.counter.onFinish,verifyTerminal:()=>true}});
await counter.start();
if(recording===2) {
 for(const id of ids) {const token=await counter.beginRecipe(id),context=claimStage3RecipeContext(token,plan);await context.counter.start();await context.counter.send('fixture-operation',()=>channels.wire.onReserve({operationId:'r1/p'+(ids.indexOf(id)+1)+'/'+hash('fixture-operation'),sequence:counter.snapshot().total,requestReservedBytes:50,responseReservedBytes:plan.maxPerResponseWireBytes+plan.responseReadUnitBytes}));context.counter.beginCleanup();context.counter.close();await counter.finishRecipe(token);}
 await counter.startNextProductionRecording();
}
fs.writeFileSync(directory+'/started-held','held',{mode:0o600,flag:'wx'});
const r=channels.forRecording(recording),operationId='r'+recording+'/control/'+hash('fixture-control');
const mark=()=>fs.writeFileSync(directory+'/hook-ran','bad');
const arm=()=>queueMicrotask(()=>fs.writeFileSync(directory+'/after-microtask','bad'));
if(!['unreserved-storage-journal','malformed-base64','ambiguous-capture-id','raw-and-commitment-body','recipe-operation-without-semantic','wire-duplicate-sequence'].includes(mode)) arm();
if(mode==='counter-sequence') channels.counter.onReserve({recording,operationId,phase:'subject',recipeId:null,sequence:counter.snapshot().total+2});
if(mode==='counter-semantic-without-recipe') channels.counter.onReserve({recording,operationId,phase:'subject',recipeId:null,sequence:counter.snapshot().total+1,semanticOperationId:'fixture-semantic'});
if(mode==='owner-recording') r.onOwnerProof({type:'production-owner',recording:3-recording});
if(mode==='auth-type') r.onAuthProof({type:'production-owner',recording});
if(mode==='auth-operation-recording') r.onAuthJournal({type:'production-auth-ownership',operationId:'r'+(3-recording)+'/control/'+hash('other'),accountMutation:'create',accountRef:'fixture'});
if(mode==='rules-type') r.onRulesProof({type:'production-owner',recording});
if(mode==='configuration-foreign-recording') r.onConfigurationChange({type:'production-rules-config-change',recording:3-recording});
if(mode==='unknown-proof-field') r.onOwnerProof({type:'production-owner',recording,undeclared:'fixture'});
if(mode==='foreign-vocabulary-field') r.onOwnerProof({type:'production-owner',recording,status:200});
if(mode==='root-getter') {const row={type:'production-owner',recording};Object.defineProperty(row,'stage',{enumerable:true,get(){mark();throw new Error('hook');}});r.onOwnerProof(row);}
if(mode==='root-proxy') r.onOwnerProof(new Proxy({type:'production-owner',recording},{ownKeys(){mark();throw new Error('hook');},getPrototypeOf(){mark();throw new Error('hook');}}));
if(mode==='fixed-error') r.onError({recording,state:'NEEDS_RECOVERY',reason:'fixture-fixed-failure'});
if(mode==='raw-error') {const error=new Error('fixture');Object.defineProperty(error,'message',{get(){mark();throw new Error('hook');}});r.onError(error);}
if(mode==='closed-channel') {channels.close();r.onOwnerProof({type:'production-owner',recording});}
if(mode==='file-fsync'||mode==='directory-fsync') {const original=fs.fsyncSync;fs.default.fsyncSync=fd=>{const isDirectory=fs.fstatSync(fd).isDirectory();if((mode==='directory-fsync')===isDirectory)throw new Error('private IO failure');return original(fd);};syncBuiltinESMExports();r.onOwnerProof({type:'production-owner',recording});}
if(mode==='wire-duplicate-sequence') {await counter.send(operationId,()=>undefined);const row={operationId,sequence:counter.snapshot().total,requestReservedBytes:50,responseReservedBytes:plan.maxPerResponseWireBytes+plan.responseReadUnitBytes};channels.wire.onReserve(row);arm();channels.wire.onReserve(row);}
if(['unreserved-storage-journal','malformed-base64','ambiguous-capture-id','raw-and-commitment-body','recipe-operation-without-semantic'].includes(mode)) {
 const token=await counter.beginRecipe(ids[0]),recipe=channels.forRecipe(recording,ids[0]);arm();
 if(mode==='unreserved-storage-journal') recipe.onJournal({operationId:'unreserved',method:'POST'});
 if(mode==='malformed-base64') recipe.onCapture({operationId:'diagnostic',status:200,bodyBase64:'%%%'});
 if(mode==='ambiguous-capture-id') recipe.onCapture({operationId:'diagnostic',stepId:'different',status:200,bodyBase64:''});
 if(mode==='raw-and-commitment-body') recipe.onCapture({operationId:'diagnostic',status:200,bodyBase64:'',bodyByteLength:0,bodySha256:hash('')});
 if(mode==='recipe-operation-without-semantic') channels.counter.onReserve({recording,operationId:'r'+recording+'/p1/'+hash('undeclared-semantic'),recipeId:ids[0],phase:'subject',sequence:counter.snapshot().total+1});
}
fs.writeFileSync(directory+'/normal-return','bad');
`;
      try {
        writeFileSync(source, script, { mode: 0o600 });
        const result = spawnSync(process.execPath, [source], {
          encoding: "utf8",
          timeout: 15000,
          env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
        });
        assert.equal(result.error, undefined);
        assert.equal(result.status, 2);
        assert.equal(result.stdout, "");
        assert.equal(result.stderr, "");
        assert.equal(existsSync(join(directory, "started-held")), true);
        for (const name of ["hook-ran", "after-microtask", "normal-return", "end-row"])
          assert.equal(existsSync(join(directory, name)), false, name);
      } finally {
        rmSync(directory, { recursive: true, force: true });
      }
    });
  }

test("declared owner, Auth, Rules, manifest and export proof shapes use their fixed recording sinks", async () => {
  await fixture(async ({ channels, directory }) => {
    const counter = counterFor(channels);
    await counter.start();
    for (const recording of [1, 2]) {
      if (recording === 2) {
        for (const id of ids) {
          const token = await counter.beginRecipe(id),
            context = claimStage3RecipeContext(token, plan);
          await context.counter.start();
          await context.counter.send("fixture-operation", () => undefined);
          context.counter.beginCleanup();
          context.counter.close();
          await counter.finishRecipe(token);
        }
        await counter.startNextProductionRecording();
      }
      const r = channels.forRecording(recording);
      // These source-shape fixtures test persistence roles, never actual token or cleanup authority.
      r.onOwnerProof({
        type: "production-owner",
        recording,
        stage: "initial",
        adcSha256: hash("adc"),
        adcType: "authorized_user",
        clientId: "fixture-client",
        principalSha256: hash("principal"),
        scopeSha256: hash("scope"),
        accessTokenSha256: hash("token"),
        accessTokenByteLength: 64,
        exchangeBodySha256: hash("exchange"),
        tokeninfoBodySha256: hash("tokeninfo"),
        deadlineMonotonicMs: 100000,
      });
      r.onAuthProof({
        type: "production-auth-account",
        recording,
        accountRef: "fixture-account",
        stage: "initial",
        ownedUidSha256: hash("uid"),
        emailSha256: hash("email"),
        tokenSha256: hash("auth-token"),
        tokenByteLength: 64,
        responseBodySha256: hash("auth-response"),
        deadlineMonotonicMs: 100000,
      });
      r.onAuthProof({
        type: "production-auth-cleanup",
        recording,
        accountRef: "fixture-account",
        ownedUidSha256: hash("uid"),
        absent: true,
      });
      r.onRulesProof({
        type: "production-rules-checkpoint",
        recording,
        checkpoint: "initial",
        sourceSha256: plan.rulesSourceSha256,
        releaseBodySha256: hash("release"),
        rulesetBodySha256: hash("ruleset"),
        bucketlessBodySha256: hash("absent"),
        bucketlessAbsent: true,
      });
      r.onRulesProof({
        type: "production-rules-reference-list",
        recording,
        label: "initial",
        pages: 1,
        releaseCount: 1,
        bodySha256: hash("list"),
        exhausted: true,
      });
      if (recording === 2) {
        r.onConfigurationChange({
          type: "production-rules-config-change",
          recording,
          state: "ruleset-absent",
          releaseName: `projects/${plan.projectId}/releases/firebase.storage/${plan.bucket}`,
          rulesetName: resources.rulesetResource,
          sourceSha256: plan.rulesSourceSha256,
        });
        r.onRulesProof({
          type: "production-rules-cleanup",
          recording,
          releaseAbsent: true,
          rulesetAbsent: true,
          bucketlessAbsent: true,
          sourceSha256: plan.rulesSourceSha256,
        });
      }
      r.onManifest({
        type: "manifest",
        recording,
        runId: plan.recordings[recording - 1].runId,
        rows: [],
      });
      r.onExport({
        type: "export",
        recording,
        runId: plan.recordings[recording - 1].runId,
        rows: [],
      });
    }
    const rows = stored(directory);
    for (const recording of [1, 2]) {
      const own = rows.filter((row) => row.data.recording === recording);
      assert.equal(own.filter((row) => row.artifactKind === "owner-proof").length, 1);
      assert.equal(own.filter((row) => row.artifactKind === "auth-proof").length, 2);
      assert.equal(
        own.filter((row) => row.artifactKind === "rules-proof").length,
        recording === 1 ? 2 : 3,
      );
      assert.equal(
        own.filter((row) => row.artifactKind === "configuration-change").length,
        recording === 1 ? 0 : 1,
      );
      assert.equal(own.filter((row) => row.artifactKind === "manifest").length, 1);
      assert.equal(own.filter((row) => row.artifactKind === "export").length, 1);
    }
    assert.equal(
      rows.every((row) => row.taskSecretStatus === "AVAILABLE"),
      true,
    );
  });
});
