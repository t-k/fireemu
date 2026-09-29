import assert from "node:assert/strict";
import fs from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { createProductionOwnerState } from "./storage-object/production-owner.mjs";
import { createProductionAuthState } from "./storage-object/production-auth.mjs";
import {
  createProductionSecretRegistry,
  productionSecretRegistryHasValue,
} from "./storage-object/production-secret-registry.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { withProjectLocks } from "./storage-object/project-locks.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import * as standalone from "./storage-object/production-standalone-fail-stop.mjs";

const api = await import("./storage-object/production-provider-boundary.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
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
const profile = {
  maxValues: 64,
  maxUtf8Bytes: 131072,
  maxIndexNodes: 200000,
  maxScanCodeUnits: 16777216,
};
const principal = {
  subject: "fixture-owner-subject",
  clientId: "fixture-client.apps.googleusercontent.com",
  requiredScopes: ["https://www.googleapis.com/auth/cloud-platform"],
};
function context(recording = 1, ordinal = 1) {
  return {
    recording,
    kind: "storage",
    phase: "subject",
    operationId: `r${recording}/p${ordinal}/${"a".repeat(64)}`,
  };
}
function fixture(action) {
  assert.equal(typeof api.createProductionCredentialProviders, "function");
  const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-object-provider-boundary-")));
  fs.chmodSync(root, 0o700);
  const capture = join(root, "capture");
  fs.mkdirSync(capture, { mode: 0o700 });
  const boundary = standalone.createProductionStandaloneFailStop({ directory: capture });
  const registry = createProductionSecretRegistry(profile);
  const providers = api.createProductionCredentialProviders({ boundary, registry });
  try {
    return action({ root, capture, boundary, registry, providers });
  } finally {
    providers.close();
    registry.close();
    fs.rmSync(root, { recursive: true, force: true });
  }
}
function ownerOptions(recording, path, bytes, registry, controls) {
  return {
    recording,
    adcInput: {
      path,
      expectedSha256: hash(bytes),
      expectedClientId: principal.clientId,
      expectedQuotaProjectId: plan.projectId,
    },
    principal,
    controls,
    verifyAdmission: () => true,
    onProof: async () => {},
    onSecret: (value) => {
      registry.register(value);
    },
  };
}
function authOptions(recording, registry, controls) {
  return {
    plan,
    recording,
    projectNumber: resources.projectNumber,
    apiKey: "SYNTHETIC_BOUNDARY_API_KEY",
    controls,
    verifyAdmission: () => true,
    onJournal: async () => {},
    onProof: async () => {},
    onSecret: (value) => {
      registry.register(value);
    },
  };
}

test("credential providers require original standalone and task registry capabilities without caller hooks", () => {
  fixture(({ boundary, registry, providers, capture }) => {
    assert.equal(standalone.isProductionStandaloneFailStop(boundary), true);
    let hooks = 0;
    const fake = {
      get directory() {
        hooks++;
        throw new Error();
      },
    };
    const proxy = new Proxy(boundary, {
      get() {
        hooks++;
        throw new Error();
      },
    });
    const revoked = Proxy.revocable(boundary, {});
    revoked.revoke();
    for (const value of [{ ...boundary }, fake, proxy, revoked.proxy, null]) {
      assert.equal(standalone.isProductionStandaloneFailStop(value), false);
      assert.throws(
        () => api.createProductionCredentialProviders({ boundary: value, registry }),
        /invalid production credential providers/,
      );
    }
    for (const value of [{ ...registry }, new Proxy(registry, {}), null])
      assert.throws(
        () => api.createProductionCredentialProviders({ boundary, registry: value }),
        /invalid production credential providers/,
      );
    assert.throws(
      () =>
        api.createProductionCredentialProviders({
          get boundary() {
            hooks++;
            return boundary;
          },
          registry,
        }),
      /invalid production credential providers/,
    );
    assert.equal(
      api.originalProductionCredentialProviderFunctions(providers, registry).ownerAuthorization,
      providers.ownerAuthorization,
    );
    for (const value of [{ ...providers }, new Proxy(providers, {}), null])
      assert.throws(
        () => api.originalProductionCredentialProviderFunctions(value, registry),
        /invalid production credential providers/,
      );
    const other = createProductionSecretRegistry(profile);
    try {
      assert.throws(
        () => api.originalProductionCredentialProviderFunctions(providers, other),
        /invalid production credential providers/,
      );
      const input = {
        plan,
        resources,
        captureDirectory: capture,
        onByteReserve: async () => {},
        verifyAdmission: () => true,
        credentialProviders: providers,
        secretRegistry: registry,
      };
      for (const value of [
        { ...providers },
        new Proxy(providers, {}),
        {
          get ownerAuthorization() {
            hooks++;
            throw new Error();
          },
        },
      ])
        assert.throws(
          () => createProductionWireTransport({ ...input, credentialProviders: value }),
          /invalid production wire configuration/,
        );
      assert.throws(
        () => createProductionWireTransport({ ...input, secretRegistry: other }),
        /invalid production wire configuration/,
      );
      assert.throws(
        () =>
          createProductionWireTransport({
            ...input,
            ownerAuthorization: () => "Bearer SYNTHETIC_CALLBACK",
          }),
        /invalid production wire configuration/,
      );
      const missing = { ...input };
      delete missing.secretRegistry;
      assert.throws(
        () => createProductionWireTransport(missing),
        /invalid production wire configuration/,
      );
    } finally {
      other.close();
    }
    assert.equal(hooks, 0);
    const getterContext = {
      get recording() {
        hooks++;
        return 0;
      },
      kind: "storage",
      phase: "subject",
      operationId: context().operationId,
    };
    for (const value of [
      getterContext,
      new Proxy(
        { ...context(), recording: 0 },
        {
          get(target, key) {
            hooks++;
            return target[key];
          },
        },
      ),
      { ...context(), recording: 2, operationId: context().operationId },
    ])
      assert.throws(
        () => providers.ownerAuthorization(value),
        /invalid production credential context/,
      );
    assert.equal(hooks, 0);
    providers.registerSecret(context(), "SYNTHETIC_SIDE_TOKEN");
    assert.equal(productionSecretRegistryHasValue(registry, "SYNTHETIC_SIDE_TOKEN"), true);
    assert.deepEqual(fs.readdirSync(capture), []);
  });
});

test("recording bindings reject copies, the other recording and replacement without reading public methods", () => {
  fixture(({ root, registry, providers }) => {
    const controls = {
      send: async () => {
        throw new Error("UNEXPECTED_CONTROL");
      },
    };
    const bytes = Buffer.from("{}");
    const owner = createProductionOwnerState(
      ownerOptions(1, join(root, "synthetic-adc.json"), bytes, registry, controls),
    );
    const auth = createProductionAuthState(authOptions(1, registry, controls));
    let hooks = 0;
    try {
      for (const [kind, state, method] of [
        ["Owner", owner, "ownerAuthorization"],
        ["Auth", auth, "accountAuthorization"],
      ]) {
        const bind = providers[`bind${kind}`];
        const fake = {
          get [method]() {
            hooks++;
            return state[method];
          },
        };
        for (const value of [{ ...state }, fake, new Proxy(state, {}), null])
          assert.throws(() => bind(1, value), /invalid production credential binding/);
        for (const recording of [2, 0, undefined, new Number(1)])
          assert.throws(() => bind(recording, state), /invalid production credential binding/);
        bind(1, state);
        assert.throws(() => bind(1, state), /invalid production credential binding/);
      }
      assert.equal(hooks, 0);
      providers.close();
      assert.throws(() => providers.bindOwner(1, owner), /invalid production credential binding/);
      assert.throws(() => providers.bindAuth(1, auth), /invalid production credential binding/);
    } finally {
      owner.close();
      auth.close();
    }
  });
});

for (const recording of [1, 2])
  test(`original owner tokens enter the same task registry before recording ${recording} wire authorization`, async () => {
    assert.equal(typeof api.createProductionCredentialProviders, "function");
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-object-provider-owner-")));
    fs.chmodSync(root, 0o700);
    const capture = join(root, "capture");
    fs.mkdirSync(capture, { mode: 0o700 });
    const registry = createProductionSecretRegistry(profile);
    const providers = api.createProductionCredentialProviders({
      boundary: standalone.createProductionStandaloneFailStop({ directory: capture }),
      registry,
    });
    const adc = {
      type: "authorized_user",
      client_id: principal.clientId,
      client_secret: "SYNTHETIC_CLIENT_SECRET",
      refresh_token: "SYNTHETIC_REFRESH_SECRET",
      quota_project_id: plan.projectId,
    };
    const bytes = Buffer.from(JSON.stringify(adc)),
      path = join(root, "synthetic-adc.json");
    fs.writeFileSync(path, bytes, { mode: 0o600 });
    const token = `SYNTHETIC_ORIGINAL_OWNER_${recording}`;
    let state,
      calls = 0;
    const controls = {
      send: async (id) => {
        calls++;
        const data = id.endsWith("owner-exchange")
          ? { access_token: token, token_type: "Bearer", expires_in: 3600 }
          : {
              sub: principal.subject,
              azp: principal.clientId,
              aud: principal.clientId,
              scope: principal.requiredScopes.join(" "),
              expires_in: 3600,
            };
        return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(data)) };
      },
    };
    try {
      state = createProductionOwnerState({
        ...ownerOptions(recording, path, bytes, registry, controls),
        onSecret: () => {},
      });
      providers.bindOwner(recording, state);
      await state.exchangeAndProve("initial");
      assert.equal(productionSecretRegistryHasValue(registry, token), false);
      assert.equal(providers.ownerAuthorization(context(recording)), `Bearer ${token}`);
      assert.equal(productionSecretRegistryHasValue(registry, token), true);
      assert.equal(calls, 2);
      assert.deepEqual(fs.readdirSync(capture), []);
    } finally {
      providers.close();
      state?.close();
      registry.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

for (const recording of [1, 2])
  test(`original Auth tokens and malformed control enter the task registry in recording ${recording}`, async () => {
    assert.equal(typeof api.createProductionCredentialProviders, "function");
    const root = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), "storage-object-provider-auth-")));
    fs.chmodSync(root, 0o700);
    const capture = join(root, "capture");
    fs.mkdirSync(capture, { mode: 0o700 });
    const registry = createProductionSecretRegistry(profile),
      providers = api.createProductionCredentialProviders({
        boundary: standalone.createProductionStandaloneFailStop({ directory: capture }),
        registry,
      });
    const recipe = buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[recording - 1].runId,
    }).recipes[0];
    const accounts = new Map(
      ["valid", "competitor"].map((kind) => [
        kind,
        { ...recipe.accounts[kind], uid: `fixture-${recording}-${kind}`, present: false },
      ]),
    );
    let calls = 0,
      state;
    const controls = {
      send: async (id) => {
        calls++;
        const match = /auth1-(valid|competitor)-setup-(.+)$/.exec(id);
        assert.ok(match);
        const account = accounts.get(match[1]);
        let data;
        if (match[2] === "signup") {
          account.present = true;
          const time = Math.floor(Date.now() / 1000);
          account.token = [
            Buffer.from(JSON.stringify({ alg: "RS256", kid: "synthetic-key" })),
            Buffer.from(
              JSON.stringify({
                sub: account.uid,
                user_id: account.uid,
                email: account.email,
                aud: plan.projectId,
                iss: `https://securetoken.google.com/${plan.projectId}`,
                iat: time,
                auth_time: time,
                exp: time + 3600,
                firebase: { sign_in_provider: "password" },
              }),
            ),
            Buffer.from("synthetic-signature"),
          ]
            .map((part) => part.toString("base64url"))
            .join(".");
          data = {
            localId: account.uid,
            email: account.email,
            idToken: account.token,
            refreshToken: `SYNTHETIC_REFRESH_${account.uid}`,
            expiresIn: "3600",
          };
        } else
          data = account.present
            ? { users: [{ localId: account.uid, email: account.email, disabled: false }] }
            : {};
        return { status: 200, arrayBuffer: async () => Buffer.from(JSON.stringify(data)) };
      },
    };
    try {
      state = createProductionAuthState({
        ...authOptions(recording, registry, controls),
        onSecret: () => {},
      });
      providers.bindAuth(recording, state);
      await state.setup(recipe.id, Object.freeze({}));
      assert.equal(productionSecretRegistryHasValue(registry, accounts.get("valid").token), false);
      const ref = { kind: "valid", accountRef: recipe.accounts.valid.ref },
        row = context(recording, 25);
      const authorization = providers.accountAuthorization(ref, row);
      assert.equal(authorization, `Firebase ${accounts.get("valid").token}`);
      assert.equal(productionSecretRegistryHasValue(registry, authorization.slice(9)), true);
      const malformed = providers.accountAuthorization({ kind: "malformed" }, row);
      assert.match(malformed, /^Firebase /);
      assert.equal(productionSecretRegistryHasValue(registry, malformed.slice(9)), true);
      assert.equal(calls, 8);
      assert.deepEqual(fs.readdirSync(capture), []);
    } finally {
      providers.close();
      state?.close();
      registry.close();
      fs.rmSync(root, { recursive: true, force: true });
    }
  });

function copyModules(destination) {
  assert.equal(typeof createProductionWireTransport, "function");
  assert.equal(typeof withProjectLocks, "function");
  const source = dirname(
    fileURLToPath(new URL("./storage-object/production-wire-transport.mjs", import.meta.url)),
  );
  fs.mkdirSync(destination, { mode: 0o700 });
  const seen = new Set();
  function copy(name) {
    if (seen.has(name)) return;
    seen.add(name);
    const text = fs.readFileSync(join(source, name), "utf8");
    fs.writeFileSync(join(destination, name), text, { mode: 0o600 });
    for (const match of text.matchAll(/(?:from\s*|import\s*\()\s*["'](\.[^"']+)["']/g))
      copy(basename(match[1]));
  }
  for (const name of [
    "production-provider-boundary.mjs",
    "production-wire-transport.mjs",
    "project-locks.mjs",
  ])
    copy(name);
}
function faultChild(paths, kind, shape, slot) {
  let step = buildCorpus({
    projectId: plan.projectId,
    bucket: plan.bucket,
    prefix: plan.recordings[0].prefix,
  }).recipes[0].preflight[0];
  if (kind === "account") {
    const recipe = buildAuthCorpus({
      projectId: plan.projectId,
      bucket: plan.bucket,
      runId: plan.recordings[0].runId,
    }).recipes[0];
    const probe = recipe.probes.find((row) => row.credential === "valid" && row.action === "read");
    step = {
      ...probe.subject,
      id: `${recipe.id}/${probe.id}/subject`,
      dialect: "firebase",
      headers: {},
    };
  }
  const directory = join(paths.root, "source");
  copyModules(directory);
  const target = join(directory, kind === "owner" ? "production-owner.mjs" : "production-auth.mjs");
  const before =
    kind === "owner"
      ? "    ownerAuthorization(suppliedInput) {"
      : "    accountAuthorization(suppliedRef, suppliedContext) {";
  const text = fs.readFileSync(target, "utf8");
  assert.equal(text.split(before).length, 2);
  // Inject only into this child's original factory; production source admission is a separate gate.
  if (
    ![
      "uninitialized",
      "closed",
      "binding-missing",
      "providers-closed",
      "providers-closed-secret",
    ].includes(shape)
  )
    fs.writeFileSync(
      target,
      text.replace(before, `${before}\n      return globalThis.__syntheticProvider();`),
      { mode: 0o600 },
    );
  const url = (name) => pathToFileURL(join(directory, name)).href;
  const source = `
    import fs from 'node:fs'; import tls from 'node:tls'; import { syncBuiltinESMExports } from 'node:module';
    const root=${JSON.stringify(paths.root)}, capture=${JSON.stringify(paths.capture)}, kind=${JSON.stringify(kind)}, shape=${JSON.stringify(shape)}, slot=${slot};
    let hooks=0, constructors=0, unhandled=0, calls=0, sockets=0, reservations=0;
    process.on('unhandledRejection',()=>{unhandled++;});
    process.on('exit',()=>fs.writeFileSync(root+'/metrics.json',JSON.stringify({hooks,constructors,unhandled,calls,sockets,reservations}),{mode:0o600}));
    tls.connect=()=>{sockets++;throw new Error('UNEXPECTED_SOCKET');};syncBuiltinESMExports();
    globalThis.__syntheticProvider=()=>{
      calls++; if(calls<slot||shape==='registry-closed')return (kind==='owner'?'Bearer ':'Firebase ')+'SYNTHETIC_SAFE_TOKEN';
      const secret='SYNTHETIC_UNSAFE_REASON_+/private';
      if(shape==='throw'){const error=new Error(secret);Object.defineProperty(error,'stack',{get(){hooks++;return secret;}});Object.defineProperty(error,'cause',{get(){hooks++;return secret;}});throw error;}
      if(shape==='thenable')return {get then(){hooks++;throw new Error(secret);}};
      if(shape==='proxy')return new Proxy({},{get(){hooks++;throw new Error(secret);},getPrototypeOf(){hooks++;throw new Error(secret);}});
      if(shape==='hidden-reject'){Promise.reject(new Error(secret));return {};}
      let value;if(shape.startsWith('subclass')){class Sub extends Promise{constructor(...args){super(...args);constructors++;}}if(shape==='subclass-species')Object.defineProperty(Sub,Symbol.species,{get(){hooks++;return Promise;}});value=Sub.reject(new Error(secret));if(shape==='subclass-nonextensible')Object.preventExtensions(value);}else value=Promise.reject(new Error(secret));
      constructors=0;if(shape==='constructor-accessor')Object.defineProperty(value,'constructor',{get(){hooks++;throw new Error(secret);}});
      if(shape==='constructor-species')Object.defineProperty(value,'constructor',{value:{get [Symbol.species](){hooks++;return Promise;}}});
      if(shape==='own-then')Object.defineProperty(value,'then',{get(){hooks++;throw new Error(secret);}});if(shape==='frozen')Object.freeze(value);return value;
    };
    const {createProductionCredentialProviders}=await import(${JSON.stringify(url("production-provider-boundary.mjs"))});
    const {createProductionStandaloneFailStop}=await import(${JSON.stringify(url("production-standalone-fail-stop.mjs"))});
    const {createProductionSecretRegistry}=await import(${JSON.stringify(url("production-secret-registry.mjs"))});
    const {createProductionOwnerState}=await import(${JSON.stringify(url("production-owner.mjs"))});
    const {createProductionAuthState}=await import(${JSON.stringify(url("production-auth.mjs"))});
    const {createProductionWireTransport}=await import(${JSON.stringify(url("production-wire-transport.mjs"))});
    const {withProjectLocks}=await import(${JSON.stringify(url("project-locks.mjs"))});
    const registry=createProductionSecretRegistry(${JSON.stringify(profile)}), providers=createProductionCredentialProviders({boundary:createProductionStandaloneFailStop({directory:capture}),registry});
    const plan=${JSON.stringify(plan)}, resources=${JSON.stringify(resources)}, controls={send:async()=>{throw new Error('UNEXPECTED_CONTROL');}};
    const owner=createProductionOwnerState({recording:1,adcInput:{path:root+'/unused-synthetic-adc.json',expectedSha256:'a'.repeat(64),expectedClientId:${JSON.stringify(principal.clientId)},expectedQuotaProjectId:plan.projectId},principal:${JSON.stringify(principal)},controls,verifyAdmission:()=>true,onSecret:()=>{},onProof:async()=>{}});
    const auth=createProductionAuthState({plan,recording:1,projectNumber:resources.projectNumber,apiKey:'SYNTHETIC_API_KEY',controls,verifyAdmission:()=>true,onSecret:()=>{},onJournal:async()=>{},onProof:async()=>{}});
    if(shape!=='binding-missing'||kind!=='owner')providers.bindOwner(1,owner);
    if(shape!=='binding-missing'||kind!=='account')providers.bindAuth(1,auth);
    const wire=createProductionWireTransport({plan,resources,captureDirectory:capture,onByteReserve:async()=>{reservations++;},verifyAdmission:()=>true,credentialProviders:providers,secretRegistry:registry});
    await withProjectLocks({projects:['example-query'],lockDir:root+'/locks',legacyLockPath:root+'/legacy.lock',taskId:'STORAGE-OBJECT',packetId:'synthetic-provider',sourceCommit:'a'.repeat(40),pid:process.pid,acquiredAt:'2026-09-29T00:00:00Z'},async lease=>{
      lease.markStarted();fs.writeFileSync(root+'/started-attempt.json','{}',{mode:0o600});
      if(shape==='closed')(kind==='owner'?owner:auth).close();
      if(shape==='providers-closed')providers.close();
      if(shape==='providers-closed-secret'){providers.close();providers.registerSecret({recording:1,kind:'storage',phase:'subject',operationId:'r1/p1/'+'a'.repeat(64)},'SYNTHETIC_LATE_SECRET');}
      if(shape==='registry-closed')registry.close();
      const step=${JSON.stringify(step)};
      const ordinal=kind==='owner'?1:25;
      await wire.fetchStorage(1,step,{operationId:'r1/p'+ordinal+'/'+${JSON.stringify(hash(step.id))},accountingPhase:'subject'});
      fs.writeFileSync(root+'/after-call','AFTER',{mode:0o600});lease.confirmClosed();
    });
  `;
  const script = join(paths.root, "synthetic-child.mjs");
  fs.writeFileSync(script, source, { mode: 0o600 });
  return spawnSync(process.execPath, [script], {
    encoding: "utf8",
    timeout: 10000,
    env: { PATH: process.env.PATH, TMPDIR: tmpdir() },
    maxBuffer: 65536,
  });
}
for (const kind of ["owner", "account"])
  test(`owned ${kind} provider fails before TLS for unsafe original results at both wire slots`, () => {
    for (const shape of [
      "native",
      "own-then",
      "constructor-accessor",
      "constructor-species",
      "frozen",
      "subclass",
      "subclass-species",
      "subclass-nonextensible",
      "thenable",
      "proxy",
      "hidden-reject",
      "throw",
    ])
      for (const slot of [1, 2])
        fixture((paths) => {
          const result = faultChild(paths, kind, shape, slot);
          assert.equal(result.error, undefined);
          assert.equal(result.signal, null);
          assert.equal(result.status, 2, `${kind}/${shape}/${slot}: ${result.stderr}`);
          assert.equal(result.stdout, "");
          assert.equal(result.stderr, "");
          const metrics = JSON.parse(fs.readFileSync(join(paths.root, "metrics.json")));
          assert.deepEqual(metrics, {
            hooks: 0,
            constructors: 0,
            unhandled: 0,
            calls: slot,
            sockets: 0,
            reservations: slot - 1,
          });
          const fatal = JSON.parse(fs.readFileSync(join(paths.capture, "fatal-r1.json")));
          assert.equal(fatal.state, "NEEDS_RECOVERY");
          assert.equal(fatal.providerKind, kind);
          assert.equal(
            fatal.reason,
            shape === "throw" ? "PROVIDER_THREW" : "PROVIDER_RESULT_UNSAFE",
          );
          assert.equal(fs.existsSync(join(paths.root, "locks/example-query.lock")), true);
          assert.equal(fs.existsSync(join(paths.root, "after-call")), false);
          for (const file of fs.readdirSync(paths.capture)) {
            const bytes = fs.readFileSync(join(paths.capture, file));
            for (const secret of ["SYNTHETIC_SAFE_TOKEN", "SYNTHETIC_UNSAFE_REASON_+/private"])
              for (const value of [
                secret,
                encodeURIComponent(secret),
                Buffer.from(secret).toString("base64"),
                Buffer.from(secret).toString("base64url"),
              ])
                assert.equal(
                  bytes.includes(Buffer.from(value)),
                  false,
                  `${kind}/${shape}/${slot}/${file}`,
                );
          }
        });
  });

test("unusable original states, closed providers and registry failure retain the started lease without dispatch", () => {
  for (const kind of ["owner", "account"])
    for (const shape of [
      "uninitialized",
      "closed",
      "binding-missing",
      "providers-closed",
      "registry-closed",
      "providers-closed-secret",
    ])
      fixture((paths) => {
        const result = faultChild(paths, kind, shape, 1);
        assert.equal(result.error, undefined);
        assert.equal(result.signal, null);
        assert.equal(result.status, 2, `${kind}/${shape}: ${result.stderr}`);
        assert.equal(result.stdout, "");
        assert.equal(result.stderr, "");
        const metrics = JSON.parse(fs.readFileSync(join(paths.root, "metrics.json")));
        assert.deepEqual(metrics, {
          hooks: 0,
          constructors: 0,
          unhandled: 0,
          calls: shape === "registry-closed" ? 1 : 0,
          sockets: 0,
          reservations: 0,
        });
        const fatal = JSON.parse(fs.readFileSync(join(paths.capture, "fatal-r1.json")));
        assert.equal(fatal.state, "NEEDS_RECOVERY");
        assert.equal(fatal.reason, "PROVIDER_THREW");
        assert.equal(
          fatal.providerKind,
          ["registry-closed", "providers-closed-secret"].includes(shape) ? "secret" : kind,
        );
        assert.equal(fs.existsSync(join(paths.root, "locks/example-query.lock")), true);
        assert.equal(fs.existsSync(join(paths.root, "after-call")), false);
      });
});
