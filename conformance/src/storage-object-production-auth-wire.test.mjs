import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Duplex } from "node:stream";
import tls from "node:tls";
import test, { afterEach, beforeEach } from "node:test";
import { buildCorpus } from "./storage-object/corpus.mjs";
import { buildAuthCorpus } from "./storage-object/auth-corpus.mjs";
import { createProductionAuthState } from "./storage-object/production-auth.mjs";
import { createProductionControlDispatcher } from "./storage-object/production-controls.mjs";
import { createProductionWireTransport } from "./storage-object/production-wire-transport.mjs";
import { createStage3RequestCounter } from "./storage-object/request-counter.mjs";
import { buildProductionStage3DraftPlan } from "./storage-object/stage3-plan.mjs";

const argv = [...process.execArgv];
beforeEach(() => {
  process.execArgv = [];
});
afterEach(() => {
  process.execArgv = [...argv];
});
const hash = (value) => createHash("sha256").update(value).digest("hex");
const plan = buildProductionStage3DraftPlan({
  projectId: "example-project",
  bucket: "example.appspot.com",
  runIds: ["recordone", "recordtwo"],
});
const projectNumber = "123456789012",
  apiKey = "SYNTHETIC_AUTH_WIRE_API_KEY_abcdefgh123456789",
  owner = "SYNTHETIC_AUTH_WIRE_OWNER_abcdefgh123456789";
const authRecipes = buildAuthCorpus({
  projectId: plan.projectId,
  bucket: plan.bucket,
  runId: "recordone",
}).recipes;
const recipeIds = [
  ...buildCorpus({ bucket: plan.bucket, prefix: plan.recordings[0].prefix }).recipes.map(
    (r) => r.id,
  ),
  ...authRecipes.map((r) => r.id),
];
function tokenFor(account) {
  const seconds = Math.floor(Date.now() / 1000);
  return [
    Buffer.from(JSON.stringify({ alg: "RS256", kid: "synthetic-key" })).toString("base64url"),
    Buffer.from(
      JSON.stringify({
        sub: account.uid,
        user_id: account.uid,
        email: account.email,
        aud: plan.projectId,
        iss: `https://securetoken.google.com/${plan.projectId}`,
        iat: seconds,
        exp: seconds + 3600,
        firebase: { sign_in_provider: "password" },
      }),
    ).toString("base64url"),
    Buffer.from(`synthetic-signature-${account.revision}`).toString("base64url"),
  ].join(".");
}

async function withMemoryTls(responder, action) {
  const originalConnect = tls.connect,
    connections = [];
  tls.connect = (options) => {
    const row = { options, bytes: Buffer.alloc(0) };
    connections.push(row);
    let responded = false;
    const socket = new Duplex({
      read() {},
      write(bytes, encoding, done) {
        row.bytes = Buffer.concat([row.bytes, bytes]);
        socket.bytesWritten += bytes.length;
        const boundary = row.bytes.indexOf("\r\n\r\n");
        const length = /content-length: (\d+)/i.exec(row.bytes.toString())?.[1];
        if (!responded && boundary >= 0 && row.bytes.length === boundary + 4 + Number(length)) {
          responded = true;
          try {
            row.head = row.bytes.subarray(0, boundary).toString();
            row.body = row.bytes.subarray(boundary + 4);
            const result = responder(row),
              body = Buffer.from(JSON.stringify(result.data));
            const response = Buffer.concat([
              Buffer.from(
                `HTTP/1.1 ${result.status} Synthetic\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`,
              ),
              body,
            ]);
            queueMicrotask(() => {
              for (let offset = 0; offset < response.length; offset += 37)
                options.onread.callback(
                  Math.min(37, response.length - offset),
                  response.subarray(offset, offset + 37),
                );
              socket.push(null);
            });
          } catch (error) {
            done(error);
            return;
          }
        }
        done();
      },
    });
    Object.assign(socket, {
      bytesWritten: 0,
      authorized: true,
      alpnProtocol: "http/1.1",
      encrypted: true,
      setTimeout() {
        return this;
      },
      setNoDelay() {
        return this;
      },
      setKeepAlive() {
        return this;
      },
    });
    queueMicrotask(() => socket.emit("secureConnect"));
    return socket;
  };
  try {
    return await action(connections);
  } finally {
    tls.connect = originalConnect;
  }
}

async function fixture(action, changes = {}) {
  const directory = mkdtempSync(join(tmpdir(), "storage-object-auth-wire-"));
  chmodSync(directory, 0o700);
  const recipe = authRecipes[0],
    accounts = ["valid", "competitor"].map((kind) =>
      Object.assign({}, recipe.accounts[kind], {
        kind,
        uid: `synthetic-uid-${kind}`,
        present: false,
        revision: 1,
      }),
    );
  const reserves = [],
    bytes = [],
    proofs = [],
    journal = [],
    secrets = [apiKey, owner];
  let state, wire;
  const counter = createStage3RequestCounter(plan, {
    onStart: async () => {},
    onReserve: async (row) => {
      reserves.push(row);
    },
    recipeLifecycle: {
      recipeIds,
      onBegin: async () => {},
      onFinish: async () => {},
      verifyTerminal: () => true,
    },
  });
  const verifyAdmission = (row) => row.recording === 1 && row.phase === counter.snapshot().mode;
  try {
    await counter.start();
    // Empty prior lifecycle fixtures do not establish aggregate terminal completion.
    for (const id of recipeIds.slice(0, 24)) {
      const token = await counter.beginRecipe(id);
      counter.beginCleanup(token);
      await counter.finishRecipe(token);
    }
    const recipeToken = await counter.beginRecipe(recipe.id);
    wire = createProductionWireTransport({
      plan,
      resources: {
        projectNumber,
        apiKeyResource: `projects/${projectNumber}/locations/global/keys/fixture-key`,
        rulesetResource: "projects/example-project/rulesets/fixture-ruleset",
      },
      captureDirectory: directory,
      onByteReserve: async (row) => {
        bytes.push(row);
        if (changes.illegalRegistration) wire.registerSecret("SYNTHETIC_LATE_CAPTURE_SECRET");
      },
      verifyAdmission: (row) => {
        if (changes.illegalAdmissionRegistration)
          wire.registerSecret("SYNTHETIC_ADMISSION_CALLBACK_SECRET");
        return verifyAdmission(row);
      },
      ownerAuthorization: () => {
        if (changes.ownerProviderFailure) {
          wire.registerSecret(owner);
          throw new Error(owner);
        }
        return `Bearer ${owner}`;
      },
      accountAuthorization: (ref, row) => {
        if (changes.closeAccountProvider) void wire.close();
        if (changes.accountAuthorizationResult !== undefined)
          return changes.accountAuthorizationResult;
        return state.accountAuthorization(ref, row);
      },
    });
    const controls = createProductionControlDispatcher({
      plan,
      counter,
      wire,
      onProof: async (row) => {
        proofs.push(row);
      },
    });
    state = createProductionAuthState({
      plan,
      recording: 1,
      projectNumber,
      apiKey,
      controls,
      verifyAdmission,
      onSecret: (value) => {
        secrets.push(value);
        wire.registerSecret(value);
      },
      onJournal: async (row) => {
        journal.push(row);
      },
      onProof: async (row) => {
        proofs.push(row);
      },
    });
    await withMemoryTls(
      (row) => {
        assert.equal(row.options.servername, row.options.host);
        assert.equal(row.options.rejectUnauthorized, true);
        const [, target] = row.head.split(" "),
          url = new URL(target, `https://${row.options.host}`);
        const authorization = /\r\nauthorization: ([^\r\n]+)/i.exec(row.head)?.[1];
        if (row.options.host === "firebasestorage.googleapis.com") {
          assert.equal(/x-goog-user-project:/i.test(row.head), false);
          assert.ok(authorization?.startsWith("Firebase "));
          const token = authorization.slice(9);
          const account = accounts.find((a) => a.token === token);
          if (!account) {
            assert.ok(secrets.includes(token));
            return { status: 403, data: { error: { code: 403, message: "Forbidden" } } };
          }
          assert.equal(account.present, true);
          return { status: 404, data: { error: { code: 404, message: "Not Found" } } };
        }
        const client = url.searchParams.has("key");
        assert.equal(authorization, client ? undefined : `Bearer ${owner}`);
        assert.equal(/x-goog-user-project:/i.test(row.head), !client);
        if (client) assert.equal(url.searchParams.get("key"), apiKey);
        let data;
        if (url.pathname === "/v1/token") {
          const form = new URLSearchParams(row.body.toString());
          assert.equal(form.get("grant_type"), "refresh_token");
          const account = accounts.find((a) => a.refreshToken === form.get("refresh_token"));
          assert.ok(account);
          account.revision++;
          account.token = tokenFor(account);
          account.refreshToken = `SYNTHETIC_REFRESH_${account.kind}_${account.revision}`;
          data = {
            user_id: account.uid,
            project_id: projectNumber,
            id_token: account.token,
            refresh_token: account.refreshToken,
            expires_in: "3600",
            token_type: "Bearer",
          };
        } else {
          const body = JSON.parse(row.body.toString());
          if (url.pathname.endsWith(":signUp")) {
            const account = accounts.find((a) => a.email === body.email);
            assert.ok(account);
            assert.equal(account.present, false);
            assert.ok(secrets.includes(body.password));
            account.present = true;
            account.token = tokenFor(account);
            account.refreshToken = `SYNTHETIC_REFRESH_${account.kind}_1`;
            data = {
              localId: account.uid,
              email: account.email,
              idToken: account.token,
              refreshToken: account.refreshToken,
              expiresIn: "3600",
            };
          } else if (url.pathname.endsWith(":delete")) {
            const account = accounts.find((a) => a.uid === body.localId);
            assert.ok(account);
            assert.equal(account.present, true);
            assert.equal(body.targetProjectId, plan.projectId);
            assert.ok(
              journal.some((r) => r.accountRef === account.ref && r.accountMutation === "delete"),
            );
            account.present = false;
            data = {};
          } else {
            assert.ok(url.pathname.endsWith(":lookup"));
            const account = accounts.find(
              (a) =>
                a.token === body.idToken ||
                body.localId?.includes(a.uid) ||
                body.email?.includes(a.email),
            );
            assert.ok(account);
            data = account.present
              ? { users: [{ localId: account.uid, email: account.email, disabled: false }] }
              : {};
          }
        }
        return { status: 200, data };
      },
      async (connections) => {
        const send = (kind) => {
          const probe = recipe.probes.find((p) => p.credential === kind && p.action === "read");
          assert.ok(probe);
          const step = {
            ...probe.subject,
            id: `auth-wire-${kind}`,
            dialect: "firebase",
            headers: {},
          };
          const operationId = `r1/p25/${hash(step.id)}`;
          return counter.send(
            operationId,
            () =>
              wire.fetchStorage(1, step, {
                method: "GET",
                operationId,
                accountingPhase: "subject",
              }),
            recipeToken,
          );
        };
        await action({
          state,
          wire,
          counter,
          recipe,
          recipeToken,
          reserves,
          bytes,
          proofs,
          journal,
          secrets,
          accounts,
          connections,
          directory,
          send,
        });
      },
    );
  } finally {
    state?.close();
    await wire?.close();
    rmSync(directory, { recursive: true });
  }
}
function assertSafe(f) {
  const inspect = (value) => {
    if (typeof value === "string") {
      const candidates = [value, Buffer.from(value, "base64").toString()];
      for (const copy of candidates.slice()) {
        try {
          candidates.push(decodeURIComponent(copy));
        } catch (error) {
          if (!(error instanceof URIError)) throw error;
        }
      }
      for (const copy of candidates)
        for (const secret of f.secrets) assert.equal(copy.includes(secret), false);
    } else if (value && typeof value === "object")
      for (const child of Object.values(value)) inspect(child);
  };
  for (const file of readdirSync(f.directory)) {
    const path = join(f.directory, file);
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const saved = readFileSync(path, "utf8");
    inspect(saved);
    inspect(JSON.parse(saved));
  }
  inspect(f.reserves);
  inspect(f.bytes);
  inspect(f.proofs);
  inspect(f.journal);
}

test("the actual Auth lifecycle, controls and wire share Firebase credentials and clean only owned accounts", async () => {
  await fixture(async (f) => {
    await f.state.setup(f.recipe.id, f.recipeToken);
    await f.state.refresh(f.recipe.id, f.recipeToken);
    for (const kind of ["valid", "competitor"]) assert.equal((await f.send(kind)).status, 404);
    f.counter.beginCleanup(f.recipeToken);
    await f.state.cleanup(f.recipe.id, f.recipeToken);
    assert.equal(f.state.snapshot().unresolved.length, 0);
    assert.equal(f.connections.length, 24);
    assert.equal(f.reserves.length, f.connections.length);
    assert.equal(f.bytes.length, f.connections.length);
    assert.equal(f.wire.snapshot().attempts, f.connections.length);
    assert.ok(f.accounts.every((a) => !a.present));
    assertSafe(f);
  });
});

test("a declared malformed credential can be registered inside the account authorization callback", async () => {
  await fixture(async (f) => {
    await f.state.setup(f.recipe.id, f.recipeToken);
    assert.equal((await f.send("malformed")).status, 403);
    assert.equal(f.connections.length, 9);
    assert.equal(f.bytes.length, 9);
    assert.equal(f.wire.snapshot().failed, false);
    assertSafe(f);
  });
});

test("credential registration from a byte reservation callback is rejected before a socket", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(f.recipe.id, f.recipeToken), /production Auth/);
      assert.equal(f.connections.length, 0);
      assert.equal(f.wire.snapshot().failed, true);
    },
    { illegalRegistration: true },
  );
});

test("a failing owner provider does not expose its credential or create a socket", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(f.recipe.id, f.recipeToken), (error) => {
        assert.equal(error.message.includes(owner), false);
        assert.equal(error.cause, undefined);
        return true;
      });
      assert.equal(f.connections.length, 0);
      assert.equal(f.wire.snapshot().failed, true);
      assertSafe(f);
    },
    { ownerProviderFailure: true },
  );
});

test("closing the wire inside an account provider prevents the subject socket", async () => {
  await fixture(
    async (f) => {
      await f.state.setup(f.recipe.id, f.recipeToken);
      await assert.rejects(f.send("valid"), /PRODUCTION_WIRE/);
      assert.equal(f.connections.length, 8);
      assert.equal(f.wire.snapshot().closed, true);
      assert.equal(f.wire.snapshot().failed, true);
      assertSafe(f);
    },
    { closeAccountProvider: true },
  );
});

test("the credential registration window excludes the admission callback", async () => {
  await fixture(
    async (f) => {
      await assert.rejects(f.state.setup(f.recipe.id, f.recipeToken), /production Auth/);
      assert.equal(f.connections.length, 0);
      assert.equal(f.wire.snapshot().failed, true);
      assertSafe(f);
    },
    { illegalAdmissionRegistration: true },
  );
});

test("account provider results are rejected without invoking coercion hooks", async () => {
  let hooks = 0;
  await fixture(
    async (f) => {
      await f.state.setup(f.recipe.id, f.recipeToken);
      await assert.rejects(f.send("valid"), /PRODUCTION_WIRE/);
      assert.equal(hooks, 0);
      assert.equal(f.connections.length, 8);
      assert.equal(f.wire.snapshot().failed, true);
      assertSafe(f);
    },
    {
      accountAuthorizationResult: {
        toString() {
          hooks++;
          return "Firebase SYNTHETIC_PROVIDER_COERCION_TOKEN";
        },
      },
    },
  );
});

test("rejecting native Promise results cannot publish an unhandled credential rejection", () => {
  for (const kind of ["owner", "account"]) {
    const child = spawnSync(process.execPath, ["--input-type=module", "-"], {
      cwd: new URL(".", import.meta.url),
      encoding: "utf8",
      timeout: 10000,
      input: `
      import {mkdtempSync,chmodSync,rmSync} from 'node:fs';
      import {tmpdir} from 'node:os';
      import {join} from 'node:path';
      import tls from 'node:tls';
      import {buildAuthCorpus} from './storage-object/auth-corpus.mjs';
      import {createProductionWireTransport} from './storage-object/production-wire-transport.mjs';
      import {buildProductionStage3DraftPlan} from './storage-object/stage3-plan.mjs';
      process.execArgv=[];
      let unhandled=0,hooks=0,providerCalls=0,reservations=0,sockets=0;
      tls.connect=()=>{sockets++;throw new Error('UNEXPECTED_SOCKET');};
      process.on('unhandledRejection',()=>{unhandled++;});
      const provider=()=>{
        providerCalls++;
        const value=Promise.reject('SYNTHETIC_PROVIDER_REJECTION_REASON');
        Object.defineProperty(value,'then',{get(){hooks++;throw new Error('UNEXPECTED_THEN_HOOK');}});
        return value;
      };
      const directory=mkdtempSync(join(tmpdir(),'storage-object-provider-promise-'));
      chmodSync(directory,0o700);
      let wire;
      try {
        const plan=buildProductionStage3DraftPlan({projectId:'example-project',bucket:'example.appspot.com',runIds:['recordone','recordtwo']});
        const kind='${kind}';
        wire=createProductionWireTransport({plan,resources:{projectNumber:'123456789012',apiKeyResource:'projects/123456789012/locations/global/keys/fixture-key',rulesetResource:'projects/example-project/rulesets/fixture-ruleset'},captureDirectory:directory,onByteReserve:async()=>{reservations++;throw new Error('UNEXPECTED_RESERVATION');},verifyAdmission:()=>true,ownerAuthorization:kind==='owner'?provider:()=> 'Bearer SYNTHETIC_OWNER',accountAuthorization:kind==='account'?provider:()=>{throw new Error('UNUSED_ACCOUNT');}});
        const step=buildAuthCorpus({projectId:plan.projectId,bucket:plan.bucket,runId:'recordone'}).recipes[0].probes.find(p=>p.credential==='valid'&&p.action==='read').subject;
        const send=()=>kind==='owner'?wire.fetchControl(1,'owner-tokeninfo',{}, {operationId:'r1/control/'+'a'.repeat(64),accountingPhase:'subject'}):wire.fetchStorage(1,{...step,id:'promise-provider',dialect:'firebase'}, {operationId:'r1/p25/'+'a'.repeat(64),accountingPhase:'subject'});
        let rejected=false;
        try {await send();} catch(error) {rejected=error.message==='PRODUCTION_WIRE_REQUEST_REJECTED' && error.cause===undefined;}
        await new Promise(resolve=>setImmediate(resolve));
        try {await send();} catch {}
        process.stdout.write(JSON.stringify({unhandled,hooks,providerCalls,reservations,sockets,rejected,attempts:wire.snapshot().attempts,failed:wire.snapshot().failed}));
      } finally {await wire?.close();rmSync(directory,{recursive:true});}
    `,
    });
    assert.equal(child.status, 0);
    assert.equal(child.stderr, "");
    assert.deepEqual(JSON.parse(child.stdout), {
      unhandled: 0,
      hooks: 0,
      providerCalls: 1,
      reservations: 0,
      sockets: 0,
      rejected: true,
      attempts: 0,
      failed: true,
    });
  }
});
