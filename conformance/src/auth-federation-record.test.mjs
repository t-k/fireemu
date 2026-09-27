import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";

import { SANDBOX_PROJECT } from "./auth-account/harness.mjs";
import { limitedFetch } from "./auth-federation/hosting.mjs";
import {
  buildFixture,
  LIMITS,
  RUNNER,
  recordCampaign,
  recordingToRecover,
  recoverCampaign,
  scanFixture,
  SOURCES,
  TASK_ID,
} from "./auth-federation/record.mjs";
import { fakeHosting } from "./auth-federation/rehearse.mjs";
import { prepareKeys } from "./auth-federation/run.mjs";

const RUN = "a1b2c3";
const CONFIG = JSON.stringify({
  authorizedDomains: [`${SANDBOX_PROJECT}.firebaseapp.com`],
  subtype: "IDENTITY_PLATFORM",
  signIn: { allowDuplicateEmails: false },
});
const reply = (status, body, headers = {}) =>
  new Response(typeof body === "string" ? body : JSON.stringify(body), {
    status,
    headers: { date: new Date().toUTCString(), ...headers },
  });

/** A fake Identity Toolkit for the prechecks, the cleanup read-backs and a recovery. */
function fakeToolkit(overrides = {}) {
  const state = {
    config: CONFIG,
    oauthIdpConfigs: [],
    inboundSamlConfigs: [],
    defaultIdps: new Set(),
    users: [],
    calls: [],
  };
  const fetchImpl = async (url, init = {}) => {
    const method = init.method ?? "GET";
    state.calls.push({ method, url });
    const { pathname } = new URL(url);
    if (overrides[pathname.split("/").at(-1)])
      return overrides[pathname.split("/").at(-1)](state, method);
    if (pathname.endsWith("/config")) {
      if (method === "PATCH") {
        const value = JSON.parse(init.body).signIn.allowDuplicateEmails;
        state.config = JSON.stringify({
          ...JSON.parse(state.config),
          signIn: { allowDuplicateEmails: value },
        });
        return reply(200, state.config);
      }
      return reply(200, state.config);
    }
    for (const collection of ["oauthIdpConfigs", "inboundSamlConfigs"]) {
      if (pathname.endsWith(`/${collection}`)) {
        return reply(200, {
          [collection]: state[collection].map((id) => ({ name: `projects/p/${collection}/${id}` })),
        });
      }
      if (pathname.includes(`/${collection}/`) && method === "DELETE") {
        state[collection] = state[collection].filter((id) => !pathname.endsWith(`/${id}`));
        return reply(200, {});
      }
    }
    if (pathname.includes("/defaultSupportedIdpConfigs/")) {
      const idp = pathname.split("/").at(-1);
      if (method === "DELETE") state.defaultIdps.delete(idp);
      return reply(method === "DELETE" || state.defaultIdps.has(idp) ? 200 : 404, {});
    }
    if (pathname.endsWith("accounts:batchGet"))
      return reply(200, state.users.length ? { users: state.users } : {});
    if (pathname.endsWith("accounts:delete")) {
      const { localId } = JSON.parse(init.body);
      state.users = state.users.filter((user) => user.localId !== localId);
      return reply(200, {});
    }
    return reply(500, { unexpected: `${method} ${url}` });
  };
  return { fetchImpl, state };
}

function sandbox({ toolkit = {}, hosting } = {}) {
  const itk = fakeToolkit(toolkit);
  const site = fakeHosting(RUN);
  const handle = hosting ?? site.handle;
  const fetchImpl = (url, init) =>
    new URL(url).host === "identitytoolkit.googleapis.com"
      ? itk.fetchImpl(url, init)
      : handle(url, init);
  return { itk, site, fetchImpl };
}

const META = {
  adminToken: "owner",
  apiKey: "fake-api-key",
  projectNumber: "123456789012",
  gitSha: "c".repeat(40),
  digest: "d".repeat(64),
  envelopeId: "AUTH-FEDERATION-record-oidc-1",
  startedAt: "t",
};

async function campaign(env, extra = {}) {
  const ledger = [];
  const { call, used } = limitedFetch(env.fetchImpl, { run: RUN, limits: LIMITS });
  const result = await recordCampaign({
    api: call,
    run: RUN,
    keys: prepareKeys(),
    certificatePem: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
    meta: META,
    appendLedger: async (line) => ledger.push(line),
    writeFixture: async () => {},
    stop: { check() {} },
    now: () => Math.floor(Date.now() / 1000),
    sleep: async () => {},
    ...extra,
  }).catch((error) => ({ thrown: error }));
  return { result, ledger, used };
}

test("the limits make the envelope's 500 requests, and the digest covers every module it runs", () => {
  assert.equal(LIMITS.api + LIMITS.issuer, RUNNER.maxRequests);
  const covered = new Set(SOURCES);
  for (const source of SOURCES) {
    for (const [, relative] of readFileSync(source, "utf8").matchAll(/from "(\.{1,2}\/[^"]+)"/g)) {
      const imported = resolve(dirname(source), relative);
      if (imported.endsWith("/config.mjs") || imported.endsWith("/evidence.mjs")) {
        // Only the local mode of run.mjs imports these, and never with a request.
        continue;
      }
      assert.ok(
        covered.has(imported),
        `${source} imports ${imported}, which the digest does not cover`,
      );
    }
  }
  assert.ok(
    !SOURCES.some((path) => path.endsWith("/rehearse.mjs")),
    "the rehearsal is not run in production",
  );
});

test("a failed precheck writes nothing and sends no write", async () => {
  const cases = {
    "a left provider": {
      toolkit: {
        oauthIdpConfigs: () =>
          reply(200, { oauthIdpConfigs: [{ name: "x/oauthIdpConfigs/oidc.fireemu-d4e5f6-a" }] }),
      },
    },
    "an account": {
      toolkit: { "accounts:batchGet": () => reply(200, { users: [{ localId: "x" }] }) },
    },
    "no Identity Platform": {
      toolkit: {
        config: () =>
          reply(200, JSON.stringify({ ...JSON.parse(CONFIG), subtype: "FIREBASE_AUTH" })),
      },
    },
  };
  for (const [name, options] of Object.entries(cases)) {
    const env = sandbox(options);
    const { result, ledger } = await campaign(env);
    assert.match(String(result.thrown?.message), /precheck/, name);
    assert.deepEqual(ledger, [], name);
    assert.ok(
      env.itk.state.calls.every(({ method }) => method === "GET"),
      name,
    );
  }
});

test("a recording that fails while publishing the issuer cleans up and writes no fixture", async () => {
  let fixture = false;
  const env = sandbox();
  const handle = env.site.handle;
  const failing = sandbox({
    hosting: (url, init) =>
      new URL(url).pathname.endsWith(":populateFiles") ? reply(500, {}) : handle(url, init),
  });
  failing.site = env.site;
  const { result, ledger } = await campaign(failing, {
    writeFixture: async () => {
      fixture = true;
    },
  });
  assert.equal(result.outcome, "failed-cleaned", JSON.stringify(result));
  assert.match(result.error, /populateFiles/);
  assert.equal(result.passes, 0);
  assert.equal(result.channelReadBack, "absent");
  assert.equal(result.versionStatus, "absent");
  assert.equal(fixture, false);
  assert.equal(result.fixtureError, undefined, "no fixture is built from an incomplete recording");
  assert.equal(ledger[0].event, "started");
  assert.deepEqual(ledger[0].touchedBefore, { "signIn.allowDuplicateEmails": false });
  assert.ok(
    !JSON.stringify(ledger[0]).includes("IDENTITY_PLATFORM"),
    "config values stay out of the ledger",
  );
});

test("the fixture keeps the first pass and the rows the second recorded differently", () => {
  const row = (status) => ({ status, body: {} });
  const fixture = buildFixture(
    [
      {
        results: {
          "auth-federation/link": { steps: { a: row(200), b: row(400) } },
          "auth-federation/only-first": { steps: { a: row(200) } },
        },
      },
      { results: { "auth-federation/link": { steps: { a: row(200), b: row(409) } } } },
    ],
    META,
  );
  assert.deepEqual(Object.keys(fixture.programs), ["auth-federation/link"]);
  assert.deepEqual(fixture.programs["auth-federation/link"].second, { b: row(409) });
  assert.equal(fixture.programs["auth-federation/link"].gitSha, META.gitSha);
  assert.equal(fixture.programs["auth-federation/link"].harnessDigest, META.digest);
});

test("a fixture with a secret, a key, a raw token or a private key is refused", () => {
  assert.doesNotThrow(() => scanFixture('{"idToken":{"<jwt>":{}}}', ["fake-api-key"]));
  assert.throws(() => scanFixture('{"x":"fake-api-key"}', ["fake-api-key"]), /secret value/);
  assert.throws(() => scanFixture(`{"x":"${"AIza"}${"Sy".padEnd(35, "0")}"}`, []), /API key/);
  assert.throws(
    () => scanFixture('{"x":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"}', []),
    /raw JWT/,
  );
  assert.throws(() => scanFixture("-----BEGIN PRIVATE KEY-----", []), /private key/);
});

test("recover removes the run's issuer, providers, default IdPs and accounts and restores the config", async () => {
  const line = (extra) =>
    JSON.stringify({ ts: "t", project: SANDBOX_PROJECT, taskId: TASK_ID, ...extra });
  const configDigestBefore = createHash("sha256").update(CONFIG).digest("hex");
  const started = line({
    event: "started",
    action: "record-oidc",
    run: RUN,
    scriptDigest: "d".repeat(64),
    configDigestBefore,
    configKeyDigestsBefore: {},
    touchedBefore: { "signIn.allowDuplicateEmails": false },
  });
  const named = line({
    action: "record-oidc",
    outcome: "needs-recovery",
    run: RUN,
    issuerHost: `${SANDBOX_PROJECT}--fed-${RUN}-rehearse.web.app`,
    version: `sites/${SANDBOX_PROJECT}/versions/rehearsal`,
  });
  const target = recordingToRecover(`${started}\n${named}`);
  assert.equal(target.run, RUN);
  assert.equal(target.version, `sites/${SANDBOX_PROJECT}/versions/rehearsal`);
  assert.equal(
    recordingToRecover(
      `${started}\n${line({ action: "record-oidc", run: RUN, outcome: "recorded" })}`,
    ),
    undefined,
  );

  const env = sandbox();
  env.site.state.channel = true;
  Object.assign(env.itk.state, {
    config: JSON.stringify({ ...JSON.parse(CONFIG), signIn: { allowDuplicateEmails: true } }),
    oauthIdpConfigs: [`oidc.fireemu-${RUN}-a`, "oidc.corporate"],
    inboundSamlConfigs: [`saml.fireemu-${RUN}-a`],
    defaultIdps: new Set(["google.com"]),
    users: [
      { localId: "1", email: `fireemu-fed-${RUN}-link@example.com` },
      { localId: "2", providerUserInfo: [{ providerId: `oidc.fireemu-${RUN}-v` }] },
      { localId: "3", email: "someone@example.com" },
    ],
  });
  const ledger = [];
  const { call } = limitedFetch(env.fetchImpl, { run: RUN, limits: LIMITS });
  const entry = await recoverCampaign({
    api: call,
    target,
    meta: { adminToken: "owner" },
    appendLedger: async (recorded) => ledger.push(recorded),
    sleep: async () => {},
  });
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.deepEqual(
    env.itk.state.oauthIdpConfigs,
    ["oidc.corporate"],
    "only the run's providers go",
  );
  assert.deepEqual(env.itk.state.inboundSamlConfigs, []);
  assert.deepEqual(
    env.itk.state.users.map((user) => user.localId),
    ["3"],
    "only the run's accounts go",
  );
  assert.equal(JSON.parse(env.itk.state.config).signIn.allowDuplicateEmails, false);
  assert.equal(env.site.state.versionDeleted, true);
  assert.equal(ledger.at(-1).action, "record-oidc-recover");
});
