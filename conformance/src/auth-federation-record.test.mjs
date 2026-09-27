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
    if (pathname.endsWith("/defaultSupportedIdpConfigs")) {
      return reply(200, {
        defaultSupportedIdpConfigs: [...state.defaultIdps].map((id) => ({
          name: `projects/p/defaultSupportedIdpConfigs/${id}`,
        })),
      });
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
  // The version create and its ID are journalled before the terminal line, for a recovery.
  assert.deepEqual(
    ledger
      .filter((line) => line.event === "progress")
      .map(({ step, versionId }) => step ?? versionId),
    ["version-create-sent", "rehearsal"],
  );
  assert.equal(ledger.at(-1).versionId, "rehearsal");
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

const ledgerLine = (extra) =>
  JSON.stringify({
    ts: "2026-09-28T00:00:00Z",
    project: SANDBOX_PROJECT,
    taskId: TASK_ID,
    ...extra,
  });
const CONFIG_DIGEST = createHash("sha256").update(CONFIG).digest("hex");
const STARTED = ledgerLine({
  event: "started",
  action: "record-oidc",
  run: RUN,
  scriptDigest: "d".repeat(64),
  configDigestBefore: CONFIG_DIGEST,
  configKeyDigestsBefore: {},
  touchedBefore: { "signIn.allowDuplicateEmails": false },
  defaultIdpsAbsentBefore: ["facebook.com"],
});
const progress = (extra) =>
  ledgerLine({ event: "progress", action: "record-oidc", run: RUN, ...extra });

test("recover finds the unfinished recording and what it journalled", () => {
  const sent = progress({ step: "version-create-sent" });
  const id = progress({ versionId: "v123" });
  assert.deepEqual(recordingToRecover(`${STARTED}\n${sent}\n${id}`), {
    run: RUN,
    digest: "d".repeat(64),
    configDigestBefore: CONFIG_DIGEST,
    configKeyDigestsBefore: {},
    touchedBefore: { "signIn.allowDuplicateEmails": false },
    defaultIdpsAbsentBefore: ["facebook.com"],
    issuerHost: undefined,
    versionId: "v123",
    versionSent: true,
  });
  // Progress lines end nothing; a clean terminal line or a recovery does.
  assert.ok(recordingToRecover(`${STARTED}\n${sent}`));
  const done = (extra) => ledgerLine({ action: "record-oidc", run: RUN, ...extra });
  assert.equal(recordingToRecover(`${STARTED}\n${done({ outcome: "recorded" })}`), undefined);
  assert.ok(recordingToRecover(`${STARTED}\n${done({ outcome: "needs-recovery" })}`));
  assert.ok(
    recordingToRecover(
      `${STARTED}\n${done({ outcome: "failed-cleaned", sandboxAtBaseline: false })}`,
    ),
  );
  assert.equal(
    recordingToRecover(
      `${STARTED}\n${done({ outcome: "needs-recovery" })}\n${ledgerLine({ action: "record-oidc-recover", run: RUN, outcome: "recovered" })}`,
    ),
    undefined,
  );
  assert.equal(recordingToRecover(""), undefined);
});

async function recover(env, target) {
  const ledger = [];
  const { call } = limitedFetch(env.fetchImpl, { run: RUN, limits: LIMITS });
  const entry = await recoverCampaign({
    api: call,
    target,
    meta: { adminToken: "owner" },
    appendLedger: async (recorded) => ledger.push(recorded),
    sleep: async () => {},
  });
  return { entry, ledger };
}

test("recover removes the run's issuer, providers, declared default IdPs and accounts and restores the config", async () => {
  const env = sandbox();
  env.site.state.channel = true;
  env.site.state.released = true;
  Object.assign(env.itk.state, {
    config: JSON.stringify({ ...JSON.parse(CONFIG), signIn: { allowDuplicateEmails: true } }),
    oauthIdpConfigs: [`oidc.fireemu-${RUN}-a`, `fireemu-${RUN}-noprefix`, "oidc.corporate"],
    inboundSamlConfigs: [`saml.fireemu-${RUN}-a`],
    defaultIdps: new Set(["facebook.com"]),
    users: [
      { localId: "1", email: `fireemu-fed-${RUN}-link@example.com` },
      { localId: "2", providerUserInfo: [{ providerId: `oidc.fireemu-${RUN}-v` }] },
      { localId: "3", email: "someone@example.com" },
    ],
  });
  // Only a started line: the version comes from the channel's release.
  const { entry, ledger } = await recover(env, recordingToRecover(STARTED));
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.equal(entry.versionId, "rehearsal");
  assert.equal(env.site.state.versionDeleted, true);
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
  assert.equal(env.itk.state.defaultIdps.size, 0);
  assert.equal(JSON.parse(env.itk.state.config).signIn.allowDuplicateEmails, false);
  assert.equal(ledger.at(-1).action, "record-oidc-recover");
});

test("recover removes the version when the channel is already gone, and never an unknown one", async () => {
  // The recording removed its channel; its version is known from the journal.
  const gone = sandbox();
  const known = await recover(
    gone,
    recordingToRecover(`${STARTED}\n${progress({ versionId: "rehearsal" })}`),
  );
  assert.equal(known.entry.outcome, "recovered", JSON.stringify(known.entry));
  assert.equal(known.entry.channelReadBack, "absent");
  assert.equal(gone.site.state.versionDeleted, true);
  // A version create was sent but its ID never journalled and no channel names it.
  const lost = await recover(
    sandbox(),
    recordingToRecover(`${STARTED}\n${progress({ step: "version-create-sent" })}`),
  );
  assert.equal(lost.entry.outcome, "needs-recovery");
  assert.equal(lost.entry.versionStatus, "unknown");
  // No version was ever attempted.
  const none = await recover(sandbox(), recordingToRecover(STARTED));
  assert.equal(none.entry.outcome, "recovered");
  assert.equal(none.entry.versionStatus, "none");
});

test("recover never removes a default IdP the run did not see absent", async () => {
  const env = sandbox();
  env.itk.state.defaultIdps = new Set(["facebook.com"]);
  const started = STARTED.replace(
    '"defaultIdpsAbsentBefore":["facebook.com"]',
    '"defaultIdpsAbsentBefore":[]',
  );
  const { entry } = await recover(env, recordingToRecover(started));
  assert.ok(env.itk.state.defaultIdps.has("facebook.com"));
  assert.equal(entry.outcome, "recovered");
});

test("a default IdP or any provider present before stops the recording before it writes", async () => {
  for (const [name, state] of Object.entries({
    "facebook.com": { defaultIdps: new Set(["facebook.com"]) },
    "a corporate OIDC provider": { oauthIdpConfigs: ["oidc.corporate"] },
  })) {
    const env = sandbox();
    Object.assign(env.itk.state, state);
    const { result, ledger } = await campaign(env);
    assert.match(String(result.thrown?.message), /precheck: the project has/, name);
    assert.deepEqual(ledger, [], name);
    assert.ok(
      env.itk.state.calls.every(({ method }) => method === "GET"),
      name,
    );
  }
});

test("a pass is held to its share of the requests", async () => {
  const { budget } = await import("./auth-federation/record.mjs");
  let sent = 0;
  const api = budget(async () => (sent += 1), 2, "pass 1");
  await api("a");
  await api("b");
  await assert.rejects(api("c"), /pass 1 used its 2 requests/);
  assert.equal(sent, 2);
});

test("ledger lines never hold the project number or the API key", async () => {
  const { appender } = await import("./auth-federation/record.mjs");
  const { mkdtemp, readFile } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "fed-ledger-"));
  const path = join(dir, "ledger.jsonl");
  const state = { sent: false };
  const append = appender(path, { api: 1, issuer: 0 }, state, {
    projectNumber: "123456789012",
    apiKey: "fake-api-key-for-the-test-00",
  });
  await append({
    event: "started",
    error: "HTTP 500 projects/123456789012 key=fake-api-key-for-the-test-00",
  });
  const text = await readFile(path, "utf8");
  assert.ok(!text.includes("123456789012") && !text.includes("fake-api-key-for-the-test-00"), text);
  assert.match(text, /<project-number>.*<api-key>/);
  assert.equal(state.sent, true, "a started line keeps the lock");
});

test("the fixture is kept privately before a scan can refuse it", async () => {
  const { writeFixtureFiles } = await import("./auth-federation/record.mjs");
  const { mkdtemp, readFile, stat } = await import("node:fs/promises");
  const { existsSync } = await import("node:fs");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const dir = await mkdtemp(join(tmpdir(), "fed-fixture-"));
  const target = join(dir, "committed.json");
  const privateDir = join(dir, "private");
  await assert.rejects(
    writeFixtureFiles(
      { programs: { x: { signerKey: "real" } } },
      { privateDir, forbidden: [], target },
    ),
    /password-hash key material/,
  );
  assert.ok(!existsSync(target));
  assert.match(await readFile(join(privateDir, "fixture.json"), "utf8"), /real/);
  assert.equal((await stat(join(privateDir, "fixture.json"))).mode & 0o777, 0o600);
  await writeFixtureFiles({ programs: {} }, { privateDir, forbidden: [], target });
  assert.ok(existsSync(target));
});

test("the fixture scan refuses key material, real hashes, client secrets and Google credentials", () => {
  const refused = {
    signerKey: '{"signerKey":"QUJD"}',
    saltSeparator: '{"saltSeparator":"Bw=="}',
    salt: '{"salt":"c2FsdA=="}',
    "a real password hash": '{"passwordHash":"aGFzaA=="}',
    "a client secret": '{"clientSecret":"not-ours"}',
    "an OAuth secret": '{"x":"GOCSPX-abc"}',
    "an access token": '{"x":"ya29.abc"}',
    "a refresh token": '{"x":"AMf-abc"}',
  };
  for (const [name, text] of Object.entries(refused))
    assert.throws(() => scanFixture(text, []), Error, name);
  assert.doesNotThrow(() =>
    scanFixture(
      '{"signerKey":"<bytes>","salt":"<bytes>","passwordHash":"UkVEQUNURUQ=","clientSecret":"fireemu-secret"}',
      [],
    ),
  );
});

test("a config answer and a provider list keep no key material or foreign secret", async () => {
  const { normalizeHttp } = await import("./auth-federation/harness.mjs");
  const ctx = { run: RUN, project: SANDBOX_PROJECT };
  const config = JSON.stringify({
    signIn: {
      allowDuplicateEmails: true,
      hashConfig: { algorithm: "SCRYPT", signerKey: "c2VjcmV0", saltSeparator: "Bw==", rounds: 8 },
    },
    notification: { sendEmail: { callbackUri: "x" } },
  });
  const projected = normalizeHttp(200, config, ctx, ["signIn.allowDuplicateEmails"]);
  assert.deepEqual(projected, { status: 200, body: { signIn: { allowDuplicateEmails: true } } });
  const whole = normalizeHttp(200, config, ctx);
  assert.equal(whole.body.signIn.hashConfig.signerKey, "<bytes>");
  assert.equal(whole.body.signIn.hashConfig.saltSeparator, "<bytes>");
  const list = normalizeHttp(
    200,
    JSON.stringify({
      defaultSupportedIdpConfigs: [
        { name: "google.com", clientSecret: "GOCSPX-real" },
        { name: "facebook.com", clientSecret: "fireemu-secret" },
      ],
      users: [{ passwordHash: "cmVhbA==", salt: "c2FsdA==" }, { passwordHash: "UkVEQUNURUQ=" }],
    }),
    ctx,
  );
  assert.deepEqual(
    list.body.defaultSupportedIdpConfigs.map((idp) => idp.clientSecret),
    ["<client-secret>", "fireemu-secret"],
  );
  assert.deepEqual(list.body.users, [
    { passwordHash: "<bytes>", salt: "<bytes>" },
    { passwordHash: "UkVEQUNURUQ=" },
  ]);
  assert.doesNotThrow(() => scanFixture(JSON.stringify([whole, list]), []));
});

test("a version whose create answer was lost is found by the run's label and removed", async () => {
  // The service made the version, the answer never came.
  const lostAnswer = (env) => (url, init) => {
    const { pathname } = new URL(url);
    if ((init?.method ?? "GET") === "POST" && pathname.endsWith("/versions")) {
      return env.site.handle(url, init).then(() => {
        throw new TypeError("fetch failed");
      });
    }
    return env.site.handle(url, init);
  };
  const base = sandbox();
  const env = sandbox({ hosting: lostAnswer(base) });
  env.site = base.site;
  const { result, ledger } = await campaign(env);
  assert.deepEqual(base.site.state.versionLabels, { "fireemu-run": RUN });
  assert.equal(base.site.state.versionDeleted, true, "the labelled version is removed");
  assert.equal(result.outcome, "failed-cleaned", JSON.stringify(result));
  assert.equal(result.versionStatus, "absent");
  assert.ok(ledger.some((line) => line.step === "version-create-sent"));

  // When no version carries the label (the listing does not show it yet), the run stays open.
  const hidden = sandbox();
  const unseen = sandbox({
    hosting: (url, init) => {
      const { pathname } = new URL(url);
      if ((init?.method ?? "GET") === "POST" && pathname.endsWith("/versions")) {
        return Promise.reject(new TypeError("fetch failed"));
      }
      return hidden.site.handle(url, init);
    },
  });
  unseen.site = hidden.site;
  const open = await campaign(unseen);
  assert.equal(open.result.outcome, "needs-recovery", JSON.stringify(open.result));
  const text = open.ledger
    .map((line) =>
      JSON.stringify({
        ts: "2026-09-28T00:00:00Z",
        project: SANDBOX_PROJECT,
        taskId: TASK_ID,
        ...line,
      }),
    )
    .join("\n");
  const target = recordingToRecover(text);
  assert.equal(target?.run, RUN);
  assert.equal(target.versionSent, true);
});

test("recover finds a version by the run's label and leaves other runs' versions", async () => {
  const env = sandbox();
  env.site.state.versionCreated = true;
  env.site.state.versionLabels = { "fireemu-run": RUN };
  env.site.state.otherVersions = [
    {
      name: `sites/${SANDBOX_PROJECT}/versions/other`,
      labels: { "fireemu-run": "d4e5f6" },
      status: "CREATED",
    },
  ];
  const { entry } = await recover(
    env,
    recordingToRecover(`${STARTED}\n${progress({ step: "version-create-sent" })}`),
  );
  assert.equal(entry.outcome, "recovered", JSON.stringify(entry));
  assert.equal(entry.versionId, "rehearsal");
  assert.equal(env.site.state.versionDeleted, true);
  assert.deepEqual(
    env.site.state.otherVersions.map((v) => v.name.split("/").at(-1)),
    ["other"],
  );
});
