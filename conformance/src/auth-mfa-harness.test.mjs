import assert from "node:assert/strict";
import { test } from "node:test";

import { buildRequest, createContext } from "./auth-account/harness.mjs";
import { PROGRAMS } from "./auth-mfa/corpus.mjs";
import {
  MFA_CONFIGS,
  MFA_CONFIG_PROBES,
  guardMfaRequest,
  validateMfaCorpus,
} from "./auth-mfa/guard.mjs";
import {
  base32Decode,
  createEnrollmentRegistry,
  deadlineAfter,
  hotp,
  normalizeMfaResponse,
  timeStep,
  totpCode,
  wrongCode,
} from "./auth-mfa/harness.mjs";
import { resolveCodes } from "./auth-mfa/session.mjs";

const production = createContext({
  run: "1790000000000",
  project: "fireemu-oracle-idp",
  target: {
    kind: "production",
    apiKey: "AIzaFAKEKEYFORTESTSONLY",
    adminToken: "ya29.owner",
    quotaProject: "fireemu-oracle-idp",
    projectNumber: "637500000000",
  },
  startedMs: 1_790_000_000_000,
});
const local = createContext({
  run: "1790000000000",
  project: "fireemu-oracle-idp",
  target: {
    kind: "local",
    origin: "http://127.0.0.1:32297",
    projectNumber: "123456789012",
    control: { url: "http://127.0.0.1:4400" },
  },
  startedMs: 1_790_000_000_000,
});

const request = (ctx, step) => buildRequest(step, ctx, new Map());
const v2 = (method, body) => ({ id: "s", path: `v2/accounts/${method}`, auth: "key", body });
const configPatch = (mfa, mask = "mfa") => ({
  id: "s",
  path: "admin/v2/projects/{project}/config",
  method: "PATCH",
  auth: "admin",
  query: { updateMask: mask },
  body: { mfa },
});

// RFC 6238 appendix B: the SHA-1 secret is the ASCII "12345678901234567890"; the RFC prints
// eight digits, whose last six are the six-digit code.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC_VECTORS = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
  [20000000000, "65353130"],
];

test("TOTP codes follow RFC 6238 (SHA-1, 30-second steps)", () => {
  assert.equal(base32Decode(RFC_SECRET).toString("ascii"), "12345678901234567890");
  assert.equal(base32Decode(RFC_SECRET.toLowerCase()).length, 20);
  for (const [seconds, eight] of RFC_VECTORS) {
    assert.equal(hotp(base32Decode(RFC_SECRET), timeStep(seconds), 8), eight, String(seconds));
    assert.equal(totpCode(RFC_SECRET, timeStep(seconds)), eight.slice(2), String(seconds));
  }
  assert.throws(() => base32Decode("not base32!"), /base32/);
});

test("a wrong code differs from every code within twenty steps", () => {
  const step = timeStep(1_790_000_000);
  const code = wrongCode(RFC_SECRET, step);
  assert.match(code, /^\d{6}$/);
  for (let s = step - 20; s <= step + 20; s += 1) assert.notEqual(totpCode(RFC_SECRET, s), code);
});

test("code forms resolve against the target's clock and are remembered per step", () => {
  const raw = new Map([["start", { totpSessionInfo: { sharedSecretKey: RFC_SECRET } }]]);
  const codes = new Map();
  const sent = [];
  const now = 1_111_111_111;
  const body = resolveCodes(
    { code: { $totp: "start", offset: -1 }, keep: { nested: "x" } },
    raw,
    codes,
    now,
    sent,
  );
  assert.equal(body.code, totpCode(RFC_SECRET, timeStep(now) - 1));
  assert.deepEqual(body.keep, { nested: "x" });
  assert.deepEqual(sent, [body.code]);
  codes.set("earlier", "123456");
  assert.equal(resolveCodes({ $sameCode: "earlier" }, raw, codes, now, []), "123456");
  assert.notEqual(
    resolveCodes({ $totpWrong: "start" }, raw, codes, now, []),
    totpCode(RFC_SECRET, timeStep(now)),
  );
  // A start that answered no secret is a dependency the row records, not a crash.
  assert.throws(
    () => resolveCodes({ $totp: "missing" }, raw, codes, now, []),
    /step missing recorded nothing at/,
  );
  assert.throws(
    () => resolveCodes({ $sameCode: "never" }, raw, codes, now, []),
    /step never recorded nothing at/,
  );
});

test("secrets, session infos and pending credentials are never recorded", () => {
  const registry = createEnrollmentRegistry();
  const body = {
    totpSessionInfo: {
      sharedSecretKey: RFC_SECRET,
      sessionInfo: "AB12-session",
      verificationCodeLength: 6,
      finalizeEnrollmentTime: "2026-09-21T15:00:00.123456Z",
    },
    mfaPendingCredential: "pending-credential",
    phoneSessionInfo: { sessionInfo: "phone-session" },
  };
  const recorded = normalizeMfaResponse(200, JSON.stringify(body), production, registry);
  const text = JSON.stringify(recorded);
  for (const secret of [RFC_SECRET, "AB12-session", "pending-credential", "phone-session"])
    assert.ok(!text.includes(secret), secret);
  assert.equal(recorded.body.totpSessionInfo.sharedSecretKey, "<sharedSecretKey>");
  assert.equal(
    recorded.body.totpSessionInfo.finalizeEnrollmentTime,
    "<run-time:instant:fraction-6>",
  );
});

test("second factors are named per program by first appearance and shape", () => {
  const registry = createEnrollmentRegistry();
  const uuid = "118bc06b-d441-4703-8217-b081775325f1";
  const first = normalizeMfaResponse(
    200,
    JSON.stringify({ mfaInfo: [{ mfaEnrollmentId: uuid, displayName: "a" }] }),
    local,
    registry,
  );
  assert.equal(first.body.mfaInfo[0].mfaEnrollmentId, "<enrollment:1:uuid>");
  const second = normalizeMfaResponse(
    400,
    JSON.stringify({ error: { message: `MFA_ENROLLMENT_NOT_FOUND ${uuid}` }, other: "plain" }),
    local,
    registry,
  );
  assert.equal(second.body.error.message, "MFA_ENROLLMENT_NOT_FOUND <enrollment:1:uuid>");
  const third = normalizeMfaResponse(
    200,
    JSON.stringify({ mfaInfo: [{ mfaEnrollmentId: "imported-factor-1" }] }),
    local,
    registry,
  );
  assert.equal(third.body.mfaInfo[0].mfaEnrollmentId, "<enrollment:2:other>");
  assert.equal(registry.size(), 2);
});

test("a config answer is recorded as its mfa member only", () => {
  const config = {
    mfa: { state: "ENABLED" },
    signIn: { hashConfig: { signerKey: "secret-signer" } },
    client: { apiKey: "AIzaFAKEKEYFORTESTSONLY" },
  };
  const recorded = normalizeMfaResponse(
    200,
    JSON.stringify(config),
    production,
    createEnrollmentRegistry(),
    { project: "mfa" },
  );
  assert.deepEqual(recorded, { status: 200, body: { mfa: { state: "ENABLED" } } });
  const refused = normalizeMfaResponse(
    400,
    JSON.stringify({ error: { message: "INVALID_CONFIG" } }),
    production,
    createEnrollmentRegistry(),
    { project: "mfa" },
  );
  assert.equal(refused.body.error.message, "INVALID_CONFIG");
});

test("an enrollment deadline is recorded as its distance from the send time", () => {
  const sent = Date.parse("2026-09-24T15:05:13Z") / 1000;
  assert.equal(deadlineAfter("2026-09-24T15:20:13.221248Z", sent), "+900s");
  assert.equal(deadlineAfter("2026-09-24T15:10:11Z", sent), "+300s");
  assert.equal(deadlineAfter("not a time", sent), "not-a-time");
});

test("phones are the configured test numbers and addresses are @example.com", () => {
  const ok = v2("mfaEnrollment:start", {
    idToken: "t",
    phoneEnrollmentInfo: { phoneNumber: "PHONE(2)" },
  });
  assert.doesNotThrow(() => guardMfaRequest(request(production, ok), production));
  const realPhone = v2("mfaEnrollment:start", {
    idToken: "t",
    phoneEnrollmentInfo: { phoneNumber: "+1 650 555 0199" },
  });
  assert.throws(() => guardMfaRequest(request(production, realPhone), production), /test phone/);
  const email = {
    id: "s",
    path: "v1/accounts:signInWithPassword",
    auth: "key",
    body: { email: "someone@gmail.com", password: "x" },
  };
  assert.throws(() => guardMfaRequest(request(production, email), production), /example\.com/);
});

test("only reviewed paths are sent, and only the harness wipes", () => {
  for (const path of [
    "v1/accounts:sendOobCode",
    "v1/accounts:signInWithIdp",
    "v2/accounts/mfaEnrollment:delete",
    "v1/projects/{project}/tenants",
  ]) {
    const step = { id: "s", path, auth: "key", body: {} };
    assert.throws(
      () => guardMfaRequest(request(production, step), production),
      /reviewed family/,
      path,
    );
  }
  const wipe = { id: "s", path: "v1/projects/{project}/accounts:batchDelete", auth: "admin" };
  assert.throws(() => guardMfaRequest(request(production, wipe), production), /reviewed family/);
  assert.doesNotThrow(() =>
    guardMfaRequest(request(production, wipe), production, { harness: true }),
  );
  const elsewhere = {
    id: "s",
    path: "v1/projects/fireemu-35fe6/accounts:lookup",
    auth: "admin",
    body: {},
  };
  assert.throws(
    () => guardMfaRequest(request(production, elsewhere), production),
    /reviewed family/,
  );
});

test("a config write changes only mfa, and only to a reviewed value", () => {
  for (const value of [...Object.values(MFA_CONFIGS), ...Object.values(MFA_CONFIG_PROBES)]) {
    assert.doesNotThrow(() => guardMfaRequest(request(production, configPatch(value)), production));
  }
  assert.throws(
    () =>
      guardMfaRequest(
        request(production, configPatch(MFA_CONFIGS.enabled, "mfa,signIn")),
        production,
      ),
    /names only mfa/,
  );
  assert.throws(
    () =>
      guardMfaRequest(
        request(production, { ...configPatch(MFA_CONFIGS.enabled), body: { signIn: {} } }),
        production,
      ),
    /holds only its masked paths/,
  );
  assert.throws(
    () =>
      guardMfaRequest(
        request(production, configPatch({ state: "ENABLED", enabledProviders: ["EMAIL"] })),
        production,
      ),
    /not reviewed/,
  );
  const put = { ...configPatch(MFA_CONFIGS.enabled), method: "PUT" };
  assert.throws(() => guardMfaRequest(request(production, put), production), /names only mfa/);
  // The email-link switch (owner decision M5), alone or with mfa, and nothing beside it.
  const withSwitch = {
    ...configPatch(MFA_CONFIGS.enabled, "mfa,signIn.email.passwordRequired"),
    body: { mfa: MFA_CONFIGS.enabled, signIn: { email: { passwordRequired: false } } },
  };
  assert.doesNotThrow(() => guardMfaRequest(request(production, withSwitch), production));
  const more = {
    ...withSwitch,
    body: { ...withSwitch.body, signIn: { email: { passwordRequired: false, enabled: false } } },
  };
  assert.throws(() => guardMfaRequest(request(production, more), production), /more than/);
});

test("the only action code is an email-link sign-in the Admin route returns", () => {
  const link = (body, auth = "admin") => ({
    id: "s",
    path:
      auth === "admin" ? "v1/projects/{project}/accounts:sendOobCode" : "v1/accounts:sendOobCode",
    auth,
    body,
  });
  const ok = { requestType: "EMAIL_SIGNIN", email: "EMAIL(a)", returnOobLink: true };
  assert.doesNotThrow(() => guardMfaRequest(request(production, link(ok)), production));
  for (const body of [
    { ...ok, returnOobLink: false },
    { ...ok, returnOobLink: undefined },
    { ...ok, requestType: "PASSWORD_RESET" },
  ]) {
    assert.throws(
      () => guardMfaRequest(request(production, link(body)), production),
      /email-link sign-in/,
    );
  }
  assert.throws(
    () => guardMfaRequest(request(production, link(ok, "key")), production),
    /reviewed family/,
  );
  const recorded = normalizeMfaResponse(
    200,
    JSON.stringify({
      oobCode: "code",
      oobLink: "https://x/?oobCode=code&apiKey=AIzaFAKEKEYFORTESTSONLY",
    }),
    production,
    createEnrollmentRegistry(),
  );
  assert.deepEqual(recorded.body, { oobCode: "<oobCode>", oobLink: "<oobLink>" });
});

test("the committed corpus is valid and within the request cap", () => {
  const requests = validateMfaCorpus(PROGRAMS);
  assert.ok(requests > 200 && requests < 450, String(requests));
  assert.equal(PROGRAMS[0].config, undefined, "the first program runs with MFA off");
  for (const program of PROGRAMS.slice(1))
    assert.ok(program.config?.mfa, `${program.id} declares its mfa config`);
});

test("the corpus validator refuses what the guard cannot see coming", () => {
  const base = { id: "p", steps: [], config: { mfa: MFA_CONFIGS.enabled } };
  const step = (extra) => ({
    id: "s",
    path: "v1/accounts:lookup",
    auth: "key",
    body: {},
    ...extra,
  });
  const refused = [
    [[{ ...base, config: { signIn: {} } }], /not allowed/],
    [[{ ...base, config: { mfa: MFA_CONFIG_PROBES.mandatory } }], /reviewed program config/],
    [[{ ...base, steps: [step({ body: { phoneNumber: "+16505550101" } })] }], /PHONE\(n\)/],
    [[{ ...base, steps: [step({ path: "v1/accounts:sendOobCode" })] }], /nothing is mailed/],
    [
      [
        { ...base, steps: [step({ waitSeconds: 5 })] },
        { id: "q", steps: [] },
      ],
      /must wait too/,
    ],
    [
      [
        { ...base, steps: [step({ waitSeconds: 5 })] },
        { id: "q", steps: [step({ id: "a" })] },
        { id: "r", steps: [step({ waitSeconds: 5 })] },
      ],
      /must wait too/,
    ],
    [
      [
        {
          ...base,
          steps: [step({ id: "a" }), step({ id: "b", age: { from: "a", seconds: 3600 } })],
        },
      ],
      /1800/,
    ],
    [[{ ...base, steps: [step({ age: { from: "later", seconds: 60 } })] }], /earlier step/],
    [
      [
        {
          id: "p",
          steps: [
            {
              id: "c",
              path: "admin/v2/projects/{project}/config",
              method: "GET",
              auth: "admin",
              project: "mfa",
            },
          ],
        },
      ],
      /declares mfa/,
    ],
    [
      [
        {
          ...base,
          steps: [
            { id: "c", path: "admin/v2/projects/{project}/config", method: "GET", auth: "admin" },
          ],
        },
      ],
      /records only mfa/,
    ],
    [[{ ...base, steps: [step({ project: "mfa" })] }], /only a config answer/],
  ];
  for (const [programs, pattern] of refused)
    assert.throws(
      () => validateMfaCorpus(programs),
      pattern,
      JSON.stringify(programs).slice(0, 200),
    );
});

test("a recording waits while another lane is on the sandbox", async () => {
  const { otherLaneOnSandbox } = await import("./auth-mfa/run.mjs");
  const now = Date.parse("2026-09-25T12:00:00Z");
  const line = (fields) => JSON.stringify({ project: "fireemu-oracle-idp", ...fields });
  const started = line({ ts: "2026-09-25T09:00:00Z", event: "started", taskId: "FS-RULES" });
  const finished = line({ ts: "2026-09-25T11:00:00Z", taskId: "FS-RULES", outcome: "recorded" });
  assert.match(otherLaneOnSandbox(started, now), /FS-RULES started/);
  assert.equal(otherLaneOnSandbox(`${started}\n${finished}`, now), undefined);
  const recent = line({ ts: "2026-09-25T11:45:00Z", taskId: "FS-RULES", outcome: "recorded" });
  assert.match(otherLaneOnSandbox(`${started}\n${recent}`, now), /wrote a line/);
  // This lane's own lines and other projects never block it.
  const own = line({ ts: "2026-09-25T11:59:00Z", event: "started", taskId: "AUTH-MFA-SANDBOX" });
  const elsewhere = JSON.stringify({
    ts: "2026-09-25T11:59:00Z",
    event: "started",
    taskId: "FS-DATA-WRITE-SANDBOX",
    project: "fireemu-oracle-sbx",
  });
  assert.equal(otherLaneOnSandbox(`${own}\n${elsewhere}\nnot json`, now), undefined);
});

test("no request names a tenant (owner decision M2)", () => {
  for (const body of [
    { email: "EMAIL(a)", password: "x", tenantId: "t1" },
    { users: [{ localId: "UID(a)", tenantId: "t1" }] },
  ]) {
    const step = { id: "s", path: "v1/accounts:signInWithPassword", auth: "key", body };
    assert.throws(() => guardMfaRequest(request(production, step), production), /tenant/);
    assert.throws(() => guardMfaRequest(request(local, step), local), /tenant/);
  }
});

test("a stop request ends a wait at once and the program still restores MFA", async () => {
  const { runCorpus } = await import("./auth-mfa/session.mjs");
  let mfa = { state: "DISABLED" };
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const { pathname } = new URL(url);
    calls.push(`${init.method ?? "GET"} ${pathname}`);
    const reply = (body) => new Response(JSON.stringify(body), { status: 200 });
    if (pathname.endsWith("/config")) {
      if (init.method === "PATCH") mfa = JSON.parse(init.body).mfa;
      return reply({ mfa, signIn: { hashConfig: { signerKey: "secret" } } });
    }
    if (pathname.endsWith(":batchGet")) return reply({ users: [] });
    return reply({ idToken: "x", mfaPendingCredential: "pending-credential-value" });
  };
  const controller = new AbortController();
  const program = {
    id: "auth-mfa/lifetime",
    config: { mfa: MFA_CONFIGS.enabled },
    steps: [
      { id: "acquire", path: "v1/accounts:signInWithPassword", auth: "key", body: {} },
      {
        id: "aged",
        path: "v1/accounts:signInWithPassword",
        auth: "key",
        body: {},
        age: { from: "acquire", seconds: 1800 },
      },
    ],
  };
  try {
    const started = Date.now();
    setTimeout(() => controller.abort(), 50);
    await assert.rejects(
      runCorpus([program], production, { signal: controller.signal, configSettleMs: 0 }),
      (error) => error.fatal && /stopped by a signal/.test(error.message),
    );
    assert.ok(Date.now() - started < 5000, "the 1800 s wait ended at once");
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(mfa, MFA_CONFIGS.disabled, "MFA is switched off again");
  assert.ok(
    !calls
      .slice(calls.lastIndexOf("PATCH /admin/v2/projects/fireemu-oracle-idp/config"))
      .includes("POST /v1/accounts:signInWithPassword"),
  );
  assert.equal(calls.filter((c) => c.startsWith("PATCH")).length, 2, "applied, then restored");
});

test("a run within an hour of anything but a clean recording is refused", async () => {
  const { recentAbort } = await import("./auth-mfa/run.mjs");
  const now = Date.parse("2026-09-25T12:00:00Z");
  const line = (outcome, ts = "2026-09-25T11:30:00Z") =>
    JSON.stringify({ ts, taskId: "AUTH-MFA-SANDBOX", outcome });
  for (const outcome of ["aborted-signal", "recorded-with-program-failures", "restored-by-hand"])
    assert.ok(recentAbort(line(outcome), now), outcome);
  assert.equal(recentAbort(line("recorded"), now), undefined);
  assert.equal(recentAbort(line("exploration (not evidence): probe"), now), undefined);
  assert.equal(recentAbort(line("aborted-fatal", "2026-09-25T10:30:00Z"), now), undefined);
  const started = JSON.stringify({
    ts: "2026-09-25T11:50:00Z",
    event: "started",
    taskId: "AUTH-MFA-SANDBOX",
  });
  assert.ok(
    recentAbort(`${line("aborted-fatal")}\n${started}`, now),
    "a started line is not an outcome",
  );
});

test("a clock-skew sample needs both readings and a round trip of at most a second", async () => {
  const { skewSample } = await import("./auth-mfa/session.mjs");
  const sent = Date.parse("2026-09-24T15:05:13Z") / 1000;
  const announced = "2026-09-24T15:20:13.400000Z";
  assert.ok(Math.abs(skewSample(announced, sent, sent + 0.4) - 0.2) < 1e-6);
  assert.equal(skewSample(announced, undefined, sent + 0.4), undefined);
  assert.equal(skewSample(announced, sent, sent + 1.5), undefined, "slow round trip");
  assert.equal(skewSample("not a time", sent, sent + 0.2), undefined);
});

/** A stub production Identity Toolkit: config and wipe routes, and every other call answered. */
function stubProduction(answer = () => ({ idToken: "x" })) {
  let mfa = { state: "DISABLED" };
  const calls = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const { pathname } = new URL(url);
    calls.push(`${init.method ?? "GET"} ${pathname}`);
    const reply = (body) => new Response(JSON.stringify(body), { status: 200 });
    if (pathname.endsWith("/config")) {
      if (init.method === "PATCH") mfa = JSON.parse(init.body).mfa;
      return reply({ mfa });
    }
    if (pathname.endsWith(":batchGet")) return reply({ users: [] });
    return reply(answer(pathname));
  };
  return { calls, mfa: () => mfa, restore: () => (globalThis.fetch = realFetch) };
}

test("window rows are not sent without a clock-skew estimate (fail closed)", async () => {
  const { runCorpus } = await import("./auth-mfa/session.mjs");
  const stub = stubProduction();
  const program = {
    id: "auth-mfa/totp/sign-in",
    config: { mfa: MFA_CONFIGS.enabled },
    steps: [{ id: "window", path: "v1/accounts:lookup", auth: "key", body: {}, align: true }],
  };
  try {
    await assert.rejects(
      runCorpus([program], production, { configSettleMs: 0 }),
      (error) => error.fatal && /no clock skew estimate/.test(error.message),
    );
  } finally {
    stub.restore();
  }
  assert.ok(!stub.calls.includes("POST /v1/accounts:lookup"), "the window row was not sent");
  assert.deepEqual(stub.mfa(), MFA_CONFIGS.disabled);
});

test("a stop before a program changes no config", async () => {
  const { runCorpus } = await import("./auth-mfa/session.mjs");
  const stub = stubProduction();
  const controller = new AbortController();
  controller.abort();
  const program = { id: "auth-mfa/sms", config: { mfa: MFA_CONFIGS.enabled }, steps: [] };
  try {
    await assert.rejects(
      runCorpus([program], production, { signal: controller.signal, configSettleMs: 0 }),
      /stopped by a signal before auth-mfa\/sms/,
    );
  } finally {
    stub.restore();
  }
  assert.ok(!stub.calls.some((call) => call.startsWith("PATCH")), stub.calls.join("\n"));
});

test("a hand restore is due only after this task's run did not end cleanly", async () => {
  const { restoreDue } = await import("./auth-mfa/run.mjs");
  const line = (fields) =>
    JSON.stringify({ project: "fireemu-oracle-idp", taskId: "AUTH-MFA-SANDBOX", ...fields });
  assert.equal(restoreDue(""), false);
  assert.equal(restoreDue(line({ event: "started" })), true);
  assert.equal(restoreDue(line({ outcome: "aborted-signal" })), true);
  assert.equal(restoreDue(line({ outcome: "recorded" })), false);
  assert.equal(restoreDue(line({ outcome: "restored-by-hand" })), true);
  const other = JSON.stringify({
    project: "fireemu-oracle-idp",
    taskId: "FS-RULES-SANDBOX",
    event: "started",
  });
  assert.equal(restoreDue(`${line({ outcome: "recorded" })}\n${other}`), false);
});

test("a rate-limited MFA answer is indeterminate, never a behavior", async () => {
  const { isTransient } = await import("./auth-account/harness.mjs");
  for (const message of ["TOO_MANY_ATTEMPTS_TRY_LATER", "QUOTA_EXCEEDED : Exceeded quota"])
    assert.equal(isTransient({ status: 400, body: { error: { message } } }), true, message);
  assert.equal(isTransient({ status: 400, body: { error: { message: "INVALID_CODE" } } }), false);
});

test("a phone control start matches any answer production recorded for a control start", async () => {
  const { classify, timingAlternatives } = await import("./auth-mfa/run.mjs");
  const refusal = (message) => ({ status: 400, body: { error: { code: 400, message, status: "INVALID_ARGUMENT" } } });
  const exists = refusal("SECOND_FACTOR_EXISTS : Phone number already enrolled as second factor for this account.");
  const expired = refusal("TOKEN_EXPIRED");
  const saved = {
    steps: { "control-start-s450": expired, "control-start-s600": exists, "aged-session-s600": exists },
    second: { "control-start-s600": expired },
  };
  const program = "auth-mfa/lifetime";
  const known = timingAlternatives(program, "control-start-s450", saved);
  assert.deepEqual(known, [expired, exists]);
  const row = (fireemu) =>
    classify({ production: expired, fireemu, timing: timingAlternatives(program, "control-start-s450", saved) });
  assert.equal(row(expired), "MATCH");
  assert.equal(row(exists), "MATCH_TIMING_DEPENDENT");
  assert.equal(row(refusal("INVALID_ID_TOKEN")), "MISMATCH");
  // Only the phone control starts of the lifetime program; nothing else borrows a sibling's answer.
  assert.deepEqual(timingAlternatives(program, "aged-session-s600", saved), []);
  assert.deepEqual(timingAlternatives("auth-mfa/sms", "control-start-s450", saved), []);
  assert.deepEqual(timingAlternatives(program, "control-start-t450", saved), []);
});

test("quota-free sends each account one wrong code and mints no token", async () => {
  const { PROGRAMS } = await import("./auth-mfa/corpus.mjs");
  const program = PROGRAMS.find((p) => p.id === "auth-mfa/totp/quota-free");
  assert.equal(program.tokens, undefined);
  const codeOf = (step) => step.body?.totpVerificationInfo?.verificationCode;
  const checks = { qe: "replayed-enrollment-code", qo: "older-unused-code" };
  for (const [account, check] of Object.entries(checks)) {
    const totpRows = program.steps.filter(
      (step) => codeOf(step) !== undefined && JSON.stringify(step).includes(`-${account}`),
    );
    const wrong = totpRows.filter((step) => step.id === check);
    assert.equal(wrong.length, 1, account);
    assert.deepEqual(
      totpRows.map((step) => step.id),
      [`finalize-${account}`, `plus-4-${account}`, check],
      account,
    );
  }
});

test("a quota-limited row passes only through its matching re-observation", async () => {
  const { REOBSERVED, reobservedStatus } = await import("./auth-mfa/run.mjs");
  assert.deepEqual(REOBSERVED, {
    "auth-mfa/totp/sign-in#replayed-enrollment-code": "auth-mfa/totp/quota-free#replayed-enrollment-code",
    "auth-mfa/totp/sign-in#older-unused-code": "auth-mfa/totp/quota-free#older-unused-code",
  });
  const refusal = (message) => ({ status: 400, body: { error: { code: 400, message, status: "INVALID_ARGUMENT" } } });
  const invalid = refusal("INVALID_CODE");
  const quota = refusal("QUOTA_EXCEEDED : Exceeded quota.");
  const rows = new Map([
    ["auth-mfa/totp/quota-free#replayed-enrollment-code", { status: "MATCH", production: invalid }],
    ["auth-mfa/totp/quota-free#older-unused-code", { status: "MISMATCH", production: invalid }],
  ]);
  const original = "auth-mfa/totp/sign-in#replayed-enrollment-code";
  const row = (name, status, fireemu) => reobservedStatus({ row: name, status, fireemu }, rows);
  assert.equal(row(original, "INDETERMINATE", invalid), "REOBSERVED_MATCH");
  // fireemu's own answer on the original row must be the re-observed one.
  assert.equal(row(original, "INDETERMINATE", quota), "INDETERMINATE");
  assert.equal(row(original, "INDETERMINATE", { status: 500, body: {} }), "INDETERMINATE");
  assert.equal(row(original, "INDETERMINATE", { status: 200, body: {} }), "INDETERMINATE");
  // The re-observation itself must match.
  assert.equal(row("auth-mfa/totp/sign-in#older-unused-code", "INDETERMINATE", invalid), "INDETERMINATE");
  // A determinate row keeps its own status; other indeterminate rows are not rescued.
  assert.equal(row(original, "MISMATCH", invalid), "MISMATCH");
  assert.equal(row("auth-mfa/sms#x", "INDETERMINATE", invalid), "INDETERMINATE");
});

test("the local session's pinned clock starts at the current second with non-zero microseconds", async () => {
  const { pinnedClockStart } = await import("./auth-mfa/run.mjs");
  assert.equal(pinnedClockStart(Date.parse("2026-09-25T08:30:12.987Z")), "2026-09-25T08:30:12.123456789Z");
  assert.match(pinnedClockStart(), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.123456789Z$/);
});
