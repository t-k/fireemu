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
  assert.ok(requests > 200 && requests < 400, String(requests));
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
      /last program/,
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
