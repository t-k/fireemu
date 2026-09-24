import assert from "node:assert/strict";
import { test } from "node:test";

import { buildRequest, createContext } from "./auth-account/harness.mjs";
import { PROGRAMS } from "./auth-action/corpus.mjs";
import {
  describeLink,
  guardActionRequest,
  normalizeActionResponse,
  validateActionCorpus,
} from "./auth-action/harness.mjs";
import { createSession } from "./auth-action/session.mjs";

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
    origin: "http://127.0.0.1:32298",
    projectNumber: "123456789012",
    control: { url: "http://127.0.0.1:4400" },
  },
  startedMs: 1_790_000_000_000,
});

const request = (ctx, step) => buildRequest(step, ctx, new Map());
const adminOob = (body) => ({
  id: "s",
  path: "v1/projects/{project}/accounts:sendOobCode",
  auth: "admin",
  body,
});
const clientOob = (body) => ({ id: "s", path: "v1/accounts:sendOobCode", auth: "key", body });

test("the Admin sendOobCode must ask for the link back, so nothing is mailed", () => {
  const ok = adminOob({ requestType: "EMAIL_SIGNIN", email: "EMAIL(a)", returnOobLink: true });
  assert.doesNotThrow(() => guardActionRequest(request(production, ok), production));
  for (const returnOobLink of [undefined, false, "true"]) {
    const step = adminOob({ requestType: "PASSWORD_RESET", email: "EMAIL(a)", returnOobLink });
    assert.throws(() => guardActionRequest(request(production, step), production), /link back/);
  }
});

test("the client sendOobCode only resets an address that has no account", () => {
  const ok = clientOob({ requestType: "PASSWORD_RESET", email: "EMAIL(unknown-1)" });
  assert.doesNotThrow(() => guardActionRequest(request(production, ok), production));
  for (const body of [
    { requestType: "PASSWORD_RESET", email: "EMAIL(a)" },
    { requestType: "VERIFY_EMAIL", email: "EMAIL(unknown-1)" },
    { requestType: "EMAIL_SIGNIN", email: "EMAIL(unknown-1)" },
    { requestType: "PASSWORD_RESET", email: "EMAIL(unknown-1)", idToken: "x" },
    { requestType: "PASSWORD_RESET", email: "EMAIL(unknown-1)", returnOobLink: false },
  ]) {
    assert.throws(
      () => guardActionRequest(request(production, clientOob(body)), production),
      /unknown address/,
      JSON.stringify(body),
    );
  }
});

test("addresses, phones and continue hosts are limited to the reviewed ones", () => {
  const withBody = (body) => request(production, adminOob({ returnOobLink: true, ...body }));
  for (const body of [
    { requestType: "PASSWORD_RESET", email: "someone@gmail.com" },
    { requestType: "VERIFY_AND_CHANGE_EMAIL", email: "EMAIL(a)", newEmail: "x@example.org" },
    { requestType: "PASSWORD_RESET", email: "EMAIL(a)", continueUrl: "https://evil.test/x" },
    { requestType: "PASSWORD_RESET", email: "EMAIL(a)", continueUrl: "https://a.web.app/x" },
  ]) {
    assert.throws(
      () => guardActionRequest(withBody(body), production),
      Error,
      JSON.stringify(body),
    );
  }
  for (const continueUrl of [
    "https://{project}.firebaseapp.com/done?x=1",
    "https://{project}.web.app/next",
    "http://localhost:5000/done",
    "https://unauthorized.example.com/done",
    "not a url",
    "",
  ]) {
    assert.doesNotThrow(() =>
      guardActionRequest(
        withBody({ requestType: "PASSWORD_RESET", email: "EMAIL(a)", continueUrl }),
        production,
      ),
    );
  }
  const phone = request(production, {
    id: "s",
    path: "v1/accounts:sendVerificationCode",
    auth: "key",
    body: { phoneNumber: "+1 650 555 9999" },
  });
  assert.throws(() => guardActionRequest(phone, production), /test phone/);
});

test("only the harness reaches the config, and it only writes the email-link switch", () => {
  const read = request(production, {
    id: "h",
    method: "GET",
    path: "admin/v2/projects/{project}/config",
    auth: "admin",
  });
  assert.throws(() => guardActionRequest(read, production), /reviewed family/);
  assert.doesNotThrow(() => guardActionRequest(read, production, { harness: true }));
  const write = (mask, body) =>
    request(production, {
      id: "h",
      method: "PATCH",
      path: "admin/v2/projects/{project}/config",
      auth: "admin",
      query: { updateMask: mask },
      body,
    });
  const ok = write("signIn.email.passwordRequired", {
    signIn: { email: { passwordRequired: false } },
  });
  assert.doesNotThrow(() => guardActionRequest(ok, production, { harness: true }));
  for (const [mask, body] of [
    ["signIn.email.enabled", { signIn: { email: { enabled: false } } }],
    [
      "signIn.email.passwordRequired",
      { signIn: { email: { passwordRequired: false, enabled: false } } },
    ],
    [
      "signIn.email.passwordRequired,authorizedDomains",
      { signIn: { email: { passwordRequired: false } }, authorizedDomains: [] },
    ],
    ["signIn.email.passwordRequired", { signIn: { email: { passwordRequired: false } }, x: 1 }],
  ]) {
    assert.throws(() => guardActionRequest(write(mask, body), production, { harness: true }));
  }
});

test("paths outside the reviewed families and other hosts are refused", () => {
  for (const path of [
    "v1/accounts:signInWithCustomToken",
    "v1/accounts:signInWithIdp",
    "v1/projects/{project}/accounts:batchDelete",
    "v1/projects/other-project/accounts:sendOobCode",
    "v2/accounts/mfaEnrollment:start",
  ]) {
    const built = request(production, { id: "s", path, auth: "admin", body: {} });
    assert.throws(() => guardActionRequest(built, production), /reviewed family/, path);
  }
  const elsewhere = {
    url: "http://127.0.0.1:9999/identitytoolkit.googleapis.com/v1/accounts:lookup",
    init: { method: "POST", headers: {} },
  };
  assert.throws(() => guardActionRequest(elsewhere, local), /left the local target/);
});

test("an action link is recorded as its parameters, never its code or key", () => {
  const code = "kMqtgFzRr-abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGH";
  const link = `https://fireemu-oracle-idp.firebaseapp.com/__/auth/action?mode=signIn&oobCode=${code}&apiKey=AIzaFAKEKEYFORTESTSONLY&continueUrl=https%3A%2F%2Ffireemu-oracle-idp.firebaseapp.com%2Ffinish&lang=en`;
  const recorded = normalizeActionResponse(
    200,
    JSON.stringify({
      kind: "k",
      oobCode: code,
      email: "fireemu-aa-1790000000000-a@example.com",
      oobLink: link,
    }),
    production,
  );
  assert.deepEqual(recorded, {
    status: 200,
    body: {
      kind: "k",
      oobCode: "<oobCode>",
      email: "fireemu-aa-<run>-a@example.com",
      oobLink: {
        handler: "<action-handler>",
        code: "the-answer-oobCode",
        params: {
          mode: "signIn",
          apiKey: "<present>",
          continueUrl: "https://demo-auth-account.firebaseapp.com/finish",
          lang: "en",
        },
      },
    },
  });
  assert.ok(!JSON.stringify(recorded).includes(code));
  assert.ok(!JSON.stringify(recorded).includes("AIzaFAKEKEYFORTESTSONLY"));
  const emulator = describeLink(
    "http://127.0.0.1:9099/emulator/action?mode=signIn&lang=en&oobCode=oob-1&apiKey=fake-api-key",
    "oob-2",
  );
  assert.equal(emulator.code, "another-code");
  assert.equal(describeLink("not a link", "x"), "<unparsable-link>");
});

test("the corpus is valid and its rules refuse mail, config drift and early waits", () => {
  assert.ok(validateActionCorpus(PROGRAMS) > 0);
  const base = { id: "p", steps: [] };
  const refused = [
    { ...base, steps: [adminOob({ requestType: "PASSWORD_RESET", email: "EMAIL(a)" })] },
    { ...base, steps: [clientOob({ requestType: "PASSWORD_RESET", email: "EMAIL(a)" })] },
    { ...base, config: { "emailPrivacyConfig.enableImprovedEmailPrivacy": false } },
    { ...base, config: { "signIn.email.passwordRequired": "false" } },
    {
      ...base,
      steps: [
        {
          ...adminOob({ requestType: "X", returnOobLink: true }),
          waitUntil: { of: "a:b", plus: 1 },
        },
      ],
    },
  ];
  for (const program of refused) {
    assert.throws(() => validateActionCorpus([program]), Error, JSON.stringify(program));
  }
  const waiting = {
    id: "w",
    steps: [{ ...clientOob({}), path: "v1/accounts:lookup", waitSeconds: 5 }],
  };
  assert.throws(() => validateActionCorpus([waiting, base]), /only the last program/);
  assert.doesNotThrow(() => validateActionCorpus([base, waiting]));
});

test("a program that fails still switches the config back and reads it back", async () => {
  const calls = [];
  let passwordRequired = true;
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const { pathname, searchParams } = new URL(url);
    calls.push(`${init.method} ${pathname.replace(/^\/identitytoolkit.googleapis.com/, "")}`);
    const json = (body) => new Response(JSON.stringify(body), { status: 200 });
    if (pathname.endsWith("/config")) {
      if (init.method === "PATCH") {
        assert.equal(searchParams.get("updateMask"), "signIn.email.passwordRequired");
        passwordRequired = JSON.parse(init.body).signIn.email.passwordRequired;
      }
      return json({
        signIn: {
          email: passwordRequired ? { enabled: true, passwordRequired } : { enabled: true },
        },
      });
    }
    if (pathname.endsWith(":batchGet")) return json({});
    if (pathname.endsWith("accounts:lookup"))
      throw Object.assign(new Error("boom"), { fatal: false });
    return json({});
  };
  try {
    const session = createSession(local);
    const program = {
      id: "p",
      config: { "signIn.email.passwordRequired": false },
      steps: [{ id: "s", path: "v1/accounts:lookup", auth: "key", body: {} }],
    };
    const result = await session.runProgram(program);
    // A transport failure is recorded, not thrown; the switch is back either way.
    assert.equal(result.steps.s.status, 0);
    assert.equal(passwordRequired, true);
    assert.deepEqual(result.config.restored, { "signIn.email.passwordRequired": true });
    assert.ok(calls.filter((c) => c.startsWith("PATCH")).length === 2, calls.join("\n"));
  } finally {
    globalThis.fetch = original;
  }
});
