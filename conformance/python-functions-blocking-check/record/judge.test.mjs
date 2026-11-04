// The judge: the production-shaped baseline is all as-expected, every rule has a mutation that makes exactly its case differ with
// the rule named, missing frames and unsent steps are reported as such, and it never throws.
import assert from "node:assert/strict";
import test from "node:test";
import { OPTIONAL_CLAIMS, REQUIRED_CLAIMS, framesOf, judge } from "./judge.mjs";
import { emailOf } from "./script.mjs";
import { LOCAL_ID, SERVICE_URI, productionFrames } from "./world.mjs";

const RUN = "0123456789abcdef";
const EMAIL = emailOf(RUN);
const SIGN_UP = { class: "2xx", status: 200, localId: LOCAL_ID };
const REGISTRATION = { trigger: { functionUri: SERVICE_URI }, serviceUri: SERVICE_URI };
const INVOKER = { members: ["allUsers"], allUsersInvoker: true };
const base = () =>
  JSON.parse(JSON.stringify(productionFrames({ runId: RUN, localId: LOCAL_ID }))).map((frame) => ({
    frame,
  }));
const OBSERVED = () => ({
  signUp: { ...SIGN_UP },
  registration: structuredClone(REGISTRATION),
  invoker: { ...INVOKER },
});
const judged = (frames, over = {}) =>
  judge({ email: EMAIL, localId: LOCAL_ID, frames, observed: OBSERVED(), ...over });
const edited = (kind, edit) => {
  const frames = base();
  edit(frames.find((e) => e.frame.kind === kind).frame);
  return frames;
};

test("the production-shaped baseline judges every case as expected", () => {
  const r = judged(base());
  assert.deepEqual(Object.fromEntries(Object.entries(r.cases).map(([id, c]) => [id, c.status])), {
    "signup-allowed": "as-expected",
    "trigger-registered": "as-expected",
    "invoker-public": "as-expected",
    "blocking-request": "as-expected",
    "blocking-claims": "as-expected",
    "blocking-sdk": "as-expected",
    "sdk-versions": "as-expected",
  });
  assert.deepEqual(r.counts, {
    "as-expected": 7,
    differs: 0,
    observed: 0,
    "not-delivered": 0,
    "not-sent": 0,
  });
  assert.equal(r.complete, true);
  assert.equal(r.mode, "production");
});

// [case, kind or "observed", edit, the rule that must be named]
const RULES = [
  ["blocking-request", "blocking-raw", (f) => (f.request.method = "GET"), "method"],
  [
    "blocking-request",
    "blocking-raw",
    (f) => (f.request.headers["content-type"] = "text/plain"),
    "content-type-json",
  ],
  [
    "blocking-request",
    "blocking-raw",
    (f) => (f.request.body_keys = ["data", "extra"]),
    "body-has-data-only",
  ],
  [
    "blocking-request",
    "blocking-raw",
    (f) => (f.request.data_keys = ["jwt", "other"]),
    "data-has-jwt-only",
  ],
  ["blocking-request", "blocking-raw", (f) => (f.request.token.segments = 2), "three-segments"],
  [
    "blocking-request",
    "blocking-raw",
    (f) =>
      (f.request.token.claim_names = f.request.token.claim_names.filter((n) => n !== "ip_address")),
    "required-claims",
  ],
  ["blocking-request", "blocking-raw", (f) => (f.request.token.header.alg = "none"), "alg-rs256"],
  ["blocking-request", "blocking-raw", (f) => (f.request.token.header.has_kid = false), "has-kid"],
  [
    "blocking-claims",
    "blocking-raw",
    (f) =>
      (f.request.token.claims.event_type =
        "providers/cloud.auth/eventTypes/user.beforeSignIn:password"),
    "event-type-names-before-create",
  ],
  [
    "blocking-claims",
    "blocking-raw",
    (f) => (f.request.token.uid = "someone-else"),
    "user-is-this-sign-up",
  ],
  [
    "blocking-claims",
    "blocking-raw",
    (f) => (f.request.token.claims.iss = "securetoken.google.com/x"),
    "iss-is-https",
  ],
  [
    "blocking-claims",
    "blocking-raw",
    (f) => (f.request.token.claims.aud = "https://elsewhere.example/"),
    "aud-is-the-function-uri",
  ],
  [
    "blocking-claims",
    "blocking-raw",
    (f) => (f.request.token.timing = { iat: 10, exp: 10 }),
    "not-expired-at-issue",
  ],
  ["blocking-claims", "blocking-raw", (f) => delete f.request.token.timing, "not-expired-at-issue"],
  [
    "blocking-sdk",
    "blocking-sdk",
    (f) => (f.event_type = "providers/cloud.auth/eventTypes/user.beforeSignIn:password"),
    "event-type-names-before-create",
  ],
  ["blocking-sdk", "blocking-sdk", (f) => (f.additional_user_info.is_new_user = false), "new-user"],
  [
    "blocking-sdk",
    "blocking-sdk",
    (f) => (f.additional_user_info.provider_id = "google.com"),
    "password-provider",
  ],
  ["blocking-sdk", "blocking-sdk", (f) => (f.uid = "someone-else"), "user-is-this-sign-up"],
  ["blocking-sdk", "blocking-sdk", (f) => (f.credential = ["id_token"]), "no-credential"],
  ["blocking-sdk", "blocking-sdk", (f) => (f.event_id_present = false), "event-id"],
  [
    "sdk-versions",
    "blocking-sdk",
    (f) => (f.versions["firebase-functions"] = "0.5.0"),
    "pinned-sdk",
  ],
];
for (const [id, kind, edit, rule] of RULES)
  test(`${id}: breaking ${rule} makes only that case differ and names the rule`, () => {
    const before = judged(base());
    const r = judged(edited(kind, edit));
    assert.equal(r.cases[id].status, "differs", id + " " + JSON.stringify(r.cases[id].notes));
    assert.ok(r.cases[id].notes.includes(rule), `${rule} is named: ${r.cases[id].notes}`);
    for (const other of Object.keys(r.cases))
      if (other !== id)
        assert.equal(r.cases[other].status, before.cases[other].status, other + " unchanged");
  });

const OBSERVED_RULES = [
  ["signup-allowed", (o) => (o.signUp.class = "4xx"), "answered-2xx"],
  ["signup-allowed", (o) => (o.signUp.localId = null), "local-id"],
  ["signup-allowed", (o) => (o.signUp.localId = ""), "local-id"],
  ["trigger-registered", (o) => (o.registration.trigger = null), "trigger-present"],
  [
    "trigger-registered",
    (o) => (o.registration.trigger = { functionUri: "https://elsewhere.example/" }),
    "uri-is-the-function-address",
  ],
  [
    "trigger-registered",
    (o) => (o.registration = { trigger: { functionUri: null }, serviceUri: null }),
    "uri-is-the-function-address",
  ],
  ["invoker-public", (o) => (o.invoker.allUsersInvoker = false), "all-users-invoker"],
];
for (const [id, edit, rule] of OBSERVED_RULES)
  test(`${id}: ${rule} is named when the observation breaks it`, () => {
    const observed = OBSERVED();
    edit(observed);
    const r = judge({ email: EMAIL, localId: LOCAL_ID, frames: base(), observed });
    assert.equal(r.cases[id].status, "differs");
    assert.ok(r.cases[id].notes.includes(rule), r.cases[id].notes.join());
  });

test("a step that was not made is not-sent and the frames are not judged", () => {
  const r = judge({
    email: EMAIL,
    localId: null,
    frames: base(),
    observed: { signUp: null, registration: null, invoker: null },
  });
  for (const id of [
    "signup-allowed",
    "trigger-registered",
    "invoker-public",
    "blocking-request",
    "blocking-claims",
    "blocking-sdk",
  ])
    assert.equal(r.cases[id].status, "not-sent", id);
  assert.deepEqual(r.cases["signup-allowed"].notes, ["sign-up"]);
  assert.deepEqual(r.cases["trigger-registered"].notes, ["config read"]);
  assert.deepEqual(r.cases["invoker-public"].notes, ["invoker read"]);
  assert.equal(r.complete, false);
});

test("a sign-up with no frame is not-delivered, a raw frame without the SDK one differs, an SDK frame alone is delivered", () => {
  const none = judged([]);
  for (const id of ["blocking-request", "blocking-claims", "blocking-sdk", "sdk-versions"])
    assert.equal(none.cases[id].status, "not-delivered", id);
  assert.equal(none.complete, false);
  const rawOnly = judged(
    base().filter((e) => e.frame.kind === "blocking-raw"),
    { errors: [{ function: "pcblock", text: "Traceback" }] },
  );
  assert.equal(rawOnly.cases["blocking-sdk"].status, "differs");
  assert.deepEqual(rawOnly.cases["blocking-sdk"].notes, ["sdk-did-not-run"]);
  assert.equal(rawOnly.cases["blocking-sdk"].observed.errors, 1);
  const sdkOnly = judged(base().filter((e) => e.frame.kind === "blocking-sdk"));
  assert.equal(sdkOnly.cases["blocking-request"].status, "not-delivered");
  assert.equal(sdkOnly.cases["blocking-sdk"].status, "as-expected");
});

test("frames of another sign-up are not this run's", () => {
  const other = JSON.parse(
    JSON.stringify(base()).replaceAll(EMAIL, "pcblock-ffffffffffffffff@example.com"),
  );
  const r = judged(other);
  assert.equal(r.cases["blocking-request"].status, "not-delivered");
  assert.equal(framesOf(other, "blocking-raw", EMAIL).length, 0);
  assert.equal(framesOf(base(), "blocking-raw", EMAIL).length, 1);
  assert.equal(framesOf(base(), "blocking-sdk", EMAIL).length, 1);
  assert.equal(framesOf(base(), "other-kind", EMAIL).length, 0);
});

test("the local mode does not require the production token header or the audience", () => {
  const frames = edited("blocking-raw", (f) => {
    f.request.token.header = { alg: "none", has_kid: false };
    f.request.token.claims.aud = "http://127.0.0.1:1/x";
  });
  assert.equal(judged(frames, { mode: "local" }).cases["blocking-request"].status, "as-expected");
  assert.equal(judged(frames, { mode: "local" }).cases["blocking-claims"].status, "as-expected");
  assert.equal(judged(frames, { mode: "production" }).cases["blocking-request"].status, "differs");
  assert.equal(judged(frames, { mode: "production" }).cases["blocking-claims"].status, "differs");
});

test("a localId of null does not hold the user to a sign-up id", () => {
  const frames = edited("blocking-raw", (f) => (f.request.token.uid = "x"));
  assert.equal(
    judge({ email: EMAIL, localId: null, frames, observed: OBSERVED() }).cases["blocking-claims"]
      .status,
    "as-expected",
  );
});

test("what the cases record beside the verdict", () => {
  const r = judged(base());
  assert.deepEqual(r.cases["signup-allowed"].observed, {
    class: "2xx",
    status: 200,
    hasLocalId: true,
  });
  assert.deepEqual(r.cases["invoker-public"].observed, { members: ["allUsers"] });
  assert.equal(r.cases["trigger-registered"].observed.event, "beforeCreate");
  assert.deepEqual(r.cases["blocking-request"].expected, { claimNames: REQUIRED_CLAIMS });
  assert.deepEqual(r.cases["blocking-request"].observed.missing, []);
  assert.deepEqual(r.cases["blocking-request"].observed.extra, []);
  assert.equal(r.cases["blocking-request"].observed.tokenHeader.alg, "RS256");
  assert.equal(r.cases["blocking-request"].observed.ipFamily, "ipv4");
  assert.ok(r.cases["blocking-claims"].observed.claims.aud);
  assert.deepEqual(
    r.cases["blocking-claims"].observed.timing.exp > r.cases["blocking-claims"].observed.timing.iat,
    true,
  );
  assert.equal(r.cases["blocking-sdk"].observed.additionalUserInfo.is_new_user, true);
  assert.equal(
    r.cases["blocking-sdk"].observed.eventType,
    "providers/cloud.auth/eventTypes/user.beforeCreate:password",
  );
  assert.deepEqual(r.cases["sdk-versions"].observed.sdkVersionsSeen, ["0.6.0"]);
  const withExtra = edited("blocking-raw", (f) => f.request.token.claim_names.push("surprise"));
  assert.deepEqual(judged(withExtra).cases["blocking-request"].observed.extra, ["surprise"]);
  for (const name of OPTIONAL_CLAIMS) assert.ok(!REQUIRED_CLAIMS.includes(name));
  const optional = edited("blocking-raw", (f) => f.request.token.claim_names.push("tenant_id"));
  assert.deepEqual(judged(optional).cases["blocking-request"].observed.extra, []);
});

test("ERROR entries are carried through reduced to their function, time and text", () => {
  const r = judged(base(), {
    errors: [{ function: "pcblock", timestamp: "t", text: "Traceback", extra: "dropped" }],
  });
  assert.deepEqual(r.errors, [{ function: "pcblock", timestamp: "t", text: "Traceback" }]);
});

test("it never throws on hostile or truncated frames", () => {
  let seed = 11;
  const next = () => (seed = (seed * 1103515245 + 12345) % 2147483648) / 2147483648;
  const junk = [
    null,
    1,
    "x",
    [],
    {},
    { frame: null },
    { request: { token: 5 } },
    { data: { email: EMAIL } },
    { request: { headers: null, token: { claims: null } } },
  ];
  for (let round = 0; round < 200; round++) {
    const frames = base();
    for (let i = 0; i < 5; i++) {
      const target = frames[Math.floor(next() * frames.length)];
      if (!target?.frame || typeof target.frame !== "object") continue;
      const keys = Object.keys(target.frame);
      target.frame[keys[Math.floor(next() * keys.length)]] = junk[Math.floor(next() * junk.length)];
      if (next() < 0.3) frames.splice(Math.floor(next() * frames.length), 1);
      if (next() < 0.3) frames.push(junk[Math.floor(next() * junk.length)]);
    }
    const r = judged(frames);
    assert.equal(
      Object.values(r.counts).reduce((a, b) => a + b, 0),
      Object.keys(r.cases).length,
    );
    for (const c of Object.values(r.cases))
      assert.ok(
        ["as-expected", "differs", "observed", "not-delivered", "not-sent"].includes(c.status),
      );
  }
});

test("the function's address is its own url or the Cloud Run service's: the trigger and the token audience may name either", () => {
  const FUNCTION_URL = "https://us-central1-p.cloudfunctions.net/pcblock";
  for (const [label, registration] of [
    [
      "the url",
      {
        trigger: { functionUri: FUNCTION_URL },
        serviceUri: SERVICE_URI,
        functionUrl: FUNCTION_URL,
      },
    ],
    [
      "the service address",
      { trigger: { functionUri: SERVICE_URI }, serviceUri: SERVICE_URI, functionUrl: FUNCTION_URL },
    ],
    [
      "the url with no service address",
      { trigger: { functionUri: FUNCTION_URL }, serviceUri: null, functionUrl: FUNCTION_URL },
    ],
  ]) {
    const observed = { ...OBSERVED(), registration };
    const r = judge({ email: EMAIL, localId: LOCAL_ID, frames: base(), observed });
    assert.equal(r.cases["trigger-registered"].status, "as-expected", label);
  }
  for (const [label, registration] of [
    [
      "another address",
      {
        trigger: { functionUri: "https://elsewhere.example/" },
        serviceUri: SERVICE_URI,
        functionUrl: FUNCTION_URL,
      },
    ],
    [
      "no address known",
      { trigger: { functionUri: FUNCTION_URL }, serviceUri: null, functionUrl: null },
    ],
    [
      "a non-text address",
      { trigger: { functionUri: 5 }, serviceUri: SERVICE_URI, functionUrl: FUNCTION_URL },
    ],
  ]) {
    const observed = { ...OBSERVED(), registration };
    const r = judge({ email: EMAIL, localId: LOCAL_ID, frames: base(), observed });
    assert.equal(r.cases["trigger-registered"].status, "differs", label);
  }
  const audOf = (aud, registration) => {
    const frames = base();
    for (const entry of frames)
      if (entry.frame.request?.token?.claims) entry.frame.request.token.claims.aud = aud;
    return judge({
      email: EMAIL,
      localId: LOCAL_ID,
      frames,
      observed: { ...OBSERVED(), registration },
    });
  };
  const both = {
    trigger: { functionUri: FUNCTION_URL },
    serviceUri: SERVICE_URI,
    functionUrl: FUNCTION_URL,
  };
  assert.equal(audOf(FUNCTION_URL, both).cases["blocking-claims"].status, "as-expected");
  assert.equal(audOf(SERVICE_URI, both).cases["blocking-claims"].status, "as-expected");
  assert.equal(
    audOf("https://elsewhere.example/", both).cases["blocking-claims"].status,
    "differs",
  );
});
