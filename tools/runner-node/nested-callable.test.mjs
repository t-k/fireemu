import assert from "node:assert/strict";
import test from "node:test";

import {
  UNVERIFIED_CREDENTIAL,
  VERIFIED_CREDENTIAL_HEADER,
  VERIFIED_APP_CHECK_HEADER,
  guardCallableWrapper,
  markNonCallableRequest,
  requestForCallableWrapper,
} from "./nested-callable.mjs";

const request = (headers = {}, rawHeaders = undefined) => ({
  method: "POST",
  body: { data: {} },
  headers: { ...headers },
  rawHeaders: rawHeaders ?? Object.entries(headers).flat(),
  header(name) {
    return this.headers[name.toLowerCase()];
  },
});
const plain = { strict: true, nonCallableHttp: true };

test("the daemon's marker is read and removed from every spelling, whatever the profile or endpoint", () => {
  for (const options of [
    plain,
    { strict: false, nonCallableHttp: true },
    { strict: true, nonCallableHttp: false },
  ]) {
    const req = request(
      { [VERIFIED_CREDENTIAL_HEADER]: "1", authorization: "Bearer t" },
      ["X-Fireemu-Credential-Verified", "1", "Authorization", "Bearer t"],
    );
    markNonCallableRequest(req, options);
    assert.equal(req.headers[VERIFIED_CREDENTIAL_HEADER], undefined);
    assert.deepEqual(req.rawHeaders, ["Authorization", "Bearer t"]);
    assert.equal(req.headers.authorization, "Bearer t");
  }
});

test("only a request to a non-callable HTTP endpoint in the strict profile is marked", () => {
  assert.equal(markNonCallableRequest(request(), plain), true);
  assert.equal(markNonCallableRequest(request(), { strict: false, nonCallableHttp: true }), false);
  assert.equal(markNonCallableRequest(request(), { strict: true, nonCallableHttp: false }), false);
  assert.equal(markNonCallableRequest(request(), {}), false);
  // A request that was not marked is handed to the wrapper unchanged, whatever it carries.
  const unmarked = request({ authorization: "Bearer forged" });
  assert.equal(requestForCallableWrapper(unmarked), unmarked);
});

test("a marked request keeps a credential only when the daemon verified it", () => {
  const verified = request({ [VERIFIED_CREDENTIAL_HEADER]: "1", authorization: "Bearer good" });
  markNonCallableRequest(verified, plain);
  assert.equal(requestForCallableWrapper(verified), verified);
  for (const marker of [undefined, "0", "true", "", "11", " 1"]) {
    const headers = { authorization: "Bearer forged" };
    if (marker !== undefined) headers[VERIFIED_CREDENTIAL_HEADER] = marker;
    const req = request(headers);
    markNonCallableRequest(req, plain);
    const seen = requestForCallableWrapper(req);
    assert.notEqual(seen, req, `marker ${JSON.stringify(marker)}`);
    assert.equal(seen.header("Authorization"), UNVERIFIED_CREDENTIAL);
  }
});

test("the unverified credential is not a Bearer, so the SDK reads it as invalid without decoding it", () => {
  assert.doesNotMatch(UNVERIFIED_CREDENTIAL, /^Bearer (.*)$/i);
  assert.ok(UNVERIFIED_CREDENTIAL.length > 0);
});

test("a request without a credential, or with an empty one, is left alone", () => {
  for (const headers of [{}, { authorization: "" }, { "content-type": "application/json" }]) {
    const req = request(headers);
    markNonCallableRequest(req, plain);
    assert.equal(requestForCallableWrapper(req), req);
  }
});

test("every shape the strict daemon did not verify is replaced, and nothing else about the request changes", () => {
  const shapes = [
    "Bearer malformed",
    "bearer malformed",
    "Bearer",
    "Bearer ",
    "Basic dXNlcjpwYXNz",
    "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ4In0.c2ln",
    "Bearer a, Bearer b",
  ];
  for (const authorization of shapes) {
    const req = request({ authorization, "content-type": "application/json" });
    markNonCallableRequest(req, plain);
    const seen = requestForCallableWrapper(req);
    assert.equal(seen.header("authorization"), UNVERIFIED_CREDENTIAL, authorization);
    assert.equal(seen.headers["content-type"], "application/json");
    assert.equal(seen.method, "POST");
    assert.deepEqual(seen.body, { data: {} });
    // The caller's own request is not changed: application code may read its credential again.
    assert.equal(req.headers.authorization, authorization);
    assert.equal(req.header("authorization"), authorization);
  }
});

test("the guarded wrapper sees the replaced credential, keeps its this and its properties, and returns its result", async () => {
  const seen = [];
  const wrapper = async function (req, res, extra) {
    seen.push([this, req.header("authorization"), res, extra]);
    return "answer";
  };
  wrapper.run = () => "run";
  wrapper.__endpoint = { callableTrigger: {} };
  const marker = Symbol("marker");
  wrapper[marker] = 7;
  const guarded = guardCallableWrapper(wrapper);
  assert.notEqual(guarded, wrapper);
  assert.equal(guarded.run(), "run");
  assert.deepEqual(guarded.__endpoint, { callableTrigger: {} });
  assert.equal(guarded[marker], 7);
  assert.equal(guarded.length, wrapper.length);
  // Properties the SDK adds after the wrapper is built land on the guarded function.
  guarded.__trigger = "x";
  assert.equal(guarded.__trigger, "x");

  const req = request({ authorization: "Bearer forged" });
  markNonCallableRequest(req, plain);
  const res = {};
  const owner = {};
  assert.equal(await guarded.call(owner, req, res, "extra"), "answer");
  assert.deepEqual(seen, [[owner, UNVERIFIED_CREDENTIAL, res, "extra"]]);

  const verified = request({ [VERIFIED_CREDENTIAL_HEADER]: "1", authorization: "Bearer good" });
  markNonCallableRequest(verified, plain);
  await guarded(verified, res);
  assert.equal(seen[1][1], "Bearer good");
  const real = request({ authorization: "Bearer forged" });
  await guarded(real, res);
  assert.equal(seen[2][1], "Bearer forged", "a real callable's request never carries the mark");
});

test("things that are not functions are not wrapped", () => {
  for (const value of [undefined, null, 1, "x", {}]) assert.equal(guardCallableWrapper(value), value);
});

test("property: the wrapper never sees a Bearer the daemon did not verify", () => {
  let seed = 12345;
  const next = () => {
    seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
    return seed / 4294967296;
  };
  const alphabet = ["Bearer ", "bearer ", "BEARER ", "Basic ", "", " ", "x", ".", "eyJ", "=", "owner"];
  for (let run = 0; run < 500; run += 1) {
    let authorization = "";
    for (let i = 0; i < 1 + Math.floor(next() * 5); i += 1) {
      authorization += alphabet[Math.floor(next() * alphabet.length)];
    }
    const verified = next() < 0.3;
    const headers = { authorization };
    if (verified) headers[VERIFIED_CREDENTIAL_HEADER] = "1";
    const req = request(headers);
    markNonCallableRequest(req, plain);
    const seen = requestForCallableWrapper(req).header("authorization");
    if (authorization === "" || verified) assert.equal(seen, authorization, authorization);
    else {
      assert.equal(seen, UNVERIFIED_CREDENTIAL, authorization);
      assert.doesNotMatch(seen, /^Bearer (.*)$/i);
    }
  }
});

test("a request without headers, or with raw headers that are not a list, is neither refused nor changed", () => {
  const bare = { method: "POST" };
  assert.equal(markNonCallableRequest(bare, plain), true);
  assert.equal(requestForCallableWrapper(bare), bare);
  assert.equal(markNonCallableRequest({}, { strict: false, nonCallableHttp: true }), false);
  for (const rawHeaders of ["x-fireemu-credential-verified: 1", { length: 2 }, 7, null]) {
    const req = { headers: {}, rawHeaders };
    markNonCallableRequest(req, plain);
    assert.equal(req.rawHeaders, rawHeaders);
  }
});

test("the wrapper sees only App Check tokens admitted by the daemon", () => {
  for (const strict of [true, false]) {
    for (const marker of ["0", "1"]) {
      const req = request({
        [VERIFIED_APP_CHECK_HEADER]: marker,
        "x-firebase-appcheck": "header.payload.signature",
        authorization: "Bearer forged",
      }, ["X-Fireemu-AppCheck-Verified", marker, "X-Firebase-AppCheck", "header.payload.signature"]);
      markNonCallableRequest(req, { strict, nonCallableHttp: true });
      const seen = requestForCallableWrapper(req);
      assert.equal(seen.header("X-Firebase-AppCheck"), marker === "1" ? "header.payload.signature" : undefined);
      assert.equal(req.header("X-Firebase-AppCheck"), "header.payload.signature");
      assert.equal(req.headers[VERIFIED_APP_CHECK_HEADER], undefined);
      assert.deepEqual(req.rawHeaders, ["X-Firebase-AppCheck", "header.payload.signature"]);
      assert.equal(seen.header("authorization"), strict ? UNVERIFIED_CREDENTIAL : "Bearer forged");
    }
  }
});

test("a task dispatched to a plain HTTP export hides a forged App Check token from its nested wrapper", () => {
  for (const strict of [false, true]) {
    const req = request({
      "x-cloudtasks-taskname": "task-1",
      "x-firebase-appcheck": "forged.token.signature",
      [VERIFIED_APP_CHECK_HEADER]: "0",
    });
    markNonCallableRequest(req, { strict, nonCallableHttp: true });
    assert.equal(requestForCallableWrapper(req).header("x-firebase-appcheck"), undefined);
    assert.equal(req.header("x-firebase-appcheck"), "forged.token.signature");
  }
});

test("property: a nested wrapper cannot read an unadmitted App Check token", () => {
  let seed = 12345;
  const alphabet = "abcXYZ019._- ";
  for (let run = 0; run < 500; run += 1) {
    let token = "";
    for (let i = 0; i < 20; i += 1) {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      token += alphabet[seed % alphabet.length];
    }
    const req = request({ [VERIFIED_APP_CHECK_HEADER]: "0", "x-firebase-appcheck": token });
    markNonCallableRequest(req, plain);
    assert.equal(requestForCallableWrapper(req).header("X-Firebase-AppCheck"), undefined);
    assert.equal(req.header("X-Firebase-AppCheck"), token);
  }
});

test("without App Check selected the emulator profile leaves the nested request unchanged", () => {
  const req = request({ "x-firebase-appcheck": "unverified" });
  assert.equal(markNonCallableRequest(req, { strict: false, nonCallableHttp: true }), false);
  assert.equal(requestForCallableWrapper(req), req);
});

test("an admitted App Check token populates request.app in the SDK wrapper", async (t) => {
  const { existsSync } = await import("node:fs");
  const { createRequire } = await import("node:module");
  const { EventEmitter } = await import("node:events");
  const sdk = new URL("../../conformance/node_modules/firebase-functions/lib/common/providers/https.js", import.meta.url);
  if (!existsSync(sdk)) return t.skip("firebase-functions is not installed under conformance");
  const previousMode = process.env.FIREBASE_DEBUG_MODE;
  const previousFeatures = process.env.FIREBASE_DEBUG_FEATURES;
  process.env.FIREBASE_DEBUG_MODE = "true";
  process.env.FIREBASE_DEBUG_FEATURES = '{"skipTokenVerification":true}';
  try {
    const { onCallHandler } = createRequire(import.meta.url)(sdk.pathname);
    const wrapper = guardCallableWrapper(onCallHandler({ cors: { origin: false }, enforceAppCheck: true }, (call) => ({ app: call.app }), "gcfv2"));
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const token = `${encode({ alg: "none" })}.${encode({ sub: "app-id" })}.signature`;
    for (const [marker, expectedStatus] of [["0", 401], ["1", 200]]) {
      const req = request({ "content-type": "application/json", "x-firebase-appcheck": token, [VERIFIED_APP_CHECK_HEADER]: marker });
      markNonCallableRequest(req, plain);
      const res = new EventEmitter();
      res.status = (status) => { res.statusCode = status; return res; };
      res.send = (body) => { res.body = body; res.emit("finish"); return res; };
      res.setHeader = () => {};
      res.getHeader = () => undefined;
      await wrapper(req, res);
      assert.equal(res.statusCode, expectedStatus);
      if (marker === "1") assert.equal(res.body.result.app.appId, "app-id");
      else assert.equal(res.body.error.status, "UNAUTHENTICATED");
    }
  } finally {
    if (previousMode === undefined) delete process.env.FIREBASE_DEBUG_MODE; else process.env.FIREBASE_DEBUG_MODE = previousMode;
    if (previousFeatures === undefined) delete process.env.FIREBASE_DEBUG_FEATURES; else process.env.FIREBASE_DEBUG_FEATURES = previousFeatures;
  }
});
