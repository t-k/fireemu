import assert from "node:assert/strict";
import { createServer, request } from "node:http";
import test from "node:test";

import { blockingResult } from "./blocking-response.mjs";
import { blockingFailure } from "./blocking-error.mjs";

class HttpsError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
    const codes = {
      "permission-denied": { canonicalName: "PERMISSION_DENIED", status: 403 },
      "invalid-argument": { canonicalName: "INVALID_ARGUMENT", status: 400 },
    };
    this.httpErrorCode = codes[code];
  }
}
const result = (value, event = "beforeSignIn") => blockingResult(value, event, HttpsError);
const invalid = (run) => assert.throws(run, (error) => error instanceof HttpsError && error.code === "invalid-argument");
const unavailable = {
  canonicalName: "UNAVAILABLE", status: 503, message: "An unexpected error occurred.",
};
const encode = (value) => JSON.parse(JSON.stringify(value));

for (const publicName of [
  "displayName", "photoURL", "disabled", "emailVerified", "customClaims", "sessionClaims",
]) {
  test(`undefined ${publicName} is not an update-mask operation`, () => {
    assert.deepEqual(result({ [publicName]: undefined }), {});
    const actual = result({ [publicName]: undefined, ignored: "not a user field" });
    assert.deepEqual(encode(actual), {});
  });
}

test("explicit null, false and empty strings are not omitted", () => {
  assert.deepEqual(result({ displayName: null, photoURL: "", disabled: false, emailVerified: false }), {
    userRecord: { displayName: null, photoUrl: "", disabled: false, emailVerified: false,
      updateMask: "displayName,photoUrl,disabled,emailVerified" },
  });
});

test("flat undefined is skipped without erasing a neighbouring real update", () => {
  assert.deepEqual(result({ displayName: undefined, emailVerified: true }), {
    userRecord: { emailVerified: true, updateMask: "emailVerified" },
  });
});

test("existing no-result and unknown-property behaviour stays unchanged", () => {
  for (const value of [undefined, null, false, 0, "ignored", () => {}]) assert.deepEqual(result(value), {});
  const unknown = {}; unknown.self = unknown;
  assert.deepEqual(result({ ignored: unknown }), {});
  assert.deepEqual(result(Object.create({ disabled: true })), {});
  invalid(() => result([]));
});

for (const field of ["customClaims", "sessionClaims"]) {
  for (const wire of [false, true]) {
    const wrap = (claims) => wire
      ? { userRecord: { [field]: claims, updateMask: field } }
      : { [field]: claims };
    test(`${field} ${wire ? "wire" : "flat"}: toJSON cannot add reserved names`, () => {
      invalid(() => result(wrap({ toJSON: () => ({ firebase: "not allowed" }) })));
    });
    test(`${field} ${wire ? "wire" : "flat"}: serialized size is checked`, () => {
      invalid(() => result(wrap({ toJSON: () => ({ value: "x".repeat(1000) }) })));
    });
    test(`${field} ${wire ? "wire" : "flat"}: each serialization hook runs once`, () => {
      let calls = 0;
      const claims = { toJSON() { calls++; return calls === 1 ? { role: "user" } : { firebase: "changed" }; } };
      const actual = result(wrap(claims));
      assert.deepEqual(encode(actual).userRecord[field], { role: "user" });
      assert.deepEqual(encode(actual).userRecord[field], { role: "user" });
      assert.equal(calls, 1);
    });
  }
}

test("wire-envelope toJSON is validated after it has run", () => {
  invalid(() => result({
    userRecord: { customClaims: { safe: true }, updateMask: "customClaims" },
    toJSON: () => ({ userRecord: { customClaims: { firebase: true }, updateMask: "customClaims" } }),
  }));
  for (const replacement of [null, [], "invalid", {}, { userRecord: null }, { userRecord: [] }]) {
    invalid(() => result({ userRecord: {}, toJSON: () => replacement }));
  }
});

test("nested wire userRecord toJSON cannot bypass claim validation", () => {
  invalid(() => result({ userRecord: {
    customClaims: { safe: true }, updateMask: "customClaims",
    toJSON: () => ({ customClaims: { firebase: true }, updateMask: "customClaims" }),
  } }));
});

test("a flat claims getter is sampled once, not once per validation stage", () => {
  let reads = 0;
  const value = { get customClaims() { reads++; return reads === 1 ? { safe: true } : { firebase: true }; } };
  assert.deepEqual(encode(result(value)).userRecord.customClaims, { safe: true });
  assert.equal(reads, 1);
});

test("a wire userRecord getter is sampled once", () => {
  let reads = 0;
  const value = { get userRecord() {
    reads++;
    return { updateMask: "customClaims", customClaims: reads === 1 ? { role: "user" } : { firebase: true } };
  } };
  assert.deepEqual(encode(result(value)).userRecord.customClaims, { role: "user" });
  assert.equal(reads, 1);
});

test("caller mutation after validation cannot change nested claims or wire extensions", () => {
  const nested = { list: [{ role: "user" }] };
  const raw = { userRecord: { customClaims: nested, updateMask: "customClaims" }, extra: { flag: true } };
  const actual = result(raw);
  raw.userRecord.updateMask = "disabled";
  nested.list[0].role = "admin";
  raw.extra.flag = false;
  assert.equal(actual.userRecord.updateMask, "customClaims");
  assert.equal(actual.userRecord.customClaims.list[0].role, "user");
  assert.equal(actual.extra.flag, true);
  for (const value of [actual, actual.userRecord, actual.extra, actual.userRecord.customClaims, actual.userRecord.customClaims.list]) {
    assert.equal(Object.isFrozen(value), true);
  }
  assert.throws(() => { actual.userRecord.updateMask = "disabled"; }, TypeError);
});

test("wire envelope extensions and non-callable toJSON data survive materialization", () => {
  const raw = JSON.parse('{"userRecord":{"customClaims":{"__proto__":{"role":"value"},"toJSON":"data"},"updateMask":"customClaims"},"extra":true}');
  assert.deepEqual(encode(result(raw)), raw);
  assert.equal({}.role, undefined);
});

test("normal Date serialization and nested JSON data are preserved", () => {
  const actual = result({ customClaims: { date: new Date("2026-01-02T00:00:00Z"), array: [1, false, null, { text: "日本語" }] } });
  assert.deepEqual(actual.userRecord.customClaims, {
    date: "2026-01-02T00:00:00.000Z", array: [1, false, null, { text: "日本語" }],
  });
});

test("claim-shape checks happen after conversion to wire JSON", () => {
  for (const shape of [[], false, 1, "text"]) {
    for (const field of ["customClaims", "sessionClaims"]) {
      invalid(() => result({ [field]: { toJSON: () => shape } }));
    }
  }
});

test("combined-size checks use final claims and preserve session override", () => {
  invalid(() => result({
    customClaims: { toJSON: () => ({ a: "a".repeat(600) }) },
    sessionClaims: { toJSON: () => ({ b: "b".repeat(600) }) },
  }));
  const actual = result({ customClaims: { shared: "a".repeat(900) }, sessionClaims: { shared: "b".repeat(900) } });
  assert.equal(actual.userRecord.customClaims.shared[0], "a");
  assert.equal(actual.userRecord.sessionClaims.shared[0], "b");
});

test("the SDK UTF-16 code-unit limit is not replaced with byte or scalar length", () => {
  const exact = { value: "😀".repeat(494) };
  assert.equal(JSON.stringify(exact).length, 1000);
  assert.deepEqual(result({ customClaims: exact }).userRecord.customClaims, exact);
  invalid(() => result({ customClaims: { value: "😀".repeat(495) } }));
});

test("unreadable or non-serializable results fail with fixed non-secret diagnostics", () => {
  const circular = {}; circular.self = circular;
  for (const value of [
    { customClaims: circular }, { customClaims: { bigint: 1n } },
    { get customClaims() { throw new Error("fixture-private"); } },
    { customClaims: { toJSON() { throw new Error("fixture-private"); } } },
    { userRecord: { get customClaims() { throw new Error("fixture-private"); } } },
  ]) {
    assert.throws(() => result(value), (error) => {
      assert.equal(error.code, "invalid-argument");
      assert.equal(error.message.includes("fixture-private"), false);
      return true;
    });
  }
});

test("ordinary literal responses stay byte-for-byte compatible", () => {
  const actual = result({ displayName: "Guest", photoURL: "https://example.invalid/photo", disabled: false,
    emailVerified: true, customClaims: { plan: "basic" }, sessionClaims: { loggedIn: true } });
  assert.equal(JSON.stringify(actual), '{"userRecord":{"displayName":"Guest","photoUrl":"https://example.invalid/photo","disabled":false,"emailVerified":true,"customClaims":{"plan":"basic"},"sessionClaims":{"loggedIn":true},"updateMask":"displayName,photoUrl,disabled,emailVerified,customClaims,sessionClaims"}}');
});

test("public error message is the exact message that was checked", () => {
  let calls = 0;
  const error = new HttpsError("permission-denied", "safe");
  Object.defineProperty(error, "message", { get() { calls++; return calls === 1 ? "safe" : "fixture-private\nunsafe"; } });
  assert.deepEqual(blockingFailure(error, [HttpsError]), { canonicalName: "PERMISSION_DENIED", status: 403, message: "safe" });
  assert.equal(calls, 1);
});

for (const field of ["code", "message", "httpErrorCode"]) {
  test(`throwing ${field} getter cannot break the public error path`, () => {
    const error = new HttpsError("permission-denied", "safe");
    Object.defineProperty(error, field, { get() { throw new Error("fixture-private"); } });
    assert.deepEqual(blockingFailure(error, [HttpsError]), unavailable);
  });
}

test("all public error inputs are sampled once", () => {
  const counts = { code: 0, message: 0, httpErrorCode: 0, canonicalName: 0, status: 0 };
  const error = new HttpsError("permission-denied", "safe");
  const metadata = {};
  for (const [name, value] of [["canonicalName", "PERMISSION_DENIED"], ["status", 403]]) {
    Object.defineProperty(metadata, name, { get() { counts[name]++; return value; } });
  }
  for (const [name, value] of [["code", "permission-denied"], ["message", "safe"], ["httpErrorCode", metadata]]) {
    Object.defineProperty(error, name, { get() { counts[name]++; return value; } });
  }
  assert.equal(blockingFailure(error, [HttpsError]).status, 403);
  assert.deepEqual(counts, { code: 1, message: 1, httpErrorCode: 1, canonicalName: 1, status: 1 });
});

test("throwing metadata, revoked proxies and instanceof hooks fail closed", () => {
  for (const field of ["canonicalName", "status"]) {
    const error = new HttpsError("permission-denied", "safe");
    Object.defineProperty(error.httpErrorCode, field, { get() { throw new Error("fixture-private"); } });
    assert.deepEqual(blockingFailure(error, [HttpsError]), unavailable);
  }
  const { proxy, revoke } = Proxy.revocable(new HttpsError("permission-denied", "safe"), {});
  revoke();
  assert.deepEqual(blockingFailure(proxy, [HttpsError]), unavailable);
  class ThrowingInstance { static [Symbol.hasInstance]() { throw new Error("fixture-private"); } }
  assert.deepEqual(blockingFailure({}, [ThrowingInstance]), unavailable);
});

test("plain thrown values are not trusted and their getters are not inspected", () => {
  let reads = 0;
  const error = { get code() { reads++; throw new Error("fixture-private"); } };
  assert.deepEqual(blockingFailure(error, [HttpsError]), unavailable);
  assert.equal(reads, 0);
  for (const value of [null, undefined, false, "private", 5]) assert.deepEqual(blockingFailure(value, [HttpsError]), unavailable);
});

test("a safe snapshot remains stable across an actual HTTP serialization", { timeout: 5000 }, async () => {
  let calls = 0;
  const source = { customClaims: { toJSON() { calls++; return calls === 1 ? { role: "user" } : { firebase: true }; } } };
  const snapshot = result(source);
  source.customClaims = { firebase: "changed" };
  const server = createServer((_req, res) => {
    res.setHeader("Content-Type", "application/json");
    res.end(JSON.stringify(snapshot));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const actual = await new Promise((resolve, reject) => {
      const req = request({ hostname: "127.0.0.1", port: server.address().port, path: "/" }, (res) => {
        const chunks = []; res.on("data", (data) => chunks.push(data));
        res.on("end", () => resolve(JSON.parse(Buffer.concat(chunks).toString("utf8"))));
        res.on("error", reject);
      });
      req.on("error", reject); req.end();
    });
    assert.deepEqual(actual.userRecord.customClaims, { role: "user" });
    assert.equal(calls, 1);
  } finally {
    server.closeAllConnections();
    await new Promise((resolve) => server.close(resolve));
  }
});
