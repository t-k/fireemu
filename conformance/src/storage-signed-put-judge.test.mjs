import "./storage-signed-put/test-preload.mjs";

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  classifyStatus,
  clockSkewOk,
  compareRecordings,
  compareTargets,
  describeSignedUrl,
  judgePut,
  normalizeBody,
  normalizeHeaders,
  parseXmlError,
  putRow,
  settleObjects,
} from "./storage-signed-put/judge.mjs";
import { CASES } from "./storage-signed-put/plan.mjs";

const xml = (code, message = "m") =>
  Buffer.from(
    `<?xml version='1.0' encoding='UTF-8'?><Error><Code>${code}</Code><Message>${message}</Message><Details>d</Details></Error>`,
  );
const control = CASES.find((c) => c.control);
const refusal = CASES.find((c) => c.id === "wrong-content-type");

describe("signed PUT judge", () => {
  it("reads a documented XML error from exact bytes and nothing else", () => {
    assert.deepEqual(parseXmlError(xml("SignatureDoesNotMatch", "no")), {
      Code: "SignatureDoesNotMatch",
      Message: "no",
      Details: "d",
    });
    assert.deepEqual(parseXmlError(Buffer.from("<Error><Code>X</Code></Error>")), { Code: "X" });
    for (const bad of [
      "",
      "{}",
      '{"error":{"code":403}}',
      "<html><body>403</body></html>",
      "<Error></Error>",
      "<Error><Message>m</Message></Error>",
      "junk<Error><Code>X</Code></Error>",
      "<Error><Code>X</Code></Error>junk",
    ]) {
      assert.equal(parseXmlError(Buffer.from(bad)), null, bad);
    }
  });

  it("classifies statuses by the shared unknown rule", () => {
    for (const [status, klass] of [
      [200, "accepted"],
      [204, "accepted"],
      [299, "accepted"],
      [199, "unknown"],
      [0, "unknown"],
      [301, "unknown"],
      [307, "unknown"],
      [399, "unknown"],
      [400, "refused"],
      [403, "refused"],
      [404, "refused"],
      [409, "refused"],
      [412, "refused"],
      [499, "refused"],
      [500, "unknown"],
      [503, "unknown"],
    ]) {
      assert.equal(classifyStatus(status), klass, String(status));
    }
  });

  it("stops the run only when the positive control is not accepted", () => {
    assert.equal(judgePut(control, { status: 200, body: Buffer.alloc(0) }).stopRun, false);
    assert.equal(judgePut(control, { status: 403, body: xml("AccessDenied") }).stopRun, true);
    assert.equal(judgePut(control, { status: 400, body: xml("InvalidArgument") }).stopRun, true);
    assert.equal(
      judgePut(refusal, { status: 403, body: xml("SignatureDoesNotMatch") }).stopRun,
      false,
    );
    assert.equal(judgePut(refusal, { status: 200, body: Buffer.alloc(0) }).stopRun, false);
  });

  it("flags a refusal case that was accepted, and names unrecorded body shapes", () => {
    assert.equal(
      judgePut(refusal, { status: 200, body: Buffer.alloc(0) }).createdUnexpectedly,
      true,
    );
    assert.equal(
      judgePut(control, { status: 200, body: Buffer.alloc(0) }).createdUnexpectedly,
      false,
    );
    assert.equal(
      judgePut(refusal, { status: 403, body: xml("SignatureDoesNotMatch") }).createdUnexpectedly,
      false,
    );
    const verdict = judgePut(refusal, { status: 403, body: xml("SignatureDoesNotMatch") });
    assert.deepEqual(
      [verdict.class, verdict.code, verdict.shape],
      ["refused", "SignatureDoesNotMatch", "xml-error"],
    );
    assert.equal(
      judgePut(refusal, { status: 403, body: Buffer.from('{"error":1}') }).shape,
      "other",
    );
    assert.equal(judgePut(refusal, { status: 403, body: Buffer.alloc(0) }).shape, "empty");
    assert.equal(judgePut(refusal, { status: 403, body: Buffer.from('{"error":1}') }).code, null);
  });

  it("compares the body by its byte length and keeps the exact digest", () => {
    const multibyte = Buffer.from("<Error><Code>X</Code><Message>日本</Message></Error>");
    const row = putRow({
      recording: 1,
      testCase: refusal,
      answer: {
        status: 403,
        body: multibyte,
        headers: { "Content-Type": "application/xml", Date: "x" },
      },
      verdict: judgePut(refusal, { status: 403, body: multibyte }),
      masks: [],
    });
    assert.equal(row.bodyBytes, multibyte.length);
    assert.notEqual(row.bodyBytes, row.body.length);
    assert.equal(row.bodySha256.length, 64);
    assert.deepEqual(Object.keys(row.headers), ["content-type"]);
  });

  it("masks run names, signature and credential values and date stamps in bodies", () => {
    const text =
      "<Error>X-Goog-Credential=a%40b%2F20261103%2Fauto&X-Goog-Signature=abcdef sp-1a2b3c4d signer@p.iam T20261103T120000Z 20261103T120000Z</Error>";
    const out = normalizeBody(text, [
      ["signer@p.iam", "<signer>"],
      ["sp-1a2b3c4d", "<run>"],
    ]);
    assert.ok(!out.includes("abcdef"));
    assert.ok(!out.includes("sp-1a2b3c4d"));
    assert.ok(out.includes("<signer>") && out.includes("<run>") && out.includes("<date>"));
  });

  it("drops volatile headers and keeps the rest sorted", () => {
    assert.deepEqual(
      normalizeHeaders({
        Date: "a",
        "X-GUploader-UploadID": "b",
        ETag: "c",
        "Content-Type": "d",
        Server: "e",
        "X-Goog-Generation": "1",
      }),
      { "content-type": "d", server: "e" },
    );
  });

  it("compares recordings and targets row by row", () => {
    const row = (recording, id, extra = {}) => ({
      recording,
      id,
      status: 403,
      class: "refused",
      code: "X",
      shape: "xml-error",
      bodyBytes: 10,
      body: "b",
      headers: {},
      ...extra,
    });
    assert.deepEqual(compareRecordings([row(1, "a"), row(2, "a")]), []);
    assert.deepEqual(compareRecordings([row(1, "a"), row(2, "a", { bodyBytes: 11 })]), [
      { id: "a", fields: ["bodyBytes"], digestOnly: false },
    ]);
    assert.deepEqual(compareRecordings([row(1, "a")]), [
      { id: "a", fields: ["missing-recording"], digestOnly: false },
    ]);
    const prod = [row(1, "a"), row(1, "b"), row(2, "a")];
    const local = [
      row(1, "a", { status: 200, class: "accepted", code: null, shape: "empty", bodyBytes: 0 }),
      row(1, "b"),
    ];
    const rows = compareTargets(prod, local);
    assert.deepEqual(
      rows.map((r) => [r.id, r.match]),
      [
        ["a", false],
        ["b", true],
      ],
    );
    assert.deepEqual(rows[0].fields, ["status", "code", "shape", "bodyBytes"]);
    assert.deepEqual(compareTargets([row(1, "c")], []), [
      {
        id: "c",
        match: false,
        exact: false,
        fields: ["missing-local"],
        exactFields: ["missing-local"],
        extra: [],
      },
    ]);
  });

  it("accepts a local clock within five seconds of the server date only", () => {
    const server = "Tue, 03 Nov 2026 12:00:00 GMT";
    const base = Date.parse(server);
    assert.equal(clockSkewOk(base, server), true);
    assert.equal(clockSkewOk(base + 5000, server), true);
    assert.equal(clockSkewOk(base - 5000, server), true);
    assert.equal(clockSkewOk(base + 5001, server), false);
    assert.equal(clockSkewOk(base - 5001, server), false);
    assert.equal(clockSkewOk(base, undefined), false);
    assert.equal(clockSkewOk(base, "not a date"), false);
  });

  it("reports no credential for a URL that has none", () => {
    const described = describeSignedUrl("https://s.example/b/x?X-Goog-Expires=1", []);
    assert.equal(described.hasCredential, false);
    assert.equal(described.signatureHexLength, 0);
    assert.equal(described.credentialScope, "");
    assert.equal(
      describeSignedUrl("https://s.example/b/x?X-Goog-Credential=a%2F1%2F2%2F3%2F4", [])
        .hasCredential,
      true,
    );
  });

  it("describes a signed URL without its credential or signature", () => {
    const url =
      "https://s.example/b/storage-signed-put/sp-1a2b3c4d/rec1/ok.png?X-Goog-Algorithm=GOOG4-RSA-SHA256&X-Goog-Credential=sa%40p.iam%2F20261103%2Fauto%2Fstorage%2Fgoog4_request&X-Goog-Date=20261103T120000Z&X-Goog-Expires=300&X-Goog-SignedHeaders=content-type%3Bhost&X-Goog-Signature=" +
      "ab".repeat(256);
    const described = describeSignedUrl(url, [["sp-1a2b3c4d", "<run>"]]);
    assert.equal(described.path, "/b/storage-signed-put/<run>/rec1/ok.png");
    assert.equal(described.signedHeaders, "content-type;host");
    assert.equal(described.expires, "300");
    assert.equal(described.credentialScope, "auto/storage/goog4_request");
    assert.equal(described.signatureHexLength, 512);
    assert.ok(!JSON.stringify(described).includes("sa@p.iam"));
    assert.ok(!JSON.stringify(described).includes("abab"));
  });
});

describe("signed PUT settlement (presubmission checklist 3)", () => {
  const settle = (...events) =>
    settleObjects(events.map(([name, event, status]) => ({ name, event, status })));
  const open = (result, name) => result.unresolved.find((u) => u.name === name)?.reason;

  it("settles a confirmed create only by its own 2xx delete and a 404 read after it", () => {
    const result = settle(
      ["a", "create", 200],
      ["a", "delete", 204],
      ["a", "read-after-delete", 404],
    );
    assert.deepEqual(result, { closureReady: true, unresolved: [] });
  });

  it("keeps a confirmed create open when it only reads 404 (no delete of its own)", () => {
    assert.match(open(settle(["a", "create", 200], ["a", "read", 404]), "a"), /not deleted/);
    assert.match(
      open(
        settle(["a", "create", 200], ["a", "delete", 404], ["a", "read-after-delete", 404]),
        "a",
      ),
      /not deleted/,
    );
    assert.match(
      open(
        settle(["a", "create", 200], ["a", "delete", 409], ["a", "read-after-delete", 404]),
        "a",
      ),
      /not deleted/,
    );
  });

  it("keeps an unknown create open on 404s, and settles it only through a positive read", () => {
    for (const unknown of [500, 503, 302, 100, Number.NaN]) {
      assert.match(
        open(settle(["a", "create", unknown], ["a", "read", 404]), "a"),
        /unknown create/,
      );
      assert.match(
        open(
          settle(["a", "create", unknown], ["a", "read", 404], ["a", "read-after-delete", 404]),
          "a",
        ),
        /unknown create/,
      );
    }
    const positive = settle(
      ["a", "create", 503],
      ["a", "read", 200],
      ["a", "delete", 204],
      ["a", "read-after-delete", 404],
    );
    assert.equal(positive.closureReady, true);
    assert.equal(
      settle(
        ["a", "create", 503],
        ["a", "listed"],
        ["a", "delete", 204],
        ["a", "read-after-delete", 404],
      ).closureReady,
      true,
    );
    assert.match(open(settle(["a", "create", 503], ["a", "read", 200]), "a"), /not deleted/);
  });

  it("keeps an unknown delete open for good, even after a later 404 or 2xx", () => {
    for (const unknown of [500, 302, 99, Number.NaN]) {
      const result = settle(
        ["a", "create", 200],
        ["a", "delete", unknown],
        ["a", "read-after-delete", 404],
      );
      assert.equal(open(result, "a"), "unknown delete");
      const resent = settle(
        ["a", "create", 200],
        ["a", "delete", unknown],
        ["a", "delete", 204],
        ["a", "read-after-delete", 404],
      );
      assert.equal(open(resent, "a"), "unknown delete");
    }
  });

  it("does not let one object's answer settle another's", () => {
    const result = settle(
      ["a", "create", 200],
      ["b", "create", 200],
      ["a", "delete", 204],
      ["a", "read-after-delete", 404],
      ["b", "read-after-delete", 404],
    );
    assert.equal(open(result, "b"), "created, not deleted and read back absent");
    assert.equal(open(result, "a"), undefined);
  });

  it("does not count a refused create as a creation", () => {
    assert.equal(settle(["a", "create", 403], ["a", "read", 404]).closureReady, true);
    assert.equal(settle(["a", "create", 400]).closureReady, true);
  });

  it("requires the read after a delete to be a 404, and the delete to be 2xx", () => {
    assert.equal(
      open(
        settle(["a", "create", 200], ["a", "delete", 204], ["a", "read-after-delete", 200]),
        "a",
      ) !== undefined,
      true,
    );
    assert.equal(open(settle(["a", "create", 200], ["a", "delete", 204]), "a") !== undefined, true);
  });

  it("takes 200 as a delete and 2xx only; a 3xx read or an unnamed event settles nothing", () => {
    for (const status of [200, 204, 299]) {
      assert.equal(
        settle(["a", "create", 200], ["a", "delete", status], ["a", "read-after-delete", 404])
          .closureReady,
        true,
        String(status),
      );
    }
    assert.equal(
      open(settle(["a", "create", 503], ["a", "read", 300]), "a"),
      "unknown create, no positive read",
    );
    assert.equal(
      open(settle(["a", "create", 503], ["a", "read", 199]), "a"),
      "unknown create, no positive read",
    );
    assert.equal(
      open(settle(["a", "create", 503], ["a", "read", 299]), "a"),
      "created, not deleted and read back absent",
    );
    assert.equal(
      open(settle(["a", "create", 200], ["a", "delete", 204], ["a", "noop", 404]), "a"),
      "created, not deleted and read back absent",
    );
    assert.equal(
      open(
        settle(["a", "create", 200], ["a", "delete", 199], ["a", "read-after-delete", 404]),
        "a",
      ),
      "unknown delete",
    );
  });
});
