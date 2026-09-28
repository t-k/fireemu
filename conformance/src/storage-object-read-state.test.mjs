import assert from "node:assert/strict";
import test from "node:test";
import { assertUnchangedReadbacks } from "./storage-object/read-state.mjs";

const before = () =>
  ["firebase", "gcs"].flatMap((dialect) => [
    {
      dialect,
      kind: "metadata",
      status: 200,
      bodyBase64: Buffer.from(
        JSON.stringify({
          bucket: "example.appspot.com",
          name: "owned/object",
          generation: "9007199254740993",
          metageneration: "1",
          metadata: { marker: "initial" },
        }),
      ).toString("base64"),
    },
    { dialect, kind: "media", status: 200, bodyBase64: "AP+A" },
  ]);
test("a full pair through both dialects establishes unchanged supplied state only", () => {
  const input = before();
  const after = structuredClone(input);
  after[0].bodyBase64 = Buffer.from(
    JSON.stringify({
      metadata: { marker: "initial" },
      metageneration: "1",
      generation: "9007199254740993",
      name: "owned/object",
      bucket: "example.appspot.com",
    }),
  ).toString("base64");
  assert.equal(assertUnchangedReadbacks({ before: input, after }), true);
});
test("a nominal read changing generation, metageneration, metadata or bytes rejects", () => {
  for (const index of [0, 2])
    for (const [field, value] of [
      ["generation", "9007199254740994"],
      ["metageneration", "2"],
      ["metadata", { marker: "changed" }],
    ]) {
      const input = before(),
        after = structuredClone(input);
      const metadata = JSON.parse(Buffer.from(after[index].bodyBase64, "base64"));
      metadata[field] = value;
      after[index].bodyBase64 = Buffer.from(JSON.stringify(metadata)).toString("base64");
      assert.throws(() => assertUnchangedReadbacks({ before: input, after }), /changed/);
    }
  for (const index of [1, 3]) {
    const input = before(),
      after = structuredClone(input);
    after[index].bodyBase64 = "AP+B";
    assert.throws(() => assertUnchangedReadbacks({ before: input, after }), /changed/);
  }
});
test("fresh absence reads accept error-body changes but reject surprising presence", () => {
  const input = before().map((row) => Object.assign({}, row, { status: 404, bodyBase64: "e30=" }));
  const after = input.map((row) => Object.assign({}, row, { bodyBase64: "e30K" }));
  assert.equal(assertUnchangedReadbacks({ before: input, after }), true);
  after[1] = { ...after[1], status: 200 };
  assert.throws(() => assertUnchangedReadbacks({ before: input, after }), /changed|inconsistent/);
});
test("incomplete, duplicate and failed readbacks cannot prove unchanged state", () => {
  for (const after of [
    before().slice(1),
    [...before().slice(0, 3), before()[0]],
    before().map((row) => Object.assign({}, row, { status: 501 })),
  ])
    assert.throws(() => assertUnchangedReadbacks({ before: before(), after }));
});
test("invalid raw encoding and invalid metadata reject without exposing body contents", () => {
  for (const bodyBase64 of ["!secret!", "bnVsbA==", "A".repeat(1_400_000)]) {
    const input = before(),
      after = structuredClone(input);
    after[0].bodyBase64 = bodyBase64;
    assert.throws(
      () => assertUnchangedReadbacks({ before: input, after }),
      (error) => !error.message.includes("secret"),
    );
  }
});
