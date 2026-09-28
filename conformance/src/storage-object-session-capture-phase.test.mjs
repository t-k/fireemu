import assert from "node:assert/strict";
import test from "node:test";
import * as module from "./storage-object/production-session.mjs";
import { buildCorpus } from "./storage-object/corpus.mjs";

test("canonical GCS and Firebase continuation phases match their validated command and range", () => {
  assert.equal(typeof module.productionSessionCapturePhase, "function");
  const corpus = buildCorpus({
    bucket: "example.appspot.com",
    prefix: "storage-object/recordone/",
  });
  const observed = new Set();
  for (const recipe of corpus.recipes.filter((row) => row.id.endsWith("/resumable-upload"))) {
    for (const step of [...recipe.steps, ...recipe.cleanup].filter(
      (row) => row.sessionUriReference,
    )) {
      let expected;
      if (step.dialect === "firebase")
        expected = {
          query: "query",
          cancel: "cancel",
          upload: "upload",
          "upload, finalize": "finalize",
        }[step.headers["x-goog-upload-command"]];
      else if (step.method === "DELETE") expected = "cancel";
      else if (step.headers["content-range"].startsWith("bytes */")) expected = "query";
      else {
        const range = /^bytes ([0-9]+)-([0-9]+)\/([0-9]+)$/.exec(step.headers["content-range"]);
        expected = BigInt(range[2]) + 1n === BigInt(range[3]) ? "finalize" : "upload";
      }
      assert.equal(
        module.productionSessionCapturePhase(step),
        expected,
        `${step.dialect}/${step.id}`,
      );
      observed.add(`${step.dialect}/${expected}`);
    }
  }
  assert.equal(observed.size, 8);
});

test("session phase classification rejects malformed data before invoking hooks", () => {
  assert.equal(typeof module.productionSessionCapturePhase, "function");
  let hooks = 0;
  const value = {
    dialect: "gcs",
    method: "PUT",
    headers: { "content-length": "0", "content-range": "bytes */3" },
  };
  for (const supplied of [
    { ...value, method: "GET" },
    { ...value, headers: { "content-length": "1", "content-range": "bytes */3" } },
    new Proxy(value, {
      ownKeys() {
        hooks++;
        throw new Error();
      },
    }),
    {
      ...value,
      headers: Object.defineProperty({}, "content-range", {
        enumerable: true,
        get() {
          hooks++;
          return "bytes */3";
        },
      }),
    },
  ])
    assert.throws(
      () => module.productionSessionCapturePhase(supplied),
      /^Error: invalid production session capture phase$/,
    );
  assert.equal(hooks, 0);
});
