import assert from "node:assert/strict";
import { test } from "node:test";
import { createContext, SANDBOX_PROJECT } from "./fs-ent-text/harness.mjs";
import { runCorpus } from "./fs-ent-text/session.mjs";

const context = () =>
  createContext({
    run: "1",
    database: "entpipe1",
    target: { kind: "production", token: "test-token", quotaProject: SANDBOX_PROJECT },
  });
const commit = (id) => ({
  id,
  rpc: "commit",
  body: {
    writes: [
      { update: { name: "{docs}/textobs1/probe", fields: { title: { stringValue: "fox" } } } },
    ],
  },
});

for (const [label, status, text] of [
  ["server-error", 500, '{"error":{}}'],
  ["timeout", 408, '{"error":{}}'],
  ["malformed-success", 200, "not-json"],
]) {
  test(`unknown ${label} preserves raw and prevents later writes and cleanup`, async () => {
    const previous = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url) => {
      calls.push(url);
      return url.endsWith(":runQuery")
        ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
        : new Response(text, { status });
    };
    try {
      let error;
      try {
        await runCorpus(
          [{ id: "probe", steps: [commit("uncertain"), commit("later")] }],
          context(),
        );
      } catch (caught) {
        error = caught;
      }
      assert.equal(error?.fatal, true);
      assert.equal(calls.length, 2, calls.join("\n"));
      assert.equal(error.partial.results.probe.raw.uncertain.response.text, text);
      assert.equal(
        error.partial.results.probe.steps.uncertain.status,
        label === "malformed-success" ? 0 : status,
      );
      assert.equal(error.partial.results.probe.steps.later, undefined);
    } finally {
      globalThis.fetch = previous;
    }
  });
}
test("definite validation rejection permits next step and normal empty cleanup", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  let writes = 0;
  globalThis.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith(":runQuery")) return new Response('[{"readTime":"2026-10-23T00:00:00Z"}]');
    writes++;
    return writes === 1
      ? new Response('{"error":{"code":400}}', { status: 400 })
      : new Response('{"commitTime":"2026-10-23T00:00:00Z","writeResults":[{}]}');
  };
  try {
    const result = await runCorpus(
      [{ id: "probe", steps: [commit("rejected"), commit("accepted")] }],
      context(),
    );
    assert.equal(result.results.probe.steps.accepted.status, 200);
    assert.equal(writes, 2);
    assert.equal(calls.length, 5);
  } finally {
    globalThis.fetch = previous;
  }
});

test("unknown seed records triggering harness raw and never wipes", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    return url.endsWith(":runQuery")
      ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
      : new Response('{"error":{"code":500}}', { status: 500 });
  };
  try {
    await assert.rejects(
      runCorpus(
        [
          {
            id: "probe",
            seed: [["textobs1/probe", { title: { stringValue: "fox" } }]],
            steps: [commit("later")],
          },
        ],
        context(),
      ),
      (error) => {
        assert.equal(error.partial.harnessRaw.response.status, 500);
        assert.equal(calls.length, 2);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});
test("unknown cleanup keeps the completed program raw", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  let queries = 0;
  globalThis.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith(":runQuery")) {
      queries++;
      return queries === 1
        ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
        : new Response('{"error":{}}', { status: 500 });
    }
    return new Response('{"commitTime":"2026-10-23T00:00:00Z","writeResults":[{}]}');
  };
  try {
    await assert.rejects(
      runCorpus([{ id: "probe", steps: [commit("known")] }], context()),
      (error) => {
        assert.equal(error.partial.results.probe.steps.known.status, 200);
        assert.equal(error.partial.results.probe.raw.known.response.status, 200);
        assert.equal(error.partial.harnessRaw.response.status, 500);
        assert.equal(calls.length, 3);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});
test("unknown gRPC read stops without cleanup or following write", async () => {
  const { createRequire } = await import("node:module");
  const grpc = createRequire(import.meta.url)("@grpc/grpc-js");
  const previous = globalThis.fetch;
  const original = grpc.Client.prototype.makeUnaryRequest;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    return new Response('[{"readTime":"2026-10-23T00:00:00Z"}]');
  };
  grpc.Client.prototype.makeUnaryRequest = function (...args) {
    calls.push("grpc");
    args.at(-1)({ code: 14, details: "unavailable" });
  };
  try {
    await assert.rejects(
      runCorpus(
        [
          {
            id: "probe",
            steps: [
              { id: "uncertain", rpc: "partitionQuery", transport: "grpc", body: {} },
              commit("later"),
            ],
          },
        ],
        context(),
      ),
      (error) => {
        assert.equal(error.partial.results.probe.steps.uncertain.code, 14);
        assert.equal(error.partial.results.probe.raw.uncertain.response.code, 14);
        assert.equal(calls.length, 2);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
    grpc.Client.prototype.makeUnaryRequest = original;
  }
});

test("the text request layer refuses the shared default database", () => {
  assert.throws(
    () =>
      createContext({
        run: "1",
        database: "(default)",
        target: { kind: "production", token: "test-token", quotaProject: SANDBOX_PROJECT },
      }),
    /not a sandbox database/,
  );
});
test("HTTP200 stream error does not permit a later mutation", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    return url.endsWith(":runQuery")
      ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
      : new Response('[{"error":{"code":500,"status":"INTERNAL"}}]');
  };
  try {
    await assert.rejects(
      runCorpus(
        [
          {
            id: "probe",
            steps: [
              {
                id: "uncertain",
                rpc: "executePipeline",
                body: { structuredPipeline: { pipeline: { stages: [] } } },
              },
              commit("later"),
            ],
          },
        ],
        context(),
      ),
      (error) => {
        assert.equal(calls.length, 2);
        assert.equal(error.partial.results.probe.raw.uncertain.response.status, 200);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});

test("an unreadable successful response retains observed status and the failure marker", async () => {
  const previous = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith(":runQuery")) return new Response('[{"readTime":"2026-10-23T00:00:00Z"}]');
    return {
      status: 200,
      text: async () => {
        throw new TypeError("body disconnected");
      },
    };
  };
  try {
    await assert.rejects(
      runCorpus([{ id: "probe", steps: [commit("uncertain"), commit("later")] }], context()),
      (error) => {
        assert.equal(calls.length, 2);
        assert.equal(error.partial.results.probe.raw.uncertain.response.status, 200);
        assert.equal(error.partial.results.probe.raw.uncertain.response.bodyReadError, "TypeError");
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});
test("unknown outer cleanup retains every completed program and request count", async () => {
  const previous = globalThis.fetch;
  let queries = 0;
  const calls = [];
  globalThis.fetch = async (url) => {
    calls.push(url);
    if (url.endsWith(":runQuery")) {
      queries++;
      return queries < 3
        ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
        : new Response('{"error":{}}', { status: 500 });
    }
    return new Response('{"commitTime":"2026-10-23T00:00:00Z","writeResults":[{}]}');
  };
  try {
    await assert.rejects(
      runCorpus([{ id: "probe", steps: [commit("known")] }], context()),
      (error) => {
        assert.equal(error.partial.results.probe.steps.known.status, 200);
        assert.equal(error.partial.harnessRaw.response.status, 500);
        assert.equal(error.partial.requests, 1);
        assert.equal(error.partial.harnessRequests, 3);
        assert.equal(calls.length, 4);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});
for (const body of ['"invalid pipeline response"', '[{"executionDuration":"invalid"}]']) {
  test(`invalid successful pipeline response halts with intact raw: ${body}`, async () => {
    const previous = globalThis.fetch;
    const calls = [];
    globalThis.fetch = async (url) => {
      calls.push(url);
      return url.endsWith(":runQuery")
        ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
        : new Response(body);
    };
    try {
      await assert.rejects(
        runCorpus(
          [
            {
              id: "probe",
              steps: [
                {
                  id: "uncertain",
                  rpc: "executePipeline",
                  body: { structuredPipeline: { pipeline: { stages: [] } } },
                },
                commit("later"),
              ],
            },
          ],
          context(),
        ),
        (error) => {
          assert.equal(calls.length, 2);
          assert.equal(error.partial.results.probe.raw.uncertain.response.text, body);
          return error.fatal;
        },
      );
    } finally {
      globalThis.fetch = previous;
    }
  });
}

test("malformed wipe inventory retains the exact received response", async () => {
  const previous = globalThis.fetch;
  const body = '[{"unexpected":true}]';
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    return new Response(body);
  };
  try {
    await assert.rejects(
      runCorpus([{ id: "probe", steps: [commit("later")] }], context()),
      (error) => {
        assert.equal(calls, 1);
        assert.equal(error.partial.harnessRaw.response.text, body);
        assert.ok(error.partial.harnessRaw.request.structuredQuery);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
  }
});
test("gRPC normalization failure is captured before any later mutation", async () => {
  const { createRequire } = await import("node:module");
  const grpc = createRequire(import.meta.url)("@grpc/grpc-js");
  const previous = globalThis.fetch;
  const original = grpc.Client.prototype.makeUnaryRequest;
  let calls = 0;
  globalThis.fetch = async () => {
    calls++;
    return new Response('[{"readTime":"2026-10-23T00:00:00Z"}]');
  };
  grpc.Client.prototype.makeUnaryRequest = function (...args) {
    calls++;
    args.at(-1)(null, { executionDuration: { seconds: "invalid", nanos: 0 } });
  };
  try {
    await assert.rejects(
      runCorpus(
        [
          {
            id: "probe",
            steps: [
              { id: "uncertain", rpc: "partitionQuery", transport: "grpc", body: {} },
              commit("later"),
            ],
          },
        ],
        context(),
      ),
      (error) => {
        assert.equal(calls, 2);
        assert.equal(
          error.partial.results.probe.raw.uncertain.response.messages[0].executionDuration.seconds,
          "invalid",
        );
        assert.equal(error.partial.results.probe.steps.uncertain.status, 0);
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
    grpc.Client.prototype.makeUnaryRequest = original;
  }
});
test("channel close failure cannot replace the original fatal partial", async () => {
  const { createRequire } = await import("node:module");
  const { v1 } = createRequire(import.meta.url)("@google-cloud/firestore");
  const previous = globalThis.fetch;
  const original = v1.FirestoreClient.prototype.close;
  globalThis.fetch = async (url) =>
    url.endsWith(":runQuery")
      ? new Response('[{"readTime":"2026-10-23T00:00:00Z"}]')
      : new Response('{"error":{}}', { status: 500 });
  v1.FirestoreClient.prototype.close = async () => {
    throw new Error("close failed");
  };
  try {
    await assert.rejects(
      runCorpus([{ id: "probe", steps: [commit("uncertain")] }], context()),
      (error) => {
        assert.equal(error.partial.results.probe.raw.uncertain.response.status, 500);
        assert.equal(error.message, "unknown program response; resource retained");
        return error.fatal;
      },
    );
  } finally {
    globalThis.fetch = previous;
    v1.FirestoreClient.prototype.close = original;
  }
});
