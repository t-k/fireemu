import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
const target = new URL("../pubsub-production/fixture-baseline.mjs", import.meta.url);
async function module() {
  assert.ok(existsSync(target), "read-only fixture baseline collector is missing");
  return import(target.href);
}
const number = "123456789012";
const options = (extra) => ({
  projectNumber: number,
  accessToken: "fake-token",
  guard: async () => {},
  persist: async () => {},
  send: async () => new Response("{}"),
  ...extra,
});
test("baseline uses exactly project identity GET, read-only project IAM POST and service-agent GET", async () => {
  const { baselineRequests } = await module(),
    r = baselineRequests(number);
  assert.equal(r.length, 3);
  assert.deepEqual(
    r.map((x) => [x.id, x.method]),
    [
      ["identity", "GET"],
      ["project-iam", "POST"],
      ["pubsub-service-identity", "GET"],
    ],
  );
  assert.equal(
    r[1].url,
    "https://cloudresourcemanager.googleapis.com/v1/projects/fireemu-oracle-idp:getIamPolicy",
  );
  assert.equal(r[1].requestBody, '{"options":{"requestedPolicyVersion":3}}');
  assert.equal(
    r[2].url,
    "https://iam.googleapis.com/v1/projects/fireemu-oracle-idp/serviceAccounts/service-123456789012%40gcp-sa-pubsub.iam.gserviceaccount.com",
  );
  assert.ok(r.every((x) => x.readOnly === true && Object.isFrozen(x)));
  assert.throws(() => baselineRequests("bad"));
});
test("durable reservations and live re-admission precede each immutable fixed request and raw response", async () => {
  const { collectBaseline } = await module();
  const rows = [];
  let checks = 0,
    calls = 0;
  const r = await collectBaseline(
    options({
      guard: async (request) => {
        checks++;
        assert.ok(Object.isFrozen(request));
      },
      persist: async (row) => rows.push(row),
      send: async (request) => {
        calls++;
        assert.equal(checks, calls * 2);
        assert.equal(rows.at(-1).state, "before-send");
        assert.equal(request.redirect, "manual");
        assert.equal(request.headers.authorization, "Bearer fake-token");
        if (request.method === "POST")
          assert.equal(request.body, '{"options":{"requestedPolicyVersion":3}}');
        return new Response("raw\n", {
          status: 403,
          headers: { "content-type": "application/json" },
        });
      },
    }),
  );
  assert.deepEqual(r, {
    outcome: "captured-read-only-baseline",
    attempted: 3,
    completed: 3,
    unknown: 0,
  });
  assert.equal(rows.filter((row) => row.state === "response-headers").length, 3);
  assert.equal(rows.at(-1).state, "response-persisted");
  assert.equal(rows.at(-1).bodyBase64, "cmF3Cg==");
  assert.match(rows.at(-1).bodySha256, /^[a-f0-9]{64}$/);
  assert.ok(!JSON.stringify(rows).includes("fake-token"));
});
test("mandatory admission and failed WAL prevent dispatch; post-WAL revocation consumes an unknown slot", async () => {
  const { collectBaseline } = await module();
  await assert.rejects(collectBaseline(options({ guard: undefined })));
  let sends = 0;
  const transport = async () => {
    sends++;
    return new Response("{}");
  };
  const failed = await collectBaseline(
    options({
      send: transport,
      persist: async () => {
        throw new Error("fake-token");
      },
    }),
  );
  assert.equal(sends, 0);
  assert.equal(failed.unknown, 1);
  let calls = 0;
  const revoked = await collectBaseline(
    options({
      send: transport,
      guard: async () => {
        if (++calls === 2) throw new Error("revoked");
      },
    }),
  );
  assert.equal(sends, 0);
  assert.equal(revoked.unknown, 1);
  assert.equal(revoked.completed, 0);
});
test("unknown transport and redirect stop without retries, extra reads or exception reflection", async () => {
  const { collectBaseline } = await module();
  for (const mode of ["transport", "redirect"]) {
    let calls = 0;
    const rows = [];
    const r = await collectBaseline(
      options({
        persist: async (row) => rows.push(row),
        send: async () => {
          calls++;
          if (mode === "transport") throw new Error("fake-token");
          return new Response("", {
            status: 302,
            headers: { location: "https://unowned.invalid" },
          });
        },
      }),
    );
    assert.equal(calls, 1);
    assert.equal(r.outcome, "incomplete-read-only-baseline");
    assert.equal(r.unknown, mode === "transport" ? 1 : 0);
    assert.ok(!JSON.stringify(rows).includes("fake-token"));
  }
});
test("wall exhaustion, response overflow and reflected credentials cannot become recorded baseline proof", async () => {
  const { collectBaseline } = await module();
  for (const mode of ["wall", "bytes", "body-secret", "header-secret"]) {
    let now = 0,
      calls = 0;
    const rows = [];
    const r = await collectBaseline(
      options({
        clock: () => now,
        persist: async (row) => {
          rows.push(row);
          if (mode === "wall" && row.state === "before-send") now = 600001;
        },
        send: async () => {
          calls++;
          return new Response(
            mode === "bytes"
              ? "x".repeat(1024 * 1024 + 1)
              : mode === "body-secret"
                ? "fake-token"
                : "{}",
            { headers: mode === "header-secret" ? { echo: "fake-token" } : {} },
          );
        },
      }),
    );
    assert.equal(r.outcome, "incomplete-read-only-baseline");
    assert.equal(r.unknown, 1);
    assert.equal(calls, mode === "wall" ? 0 : 1);
    assert.ok(!JSON.stringify(rows).includes("fake-token"));
    assert.equal(rows.filter((row) => row.state === "response-persisted").length, 0);
  }
});
test("late final persistence cannot report a captured baseline", async () => {
  const { collectBaseline } = await module();
  let now = 0;
  const result = await collectBaseline(
    options({
      clock: () => now,
      persist: async (row) => {
        if (row.id === "pubsub-service-identity" && row.state === "response-persisted")
          now = 600001;
      },
    }),
  );
  assert.equal(result.outcome, "incomplete-read-only-baseline");
  assert.equal(result.completed, 2);
  assert.equal(result.unknown, 1);
});
test("late final response cleanup cannot report captured despite three durable responses", async () => {
  const { collectBaseline } = await module();
  let now = 0,
    sends = 0;
  const result = await collectBaseline(
    options({
      clock: () => now,
      send: async () => {
        sends++;
        return {
          status: 200,
          headers: new Headers(),
          body: {
            locked: false,
            getReader: () => undefined,
            cancel: async () => {
              if (sends === 3) now = 600001;
            },
          },
        };
      },
    }),
  );
  assert.equal(result.outcome, "incomplete-read-only-baseline");
  assert.equal(result.completed, 3);
  assert.equal(result.unknown, 0);
});
test("overall abort bounds a hanging callback and requires process termination", async () => {
  const { collectBaseline } = await module();
  const abort = new AbortController();
  let sends = 0;
  const result = await collectBaseline(
    options({
      signal: abort.signal,
      guard: async (_request, context) => {
        assert.ok(context.signal instanceof AbortSignal);
        abort.abort();
        return new Promise(() => {});
      },
      send: async () => {
        sends++;
        return new Response("{}");
      },
    }),
  );
  assert.equal(sends, 0);
  assert.equal(result.outcome, "incomplete-read-only-baseline");
  assert.equal(result.terminationRequired, true);
});
test("interrupted reservation conservatively consumes its slot and prohibits dispatch", async () => {
  const { collectBaseline } = await module();
  const abort = new AbortController();
  let sends = 0;
  const result = await collectBaseline(
    options({
      signal: abort.signal,
      persist: async (row, context) => {
        assert.equal(row.state, "before-send");
        assert.ok(context.signal instanceof AbortSignal);
        abort.abort();
        return new Promise(() => {});
      },
      send: async () => {
        sends++;
        return new Response("{}");
      },
    }),
  );
  assert.equal(sends, 0);
  assert.equal(result.attempted, 1);
  assert.equal(result.unknown, 1);
  assert.equal(result.terminationRequired, true);
});
test("failed response cleanup halts before another request", async () => {
  const { collectBaseline } = await module();
  let sends = 0;
  const result = await collectBaseline(
    options({
      send: async () => {
        sends++;
        return {
          status: 200,
          headers: new Headers(),
          body: {
            locked: false,
            getReader: () => undefined,
            cancel: async () => {
              throw new Error("cleanup failure");
            },
          },
        };
      },
    }),
  );
  assert.equal(sends, 1);
  assert.equal(result.outcome, "incomplete-read-only-baseline");
});
test("header failure cancels the response and aborts its request signal", async () => {
  const { collectBaseline } = await module();
  for (const mode of ["oversized", "sink-rejected"]) {
    let cancelled = 0,
      requestSignal;
    const result = await collectBaseline(
      options({
        persist: async (row) => {
          if (mode === "sink-rejected" && row.state === "response-headers")
            throw new Error("sink failure");
        },
        send: async (request) => {
          requestSignal = request.signal;
          return new Response(
            new ReadableStream({
              cancel() {
                cancelled++;
              },
            }),
            {
              headers: mode === "oversized" ? { oversized: "x".repeat(16385) } : {},
            },
          );
        },
      }),
    );
    assert.equal(result.outcome, "incomplete-read-only-baseline");
    assert.equal(result.unknown, 1);
    assert.equal(cancelled, 1);
    assert.equal(requestSignal.aborted, true);
  }
});
