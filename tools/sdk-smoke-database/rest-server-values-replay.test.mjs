import test from "node:test";
import assert from "node:assert/strict";
import { maskObservation, compareCase, replayCase } from "./rest-server-values-replay.mjs";

const observed = () => ({
  id: "multipath-one-clock",
  round: "r1",
  preimage: { counter: 7 },
  request: {
    method: "PATCH",
    body: JSON.stringify({
      first: { ".sv": "timestamp" },
      second: { ".sv": "timestamp" },
      counter: { ".sv": { increment: 5 } },
    }),
  },
  before: { status: 200 },
  response: { status: 200 },
  after: { status: 200 },
  value: { first: 100, second: 100, counter: 12 },
  readback: { first: 100, second: 100, counter: 12 },
  sameClock: true,
  responseMatchesReadback: true,
});
test("timestamp masking preserves numeric values and binds one atomic clock across write and read", () => {
  const expected = maskObservation(observed());
  assert.deepEqual(expected.value, { first: "<timestamp>", second: "<timestamp>", counter: 12 });
  const local = observed();
  local.value.first = 200;
  local.value.second = 200;
  local.readback.first = 200;
  local.readback.second = 200;
  assert.equal(compareCase(expected, local).verdict, "MATCH");
  for (const mutate of [
    (x) => {
      x.readback.first = 201;
    },
    (x) => {
      x.value.second = 201;
    },
    (x) => {
      x.value.first = "200";
    },
    (x) => {
      x.value.counter = 13;
    },
    (x) => {
      x.response.status = 500;
    },
    (x) => {
      x.request.body = "{}";
    },
  ]) {
    const bad = structuredClone(local);
    mutate(bad);
    assert.notEqual(compareCase(expected, bad).verdict, "MATCH");
  }
});
test("extractor rejects false relation and untyped timestamps", () => {
  const bad = observed();
  bad.value.first = "100";
  assert.throws(() => maskObservation(bad));
  const bad2 = observed();
  bad2.readback.first = 99;
  assert.throws(() => maskObservation(bad2));
});
test("transport errors cannot be marked match", async () => {
  await assert.rejects(
    replayCase(
      maskObservation(observed()),
      async () => {
        throw Error("unknown");
      },
      "ownedroot",
    ),
  );
});

test("recorded fixture is complete and contains no absolute production identifiers", async () => {
  const { readFile } = await import("node:fs/promises");
  const text = await readFile(
    new URL("./fixtures/production-rest-server-values.json", import.meta.url),
    "utf8",
  );
  const fixture = JSON.parse(text);
  assert.equal(fixture.rows.length, 10);
  assert.equal(new Set(fixture.rows.map((r) => `${r.round}/${r.id}`)).size, 10);
  assert.doesNotMatch(text, /rnext1_|firebaseio\.com|Bearer |ya29\./);
});

test("local replay uses manual redirects and restores Rules after all ten typed observations", async () => {
  const { readFile } = await import("node:fs/promises");
  const { replay } = await import("./rest-server-values-replay.mjs");
  const fixture = JSON.parse(
    await readFile(
      new URL("./fixtures/production-rest-server-values.json", import.meta.url),
      "utf8",
    ),
  );
  const store = new Map(),
    calls = [];
  let rules = '{"rules":{".read":false}}';
  const fake = async (input, options) => {
    const u = new URL(input);
    calls.push({ path: u.pathname, method: options.method ?? "GET", redirect: options.redirect });
    let value = null;
    if (u.pathname === "/.settings/rules.json") {
      if (options.method === "PUT") rules = options.body;
      return new Response(rules, { status: 200 });
    }
    if (options.method === "DELETE") {
      store.clear();
      return new Response("null", { status: 200 });
    }
    if (options.method === "PUT") {
      const body = JSON.parse(options.body);
      if (body && body[".sv"])
        value =
          body[".sv"] === "timestamp"
            ? 123456
            : (typeof store.get(u.pathname) === "number" ? store.get(u.pathname) : 0) +
              body[".sv"].increment;
      else value = body;
      store.set(u.pathname, value);
    } else if (options.method === "PATCH") {
      value = { first: 123457, second: 123457, counter: 12 };
      store.set(u.pathname, value);
    } else value = store.get(u.pathname) ?? null;
    return new Response(JSON.stringify(value), { status: 200 });
  };
  const result = await replay("http://127.0.0.1:12345", fixture, { fetchImpl: fake });
  assert.equal(result.rows.length, 10);
  assert.ok(result.rows.every((row) => row.result.verdict === "MATCH"));
  assert.deepEqual(result.cleanup, { ownedRootAbsent: true, rulesRestored: true });
  assert.equal(rules, '{"rules":{".read":false}}');
  assert.ok(calls.every((x) => x.redirect === "manual"));
  assert.equal(calls.filter((x) => x.method === "DELETE").length, 1);
});

test("failed Rules setup restores baseline and cleanup failure is not success", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  let rules = "old",
    deleteCount = 0;
  const fixture = { schemaVersion: 1, rows: Array(10).fill({}) };
  const fake = async (input, options) => {
    const u = new URL(input);
    if (u.pathname === "/.settings/rules.json") {
      if (options.method === "PUT") {
        if (options.body !== "old") {
          rules = options.body;
          return new Response("", { status: 403 });
        }
        rules = options.body;
      }
      return new Response(rules, { status: 200 });
    }
    if (options.method === "DELETE") deleteCount++;
    return new Response("null", { status: 200 });
  };
  await assert.rejects(
    replay("http://127.0.0.1:12345", fixture, { fetchImpl: fake }),
    /rules setup unresolved/,
  );
  assert.equal(rules, "old");
  assert.equal(deleteCount, 1);
  const bad = async (input, options) => {
    const u = new URL(input);
    if (u.pathname === "/.settings/rules.json")
      return options.method === "PUT" && options.body !== "old"
        ? new Response("", { status: 403 })
        : new Response("old", { status: 200 });
    return new Response("", { status: 500 });
  };
  await assert.rejects(replay("http://127.0.0.1:12345", fixture, { fetchImpl: bad }), /unknown/);
});

test("each generated case, round and profile comparison is exercised", async () => {
  const { readFile } = await import("node:fs/promises");
  const fixture = JSON.parse(
    await readFile(
      new URL("./fixtures/production-rest-server-values.json", import.meta.url),
      "utf8",
    ),
  );
  const lines = (
    await readFile(new URL("./fixtures/rest-server-values.generated.tsv", import.meta.url), "utf8")
  )
    .trim()
    .split("\n")
    .slice(1);
  assert.equal(lines.length, 20);
  for (const line of lines) {
    const [id, round, profile] = line.split("\t"),
      row = fixture.rows.find((x) => x.id === id && x.round === round);
    assert.ok(["strict", "ordinary"].includes(profile));
    const local = structuredClone(row);
    if (id === "timestamp-single") local.value = local.readback = 42;
    if (id === "multipath-one-clock") {
      local.value.first = local.value.second = 42;
      local.readback.first = local.readback.second = 42;
    }
    assert.equal(compareCase(row, local).verdict, "MATCH", line);
  }
});

test("timestamp relation is independent of clock value while one changed leaf fails", () => {
  const expected = maskObservation(observed());
  for (let time = -100; time <= 100; time++) {
    const row = observed();
    row.value.first = row.value.second = row.readback.first = row.readback.second = time;
    assert.equal(compareCase(expected, row).verdict, "MATCH");
    row.readback.second = time + 1;
    assert.notEqual(compareCase(expected, row).verdict, "MATCH");
  }
});

test("remote origins and redirected baseline are refused", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  await assert.rejects(
    replay("https://example.invalid", { schemaVersion: 1, rows: [] }),
    /local origin/,
  );
  let calls = 0;
  await assert.rejects(
    replay(
      "http://127.0.0.1:12345",
      { schemaVersion: 1, rows: Array(10).fill({}) },
      {
        fetchImpl: async (_url, options) => {
          calls++;
          assert.equal(options.redirect, "manual");
          return new Response("", { status: 302 });
        },
      },
    ),
    /unknown/,
  );
  assert.equal(calls, 1);
});

test("both timestamps must match even when the entire write and readback agree", () => {
  const row = observed();
  row.value.second = 101;
  row.readback.second = 101;
  assert.throws(() => maskObservation(row), /timestamp relation/);
});

test("single timestamp must be an integer even when write and readback agree", () => {
  const row = { ...observed(), id: "timestamp-single", value: "100", readback: "100" };
  assert.throws(() => maskObservation(row), /timestamp type/);
});

test("failed root deletion cannot be hidden by a null cleanup read", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  let rules = "old";
  const fake = async (input, options) => {
    const u = new URL(input);
    if (u.pathname === "/.settings/rules.json") {
      if (options.method === "PUT") {
        if (options.body !== "old") {
          rules = options.body;
          return new Response("", { status: 403 });
        }
        rules = options.body;
      }
      return new Response(rules, { status: 200 });
    }
    if (options.method === "DELETE") return new Response("", { status: 403 });
    return new Response("null", { status: 200 });
  };
  await assert.rejects(
    replay(
      "http://127.0.0.1:12345",
      { schemaVersion: 1, rows: Array(10).fill({}) },
      { fetchImpl: fake },
    ),
    /cleanup unresolved/,
  );
  assert.equal(rules, "old");
});

test("unknown write or interrupted response prevents any subsequent cleanup request", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  const { readFile } = await import("node:fs/promises");
  const fixture = JSON.parse(
    await readFile(
      new URL("./fixtures/production-rest-server-values.json", import.meta.url),
      "utf8",
    ),
  );
  for (const fault of ["reject", "body"]) {
    let n = 0;
    const calls = [];
    const fake = async (input, options) => {
      const path = new URL(input).pathname;
      calls.push({ path, method: options.method ?? "GET" });
      if (path === "/.settings/rules.json")
        return new Response(options.method === "PUT" ? "{}" : "old", { status: 200 });
      if (++n === 1) return new Response("null", { status: 200 });
      if (n === 2) {
        if (fault === "reject") throw Error("timeout");
        return {
          status: 200,
          headers: new Headers(),
          text: async () => {
            throw Error("body interrupted");
          },
        };
      }
      throw Error("later request");
    };
    await assert.rejects(replay("http://127.0.0.1:12345", fixture, { fetchImpl: fake }), /unknown/);
    assert.equal(calls.length, 4);
  }
});

test("unknown root DELETE prevents later cleanup reads and Rules restoration", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  let calls = [];
  const fake = async (input, options) => {
    const path = new URL(input).pathname;
    calls.push({ path, method: options.method ?? "GET" });
    if (path === "/.settings/rules.json") {
      if (options.method === "PUT" && options.body !== "old")
        return new Response("", { status: 403 });
      return new Response("old", { status: 200 });
    }
    if (options.method === "DELETE") throw Error("timeout");
    throw Error("later request");
  };
  await assert.rejects(
    replay(
      "http://127.0.0.1:12345",
      { schemaVersion: 1, rows: Array(10).fill({}) },
      { fetchImpl: fake },
    ),
    /unknown/,
  );
  assert.equal(calls.length, 3);
});

test("unreadable JSON after a dispatched write is unknown and stops cleanup", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  const { readFile } = await import("node:fs/promises");
  const fixture = JSON.parse(
    await readFile(
      new URL("./fixtures/production-rest-server-values.json", import.meta.url),
      "utf8",
    ),
  );
  let calls = 0;
  const fake = async (input, options) => {
    calls++;
    const path = new URL(input).pathname;
    if (path === "/.settings/rules.json")
      return new Response(options.method === "PUT" ? "{}" : "old", { status: 200 });
    return new Response("invalid json", { status: 200 });
  };
  await assert.rejects(replay("http://127.0.0.1:12345", fixture, { fetchImpl: fake }), /unknown/);
  assert.equal(calls, 3);
});

test("unknown error retains owned scope for recovery without exposing request values", async () => {
  const { replay } = await import("./rest-server-values-replay.mjs");
  const fake = async (input, options) => {
    const path = new URL(input).pathname;
    if (path === "/.settings/rules.json")
      return new Response(options.method === "PUT" ? "{}" : "old", { status: 200 });
    throw Error("timeout");
  };
  let error;
  try {
    await replay(
      "http://127.0.0.1:12345",
      {
        schemaVersion: 1,
        rows: Array(10).fill({
          id: "timestamp-single",
          round: "r1",
          preimage: null,
          request: { method: "PUT", body: "{}" },
        }),
      },
      { fetchImpl: fake },
    );
  } catch (e) {
    error = e;
  }
  assert.match(error.message, /unknown/);
  assert.match(error.ownedRoot, /^svreplay[a-f0-9]{16}$/);
});
