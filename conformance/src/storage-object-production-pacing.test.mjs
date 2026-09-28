import assert from "node:assert/strict";
import test from "node:test";

const module = await import("./storage-object/production-pacing.mjs").catch((error) => {
  if (error.code !== "ERR_MODULE_NOT_FOUND") throw error;
  return {};
});

const prefix = "storage-object/run/pacing/recording-1/";
const name = `${prefix}object`;
function fixture(overrides = {}) {
  assert.equal(typeof module.createObjectMutationPacer, "function", "mutation pacer is missing");
  let time = 0;
  const waits = [];
  const pacer = module.createObjectMutationPacer({
    ownedPrefixes: [prefix],
    now: () => time,
    sleep: async (milliseconds) => {
      waits.push(milliseconds);
      time += milliseconds;
    },
    ...overrides,
  });
  return { pacer, waits, now: () => time, setTime: (value) => (time = value) };
}

test("same-object attempts are separated by at least one second at the dispatch boundary", async () => {
  const f = fixture();
  const dispatched = [];
  const attempt = () => dispatched.push(f.now());
  await f.pacer.dispatch(name, attempt);
  f.setTime(999.999);
  await f.pacer.dispatch(name, attempt);
  assert.deepEqual(f.waits, [1]);
  assert.ok(dispatched[1] - dispatched[0] >= 1000);
});

test("exactly one second admits without a delay", async () => {
  const f = fixture();
  await f.pacer.dispatch(name, () => {});
  f.setTime(1000);
  await f.pacer.dispatch(name, () => {});
  assert.deepEqual(f.waits, []);
});

test("different owned objects do not inherit each other's interval", async () => {
  const f = fixture();
  await f.pacer.dispatch(name, () => {});
  await f.pacer.dispatch(`${prefix}other`, () => {});
  assert.deepEqual(f.waits, []);
});

test("an uncertain or rejected attempt still consumes its interval without automatic retry", async () => {
  const f = fixture();
  let calls = 0;
  await assert.rejects(
    f.pacer.dispatch(name, () => {
      calls++;
      throw new Error("uncertain dispatch");
    }),
    /uncertain dispatch/,
  );
  assert.equal(calls, 1);
  await f.pacer.dispatch(name, () => calls++);
  assert.equal(calls, 2);
  assert.deepEqual(f.waits, [1000]);
});

test("time spent admitting and dispatching an attempt cannot shorten the next interval", async () => {
  const f = fixture();
  const dispatched = [];
  await f.pacer.dispatch(name, () => {
    f.setTime(5000);
    dispatched.push(f.now());
  });
  await f.pacer.dispatch(name, () => dispatched.push(f.now()));
  assert.ok(dispatched[1] - dispatched[0] >= 1000);
});

test("an outside name and invalid callback reject before any dispatch", async () => {
  const f = fixture();
  let calls = 0;
  for (const outside of ["storage-object/run/other/object", prefix, "", null])
    await assert.rejects(
      f.pacer.dispatch(outside, () => calls++),
      /owned object/,
    );
  await assert.rejects(f.pacer.dispatch(name, null), /dispatch callback/);
  assert.equal(calls, 0);
  assert.deepEqual(f.waits, []);
});

test("concurrent dispatch cannot bypass an active attempt", async () => {
  const f = fixture();
  let release;
  const pending = f.pacer.dispatch(name, () => new Promise((resolve) => (release = resolve)));
  await assert.rejects(
    f.pacer.dispatch(`${prefix}other`, () => {}),
    /active/,
  );
  release("finished");
  assert.equal(await pending, "finished");
  await f.pacer.dispatch(`${prefix}other`, () => {});
});

test("a backward or nonfinite clock stops before dispatch", async () => {
  const f = fixture();
  let calls = 0;
  f.setTime(1);
  await f.pacer.dispatch(name, () => calls++);
  for (const value of [0, NaN, Infinity]) {
    f.setTime(value);
    await assert.rejects(
      f.pacer.dispatch(`${prefix}other`, () => calls++),
      /monotonic clock/,
    );
  }
  assert.equal(calls, 1);
});

test("early wakeups are rechecked and a frozen clock rejects after bounded waits", async () => {
  let time = 0;
  const waits = [];
  const f = fixture({ now: () => time, sleep: async (duration) => waits.push(duration) });
  let calls = 0;
  await f.pacer.dispatch(name, () => calls++);
  time = 500;
  await assert.rejects(
    f.pacer.dispatch(name, () => calls++),
    /interval not reached/,
  );
  assert.deepEqual(waits, [500, 500]);
  assert.equal(calls, 1);
  time = 1000;
  await f.pacer.dispatch(name, () => calls++);
  assert.equal(calls, 2);
});

test("invalid configuration and mutable caller prefixes cannot expand ownership", async () => {
  const f = fixture();
  assert.ok(f.pacer);
  const config = { ownedPrefixes: [prefix], now: () => 0, sleep: async () => {} };
  const pacer = module.createObjectMutationPacer(config);
  config.ownedPrefixes.push("outside/");
  await assert.rejects(
    pacer.dispatch("outside/object", () => {}),
    /owned object/,
  );
  for (const invalid of [[], [""], ["no-slash"], [prefix, `${prefix}nested/`], [prefix, prefix]])
    assert.throws(
      () => module.createObjectMutationPacer({ ...config, ownedPrefixes: invalid }),
      /pacing configuration/,
    );
});
