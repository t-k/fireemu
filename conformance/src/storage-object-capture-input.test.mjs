import assert from "node:assert/strict";
import test from "node:test";
import {
  copyProductionCaptureArray,
  copyProductionCaptureBody,
  copyProductionCaptureRecord,
} from "./storage-object/production-capture-input.mjs";
import { MAX_RESPONSE_BODY_BYTES } from "./storage-object/wire-limits.mjs";

test("input snapshots preserve the exact body boundary and reject the next original byte", () => {
  const body = Buffer.alloc(MAX_RESPONSE_BODY_BYTES, 127),
    copy = copyProductionCaptureBody(body);
  assert.deepEqual(copy, body);
  body[0] = 0;
  assert.equal(copy[0], 127);
  assert.throws(
    () => copyProductionCaptureBody(Buffer.alloc(MAX_RESPONSE_BODY_BYTES + 1)),
    /invalid capture input/,
  );
});
test("input snapshots ignore Buffer hooks and reject Proxy or foreign Buffer prototypes before access", () => {
  let hooks = 0;
  const body = Buffer.from([0, 1, 255]);
  for (const key of ["length", "byteLength", "valueOf", "toString"])
    Object.defineProperty(body, key, {
      get() {
        hooks++;
        throw new Error();
      },
    });
  assert.deepEqual(copyProductionCaptureBody(body), Buffer.from([0, 1, 255]));
  assert.throws(
    () =>
      copyProductionCaptureBody(
        new Proxy(body, {
          get() {
            hooks++;
            throw new Error();
          },
        }),
      ),
    /invalid capture input/,
  );
  assert.throws(
    () => copyProductionCaptureBody(new Uint8Array([0, 1, 255])),
    /invalid capture input/,
  );
  assert.equal(hooks, 0);
});
test("array snapshots require finite numeric bounds and dense original data descriptors", () => {
  let hooks = 0;
  const hook = {
    valueOf() {
      hooks++;
      return 10;
    },
  };
  for (const maximum of [undefined, Infinity, NaN, -1, 1.5, hook])
    assert.throws(() => copyProductionCaptureArray([1], maximum), /invalid capture input/);
  assert.deepEqual(copyProductionCaptureArray([1, 2], 2), [1, 2]);
  assert.deepEqual(copyProductionCaptureArray([], 0), []);
  assert.throws(() => copyProductionCaptureArray([1, 2, 3], 2), /invalid capture input/);
  const getter = Object.defineProperty([1], "0", {
    get() {
      hooks++;
      return 1;
    },
    enumerable: true,
  });
  const hole = [];
  hole.length = 1;
  for (const value of [
    getter,
    hole,
    new Proxy([1], {
      get() {
        hooks++;
        throw new Error();
      },
    }),
    Object.assign([1], { unknown: 2 }),
  ])
    assert.throws(() => copyProductionCaptureArray(value, 2), /invalid capture input/);
  assert.equal(hooks, 0);
});
test("record snapshots reject schema hooks and unknown, inherited or accessor fields", () => {
  let hooks = 0;
  const getter = Object.defineProperty({}, "safe", {
    enumerable: true,
    get() {
      hooks++;
      throw new Error();
    },
  });
  for (const value of [
    getter,
    { safe: 1, unknown: 2 },
    Object.create({ safe: 1 }),
    new Proxy(
      { safe: 1 },
      {
        ownKeys() {
          hooks++;
          throw new Error();
        },
      },
    ),
  ])
    assert.throws(() => copyProductionCaptureRecord(value, ["safe"]), /invalid capture input/);
  for (const keys of [
    undefined,
    new Proxy(["safe"], {
      get() {
        hooks++;
        throw new Error();
      },
    }),
    ["safe", "safe"],
    [{}],
  ])
    assert.throws(() => copyProductionCaptureRecord({ safe: 1 }, keys), /invalid capture input/);
  assert.deepEqual(copyProductionCaptureRecord({ safe: 1 }, ["safe"]), { safe: 1 });
  assert.equal(hooks, 0);
});
