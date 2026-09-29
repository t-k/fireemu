import assert from "node:assert/strict";
import test from "node:test";
import { plain } from "./storage-rules/shape.mjs";

test("only an ordinary object literal is plain", () => {
  class Box { constructor() { this.a = 1; } }
  for (const value of [{}, { a: 1 }, { a: { b: 2 } }, JSON.parse('{"x":1}')]) assert.equal(plain(value), true);
  for (const value of [null, undefined, 0, "x", true, [], [1], new Box(), Object.create(null), Object.create({}), new Map(), new Date(), () => 1, Buffer.alloc(1), new Proxy([], {})]) assert.equal(plain(value), false, typeof value);
});
