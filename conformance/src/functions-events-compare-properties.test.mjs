// Property-based tests for the comparator's pure normalizer and diff. No property library is a
// dependency, so frames come from a small deterministic PRNG; every failure names its seed and case.
import assert from "node:assert/strict";
import { test } from "node:test";
import { compareObservation, deriveVolatile } from "./functions-events/compare/diff.mjs";
import {
  applyPlaceholders,
  flatten,
  formatOf,
  placeholderTable,
  PRODUCTION_ONLY_PATHS,
  splitProductionOnly,
} from "./functions-events/compare/normalize.mjs";

const CASES = 200;
const SEED = 0x5eed_2026;

function mulberry32(seed) {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const pick = (random, items) => items[Math.floor(random() * items.length)];
const int = (random, max) => Math.floor(random() * max);
const chars = (random, alphabet, length) =>
  Array.from({ length }, () => pick(random, alphabet)).join("");
const HEX = "0123456789abcdef";
const DIGITS = "0123456789";

function randomId(random) {
  return `e${chars(random, HEX, 8 + int(random, 8))}`;
}

function randomString(random, ids) {
  switch (int(random, 7)) {
    case 0:
      return `2026-${chars(random, DIGITS, 2)}-${chars(random, DIGITS, 2)}T${chars(random, DIGITS, 2)}:${chars(random, DIGITS, 2)}:${chars(random, DIGITS, 2)}.${chars(random, DIGITS, 1 + int(random, 9))}Z`;
    case 1:
      return chars(random, DIGITS, 1 + int(random, 17));
    case 2:
      return `${chars(random, HEX, 8)}-${chars(random, HEX, 4)}-${chars(random, HEX, 4)}-${chars(random, HEX, 4)}-${chars(random, HEX, 12)}`;
    case 3:
      return `projects/${pick(random, ids)}/x/${pick(random, ids)}`;
    case 4:
      return pick(random, ids);
    default:
      return chars(random, "abcXYZ/=+-_ .", int(random, 12));
  }
}

function randomValue(random, ids, depth) {
  const choice = int(random, depth > 3 ? 5 : 8);
  if (choice === 0) return null;
  if (choice === 1) return random() < 0.5;
  if (choice === 2) return random() < 0.5 ? int(random, 1e6) : int(random, 1e6) + 0.25;
  if (choice <= 4) return randomString(random, ids);
  if (choice === 5) {
    return Array.from({ length: int(random, 4) }, () => randomValue(random, ids, depth + 1));
  }
  const out = {};
  for (let i = int(random, 5); i > 0; i -= 1) {
    const key = random() < 0.2 ? pick(random, ids) : chars(random, "abcdefg_.", 1 + int(random, 4));
    out[key] = randomValue(random, ids, depth + 1);
  }
  return out;
}

function randomFrame(random) {
  const ids = [randomId(random), randomId(random), randomId(random)];
  const matchKey = { kind: "firestore", value: `fe_events_primary/${ids[0]}` };
  const frame = {
    handler: "fsCreatedV2",
    generation: 2,
    source: "firestore",
    event: { id: randomString(random, ids), data: randomValue(random, ids, 0) },
  };
  if (random() < 0.5) frame.event.eventKeys = ["data", "id"];
  if (random() < 0.5)
    frame.event.extensionAttributes = {
      traceparent: "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
    };
  if (random() < 0.3) frame.event.context = { contextKeys: ["eventId"], contextExtras: {} };
  return { frame, table: placeholderTable({ matchKey, project: ids[1] }) };
}

/** Change a primitive's value but keep every format feature (kind, length, precision, zone). */
function sameFormatVariant(random, value) {
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") {
    return Number.isInteger(value) ? value + 1 + int(random, 9) : value + 1 + int(random, 9);
  }
  if (typeof value !== "string") return value;
  const swap = (ch) => {
    if (/[0-9]/.test(ch)) return pick(random, DIGITS);
    if (/[a-f]/.test(ch)) return pick(random, "abcdef");
    if (/[A-Za-z]/.test(ch)) return pick(random, "ghijkXYZ");
    return ch;
  };
  return [...value].map(swap).join("");
}

function varyPaths(random, value, chosen, path = "$") {
  if (Array.isArray(value))
    return value.map((child, i) => varyPaths(random, child, chosen, `${path}[${i}]`));
  if (value !== null && typeof value === "object") {
    const out = {};
    for (const [key, child] of Object.entries(value)) {
      const next = /^[A-Za-z_][A-Za-z0-9_]*$/.test(key)
        ? `${path}.${key}`
        : `${path}[${JSON.stringify(key)}]`;
      out[key] = varyPaths(random, child, chosen, next);
    }
    return out;
  }
  return chosen.has(path) ? sameFormatVariant(random, value) : value;
}

function primitivePaths(leaves) {
  return [...leaves]
    .filter(([, leaf]) => leaf.type !== "object" && leaf.type !== "array")
    .map(([path]) => path);
}

function forEachCase(name, body) {
  const random = mulberry32(SEED ^ [...name].reduce((sum, ch) => sum + ch.charCodeAt(0), 0));
  for (let index = 0; index < CASES; index += 1) {
    try {
      body(random, index);
    } catch (error) {
      error.message = `${name}: case ${index} (seed ${SEED}): ${error.message}`;
      throw error;
    }
  }
}

test("property: placeholder replacement is idempotent", () => {
  forEachCase("idempotent", (random) => {
    const { frame, table } = randomFrame(random);
    const once = applyPlaceholders(frame, table);
    assert.deepEqual(applyPlaceholders(once, table), once);
  });
});

test("property: placeholder replacement never hides, adds or retypes a field", () => {
  forEachCase("presence", (random) => {
    const { frame, table } = randomFrame(random);
    const before = [...flatten(frame).values()].map((leaf) => leaf.type);
    const after = [...flatten(applyPlaceholders(frame, table)).values()].map((leaf) => leaf.type);
    assert.deepEqual(after, before);
  });
});

test("property: splitting the listing removes listing subtrees and retains masked Gen2 traceparents", () => {
  const listingRoots = PRODUCTION_ONLY_PATHS.map((segments) => `$.${segments.join(".")}`);
  const underListing = (path) =>
    listingRoots.some(
      (root) => path === root || path.startsWith(`${root}.`) || path.startsWith(`${root}[`),
    );
  forEachCase("listing", (random) => {
    const { frame } = randomFrame(random);
    const all = [...flatten(frame).keys()];
    const kept = [...flatten(splitProductionOnly(frame).frame).keys()];
    assert.deepEqual(kept, [
      ...all.filter((path) => !underListing(path)),
      ...(frame.event.extensionAttributes ? ["$.event.traceparent"] : []),
    ]);
  });
});

test("property: an observation agrees with itself and derives no volatile path from itself", () => {
  forEachCase("self", (random) => {
    const leaves = flatten(randomFrame(random).frame);
    const { disagreements, volatile } = deriveVolatile(leaves, leaves);
    assert.deepEqual(disagreements, []);
    assert.equal(volatile.size, 0);
    assert.deepEqual(compareObservation(leaves, volatile, leaves, "emulator"), []);
  });
});

test("property: MATCH and DIFF are symmetric between the two sides", () => {
  forEachCase("symmetry", (random) => {
    const a = randomFrame(random).frame;
    const b = random() < 0.5 ? randomFrame(random).frame : structuredClone(a);
    if (random() < 0.5) b.event.extra = random() < 0.5 ? 1 : "x";
    const la = flatten(a);
    const lb = flatten(b);
    const volatile = deriveVolatile(
      la,
      flatten(varyPaths(random, a, new Set(primitivePaths(la).filter(() => random() < 0.3)))),
    ).volatile;
    const forward = compareObservation(la, volatile, lb, "x");
    const backward = compareObservation(lb, volatile, la, "x");
    assert.equal(forward.length === 0, backward.length === 0);
    const mirror = (reason) =>
      reason
        .replace(/ \(.*\)$/, "")
        .replace("missing-field", "extra-field#")
        .replace(/^x: extra-field /, "x: missing-field ")
        .replace("extra-field#", "extra-field");
    assert.deepEqual(
      new Set(forward.map(mirror)),
      new Set(backward.map((reason) => reason.replace(/ \(.*\)$/, ""))),
    );
  });
});

test("property: a same-format variation of the volatile paths only is a MATCH", () => {
  forEachCase("volatile-match", (random) => {
    const pass1 = randomFrame(random).frame;
    const leaves = flatten(pass1);
    const chosen = new Set(primitivePaths(leaves).filter(() => random() < 0.5));
    const pass2 = varyPaths(random, pass1, chosen);
    const { disagreements, volatile } = deriveVolatile(leaves, flatten(pass2));
    assert.deepEqual(disagreements, []);
    for (const path of volatile.keys()) assert.ok(chosen.has(path), `${path} was not varied`);
    const local = varyPaths(random, pass1, new Set(volatile.keys()));
    assert.deepEqual(compareObservation(leaves, volatile, flatten(local), "emulator"), []);
  });
});

test("property: masking a volatile value never hides a missing field or a changed format", () => {
  forEachCase("never-hide", (random) => {
    const pass1 = randomFrame(random).frame;
    const leaves = flatten(pass1);
    const primitives = primitivePaths(leaves);
    const { volatile } = deriveVolatile(
      leaves,
      flatten(varyPaths(random, pass1, new Set(primitives))),
    );
    const removed = new Map(leaves);
    const victim = pick(
      random,
      [...leaves.keys()].filter((path) => path !== "$"),
    );
    if (!victim) return;
    for (const path of removed.keys()) {
      if (path === victim || path.startsWith(`${victim}.`) || path.startsWith(`${victim}[`))
        removed.delete(path);
    }
    const reasons = compareObservation(leaves, volatile, removed, "emulator");
    assert.ok(reasons.includes(`emulator: missing-field ${victim}`), `${victim} hidden`);

    const strings = primitives.filter(
      (path) => leaves.get(path).type === "string" && volatile.has(path),
    );
    if (strings.length === 0) return;
    const target = pick(random, strings);
    const longer = new Map(leaves);
    longer.set(target, { type: "string", value: `${leaves.get(target).value}9` });
    const features = volatile.get(target);
    const lengthStable = !features.has("length") && !features.has("kind");
    const changed = compareObservation(leaves, volatile, longer, "emulator");
    if (
      lengthStable &&
      formatOf(`${leaves.get(target).value}9`).kind === formatOf(leaves.get(target).value).kind
    ) {
      assert.ok(
        changed.some((reason) => reason.startsWith(`emulator: format ${target} length`)),
        `${target} length hidden`,
      );
    } else {
      assert.ok(changed.length > 0 || features.has("length") || features.has("kind"));
    }
  });
});
