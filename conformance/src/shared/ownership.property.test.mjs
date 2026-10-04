// A generated test of the ownership library: random scripts of creates, deletes and reads against a
// simulated world, with answers of every class, effects that do or do not match the answer, and
// noise (foreign resources, foreign deletes, lost requests, crashes between a request and its
// answer, torn ledger tails). The seed is fixed, so a failure names the case that reproduces it.

import assert from "node:assert/strict";
import * as fs from "node:fs";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";

import {
  beginCreate,
  beginDelete,
  closeOwnership,
  closureReport,
  mayDelete,
  openOwnership,
  OwnershipError,
  recordAnswer,
  recordRead,
  unsettledNames,
} from "./ownership.mjs";

const BASE_SEED = 0x5eed_0835;
const CASES = 600;
const NAMES = ["n0", "n1", "n2", "n3"];
const NOW = () => 1_788_000_000_000;

/** mulberry32: a small deterministic generator. */
function prng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
  return {
    next,
    int: (n) => Math.floor(next() * n),
    pick: (list) => list[Math.floor(next() * list.length)],
    chance: (p) => next() < p,
  };
}

// ---- the answers a server or a network can give ----

const UNKNOWN_ANSWERS = [
  { transportError: true },
  { status: 500, bodyReadable: true },
  { status: 502, bodyReadable: true },
  { status: 503, bodyReadable: true },
  { status: 504, bodyReadable: true },
  { status: 302, bodyReadable: true },
  { status: 301, bodyReadable: true },
  { status: 199, bodyReadable: true },
  { status: 100, bodyReadable: true },
  { status: 200, bodyReadable: false },
  { status: 204, bodyReadable: false },
  { status: 404, bodyReadable: false },
  { status: 409, bodyReadable: false },
  { status: 200, bodyReadable: true, operationPending: true },
];
const REFUSALS = [
  { status: 400, bodyReadable: true },
  { status: 403, bodyReadable: true },
  { status: 429, bodyReadable: true },
];
const SUCCESSES = [
  { status: 200, bodyReadable: true },
  { status: 201, bodyReadable: true },
  { status: 204, bodyReadable: true },
];
const CONFLICT = { status: 409, bodyReadable: true };
const NOT_FOUND = { status: 404, bodyReadable: true };

// ---- the simulated world ----

function newWorld(rng, collisions) {
  const world = new Map();
  for (const name of NAMES) {
    world.set(name, { exists: rng.chance(0.3), creator: "foreign" });
  }
  return { names: world, collisions };
}

// ---- the reference: an independent fold over the history of each name ----

function reference(history) {
  let owned = false; // a resource of ours exists, as far as the answers say
  let created = false; // this run's own create answered 2xx, or a GET settled it as present
  let pending = null;
  let noResend = false;
  for (const event of history) {
    if (event.kind === "create") {
      if (event.klass === "ok") {
        owned = true;
        created = true;
      } else if (event.klass === "unknown") pending = "create";
    } else if (event.kind === "delete") {
      if (event.klass === "ok" || event.klass === "notFound") owned = false;
      else if (event.klass === "unknown") {
        pending = "delete";
        noResend = true;
      }
    } else if (event.kind === "read" && pending && event.observed !== "unknown") {
      if (pending === "create" && event.observed === "present") {
        owned = true;
        created = true;
      }
      if (pending === "delete" && event.observed === "absent") owned = false;
      pending = null;
    }
  }
  return { owned, created, pending, noResend };
}

function classOf(answer) {
  const { status, bodyReadable, transportError, operationPending } = answer;
  if (transportError || operationPending || bodyReadable !== true) return "unknown";
  if (status < 200) return "unknown";
  if (status < 300) return "ok";
  if (status < 400) return "unknown";
  if (status === 409) return "conflict";
  if (status === 404) return "notFound";
  if (status < 500) return "refused";
  return "unknown";
}

function observedOf(answer) {
  const klass = classOf(answer);
  return klass === "ok" ? "present" : klass === "notFound" ? "absent" : "unknown";
}

// ---- one generated case ----

function spyIo(events, real) {
  return {
    writeSync(fd, buffer, offset, length) {
      events.push("write");
      return fs.writeSync(fd, buffer, offset, length);
    },
    fsyncSync(fd) {
      events.push("fsync");
      // The ordering is what the test checks; the disk flush itself is real in every 20th case.
      if (real) fs.fsyncSync(fd);
    },
  };
}

function lines(path) {
  const text = fs.readFileSync(path, "utf8");
  return text === ""
    ? []
    : text
        .replace(/\n$/u, "")
        .split("\n")
        .map((line) => JSON.parse(line));
}

function runCase(index) {
  const seed = BASE_SEED + index * 7919;
  const rng = prng(seed);
  const collisions = rng.chance(0.25);
  const world = newWorld(rng, collisions);
  const dir = mkdtempSync(join(tmpdir(), "ownership-prop-"));
  const path = join(dir, "ledger.jsonl");
  const events = [];
  const io = spyIo(events, index % 20 === 0);
  const history = new Map(NAMES.map((name) => [name, []]));
  let unknownDeleteSeen = false;
  const where = `case ${index} (seed ${seed}${collisions ? ", collisions" : ""})`;

  let state = openOwnership({ path, runId: "prop", io, now: NOW });
  const reopen = (tear) => {
    closeOwnership(state);
    if (tear) fs.appendFileSync(path, '{"v":1,"runId":"prop","seq":99999,"phase":"intent","na');
    state = openOwnership({ path, runId: "prop", io, now: NOW });
  };
  // What the library must say, from the reference.
  const expectedAllowed = (name) => {
    const r = reference(history.get(name));
    return r.created && !r.pending && !r.noResend;
  };
  const checkDurable = (what, phase) => {
    const rows = lines(path);
    assert.equal(rows.at(-1).phase, phase, `${where}: ${what}: the last durable row is ${phase}`);
  };

  const check = (step) => {
    // Every write is followed by its fsync before the call returns.
    for (let i = 0; i < events.length; i += 2) {
      assert.deepEqual(
        events.slice(i, i + 2),
        ["write", "fsync"],
        `${where}: step ${step}: write then fsync`,
      );
    }
    assert.equal(events.length % 2, 0, where);
    for (const name of NAMES) {
      const r = reference(history.get(name));
      assert.equal(
        mayDelete(state, name).allowed,
        r.created && !r.pending && !r.noResend,
        `${where}: step ${step}: guard for ${name}`,
      );
      assert.equal(
        unsettledNames(state).includes(name),
        r.pending !== null,
        `${where}: step ${step}: unsettled ${name}`,
      );
    }
    const report = closureReport(state);
    const wantReady =
      NAMES.every((name) => {
        const r = reference(history.get(name));
        return !r.owned && !r.pending;
      }) && !unknownDeleteSeen;
    assert.equal(
      report.closureReady,
      wantReady,
      `${where}: step ${step}: closureReady (${report.reasons.join(",")})`,
    );
    if (unknownDeleteSeen)
      assert.equal(
        report.closureReady,
        false,
        `${where}: step ${step}: an unknown delete keeps closure false`,
      );
  };

  const steps = 6 + rng.int(28);
  for (let step = 0; step < steps; step += 1) {
    const name = rng.pick(NAMES);
    const w = world.names.get(name);
    const op = rng.pick(["create", "create", "delete", "delete", "read", "read", "noise", "crash"]);
    if (op === "noise") {
      const noise = rng.pick(["foreignDelete", "foreignCreate", "foreignRecreate"]);
      if (noise === "foreignDelete") w.exists = false;
      else if (collisions && !w.exists) Object.assign(w, { exists: true, creator: "foreign" });
      else if (collisions && noise === "foreignRecreate")
        Object.assign(w, { exists: true, creator: "foreign" });
      check(step);
      continue;
    }
    if (op === "crash") {
      // Die between a request and its answer, or between two requests; then resume.
      const inFlight = rng.chance(0.6);
      if (inFlight) {
        const action = w.exists || rng.chance(0.5) ? "delete" : "create";
        const allowed =
          action === "create" ? !reference(history.get(name)).pending : expectedAllowed(name);
        if (allowed) {
          const ticket =
            action === "create"
              ? beginCreate(state, { name, transport: "rest" })
              : beginDelete(state, { name, transport: "rest" });
          assert.ok(ticket, where);
          checkDurable("crash intent", "intent");
          // The request went out; the effect may or may not have happened.
          if (action === "create" && !w.exists && rng.chance(0.5))
            Object.assign(w, { exists: true, creator: "run" });
          if (action === "delete" && w.exists && rng.chance(0.5)) w.exists = false;
          history.get(name).push({ kind: action, klass: "unknown" });
          if (action === "delete") unknownDeleteSeen = true;
        }
      }
      events.length = 0;
      reopen(rng.chance(0.4));
      events.length = 0;
      check(step);
      continue;
    }
    if (op === "read") {
      const unknown = rng.chance(0.25);
      const answer = unknown
        ? rng.pick(UNKNOWN_ANSWERS)
        : w.exists
          ? rng.pick(SUCCESSES)
          : NOT_FOUND;
      events.length = 0;
      const observed = recordRead(state, { name, transport: "rest", answer });
      checkDurable("read", "read");
      assert.equal(observed, observedOf(answer), where);
      history.get(name).push({ kind: "read", observed });
      events.length = 0;
      check(step);
      continue;
    }
    if (op === "create") {
      const r = reference(history.get(name));
      events.length = 0;
      if (r.pending) {
        assert.throws(
          () => beginCreate(state, { name, transport: "rest" }),
          (e) => e instanceof OwnershipError && e.code === "unsettled",
          where,
        );
        events.length = 0;
        check(step);
        continue;
      }
      const ticket = beginCreate(state, { name, transport: "rest" });
      checkDurable("create intent", "intent");
      // Choose what the server does and what the caller sees.
      let answer;
      if (w.exists) {
        // The name is taken: an honest 409, or the answer is lost (the request had no effect).
        const lost = (collisions || w.creator === "run") && rng.chance(0.3);
        answer = lost
          ? rng.pick(UNKNOWN_ANSWERS)
          : rng.chance(0.85)
            ? CONFLICT
            : rng.pick(REFUSALS);
      } else {
        const applied = rng.chance(0.6);
        if (applied) {
          Object.assign(w, { exists: true, creator: "run" });
          answer = rng.chance(0.7) ? rng.pick(SUCCESSES) : rng.pick(UNKNOWN_ANSWERS);
        } else {
          answer = rng.chance(0.5) ? rng.pick(REFUSALS) : rng.pick(UNKNOWN_ANSWERS);
        }
      }
      const klass = recordAnswer(state, ticket, answer).class;
      checkDurable("create answer", "answer");
      assert.equal(klass, classOf(answer), where);
      history.get(name).push({ kind: "create", klass });
      events.length = 0;
      check(step);
      continue;
    }
    // delete
    events.length = 0;
    if (!expectedAllowed(name)) {
      assert.throws(
        () => beginDelete(state, { name, transport: "rest" }),
        (e) => e instanceof OwnershipError,
        `${where}: step ${step}: delete of ${name} must be refused`,
      );
      events.length = 0;
      check(step);
      continue;
    }
    // The guard allowed it: in a world without collisions the resource at this name is ours, or gone.
    if (!collisions && w.exists) {
      assert.equal(
        w.creator,
        "run",
        `${where}: step ${step}: the guard allowed a delete of a name this run does not own`,
      );
    }
    const ticket = beginDelete(state, { name, transport: "rest" });
    checkDurable("delete intent", "intent");
    let answer;
    if (!w.exists) {
      answer = rng.chance(0.8) ? NOT_FOUND : rng.pick(UNKNOWN_ANSWERS);
    } else {
      const applied = rng.chance(0.65);
      if (applied) {
        w.exists = false;
        answer = rng.chance(0.7) ? rng.pick(SUCCESSES) : rng.pick(UNKNOWN_ANSWERS);
      } else {
        answer = rng.chance(0.5) ? CONFLICT : rng.pick(UNKNOWN_ANSWERS);
      }
    }
    const klass = recordAnswer(state, ticket, answer).class;
    checkDurable("delete answer", "answer");
    assert.equal(klass, classOf(answer), where);
    history.get(name).push({ kind: "delete", klass });
    if (klass === "unknown") unknownDeleteSeen = true;
    events.length = 0;
    check(step);
  }

  // At the end of every case: the rows on disk replay to the same decisions, and one row of the
  // ledger exists for every fsync.
  const before = NAMES.map((name) => [
    mayDelete(state, name),
    unsettledNames(state),
    closureReport(state),
  ]);
  const writes = lines(path).length;
  events.length = 0;
  reopen(false);
  const after = NAMES.map((name) => [
    mayDelete(state, name),
    unsettledNames(state),
    closureReport(state),
  ]);
  assert.deepEqual(after, before, `${where}: a resume changes nothing`);
  assert.ok(lines(path).length >= writes, where);
  closeOwnership(state);
  rmSync(dir, { recursive: true, force: true });
  return { steps, unknownDeleteSeen, collisions };
}

describe("generated scripts against a simulated world", () => {
  it(`holds the three rules in ${CASES} fixed-seed cases`, () => {
    let unknownDeletes = 0;
    let collisionCases = 0;
    let total = 0;
    for (let index = 0; index < CASES; index += 1) {
      const result = runCase(index);
      total += result.steps;
      if (result.unknownDeleteSeen) unknownDeletes += 1;
      if (result.collisions) collisionCases += 1;
    }
    assert.ok(CASES >= 400);
    // The generator reaches the interesting corners; a regression in it would make the test vacuous.
    assert.ok(
      unknownDeletes > CASES / 10,
      `unknown deletes were generated in ${unknownDeletes} cases`,
    );
    assert.ok(
      collisionCases > CASES / 10 && collisionCases < CASES / 2,
      `${collisionCases} collision cases`,
    );
    assert.ok(total > CASES * 6, `${total} steps`);
  });

  it("is deterministic: the same case twice gives the same result", () => {
    assert.deepEqual(runCase(17), runCase(17));
    assert.notDeepEqual(
      [runCase(1), runCase(2), runCase(3), runCase(4)].map((r) => r.steps),
      [0, 0, 0, 0],
    );
  });
});
