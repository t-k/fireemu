// A model-based check of the session against the in-process world under random faults: whatever
// the sandbox answers (resets, 5xx, answers lost after the effect), the recording never deletes a
// name it did not create, never re-sends a delete, never writes a token, and calls itself
// closure-ready only when the world really is back to where it started.

import assert from "node:assert/strict";
import { test } from "node:test";

import { fakeSession, generator } from "./securetoken-body/test-support.mjs";

const ROUNDS = 60;

/** A fault schedule: each non-refresh request may fail before the effect or lose its answer after. */
function schedule(rng, density) {
  const hit = (req) => req.path !== "v1/token" && rng.next() < density;
  const kind = () => rng.pick(["throw", "503", "408", "garbled"]);
  const answer = (k) =>
    k === "throw"
      ? "throw"
      : k === "garbled"
        ? { status: 200, text: "not json" }
        : { status: Number(k), json: {} };
  return {
    faults: [(req) => (hit(req) ? answer(kind()) : undefined)],
    lateFaults: [(req) => (hit(req) ? answer(kind()) : undefined)],
  };
}

test("property: under random faults the recording stays inside its own names and tells the truth about closure", async () => {
  const seeds = Array.from({ length: ROUNDS }, (_, i) => 0x1000 + i);
  return Promise.all(
    seeds.map(async (seed) => {
      const rng = generator(seed);
      const density = rng.pick([0, 0.02, 0.05, 0.12, 0.3]);
      const tenancy = rng.bool();
      const run = String(1794000000 + seed);
      const { session, world } = fakeSession({
        run,
        world: { tenancy, ...schedule(rng, density) },
        session: { pollLimit: 4 },
      });
      const recording = await session.runRecording();
      const where = `seed ${seed} density ${density} tenancy ${tenancy}`;

      // Only the run's own names are ever deleted, and no delete is sent twice for one name.
      const deletes = world.log.filter(
        (e) => e.method === "DELETE" || e.path.endsWith("accounts:delete"),
      );
      const seen = new Set();
      for (const entry of deletes) {
        const target = entry.method === "DELETE" ? entry.path : JSON.parse(entry.body).localId;
        const ownName =
          entry.method === "DELETE"
            ? entry.path.includes(`/tenants/stb-${run}-`)
            : target.startsWith(`stb-${run}-`);
        assert.ok(ownName, `${where}: deleted ${target}`);
        const key = `${entry.path}|${target}`;
        assert.ok(!seen.has(key), `${where}: second delete of ${target}`);
        seen.add(key);
      }

      // Nothing resolved at send time reaches the record.
      const { secrets, ...publicPart } = recording;
      const text = JSON.stringify(publicPart);
      for (const secret of secrets)
        assert.ok(!text.includes(secret), `${where}: secret in the record`);
      for (const token of world.tokens.keys())
        assert.ok(!text.includes(token), `${where}: token in the record`);

      // closureReady is a claim about the world: nothing of the run left, tenancy as it was.
      if (recording.closureReady) {
        assert.equal(world.accounts.size, 0, where);
        assert.equal(world.tenants.size, 0, where);
        assert.equal(world.tenancy, tenancy, where);
        assert.deepEqual(recording.cleanupErrors, [], where);
      }
      // And the converse for what the run could not delete: it says so.
      if (world.accounts.size + world.tenants.size > 0) {
        assert.equal(recording.closureReady, false, `${where}: left resources but claims closure`);
      }
      // A delete whose answer was unknown is reported, never silently closed.
      if (recording.ownership.unknownDeletes > 0)
        assert.equal(recording.closureReady, false, where);
      // The rows it did record are complete records or an honest transport failure.
      for (const row of Object.values(recording.rows)) {
        assert.ok(typeof row.status === "number", where);
        assert.deepEqual(
          Object.keys(row.request).toSorted(),
          ["bodyBytes", "contentType", "fields"],
          where,
        );
      }
    }),
  );
});

test("property: with no faults every seed gives the same closure-ready recording", async () => {
  for (let seed = 0; seed < 5; seed += 1) {
    const { session, world } = fakeSession({
      run: String(1794100000 + seed),
      world: { tenancy: seed % 2 === 0 },
    });
    const recording = await session.runRecording();
    assert.equal(recording.closureReady, true);
    assert.equal(Object.keys(recording.rows).length, 24);
    assert.equal(world.accounts.size + world.tenants.size, 0);
  }
});
