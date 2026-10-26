// Shared by the O-6 and O-7 corpus tests: a seeded property loop, program inspection helpers and
// an in-memory stand-in for the sandbox database. Not a test file, and sends no request.

import assert from "node:assert/strict";

import { SANDBOX_PROJECT, createContext } from "./harness.mjs";

export const steps = (program, rpc = "executePipeline") =>
  program.steps.filter((s) => s.rpc === rpc);

/** A small seeded generator, so a failing property reproduces from its seed. */
export function mulberry32(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
export const pick = (random, items) => items[Math.floor(random() * items.length)];
export const between = (random, low, high) => low + Math.floor(random() * (high - low + 1));

/** Runs `check` on `runs` generated inputs; the seed is in the failure message. */
export function forAll(runs, generate, check) {
  for (let seed = 1; seed <= runs; seed += 1) {
    const input = generate(mulberry32(seed));
    try {
      check(input);
    } catch (error) {
      error.message = `seed ${seed}: ${error.message}`;
      throw error;
    }
  }
}

export const production = () =>
  createContext({
    run: "1",
    startedMs: Date.parse("2026-10-26T00:00:00Z"),
    database: "entpipe1",
    target: { kind: "production", token: "t", quotaProject: SANDBOX_PROJECT },
  });

export const parentOf = (path) => path.split("/").slice(0, -1).join("/");
export const relative = (name) => name.replace(/^\{docs\}\//, "");

/** Every collection a program writes: seeds and commit updates. */
export function writtenCollections(program) {
  const names = [
    ...(program.seed ?? []).map(([name]) => name),
    ...steps(program, "commit").flatMap((s) =>
      s.body.writes.filter((w) => w.update).map((w) => relative(w.update.name)),
    ),
  ];
  return new Set(names.map(parentOf));
}

/** An in-memory Firestore: commit, the kindless wipe query and an empty pipeline answer. */
export function fakeFirestore(initial = []) {
  const store = new Map(initial.map((name) => [name, {}]));
  const calls = [];
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    const path = String(url);
    calls.push(path);
    const base = `https://firestore.googleapis.com/v1/projects/${SANDBOX_PROJECT}/databases/entpipe1/documents`;
    assert.ok(path.startsWith(`${base}:`), path);
    const body = init.body ? JSON.parse(init.body) : {};
    if (path.endsWith(":commit")) {
      for (const write of body.writes) {
        if (write.update) store.set(write.update.name, write.update.fields);
        else store.delete(write.delete);
      }
      return new Response(JSON.stringify({ writeResults: body.writes.map(() => ({})) }));
    }
    if (path.endsWith(":runQuery")) {
      const names = [...store.keys()].toSorted().slice(0, body.structuredQuery.limit);
      return new Response(
        JSON.stringify(names.length ? names.map((name) => ({ document: { name } })) : [{}]),
      );
    }
    return new Response(JSON.stringify([{ executionTime: "2026-10-26T00:00:00Z" }]));
  };
  return {
    store,
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

export const stagesOf = (s) => s.body.structuredPipeline.pipeline.stages;
