// Helpers shared by the Secure Token body tests: a context and a session wired to the in-process
// world, and a seeded generator. Not a test file (the selftest glob picks up `*.test.mjs` only).

import { createContext, SANDBOX_PROJECT } from "../auth-account/harness.mjs";
import { openOwnership } from "../shared/ownership.mjs";
import { tempDir } from "../test-tmpdir.mjs";
import { createSession } from "./session.mjs";
import { createWorld } from "./test-world.mjs";

export const NUMBER = "123456789012";

export function localCtx(run = "1794000000") {
  return createContext({
    run,
    project: SANDBOX_PROJECT,
    target: { kind: "local", origin: "http://127.0.0.1:1", projectNumber: NUMBER },
  });
}

/** A session against a fresh world; `world` options pass to `createWorld`. */
export function fakeSession({ world: worldOptions = {}, run, session: sessionOptions = {} } = {}) {
  const ctx = localCtx(run);
  const fake = createWorld({ project: ctx.project, number: NUMBER, ...worldOptions });
  const dir = tempDir("stb-");
  const ownership = openOwnership({ path: `${dir}/issued.jsonl`, runId: `stb-${ctx.run}` });
  const journal = [];
  const session = createSession(ctx, {
    transport: fake.fetch,
    ownership,
    pollMs: 0,
    sleep: async () => {},
    journal: (entry) => journal.push(entry),
    ...sessionOptions,
  });
  return { ctx, session, ownership, ledgerPath: `${dir}/issued.jsonl`, journal, ...fake };
}

/** mulberry32: a small seeded generator; a failing case is reproduced by its seed. */
export function generator(seed) {
  let state = seed >>> 0;
  const next = () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const int = (n) => Math.floor(next() * n);
  const pick = (items) => items[int(items.length)];
  return { next, int, pick, bool: (p = 0.5) => next() < p };
}
