// Test support: the orchestrator against the in-memory world.
import { record } from "./run.mjs";
import { NUMBER, createWorld } from "./world.mjs";

export const RUN = "0123456789abcdef";

export async function go(
  worldOptions = {},
  options = {},
  wrapSend = (send) => send,
  wrapCli = (runCli) => runCli,
) {
  const world = createWorld({ runId: RUN, ...worldOptions });
  const journal = [];
  const sleeps = [];
  const result = await record({
    runId: RUN,
    projectNumber: NUMBER,
    accessToken: "test-token-abcdefgh",
    save: async (row) => journal.push(row),
    send: wrapSend(world.send, world),
    runCli: wrapCli((o) => world.runCli(o), world),
    clock: () => world.now,
    sleep: async (ms) => {
      sleeps.push(ms);
      world.advance(ms);
    },
    ...options,
  });
  return { world, journal, sleeps, result };
}

export const mutations = (world) =>
  world.calls.filter(
    (c) => !c.startsWith("GET ") && !c.includes("entries:list") && !c.includes("getIamPolicy"),
  );
export const count = (world, prefix) => world.calls.filter((c) => c.startsWith(prefix)).length;
export const emptyWorld = (w) =>
  w.functions.size === 0 &&
  w.runServices.size === 0 &&
  w.queues.size === 0 &&
  w.packages.size === 0;
