// Runs the two local scenarios under both profiles and prints (and writes) the comparison with the second delivery
// recording. Loopback only; needs a fireemu binary (build it with RUSTC_WRAPPER= so that no compiler cache is
// involved), a Node 22 binary and a node_modules holding firebase-functions 7.3.2.
//
//   node run-compare.mjs --fireemu <bin> --node <node22> --deps <node_modules> [--out <file>] [--production <digest>]
//                        [--also <digest>,...]
//
// `--production` names the recording's public digest (default `production-run2.json`; `production-run3.json` is the
// third delivery recording, which also holds the messages pulled from the Gen1 topics: the comparison then puts a pull
// subscription on each Gen1 function's topic in the local run and adds the published-message rows). `--also` names
// further recordings (comma-separated) whose extra REST jobs' retry chains join the retry rows (`production-run4.json`:
// the doubling chains of run `ecef353d18975246`, which ran another fixture).
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { compareProfiles, loadDigest } from "./compare.mjs";
import { INFLIGHT_RUN, logicalSlowHandler } from "./inflight.mjs";
import { runLocal } from "./local-run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(
  process.argv
    .slice(2)
    .flatMap((a, i, all) => (a.startsWith("--") ? [[a.slice(2), all[i + 1]]] : [])),
);
for (const key of ["fireemu", "node", "deps"])
  if (!args[key]) throw new Error(`--${key} is required`);

const production = loadDigest(join(here, args.production ?? "production-run2.json"));
// The Gen1 functions' topics in the recording (the jobs' ids): the local run subscribes to the same ones.
const pullTopics = [...new Set((production.published ?? []).map((m) => m.function))]
  .toSorted()
  .map((fn) => `firebase-schedule-${fn}-us-central1`);
// The recorded fixture's slow handler sleeps 100 real seconds, which would stall a logical clock; the copy sleeps 100 ms.
const patch = (source, { clockFile }) =>
  source
    .replace("setTimeout(resolve, 100_000)", "setTimeout(resolve, 100)")
    .replace(
      "Date.now() - Date.parse(event.scheduleTime)",
      `Number(require("node:fs").readFileSync(${JSON.stringify(clockFile)}, "utf8")) * 1000 - Date.parse(event.scheduleTime)`,
    );
const common = {
  fireemu: args.fireemu,
  node: args.node,
  depsDir: args.deps,
  start: "2026-10-05T08:40:30Z",
};
let results = {};
// `--cache <file>` keeps the local timelines (the runs take minutes): an existing file is read instead of running. A
// cache written before the in-flight scenario holds no timeline for it, and the row then diverges.
if (args.cache && existsSync(args.cache)) results = JSON.parse(readFileSync(args.cache, "utf8"));
else
  for (const profile of ["strict", "emulator"]) {
    results[profile] = {
      natural: await runLocal({
        ...common,
        profile,
        fixtureDir: join(here, "..", "fixture"),
        seconds: 700,
        clockFile: true,
        awaitIdle: false,
        pauseMs: 150,
        pullTopics,
        patch,
      }),
      // The slow job's handler lasts 100 logical seconds, so an occurrence can fall inside a running handler.
      inflight: await runLocal({
        ...common,
        profile,
        fixtureDir: join(here, "..", "fixture"),
        patch: logicalSlowHandler,
        ...INFLIGHT_RUN,
      }),
      // A failing handler's retry chain waits on the logical clock: do not wait for the runtime to be idle.
      probe: await runLocal({
        ...common,
        profile,
        fixtureDir: join(here, "fixture-probe"),
        seconds: 900,
        awaitIdle: false,
        pauseMs: 150,
      }),
    };
  }
for (const [profile, scenarios] of Object.entries(results))
  for (const [scenario, run] of Object.entries(scenarios))
    if (run.exitCode !== 0) throw new Error(`${profile}/${scenario} exited with ${run.exitCode}`);
if (args.cache && !existsSync(args.cache)) writeFileSync(args.cache, JSON.stringify(results));
const also = (args.also ?? "")
  .split(",")
  .filter(Boolean)
  .map((name) => loadDigest(join(here, name)));
const table = compareProfiles(production, results.strict, results.emulator, also);
const summary = (profile) =>
  table.reduce((n, r) => ({ ...n, [r[profile].verdict]: (n[r[profile].verdict] ?? 0) + 1 }), {});
const output = {
  schemaVersion: 1,
  run: production.run,
  table,
  strict: summary("strict"),
  emulator: summary("emulator"),
};
if (args.out) writeFileSync(args.out, JSON.stringify(output, null, 1) + "\n");
for (const r of table)
  console.log(
    `${r.id.padEnd(36)} strict ${r.strict.verdict.padEnd(14)} emulator ${r.emulator.verdict.padEnd(14)} ${r.note}`,
  );
console.log("strict", output.strict, "emulator", output.emulator);
