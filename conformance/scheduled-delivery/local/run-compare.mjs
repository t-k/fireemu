// Runs the two local scenarios under both profiles and prints (and writes) the comparison with the second delivery
// recording. Loopback only; needs a fireemu binary (build it with RUSTC_WRAPPER= so that no compiler cache is
// involved), a Node 22 binary and a node_modules holding firebase-functions 7.3.2.
//
//   node run-compare.mjs --fireemu <bin> --node <node22> --deps <node_modules> [--out <file>]
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { compareProfiles, loadDigest } from "./compare.mjs";
import { runLocal } from "./local-run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(
  process.argv
    .slice(2)
    .flatMap((a, i, all) => (a.startsWith("--") ? [[a.slice(2), all[i + 1]]] : [])),
);
for (const key of ["fireemu", "node", "deps"])
  if (!args[key]) throw new Error(`--${key} is required`);

const production = loadDigest(join(here, "production-run2.json"));
// The recorded fixture's slow handler sleeps 100 real seconds, which would stall a logical clock; the copy sleeps 100 ms.
const patch = (source) =>
  source.replace("setTimeout(resolve, 100_000)", "setTimeout(resolve, 100)");
const common = {
  fireemu: args.fireemu,
  node: args.node,
  depsDir: args.deps,
  start: "2026-10-05T08:40:30Z",
};
let results = {};
// `--cache <file>` keeps the local timelines (the runs take minutes): an existing file is read instead of running.
if (args.cache && existsSync(args.cache)) results = JSON.parse(readFileSync(args.cache, "utf8"));
else
  for (const profile of ["strict", "emulator"]) {
    results[profile] = {
      natural: await runLocal({
        ...common,
        profile,
        fixtureDir: join(here, "..", "fixture"),
        seconds: 700,
        patch,
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
if (args.cache && !existsSync(args.cache)) writeFileSync(args.cache, JSON.stringify(results));
const table = compareProfiles(production, results.strict, results.emulator);
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
