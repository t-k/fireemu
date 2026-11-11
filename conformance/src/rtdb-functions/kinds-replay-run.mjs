// The producer of the `kinds` closure replay: the two local runs a release binary is judged on.
// Usage: node kinds-replay-run.mjs --fireemu <binary> --profile strict --out <new directory>
// `<out>/all` holds the 21 steps of RTDB-TRIGGERS-KINDS-20261108-01 and `<out>/v2` the user writes of
// RTDB-TRIGGERS-KINDS-20261109-02; `adjudicateKinds` (kinds-replay.mjs) judges both.
import { mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { runLocal } from "./kinds-local-run.mjs";

export async function runKindsReplay({ fireemu, profile, out }) {
  if (!fireemu || !out) throw new Error("--fireemu and --out are required");
  if (profile !== "strict") throw new Error("the kinds replay judges the strict profile only");
  mkdirSync(out);
  const all = await runLocal({ fireemu, profile, out: path.join(out, "all"), steps: undefined });
  const v2 = await runLocal({ fireemu, profile, out: path.join(out, "v2"), steps: "v2" });
  return { all, v2 };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const argv = process.argv.slice(2);
  const opt = (name) => argv[argv.indexOf(name) + 1];
  const { all, v2 } = await runKindsReplay({
    fireemu: opt("--fireemu"),
    profile: opt("--profile") ?? "strict",
    out: opt("--out"),
  });
  console.log(
    JSON.stringify({
      all: { frames: all.frames.length, writes: all.writes },
      v2: { frames: v2.frames.length, writes: v2.writes },
    }),
  );
}
