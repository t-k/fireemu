import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function compareBurst(production, local) {
  const p = production.offsetsMs;
  const l = local.offsetsMs;
  if (
    ![p, l].every(
      (offsets) =>
        Array.isArray(offsets) &&
        offsets.every((n, i) => Number.isFinite(n) && (i === 0 || offsets[i - 1] <= n)),
    )
  )
    throw new Error("burst offsets must be sorted finite numbers");
  const burst = p.filter((n) => n < 1000).length;
  const localBurst = l.filter((n) => n < 1000).length;
  const toleranceMs =
    burst < p.length
      ? Math.max(...p.slice(burst).map((n, i) => Math.abs(n - (p[burst] + i * 1000)))) + 250
      : 250;
  const rows = [
    {
      name: "burst",
      production: burst,
      local: localBurst,
      verdict: burst === localBurst ? "MATCH" : "MISMATCH",
    },
    {
      name: "cadence",
      toleranceMs,
      verdict: p
        .slice(burst)
        .every((n, i) => Number.isFinite(l[burst + i]) && Math.abs(l[burst + i] - n) <= toleranceMs)
        ? "MATCH"
        : "MISMATCH",
    },
    {
      name: "count",
      production: p.length,
      local: l.length,
      verdict: p.length === 120 && l.length === 120 ? "MATCH" : "MISMATCH",
    },
  ];
  return {
    kind: "task-queue-burst-comparison-v1",
    rows,
    verdict: rows.every((row) => row.verdict === "MATCH") ? "MATCH" : "MISMATCH",
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [, , production, local, flag, out, ...extra] = process.argv;
  if (!production || !local || flag !== "--out" || !out || extra.length)
    throw new Error("<production> <local> --out <new file>");
  const result = compareBurst(
    JSON.parse(readFileSync(production)),
    JSON.parse(readFileSync(local)),
  );
  writeFileSync(out, JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
}
