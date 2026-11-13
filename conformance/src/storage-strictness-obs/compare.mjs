import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { judgeJournal, readJournal } from "./judge.mjs";

export function compare(production, local) {
  const cases = [...new Set([...production, ...local].map((row) => row.case))];
  return cases.map((id) => {
    const p = production.filter((row) => row.case === id);
    const l = local.filter((row) => row.case === id);
    if (p.length !== 1 || l.length !== 1 || p[0].known !== true || l[0].known !== true)
      return { case: id, verdict: "NEEDS-REVIEW" };
    const fields = [
      "status",
      "shape",
      "bodyBytes",
      "sha256",
      "headerNames",
      "headers",
      "json",
      "xml",
    ].filter((field) => JSON.stringify(p[0][field]) !== JSON.stringify(l[0][field]));
    return { case: id, verdict: fields.length ? `DIFFERS(${fields.join(",")})` : "MATCH" };
  });
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const production = JSON.parse(readFileSync(process.argv[2], "utf8"));
    const rows = compare(production, judgeJournal(readJournal(process.argv[3])));
    for (const row of rows) console.log(`${row.case} ${row.verdict}`);
    process.exitCode = rows.length && rows.every((row) => row.verdict === "MATCH") ? 0 : 1;
  } catch {
    console.error("Could not compare production rows and local journal");
    process.exitCode = 1;
  }
}
