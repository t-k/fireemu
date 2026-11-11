// The judge of the `case` family: reads the rows of a run against the three candidate answers of
// plan-case.mjs. It reads only the classes the row judge already gave from recorded shapes (`allow`
// is a 200, `deny` the recorded 403). Anything else is unread, and a reading with an unread row is
// incomplete, never a verdict. Controls come first: if an ASCII control or a literal-parse control
// answers wrongly, the rules in force were not the program's (a stale release, a refusal to
// compile), and nothing else is read.

import { CANDIDATES } from "./plan-case.mjs";

const READ = new Set(["allow", "deny"]);
const classOf = (allowed) => (allowed ? "allow" : "deny");

/**
 * @param {Array<{recording: number, id: string, class: string}>} rows rows of a run
 * @param {object} plan the case plan
 * @param {{recordings?: number}} [options]
 */
export function readCase(rows, plan, { recordings = 2, perProgram = true } = {}) {
  const planRows = plan.rows;
  const known = new Set(planRows.map((row) => row.id));
  const answers = new Map();
  for (const row of rows)
    if (known.has(row.id)) answers.set(`${row.recording}/${row.id}`, row.class);
  const recordingNumbers = Array.from({ length: recordings }, (_, i) => i + 1);

  const unread = [];
  for (const recording of recordingNumbers)
    for (const row of planRows)
      if (!READ.has(answers.get(`${recording}/${row.id}`))) unread.push(`${recording}/${row.id}`);

  const failedControls = [];
  for (const row of planRows.filter((r) => r.control))
    for (const recording of recordingNumbers) {
      const got = answers.get(`${recording}/${row.id}`);
      if (
        READ.has(got) &&
        got !== classOf(row.candidates.ascii) &&
        !failedControls.includes(row.id)
      )
        failedControls.push(row.id);
    }

  const disagreeing = [];
  for (const row of planRows) {
    const classes = recordingNumbers.map((n) => answers.get(`${n}/${row.id}`));
    if (classes.every((c) => READ.has(c)) && new Set(classes).size > 1) disagreeing.push(row.id);
  }

  const perCandidate = {};
  for (const candidate of CANDIDATES) {
    const mismatches = [];
    for (const row of planRows)
      for (const recording of recordingNumbers) {
        const got = answers.get(`${recording}/${row.id}`);
        if (
          READ.has(got) &&
          got !== classOf(row.candidates[candidate]) &&
          !mismatches.includes(row.id)
        )
          mismatches.push(row.id);
      }
    perCandidate[candidate] = {
      mismatches,
      consistent: unread.length === 0 && mismatches.length === 0,
    };
  }

  const complete = unread.length === 0;
  const fits = CANDIDATES.filter((c) => perCandidate[c].consistent);
  let verdict;
  if (failedControls.length > 0) verdict = "controls-failed";
  else if (!complete) verdict = "incomplete";
  else if (disagreeing.length > 0) verdict = "disagree";
  else if (fits.length === 1) verdict = fits[0];
  else verdict = fits.length === 0 ? "none" : "ambiguous";

  // Each ruleset alone, so a refused second ruleset does not hide what the first answered.
  const byProgram = {};
  if (perProgram)
    for (const id of new Set(planRows.map((row) => row.program).filter(Boolean)))
      byProgram[id] = readCase(
        rows,
        { rows: planRows.filter((row) => row.program === id) },
        { recordings, perProgram: false },
      ).verdict;

  return {
    verdict,
    byProgram,
    complete,
    controls: failedControls.length === 0 ? "ok" : "failed",
    failedControls,
    unread,
    disagreeing,
    perCandidate,
    table: planRows.map((row) => ({
      id: row.id,
      group: row.group,
      control: row.control,
      classes: recordingNumbers.map((n) => answers.get(`${n}/${row.id}`) ?? "missing"),
      predicted: row.candidates,
    })),
  };
}

/** The reading as text for the run report and the review. */
export function renderReading(reading) {
  const lines = [
    `verdict: ${reading.verdict}`,
    `complete: ${reading.complete}; controls: ${reading.controls}${reading.failedControls.length ? ` (${reading.failedControls.join(", ")})` : ""}`,
  ];
  if (reading.unread.length) lines.push(`unread: ${reading.unread.join(", ")}`);
  if (reading.disagreeing.length) lines.push(`disagreeing: ${reading.disagreeing.join(", ")}`);
  for (const candidate of CANDIDATES) {
    const { mismatches } = reading.perCandidate[candidate];
    lines.push(
      `${candidate}: ${mismatches.length} mismatch(es)${mismatches.length ? `: ${mismatches.join(", ")}` : ""}`,
    );
  }
  const programs = Object.entries(reading.byProgram ?? {});
  if (programs.length)
    lines.push(`programs: ${programs.map(([id, v]) => `${id}=${v}`).join(", ")}`);
  lines.push("", ["row", "group", "answers", "ascii", "full", "simple"].join("\t"));
  for (const row of reading.table)
    lines.push(
      [
        row.id,
        row.control ? "control" : row.group,
        row.classes.join(","),
        ...CANDIDATES.map((c) => classOf(row.predicted[c])),
      ].join("\t"),
    );
  return lines.join("\n");
}
