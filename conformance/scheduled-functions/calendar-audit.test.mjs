import assert from "node:assert/strict";
import { test } from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { HARNESS_FILES } from "./calendar-measure.mjs";
import { calendarFixture } from "./calendar-local.mjs";

// Condition (C), last item: every child-process call site in the harness's import closure goes
// through the recorder, and only the measuring entry may start a new session.
const here = (name) => fileURLToPath(new URL("./" + name, import.meta.url));
const ENTRY = "calendar-run-local.mjs";
const RECORDER = "calendar-recorder.mjs";
const MEASURE = "calendar-measure.mjs";

const localImports = (source) =>
  [...source.matchAll(/(?:^|\n)\s*(?:import|export)\b[^;]*?\bfrom\s*["']\.\/([^"']+)["']/g)].map(
    (match) => match[1],
  );

/** The relative-import closure of `entry`, read through `load(name)`. */
export async function importClosure(entry, load) {
  const sources = new Map();
  const pending = [entry];
  while (pending.length) {
    const name = pending.pop();
    if (sources.has(name)) continue;
    const source = await load(name);
    sources.set(name, source);
    pending.push(...localImports(source));
  }
  return sources;
}

const FORBIDDEN = [
  [/\bcreateRequire\b/, "createRequire"],
  [/\bimport\s*\(/, "dynamic import"],
  // `require` does not exist in an ES module without createRequire or the module builtins.
  [/["'](?:node:)?module["']/, "module builtin"],
  [/\bgetBuiltinModule\b/, "getBuiltinModule"],
  [/worker_threads/, "worker_threads"],
  [/node:cluster|["']cluster["']/, "cluster"],
  [/process\s*\.\s*(binding|_linkedBinding|dlopen)\b/, "native binding"],
  [/\bprocess\s*\.\s*execve\b/, "execve"],
];

/** Problems with the closure: who may use child_process, and who may start a session. */
export function auditSources(sources) {
  const problems = [];
  for (const [name, source] of sources) {
    for (const [pattern, what] of FORBIDDEN)
      if (pattern.test(source)) problems.push(`${name}: ${what}`);
    if (/["'](?:node:)?child_process["']/.test(source) && name !== RECORDER)
      problems.push(`${name}: child_process outside the recorder`);
    const sessions = source.match(/\bdetached\s*:/g)?.length ?? 0;
    const allowed = name === MEASURE ? 1 : 0;
    if (sessions !== allowed) problems.push(`${name}: ${sessions} detached spawn(s)`);
    if (/\bsetsid\b/.test(source)) problems.push(`${name}: setsid`);
  }
  const measure = sources.get(MEASURE) ?? "";
  if (!/\{\s*detached:\s*true,[^}]*\},\s*"outer",?\s*\)/.test(measure))
    problems.push(`${MEASURE}: the detached spawn is not the outer launcher's`);
  if (!sources.has(RECORDER)) problems.push("the recorder is not in the closure");
  return problems;
}

const load = (name) => readFile(here(name), "utf8");

test("the audit refuses each kind of call site it exists to catch", async () => {
  const base = new Map([
    [RECORDER, 'import { spawn } from "node:child_process";\n'],
    [MEASURE, 'recorder.spawn(node, [x], { detached: true, stdio: "ignore" }, "outer");\n'],
  ]);
  assert.deepEqual(auditSources(base), []);
  const withFile = (name, source) => new Map([...base, [name, source]]);
  for (const [source, expected] of [
    ['import { execFile } from "node:child_process";', "child_process outside the recorder"],
    ['import { createRequire } from "node:module";', "module builtin"],
    ['const cp = process.getBuiltinModule("node:child_process");', "getBuiltinModule"],
    ['import("./other.mjs");', "dynamic import"],
    ["const r = createRequire(import.meta.url);", "createRequire"],
    ['import { Worker } from "node:worker_threads";', "worker_threads"],
    ["process.dlopen(module, path);", "native binding"],
    ["recorder.spawn(a, b, { detached: true }, 'inner');", "1 detached spawn(s)"],
    ["os.setsid()", "setsid"],
  ])
    assert.ok(
      auditSources(withFile("calendar-other.mjs", source)).includes(
        `calendar-other.mjs: ${expected}`,
      ),
      source,
    );
  const moved = new Map([
    [RECORDER, base.get(RECORDER)],
    [MEASURE, 'recorder.spawn(node, [x], { detached: true }, "inner");\n'],
  ]);
  assert.ok(
    auditSources(moved).includes(`${MEASURE}: the detached spawn is not the outer launcher's`),
  );
  const twice = new Map([...base, [MEASURE, base.get(MEASURE).repeat(2)]]);
  assert.ok(auditSources(twice).includes(`${MEASURE}: 2 detached spawn(s)`));
});

test("the harness's import closure passes the audit and is exactly its versioned module set", async () => {
  const sources = await importClosure(ENTRY, load);
  assert.deepEqual(auditSources(sources), []);
  assert.deepEqual(
    [...sources.keys()].sort(),
    HARNESS_FILES.filter((name) => name.endsWith(".mjs")).sort(),
  );
});

test("the refusal fixture starts no process and loads no control preamble", () => {
  const fixture = calendarFixture({
    schedule: "every 5 minutes",
    timeZone: "Invalid/CalendarZone",
  });
  for (const word of ["child_process", "spawn", "exec", "fork", "controls.cjs", "python"])
    assert.ok(!fixture.includes(word), word);
});
