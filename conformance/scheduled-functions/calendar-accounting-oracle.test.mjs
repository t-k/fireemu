import assert from "node:assert/strict";
import { test } from "node:test";
import { judgeInventory } from "./calendar-accounting.mjs";

// Review S8: an oracle for condition (E) written from the condition text (ledger 786 and
// condition-v4) and the reviewed refinements (D4, S2, the ESRCH chain, complete passes),
// independently of calendar-accounting.mjs, compared on generated inventories.

const S = 300;
const LAUNCH = Date.parse("2026-10-02T06:00:00Z");
const DIRS = ["/private/run-1", "/private/acc-1"];
const RECORDED = [
  { pid: 41, uid: 501, started: "Fri Oct 2 06:00:03 2026" },
  { pid: 42, uid: 501, started: "Fri Oct 2 06:00:04 2026" },
];
const CTX = {
  sessionId: S,
  recorded: RECORDED,
  privateDirs: DIRS,
  launchTime: LAUNCH,
  rootPid: 100,
};

const at = (row) => Date.parse(row.started + " GMT");
const namesDir = (args) =>
  DIRS.some((dir) => args.split(" ").some((word) => word === dir || word.startsWith(dir + "/")));

/** The oracle's judgement of one pass: "survivors", "inconclusive", "repass" or "clean". */
function oraclePass(rows) {
  if (!rows.some((row) => row.pid === 1) || !rows.some((row) => row.pid === CTX.rootPid))
    return "inconclusive";
  const byPid = new Map(rows.map((row) => [row.pid, row]));
  const inS = (pid) => byPid.get(pid)?.sid === S;
  const isRecordedPid = (pid) => RECORDED.some((identity) => identity.pid === pid);
  // Could an ESRCH row have been in S? Only through ancestors that could have been.
  const reachesS = (row) => {
    const visited = [];
    let pid = row.ppid;
    while (!visited.includes(pid)) {
      visited.push(pid);
      if (pid === 1 || inS(pid) || isRecordedPid(pid)) return true;
      const up = byPid.get(pid);
      if (!up || up.sid !== "ESRCH") return false;
      pid = up.ppid;
    }
    return true;
  };
  let survivors = false,
    unknown = false,
    repass = false;
  for (const row of rows) {
    if (Number.isNaN(at(row)) || (typeof row.sid !== "number" && row.sid !== "ESRCH")) {
      unknown = true;
      continue;
    }
    const zombie = row.stat.startsWith("Z");
    const clause1 = row.sid === S;
    const clause2 = RECORDED.some(
      (identity) =>
        identity.pid === row.pid && identity.uid === row.uid && identity.started === row.started,
    );
    const clause3 = at(row) >= LAUNCH && namesDir(row.args);
    const clause4 = zombie && (isRecordedPid(row.pid) || isRecordedPid(row.ppid) || inS(row.ppid));
    if (clause1 || clause2 || clause3 || clause4) {
      survivors = true;
      continue;
    }
    if (zombie) {
      const parent = byPid.get(row.ppid);
      if (row.ppid === 1 && at(row) >= LAUNCH) repass = true;
      else if (!(
        parent &&
        !parent.stat.startsWith("Z") &&
        typeof parent.sid === "number" &&
        parent.sid !== S
      ))
        unknown = true;
      continue;
    }
    if (row.sid === "ESRCH" && at(row) >= LAUNCH && reachesS(row)) repass = true;
  }
  if (survivors) return "survivors";
  if (unknown) return "inconclusive";
  return repass ? "repass" : "clean";
}

/** The oracle's outcome of an inventory. */
function oracle(passes) {
  if (passes.length < 1 || passes.length > 5) return "inconclusive";
  let previous = false;
  for (const rows of passes) {
    const judged = oraclePass(rows);
    if (judged === "survivors" || judged === "inconclusive") return judged;
    const clean = judged === "clean";
    if (clean && previous) return "clean";
    previous = clean;
  }
  return "inconclusive";
}

function generated(seed) {
  let state = seed >>> 0 || 1;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return state >>> 0;
  };
}

const pick = (random, list) => list[random() % list.length];
const STARTS = [
  "Fri Oct 2 05:00:00 2026",
  "Fri Oct 2 05:59:59 2026",
  "Fri Oct 2 06:00:00 2026",
  "Fri Oct 2 06:00:03 2026",
  "Fri Oct 2 06:00:04 2026",
  "Fri Oct 2 06:00:09 2026",
];

function generatedPass(random) {
  const rows = [];
  if (random() % 20 !== 0)
    rows.push({
      pid: 1,
      ppid: 0,
      uid: 0,
      started: STARTS[0],
      stat: "Ss",
      args: "/sbin/launchd",
      sid: 1,
    });
  if (random() % 20 !== 0)
    rows.push({
      pid: 100,
      ppid: 1,
      uid: 501,
      started: STARTS[0],
      stat: "S",
      args: "node measure",
      sid: 50,
    });
  const count = random() % 7;
  for (let i = 0; i < count; i++) {
    const pid = pick(random, [41, 42, 43, 44, 45, 46, 47, 48]);
    if (rows.some((row) => row.pid === pid)) continue;
    rows.push({
      pid,
      ppid: pick(random, [1, 41, 42, 43, 44, 45, 46, 99]),
      uid: pick(random, [501, 501, 0]),
      started: random() % 25 === 0 ? "Fri Foo 2 06:00:03 2026" : pick(random, STARTS),
      stat: pick(random, ["S", "R", "Z", "Z+"]),
      args: pick(random, [
        "x",
        "node /private/run-1/y",
        "python3 /private/acc-1/z",
        "/private/run-10/w",
      ]),
      sid: pick(random, [S, 77, 88, "ESRCH", "ESRCH", "EPERM"]),
    });
  }
  return rows;
}

test("the inventory judge agrees with the condition-derived oracle on generated inventories", () => {
  const random = generated(0xe0e786);
  const counts = {};
  for (let i = 0; i < 4000; i++) {
    const passes = Array.from({ length: 1 + (random() % 5) }, () => generatedPass(random));
    // Often repeat the same pass, as a quiet machine would list it.
    if (random() % 2 === 0) passes.fill(passes[0]);
    const expected = oracle(passes);
    counts[expected] = (counts[expected] ?? 0) + 1;
    assert.equal(
      judgeInventory(passes, CTX).outcome,
      expected,
      `seede0e786/${i}: ${JSON.stringify(passes)}`,
    );
  }
  // The generator reaches every outcome often enough to mean something.
  for (const outcome of ["clean", "survivors", "inconclusive"])
    assert.ok((counts[outcome] ?? 0) > 200, `${outcome}: ${JSON.stringify(counts)}`);
});
