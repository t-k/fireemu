// Reads the cell records of a recording into answers to the open questions of the PUBSUB-NEGCACHE
// packet. The judge reads only what was measured: status, latency class and the measured age from the
// arming request. A question is answered only when both recordings agree on it; otherwise it is
// `mixed` and no rule is written. A cell whose prerequisite failed (the "absent" name answered 200,
// the create did not answer 200) contributes nothing.

import { SLOW_MS } from "./answer.mjs";
import { CELLS } from "./program.mjs";

export const WINDOW_EDGE_MS = 9400; // a read earlier than this after the arming start is inside any recorded window

/** A forwarded answer read after the window cannot tell "never armed" from "expired". */
export const inWindow = (step) => step && step.ageMs !== null && step.ageMs < WINDOW_EDGE_MS;

/** hit: a cached 404; ok: 200; miss: a forwarded (slow) 404; ambiguous: 60-120 ms; other: anything else. */
export function readOutcome(step) {
  if (!step || step.kind === "unknown") return "other";
  if (step.kind === "ok") return "ok";
  if (step.status === 404) {
    if (step.latency === "fast") return "hit";
    if (step.latency === "slow") return "miss";
    return "ambiguous";
  }
  return "other";
}

// Expected statuses of the leading steps of each cell; null = any. A mismatch fails the prerequisite.
const ABSENT_FIRST = [404, 200];
export const EXPECT = {
  C0d: [200, 200, 200, 200],
  C0f: [200, 200, 200],
  C2: [200],
  N2a: ABSENT_FIRST,
  N2b: ABSENT_FIRST,
  N4: ABSENT_FIRST,
  N5: [200, 404, 200],
  V1: ABSENT_FIRST,
  V2: ABSENT_FIRST,
  V3: ABSENT_FIRST,
  V4: ABSENT_FIRST,
  N1: [404],
  A1: ABSENT_FIRST,
  A2: ABSENT_FIRST,
  A3: ABSENT_FIRST,
  A4: ABSENT_FIRST,
  A5: ABSENT_FIRST,
  A7: ABSENT_FIRST,
  A8: ABSENT_FIRST,
  A9: ABSENT_FIRST,
  E1: [200, 404],
  E2: [200, 404],
  E3: [200, 404],
  E4: [200, 404],
  "A6.1": [200, 404],
  "A6.2": [200, 404],
  "A6.3": [200, 404],
  D1: [200, 404],
  D2: [200, 404],
  P1: [200, 200, 200, 404, 200],
  P2: [200, 200, 200, 404, 200],
  P3: [200, 200, 200, 404, 200],
  K1: [200, 404, 200],
};

export function prerequisite(record) {
  if (record.skipped) return { ok: false, reason: `skipped: ${record.skipped}` };
  const expected = EXPECT[record.id];
  if (!expected) return { ok: false, reason: "no expectation for the cell" };
  if (record.steps.length < expected.length)
    return { ok: false, reason: record.aborted ?? "cell incomplete" };
  for (let i = 0; i < expected.length; i += 1)
    if (record.steps[i].status !== expected[i])
      return {
        ok: false,
        reason: `step ${i} answered ${record.steps[i].status}, expected ${expected[i]}`,
        step: i,
      };
  return { ok: true };
}

const step = (record, i) => record.steps.find((s) => s.i === i);
const reads = (record, from) =>
  record.steps.filter(
    (s) => s.i >= from && ["getSub", "getSnap"].includes(s.op) && s.ageMs !== null,
  );

/** The hit/miss pattern of the reads of a cell, in age order, with the last hit and the first later miss. */
export function window(record, from) {
  const items = reads(record, from)
    .map((s) => ({ age: s.ageMs, outcome: readOutcome(s) }))
    .toSorted((a, b) => a.age - b.age);
  let lastHit = null;
  let firstMiss = null;
  let consistent = true;
  for (const item of items) {
    if (["ambiguous", "other"].includes(item.outcome)) consistent = false;
    if (item.outcome === "hit") {
      if (firstMiss !== null) consistent = false;
      lastHit = item.age;
    } else if (firstMiss === null && ["ok", "miss"].includes(item.outcome)) firstMiss = item.age;
  }
  return { items, lastHit, firstMiss, consistent };
}

/** `first` is the read inside the window, `last` the read after it. */
function armVerdict(first, last) {
  const f = readOutcome(first);
  if (f === "hit") return readOutcome(last) === "ok" ? "arms" : "mixed";
  if (f === "ok") return inWindow(first) ? "does-not-arm" : "inconclusive";
  return "mixed";
}
/** A cached or forwarded answer to a read inside the window; a forwarded one outside it proves nothing. */
const windowRead = (s) => {
  const o = readOutcome(s);
  return o === "hit"
    ? "hit"
    : o === "ok"
      ? inWindow(s)
        ? "ok"
        : "inconclusive"
      : o === "miss"
        ? inWindow(s)
          ? "miss"
          : "inconclusive"
        : "mixed";
};

const byId = (records) => Object.fromEntries(records.map((r) => [r.id, r]));
const pair = (a, b) => (a === b ? a : "mixed");

export function judgeRun(records) {
  const cells = byId(records);
  const valid = {};
  const invalid = {};
  for (const [id, record] of Object.entries(cells)) {
    const p = prerequisite(record);
    if (p.ok) valid[id] = record;
    else invalid[id] = p.reason;
  }
  const answers = {};
  const need = (...ids) => ids.filter((id) => valid[id]).map((id) => valid[id]);

  // Q-TTL
  {
    const rows = need("E1", "E2", "E3", "E4", "N2a", "N2b").map((r) => ({
      id: r.id,
      ...window(r, r.arm + 1),
    }));
    const lastHit = Math.max(-1, ...rows.map((r) => r.lastHit ?? -1));
    const firstMiss = Math.min(Infinity, ...rows.map((r) => r.firstMiss ?? Infinity));
    answers.ttl = {
      cells: rows.map((r) => r.id),
      lastHitMs: lastHit < 0 ? null : lastHit,
      firstMissMs: Number.isFinite(firstMiss) ? firstMiss : null,
      verdict:
        rows.length === 0
          ? "no-data"
          : !rows.every((r) => r.consistent) || lastHit >= firstMiss
            ? "inconsistent"
            : Number.isFinite(firstMiss)
              ? "window"
              : "open",
    };
  }
  // Q-ARM
  {
    const out = {};
    for (const id of ["A1", "A2", "A3", "A4", "A5", "A7", "A8", "A9"]) {
      const r = valid[id];
      if (!r) continue;
      out[id] = armVerdict(step(r, 2), step(r, 3));
    }
    const seeks = need("A6.1", "A6.2", "A6.3").map((r) => armVerdict(step(r, 2), step(r, 3)));
    out.seek = {
      arms: seeks.filter((s) => s === "arms").length,
      of: seeks.length,
      other: seeks.filter((s) => !["arms", "does-not-arm"].includes(s)).length,
    };
    answers.arm = out;
  }
  // Q-ABSENT
  {
    const n1 = valid.N1;
    const outcomes = n1 ? [1, 2].map((i) => windowRead(step(n1, i))) : [];
    answers.absent = {
      pureNegative: !n1
        ? "no-data"
        : outcomes.every((o) => o === "hit")
          ? "served"
          : outcomes.every((o) => o === "miss" || o === "ok")
            ? "not-served"
            : "mixed",
      existingServed:
        need("E1", "E2", "E3", "E4")
          .map((r) => windowRead(step(r, 2)))
          .reduce((acc, o) => pair(acc ?? o, o), null)
          ?.replace("hit", "served")
          .replace(/^ok$/, "not-served") ?? "no-data",
    };
  }
  // Q-BODY
  {
    const n4 = valid.N4;
    const n5 = valid.N5;
    answers.body = {
      urlName: !n4
        ? "no-data"
        : [2, 3].every((i) => windowRead(step(n4, i)) === "hit")
          ? "does-not-clear"
          : [2, 3].every((i) => windowRead(step(n4, i)) === "ok")
            ? "clears"
            : "mixed",
      otherName: !n5
        ? "no-data"
        : windowRead(step(n5, 3)) === "hit"
          ? "does-not-clear"
          : windowRead(step(n5, 3)) === "ok"
            ? "clears"
            : "mixed",
    };
  }
  // Q-SERVE and Q-REARM
  {
    const probe = (r) =>
      readOutcome(step(r, 2)) === "hit"
        ? "answered-from-entry"
        : step(r, 2)?.kind === "ok" && inWindow(step(r, 2))
          ? "reaches-backend"
          : "mixed";
    const serve = {};
    for (const id of ["V1", "V2", "V3", "V4"]) if (valid[id]) serve[id] = probe(valid[id]);
    if (valid.V3) {
      const last = step(valid.V3, 3);
      serve.V3applied =
        last?.kind === "ok" ? (last.body?.labels?.k === "v" ? "yes" : "no") : "unread";
    }
    if (valid.V4) {
      const list = step(valid.V4, 3);
      // Only a complete answer (no nextPageToken) can show that a name is absent.
      const names =
        list?.kind === "ok" && list.body && list.body.complete === true
          ? (list.body.subscriptions ?? []).map((s) => s.name)
          : null;
      serve.V4present =
        names === null ? "unread" : names.some((n) => n.endsWith("-nc-v4-x")) ? "yes" : "no";
      const rearm = readOutcome(step(valid.V4, 4));
      // The question only exists when the DELETE was answered from the entry.
      serve.V4rearm =
        serve.V4 !== "answered-from-entry"
          ? "not-applicable"
          : rearm === "hit"
            ? "re-armed"
            : ["ok", "miss"].includes(rearm)
              ? "not-re-armed"
              : "mixed";
    }
    answers.serve = serve;
    answers.rearm = {
      deleteHit: serve.V4rearm ?? "no-data",
      getHitExtends: (() => {
        const rows = need("E1", "E2", "E3", "E4", "N2a", "N2b").map((r) => window(r, r.arm + 1));
        if (!rows.length) return "no-data";
        // A cell with hits at most 3 s apart that never misses up to 10.5 s is either extended by its
        // hits or has a window longer than the grid; the cells cannot tell these apart.
        return rows.some((r) => r.firstMiss === null)
          ? "yes-or-window-over-10.5s"
          : rows.every((r) => r.consistent)
            ? "no"
            : "mixed";
      })(),
      afterSeek: need("D1", "D2").map((r) => window(r, 2).lastHit),
    };
  }
  // Q-EXEMPT
  {
    const out = {};
    for (const [id, age] of [
      ["P1", 4000],
      ["P3", 7000],
      ["P2", 13000],
    ]) {
      const r = valid[id];
      if (!r) continue;
      const o = windowRead(step(r, 5));
      out[`${age}ms`] =
        o === "hit"
          ? "armed"
          : o === "ok"
            ? "exempt"
            : o === "inconclusive"
              ? "inconclusive"
              : "mixed";
    }
    answers.exempt = out;
  }
  // Q-KEY
  {
    const k = valid.K1;
    const label = (i) =>
      k
        ? windowRead(step(k, i)) === "hit"
          ? "shared"
          : windowRead(step(k, i)) === "ok"
            ? "separate"
            : "mixed"
        : "no-data";
    answers.key = k
      ? {
          queryAltJson: label(3),
          queryFields: label(4),
          snapshotSameId: label(5),
          grpc: label(6),
          topic: label(7),
        }
      : "no-data";
  }
  // Q-CONN: only reads that are clearly a hit, a miss or a 200 can differ; an ambiguous or odd read says nothing.
  {
    const clear = new Set(["hit", "miss", "ok"]);
    const same = (a, b) => {
      const ra = valid[a];
      const rb = valid[b];
      if (!ra || !rb) return "no-data";
      const f = (r) =>
        reads(r, r.arm + 1)
          .toSorted((x, y) => x.i - y.i)
          .map(readOutcome);
      const fa = f(ra);
      const fb = f(rb);
      if (![...fa, ...fb].every((o) => clear.has(o))) return "no-data";
      return fa.join(",") === fb.join(",") ? "same" : "differs";
    };
    answers.conn = {
      grid_a_existing: same("E1", "E2"),
      grid_b_existing: same("E3", "E4"),
      base: same("N2a", "N2b"),
    };
  }
  // Calibration (C0d, C0f, C2): what the latency classes and the existing-name cells stand on.
  {
    const median = (values) => {
      const sorted = values.filter((v) => Number.isFinite(v)).toSorted((x, y) => x - y);
      return sorted.length ? sorted[Math.floor(sorted.length / 2)] : null;
    };
    const gets = (r) => r?.steps.filter((x) => x.op === "getTopic") ?? [];
    const d = valid.C0d;
    const f = valid.C0f;
    const forwardedDedicated = median(gets(d).map((x) => x.headersMs));
    const forwardedFresh = median(gets(f).map((x) => x.headersMs));
    const pull = d?.steps.find((x) => x.op === "pullSub");
    const c2 = valid.C2 ?? records.find((r) => r.id === "C2");
    answers.calibration = {
      forwardedGetMs: { dedicated: forwardedDedicated, fresh: forwardedFresh },
      freshConnectMs: median(gets(f).map((x) => x.connectMs)),
      // Forwarded GETs must classify as slow on both kinds of connection, or the latency classes do not hold here.
      latencyClassesHold:
        forwardedDedicated === null || forwardedFresh === null
          ? "no-data"
          : forwardedDedicated >= SLOW_MS && forwardedFresh >= SLOW_MS,
      emptyPull: pull ? { status: pull.status, headersMs: pull.headersMs } : "no-data",
      failedCreateOnExisting: c2?.steps?.[1] ? c2.steps[1].status : "no-data",
      failedCreateArms: c2?.steps?.[2] ? readOutcome(c2.steps[2]) === "hit" : "no-data",
    };
  }
  return { answers, invalid, valid: Object.keys(valid) };
}

/**
 * Two recordings: a question is answered only where they agree. Measured ages are compared as intervals,
 * not by equality: the window of two runs is (max last hit, min first miss) and must stay consistent;
 * the calibration of the two runs is reported side by side.
 */
export function combineRuns(first, second) {
  const merge = (a, b) => {
    if (
      a !== null &&
      typeof a === "object" &&
      b !== null &&
      typeof b === "object" &&
      !Array.isArray(a)
    ) {
      const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
      return Object.fromEntries([...keys].map((key) => [key, merge(a[key], b[key])]));
    }
    return JSON.stringify(a) === JSON.stringify(b) ? a : { mixed: [a, b] };
  };
  const out = merge(first.answers, second.answers);
  const [x, y] = [first.answers, second.answers];
  if (x?.ttl && y?.ttl) {
    const hits = [x.ttl.lastHitMs, y.ttl.lastHitMs].filter((v) => v !== null);
    const misses = [x.ttl.firstMissMs, y.ttl.firstMissMs].filter((v) => v !== null);
    const lastHitMs = hits.length ? Math.max(...hits) : null;
    const firstMissMs = misses.length ? Math.min(...misses) : null;
    const agree = x.ttl.verdict === y.ttl.verdict;
    out.ttl = {
      cells: [...new Set([...x.ttl.cells, ...y.ttl.cells])],
      lastHitMs,
      firstMissMs,
      verdict: !agree
        ? { mixed: [x.ttl.verdict, y.ttl.verdict] }
        : lastHitMs !== null && firstMissMs !== null && lastHitMs >= firstMissMs
          ? "inconsistent"
          : x.ttl.verdict,
    };
  }
  if (x?.rearm && y?.rearm) {
    const shape = (list) => list.map((v) => v !== null);
    const same =
      JSON.stringify(shape(x.rearm.afterSeek)) === JSON.stringify(shape(y.rearm.afterSeek));
    out.rearm = {
      ...out.rearm,
      afterSeek: same
        ? x.rearm.afterSeek.map((v, i) => (v === null ? null : Math.max(v, y.rearm.afterSeek[i])))
        : { mixed: [x.rearm.afterSeek, y.rearm.afterSeek] },
    };
  }
  if (x?.calibration && y?.calibration) out.calibration = { runs: [x.calibration, y.calibration] };
  // No rule is written unless forwarded GETs classified as slow on both kinds of connection in BOTH
  // runs: otherwise the latency classes (and every hit and miss) do not hold on this network.
  const holds = [x?.calibration?.latencyClassesHold, y?.calibration?.latencyClassesHold];
  if (holds.every((value) => value === true)) return { rulesAllowed: true, answers: out };
  return {
    rulesAllowed: false,
    withheld: `latencyClassesHold is ${JSON.stringify(holds)}, not true in both runs: no rule is written`,
    answers: out,
  };
}

export const cellIds = () => CELLS.map((c) => c.id);
