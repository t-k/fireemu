// Compares two projections of the program (two production recordings, or fireemu and a recording), case by case.
//
// A row has a structure verdict and a timing verdict, kept apart because production's times are never equal twice:
//   structure: MATCH (equal as projected), MATCH_LAYOUT (equal once the volatile layouts of LAYOUT_RULES are applied, each rule
//     counted and cited), KNOWN_DIFFERENCE (differs, and a known difference names the case and the part), MISMATCH.
//   timing: WITHIN (the first delivery and every gap are within the tolerance of the other side's), OUTSIDE, NOT_COMPARED
//     (a case with no timing claim), KNOWN_DIFFERENCE.
// A known difference cites a ruling; one that cites none is refused.
import { digestOf } from "./project.mjs";

/** Tolerances in milliseconds, by what is measured. They are stated in every comparison file. */
export const TOLERANCE = Object.freeze({
  // Cloud Tasks and Cloud Run add up to a second to a delay (a retry's gap was 1, 2, 4, 6, 6 s configured and 1.05, 3.04, 4.04,
  // 6.03, 6.04 s observed once, 1.07, 2.04, 4.03, 6.04, 6.03 s the next time).
  gapMs: 1500,
  firstMs: 1500,
});

/**
 * Layouts that vary between two production runs of the same case, so that a difference in them is not a difference of
 * behaviour. A rule hides a value or the presence of an edge header, never a format of the answer.
 */
export const LAYOUT_RULES = Object.freeze([
  {
    id: "volatile-edge-header",
    what: "x-client-data is added to some deliveries by the front end and not to others (names set of one delivery, 16 or 17 names)",
    apply(delivery) {
      const names = delivery.request.headers.names;
      const next = names.filter((name) => name !== "x-client-data");
      if (next.length === names.length) return false;
      delivery.request.headers.names = next;
      return true;
    },
  },
  {
    id: "eta-digits",
    what: "X-CloudTasks-TaskETA is a Unix time with three to seven fractional digits (a float printed without trailing zeros)",
    apply(delivery) {
      const eta = delivery.request.headers.eta;
      if (!/^UNIX\(f[3-7]\)$/.test(eta)) return false;
      delivery.request.headers.eta = "UNIX(f3-7)";
      return true;
    },
  },
  {
    id: "numeric-id-length",
    what: "a generated task id is a decimal number of 19 or 20 digits",
    apply(delivery) {
      const name = delivery.request.headers.taskName;
      if (!/^ID\((19|20)\)$/.test(name)) return false;
      delivery.request.headers.taskName = "ID(19-20)";
      return true;
    },
  },
]);

const clone = (value) => JSON.parse(JSON.stringify(value));

function normalizeNames(record, used) {
  const copy = clone(record);
  for (const delivery of copy.deliveries)
    for (const rule of LAYOUT_RULES)
      if (rule.apply(delivery)) used.set(rule.id, (used.get(rule.id) ?? 0) + 1);
  const body = copy.admission?.body;
  if (typeof body?.name === "string" && /\/tasks\/ID\((19|20)\)$/.test(body.name)) {
    body.name = body.name.replace(/ID\((19|20)\)$/, "ID(19-20)");
    used.set("numeric-id-length", (used.get("numeric-id-length") ?? 0) + 1);
  }
  delete copy.timing;
  return copy;
}

/** The first difference between two JSON values as a path, or null. */
export function firstDifference(a, b, path = "") {
  if (
    typeof a !== typeof b ||
    Array.isArray(a) !== Array.isArray(b) ||
    (a === null) !== (b === null)
  )
    return { path, a, b };
  if (Array.isArray(a)) {
    if (a.length !== b.length) return { path: path + "[length]", a: a.length, b: b.length };
    for (let i = 0; i < a.length; i++) {
      const d = firstDifference(a[i], b[i], `${path}[${i}]`);
      if (d) return d;
    }
    return null;
  }
  if (a !== null && typeof a === "object") {
    for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].toSorted()) {
      if (!(key in a) || !(key in b)) return { path: `${path}/${key}`, a: a[key], b: b[key] };
      const d = firstDifference(a[key], b[key], `${path}/${key}`);
      if (d) return d;
    }
    return null;
  }
  return a === b ? null : { path, a, b };
}

/** Every difference between two JSON values: `{path, a, b}` with array positions kept (`[0]`). */
export function allDifferences(a, b, path = "", out = []) {
  if (
    typeof a !== typeof b ||
    Array.isArray(a) !== Array.isArray(b) ||
    (a === null) !== (b === null)
  ) {
    out.push({ path, a, b });
  } else if (Array.isArray(a)) {
    if (a.length !== b.length) out.push({ path: path + "[length]", a: a.length, b: b.length });
    else a.forEach((item, i) => allDifferences(item, b[i], `${path}[${i}]`, out));
  } else if (a !== null && typeof a === "object") {
    for (const key of [...new Set([...Object.keys(a), ...Object.keys(b)])].toSorted()) {
      if (!(key in a) || !(key in b)) out.push({ path: `${path}/${key}`, a: a[key], b: b[key] });
      else allDifferences(a[key], b[key], `${path}/${key}`, out);
    }
  } else if (a !== b) out.push({ path, a, b });
  return out;
}

/** The most deliveries of a group of cases that were running at the same time, from their start and end offsets. */
export function maxOverlap(projection, keys) {
  const events = [];
  for (const key of keys)
    for (const [i, start] of (projection.cases[key]?.timing.startsAtMs ?? []).entries()) {
      const end = projection.cases[key].timing.endsAtMs[i];
      if (start === null || end === null) continue;
      events.push([start, 1], [end, -1]);
    }
  // An end at the instant of a start frees its slot first.
  events.sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  let running = 0;
  let max = 0;
  for (const [, delta] of events) {
    running += delta;
    max = Math.max(max, running);
  }
  return max;
}

/** Properties of a group of cases, compared as numbers (the concurrency limits). */
export const PROPERTIES = Object.freeze([
  {
    id: "conc1-max-overlap",
    keys: ["a", "b", "c", "d"].map((n) => "conc1-" + n),
    what: "a queue with maxConcurrentDispatches 1 runs one delivery at a time",
  },
  {
    id: "conc2-max-overlap",
    keys: ["a", "b", "c", "d", "e"].map((n) => "conc2-" + n),
    what: "a queue with maxConcurrentDispatches 2 runs two deliveries at a time, and does run two",
  },
]);

export function compareProperties(left, right) {
  return PROPERTIES.map(({ id, keys, what }) => {
    const l = maxOverlap(left, keys);
    const r = maxOverlap(right, keys);
    return { id, what, left: l, right: r, verdict: l === r ? "MATCH" : "MISMATCH" };
  });
}

const within = (x, y, tolerance) => x === null || y === null || Math.abs(x - y) <= tolerance;

/** Timing of two cases: the first delivery and each gap, when both have the same number of deliveries. */
export function compareTiming(a, b, { tolerance = TOLERANCE, claim = true } = {}) {
  if (!claim) return { verdict: "NOT_COMPARED" };
  if (a.gapsMs.length !== b.gapsMs.length)
    return { verdict: "OUTSIDE", why: "attempts", a: a.gapsMs.length + 1, b: b.gapsMs.length + 1 };
  if (!within(a.firstMs, b.firstMs, tolerance.firstMs))
    return { verdict: "OUTSIDE", why: "first", a: a.firstMs, b: b.firstMs };
  for (let i = 0; i < a.gapsMs.length; i++)
    if (!within(a.gapsMs[i], b.gapsMs[i], tolerance.gapMs))
      return { verdict: "OUTSIDE", why: `gap ${i + 1}`, a: a.gapsMs[i], b: b.gapsMs[i] };
  return { verdict: "WITHIN" };
}

/**
 * @param left, right: projections (`projectRecording` output, or a local replay in the same shape).
 * @param knownDifferences: `{ id, cases: [key] | "*", part: "structure"|"timing", ruling, what }[]` (the ruling is required).
 * @param noTimingClaim: case keys whose timing is not compared (a case whose delay is the service's own latency).
 */
/**
 * Cases whose number of attempts is not fixed by the configuration (a queue with maxAttempts 100 and a retry window): the
 * deliveries are compared up to the shorter side when the counts differ by at most this many.
 */
export const ATTEMPT_JITTER = Object.freeze({ "window-six": 3 });

export function compareProjections(
  left,
  right,
  {
    knownDifferences = [],
    noTimingClaim = new Set(),
    tolerance = TOLERANCE,
    attemptJitter = ATTEMPT_JITTER,
  } = {},
) {
  for (const kd of knownDifferences)
    if (
      !kd.id ||
      !kd.ruling ||
      !kd.what ||
      !Array.isArray(kd.paths) ||
      (kd.paths.length === 0 && !kd.hide)
    )
      throw new Error(`a known difference needs an id, a ruling, a text and paths: ${kd.id}`);
  const rows = [];
  const used = new Map();
  const keys = Object.keys(left.cases);
  for (const key of Object.keys(right.cases))
    if (!keys.includes(key)) throw new Error(`case ${key} is only on the right`);
  const PARTS = ["admission", "deliveries"];
  const worst = ["MISMATCH", "UNKNOWN", "KNOWN_DIFFERENCE", "MATCH_LAYOUT", "MATCH"];
  for (const key of keys) {
    const l = left.cases[key];
    const r = right.cases[key];
    if (!r) {
      rows.push({
        case: key,
        structure: "UNKNOWN",
        parts: {},
        timing: { verdict: "NOT_COMPARED" },
        why: "absent on the right",
      });
      continue;
    }
    const rules = new Map();
    const nl = normalizeNames(l, rules);
    const nr = normalizeNames(r, new Map());
    let jitter = false;
    if (key in attemptJitter && nl.deliveries.length !== nr.deliveries.length) {
      const n = Math.min(nl.deliveries.length, nr.deliveries.length);
      if (Math.abs(nl.deliveries.length - nr.deliveries.length) <= attemptJitter[key]) {
        nl.deliveries.length = n;
        nr.deliveries.length = n;
        jitter = true;
      }
    }
    const exactL = clone(l);
    const exactR = clone(r);
    delete exactL.timing;
    delete exactR.timing;
    const parts = {};
    for (const part of PARTS) {
      const exact =
        part === "deliveries" && jitter
          ? { path: "/deliveries[length]" }
          : firstDifference(exactL[part], exactR[part]);
      const layout = firstDifference(nl[part], nr[part]);
      if (!exact) parts[part] = { verdict: "MATCH" };
      else if (!layout) parts[part] = { verdict: "MATCH_LAYOUT" };
      else {
        // Every difference must be covered by a known difference of this part and case; one that is not makes the case a mismatch.
        const covered = new Set();
        const uncovered = [];
        // A known difference may hide a part of a delivery on both sides first (the headers Cloud Run adds, the identity token).
        const hl = clone(nl[part]);
        const hr = clone(nr[part]);
        if (part === "deliveries")
          for (const kd of knownDifferences.filter(
            (k) => k.part === part && k.hide && (k.cases === "*" || k.cases.includes(key)),
          ))
            for (const side of [hl, hr])
              for (const delivery of side) if (kd.hide(delivery)) covered.add(kd.id);
        for (const d of allDifferences(hl, hr)) {
          const plain = d.path.replace(/\[\d+\]/g, "[]");
          const kd = knownDifferences.find(
            (k) =>
              k.part === part &&
              (k.cases === "*" || k.cases.includes(key)) &&
              k.paths.some((re) => re.test(plain)),
          );
          if (kd) covered.add(kd.id);
          else uncovered.push({ path: d.path, left: d.a, right: d.b });
        }
        parts[part] =
          uncovered.length === 0
            ? { verdict: "KNOWN_DIFFERENCE", knownDifferences: [...covered].toSorted() }
            : { verdict: "MISMATCH", uncovered: uncovered.slice(0, 5), count: uncovered.length };
        if (parts[part].verdict === "KNOWN_DIFFERENCE" && parts[part].knownDifferences.length === 0)
          parts[part] = { verdict: "MATCH_LAYOUT" };
      }
      if (parts[part].verdict === "MATCH_LAYOUT" || (parts[part].verdict === "MATCH" && false)) {
        /* counted below */
      }
    }
    if (Object.values(parts).some((p) => p.verdict === "MATCH_LAYOUT")) {
      for (const [id, n] of rules) used.set(id, (used.get(id) ?? 0) + (n > 0 ? 1 : 0));
      if (jitter) used.set("attempt-count-jitter", (used.get("attempt-count-jitter") ?? 0) + 1);
    }
    const structure =
      worst.find((v) => Object.values(parts).some((p) => p.verdict === v)) ?? "MATCH";
    let timing = compareTiming(l.timing, r.timing, { tolerance, claim: !noTimingClaim.has(key) });
    let timingKnown = null;
    if (timing.verdict === "OUTSIDE") {
      timingKnown = knownDifferences.find(
        (kd) => kd.part === "timing" && (kd.cases === "*" || kd.cases.includes(key)),
      );
      if (timingKnown) timing = { ...timing, verdict: "KNOWN_DIFFERENCE" };
    }
    rows.push({
      case: key,
      structure,
      parts,
      timing,
      ...(timingKnown ? { timingKnownDifference: timingKnown.id } : {}),
    });
  }
  const count = (field, extract) => {
    const summary = {};
    for (const row of rows) summary[extract(row)] = (summary[extract(row)] ?? 0) + 1;
    return summary;
  };
  return {
    schemaVersion: 1,
    left: { alias: left.alias, corpusSha256: left.corpusSha256 },
    right: { alias: right.alias, corpusSha256: right.corpusSha256 },
    tolerance,
    layoutRules: [
      ...LAYOUT_RULES.map(({ id, what }) => ({ id, what, rows: used.get(id) ?? 0 })),
      {
        id: "attempt-count-jitter",
        what:
          "the number of attempts of a queue whose retry window does not bound them differs by at most " +
          JSON.stringify(attemptJitter),
        rows: used.get("attempt-count-jitter") ?? 0,
      },
    ],
    knownDifferences: knownDifferences.map(({ id, cases, part, ruling, what, paths }) => ({
      id,
      cases,
      part,
      ruling,
      what,
      paths: paths.map(String),
      rows: rows.filter((row) =>
        Object.values(row.parts).some((p) => p.knownDifferences?.includes(id)),
      ).length,
    })),
    properties: compareProperties(left, right),
    summary: {
      structure: count("structure", (row) => row.structure),
      admission: count("admission", (row) => row.parts.admission?.verdict ?? "UNKNOWN"),
      deliveries: count("deliveries", (row) => row.parts.deliveries?.verdict ?? "UNKNOWN"),
      timing: count("timing", (row) => row.timing.verdict),
    },
    rows,
    digest: digestOf(rows),
  };
}
