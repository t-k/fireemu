// Offline comparison of one production run record with the local driver sessions (record-schema.md,
// decisions E8 and E9 of the frozen closure). Pure: no I/O, no clock. Every row is MATCH only when
// both production passes agree with each other and both local profiles agree with production on the
// deterministic observation of its case; anything unobserved or unattributable is INCOMPLETE with a
// reason, and an observed difference (including a late frame) is a DIFF.
import { resourceMatches } from "../session.mjs";
import { fromLocalSession, fromProductionRun, validMatchKey } from "./adapters.mjs";
import { compareObservation, deriveVolatile } from "./diff.mjs";
import { applyPlaceholders, flatten, placeholderTable, splitProductionOnly } from "./normalize.mjs";

/**
 * A frame whose event time lies this close outside an operation's source call (recorder clock vs
 * the service's event time) cannot be told apart from that operation's own event, so it is
 * reported as unattributable instead of being guessed either way.
 */
export const ATTRIBUTION_TOLERANCE_MS = 1000;
export const PROFILES = ["emulator", "strict"];
const RANK = { MATCH: 0, INCOMPLETE: 1, DIFF: 2 };
const NEGATIVE = "none-in-window";
const RETRY = "failed-then-succeeded-same-event";

/** The worst status of a list (DIFF over INCOMPLETE over MATCH); an empty list is MATCH. */
export const worstStatus = (statuses) =>
  statuses.reduce((worst, status) => (RANK[status] > RANK[worst] ? status : worst), "MATCH");

const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const result = (status, reasons, extra = {}) => ({ status, reasons, ...extra });
const incomplete = (...reasons) => result("INCOMPLETE", reasons.flat());
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

/** For every production frame, the operations it matches by resource and by event time. */
function attribute(production, toleranceMs) {
  const operations = production.passes.flatMap((pass) => pass.operations);
  const attribution = new Map();
  for (const frame of production.frames) {
    const entry = { resourceOf: [], subjectOf: [], nearOf: [] };
    attribution.set(frame, entry);
    if (!isObject(frame.frame)) continue;
    for (const op of operations) {
      if (!validMatchKey(op.matchKey) || !resourceMatches(frame.frame, op.matchKey)) continue;
      entry.resourceOf.push(op);
      if (frame.eventMs === null || op.startMs === null || op.endMs === null) {
        entry.nearOf.push(op);
      } else if (frame.eventMs >= op.startMs && frame.eventMs <= op.endMs) {
        entry.subjectOf.push(op);
      } else if (
        frame.eventMs >= op.startMs - toleranceMs &&
        frame.eventMs <= op.endMs + toleranceMs
      ) {
        entry.nearOf.push(op);
      }
    }
  }
  return attribution;
}

const byLogTime = (a, b) => a.logMs - b.logMs || byText(a.insertId, b.insertId);

function retryObservation(frames, label, handler, windowSeconds, frameOf) {
  const attempts = (kind) =>
    frames.filter((frame) => frameOf(frame).event?.data?.fixtureAttempt === kind);
  const failed = attempts("failed");
  const succeeded = attempts("succeeded");
  if (failed.length + succeeded.length !== frames.length) {
    return incomplete(`${label}: ${handler} frame(s) without a fixture attempt`);
  }
  const missing = [];
  if (failed.length === 0)
    missing.push(`${label}: no failed ${handler} attempt in the ${windowSeconds} s window`);
  if (succeeded.length === 0) {
    missing.push(`${label}: no succeeded ${handler} attempt in the ${windowSeconds} s window`);
  }
  if (missing.length > 0) return incomplete(missing);
  const first = frameOf(failed[0]).event;
  const same = (frame) =>
    typeof first.id === "string" && first.id.length > 0 && frameOf(frame).event.id === first.id;
  const pair = frameOf(succeeded.find(same) ?? succeeded[0]);
  return result("OK", [], {
    observation: {
      retry: {
        sameEventId: pair.event.id === first.id,
        sameSource: pair.event.source === first.source,
        sameTime: pair.event.time === first.time,
      },
      failed: frameOf(failed[0]),
      succeeded: pair,
    },
  });
}

function observeProductionPass({
  production,
  attribution,
  pass,
  row,
  scenario,
  handler,
  toleranceMs,
}) {
  const label = `production pass ${pass.pass}`;
  const subjects = pass.operations.filter(
    (op) => op.scenarioId === scenario.id && op.role === "subject",
  );
  if (subjects.length !== 1) {
    return incomplete(`${label}: ${subjects.length} subject operations for ${scenario.id}`);
  }
  const [op] = subjects;
  if (op.issues.length > 0) return incomplete(op.issues.map((issue) => `${label}: ${issue}`));
  if (op.sourceResult !== scenario.sourceResult) {
    return incomplete(
      `${label}: source call returned ${op.sourceResult}, the corpus expects ${scenario.sourceResult}`,
    );
  }
  const windowSeconds = row.window.maximumSeconds;
  const windowEnd = op.endMs + windowSeconds * 1000;
  const handlerFrames = production.frames.filter((frame) => frame.handler === handler);
  const mine = handlerFrames.filter((frame) => attribution.get(frame).resourceOf.includes(op));
  const near = mine.filter((frame) => attribution.get(frame).nearOf.includes(op));
  const subject = mine.filter((frame) => attribution.get(frame).subjectOf.includes(op));
  const reasons = [];
  if (near.length > 0) {
    reasons.push(
      `${label}: ${near.length} ${handler} frame(s) of the subject cannot be attributed (no event time, or within ${toleranceMs} ms of the source call)`,
    );
  }
  for (const frame of subject) {
    for (const issue of frame.issues) reasons.push(`${label}: ${issue}`);
    if (attribution.get(frame).subjectOf.length > 1) {
      reasons.push(`${label}: a ${handler} frame matches more than one operation`);
    }
  }
  const base = { sourceResult: op.sourceResult, readback: op.readback ?? null };
  const table = placeholderTable({ matchKey: op.matchKey, project: production.project });

  if (row.delivery === NEGATIVE) {
    if (subject.length > 0) {
      return result("DIFF", [
        `${label}: ${handler} delivered ${subject.length} frame(s) on a no-event case`,
      ]);
    }
    if (reasons.length > 0) return incomplete([...new Set(reasons)]);
    const foreign = handlerFrames.filter(
      (frame) =>
        attribution.get(frame).resourceOf.length === 0 &&
        !(frame.logMs !== null && frame.logMs < op.startMs),
    );
    if (foreign.length > 0) {
      reasons.push(
        `${label}: ${foreign.length} ${handler} frame(s) correlate with no operation during or after the observation`,
      );
    }
    const others = new Set(pass.operations.filter((other) => other !== op));
    const controls = handlerFrames.filter((frame) => {
      const { subjectOf } = attribution.get(frame);
      return frame.issues.length === 0 && subjectOf.length === 1 && others.has(subjectOf[0]);
    });
    if (!controls.some((frame) => frame.logMs < op.startMs)) {
      reasons.push(`${label}: no positive ${handler} frame before the operation`);
    }
    if (!controls.some((frame) => frame.logMs > windowEnd)) {
      reasons.push(`${label}: no positive ${handler} frame after the window`);
    }
    if (reasons.length > 0) return incomplete(reasons);
    return result("OK", [], {
      observation: applyPlaceholders({ ...base, delivered: false }, table),
    });
  }

  const late = subject.filter((frame) => frame.logMs > windowEnd);
  if (late.length > 0) {
    return result("DIFF", [
      `${label}: ${late.length} ${handler} frame(s) arrived after the ${windowSeconds} s window`,
    ]);
  }
  if (reasons.length > 0) return incomplete([...new Set(reasons)]);
  const inWindow = [...subject].sort(byLogTime);
  if (inWindow.length === 0) {
    return incomplete(`${label}: no ${handler} frame in the ${windowSeconds} s window`);
  }
  const listings = [];
  const strip = (frame) => {
    const { frame: stripped, listing } = splitProductionOnly(frame.frame);
    listings.push(listing);
    return stripped;
  };
  if (row.delivery === RETRY) {
    const retry = retryObservation(inWindow, label, handler, windowSeconds, strip);
    if (retry.status !== "OK") return retry;
    return result("OK", [], {
      observation: applyPlaceholders({ ...base, ...retry.observation }, table),
      listings: listings.map((listing) => applyPlaceholders(listing, table)),
    });
  }
  return result("OK", [], {
    observation: applyPlaceholders({ ...base, frame: strip(inWindow[0]) }, table),
    listings: listings.map((listing) => applyPlaceholders(listing, table)),
  });
}

function localControl(operations, from, step, role, generation) {
  for (let index = from + step; index >= 0 && index < operations.length; index += step) {
    const candidate = operations[index];
    if (candidate.role !== role) continue;
    return (
      candidate.issues.length === 0 &&
      candidate.status !== "INCOMPLETE" &&
      candidate.frames[generation].length > 0
    );
  }
  return false;
}

function observeLocal({ local, profile, row, scenario, handler, localProject }) {
  const program = local.programs.get(row.recipeId);
  if (!program) return incomplete(`${profile}: local session has no ${row.recipeId} program`);
  const subjects = program.operations.filter(
    (op) => op.scenarioId === scenario.id && op.role === "subject",
  );
  if (subjects.length !== 1) {
    return incomplete(`${profile}: ${subjects.length} local subject operations for ${scenario.id}`);
  }
  const [op] = subjects;
  if (op.issues.length > 0) return incomplete(op.issues.map((issue) => `${profile}: ${issue}`));
  if (op.status === "INCOMPLETE") {
    return incomplete(`${profile}: the local driver marked the operation INCOMPLETE`);
  }
  const frames = [...op.frames[row.generation]].sort((a, b) => a.sequence - b.sequence);
  if (frames.some(({ frame }) => frame.handler !== handler)) {
    return incomplete(`${profile}: a local frame belongs to another handler than ${handler}`);
  }
  const base = { sourceResult: op.sourceResult, readback: op.readback ?? null };
  const table = placeholderTable({ matchKey: op.matchKey, project: localProject });
  if (row.delivery === NEGATIVE) {
    if (frames.length > 0) {
      return result("DIFF", [
        `${profile}: ${handler} delivered ${frames.length} frame(s) on a no-event case`,
      ]);
    }
    const reasons = [];
    if (
      !localControl(program.operations, op.index, -1, "positive-control-before", row.generation)
    ) {
      reasons.push(`${profile}: no positive ${handler} control before the operation`);
    }
    if (!localControl(program.operations, op.index, 1, "positive-control-after", row.generation)) {
      reasons.push(`${profile}: no positive ${handler} control after the operation`);
    }
    if (reasons.length > 0) return incomplete(reasons);
    return result("OK", [], {
      observation: applyPlaceholders({ ...base, delivered: false }, table),
    });
  }
  if (frames.length === 0) return incomplete(`${profile}: no local ${handler} frame`);
  const strip = ({ frame }) => splitProductionOnly(frame).frame;
  if (row.delivery === RETRY) {
    const retry = retryObservation(frames, profile, handler, row.window.maximumSeconds, strip);
    if (retry.status !== "OK") return retry;
    return result("OK", [], {
      observation: applyPlaceholders({ ...base, ...retry.observation }, table),
    });
  }
  return result("OK", [], {
    observation: applyPlaceholders({ ...base, frame: strip(frames[0]) }, table),
  });
}

function mergeListings(listings) {
  const merged = {};
  for (const listing of listings) {
    for (const [path, names] of Object.entries(listing)) {
      merged[path] = [...new Set([...(merged[path] ?? []), ...names])].sort(byText);
    }
  }
  return Object.fromEntries(Object.entries(merged).sort(([a], [b]) => byText(a, b)));
}

function plainVolatile(volatile) {
  return Object.fromEntries(
    [...volatile.entries()].map(([path, features]) => [path, [...features]]),
  );
}

function frozenCases({ corpus, programs }) {
  if (!Array.isArray(corpus?.cases) || !Array.isArray(corpus?.scenarios)) {
    throw new TypeError("corpus must list cases and scenarios");
  }
  if (!Array.isArray(programs?.programs)) throw new TypeError("programs must list programs");
  const cases = new Map(corpus.cases.map((row) => [row.id, row]));
  const scenarios = new Map(corpus.scenarios.map((scenario) => [scenario.id, scenario]));
  return programs.programs.flatMap((program) =>
    program.caseIds.map((caseId) => {
      const row = cases.get(caseId);
      if (!row || row.recipeId !== program.recipeId) {
        throw new TypeError(`programs list an unknown case ${caseId} for ${program.recipeId}`);
      }
      const handler = program.handlerExports?.[`v${row.generation}`];
      const scenario = scenarios.get(row.scenario);
      if (!handler || !scenario || !row.window || !Number.isFinite(row.window.maximumSeconds)) {
        throw new TypeError(`case ${caseId} has no handler, scenario or window`);
      }
      return { row, handler, scenario };
    }),
  );
}

/**
 * Compare a production run record with the emulator and strict local sessions.
 * Returns rows (one per frozen case id of programs.json), the summary, the volatile paths derived
 * from the two production passes, the condition results (worst row) and frame accounting.
 */
export function compareRuns({
  corpus,
  programs,
  productionRun,
  localSessions,
  localProject,
  toleranceMs = ATTRIBUTION_TOLERANCE_MS,
}) {
  if (typeof localProject !== "string" || localProject.length === 0) {
    throw new TypeError("localProject (the project id of the local sessions) is required");
  }
  for (const profile of PROFILES) {
    if (!localSessions?.[profile])
      throw new TypeError(`local session for profile ${profile} is required`);
  }
  const frozen = frozenCases({ corpus, programs });
  const production = fromProductionRun(productionRun);
  const locals = Object.fromEntries(
    PROFILES.map((profile) => [profile, fromLocalSession(localSessions[profile])]),
  );
  const attribution = attribute(production, toleranceMs);
  const volatilePaths = {};
  const rows = frozen.map(({ row, handler, scenario }) => {
    const reasons = [];
    const statuses = [];
    const passes = production.passes.map((pass) =>
      observeProductionPass({ production, attribution, pass, row, scenario, handler, toleranceMs }),
    );
    const localResults = PROFILES.map((profile) =>
      observeLocal({ local: locals[profile], profile, row, scenario, handler, localProject }),
    );
    for (const observed of [...passes, ...localResults]) {
      if (observed.status === "OK") continue;
      statuses.push(observed.status);
      reasons.push(...observed.reasons);
    }
    let productionOnly = {};
    if (passes.every(({ status }) => status === "OK")) {
      productionOnly = mergeListings(passes.flatMap(({ listings }) => listings ?? []));
      const reference = flatten(passes[0].observation);
      const { disagreements, volatile } = deriveVolatile(reference, flatten(passes[1].observation));
      volatilePaths[`${handler}/${scenario.id}`] = plainVolatile(volatile);
      if (disagreements.length > 0) {
        statuses.push("INCOMPLETE");
        reasons.push(...disagreements.map((reason) => `production passes disagree: ${reason}`));
      } else {
        PROFILES.forEach((profile, index) => {
          if (localResults[index].status !== "OK") return;
          const found = compareObservation(
            reference,
            volatile,
            flatten(localResults[index].observation),
            profile,
          );
          if (found.length > 0) {
            statuses.push("DIFF");
            reasons.push(...found);
          }
        });
      }
    }
    const program = programs.programs.find((candidate) => candidate.caseIds.includes(row.id));
    return {
      row: `${program.recipeId}#${row.case}#v${row.generation}`,
      caseId: row.id,
      conditionId: row.conditionId,
      case: row.case,
      generation: row.generation,
      scenarioId: scenario.id,
      handler,
      delivery: row.delivery,
      status: worstStatus(statuses),
      reasons,
      ...(Object.keys(productionOnly).length > 0 ? { productionOnly } : {}),
    };
  });

  const conditions = {};
  for (const row of rows)
    conditions[row.conditionId] = worstStatus([conditions[row.conditionId] ?? "MATCH", row.status]);
  const count = (status) => rows.filter((row) => row.status === status).length;
  const handlers = new Set(
    programs.programs.flatMap((program) => Object.values(program.handlerExports)),
  );
  const entries = production.frames.map((frame) => attribution.get(frame));
  return {
    rows,
    summary: {
      rows: rows.length,
      match: count("MATCH"),
      diff: count("DIFF"),
      incomplete: count("INCOMPLETE"),
    },
    volatilePaths: Object.fromEntries(
      Object.entries(volatilePaths).sort(([a], [b]) => byText(a, b)),
    ),
    conditions: Object.fromEntries(Object.entries(conditions).sort(([a], [b]) => byText(a, b))),
    frameAccounting: {
      frames: production.frames.length,
      duplicateReads: production.duplicateFrames,
      withIssues: production.frames.filter((frame) => frame.issues.length > 0).length,
      unknownHandlers: [
        ...new Set(
          production.frames.map((frame) => frame.handler).filter((name) => !handlers.has(name)),
        ),
      ]
        .map(String)
        .sort(byText),
      foreign: entries.filter((entry) => entry.resourceOf.length === 0).length,
      lifecycle: entries.filter(
        (entry) =>
          entry.resourceOf.length > 0 && entry.subjectOf.length === 0 && entry.nearOf.length === 0,
      ).length,
      unattributable: entries.filter((entry) => entry.nearOf.length > 0).length,
      multiplyAttributed: entries.filter((entry) => entry.subjectOf.length > 1).length,
    },
  };
}
