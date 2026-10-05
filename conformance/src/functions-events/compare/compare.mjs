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
// Owner ledger 840: the document field maps of a Gen2 Firestore event are compared unordered (values still exactly); Gen1 and every
// other member keep their order comparison.
export const GEN2_FIRESTORE_FIELD_MAPS = Object.freeze([
  "$.frame.event.data.data",
  "$.frame.event.data.before.data",
  "$.frame.event.data.after.data",
]);

// The retry rows carry the same Gen2 Firestore document field maps under the attempt they belong to (observeProductionPass and
// observeLocal build `$.failed` and `$.succeeded` from the failed and the succeeded frame), so the ruling covers them there.
const RETRY_RECIPE = "functions-events/delivery/retry";
export const RETRY_FIRESTORE_FIELD_MAPS = Object.freeze(
  ["failed", "succeeded"].flatMap((attempt) =>
    ["data", "before.data", "after.data"].map((map) => `$.${attempt}.event.data.${map}`),
  ),
);

/** The predicate naming the objects whose member order a row does not compare, or none. */
export function orderIgnoredFor(row, scenario) {
  if (row.generation !== 2 || scenario.source !== "firestore") return () => false;
  const roots =
    row.recipeId === RETRY_RECIPE ? RETRY_FIRESTORE_FIELD_MAPS : GEN2_FIRESTORE_FIELD_MAPS;
  return (path) =>
    roots.some(
      (root) => path === root || path.startsWith(`${root}.`) || path.startsWith(`${root}[`),
    );
}

// Values a row compares by shape, not by value (declared, with the reason):
//  - the Pub/Sub v2 `data.subscription` names the subscription Eventarc made for the deployment, `eventarc-<region>-<function>-
//    <6 digits>-sub-<3 digits>`; production draws the two numbers per deployment (FE v5 834054/834, FE v7 293232/576: fixed within
//    a deployment, so the two passes of one run cannot show it varying) and fireemu derives its own, so the numbers are masked and
//    the rest, the shape, is compared;
//  - the `authId` of an auth-context write is the id of the credential that wrote: production prints the recorder's own (its email
//    for the user credential, a uid for an ID-token write), which a local session cannot have, so only that a non-empty string is
//    present is compared (the `authType` beside it is compared exactly).
const maskSubscription = (value) =>
  value.replace(/-\d{6}-sub-\d{3}$/, "-<6 digits>-sub-<3 digits>");
const maskPresent = (value) => (value.length > 0 ? "<present>" : value);

/** The declared masks of a row: `{ path, mask }` entries (see above), or none. */
export function declaredMasksFor(row, scenario) {
  const masks = [];
  if (row.generation === 2 && scenario.source === "pubsub")
    masks.push({ path: "$.frame.event.data.subscription", mask: maskSubscription });
  if (row.recipeId === "functions-events/firestore/auth-context" && scenario.source === "firestore")
    masks.push({ path: "$.frame.event.authId", mask: maskPresent });
  return masks;
}

/** A copy of a flattened observation with the declared masks applied to the string values at their paths. */
export function applyDeclaredMasks(observation, masks) {
  if (masks.length === 0) return observation;
  const masked = new Map(observation);
  for (const { path, mask } of masks) {
    const leaf = masked.get(path);
    if (leaf?.type === "string") masked.set(path, { ...leaf, value: mask(leaf.value) });
  }
  return masked;
}

const NEGATIVE = "none-in-window";
const RETRY = "failed-then-succeeded-same-event";

/** The worst status of a list (DIFF over INCOMPLETE over MATCH); an empty list is MATCH. */
export const worstStatus = (statuses) =>
  statuses.reduce((worst, status) => (RANK[status] > RANK[worst] ? status : worst), "MATCH");

const byText = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
const result = (status, reasons, extra = {}) => ({ status, reasons, ...extra });
const incomplete = (...reasons) => result("INCOMPLETE", reasons.flat());
const isObject = (value) => value !== null && typeof value === "object" && !Array.isArray(value);

const isText = (value) => typeof value === "string" && value.length > 0;

/**
 * True when a frame names a resource the way resourceMatches reads it (session.mjs). A frame that
 * names a resource no operation owns cannot be a subject's event; one that names none could be.
 */
export function resourceIdentified(frame) {
  const event = frame.event ?? {};
  const data = event.data ?? {};
  switch (frame.source) {
    case "firestore":
      return [
        data.path,
        data.before?.path,
        data.after?.path,
        event.subject,
        event.context?.resource?.name,
      ].some(isText);
    case "storage":
      return isText(data.name);
    case "auth":
      return isText(data.uid);
    case "pubsub":
      return [data.message?.messageId, data.messageId, event.context?.eventId].some(isText);
    default:
      return false;
  }
}

/**
 * For every production frame, the operations it matches by resource and by time (`attributionMs`). A frame inside an
 * operation's call window is that operation's. A frame within the tolerance of a window is that operation's only when no
 * other operation of the same resource could own it too; with two or more candidates, or no time, it is attributed to none
 * (`nearOf`), so the ambiguity fails closed.
 */
export function attribute(production, toleranceMs) {
  const operations = production.passes.flatMap((pass) => pass.operations);
  const attribution = new Map();
  for (const frame of production.frames) {
    const entry = { resourceOf: [], subjectOf: [], nearOf: [], identified: false };
    attribution.set(frame, entry);
    if (!isObject(frame.frame)) continue;
    entry.identified = resourceIdentified(frame.frame);
    const nearByTime = [];
    for (const op of operations) {
      if (!validMatchKey(op.matchKey) || !resourceMatches(frame.frame, op.matchKey)) continue;
      entry.resourceOf.push(op);
      if (frame.attributionMs === null || op.startMs === null || op.endMs === null) {
        entry.nearOf.push(op);
      } else if (frame.attributionMs >= op.startMs && frame.attributionMs <= op.endMs) {
        entry.subjectOf.push(op);
      } else if (
        frame.attributionMs >= op.startMs - toleranceMs &&
        frame.attributionMs <= op.endMs + toleranceMs
      ) {
        entry.nearOf.push(op);
        nearByTime.push(op);
      }
    }
    if (entry.subjectOf.length === 0 && entry.nearOf.length === 1 && nearByTime.length === 1) {
      entry.subjectOf = nearByTime;
      entry.nearOf = [];
    }
  }
  return attribution;
}

/** At-least-once duplicates of one event print the same frame; otherwise no representative exists. */
const allSame = (frames) =>
  frames.every((frame) => JSON.stringify(frame) === JSON.stringify(frames[0]));

function retryObservation(frames, label, handler, windowSeconds, frameOf) {
  const printed = frames.map(frameOf);
  const attempts = (kind) => printed.filter((frame) => frame.event?.data?.fixtureAttempt === kind);
  const failed = attempts("failed");
  const succeeded = attempts("succeeded");
  if (failed.length + succeeded.length !== printed.length) {
    return incomplete(`${label}: ${handler} frame(s) without a fixture attempt`);
  }
  const reasons = [];
  for (const [kind, list] of [
    ["failed", failed],
    ["succeeded", succeeded],
  ]) {
    if (list.length === 0) {
      reasons.push(`${label}: no ${kind} ${handler} attempt in the ${windowSeconds} s window`);
    } else if (!allSame(list)) {
      reasons.push(`${label}: ${list.length} ${kind} ${handler} frames differ from each other`);
    }
  }
  if (reasons.length > 0) return incomplete(reasons);
  const [first] = failed;
  const [pair] = succeeded;
  return result("OK", [], {
    observation: {
      retry: {
        sameEventId: pair.event.id === first.event.id,
        sameSource: pair.event.source === first.event.source,
        sameTime: pair.event.time === first.event.time,
      },
      failed: first,
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
  // The source readbacks are recorded for review, not compared: production REST answers and the local SDK's
  // readbacks have different shapes, and every delivered field already sits in the frames.
  const base = { sourceResult: op.sourceResult };
  const table = placeholderTable({ matchKey: op.matchKey, project: production.project });

  if (row.delivery === NEGATIVE) {
    if (subject.length > 0) {
      return result("DIFF", [
        `${label}: ${handler} delivered ${subject.length} frame(s) on a no-event case`,
      ]);
    }
    const unidentified = handlerFrames.filter(
      (frame) =>
        !attribution.get(frame).identified && !(frame.logMs !== null && frame.logMs < op.startMs),
    );
    if (unidentified.length > 0) {
      reasons.push(
        `${label}: ${unidentified.length} ${handler} frame(s) with no identifiable resource during or after the observation`,
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
  if (subject.length === 0) {
    return incomplete(`${label}: no ${handler} frame in the ${windowSeconds} s window`);
  }
  const listings = [];
  const strip = (frame) => {
    const { frame: stripped, listing } = splitProductionOnly(frame.frame);
    listings.push(listing);
    return stripped;
  };
  if (row.delivery === RETRY) {
    const retry = retryObservation(subject, label, handler, windowSeconds, strip);
    if (retry.status !== "OK") return retry;
    return result("OK", [], {
      observation: applyPlaceholders({ ...base, ...retry.observation }, table),
      listings: listings.map((listing) => applyPlaceholders(listing, table)),
    });
  }
  const stripped = subject.map(strip);
  if (!allSame(stripped)) {
    return incomplete(
      `${label}: ${stripped.length} ${handler} frames of the subject differ from each other`,
    );
  }
  return result("OK", [], {
    observation: applyPlaceholders({ ...base, frame: stripped[0] }, table),
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
  const frames = op.frames[row.generation];
  if (frames.some(({ frame }) => frame.handler !== handler)) {
    return incomplete(`${profile}: a local frame belongs to another handler than ${handler}`);
  }
  // The source readbacks are recorded for review, not compared: production REST answers and the local SDK's
  // readbacks have different shapes, and every delivered field already sits in the frames.
  const base = { sourceResult: op.sourceResult };
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
  const stripped = frames.map(strip);
  if (!allSame(stripped)) {
    return incomplete(
      `${profile}: ${stripped.length} local ${handler} frames differ from each other`,
    );
  }
  return result("OK", [], {
    observation: applyPlaceholders({ ...base, frame: stripped[0] }, table),
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
    // What each profile's verdict rests on: the production observation (a fault of the recording counts for both profiles)
    // and that profile's own local observation and comparison. The row keeps the combined status and reasons as before.
    const sides = {
      production: { statuses: [], reasons: [] },
      ...Object.fromEntries(PROFILES.map((profile) => [profile, { statuses: [], reasons: [] }])),
    };
    const passes = production.passes.map((pass) =>
      observeProductionPass({ production, attribution, pass, row, scenario, handler, toleranceMs }),
    );
    const localResults = PROFILES.map((profile) =>
      observeLocal({ local: locals[profile], profile, row, scenario, handler, localProject }),
    );
    const note = (side, status, found) => {
      statuses.push(status);
      reasons.push(...found);
      sides[side].statuses.push(status);
      sides[side].reasons.push(...found);
    };
    passes.forEach((observed) => {
      if (observed.status !== "OK") note("production", observed.status, observed.reasons);
    });
    localResults.forEach((observed, index) => {
      if (observed.status !== "OK") note(PROFILES[index], observed.status, observed.reasons);
    });
    let productionOnly = {};
    if (passes.every(({ status }) => status === "OK")) {
      productionOnly = mergeListings(passes.flatMap(({ listings }) => listings ?? []));
      const masks = declaredMasksFor(row, scenario);
      const reference = applyDeclaredMasks(flatten(passes[0].observation), masks);
      const orderIgnored = orderIgnoredFor(row, scenario);
      const { disagreements, volatile } = deriveVolatile(
        reference,
        applyDeclaredMasks(flatten(passes[1].observation), masks),
        {
          orderIgnored,
        },
      );
      volatilePaths[`${handler}/${scenario.id}`] = plainVolatile(volatile);
      if (disagreements.length > 0) {
        note(
          "production",
          "INCOMPLETE",
          disagreements.map((reason) => `production passes disagree: ${reason}`),
        );
      } else {
        PROFILES.forEach((profile, index) => {
          if (localResults[index].status !== "OK") return;
          const found = compareObservation(
            reference,
            volatile,
            applyDeclaredMasks(flatten(localResults[index].observation), masks),
            profile,
            { orderIgnored },
          );
          if (found.length > 0) note(profile, "DIFF", found);
        });
      }
    }
    const profiles = Object.fromEntries(
      PROFILES.map((profile) => [
        profile,
        {
          status: worstStatus([...sides.production.statuses, ...sides[profile].statuses]),
          reasons: [...sides.production.reasons, ...sides[profile].reasons],
        },
      ]),
    );
    const productionSide = {
      status: worstStatus(sides.production.statuses),
      reasons: sides.production.reasons,
    };
    return {
      row: `${row.recipeId}#${row.case}#v${row.generation}`,
      caseId: row.id,
      conditionId: row.conditionId,
      case: row.case,
      generation: row.generation,
      scenarioId: scenario.id,
      handler,
      delivery: row.delivery,
      status: worstStatus(statuses),
      reasons,
      production: productionSide,
      profiles,
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
      unowned: entries.filter((entry) => entry.identified && entry.resourceOf.length === 0).length,
      unidentified: entries.filter((entry) => !entry.identified).length,
      lifecycle: entries.filter(
        (entry) =>
          entry.resourceOf.length > 0 && entry.subjectOf.length === 0 && entry.nearOf.length === 0,
      ).length,
      unattributable: entries.filter((entry) => entry.nearOf.length > 0).length,
      multiplyAttributed: entries.filter((entry) => entry.subjectOf.length > 1).length,
    },
  };
}
