// The fixed CV14 write sequence and the pure judgement of what the handlers printed for it. Nothing
// here talks to a service: the recorder sends the writes and collects the frames, and this module says
// which frame belongs to which write and how each handler's deliveries compare with what the
// documentation says a trigger delivers. Production is the oracle: the documented column marks where an
// observation departs from the documentation, it never decides what production did.

import { isDeepStrictEqual } from "node:util";

import { FIXTURE_HANDLERS, PREFIX } from "./frames.mjs";

/** Nine writes under the run prefix; the last two carry no token (the UNAUTHENTICATED context). */
export const STEPS = Object.freeze(
  [
    ["s1", "create item a", "PUT", "items/a", { n: 1, tag: "one" }, "admin"],
    ["s2", "update a child of a", "PATCH", "items/a", { n: 2 }, "admin"],
    ["s3", "write the same value again (no-op)", "PUT", "items/a", { n: 2, tag: "one" }, "admin"],
    ["s4", "delete item a", "DELETE", "items/a", undefined, "admin"],
    [
      "s5",
      "create item b with a nested object",
      "PUT",
      "items/b",
      { n: 1, nested: { x: 1, y: { z: 1 } } },
      "admin",
    ],
    ["s6", "update a nested child of b", "PATCH", "items/b/nested", { x: 2 }, "admin"],
    ["s7", "write a sibling path with no handler", "PUT", "other/x", { n: 1 }, "admin"],
    ["s8", "create item c without a token", "PUT", "items/c", { n: 1 }, "anonymous"],
    ["s9", "delete item c without a token", "DELETE", "items/c", undefined, "anonymous"],
  ].map(([id, label, method, path, body, context]) =>
    Object.freeze({ id, label, method, path: `${PREFIX}/${path}`, body, context }),
  ),
);

const HANDLERS = new Map(FIXTURE_HANDLERS.map((handler) => [handler.name, handler]));

const clone = (value) => (value === undefined ? undefined : structuredClone(value));

/** Removes null leaves and objects left empty: the tree RTDB stores. */
function prune(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  const out = {};
  for (const [key, child] of Object.entries(value)) {
    const kept = prune(child);
    if (kept === null || kept === undefined) continue;
    if (typeof kept === "object" && !Array.isArray(kept) && Object.keys(kept).length === 0)
      continue;
    out[key] = kept;
  }
  return out;
}

function setAt(root, segments, value) {
  if (segments.length === 0) return value === null || value === undefined ? {} : clone(value);
  const tree = typeof root === "object" && root !== null && !Array.isArray(root) ? root : {};
  const [head, ...rest] = segments;
  tree[head] = setAt(tree[head], rest, value);
  return tree;
}

/** The tree after one REST write: PUT replaces, PATCH merges children, DELETE and null remove. The input is not changed. */
export function applyWrite(tree, method, segments, body) {
  let next = clone(tree);
  if (method === "PUT") next = setAt(next, segments, body);
  else if (method === "DELETE") next = setAt(next, segments, null);
  else if (method === "PATCH") {
    for (const [key, value] of Object.entries(body ?? {}))
      next = setAt(next, [...segments, key], value);
  } else throw new Error(`unknown method ${method}`);
  return prune(next);
}

const itemOf = (tree, id) => tree?.[PREFIX]?.items?.[id] ?? null;

/** For every step, the item it touches and that item's value before and after (null: absent). */
export function itemTransitions(steps = STEPS) {
  let tree = {};
  return steps.map((step) => {
    const segments = step.path.split("/");
    const id = segments[0] === PREFIX && segments[1] === "items" ? segments[2] : null;
    const before = id === null ? null : clone(itemOf(tree, id));
    tree = applyWrite(tree, step.method, segments, step.body);
    const after = id === null ? null : clone(itemOf(tree, id));
    return { step: step.id, id, before, after };
  });
}

/** What the documentation says an event kind delivers for an item going from `before` to `after`. */
export function documentedFires(event, before, after) {
  if (event === "create") return before === null && after !== null;
  if (event === "delete") return before !== null && after === null;
  if (event === "update")
    return before !== null && after !== null && !isDeepStrictEqual(before, after);
  if (event === "write") return !isDeepStrictEqual(before, after);
  throw new Error(`unknown event kind ${event}`);
}

const isSnapshot = (value) =>
  value !== null &&
  typeof value === "object" &&
  typeof value.exists === "boolean" &&
  "value" in value;
const valueOf = (snapshot) => (snapshot.exists ? snapshot.value : null);

/** The item id and the transition a frame shows (only what its handler can see), or a reason it cannot be read. */
function frameView(frame) {
  const handler = HANDLERS.get(frame?.handler);
  if (!handler || handler.generation !== frame.generation) return { reason: "handler" };
  const id = handler.generation === 1 ? frame.event?.context?.params?.id : frame.event?.params?.id;
  const data = frame.event?.data;
  if (typeof id !== "string") return { reason: "shape" };
  if (handler.event === "create") {
    return isSnapshot(data)
      ? { handler, id, known: { before: null, after: valueOf(data) } }
      : { reason: "shape" };
  }
  if (handler.event === "delete") {
    return isSnapshot(data)
      ? { handler, id, known: { before: valueOf(data), after: null } }
      : { reason: "shape" };
  }
  return isSnapshot(data?.before) && isSnapshot(data?.after)
    ? { handler, id, known: { before: valueOf(data.before), after: valueOf(data.after) } }
    : { reason: "shape" };
}

/** The one write a frame belongs to; several candidates or none are reported as such, never guessed. */
export function matchFrame(frame, steps = STEPS) {
  const view = frameView(frame);
  if (view.reason) return { step: null, candidates: [], reason: view.reason };
  const candidates = itemTransitions(steps)
    .filter(
      (t) =>
        t.id === view.id &&
        Object.entries(view.known).every(([side, value]) => isDeepStrictEqual(t[side], value)),
    )
    .map((t) => t.step);
  if (candidates.length === 1) return { step: candidates[0], candidates, reason: null };
  return { step: null, candidates, reason: candidates.length === 0 ? "no-match" : "ambiguous" };
}

const eventId = (frame) =>
  (frame.generation === 1 ? frame.event?.context?.eventId : frame.event?.id) ??
  `${frame.handler}#${frame.seq}`;

/**
 * Per write and handler: how many frames, how many distinct event ids, how many repeats, what the
 * documentation says, and how long the first delivery took after the write was answered. Frames that
 * belong to no single write are listed apart.
 */
export function observe({ writes, frames, steps = STEPS }) {
  const transitions = itemTransitions(steps);
  const byStep = new Map(steps.map((step) => [step.id, new Map()]));
  const unattributed = [];
  let attributed = 0;
  for (const frame of frames) {
    const match = matchFrame(frame, steps);
    if (match.step === null) {
      unattributed.push({
        handler: frame?.handler ?? null,
        seq: frame?.seq ?? null,
        reason: match.reason,
        candidates: match.candidates,
      });
      continue;
    }
    attributed += 1;
    const perHandler = byStep.get(match.step);
    perHandler.set(frame.handler, [...(perHandler.get(frame.handler) ?? []), frame]);
  }
  const reportSteps = steps.map((step, index) => {
    const { before, after } = transitions[index];
    const write = writes[step.id] ?? null;
    const handlers = {};
    for (const handler of FIXTURE_HANDLERS) {
      const own = byStep.get(step.id).get(handler.name) ?? [];
      const ids = new Set(own.map(eventId));
      const documented = documentedFires(handler.event, before, after) ? 1 : 0;
      const times = own.map((frame) => Date.parse(frame.receivedAt)).filter(Number.isFinite);
      handlers[handler.name] = {
        frames: own.length,
        distinctEventIds: ids.size,
        duplicateFrames: own.length - ids.size,
        documented,
        matchesDocumented: documented === 1 ? ids.size === 1 && own.length === 1 : own.length === 0,
        firstLatencyMs:
          times.length > 0 && Number.isFinite(write?.answeredAtMs)
            ? Math.min(...times) - write.answeredAtMs
            : null,
      };
    }
    return {
      id: step.id,
      context: step.context,
      write: write === null ? null : { outcome: write.outcome, status: write.status },
      handlers,
    };
  });
  return {
    steps: reportSteps,
    unattributed,
    totals: { frames: frames.length, attributed, unattributed: unattributed.length },
  };
}
