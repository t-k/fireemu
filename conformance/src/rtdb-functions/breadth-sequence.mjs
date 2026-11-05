import { isDeepStrictEqual } from "node:util";
import { FIXTURE_HANDLERS, PREFIX } from "./breadth-frames.mjs";

const clone = (value) => (value === undefined ? undefined : structuredClone(value));
function prune(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return value;
  return Object.fromEntries(
    Object.entries(value)
      .map(([k, v]) => [k, prune(v)])
      .filter(
        ([, v]) =>
          v != null && (typeof v !== "object" || Array.isArray(v) || Object.keys(v).length),
      ),
  );
}
function setAt(tree, path, value) {
  if (!path.length) return value == null ? {} : clone(value);
  const out = tree && typeof tree === "object" && !Array.isArray(tree) ? tree : {};
  out[path[0]] = setAt(out[path[0]], path.slice(1), value);
  if (path.length === 1 && value == null) delete out[path[0]];
  return out;
}
export function applyWrite(tree, method, segments, body) {
  let next = clone(tree);
  if (method === "PUT") next = setAt(next, segments, body);
  else if (method === "DELETE") next = setAt(next, segments, null);
  else if (method === "PATCH")
    for (const [key, value] of Object.entries(body ?? {}))
      next = setAt(next, [...segments, ...key.split("/")], value);
  else throw new Error(`unknown method ${method}`);
  return prune(next);
}
export function itemTransitions(steps) {
  let tree = {};
  return steps.map((step) => {
    const previous = tree;
    tree = applyWrite(tree, step.method, step.path.split("/").filter(Boolean), step.body);
    const leaves = [];
    const groups = new Set([
      ...Object.keys(previous[PREFIX] ?? {}),
      ...Object.keys(tree[PREFIX] ?? {}),
    ]);
    for (const group of [...groups].sort()) {
      const beforeItems = previous[PREFIX]?.[group]?.items ?? {};
      const afterItems = tree[PREFIX]?.[group]?.items ?? {};
      for (const id of [
        ...new Set([...Object.keys(beforeItems), ...Object.keys(afterItems)]),
      ].sort()) {
        const before = beforeItems[id] ?? null,
          after = afterItems[id] ?? null;
        if (!isDeepStrictEqual(before, after))
          leaves.push({ group, id, before: clone(before), after: clone(after) });
      }
    }
    return { step: step.id, leaves };
  });
}
export function matchFrame(frame, steps) {
  const handler = FIXTURE_HANDLERS.find(
    (h) => h.name === frame?.handler && h.generation === frame.generation,
  );
  const params = frame?.generation === 1 ? frame.event?.context?.params : frame.event?.params;
  const data = frame?.event?.data;
  if (!handler) return { step: null, candidates: [], reason: "handler" };
  if (
    typeof params?.group !== "string" ||
    typeof params?.id !== "string" ||
    typeof data?.before?.exists !== "boolean" ||
    typeof data?.after?.exists !== "boolean"
  )
    return { step: null, candidates: [], reason: "shape" };
  const before = data.before.exists ? data.before.value : null,
    after = data.after.exists ? data.after.value : null;
  const candidates = itemTransitions(steps)
    .filter((t) =>
      t.leaves.some(
        (l) =>
          l.group === params.group &&
          l.id === params.id &&
          isDeepStrictEqual(l.before, before) &&
          isDeepStrictEqual(l.after, after),
      ),
    )
    .map((t) => t.step);
  return {
    step: candidates.length === 1 ? candidates[0] : null,
    candidates,
    reason: candidates.length === 1 ? null : candidates.length ? "ambiguous" : "no-match",
  };
}

export function buildSteps(nonce) {
  const mark = (value) => (nonce === undefined ? value : { ...value, run: nonce });
  return [
    ["w1", "PUT", "ga/items/a1", mark({ value: 1 }), "admin"],
    ["w2", "PUT", "gr/items/f1", mark({ value: 1, failForMs: 45000 }), "admin"],
    [
      "w3",
      "PUT",
      "ga",
      { items: { b1: mark({ value: 1 }), b2: mark({ value: 1 }), b3: mark({ value: 1 }) } },
      "admin",
    ],
    [
      "w4",
      "PUT",
      "ga/items",
      { b1: mark({ value: 1 }), b2: mark({ value: 2 }), b4: mark({ value: 4 }) },
      "admin",
    ],
    ["w5", "PATCH", "", { "ga/items/b1/value": 5, "gb/items/c1": mark({ value: 5 }) }, "admin"],
    ["w6", "DELETE", "ga", undefined, "admin"],
    ["w7", "PUT", "gv/items/u1", mark({ value: 7 }), "user-rest"],
    ["w8", "PATCH", "gv/items/u1", { value: 8 }, "user-rest"],
    ["w9", "DELETE", "gv/items/u1", undefined, "user-rest"],
    ["w10", "PUT", "gu", { items: { a: mark({ value: 1 }), b: mark({ value: 1 }) } }, "user-sdk"],
    ["w11", "PATCH", "gu", { "items/a/value": 2, "items/b/value": 2 }, "user-sdk"],
    ["w12", "DELETE", "gu", undefined, "user-sdk"],
  ].map(([id, method, path, body, context]) => ({
    id,
    method,
    path: [PREFIX, path].filter(Boolean).join("/"),
    body,
    context,
  }));
}
export const STEPS = buildSteps();
export function observe({ writes = {}, frames = [], steps = STEPS }) {
  const transitions = itemTransitions(steps);
  const collected = new Map();
  const unattributed = [];
  for (const frame of frames) {
    const match = matchFrame(frame, steps);
    if (!match.step) {
      unattributed.push({
        handler: frame?.handler ?? null,
        reason: match.reason,
        candidates: match.candidates,
      });
      continue;
    }
    const params = frame.generation === 1 ? frame.event.context.params : frame.event.params;
    const key = JSON.stringify([match.step, frame.handler, params.group, params.id]);
    if (!collected.has(key)) collected.set(key, []);
    collected.get(key).push(frame);
  }
  const result = steps.map((step, index) => {
    const leaves = transitions[index].leaves.map((leaf) => ({
      ...leaf,
      handlers: Object.fromEntries(
        FIXTURE_HANDLERS.map((handler) => {
          const frames =
            collected.get(JSON.stringify([step.id, handler.name, leaf.group, leaf.id])) ?? [];
          const attempts = {};
          for (const frame of frames) {
            const id =
              (frame.generation === 1 ? frame.event?.context?.eventId : frame.event?.id) ??
              `${handler.name}#${frame.seq}`;
            (attempts[id] ??= []).push(frame.attempt ?? null);
          }
          return [
            handler.name,
            {
              documented: 1,
              frames: frames.length,
              distinctEventIds: Object.keys(attempts).length,
              duplicateFrames: frames.length - Object.keys(attempts).length,
              attempts,
            },
          ];
        }),
      ),
    }));
    return {
      id: step.id,
      context: step.context,
      path: step.path,
      write: writes[step.id] ?? null,
      leaves,
    };
  });
  return {
    steps: result,
    unattributed,
    totals: {
      frames: frames.length,
      attributed: frames.length - unattributed.length,
      unattributed: unattributed.length,
    },
  };
}
