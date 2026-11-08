// The model of the kinds recording: which handler must be delivered what, for each write. A write moves
// the tree; each item below `/k9-rtdb/<group>/items/<id>` whose node changed is one transition (created,
// updated or deleted), and each group whose subtree changed is one group transition. A kind handler is
// expected exactly for the transitions of its kind, the glob handler for every item transition, the group
// handler for every group transition. Nothing here decides what production does: observation steps
// (`observeOnly`) are recorded and never judged missing.

import { isDeepStrictEqual } from "node:util";
import { applyWrite } from "./breadth-sequence.mjs";
import { FIXTURE_HANDLERS, PREFIX } from "./kinds-frames.mjs";

export { applyWrite };
const clone = (value) => (value === undefined ? undefined : structuredClone(value));
const STRING_LIMIT = 256;
export const BLOB_SIZES = Object.freeze({
  small: 100 * 1024,
  medium: 600 * 1024,
  large: 2 * 1024 * 1024,
});

/** Strings above 256 characters are reduced to their length, as the fixture's frames reduce them. */
export function reduceBig(value) {
  if (typeof value === "string")
    return value.length <= STRING_LIMIT ? value : { type: "string", length: value.length };
  if (Array.isArray(value)) return value.map(reduceBig);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, reduceBig(item)]));
  return value;
}

/**
 * What a snapshot's value shows of a tree node when priorities and `.value` wrappers are not counted.
 * The Functions SDK has no priority: its `getPriority()` is a constant 0, and `val()` is the event's data
 * as the service sent it, so a frame may or may not carry `.priority` and `.value` members. Frames are
 * attributed on this form, and the members themselves are compared between runs.
 */
export function plain(node) {
  if (node === null || typeof node !== "object" || Array.isArray(node)) return node;
  if (".value" in node) return node[".value"];
  return Object.fromEntries(
    Object.entries(node)
      .filter(([key]) => key !== ".priority")
      .map(([key, item]) => [key, plain(item)]),
  );
}

export const kindOf = (before, after) =>
  isDeepStrictEqual(before ?? null, after ?? null)
    ? null
    : before == null
      ? "create"
      : after == null
        ? "delete"
        : "update";

export function buildSteps(nonce) {
  const mark = (value) => (nonce === undefined ? value : { ...value, run: nonce });
  const blob = (n) => "x".repeat(n);
  return [
    ["k1", "PUT", "ga/items/a1", mark({ value: 1 }), "admin"],
    ["k2", "PUT", "ga/items/a1", mark({ value: 2 }), "admin"],
    [
      "k3",
      "PUT",
      "ga",
      { items: { a1: mark({ value: 2 }), b1: mark({ value: 1 }), b2: mark({ value: 1 }) } },
      "admin",
    ],
    ["k4", "PUT", "ga/items", { b1: mark({ value: 2 }), b3: mark({ value: 3 }) }, "admin"],
    [
      "k5",
      "PATCH",
      "",
      {
        "ga/items/b1/value": 5,
        "ga/items/b3": null,
        "ga/items/b4": mark({ value: 4 }),
        "gb/items/c1": mark({ value: 5 }),
      },
      "admin",
    ],
    ["k6", "DELETE", "ga", undefined, "admin"],
    ["k7", "PUT", "gp/items/p1", mark({ value: 1, ".priority": 7 }), "admin"],
    ["k8", "PUT", "gp/items/p1/.priority", 9, "admin", { observeOnly: true }],
    ["k9", "PUT", "gp/items/p2", { ".value": 3, ".priority": 2 }, "admin"],
    ["k10", "DELETE", "gp", undefined, "admin"],
    [
      "k11",
      "PUT",
      "gl/items/l1",
      mark({ value: 1, blob: blob(BLOB_SIZES.small) }),
      "admin",
      { observeOnly: true },
    ],
    [
      "k12",
      "PUT",
      "gl/items/l2",
      mark({ value: 2, blob: blob(BLOB_SIZES.medium) }),
      "admin",
      { observeOnly: true },
    ],
    [
      "k13",
      "PUT",
      "gl/items/l3",
      mark({ value: 3, blob: blob(BLOB_SIZES.large) }),
      "admin",
      { observeOnly: true },
    ],
    ["k14", "DELETE", "gl", undefined, "admin", { observeOnly: true }],
    ["k15", "PUT", "gc/items/u1", mark({ value: 1 }), "user-rest"],
    ["k16", "PATCH", "gc/items/u1", { value: 2 }, "user-rest"],
    ["k17", "DELETE", "gc/items/u1", undefined, "user-rest"],
    ["k18", "PUT", "gs/items/s1", mark({ value: 1 }), "user-sdk", { via: "set" }],
    ["k19", "PUT", "gs/items/s1", mark({ value: 2 }), "user-sdk", { via: "transaction" }],
    ["k20", "PUT", "gs/items/s2", mark({ value: 1 }), "user-sdk", { via: "transaction" }],
    [
      "k21",
      "PATCH",
      "",
      { "gs/items/s1": null, "gs/items/s3": mark({ value: 3 }) },
      "user-sdk",
      { via: "onDisconnect" },
    ],
  ].map(([id, method, path, body, context, extra]) => ({
    id,
    method,
    path: [PREFIX, path].filter(Boolean).join("/"),
    body,
    context,
    ...extra,
  }));
}
export const STEPS = buildSteps();

const cache = new WeakMap();
/** The transitions of each step: item leaves (with kind) and groups. Values are in the reduced form. */
export function transitions(steps) {
  if (!cache.has(steps)) cache.set(steps, computeTransitions(steps));
  return cache.get(steps);
}
function computeTransitions(steps) {
  let tree = {};
  return steps.map((step) => {
    const previous = tree;
    tree = applyWrite(tree, step.method, step.path.split("/").filter(Boolean), step.body);
    const leaves = [];
    const groups = [];
    const names = [
      ...new Set([...Object.keys(previous[PREFIX] ?? {}), ...Object.keys(tree[PREFIX] ?? {})]),
    ].sort();
    for (const group of names) {
      const beforeGroup = previous[PREFIX]?.[group] ?? null;
      const afterGroup = tree[PREFIX]?.[group] ?? null;
      if (!isDeepStrictEqual(beforeGroup, afterGroup))
        groups.push({
          group,
          before: reduceBig(clone(plain(beforeGroup))),
          after: reduceBig(clone(plain(afterGroup))),
        });
      const beforeItems = beforeGroup?.items ?? {};
      const afterItems = afterGroup?.items ?? {};
      const ids = [...new Set([...Object.keys(beforeItems), ...Object.keys(afterItems)])];
      for (const id of ids) {
        const before = beforeItems[id] ?? null;
        const after = afterItems[id] ?? null;
        const kind = kindOf(before, after);
        if (kind)
          leaves.push({
            group,
            id,
            kind,
            before: reduceBig(clone(before)),
            after: reduceBig(clone(after)),
            plainBefore: reduceBig(clone(plain(before))),
            plainAfter: reduceBig(clone(plain(after))),
          });
      }
    }
    return { step: step.id, observeOnly: step.observeOnly === true, leaves, groups };
  });
}

const handlerOf = (name, generation) =>
  FIXTURE_HANDLERS.find((h) => h.name === name && h.generation === generation);

/** What a frame says the node was before and after, in the plain form. */
function frameSides(handler, data) {
  const side = (s) => reduceBig(plain(s?.exists ? s.value : null));
  if (handler.event === "create") return { before: null, after: side(data) };
  if (handler.event === "delete") return { before: side(data), after: null };
  return { before: side(data?.before), after: side(data?.after) };
}

export function matchFrame(frame, steps) {
  const handler = handlerOf(frame?.handler, frame?.generation);
  if (!handler) return { step: null, candidates: [], reason: "handler" };
  const params = frame.generation === 1 ? frame.event?.context?.params : frame.event?.params;
  const data = frame.event?.data;
  const wrongData =
    handler.event === "create" || handler.event === "delete"
      ? typeof data?.exists !== "boolean"
      : typeof data?.before?.exists !== "boolean" || typeof data?.after?.exists !== "boolean";
  if (
    typeof params?.group !== "string" ||
    (handler.level === "item" && typeof params?.id !== "string") ||
    wrongData
  )
    return { step: null, candidates: [], reason: "shape" };
  const { before, after } = frameSides(handler, data);
  const candidates = transitions(steps)
    .filter((t) =>
      handler.level === "group"
        ? t.groups.some(
            (g) =>
              g.group === params.group &&
              isDeepStrictEqual(g.before, before) &&
              isDeepStrictEqual(g.after, after),
          )
        : t.leaves.some(
            (l) =>
              l.group === params.group &&
              l.id === params.id &&
              isDeepStrictEqual(l.plainBefore, before) &&
              isDeepStrictEqual(l.plainAfter, after),
          ),
    )
    .map((t) => t.step);
  return {
    step: candidates.length === 1 ? candidates[0] : null,
    candidates,
    reason: candidates.length === 1 ? null : candidates.length ? "ambiguous" : "no-match",
  };
}

const expects = (handler, kind) => (handler.event === "write" || handler.event === kind ? 1 : 0);

export function observe({ writes = {}, frames = [], steps = STEPS }) {
  const all = transitions(steps);
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
    const key = JSON.stringify([match.step, frame.handler, params.group, params.id ?? null]);
    if (!collected.has(key)) collected.set(key, []);
    collected.get(key).push(frame);
  }
  const tally = (stepId, handler, group, id) => {
    const frames = collected.get(JSON.stringify([stepId, handler.name, group, id])) ?? [];
    const ids = new Map();
    for (const frame of frames) {
      const eventId =
        (frame.generation === 1 ? frame.event?.context?.eventId : frame.event?.id) ??
        `${handler.name}#${frame.seq}`;
      ids.set(eventId, (ids.get(eventId) ?? 0) + 1);
    }
    return {
      frames: frames.length,
      distinctEventIds: ids.size,
      duplicateFrames: frames.length - ids.size,
    };
  };
  const result = steps.map((step, index) => ({
    id: step.id,
    context: step.context,
    path: step.path,
    observeOnly: step.observeOnly === true,
    write: writes[step.id] ?? null,
    leaves: all[index].leaves.map((leaf) => ({
      ...leaf,
      handlers: Object.fromEntries(
        FIXTURE_HANDLERS.filter((h) => h.level === "item").map((handler) => [
          handler.name,
          {
            expected: expects(handler, leaf.kind),
            ...tally(step.id, handler, leaf.group, leaf.id),
          },
        ]),
      ),
    })),
    groups: all[index].groups.map((group) => ({
      ...group,
      handlers: Object.fromEntries(
        FIXTURE_HANDLERS.filter((h) => h.level === "group").map((handler) => [
          handler.name,
          { expected: 1, ...tally(step.id, handler, group.group, null) },
        ]),
      ),
    })),
  }));
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
