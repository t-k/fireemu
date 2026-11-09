import { FIXTURE_HANDLERS } from "./kinds-frames.mjs";
import { transitions } from "./kinds-sequence.mjs";

const snap = (v) =>
  v === null ? { exists: false, key: "k", value: null } : { exists: true, key: "k", value: v };
export function perfectFrames(steps, only = FIXTURE_HANDLERS.map((h) => h.name)) {
  const frames = [];
  let n = 0;
  for (const t of transitions(steps)) {
    for (const leaf of t.leaves)
      for (const handler of FIXTURE_HANDLERS.filter((h) => h.level === "item")) {
        if (!only.includes(handler.name)) continue;
        if (handler.event !== "write" && handler.event !== leaf.kind) continue;
        const data =
          handler.event === "create"
            ? snap(leaf.after)
            : handler.event === "delete"
              ? snap(leaf.before)
              : { before: snap(leaf.before), after: snap(leaf.after) };
        const params = { group: leaf.group, id: leaf.id };
        frames.push({
          handler: handler.name,
          generation: handler.generation,
          seq: ++n,
          event:
            handler.generation === 1
              ? { context: { params, eventId: `e${n}`, contextKeys: [] }, data }
              : { params, id: `e${n}`, data, eventKeys: [] },
        });
      }
    for (const g of t.groups) {
      const handler = FIXTURE_HANDLERS.find((h) => h.level === "group");
      if (!only.includes(handler.name)) continue;
      frames.push({
        handler: handler.name,
        generation: 2,
        seq: ++n,
        event: {
          params: { group: g.group },
          id: `e${n}`,
          data: { before: snap(g.before), after: snap(g.after) },
          eventKeys: [],
        },
      });
    }
  }
  return frames;
}

import { KINDS_SCENARIO, KINDS_WINDOWS } from "./kinds-scenario.mjs";
import { TARGETS } from "./kinds-targets.mjs";

/**
 * A fake world for the shared flow with the kinds scenario plugged in. `frames: "all"` delivers every
 * expected frame once after the last write; `options.failure` makes the deploy of one handler fail with
 * `options.kind`; `options.records` lists the handlers whose deploy is read back.
 */
export function makeWorld(options = {}) {
  const scenario = options.scenario ?? KINDS_SCENARIO;
  const events = [];
  let now = 0;
  const ops = {
    assertAbsent: async (spec) => events.push(`absent ${spec.functionName}`),
    deploy: async (spec, state) => {
      events.push(`deploy ${spec.functionName}`);
      state.started = true;
      if (options.failure === spec.functionName) {
        state.deployFailure = { class: options.kind, evidence: [{ status: 400 }] };
        throw Error("deploy failed");
      }
    },
    read: async (spec, state) => {
      state.record = { name: spec.functionName };
    },
    cleanup: async (spec, state) => {
      events.push(`cleanup ${spec.functionName}`);
      state.cleaned = true;
      state.functionSeen = options.kind !== "unknown";
    },
  };
  const steps = scenario.buildSteps("fake");
  let delivered = false;
  const deps = {
    targets: TARGETS,
    steps,
    ops: { gcfv1: ops, gcfv2: ops },
    windows: KINDS_WINDOWS,
    observe: scenario.observe,
    judge: scenario.judge,
    complete: scenario.complete,
    preflight: async () => {
      events.push("preflight");
      if (options.preflightFails) throw Error("preflight");
    },
    inventory: {
      take: async () => ({ complete: true }),
      removeLeftovers: async () => {
        events.push("cleanup inventory");
        return { ok: true };
      },
    },
    rtdb: {
      setup: async () => events.push("setup rtdb"),
      write: async (step) => {
        events.push(`write ${step.id}`);
        const refused = (options.refuse ?? (() => false))(step);
        return refused ? { outcome: "refused", status: 400 } : { outcome: "ok", status: 200 };
      },
      cleanup: async () => {
        events.push("cleanup rtdb");
        return { closed: true, errors: [], unresolved: [] };
      },
    },
    auth: {
      uid: "fake-uid",
      create: async () => ({ outcome: "ok" }),
      signIn: async () => ({ outcome: "ok" }),
      delete: async () => {
        events.push("cleanup user");
        return "ok";
      },
      confirmGone: async () => true,
    },
    sdk: {
      close: async () => events.push("close sdk"),
      write: async (id) => {
        events.push(`write ${id}`);
        return { outcome: "ok", status: 200 };
      },
    },
    logs: {
      read: async () => {
        const ready = options.frames === "all" && !delivered && events.includes("write k21");
        const deployed = new Set(
          events.filter((e) => e.startsWith("deploy ")).map((e) => e.slice(7)),
        );
        const frames = ready
          ? perfectFrames(
              steps,
              TARGETS.map((t) => t.functionName).filter(
                (name) => deployed.has(name) && name !== options.failure,
              ),
            ).filter((f) => !(options.drop ?? (() => false))(f))
          : [];
        if (ready) delivered = true;
        return { frames, entries: frames.length, ignored: {}, complete: true };
      },
    },
    uploads: { report: () => ({ closureReady: true, reasons: [] }) },
    ownedNames: () => null,
    log: async () => {},
    abort: { stopped: false },
    clock: {
      now: () => now,
      sleep: async (ms) => {
        now += ms;
      },
    },
  };
  return { events, deps };
}
