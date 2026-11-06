import { TARGETS } from "./breadth-targets.mjs";
import { buildSteps, itemTransitions } from "./breadth-sequence.mjs";

export function makeWorld(options = {}) {
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
  const steps = buildSteps("fake");
  let sentFrames = false;
  const deps = {
    targets: TARGETS,
    steps,
    ops: { gcfv1: ops, gcfv2: ops },
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
        return { outcome: "ok", status: 200 };
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
        const ready = options.allFrames && !sentFrames && events.includes("write w12");
        const frames = ready
          ? itemTransitions(steps).flatMap(({ leaves }) =>
              leaves.flatMap((leaf) =>
                TARGETS.map((target) => {
                  const params = { group: leaf.group, id: leaf.id };
                  const snapshot = (value) => ({ exists: value !== null, value });
                  return {
                    handler: target.functionName,
                    generation: target.generation === "gcfv1" ? 1 : 2,
                    event: {
                      params,
                      context: { params, eventId: "event" },
                      id: "event",
                      data: { before: snapshot(leaf.before), after: snapshot(leaf.after) },
                    },
                    attempt: {
                      threw: Boolean(
                        leaf.group === "gr" && target.required && options.missingRetrySuccess,
                      ),
                    },
                  };
                }),
              ),
            )
          : [];
        if (ready) sentFrames = true;
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
