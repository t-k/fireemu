// Fakes for the flow tests: every collaborator of runStage2 replaced by a recorder of what it was asked,
// in order. Shared by the scenario tests and the generated ones.

import { resolveTarget } from "../../functions-http/harness.mjs";
import { FIXTURE_HANDLERS } from "./frames.mjs";
import { STAGE2_WINDOWS } from "./flow.mjs";
import { resolveGen1Target } from "./gen1.mjs";
import { STEPS, documentedFires, itemTransitions } from "./sequence.mjs";

export const COMMON = { region: "us-central1", codebase: "rtdb-functions-oracle" };
export const targets = FIXTURE_HANDLERS.map((h) =>
  h.generation === 1
    ? resolveGen1Target({ functionName: h.name, ...COMMON, generation: "gcfv1" })
    : resolveTarget({ functionName: h.name, ...COMMON, generation: "gcfv2" }),
);
const HANDLER = Object.fromEntries(FIXTURE_HANDLERS.map((h) => [h.name, h]));
const TRANSITIONS = Object.fromEntries(itemTransitions(STEPS).map((t) => [t.step, t]));

/** The frame the handler prints when the platform delivers every documented event once. */
export function frameFor(handlerName, step, n = 1) {
  const handler = HANDLER[handlerName];
  const { id, before, after } = TRANSITIONS[step];
  const snap = (value) => ({ exists: value !== null, key: id, value });
  const data =
    handler.event === "create"
      ? snap(after)
      : handler.event === "delete"
        ? snap(before)
        : { before: snap(before), after: snap(after) };
  const eventId = `ev-${handlerName}-${step}-${n}`;
  return {
    handler: handlerName,
    generation: handler.generation,
    seq: n,
    receivedAt: "2026-10-27T00:00:05.000Z",
    event:
      handler.generation === 1
        ? { context: { eventId, params: { id } }, data }
        : { id: eventId, params: { id }, data },
  };
}

/** A world in which all collaborators are fakes that log what they were asked, in order. */
export function makeWorld(options = {}) {
  const events = [];
  let nowMs = Date.parse("2026-10-27T00:00:00.000Z");
  const states = new Map();
  const log = [];
  const written = [];
  const delivered = new Set(); // step ids whose frames the fake log has
  const seenFrames = [];
  const world = {
    reads: [],
    events,
    log,
    written,
    states,
    clock: {
      now: () => nowMs,
      sleep: async (ms) => {
        nowMs += ms;
        events.push(`sleep ${ms}`);
      },
    },
  };
  const ops = (gen) => ({
    assertAbsent: async (spec) => {
      events.push(`absent ${spec.functionName}`);
      if (options.present === spec.functionName)
        throw new Error("reserved function already exists");
    },
    deploy: async (spec, state) => {
      events.push(`deploy ${spec.functionName}`);
      Object.assign(state, { started: true, cleaned: false, gen });
      if (options.failDeploy === spec.functionName) {
        // what the bound operations record for a failed CLI deploy (wiring.mjs)
        if (options.deployClass) {
          state.deployFailure = { class: options.deployClass, evidence: [{ status: 400 }] };
        }
        throw new Error("deploy failed");
      }
    },
    read: async (spec, state) => {
      events.push(`read ${spec.functionName}`);
      if (options.failRead === spec.functionName) throw new Error("function record differs");
      state.record = { name: spec.functionName };
    },
    cleanup: async (spec, state) => {
      events.push(`cleanup ${spec.functionName}`);
      // whether the cleanup read the function present before its exact delete
      if (options.functionSeen !== undefined) state.functionSeen = options.functionSeen;
      if (options.cleanupThrows === spec.functionName) throw new Error("cleanup threw");
      if (options.cleanupFails === spec.functionName) {
        state.cleanupError = "function remains after delete";
        return;
      }
      state.cleaned = true;
    },
  });
  const deps = {
    targets,
    ops: { gcfv1: ops(1), gcfv2: ops(2) },
    ownedNames: (record, spec) =>
      spec.generation === "gcfv2"
        ? { trigger: `t-${spec.functionName}`, topic: `p-${spec.functionName}` }
        : null,
    preflight: async () => {
      events.push("preflight");
      if (options.preflightFails) throw new Error("preflight refused");
    },
    inventory: {
      take: async () => {
        events.push("inventory-take");
        return { complete: options.inventoryIncomplete !== true, items: {} };
      },
      removeLeftovers: async (before, owned) => {
        events.push(`inventory-clean ${owned.length}`);
        return (
          options.inventory ?? {
            ok: true,
            deleted: [],
            residual: {},
            incomplete: false,
            error: null,
          }
        );
      },
    },
    rtdb: {
      setup: async () => {
        events.push("rtdb-setup");
        if (options.setupFails) throw new Error("setup refused");
      },
      write: async (step) => {
        events.push(`write ${step.id}`);
        if (options.writeThrows === step.id) throw new Error("cap reached before the write");
        written.push(step.id);
        const answer = options.answers?.[step.id] ?? { outcome: "ok", status: 200 };
        if (answer.outcome === "ok") {
          for (const h of FIXTURE_HANDLERS) {
            const t = TRANSITIONS[step.id];
            if (documentedFires(h.event, t.before, t.after) && !options.silent?.has(h.name)) {
              delivered.add(`${h.name}:${step.id}`);
            }
          }
        }
        return { ...answer, answeredAtMs: world.clock.now() };
      },
      cleanup: async () => {
        events.push("rtdb-cleanup");
        return options.rtdb ?? { closed: true, errors: [], unresolved: [] };
      },
    },
    logs: {
      read: async (range) => {
        events.push("logs");
        world.reads.push(range);
        options.onRead?.(world.reads.length);
        if (options.logsIncomplete) return { frames: [], entries: 0, ignored: {}, complete: false };
        const fresh = [];
        for (const key of delivered) {
          const [handler, step] = key.split(":");
          if (seenFrames.includes(key)) continue;
          seenFrames.push(key);
          const frame = frameFor(handler, step);
          if (options.unnamedMember) {
            if (frame.generation === 1) frame.event.context.contextKeys = ["eventId", "domain"];
            else frame.event.eventKeys = ["id", "traceparent"];
          }
          fresh.push(frame);
        }
        if (options.strangerFrame && !seenFrames.includes("stranger")) {
          seenFrames.push("stranger");
          // the same path and kind of change as a real one, with a value no write of the run made
          const stranger = frameFor("rtdbWrittenV2", "s1");
          stranger.event.data.after.value = { n: 99 };
          fresh.push(stranger);
        }
        return {
          frames: fresh,
          entries: fresh.length,
          ignored: options.ignoredCounts ?? {},
          complete: true,
        };
      },
    },
    uploads: {
      report: () => ({
        closureReady: options.uploadsOpen !== true,
        reasons: options.uploadsOpen ? ["x"] : [],
      }),
    },
    log: async (action, detail) => log.push([action, detail]),
    abort: options.abort ?? { stopped: false },
    clock: world.clock,
    windows: STAGE2_WINDOWS,
    programId: "cv14-test",
  };
  world.deps = deps;
  return world;
}
