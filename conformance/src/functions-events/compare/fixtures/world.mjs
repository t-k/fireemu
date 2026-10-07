// The shared comparison world for the compare tests: a production run and two local sessions for the
// firestore/create, firestore/routing and delivery/retry programs, where production and fireemu agree.
import {
  LOCAL_PROJECT,
  PRODUCTION_PROJECT,
  T0,
  firestoreFrame,
  frameEntry,
  localOp,
  localSession,
  op,
  productionRun,
} from "./build.mjs";

export const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
export const docId = (n) => `e${String(n).padStart(32, "0")}`;
export const PASS_OFFSET = 3_600_000;

/**
 * A production run and two local sessions for the firestore/create, firestore/routing and
 * delivery/retry programs, where production and fireemu agree. Tests break one thing at a time.
 */
export function world() {
  const passes = [[], []];
  const frames = [];
  for (const pass of [1, 2]) {
    const s = T0 + 60_000 + (pass - 1) * PASS_OFFSET;
    const n = pass * 100;
    const create = `fe_events_primary/${docId(n + 1)}`;
    const other = `fe_events_control/${docId(n + 2)}`;
    const after = `fe_events_primary/${docId(n + 3)}`;
    const retry = `fe_events_primary/${docId(n + 4)}`;
    const ops = passes[pass - 1];
    ops.push(
      op({
        scenarioId: "fs-create",
        start: s,
        matchKey: { kind: "firestore", value: create },
        readback: { exists: true, path: create },
      }),
      op({
        scenarioId: "fs-other-path",
        start: s + 10_000,
        matchKey: { kind: "firestore", value: other },
        readback: { exists: true, path: other },
      }),
      op({
        scenarioId: "fs-auth-admin",
        start: s + 140_000,
        matchKey: { kind: "firestore", value: after },
        readback: { exists: true, path: after },
      }),
      op({
        scenarioId: "fs-retry",
        start: s + 200_000,
        matchKey: { kind: "firestore", value: retry },
        readback: { exists: true, path: retry },
        windowSeconds: 600,
      }),
    );
    for (const [generation, handler] of [
      [1, "fsCreatedV1"],
      [2, "fsCreatedV2"],
    ]) {
      frames.push(
        frameEntry(
          firestoreFrame({
            handler,
            generation,
            project: PRODUCTION_PROJECT,
            path: create,
            eventId: uuid(n + 10 + generation),
            timeMs: s + 500.123,
          }),
          s + 2000,
        ),
        frameEntry(
          firestoreFrame({
            handler,
            generation,
            project: PRODUCTION_PROJECT,
            path: after,
            eventId: uuid(n + 20 + generation),
            timeMs: s + 140_400.5,
          }),
          s + 142_000,
        ),
      );
    }
    for (const fixtureAttempt of ["failed", "succeeded"]) {
      frames.push(
        frameEntry(
          firestoreFrame({
            handler: "fsRetryV2",
            generation: 2,
            project: PRODUCTION_PROJECT,
            path: retry,
            eventId: uuid(n + 30),
            timeMs: s + 200_300.25,
            data: { fixtureKind: "retry" },
            fixtureAttempt,
          }),
          s + (fixtureAttempt === "failed" ? 202_000 : 215_000),
        ),
      );
    }
  }
  const run = productionRun(passes[0], passes[1], frames);
  const local = (salt) => {
    const create = `fe_events_primary/${docId(salt + 1)}`;
    const before = `fe_events_primary/${docId(salt + 2)}`;
    const other = `fe_events_control/${docId(salt + 3)}`;
    const after = `fe_events_primary/${docId(salt + 4)}`;
    const retry = `fe_events_primary/${docId(salt + 5)}`;
    const both = (path, base, timeMs) => ({
      v1: [
        firestoreFrame({
          handler: "fsCreatedV1",
          generation: 1,
          project: LOCAL_PROJECT,
          path,
          eventId: uuid(base + 1),
          timeMs,
        }),
      ],
      v2: [
        firestoreFrame({
          handler: "fsCreatedV2",
          generation: 2,
          project: LOCAL_PROJECT,
          path,
          eventId: uuid(base + 2),
          timeMs,
        }),
      ],
    });
    const key = (path) => ({ kind: "firestore", value: path });
    const subject = () =>
      localOp({
        scenarioId: "fs-create",
        matchKey: key(create),
        readback: { exists: true, path: create },
        ...both(create, salt + 10, T0 + 7.5),
      });
    return localSession([
      { recipeId: "functions-events/firestore/create", operations: [subject()] },
      {
        recipeId: "functions-events/firestore/routing",
        operations: [
          subject(),
          localOp({
            scenarioId: "fs-create",
            role: "positive-control-before",
            matchKey: key(before),
            readback: { exists: true, path: before },
            ...both(before, salt + 20, T0 + 9.25),
          }),
          localOp({
            scenarioId: "fs-other-path",
            matchKey: key(other),
            readback: { exists: true, path: other },
          }),
          localOp({
            scenarioId: "fs-create",
            role: "positive-control-after",
            matchKey: key(after),
            readback: { exists: true, path: after },
            ...both(after, salt + 30, T0 + 11.5),
          }),
        ],
      },
      {
        recipeId: "functions-events/delivery/retry",
        operations: [
          localOp({
            scenarioId: "fs-retry",
            matchKey: key(retry),
            readback: { exists: true, path: retry },
            v2: ["failed", "succeeded"].map((fixtureAttempt) =>
              firestoreFrame({
                handler: "fsRetryV2",
                generation: 2,
                project: LOCAL_PROJECT,
                path: retry,
                eventId: uuid(salt + 40),
                timeMs: T0 + 13.75,
                data: { fixtureKind: "retry" },
                fixtureAttempt,
              }),
            ),
          }),
        ],
      },
    ]);
  };
  return { run, emulator: local(900), strict: local(950) };
}
