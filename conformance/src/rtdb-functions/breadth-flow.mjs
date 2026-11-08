import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { observe as breadthObserve } from "./breadth-sequence.mjs";
import { judgeRun as breadthJudge } from "./breadth-judge.mjs";

export const BREADTH_WINDOWS = Object.freeze({
  propagationMs: 300000,
  writeMs: 6000,
  pollMs: 15000,
  quietMs: 30000,
  tailMs: 150000,
});

/** Complete when every deployed handler delivered every changed leaf, and each retry-on handler succeeded. */
export function breadthComplete({ report, deployed, result }) {
  return (
    !result.logs.incomplete &&
    report.steps.every((step) =>
      step.leaves.every((leaf) =>
        deployed.every((target) => {
          const seen = leaf.handlers[target.functionName];
          return (
            seen?.frames > 0 &&
            (leaf.group !== "gr" ||
              !target.required ||
              Object.values(seen.attempts).some((attempts) =>
                attempts.some((attempt) => attempt?.threw === false),
              ))
          );
        }),
      ),
    )
  );
}

/**
 * The shared flow of a trigger recording. The breadth recording is the default; another scenario plugs
 * in `deps.observe`, `deps.judge`, `deps.complete` and `deps.windows`.
 */
export async function runBreadth(deps) {
  const { targets, ops, clock, abort, log } = deps;
  const windows = deps.windows ?? BREADTH_WINDOWS;
  const observe = deps.observe ?? breadthObserve;
  const judgeRun = deps.judge ?? breadthJudge;
  const complete = deps.complete ?? breadthComplete;
  const states = new Map(targets.map((t) => [t.key, { started: false, cleaned: false }]));
  const reasons = [];
  const writes = {};
  const result = {
    outcome: "recorded",
    nonce: deps.nonce,
    uid: null,
    reasons,
    residual: false,
    deployed: 0,
    deploys: {},
    records: deps.records ?? {},
    frames: [],
    logs: { reads: 0, entries: 0, incomplete: false, ignored: {} },
    cleanup: { targets: {}, user: null, inventory: null, rtdb: null },
    report: null,
  };
  let before,
    rtdbAttempted = false,
    userAttempted = false,
    start;
  const phase = (name) => log("phase", name);
  const readLogs = async () => {
    const reply = await deps.logs.read({
      start,
      end: new Date(clock.now() + 300000).toISOString(),
    });
    result.logs.reads++;
    result.logs.entries += reply.entries ?? 0;
    if (!reply.complete && !result.logs.incomplete) {
      result.logs.incomplete = true;
      reasons.push("a Cloud Logging read was incomplete");
    }
    for (const [key, count] of Object.entries(reply.ignored ?? {}))
      result.logs.ignored[key] = Math.max(result.logs.ignored[key] ?? 0, count);
    result.frames.push(...reply.frames.map((frame) => frame.frame ?? frame));
    if (deps.budget?.exhausted) throw Error("total request ceiling reached");
  };
  try {
    if (deps.runDir)
      await writeFile(
        join(deps.runDir, "run-identity.json"),
        JSON.stringify({
          nonce: deps.nonce,
          email: `breadth-${deps.nonce}@example.com`,
          uid: null,
        }),
        { mode: 0o600 },
      );
    await phase("preflight");
    await deps.preflight();
    await phase("inventory");
    before = await deps.inventory.take();
    if (!before.complete) throw Error("inventory incomplete");
    if (deps.runDir)
      await writeFile(join(deps.runDir, "inventory-before.json"), JSON.stringify(before), {
        mode: 0o600,
      });
    for (const spec of targets) await ops[spec.generation].assertAbsent(spec);
    await phase("rtdb-up");
    rtdbAttempted = true;
    await deps.rtdb.setup();
    await phase("user-up");
    userAttempted = true;
    if ((await deps.auth.create()).outcome !== "ok") throw Error("user create failed or unknown");
    result.uid = deps.auth.uid;
    if (deps.runDir)
      await writeFile(
        join(deps.runDir, "run-identity.json"),
        JSON.stringify({
          nonce: deps.nonce,
          email: `breadth-${deps.nonce}@example.com`,
          uid: result.uid,
        }),
        { mode: 0o600 },
      );
    if ((await deps.auth.signIn()).outcome !== "ok") throw Error("user sign-in failed or unknown");
    await phase("deploy");
    start = new Date(clock.now() - 60000).toISOString();
    for (const spec of targets) {
      if (abort.stopped) throw Error("signal before deploy");
      const state = states.get(spec.key);
      try {
        await ops[spec.generation].deploy(spec, state);
      } catch (error) {
        if (!spec.required && state.deployFailure?.class === "refused") continue;
        throw error;
      }
      try {
        await ops[spec.generation].read(spec, state);
      } finally {
        result.records[spec.key] = state.record ?? result.records[spec.key] ?? null;
        if (deps.runDir)
          await writeFile(join(deps.runDir, "records.json"), JSON.stringify(result.records), {
            mode: 0o600,
          });
      }
      result.deployed++;
    }
    await phase("propagation-wait");
    for (
      const deadline = clock.now() + windows.propagationMs;
      clock.now() < deadline && !abort.stopped;
    )
      await clock.sleep(Math.min(windows.pollMs, deadline - clock.now()));
    if (abort.stopped) throw Error("signal during propagation");
    await phase("observe");
    let nextRead = clock.now() + windows.pollMs;
    for (const step of deps.steps) {
      if (abort.stopped) throw Error("signal during observation");
      const answer =
        step.context === "user-sdk" ? await deps.sdk.write(step.id) : await deps.rtdb.write(step);
      writes[step.id] = answer;
      if (answer.outcome !== "ok") throw Error(`write ${step.id} ${answer.outcome}`);
      const deadline = clock.now() + windows.writeMs;
      while (clock.now() < deadline) {
        await clock.sleep(Math.min(deadline, nextRead) - clock.now());
        if (clock.now() >= nextRead) {
          await readLogs();
          nextRead += windows.pollMs;
        }
      }
    }
    await phase("tail");
    const deadline = clock.now() + windows.tailMs;
    let quietSince = null;
    while (clock.now() < deadline && !abort.stopped) {
      await clock.sleep(Math.min(deadline, nextRead) - clock.now());
      if (clock.now() >= nextRead) {
        const previous = result.frames.length;
        await readLogs();
        nextRead += windows.pollMs;
        const report = observe({ writes, frames: result.frames, steps: deps.steps });
        const deployed = targets.filter((target) => result.records[target.key] !== undefined);
        const finished = complete({ report, deployed, result });
        if (!finished) quietSince = null;
        else if (quietSince === null || result.frames.length !== previous) quietSince = clock.now();
        if (quietSince !== null && clock.now() - quietSince >= windows.quietMs) break;
      }
    }
    if (abort.stopped) throw Error("signal during tail");
  } catch (error) {
    reasons.push(error.message);
  }
  try {
    if (Object.keys(writes).length || result.frames.length) {
      result.report = observe({ writes, frames: result.frames, steps: deps.steps });
      reasons.push(
        ...judgeRun({
          report: result.report,
          frames: result.frames,
          writes,
          ignored: result.logs.ignored,
          userUid: deps.auth.uid,
          deployed: targets
            .filter((target) => result.records[target.key] !== undefined)
            .map((target) => target.functionName),
        }),
      );
    }
  } catch (error) {
    reasons.push(error.message);
  }
  try {
    await deps.sdk.close();
  } catch (error) {
    reasons.push(`SDK cleanup: ${error.message}`);
  }
  deps.budget?.startCleanup();
  try {
    await phase("cleanup");
  } catch (error) {
    reasons.push(`cleanup journal: ${error.message}`);
  }
  const owned = [];
  for (const spec of targets) {
    const state = states.get(spec.key);
    if (!state.started) continue;
    try {
      await ops[spec.generation].cleanup(spec, state);
    } catch (error) {
      state.cleanupError = error.message;
    }
    result.cleanup.targets[spec.key] = {
      cleaned: state.cleaned === true,
      error: state.cleanupError ?? null,
    };
    if (!state.cleaned) {
      result.residual = true;
      reasons.push(`${spec.key} was not cleaned`);
    }
    if (state.deployFailure) {
      result.deploys[spec.key] = {
        ...state.deployFailure,
        functionSeen: state.functionSeen === true,
      };
      if (state.deployFailure.class !== "refused" && !state.functionSeen) {
        result.residual = true;
        reasons.push(`${spec.key} create remains unknown`);
      }
    }
    if (state.record) {
      result.records[spec.key] = state.record;
      try {
        const names = deps.ownedNames(state.record, spec);
        if (names) owned.push(names);
      } catch (error) {
        result.residual = true;
        reasons.push(`${spec.key} ownership: ${error.message}`);
      }
    }
  }
  if (userAttempted) {
    try {
      const deleted = await deps.auth.delete();
      const gone = deleted === "ok" && (await deps.auth.confirmGone());
      result.cleanup.user = { deleted, gone };
      if (!gone && deps.auth.state !== "create-refused") {
        result.residual = true;
        reasons.push("user cleanup unresolved");
      }
    } catch (error) {
      result.residual = true;
      reasons.push(`user cleanup: ${error.message}`);
    }
  }
  if ([...states.values()].some((state) => state.started) && before) {
    try {
      result.cleanup.inventory = await deps.inventory.removeLeftovers(before, owned);
      if (!result.cleanup.inventory.ok) {
        result.residual = true;
        reasons.push("inventory cleanup unresolved");
      }
    } catch (error) {
      result.residual = true;
      reasons.push(`inventory cleanup: ${error.message}`);
    }
  }
  if (rtdbAttempted) {
    try {
      result.cleanup.rtdb = await deps.rtdb.cleanup();
      if (!result.cleanup.rtdb.closed) {
        result.residual = true;
        reasons.push("RTDB cleanup unresolved");
      }
    } catch (error) {
      result.residual = true;
      reasons.push(`RTDB cleanup: ${error.message}`);
    }
  }
  try {
    if (!deps.uploads.report().closureReady) {
      result.residual = true;
      reasons.push("source upload ledger is not closed");
    }
  } catch (error) {
    result.residual = true;
    reasons.push(`source upload cleanup: ${error.message}`);
  }
  if (deps.budget?.cleanupExhausted) {
    result.residual = true;
    reasons.push("request ceiling reached; recovery required");
  }
  try {
    await phase("closed");
  } catch (error) {
    reasons.push(`closed journal: ${error.message}`);
  }
  if (reasons.length) result.outcome = "stopped-needs-review";
  return result;
}
