// 1st gen targets for the CV14 recorder. The FUNCTIONS-HTTP target operations are 2nd gen only: a
// 2nd gen function has a Cloud Run service and an image package of its own, and its source goes to the
// project's `gcf-v2-uploads-*` bucket. A 1st gen function has neither: the v1 API names the function,
// a delete answers with `operations/<id>` (the operation names its function in `metadata.target`, as
// the FE v6 debug log recorded it), its source goes to a bucket outside the project, and the service
// removes its Artifact Registry images with the function (FE stage 2, 2026-09-30). Nothing here is
// shared with the 2nd gen path, so the reviewed 2nd gen operations stay as they are.

import { resolveTarget } from "../../functions-http/harness.mjs";

const FUNCTION_HOST = "https://cloudfunctions.googleapis.com";
const sleepFor = (ms) => new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
const RESOLVED = new WeakSet();
const OPERATION_NAME = /^operations\/[A-Za-z0-9_-]{1,256}$/u;
const DELETE_POLLS = 10;

/**
 * A 1st gen target spec: the fields of a 2nd gen spec with `generation: "gcfv1"`. The fields are
 * validated by the same rules (names, region, codebase, no inherited or computed fields); the result
 * is frozen and resolving it again returns it.
 */
export function resolveGen1Target(target) {
  if (RESOLVED.has(target)) return target;
  if (target === null || typeof target !== "object" || Array.isArray(target)) {
    throw new Error("invalid target spec: a plain object is required");
  }
  const generation = Object.getOwnPropertyDescriptor(target, "generation");
  if (!generation || !("value" in generation) || generation.value !== "gcfv1") {
    throw new Error("a 1st gen target needs generation gcfv1");
  }
  const copy = Object.defineProperties({}, Object.getOwnPropertyDescriptors(target));
  Object.defineProperty(copy, "generation", { value: "gcfv2", enumerable: true });
  const resolved = Object.freeze({ ...resolveTarget(copy), generation: "gcfv1" });
  RESOLVED.add(resolved);
  return resolved;
}

const resourceOf = ({ project, region, functionName }) =>
  `projects/${project}/locations/${region}/functions/${functionName}`;

export const gen1FunctionUrl = (target) =>
  `${FUNCTION_HOST}/v1/${resourceOf(resolveGen1Target(target))}`;

/** The function must not exist before the deploy. */
export async function assertGen1Absent(control, target, kind = "control") {
  const reply = await control("GET", gen1FunctionUrl(target), undefined, kind, [200, 404]);
  if (reply.status !== 404) throw new Error("reserved function already exists");
}

/** The deployed record is the reviewed function: its resource, codebase and tool, active, with a trigger. */
export function validateGen1Record(record, target) {
  const spec = resolveGen1Target(target);
  if (record?.name !== resourceOf(spec)) {
    throw new Error("function name differs from the reviewed resource");
  }
  if (record.status !== "ACTIVE") throw new Error("function is not active");
  if (record.runtime !== spec.runtime || record.entryPoint !== spec.entryPoint) {
    throw new Error("function runtime or entry point differs from the fixture");
  }
  if (record.labels?.["firebase-functions-codebase"] !== spec.codebase) {
    throw new Error("function codebase differs from the reviewed codebase");
  }
  if (record.labels["deployment-tool"] !== "cli-firebase") {
    throw new Error("function was not deployed by the Firebase CLI (deployment tool label)");
  }
  if (typeof record.eventTrigger?.eventType !== "string") {
    throw new Error("function has no event trigger");
  }
}

/** Reads the deployed function and keeps its record (the first production record of an RTDB trigger) in `state`. */
export async function readDeployedGen1(control, target, state) {
  const reply = await control("GET", gen1FunctionUrl(target), undefined, "control");
  validateGen1Record(reply.value, target);
  state.record = reply.value;
}

/** Starts the target's upload ledger entry as a 1st gen deploy, then runs the CLI for the one function. */
export async function deployGen1(
  target,
  programId,
  state,
  uploads,
  adcPath,
  budget,
  runDir,
  run,
  tap = () => {},
) {
  const spec = resolveGen1Target(target);
  if (uploads.region !== spec.region) {
    throw new Error("target region differs from the region of the upload helper");
  }
  const upload = await uploads.beginDeploy(`${programId}:${spec.key}`, { generation: 1 });
  const deployTrack = {
    onEvent: (event, line) => {
      tap(event, line);
      upload.observe(event);
    },
  };
  Object.assign(state, {
    target: spec,
    upload,
    deployTrack,
    started: true,
    exposureStart: Date.now(),
  });
  await run(
    ["deploy", "--only", `functions:${spec.codebase}:${spec.functionName}`],
    adcPath,
    budget,
    "cliDeploy",
    runDir,
    deployTrack,
  );
}

/**
 * Deletes the function by its exact resource, once (an unknown answer is never re-sent), polls the
 * operation, reads the function back absent and settles the deploy's upload ledger. Any problem leaves
 * `state.cleanupError` and the target not cleaned; nothing else is touched.
 */
export async function cleanupGen1(
  control,
  target,
  state,
  { log = async () => {}, sleep = sleepFor } = {},
) {
  if (!state.started) return;
  try {
    const spec = state.target ?? resolveGen1Target(target);
    const url = gen1FunctionUrl(spec);
    const current = await control("GET", url, undefined, "cleanup", [200, 404]);
    if (current.status === 200) {
      const started = await control("DELETE", url, undefined, "cleanup", [200]);
      const name = started.value?.name;
      if (
        typeof name !== "string" ||
        !OPERATION_NAME.test(name) ||
        started.value.metadata?.target !== resourceOf(spec)
      ) {
        throw new Error("Cloud Functions returned an unreviewed delete operation");
      }
      let operation = started.value;
      for (let poll = 0; !operation.done && poll < DELETE_POLLS; poll += 1) {
        await sleep(10_000);
        operation = (await control("GET", `${FUNCTION_HOST}/v1/${name}`, undefined, "cleanup"))
          .value;
      }
      if (operation.error) throw new Error("function delete operation failed");
      if (!operation.done) {
        throw new Error(`function delete operation did not complete within ${DELETE_POLLS} polls`);
      }
      await log("function-deleted", `${url}; exact delete completed`);
    } else {
      await log("function-already-absent", `${url}; no delete sent`);
    }
    const after = await control("GET", url, undefined, "cleanup", [200, 404]);
    if (after.status !== 404) throw new Error("function remains after delete");
    if (state.upload) {
      const uploads = await state.upload.finish({
        cliExited: state.deployTrack?.exited === true,
        exitCode: state.deployTrack?.exitCode ?? null,
      });
      if (!uploads.clean) {
        state.uploadCleanupError = `source upload not cleaned: ${uploads.reasons.join(", ")}`;
      }
    }
    if (state.uploadCleanupError) throw new Error(state.uploadCleanupError);
    state.cleaned = true;
  } catch (error) {
    state.cleanupError = error.message;
  }
}
