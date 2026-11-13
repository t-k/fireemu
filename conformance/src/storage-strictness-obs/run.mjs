// Offline by default. Production requires both --send and the launch-script environment flag.
// readback uses --out from the original run and --run-id, and refuses before ten minutes elapse.
import { execFileSync } from "node:child_process";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { isDeepStrictEqual, parseArgs } from "node:util";
import { CORS, GuardError, isSuccess, requests, SEND_FLAG, targetOf } from "./guard.mjs";
import { fetchNet, installEgressGuard } from "./egress.mjs";
import { readJournal, settlement } from "./judge.mjs";
import { createProductionClient, createWire, openJournal } from "./wire.mjs";
import { createFakeWorld } from "./world.fake.mjs";

const parse = (answer) => {
  try {
    return JSON.parse(answer.body.toString("utf8"));
  } catch {
    return null;
  }
};
const emptyList = (answer) => {
  const value = parse(answer);
  return (
    !answer.unknown &&
    isSuccess(answer.status) &&
    value &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).every((key) =>
      ["kind", "items", "prefixes", "nextPageToken"].includes(key),
    ) &&
    (value.kind === undefined || value.kind === "storage#objects") &&
    !value.nextPageToken &&
    (value.items === undefined || (Array.isArray(value.items) && value.items.length === 0)) &&
    (value.prefixes === undefined || (Array.isArray(value.prefixes) && value.prefixes.length === 0))
  );
};

export const CLEANUP_RESERVE_MS = 5 * 60_000;
// W2 must show the hard-delete policy the run asked for; production reports int64 values as strings.
export const hardDeletes = (policy) =>
  policy !== null &&
  typeof policy === "object" &&
  (policy.retentionDurationSeconds === "0" || policy.retentionDurationSeconds === 0);
// After the PATCH, production may omit the empty field or report it as [] (presend Should 2).
export const corsCleared = (metadata) =>
  metadata !== null &&
  typeof metadata === "object" &&
  !Array.isArray(metadata) &&
  (!Object.hasOwn(metadata, "cors") || isDeepStrictEqual(metadata.cors, []));
export const exitCode = (report, a2) => (report.closureReady && (a2 || report.completed) ? 0 : 1);
export function assertNoCredentialOverrides(env) {
  if (
    Object.keys(env).some(
      (key) => key === "GOOGLE_APPLICATION_CREDENTIALS" || key.startsWith("CLOUDSDK_"),
    )
  )
    throw new GuardError("credential overrides refused");
}

export async function observe({
  target,
  client,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
}) {
  let plan = requests(target);
  let location = "US";
  let armed = false;
  let completed = false;
  let defaultCors;
  const violations = [];
  const failures = [];
  const answers = {};
  const send = async (id) => {
    if (target.local && ["W1", "R1", "R2", "R3", "R4", "R5", "K3", "K-retry", "K4"].includes(id)) {
      client.append({
        phase: "skipped",
        case: id,
        reason: "local: fireemu has no bucket management",
      });
      return null;
    }
    const answer = await client.wire(plan[id], location);
    answers[id] = answer;
    return answer;
  };
  const check = (condition, id, hard = false) => {
    if (condition) return;
    violations.push(id);
    if (!target.local || hard) throw new Error("sequence precondition failed");
  };
  // The sequence stops CLEANUP_RESERVE_MS before the run deadline so the cleanup keeps its time (presend Should 3).
  const executeCase = async (id) => {
    if (client.deadline - client.now() < CLEANUP_RESERVE_MS)
      throw new Error("sequence stopped to keep the cleanup reserve");
    const answer = await send(id);
    if (answer.unknown) throw new Error("unknown answer");
    return answer;
  };
  const safe = async (id) => {
    try {
      return await send(id);
    } catch {
      failures.push(id);
      return { status: null, unknown: true, body: Buffer.alloc(0), headers: {} };
    }
  };
  const pending = (resource) =>
    settlement(client.entries).unresolved.find((entry) => entry.resource === resource);
  // An unknown delete is sticky even when another dialect addresses the same object.
  const remove = async (id) => {
    if (!client.unknownDeletes.has(plan[id].resource)) return safe(id);
    return null;
  };
  try {
    const p1 = await executeCase("P1");
    const metadata = parse(p1);
    check(isSuccess(p1.status) && typeof metadata?.location === "string", "P1");
    location = metadata?.location ?? "US";
    defaultCors = metadata?.cors;
    plan = requests(target, location);
    check((await executeCase("P2")).status === 404, "P2", true);
    check((await executeCase("P3")).status === (target.local ? 200 : 404), "P3");
    check(emptyList(await executeCase("P4")), "P4", true);
    armed = true;
    if (target.local) await send("W1");
    else check(isSuccess((await executeCase("W1")).status), "W1");
    const w2 = await executeCase("W2");
    // Fireemu's bucket metadata omits CORS configured through the rehearsal config.
    const w2Metadata = parse(w2);
    check(
      isSuccess(w2.status) &&
        ((isDeepStrictEqual(w2Metadata?.cors, CORS) && hardDeletes(w2Metadata?.softDeletePolicy)) ||
          (target.local &&
            w2Metadata?.name === target.tempBucket &&
            !Object.hasOwn(w2Metadata, "cors"))),
      "W2",
    );
    for (const id of ["W3", "W4"]) check(isSuccess((await executeCase(id)).status), id);
    for (let i = 1; i <= 14; i++) await executeCase(`A${i}`);
    for (let i = 1; i <= 8; i++) await executeCase(`C${i}`);
    if (target.local) {
      for (const id of ["R1", "R2", "R3", "R4", "R5"]) await send(id);
    } else {
      check(isSuccess((await executeCase("R1")).status), "R1");
      const r2 = await executeCase("R2");
      check(isSuccess(r2.status) && corsCleared(parse(r2)), "R2");
      for (let i = 3; i <= 5; i++) {
        if (i > 3) await sleep(Math.min(20_000, Math.max(0, client.deadline - client.now())));
        const answer = await executeCase(`R${i}`);
        if (!Object.hasOwn(answer.headers, "access-control-allow-origin")) break;
      }
    }
    await executeCase("F1");
    await executeCase("F2");
    completed = true;
  } catch {
    failures.push("sequence stopped");
  } finally {
    if (armed) {
      // A positive read is needed before an unknown creation can be confirmed.
      for (const [write, read] of [
        ["W1", "K-read-bucket"],
        ["W3", "K-read-t-cors"],
        ["W4", "K-read-default"],
      ]) {
        if (pending(plan[write].resource)?.unknownCreate) await safe(read);
      }
      // Unexpected successful or unknown negative probes still own their cleanup obligations.
      for (const key of ["t-y", "m-x", "m-y"]) {
        const resource = plan[`K-read-${key}`].resource;
        if (!pending(resource)) continue;
        const answer = await safe(`K-read-${key}`);
        if (isSuccess(answer.status) && !answer.unknown) await remove(`K-delete-${key}`);
        await safe(`K-verify-${key}`);
      }
      // A refused bucket create confers no ownership; in particular, a racing 409 must not delete someone else's bucket.
      const ownsTemp = target.local || answers.W1?.unknown || isSuccess(answers.W1?.status);
      if (ownsTemp) await remove("K1");
      await safe("K2");
      const deletion = ownsTemp ? await remove("K3") : null;
      if (target.local) await safe("K-retry");
      if (deletion?.status === 409 && !deletion.unknown) {
        const listed = await safe("K-list");
        const items = parse(listed);
        if (
          isSuccess(listed.status) &&
          !listed.unknown &&
          items &&
          !items.nextPageToken &&
          Array.isArray(items.items ?? [])
        ) {
          for (const object of items.items ?? []) {
            const key =
              object.name === "cors/o.txt" ? "t-cors" : object.name === "y" ? "t-y" : null;
            if (!key) {
              failures.push("unplanned object in temporary bucket");
              continue;
            }
            await remove(`K-delete-${key}`);
            await safe(`K-verify-${key}`);
          }
          await remove("K-retry");
        } else failures.push("temporary bucket list not complete");
      }
      await safe("K4");
      await safe("K5");
      const object = await safe("K6");
      if (isSuccess(object.status) && !object.unknown && !isSuccess(answers.F2?.status)) {
        await remove("K7");
        await safe("K8");
        await safe("K9");
      }
    }
  }
  const settled = settlement(client.entries);
  const corsRead = answers["K-verify-t-cors"] ?? answers.K2;
  const cleanupVerified =
    armed &&
    corsRead?.status === 404 &&
    !corsRead?.unknown &&
    (target.local || (answers.K4?.status === 404 && !answers.K4?.unknown)) &&
    emptyList(answers.K9 ?? answers.K5 ?? { body: Buffer.alloc(0) }) &&
    (answers.K8 ?? answers.K6)?.status === 404 &&
    !(answers.K8 ?? answers.K6)?.unknown;
  return {
    completed,
    location,
    ...(defaultCors === undefined ? {} : { defaultCors }),
    violations,
    failures,
    requests: client.budget.count,
    ...settled,
    closureReady: Boolean(settled.closureReady && cleanupVerified && violations.length === 0),
    cleanupVerified: Boolean(cleanupVerified),
  };
}

export async function readback({ target, client, previous, now = Date.now }) {
  const header = previous[0];
  const summary = previous.at(-1);
  if (
    header?.phase !== "header" ||
    header.runId !== target.runId ||
    header.project !== target.project ||
    header.defaultBucket !== target.defaultBucket ||
    summary?.phase !== "summary" ||
    !Number.isFinite(summary.endedAt) ||
    now() - summary.endedAt < 10 * 60_000
  )
    throw new GuardError("A2 needs the matching completed journal and a ten-minute delay");
  const plan = requests(target);
  const answers = {};
  for (const id of ["A2-bucket", "A2-prefix", "A2-object", "A2-cors", "A2-t-y", "A2-m-x", "A2-m-y"])
    answers[id] = await client.wire(plan[id]);
  const evidence = client.entries.map((entry) => ({ ...entry, session: "a2" }));
  const settled = settlement([...previous, ...evidence]);
  const absent = Object.entries(answers).every(([id, answer]) =>
    id === "A2-prefix" ? emptyList(answer) : answer.status === 404 && !answer.unknown,
  );
  return {
    ...settled,
    closureReady: settled.closureReady && absent,
    readbackVerified: absent,
    requests: client.budget.count,
  };
}

export async function main(argv = process.argv.slice(2)) {
  const startedAt = Date.now();
  const { values, positionals } = parseArgs({
    args: argv,
    allowPositionals: true,
    options: {
      project: { type: "string" },
      "default-bucket": { type: "string" },
      "run-id": { type: "string" },
      out: { type: "string" },
      local: { type: "string" },
      send: { type: "boolean", default: false },
    },
  });
  const a2 = positionals[0] === "readback";
  if (
    positionals.length > (a2 ? 1 : 0) ||
    !values.out ||
    (a2 && !values["run-id"]) ||
    (!a2 && values["run-id"] && !values.local) ||
    (values.local && values.send)
  )
    throw new GuardError("invalid arguments");
  const target = targetOf({
    project: values.project,
    defaultBucket: values["default-bucket"],
    runId: values["run-id"],
    local: values.local,
  });
  // --send without the launch-script flag is refused, never quietly replaced by the fake world.
  if (values.send && process.env[SEND_FLAG] !== "launch-script")
    throw new GuardError("production send flag required");
  const mode = values.local ? "local" : values.send ? "production" : "fake";
  let previous;
  if (a2) {
    previous = readJournal(join(values.out, "journal.jsonl"));
    if (previous[0]?.mode !== mode) throw new GuardError("A2 mode must match the original run");
    const end = previous.at(-1);
    if (
      end?.phase !== "summary" ||
      !Number.isFinite(end.endedAt) ||
      Date.now() - end.endedAt < 600_000 ||
      previous[0].runId !== target.runId ||
      previous[0].project !== target.project ||
      previous[0].defaultBucket !== target.defaultBucket
    )
      throw new GuardError("A2 is too early or belongs to another run");
  }
  mkdirSync(values.out, { recursive: true, mode: 0o700 });
  const journal = openJournal(join(values.out, a2 ? "readback.jsonl" : "journal.jsonl"));
  let restore;
  try {
    let token = "fake-owner";
    let net;
    if (mode === "production") {
      assertNoCredentialOverrides(process.env);
      try {
        token = execFileSync("gcloud", ["auth", "print-access-token"], {
          encoding: "utf8",
          timeout: 30_000,
          stdio: ["ignore", "pipe", "pipe"],
        }).trim();
      } catch {
        throw new GuardError("owner access token acquisition failed");
      }
      net = createProductionClient(target, { send: values.send, token });
    } else if (mode === "local") net = fetchNet(target);
    else net = createFakeWorld(target).net;
    restore = installEgressGuard();
    const header = {
      phase: "header",
      mode,
      runId: target.runId,
      project: target.project,
      defaultBucket: target.defaultBucket,
      startedAt,
    };
    journal.append(header);
    const client = createWire({ target, net, journal, token, deadline: startedAt + 15 * 60_000 });
    const report = a2
      ? await readback({ target, client, previous })
      : await observe({ target, client, ...(mode === "fake" ? { sleep: async () => {} } : {}) });
    const summary = { phase: "summary", mode, runId: target.runId, ...report, endedAt: Date.now() };
    journal.append(summary);
    console.log(JSON.stringify(summary));
    return exitCode(report, a2);
  } finally {
    restore?.();
    journal.close();
  }
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    process.exitCode = await main();
  } catch {
    console.error("Recorder refused or failed; inspect the private journal");
    process.exitCode = 1;
  }
}
