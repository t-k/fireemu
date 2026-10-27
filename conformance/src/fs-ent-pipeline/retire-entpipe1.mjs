// Sends the retirement of the kept database `entpipe1` in three phases (see retire.mjs for the
// plan, the guard and the judges):
//
//   node src/fs-ent-pipeline/retire-entpipe1.mjs s0 --out <new dir> --packet-sha <sha>
//   node src/fs-ent-pipeline/retire-entpipe1.mjs s4 --out <new dir> --packet-sha <sha> --s0 <s0 dir>
//   node src/fs-ent-pipeline/retire-entpipe1.mjs a2 --out <new dir> --packet-sha <sha> --s0 <s0 dir> --s4 <s4 dir>
//
// Every phase needs ENTPIPE1_RETIRE_GO in the environment, equal to --packet-sha (the coordinator
// sets it at GO); the token comes from `gcloud auth application-default print-access-token` and is
// never written anywhere. Each request is sent once and never retried. A line is journalled
// before the request and another after it, so a crash leaves an unsettled request visible. The
// delete is sent at most once ever: s4 creates `s4-sent` in the s0 directory exclusively before
// the request. Exit codes: 0 phase passed, 1 stopped before sending a delete (or a read refused),
// 2 unknown delete (needs recovery: only a later a2 read-back closes it), 3 usage error.

import { execFile } from "node:child_process";
import { mkdir, readFile, readdir, writeFile, appendFile, open } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";

import { isMainModule } from "../fs-query-index/main-module.mjs";
import {
  MAX_OPERATION_READS,
  PLAN,
  PROJECT,
  buildRequest,
  judgeA2,
  judgeDelete,
  judgeOperation,
  judgeS0,
} from "./retire.mjs";

const execFileAsync = promisify(execFile);
const TIMEOUT_MS = 30_000;
export const READ_BACK_AFTER_MS = 10 * 60 * 1000;
const OPERATION_INTERVAL_MS = 10_000;

const stepsOf = (phase) => PLAN.filter((step) => step.phase === phase);

async function emptyDir(dir) {
  await mkdir(dir, { recursive: true });
  if ((await readdir(dir)).length > 0) throw new Error(`${dir} is not empty`);
}

/** Sends one request, journals it before and after, and saves the answer; never retries. */
async function send(ctx, step, request) {
  const sentAt = ctx.now().toISOString();
  await appendFile(
    join(ctx.out, "journal.jsonl"),
    `${JSON.stringify({ id: step.id, sending: sentAt })}\n`,
  );
  let answer;
  try {
    const response = await ctx.fetch(request.url, {
      method: request.method,
      headers: {
        authorization: `Bearer ${ctx.token}`,
        "x-goog-user-project": PROJECT,
        ...(request.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: request.body === undefined ? undefined : JSON.stringify(request.body),
      redirect: "error",
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const text = await response.text();
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      body = { unparsed: text.slice(0, 200) };
    }
    answer = { status: response.status, body };
  } catch (error) {
    answer = { status: 0, body: { transport: String(error?.name ?? error) } };
  }
  const answeredAt = ctx.now().toISOString();
  await writeFile(
    join(ctx.out, `${step.id}.json`),
    `${JSON.stringify({ sentAt, answeredAt, ...answer })}\n`,
  );
  await appendFile(
    join(ctx.out, "journal.jsonl"),
    `${JSON.stringify({ id: step.id, status: answer.status, sentAt, answeredAt })}\n`,
  );
  return { ...answer, sentAt };
}

const readJson = async (dir, name) => JSON.parse(await readFile(join(dir, name), "utf8"));

/** S0: the read-only snapshot. Stops at the first answer that is not a complete 200. */
export async function runS0(ctx) {
  await emptyDir(ctx.out);
  const answers = {};
  for (const step of stepsOf("S0")) {
    answers[step.id] = await send(ctx, step, buildRequest(step));
    if (answers[step.id].status !== 200) break;
  }
  const verdict = judgeS0(answers);
  await writeFile(join(ctx.out, "s0-verdict.json"), `${JSON.stringify(verdict)}\n`);
  return { code: verdict.ok ? 0 : 1, verdict };
}

/** S4: the delete, once. Needs a passing S0; marks the S0 directory so it is never sent twice. */
export async function runS4(ctx) {
  const s0 = await readJson(ctx.s0, "s0-verdict.json");
  if (!s0.ok) return { code: 1, verdict: { stopped: "S0 did not pass" } };
  await emptyDir(ctx.out);
  const marker = await open(join(ctx.s0, "s4-sent"), "wx");
  await marker.close();
  const [deleteStep, describeAfter] = stepsOf("S4");
  const deleted = await send(ctx, deleteStep, buildRequest(deleteStep));
  const judged = judgeDelete(deleted);
  const verdict = { delete: judged, sentAt: deleted.sentAt };
  if (judged.verdict !== "accepted") {
    await writeFile(join(ctx.out, "s4-verdict.json"), `${JSON.stringify(verdict)}\n`);
    return { code: judged.verdict === "refused" ? 1 : 2, verdict };
  }
  verdict.operations = [];
  for (let n = 1; n <= MAX_OPERATION_READS; n += 1) {
    await ctx.sleep(OPERATION_INTERVAL_MS);
    const step = { id: `s4-operation-${n}`, phase: "S4", method: "GET" };
    const read = await send(ctx, step, buildRequest(step, judged.operation));
    const result = judgeOperation(read, judged.operation).verdict;
    verdict.operations.push(result);
    if (result === "done") break;
  }
  const after = await send(ctx, describeAfter, buildRequest(describeAfter));
  verdict.describeAfter = after.status;
  await writeFile(join(ctx.out, "s4-verdict.json"), `${JSON.stringify(verdict)}\n`);
  return { code: 0, verdict };
}

/** A2: the read-back, at least ten minutes after the delete was sent. */
export async function runA2(ctx) {
  const s0 = await readJson(ctx.s0, "s0-verdict.json");
  const s4 = await readJson(ctx.s4, "s4-verdict.json");
  const waited = ctx.now().getTime() - Date.parse(s4.sentAt);
  if (!(waited >= READ_BACK_AFTER_MS))
    return { code: 1, verdict: { stopped: "less than ten minutes since the delete" } };
  await emptyDir(ctx.out);
  const answers = {};
  for (const step of stepsOf("A2")) answers[step.id] = await send(ctx, step, buildRequest(step));
  const verdict = judgeA2(answers, s0.snapshot);
  await writeFile(join(ctx.out, "a2-verdict.json"), `${JSON.stringify(verdict)}\n`);
  return { code: verdict.verdict === "deleted" ? 0 : 1, verdict };
}

export const PHASES = { s0: runS0, s4: runS4, a2: runA2 };

async function main(argv) {
  const [phase, ...rest] = argv;
  const flags = {};
  for (let i = 0; i < rest.length; i += 2) flags[rest[i].replace(/^--/, "")] = rest[i + 1];
  const go = process.env.ENTPIPE1_RETIRE_GO;
  if (!PHASES[phase] || !flags.out || !flags["packet-sha"] || go !== flags["packet-sha"]) {
    console.error("usage: see the header; ENTPIPE1_RETIRE_GO must equal --packet-sha");
    return 3;
  }
  const { stdout } = await execFileAsync("gcloud", [
    "auth",
    "application-default",
    "print-access-token",
  ]);
  const ctx = {
    out: flags.out,
    s0: flags.s0,
    s4: flags.s4,
    token: stdout.trim(),
    fetch,
    now: () => new Date(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  };
  const { code, verdict } = await PHASES[phase](ctx);
  console.log(JSON.stringify(verdict));
  return code;
}

if (isMainModule(import.meta)) process.exit(await main(process.argv.slice(2)));
