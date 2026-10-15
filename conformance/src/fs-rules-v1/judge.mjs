// The pure decisions of the FS-3 runner: what a recording may start from, how a saved row is
// compared with a local one, and what the fixture and the console show. Nothing here performs I/O
// except `harnessDigest`, which reads the harness sources unless it is given a reader.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { CONFORMANCE_DIR } from "../config.mjs";
import {
  isTransient,
  RECORDED_PROJECT,
  SANDBOX_PROJECT,
  sameRecording,
} from "../fs-rules/harness.mjs";
import {
  BAD_PATH_PROGRAMS,
  countRequests,
  HARNESS_CAP,
  PROGRAMS,
  programDigest,
} from "./corpus.mjs";

export const TASK_ID = "FS-3-V1-RULES";
/** The ledger task of the FS-8 corpus (Rules get()/exists() on a bad path). */
export const TASK_ID_BAD_PATH = "FS-8-RULES-BAD-PATH";

const isBadPath = (program) => program.id.startsWith("fs-rules-v1/bad-path/");

/** The ledger task id of a run: one corpus family at a time, so its lines name the right task. */
export function taskIdFor(programs) {
  if (programs.length === 0) throw new Error("no program to name a task for");
  const badPath = programs.filter(isBadPath).length;
  if (badPath !== 0 && badPath !== programs.length)
    throw new Error("a run mixes FS-3 and FS-8 programs");
  return badPath ? TASK_ID_BAD_PATH : TASK_ID;
}
/** The synthetic project number fireemu is configured with. */
export const LOCAL_PROJECT_NUMBER = "123456789012";
/** The project id the official emulator runs under (its CLI stays offline for `demo-`). */
export const OFFICIAL_PROJECT = "demo-fs3-v1";

export const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/** The sources a saved row's meaning depends on; a change makes the rows stale. */
export const HARNESS_FILES = [
  "fs-rules/harness.mjs",
  "auth-fs-cross/listen-grpc.mjs",
  "fs-rules-v1/session.mjs",
  "fs-rules-v1/grpc.mjs",
  "fs-rules-v1/corpus.mjs",
];

export const harnessDigest = (
  read = (file) => readFileSync(join(CONFORMANCE_DIR, "src", file), "utf8"),
) => sha256(HARNESS_FILES.map((file) => read(file)).join("\n"));

/** Ceilings of one recording, from the corpus. */
export const ceilings = (programs) => ({
  maxRequests: countRequests(programs),
  maxHarnessRequests: HARNESS_CAP,
});

/** Production price per request is far below this; the figure is a ceiling, not a bill. */
export const estimatedUsd = (requests) => Number((requests * 0.000002 + 0.01).toFixed(4));

// ---- starting a recording -------------------------------------------------------------------

/**
 * Why a recording may not start. The sandbox must be as the lanes leave it, because the run
 * restores exactly that: no release, no ruleset, no database but `(default)`, no document, no
 * project-level account, anonymous sign-in allowed, no other lane active, every read answered.
 */
export function preflightProblems(report) {
  const foreign = report.databases.filter((db) => db !== "(default)");
  return [
    ...report.failedReads.map((read) => `preflight read failed: ${read}`),
    ...(foreign.length ? [`databases other than (default) exist: ${foreign.join(", ")}`] : []),
    ...(report.releases.length ? [`release(s) exist: ${report.releases.join(", ")}`] : []),
    ...(report.rulesets ? [`${report.rulesets} ruleset(s) exist`] : []),
    ...(report.defaultHasDocuments ? ["(default) holds documents; the run would wipe them"] : []),
    ...(report.projectAccounts === 0
      ? []
      : [`${report.projectAccounts} project-level account(s) exist`]),
    ...(report.anonymousEnabled ? [] : ["anonymous sign-in is not enabled"]),
    ...(report.otherLanesRecently.length
      ? [`other lanes used the sandbox within 30 minutes: ${report.otherLanesRecently.join(", ")}`]
      : []),
    ...(report.openRuns.length ? [`runs still open: ${report.openRuns.join(", ")}`] : []),
  ];
}

function ledgerEntries(ledgerText) {
  return ledgerText
    .split("\n")
    .filter((line) => line.trim())
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return undefined;
      }
    })
    .filter(Boolean);
}

/** Tasks other than this one with a ledger line for the sandbox in the last 30 minutes. */
export function otherLanesRecently(ledgerText, now = Date.now(), self = TASK_ID) {
  const tasks = new Set();
  for (const entry of ledgerEntries(ledgerText)) {
    if (entry.project !== SANDBOX_PROJECT || entry.taskId === self) continue;
    if (now - Date.parse(entry.ts) < 30 * 60_000) tasks.add(entry.taskId ?? "unknown");
  }
  return [...tasks];
}

/**
 * Other tasks with a `started` line for the sandbox in the last 6 hours and no later line of the
 * same task: a run of theirs may still be going.
 */
export function openRuns(ledgerText, now = Date.now(), self = TASK_ID) {
  const open = new Map();
  for (const entry of ledgerEntries(ledgerText)) {
    if (entry.project !== SANDBOX_PROJECT || entry.taskId === self || !entry.taskId) continue;
    if (entry.event === "started") open.set(entry.taskId, Date.parse(entry.ts));
    else open.delete(entry.taskId);
  }
  return [...open].filter(([, started]) => now - started < 6 * 3_600_000).map(([task]) => task);
}

/** The last line of this task, if it aborted or needs recovery within the hour. */
export function recentAbort(ledgerText, now = Date.now(), self = TASK_ID) {
  const last = ledgerEntries(ledgerText).findLast(
    (entry) => entry.taskId === self && entry.outcome,
  );
  if (!last || !/^(aborted|needs-recovery)/.test(String(last.outcome))) return undefined;
  return now - Date.parse(last.ts) < 3_600_000 ? last : undefined;
}

/** The operator confirms that no AUTH lane records on the sandbox: ISO time within the last hour. */
export function confirmedNoAuthRecording(env = process.env, now = Date.now()) {
  const at = Date.parse(env.FS3_NO_AUTH_RECORDING ?? "");
  if (!Number.isFinite(at) || now - at > 3_600_000 || at - now > 60_000) {
    throw new Error(
      "FS3_NO_AUTH_RECORDING must be the ISO time (within the last hour) at which the operator confirmed that no AUTH lane is recording on the sandbox",
    );
  }
  return new Date(at).toISOString();
}

/** The corpus family of FS3_CORPUS: `v1` (FS-3, the default) or `bad-path` (FS-8). */
export function corpusFor(env = process.env) {
  const family = env.FS3_CORPUS ?? "v1";
  if (family === "v1") return PROGRAMS;
  if (family === "bad-path") return BAD_PATH_PROGRAMS;
  throw new Error(`FS3_CORPUS must be v1 or bad-path, not ${family}`);
}

/** Programs selected by id prefix in FS3_PROGRAMS (all of the chosen corpus when unset). */
export function selectPrograms(programs, env = process.env) {
  programs ??= corpusFor(env);
  taskIdFor(programs);
  const prefixes = (env.FS3_PROGRAMS ?? "").split(",").filter(Boolean);
  const selected = prefixes.length
    ? programs.filter((p) => prefixes.some((prefix) => p.id.startsWith(prefix)))
    : programs;
  if (selected.length === 0) throw new Error("no program matches FS3_PROGRAMS");
  return selected;
}

// ---- the fixture ----------------------------------------------------------------------------

/** The fixture text: first recording per program, the differing rows of the second, diagnostics. */
export function fixtureText({ programs, recordings, meta, existing }) {
  const [first, second] = recordings;
  const fixture = existing ?? { version: 1, recordedAgainst: {}, programs: {} };
  fixture.recordedAgainst = {
    target:
      "production Firestore REST v1 and gRPC, Identity Platform sandbox, anonymous end-user ID tokens",
    project: RECORDED_PROJECT,
    note: "Two recordings per program. The project, its number, the run id and run-window times are placeholders. `second` holds the other recording of rows that differed. `diagnostics` is the refusal text of a ruleset production would not compile; it is never compared.",
  };
  for (const program of programs) {
    const one = first.results[program.id];
    const two = second.results[program.id];
    if (!one || !two) continue;
    const differing = Object.fromEntries(
      Object.entries(two.steps).filter(([id, rec]) => !sameRecording(rec, one.steps[id])),
    );
    fixture.programs[program.id] = {
      corpusDigest: programDigest(program),
      harnessDigest: meta.harness,
      recordedAt: meta.startedAt,
      gitSha: meta.sha,
      steps: one.steps,
      ...(Object.keys(differing).length ? { second: differing } : {}),
      ...(first.diagnostics[program.ruleset]
        ? { diagnostics: first.diagnostics[program.ruleset] }
        : {}),
    };
  }
  fixture.programs = Object.fromEntries(
    Object.entries(fixture.programs).toSorted(([a], [b]) => a.localeCompare(b)),
  );
  return `${JSON.stringify(fixture, null, 2)}\n`;
}

// ---- comparison -----------------------------------------------------------------------------

/**
 * Rows whose two production recordings may differ, with the reason. A differing row outside this
 * list is INDETERMINATE: it may be a propagation artefact, not behavior.
 */
export const NONDETERMINISTIC_ROWS = {};

/** gRPC codes that say nothing about Rules: DEADLINE_EXCEEDED, RESOURCE_EXHAUSTED, INTERNAL, UNAVAILABLE. */
const TRANSIENT_LISTEN_CODES = new Set([4, 8, 13, 14]);

/**
 * Whether a recorded answer says nothing about behaviour. A Listen has no status: it is transient
 * when it ended on a transient gRPC code or never answered (`silent`), on top of what any answer
 * can be (`isTransient`). A refusal (PERMISSION_DENIED, code 7) is a behaviour.
 */
export function isTransientRow(recorded) {
  if (isTransient(recorded)) return true;
  if (!recorded?.listen) return false;
  return (
    recorded.silent === true ||
    (recorded.end?.reason === "error" && TRANSIENT_LISTEN_CODES.has(recorded.end.code))
  );
}

/**
 * A recorded production Listen as it is compared. Production sends an existence filter, and the heartbeat after it,
 * only when the stream is still open when they are due: two recordings of the same program
 * differed that way (FS-3 run 1, `group-listen-none` of three programs), so neither frame is
 * compared on production's side (never on fireemu's). Every other frame, its order and its resume-token flag still are.
 */
export function comparable(recorded) {
  if (!recorded?.listen) return recorded;
  const frames = [];
  for (const frame of recorded.frames.filter((f) => f.kind !== "filter")) {
    if (frame.kind === "boundary" && frames.at(-1)?.kind === "boundary")
      frames[frames.length - 1] = frame;
    else frames.push(frame);
  }
  return { ...recorded, frames };
}

export function classify(
  { row, stale, production, alternative, fireemu },
  nondeterministic = NONDETERMINISTIC_ROWS,
) {
  if (stale) return "STALE_FIXTURE";
  if (production === undefined) return "MISSING_FIXTURE";
  if (fireemu === undefined) return "MISSING";
  if ([production, alternative, fireemu].some(isTransientRow)) return "INDETERMINATE";
  // Only production's frames are relaxed; what fireemu sends is compared in full.
  const [one, other] = [production, alternative].map(comparable);
  const local = fireemu;
  // A second recording that only differs in what is not compared is the same answer.
  const second = other !== undefined && sameRecording(one, other) ? undefined : other;
  if (second && !Object.hasOwn(nondeterministic, row)) return "INDETERMINATE";
  // A row whose dependency was refused on both sides never ran: it confirms that refusal only.
  if (one.unresolved !== undefined || local.unresolved !== undefined) {
    const same = one.unresolved === local.unresolved;
    return same && !second ? "DEPENDENCY_REFUSED" : "MISMATCH";
  }
  if (sameRecording(one, local)) return second ? "MATCH_NONDETERMINISTIC" : "MATCH";
  if (second && sameRecording(second, local)) return "MATCH_NONDETERMINISTIC";
  return "MISMATCH";
}

export const PASSING = new Set(["MATCH", "MATCH_NONDETERMINISTIC", "DEPENDENCY_REFUSED"]);

/** Compares the saved production rows with a local run, row by row. */
export function compareRows({ fixture, programs, local, harness = harnessDigest() }) {
  const rows = [];
  for (const program of programs) {
    const saved = fixture.programs?.[program.id];
    const stale =
      saved !== undefined &&
      (saved.corpusDigest !== programDigest(program) || saved.harnessDigest !== harness);
    for (const step of program.steps) {
      const production = saved?.steps?.[step.id];
      const alternative = saved?.second?.[step.id];
      const fireemu = local.results[program.id]?.steps?.[step.id];
      const row = `${program.id}#${step.id}`;
      rows.push({
        row,
        status: classify({ row, stale, production, alternative, fireemu }),
        production,
        ...(alternative ? { alternative } : {}),
        fireemu,
      });
    }
  }
  return rows;
}

/** A row in one short token, for the console. */
export function brief(recorded) {
  if (recorded === undefined) return "-";
  if (recorded.compiled !== undefined) return `compiled=${recorded.compiled}`;
  if (recorded.unresolved !== undefined) return "not-published";
  if (recorded.listen) {
    const kinds = [];
    for (const frame of recorded.frames) {
      const last = kinds.at(-1);
      if (frame.kind === "documentChange" && last?.documents) last.documents += 1;
      else if (frame.kind === "documentChange") kinds.push({ documents: 1 });
      else if (frame.kind === "targetChange")
        kinds.push({ text: `${frame.type}${frame.cause ? `:cause${frame.cause.code}` : ""}` });
      else kinds.push({ text: frame.kind });
    }
    const tokens = kinds.map((k) => (k.documents ? `documentChangex${k.documents}` : k.text));
    return `listen[${tokens.join(",")}]${recorded.end === "open" ? "" : ` end=${recorded.end.code}`}`;
  }
  if (recorded.grpc !== undefined) {
    const n = recorded.messages?.length ?? 0;
    return recorded.grpc === 0 ? `grpc0 msgs=${n}` : `grpc${recorded.grpc}`;
  }
  const body = recorded.body;
  if (Array.isArray(body)) {
    const documents = body.filter((e) => e.document).length;
    const aggregate = body.find((e) => e.result)?.result?.aggregateFields?.n?.integerValue;
    const refused = body.find((e) => e.error)?.error?.status;
    if (refused) return `${recorded.status} ${refused}`;
    return `${recorded.status} ${aggregate === undefined ? `docs=${documents}` : `count=${aggregate}`}`;
  }
  return `${recorded.status}${body?.error?.status ? ` ${body.error.status}` : ""}`;
}

// ---- the local side -------------------------------------------------------------------------

/** The daemon configuration fireemu runs the corpus under. */
export function fireemuConfig(profile) {
  return {
    schemaVersion: 1,
    profile,
    // Strict gives some production refusals only with productionExact; the emulator profile
    // refuses the key.
    ...(profile === "strict" ? { productionExact: true } : {}),
    daemon: { authProjectNumbers: { [SANDBOX_PROJECT]: LOCAL_PROJECT_NUMBER } },
    auth: { idTokenSigning: "session-rsa", apiKeys: ["fake-api-key"] },
  };
}

/** An unsigned ID token of an anonymous user, which the official emulator accepts. */
export function mockToken(uid, project = OFFICIAL_PROJECT, now = Math.floor(Date.now() / 1000)) {
  const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
  return `${b64({ alg: "none", typ: "JWT" })}.${b64({
    iss: `https://securetoken.google.com/${project}`,
    aud: project,
    sub: uid,
    user_id: uid,
    iat: now,
    exp: now + 3600,
    auth_time: now,
    firebase: { sign_in_provider: "anonymous", identities: {} },
  })}.`;
}
