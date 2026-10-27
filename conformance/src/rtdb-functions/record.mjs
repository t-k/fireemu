// The entry of the CV14 recorder (stage 2 of the Gen2 upload work): admission by a reviewed approval file
// and packet, the pins, the environment of a real run (ADC, the Firebase CLI, the network), and the
// private output of a run. This module has no side effects on import; the launch script owns the lock and
// the sandbox ledger, and the recorder writes only inside its private run directory. The run itself is
// flow.mjs; `executeRun` takes an environment so the whole path is exercised on fakes.

import { execFileSync } from "node:child_process";
import { appendFile, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { adcPreflight } from "../../../tools/sdk-smoke-database/adc-preflight.mjs";
import { PROJECT } from "../../functions-http/harness.mjs";
import {
  PRIVATE_ROOT,
  PROJECT_IDENTITY_FILE,
  PROJECT_IDENTITY_SHA,
  acquireToken,
  cli,
  createControl,
  ownerAdc,
  readPrivateProjectIdentity,
} from "../../functions-http/production.mjs";
import { assembleStage2 } from "./assemble.mjs";
import { runStage2 } from "./flow.mjs";
import { requiredInstalledDependencies, requiredStage2Sources } from "./pins.mjs";
import { STAGE2_HOSTS, bearerFetch, createStage2Budget } from "./wiring.mjs";

const STAGE_DIR = fileURLToPath(new URL("./", import.meta.url));
const MASK = "123456789012";
const SECRET_SHAPES =
  /ya29\.|AIza[0-9A-Za-z_-]{20,}|eyJ[0-9A-Za-z_-]{8,}|Bearer\s+\S{8,}|X-Goog-Signature|Signature=/u;
const sha256 = (bytes) =>
  execFileSync("shasum", ["-a", "256"], { input: bytes, encoding: "utf8" }).split(" ")[0];

/** The approval binds one decision, one commit and one packet, and no other line says otherwise. */
export function assertApproval(content, gitSha, packetSha256) {
  const lines = content.replaceAll("\r\n", "\n").split("\n");
  if (
    lines[0] !== "Decision: APPROVE" ||
    lines[1] !== `gitSha: ${gitSha}` ||
    lines[2] !== `packetSha256: ${packetSha256}` ||
    lines.slice(3).some((line) => /(?:^|[\s#>])(?:Decision|gitSha|packetSha256)\s*:/u.test(line))
  ) {
    throw new Error("CV14 pre-send APPROVE must bind a single decision, commit and packet");
  }
}

/** The one fenced `json cv14-pins` block of the packet: the values the packet fixes for the run. */
export function parsePacketPins(markdown) {
  const blocks = [...markdown.matchAll(/```json cv14-pins\n([\s\S]*?)\n```/gu)];
  if (blocks.length !== 1) throw new Error("invalid packet pins: exactly one cv14-pins block");
  let pins;
  try {
    pins = JSON.parse(blocks[0][1]);
  } catch {
    throw new Error("invalid packet pins: not JSON");
  }
  if (
    pins === null ||
    typeof pins !== "object" ||
    Object.keys(pins).join() !== "baselineRulesSha256" ||
    !/^[0-9a-f]{64}$/u.test(pins.baselineRulesSha256)
  ) {
    throw new Error("invalid packet pins: baselineRulesSha256 only, 64 hex");
  }
  return { baselineRulesSha256: pins.baselineRulesSha256 };
}

/** A token for the RTDB data plane, refreshed after it expired; every refresh is counted as a `token` request. */
export function createTokenProvider(
  adc,
  budget,
  { acquire = acquireToken, now = Date.now, onToken = () => {} } = {},
) {
  let token;
  return async () => {
    if (!token || now() >= token.expiresAt) {
      token = await acquire(adc, budget, "token");
      onToken(token.value);
    }
    return token.value;
  };
}

/** A token provider and the list of every access token it has handed out: secrets a stored file must not hold. */
export function tokenProviderWithSecrets(adc, budget, options = {}) {
  const secrets = [];
  const getToken = createTokenProvider(adc, budget, {
    ...options,
    onToken: (value) => secrets.push(value),
  });
  return { getToken, secrets };
}

/** The FUNCTIONS-HTTP accounting constant per deploy; not a measured bill. */
export const estimatedUsd = (requests) => Number((0.01 + requests.cliDeploy * 0.55).toFixed(2));
export const exitCodeOf = ({ outcome, residual }) =>
  residual ? 3 : outcome === "recorded" ? 0 : 2;

const maskNumber = (text, projectNumber) => text.replaceAll(projectNumber, MASK);

/** Runs one CV14 observation in `environment`, writes its private output and returns counts only. */
export async function executeRun({ environment, runDir, packetPins, assemble = assembleStage2 }) {
  const journalPath = join(runDir, "journal.jsonl");
  const log = (action, detail) =>
    appendFile(
      journalPath,
      `${JSON.stringify({ ts: new Date().toISOString(), action, detail })}\n`,
      {
        mode: 0o600,
      },
    );
  const packet = {
    ...(environment.rtdbPacket ?? {
      projectId: environment.projectId,
      projectNumber: environment.projectNumber,
    }),
    baselineRulesSha256: packetPins.baselineRulesSha256,
  };
  const assembled = assemble({ ...environment, packet, runDir, log });
  let result;
  try {
    result = await runStage2(assembled.deps);
  } catch (error) {
    result = {
      outcome: "stopped-needs-review",
      reasons: [`the run failed: ${error.message}`],
      residual: true,
      deployed: 0,
      report: null,
      records: {},
      frames: [],
      logs: {},
      cleanup: {},
    };
  }
  if (environment.budget.snapshot().cliDeploy > 0) {
    try {
      const grants = await assembled.readGrantsAfter();
      if (grants.iam.removed.length > 0) {
        result.reasons.push(`${grants.iam.removed.length} project IAM binding(s) disappeared`);
        result.residual = true;
      }
    } catch (error) {
      result.reasons.push(`service-agent grant readback: ${error.message}`);
      result.residual = true;
    }
  }
  assembled.uploads.close();
  const requests = environment.budget.snapshot();

  const write = async (name, text) => {
    const masked = maskNumber(text, environment.projectNumber);
    const secrets = (environment.secrets ?? []).filter(Boolean);
    if (SECRET_SHAPES.test(masked) || secrets.some((secret) => masked.includes(secret))) {
      throw new Error(`the output was refused: ${name} holds a secret`);
    }
    await writeFile(join(runDir, name), masked, { mode: 0o600 });
  };
  const json = (value) => `${JSON.stringify(value, null, 2)}\n`;
  const outputs = {
    "report.json": () => json(result.report),
    "frames.jsonl": () => result.frames.map((frame) => JSON.stringify(frame)).join("\n") + "\n",
    "records.json": () => json(result.records),
    "forms.json": () => json(assembled.forms.summary()),
    "lines-masked.txt": () => `${assembled.forms.maskedLines().join("\n")}\n`,
    "inventory.json": () => json(result.cleanup?.inventory ?? null),
    "grants.json": () => json(assembled.grants),
  };
  for (const [name, produce] of Object.entries(outputs)) {
    try {
      await write(name, produce());
    } catch (error) {
      if (!result.reasons.includes(error.message)) result.reasons.push(error.message);
      result.outcome = "stopped-needs-review";
      await writeFile(join(runDir, name), `${JSON.stringify({ withheld: error.message })}\n`, {
        mode: 0o600,
      });
    }
  }
  const summary = {
    outcome: result.reasons.length > 0 ? "stopped-needs-review" : result.outcome,
    residual: result.residual,
    runDir,
    requests,
    estimatedUsd: estimatedUsd(requests),
  };
  await write(
    "result.json",
    json({
      outcome: summary.outcome,
      reasons: result.reasons,
      residual: result.residual,
      nonce: result.nonce ?? null,
      deployed: result.deployed,
      cleanup: result.cleanup,
      logs: result.logs,
      requests,
      estimatedUsd: summary.estimatedUsd,
    }),
  );
  return summary;
}

/**
 * Admission: the private paths, a clean reviewed tree, the approval that binds this commit and packet,
 * the packet's pins, the reviewed sources, and an ADC token with the scopes the RTDB hosts need. Every
 * outside effect comes in through `deps`, so each refusal is tested.
 */
export async function admitRun({ env, privateRoot, root, deps }) {
  const reviewPath = env.FIREEMU_CV14_REVIEW;
  const packetPath = env.FIREEMU_CV14_PACKET;
  if (
    !reviewPath ||
    !packetPath ||
    !reviewPath.startsWith(`${privateRoot}/`) ||
    !packetPath.startsWith(`${privateRoot}/`)
  ) {
    throw new Error("private review and packet paths are required");
  }
  const gitSha = (await deps.git(["rev-parse", "HEAD"], root)).trim();
  const dirty = await deps.git(
    [
      "status",
      "--porcelain",
      // explicit: `status.showUntrackedFiles` in the user's git config would otherwise hide new files
      "--untracked-files=all",
      "--",
      "conformance/functions-http",
      "conformance/src/shared",
      "conformance/src/rtdb-functions",
      "tools/sdk-smoke-database",
    ],
    root,
  );
  if (dirty) throw new Error("CV14 needs a clean reviewed commit");
  // The CLI uploads everything in fixtures/ except node_modules and .git and reads its .env files; an
  // ignored file there would be deployed without showing in the status above.
  const ignored = (
    await deps.git(
      [
        "status",
        "--porcelain",
        // `normal`, not `all`: `all` lists every file inside an ignored node_modules, `normal` keeps the
        // directory as one entry; both override `status.showUntrackedFiles=no`, which would otherwise
        // hide even the ignored entries
        "--untracked-files=normal",
        "--ignored",
        "--",
        "conformance/src/rtdb-functions/fixtures",
      ],
      root,
    )
  )
    .split("\n")
    .filter(
      (line) => line !== "" && line !== "!! conformance/src/rtdb-functions/fixtures/node_modules/",
    );
  if (ignored.length > 0) {
    throw new Error(
      `the fixture directory holds files git does not track: ${ignored.length} entry(ies)`,
    );
  }
  const packet = await deps.readFile(packetPath);
  assertApproval(await deps.readFile(reviewPath, "utf8"), gitSha, sha256(packet));
  const packetPins = parsePacketPins(packet.toString("utf8"));
  await deps.requiredSources();
  const verdict = await deps.adcVerdict();
  if (!verdict.ok) throw new Error(`the ADC token is not usable (${verdict.reason})`);
  return { gitSha, packetPins };
}

/** The command-line entry: admission by approval file, pins and the ADC scope check, then the run. */
export async function recordStage2() {
  const root = fileURLToPath(new URL("../../..", import.meta.url));
  const adc = await ownerAdc();
  const budget = createStage2Budget();
  // every access token this process holds is a secret a stored file must not contain
  const { getToken, secrets } = tokenProviderWithSecrets(adc.file, budget);
  const { packetPins } = await admitRun({
    env: process.env,
    privateRoot: PRIVATE_ROOT,
    root,
    deps: {
      git: async (args, cwd) => execFileSync("git", args, { cwd, encoding: "utf8" }),
      readFile,
      requiredSources: async () => {
        await requiredStage2Sources();
        await requiredInstalledDependencies();
      },
      adcVerdict: async () => adcPreflight(fetch, await getToken()),
    },
  });
  const projectNumber = await readPrivateProjectIdentity(
    PROJECT_IDENTITY_FILE,
    PROJECT_IDENTITY_SHA,
  );

  const runDir = join(PRIVATE_ROOT, "runs", `cv14-${new Date().toISOString().replaceAll(":", "")}`);
  await mkdir(runDir, { recursive: true, mode: 0o700 });
  const abort = { stopped: false };
  const stop = { requested: false };
  const onSignal = () => {
    abort.stopped = true;
    stop.requested = true;
  };
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.on(signal, onSignal);
  try {
    const environment = {
      control: createControl(adc.file, budget, { extraHosts: [...STAGE2_HOSTS] }),
      runCli: (args, adcPath, runBudget, kind, dir, track) =>
        cli(args, adcPath, runBudget, kind, dir, track, undefined, { cwd: STAGE_DIR }),
      adminFetch: bearerFetch(getToken, PROJECT),
      anonymousFetch: fetch,
      budget,
      adcPath: adc.path,
      projectNumber,
      projectId: PROJECT,
      clock: {
        now: Date.now,
        sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
      },
      abort,
      stop,
      secrets,
    };
    const summary = await executeRun({ environment, runDir, packetPins });
    console.log(JSON.stringify({ outcome: summary.outcome, residual: summary.residual, runDir }));
    process.exitCode = exitCodeOf(summary);
  } finally {
    for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) process.off(signal, onSignal);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  recordStage2().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
