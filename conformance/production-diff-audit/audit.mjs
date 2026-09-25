#!/usr/bin/env node
import { resolve, dirname, isAbsolute } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { loadInstalled } from "./installed.mjs";
import { auditSubject, auditExitCode, renderReport, SCHEMA, TASK } from "./suite.mjs";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const HELP =
  "node conformance/production-diff-audit/audit.mjs --out /absolute/new-private-dir [--repo /repository]\n" +
  "Read-only comparator audit; no fireemu/official emulator/server is started; no live mode.";

export function parseArgs(argv) {
  if (argv.length === 0 || (argv.length === 1 && ["-h", "--help", "help"].includes(argv[0])))
    return { help: true };
  const options = { repo: ROOT };
  const seen = new Set();
  for (let i = 0; i < argv.length; i += 2) {
    const key = { "--repo": "repo", "--out": "out" }[argv[i]];
    if (!key || seen.has(key) || !argv[i + 1] || argv[i + 1].startsWith("--"))
      throw new Error("invalid-audit-arguments");
    seen.add(key);
    options[key] = argv[i + 1];
  }
  if (!options.out || !isAbsolute(options.out)) throw new Error("absolute-new-output-required");
  options.repo = resolve(options.repo);
  return options;
}

/** Dependency injection is for tests; the CLI exposes no alternate loader or model. */
export async function main(
  argv = process.argv.slice(2),
  {
    load = loadInstalled,
    stdout = (text) => console.log(text),
    stderr = (text) => console.error(text),
  } = {},
) {
  let report;
  try {
    const options = parseArgs(argv);
    if (options.help) {
      stdout(HELP);
      return 0;
    }
    const installed = await load(options.repo);
    const directory = await installed.createOutput(options.out);
    report = auditSubject(installed.subject, installed.identity);
    if (!(await installed.unchanged())) {
      report.auditPassed = false;
      report.auditState = "INDETERMINATE";
      report.errors.push("audit-source-changed");
    }
    await installed.publish(directory, report, renderReport(report));
    stdout(
      JSON.stringify({
        taskId: TASK,
        auditState: report.auditState,
        auditPassed: report.auditPassed,
        groups: report.summary.groups,
        productionExecuted: false,
        nativeRuntimeExecuted: false,
        evidenceKind: report.evidenceKind,
        completeRepositoryValidation: report.identity.completeRepositoryValidation,
      }),
    );
    return auditExitCode(report);
  } catch (error) {
    const allowed = new Set([
      "invalid-audit-arguments",
      "absolute-new-output-required",
      "required-pilot-or-audit-not-installed",
      "unsupported-audit-case",
      "required-git-object-unavailable",
      "source-pin-mismatch",
      "comparator-semantics-pin-mismatch",
      "audit-source-changed",
      "output-must-be-outside-repository",
      "audit-source-symlink",
    ]);
    stderr(
      JSON.stringify({
        schema: SCHEMA,
        taskId: TASK,
        auditPassed: false,
        auditState: "INDETERMINATE",
        code: allowed.has(error?.message)
          ? error.message
          : "audit-input-execution-or-publication-failed",
        productionExecuted: false,
        nativeRuntimeExecuted: false,
        compatibilityEstablished: false,
      }),
    );
    return 2;
  }
}
if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().then(
    (code) => {
      process.exitCode = code;
    },
    () => {
      process.exitCode = 2;
    },
  );
}
