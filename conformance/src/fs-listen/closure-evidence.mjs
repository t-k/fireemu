// Offline closure evidence under the coordinator rulings; never changes closure statuses.
// node conformance/src/fs-listen/closure-evidence.mjs --binary target/listen-final/release/fireemu
//   --production-root <private runs directory> [--local-native N --local-l1b V --local-sdk S --local-browser B]
//   [--out target/codex-out/FS-LISTEN-SDK-comparison.json --summary target/codex-out/listen-closure-summary.md]
// Without supplied local files, reuse record.mjs with the strict profile (including the 35-minute expiry case).
import { spawnSync, execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { isDeepStrictEqual } from "node:util";
import { basename, dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  canonicalRow,
  classifyRow,
  classifyLocal,
  isUnfinished,
  compareRecordings,
  recordingProblems,
} from "./compare.mjs";

const ROOT = fileURLToPath(new URL("../../../", import.meta.url));
const HERE = dirname(fileURLToPath(import.meta.url));
const RUNS = [
  [
    "native",
    "native",
    "native-prod.json",
    ["listen-l1-native-20261005T002459Z-r1", "listen-l1-native-20261005T013618Z-r2"],
  ],
  [
    "sdk",
    "sdk",
    "sdk-prod.json",
    ["listen-l1-sdk-20261005T004425Z-r1", "listen-l1-sdk-20261005T013136Z-r2"],
  ],
  [
    "l1b",
    "native",
    "l1b-prod.json",
    ["listen-l1b-native-20261005T115528Z-r1", "listen-l1b-native-20261005T123312Z-r2"],
  ],
  [
    "l2",
    "browser",
    "browser-prod.json",
    ["listen-l2-browser-20261005T135910Z-r1", "listen-l2-browser-20261005T145934Z-r2"],
  ],
  ["l3", "browser", "browser-prod.json", ["listen-l3-browser-20261006T050949Z-r1"]],
];
const RULINGS = "docs.local/runs/fs-listen-l3/coordinator-rulings.md";
const INVESTIGATION = "docs.local/runs/fs-listen-l3/l3-response-structure.md";
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const read = (path) => JSON.parse(readFileSync(path, "utf8"));
const git = (...args) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8" }).trim();
const counts = (rows) =>
  rows.reduce(
    (s, r) => {
      s[r.status] += 1;
      return s;
    },
    {
      MATCH: 0,
      DIVERGES: 0,
      NOT_COMPARABLE: 0,
    },
  );

export async function closureEvidence(options) {
  if (!options.binary || !options["production-root"])
    throw new Error("--binary and --production-root are required");
  const binary = resolve(options.binary);
  const binarySha256 = hash(readFileSync(binary));
  const out = resolve(options.out ?? "target/codex-out/FS-LISTEN-SDK-comparison.json");
  const summaryPath = resolve(options.summary ?? "target/codex-out/listen-closure-summary.md");
  const work = join(ROOT, "target/codex-out/listen-closure");
  mkdirSync(work, { recursive: true });
  const tmp = join(work, "tmp");
  mkdirSync(tmp, { recursive: true });
  const runnerFiles = git("ls-files", "--cached", "--others", "--exclude-standard", "conformance")
    .split("\n")
    .toSorted();
  const runnerTree = {
    commit: git("rev-parse", "HEAD"),
    tree: git("rev-parse", "HEAD:conformance"),
    workingTreeSha256: hash(
      runnerFiles.map((path) => `${path}\0${hash(readFileSync(join(ROOT, path)))}\n`).join(""),
    ),
    dirty: git("status", "--porcelain", "--", "conformance") !== "",
  };
  const localFiles = {};
  for (const kind of ["native", "l1b", "sdk", "browser"]) {
    const path = resolve(options[`local-${kind}`] ?? join(work, `${kind}-strict.json`));
    if (!options[`local-${kind}`]) {
      const log = join(work, `${kind}-record.log`);
      const args = [
        join(HERE, "record.mjs"),
        kind === "l1b" ? "native" : kind,
        "--target",
        "local",
        "--profile",
        "strict",
        "--out",
        path,
      ];
      if (kind === "native") args.push("--include-long", "yes");
      if (kind === "l1b") args.push("--programs", "resume-variants");
      const result = spawnSync(process.execPath, args, {
        cwd: ROOT,
        env: { ...process.env, FIREEMU_BIN: binary, TMPDIR: tmp },
        encoding: "utf8",
      });
      writeFileSync(log, `${result.stdout ?? ""}${result.stderr ?? ""}`);
      if (result.error || ![0, 2].includes(result.status))
        throw new Error(`local ${kind} recording failed; see ${relative(ROOT, log)}`);
    }
    const bytes = readFileSync(path);
    const recording = JSON.parse(bytes);
    const p = recording.provenance;
    if (p?.binarySha256 !== binarySha256 || p.target !== "local" || p.profile !== "strict")
      throw new Error(`local ${kind} recording names another binary or strict profile`);
    localFiles[kind] = { recording, path: relative(ROOT, path), sha256: hash(bytes) };
  }
  const bindings = Object.values(localFiles).map((l) => l.recording.provenance);
  const source = bindings[0];
  if (
    bindings.some(
      (p) =>
        p.sourceCommit !== source.sourceCommit ||
        p.buildInputs?.inputsSha256 !== source.buildInputs?.inputsSha256,
    )
  )
    throw new Error("local recordings disagree on source provenance");
  const closure = read(join(ROOT, "spec/compatibility/closure/FS-LISTEN-SDK.json"));
  const conditionIds = new Set(closure.conditions.map((c) => c.conditionId));
  const rows = [],
    productionRecordings = [];
  for (const [packet, kind, filename, directories] of RUNS) {
    const local = localFiles[kind === "native" ? packet : kind];
    if (local.recording.kind !== kind)
      throw new Error(`local ${packet} has the wrong recording kind`);
    const productions = directories.map((directory) => {
      const path = join(options["production-root"], directory, filename);
      const bytes = readFileSync(path),
        recording = JSON.parse(bytes);
      if (recording.kind !== kind)
        throw new Error(`production ${packet} has the wrong recording kind`);
      const reference = {
        path: `docs.local/runs/${directory}/${filename}`,
        sha256: hash(bytes),
        run: recording.run,
        kind,
        requests: recording.requests ?? null,
        cleanupComplete: recording.cleanup?.complete === true,
      };
      productionRecordings.push(reference);
      return { recording, path, reference };
    });
    if (new Set(productions.map((p) => p.recording.run)).size !== productions.length)
      throw new Error(`production ${packet} does not have distinct runs`);
    const divergencePath = join(
      HERE,
      "data",
      packet === "l1b" ? "l1b-divergences-strict.json" : "divergences-strict.json",
    );
    const divergences = kind === "native" ? read(divergencePath) : {};
    const paired =
      kind === "browser" || productions.some((p) => recordingProblems(p.recording).length)
        ? null
        : compareRecordings({
            productions: productions.map((p) => p.recording),
            local: local.recording,
            divergences,
          });
    for (const production of productions) {
      let report = paired;
      if (kind === "browser") {
        const reportPath = join(work, `${basename(dirname(production.path))}-compare.json`);
        // Reuse the latest browser CLI verbatim, including its body-byte diagnostics and D4/D5 reasons.
        const result = spawnSync(
          process.execPath,
          [
            join(HERE, "compare.mjs"),
            "--production",
            production.path,
            "--local",
            resolve(ROOT, local.path),
            "--out",
            reportPath,
          ],
          { cwd: ROOT, encoding: "utf8" },
        );
        if (result.error || ![0, 1].includes(result.status))
          throw new Error(`browser comparator failed for ${packet}`);
        report = read(reportPath);
      }
      const ids = new Set([
        ...Object.keys(production.recording.rows),
        ...productions.flatMap((p) => Object.keys(p.recording.rows)),
        ...Object.keys(local.recording.rows).filter(
          (id) => packet !== "l2" || !local.recording.rows[id].l3,
        ),
      ]);
      for (const id of [...ids].toSorted()) {
        const observed =
          production.recording.rows[id] ??
          productions.find((p) => p.recording.rows[id])?.recording.rows[id] ??
          local.recording.rows[id];
        let result = report?.rows[id];
        let productionAnswers;
        if (
          productions.length === 2 &&
          (result?.status === "NONDETERMINISTIC" ||
            (kind === "browser" &&
              productions.every((p) => p.recording.rows[id]) &&
              classifyRow(productions[0].recording.rows[id], productions[1].recording.rows[id]) ===
                "DIFFER"))
        ) {
          const localRow = local.recording.rows[id];
          productionAnswers = productions.map((p) => ({
            run: p.recording.run,
            sha256: p.reference.sha256,
            canonicalMatch: Boolean(
              localRow &&
              !isUnfinished(localRow) &&
              !local.recording.errors?.[localRow.program] &&
              isDeepStrictEqual(canonicalRow(p.recording.rows[id]), canonicalRow(localRow)) &&
              (kind === "browser" ||
                classifyLocal(p.recording.rows[id], p.recording.rows[id], localRow) === "MATCH"),
            ),
          }));
          const matches = productionAnswers.filter((p) => p.canonicalMatch).map((p) => p.run);
          result = {
            ...result,
            comparatorResult: "NONDETERMINISTIC",
            status:
              !localRow || isUnfinished(localRow) || local.recording.errors?.[localRow.program]
                ? "NOT_COMPARABLE"
                : matches.length
                  ? "MATCH"
                  : "DIVERGES",
            reason:
              !localRow || isUnfinished(localRow) || local.recording.errors?.[localRow.program]
                ? "Production varies; the strict row is missing or unfinished and cannot establish parity."
                : matches.length
                  ? `Production varies; strict's canonical answer equals production run ${matches.join(", ")} (closure ruling 2).`
                  : "Production varies; strict's canonical answer equals neither recorded production answer (closure ruling 2).",
          };
        }
        const problems =
          recordingProblems(local.recording).length ||
          productions.some((p) => recordingProblems(p.recording).length);
        const status = problems
          ? "NOT_COMPARABLE"
          : ["MATCH", "DIVERGES", "NOT_COMPARABLE"].includes(result?.status)
            ? result.status
            : ["MISMATCH", "KNOWN_DIVERGENCE"].includes(result?.status)
              ? "DIVERGES"
              : "NOT_COMPARABLE";
        const reason = problems
          ? "Recording cleanup or program errors prevent comparison; see the private recording log."
          : (result?.reason ??
            {
              MATCH:
                "Canonical observations match both production recordings under compareRecordings.",
              MISMATCH:
                "Canonical observations differ from the agreeing production rows under compareRecordings.",
              INDETERMINATE:
                "At least one recorded observation is unfinished under compareRecordings.",
              MISSING: "The local recording lacks this production case.",
              EXTRA: "At least one production recording lacks this local case.",
              PRODUCTION_MISSING: "At least one production recording lacks this case.",
            }[result?.status] ??
            "Comparison row missing.");
        for (const conditionId of observed?.conditions ?? []) {
          if (!conditionIds.has(conditionId)) continue;
          const row = {
            conditionId,
            row: id,
            packet,
            status,
            reason,
            comparatorResult: result?.comparatorResult ?? result?.status ?? null,
            production: production.reference,
            productionRowPresent: Object.hasOwn(production.recording.rows, id),
            productionRecordings: productions.length,
            local: { path: local.path, sha256: local.sha256, run: local.recording.run },
            binarySha256,
            runnerTree: runnerTree.workingTreeSha256,
          };
          if (productionAnswers) {
            row.productionAnswers = productionAnswers;
            row.matchedProductionRuns = productionAnswers
              .filter((p) => p.canonicalMatch)
              .map((p) => p.run);
          }
          if (divergences[id])
            row.declaredDifference = {
              source: `conformance/src/fs-listen/data/${basename(divergencePath)}#${id}`,
              reason: divergences[id].reason ?? divergences[id],
              approved:
                conditionId.endsWith("/raw-resume-token") ||
                (conditionId.endsWith("/existence-filter-reconnect") &&
                  /native\/existence-filter\/with-expected-count/.test(id)),
              ruling: `${RULINGS}, closure ruling 1`,
            };
          if (packet === "l3") {
            row.recordingNote =
              "Single production recording approved by owner ledger 921 and closure ruling 4; no independent repeat is claimed.";
            if (result?.bodyBytes) row.bodyBytes = result.bodyBytes;
            row.requestByteCounts = {
              judgement: "RECORDED_NOT_JUDGED",
              source:
                "conformance/src/fs-listen/compare.mjs (latest browser normalization); task's declared request-byte ruling",
            };
            if (status === "DIVERGES" && /\/203C?$/.test(id)) {
              row.differences = ["D4", "D5"]
                .filter((code) => row.reason.includes(`${code}:`))
                .map((code) => ({
                  id: code,
                  approved: true,
                  ruling: `${RULINGS}, closure ruling 3`,
                  source: `${INVESTIGATION}#${code === "D4" ? "d4-local-only-filter-before-current-in-both-restarted-online-phases" : "d5-production-only-resetreplay-segments-and-message-countorder"}`,
                }));
              const relations = [production.recording.rows[id], local.recording.rows[id]].map((r) =>
                (r?.observed ?? []).flatMap((e) =>
                  (e.wire ?? []).flatMap((w) =>
                    (w.boundaries ?? []).flatMap((b, i, all) =>
                      b.type === "CURRENT" &&
                      all[i + 1]?.type === "NO_CHANGE" &&
                      b.resumeToken &&
                      all[i + 1].resumeToken
                        ? [
                            {
                              phase: w.phase,
                              equal: b.resumeToken.relation === all[i + 1].resumeToken.relation,
                            },
                          ]
                        : [],
                    ),
                  ),
                ),
              );
              if (
                !isDeepStrictEqual(
                  ...relations.map((items) =>
                    [...new Set(items.map(({ phase, equal }) => `${phase}:${equal}`))].toSorted(),
                  ),
                )
              ) {
                row.differences.push({
                  id: "boundary-token-relationship",
                  approved: false,
                  reason:
                    "CURRENT and the following NO_CHANGE share a resume token in production but use different tokens in strict; closure ruling 3 does not approve this additional difference.",
                  production: relations[0],
                  local: relations[1],
                  source: `${INVESTIGATION}#d6-exhaustiveness-causes-other-fields-and-member-order`,
                });
                row.reason +=
                  " boundary-token-relationship: CURRENT and the following NO_CHANGE have different token equality relationships.";
              }
              if (!row.differences.length)
                row.differences.push({ id: "unclassified-canonical-difference", approved: false });
            }
            if (id.endsWith("/202")) {
              row.terminateOnTabClose = (production.recording.rows[id]?.observed ?? []).some(
                (e) => e.terminate?.length,
              )
                ? "OBSERVED"
                : "UNOBSERVED";
              row.terminateRuling = `${RULINGS}#2026-10-06-0438z-row-202-terminate-is-an-observation-not-a-requirement`;
              row.reason +=
                " Empty terminate is a complete close observation, but does not establish the terminate-on-tab-close clause.";
            }
          }
          rows.push(row);
        }
      }
    }
  }
  const conditions = closure.conditions.map((condition) => {
    const own = rows.filter((r) => r.conditionId === condition.conditionId);
    const blockers = [];
    if (!own.length)
      blockers.push(
        "No recorded case rows; final-artifact and independent review gates are recorded separately.",
      );
    for (const row of own) {
      if (row.status === "NOT_COMPARABLE")
        blockers.push(`${row.production.run}:${row.row}: ${row.reason}`);
      if (row.status === "DIVERGES") {
        const nativeApproved = row.declaredDifference?.approved;
        if (
          !nativeApproved &&
          !(row.differences?.length && row.differences.every((d) => d.approved))
        )
          blockers.push(
            `${row.production.run}:${row.row}: unapproved ${
              row.differences
                ?.filter((d) => !d.approved)
                .map((d) => d.id)
                .join(", ") || "canonical difference"
            }.`,
          );
      }
    }
    return {
      conditionId: condition.conditionId,
      counts: counts(own),
      rows: own.map((r) => `${r.production.run}:${r.row}`),
      blockers,
    };
  });
  const evidence = {
    kind: "fs-listen-sdk-comparison-v1",
    evidencePath: "spec/compatibility/closure/evidence/FS-LISTEN-SDK-comparison.json",
    artifactSha256: binarySha256,
    sourceCommit: source.sourceCommit,
    buildInputs: source.buildInputs,
    sourceBound: bindings.every(
      (p) =>
        p.buildInputs?.dirty === false &&
        p.binaryBuiltAfterSource === true &&
        p.sourceCommit === runnerTree.commit,
    ),
    runnerTree,
    productionRecordings,
    summary: counts(rows),
    rows,
    conditions,
    scopeNotes: [
      "Conditions are mapped from each recorded row's conditions, following docs.local/runs/listen-lane/condition-map.md; FS-TRANSACTION rows are excluded.",
      `Condition 10: ${RULINGS}, 2026-10-06 04:38Z permits an empty terminate observation; the clause remains unobserved.`,
      `Response boundary bytes are retained, not judged by exact equality (${RULINGS}, 2026-10-06 06:12Z); decoded contents are compared by the latest compare.mjs.`,
      "Request bytes are retained, not judged by the latest browser comparer: SDK auth form fields were not retained; this supersedes the earlier proposed project-name-only count normalization.",
      `L3 D4/D5: ${INVESTIGATION}; task declares their deciding production state undetermined. Observed DIVERGES is not rewritten as MATCH.`,
      "Release-artifact closure comparison under coordinator closure rulings 1-5. Approved differences remain DIVERGES; additional differences remain blockers. Parent status remains IMPLEMENTING; independent closure review is pending.",
    ],
  };
  if (!evidence.sourceBound)
    for (const condition of conditions)
      condition.blockers.push(
        "Local binary provenance is not a clean build of the current source head.",
      );
  mkdirSync(dirname(out), { recursive: true });
  writeFileSync(out, `${JSON.stringify(evidence, null, 2)}\n`);
  mkdirSync(dirname(summaryPath), { recursive: true });
  writeFileSync(
    summaryPath,
    [
      "# FS-LISTEN-SDK closure comparison",
      "",
      `Binary SHA-256: ${binarySha256}; source: ${source.sourceCommit}; source-bound: ${evidence.sourceBound}.`,
      `Runner working tree SHA-256: ${runnerTree.workingTreeSha256}; dirty: ${runnerTree.dirty}.`,
      `Comparison: ${relative(ROOT, out)}; totals: ${JSON.stringify(evidence.summary)}.`,
      "",
      "Each listed run:case is one evidence row; cases shared by conditions are counted once per condition. L3 is one production run, never duplicated into a pair.",
      "",
      "| Condition | MATCH | DIVERGES | NOT_COMPARABLE | Remaining blockers |",
      "| --- | ---: | ---: | ---: | --- |",
      ...conditions.map(
        (c) =>
          `| ${c.conditionId} | ${c.counts.MATCH} | ${c.counts.DIVERGES} | ${c.counts.NOT_COMPARABLE} | ${c.blockers.join(" ") || "Covered by coordinator closure rulings 1-5."} |`,
      ),
      "",
      ...evidence.scopeNotes,
      "",
      ...conditions.flatMap((c) =>
        [`## ${c.conditionId}`, ""].concat(
          rows
            .filter((r) => r.conditionId === c.conditionId)
            .map((r) => `- ${r.production.run}:${r.row} — ${r.status}: ${r.reason}`),
          [""],
        ),
      ),
    ].join("\n"),
  );
  return evidence;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const options = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const flag = process.argv[i],
      value = process.argv[i + 1];
    if (
      !/^--(?:binary|production-root|local-native|local-l1b|local-sdk|local-browser|out|summary)$/.test(
        flag,
      ) ||
      !value
    )
      throw new Error(`unexpected argument ${flag}`);
    options[flag.slice(2)] = value;
  }
  closureEvidence(options)
    .then((evidence) =>
      console.log(
        `closure evidence: ${evidence.rows.length} rows ${JSON.stringify(evidence.summary)}; source-bound ${evidence.sourceBound}`,
      ),
    )
    .catch((error) => {
      console.error(error.message);
      process.exitCode = 1;
    });
}
