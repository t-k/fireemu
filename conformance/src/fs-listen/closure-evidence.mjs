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
// Closure ruling 1 and its 2026-10-06 13:26Z M3 extension name these run:row pairs.
const APPROVED_NATIVE_ROWS = new Set([
  "nmuuicyas:native/resume-token/current",
  "nmuukwo6n:native/resume-token/current",
  "nmuuicyas:native/existence-filter/with-expected-count",
  "nmuukwo6n:native/existence-filter/with-expected-count",
  ...["nmuv70w0y", "nmuv8dk6e"].flatMap((run) =>
    [
      "native/resume-grid-gc/k0",
      "native/resume-grid-tc/k1-expected",
      "native/resume-grid-tc/k1-repeat",
    ].map((row) => `${run}:${row}`),
  ),
]);
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
        const aggregateStatus = problems
          ? "NOT_COMPARABLE"
          : ["MATCH", "DIVERGES", "NOT_COMPARABLE"].includes(result?.status)
            ? result.status
            : ["MISMATCH", "KNOWN_DIVERGENCE"].includes(result?.status)
              ? "DIVERGES"
              : "NOT_COMPARABLE";
        const callbackStatus = result?.callbackStatus;
        const status = problems
          ? "NOT_COMPARABLE"
          : callbackStatus == null || callbackStatus === "MATCH"
            ? aggregateStatus
            : callbackStatus === "MISMATCH"
              ? "DIVERGES"
              : "NOT_COMPARABLE";
        const aggregateReason = problems
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
        const reason =
          callbackStatus == null
            ? aggregateReason
            : `${aggregateReason} Callback sequence: ${callbackStatus}; aggregate result retained independently.`;
        for (const conditionId of observed?.conditions ?? []) {
          if (!conditionIds.has(conditionId)) continue;
          const row = {
            conditionId,
            row: id,
            packet,
            status,
            reason,
            comparatorResult: result?.comparatorResult ?? result?.status ?? null,
            ...(callbackStatus == null ? {} : { aggregateStatus, callbackStatus }),
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
                result?.status === "KNOWN_DIVERGENCE" &&
                APPROVED_NATIVE_ROWS.has(`${production.reference.run}:${id}`),
              ruling: `${RULINGS}, closure ruling 1 and 2026-10-06 13:26Z M3`,
            };
          if (packet === "l3") {
            row.recordingNote = conditionId.endsWith("/browser-tab-lifecycle")
              ? "Single production recording approved by owner ledger 921 and closure ruling 4; no independent repeat is claimed."
              : "Single production recording approved by owner ledger 921; no independent repeat is claimed.";
            if (result?.bodyBytes) row.bodyBytes = result.bodyBytes;
            row.requestByteCounts = {
              judgement: "RECORDED_NOT_JUDGED",
              source: `${RULINGS}, 2026-10-06 13:26Z M4 (supersedes 06:12Z item 1)`,
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
              // Compare the entire canonical residual, including SDK phases, after removing only D4/D5.
              const residual = [production.recording.rows[id], local.recording.rows[id]].map(
                (r) => {
                  let canonical = canonicalRow(r);
                  for (const event of canonical.observed) {
                    const aliases = new Map();
                    for (const window of event.resume ?? []) {
                      const kept = [];
                      const frames = window.boundaryContents ?? [];
                      for (let i = 0; i < frames.length; i += 1) {
                        const message = frames[i].message;
                        if (message?.filter) continue;
                        if (message?.targetChange?.targetChangeType === "RESET") {
                          const previous = kept.findLast(
                            (f) => f.message?.targetChange?.targetChangeType === "CURRENT",
                          );
                          while (frames[i + 1]?.message?.documentChange) i += 1;
                          if (
                            previous &&
                            frames[i + 1]?.message?.targetChange?.targetChangeType === "CURRENT" &&
                            frames[i + 2]?.message?.targetChange &&
                            !frames[i + 2].message.targetChange.targetChangeType
                          ) {
                            const replay = frames[i + 1].message.targetChange;
                            for (const field of ["resumeToken", "readTime"])
                              if (replay[field] && previous.message.targetChange[field])
                                aliases.set(replay[field], previous.message.targetChange[field]);
                            i += 2;
                          }
                          continue;
                        }
                        kept.push({ message });
                      }
                      if (window.boundaryContents) window.boundaryContents = kept;
                    }
                    // D5 can issue a replacement resume point in the removed repeated snapshot.
                    for (const window of event.resume ?? [])
                      for (const target of window.targets) {
                        if (target.tokenRelation == null) continue;
                        const token = `<base64:resume-token:length=${target.tokenLength}:R${target.tokenRelation}>`;
                        const replacement = aliases.get(token);
                        if (replacement)
                          target.tokenRelation = Number(replacement.match(/:R(\d+)>$/)[1]);
                      }
                    const timestamps = new Map(),
                      tokens = new Map();
                    const normalized = JSON.parse(
                      JSON.stringify(event, (key, value) => {
                        if (key === "tokenRelation" && value != null)
                          return tokens.get(value) ?? value;
                        if (typeof value !== "string") return value;
                        value = aliases.get(value) ?? value;
                        if (/^<timestamp:T\d+>$/.test(value)) {
                          if (!timestamps.has(value)) timestamps.set(value, timestamps.size + 1);
                          return `<timestamp:T${timestamps.get(value)}>`;
                        }
                        if (/^<base64:resume-token:length=\d+:R\d+>$/.test(value)) {
                          const relation = Number(value.match(/:R(\d+)>$/)[1]);
                          if (!tokens.has(relation)) tokens.set(relation, tokens.size + 1);
                          return value.replace(/:R\d+>$/, `:R${tokens.get(relation)}>`);
                        }
                        return value;
                      }),
                    );
                    Object.assign(event, normalized);
                  }
                  return canonical;
                },
              );
              for (let e = 0; e < residual[0].observed.length; e += 1) {
                const pair = residual.map((r) => r.observed[e]);
                if (!pair[1]) continue;
                const restart = pair.map((event) =>
                  event.resume?.find((w) => w.phase === "restarted-online"),
                );
                if (restart.some((w) => !w)) continue;
                const boundaries = restart.map((w) =>
                  (w.boundaryContents ?? []).map((f) => f.message?.targetChange).filter(Boolean),
                );
                const echo = boundaries.map((items) =>
                  items.find((b) => !b.targetChangeType && b.resumeToken),
                );
                const current = boundaries.map((items) =>
                  items.find((b) => b.targetChangeType === "CURRENT"),
                );
                const point = pair.map((event, side) =>
                  event.resume
                    .filter((w) => w.phase === "warm")
                    .flatMap((w) => w.boundaryContents ?? [])
                    .map((f) => f.message?.targetChange)
                    .findLast((b) => b?.resumeToken === echo[side]?.resumeToken),
                );
                if (echo.some((b) => !b) || current.some((b) => !b) || point.some((b) => !b))
                  continue;
                if (
                  echo[0].readTime === point[0].readTime &&
                  echo[1].readTime !== point[1].readTime &&
                  echo[1].readTime === current[1].readTime
                ) {
                  row.differences.push({
                    id: "D7(a)",
                    approved: true,
                    ruling: `${RULINGS}, 2026-10-06 13:26Z M1`,
                    reason:
                      "Resume echo read time: production echoes the resume point; strict uses the new snapshot's read time.",
                  });
                  echo[1].readTime = point[1].readTime;
                }
                if (
                  current[0].resumeToken !== echo[0].resumeToken &&
                  current[1].resumeToken === echo[1].resumeToken &&
                  current[0].resumeToken?.replace(/:R\d+>$/, ">") ===
                    current[1].resumeToken?.replace(/:R\d+>$/, ">")
                ) {
                  row.differences.push({
                    id: "D7(b)",
                    approved: true,
                    ruling: `${RULINGS}, 2026-10-06 13:26Z M1`,
                    reason:
                      "CURRENT re-issues the resumed bytes in strict; production issues a new token.",
                  });
                  const following = boundaries[0][boundaries[0].indexOf(current[0]) + 1];
                  if (following?.resumeToken === current[0].resumeToken)
                    following.resumeToken = current[1].resumeToken;
                  current[0].resumeToken = current[1].resumeToken;
                }
              }
              if (!isDeepStrictEqual(...residual))
                row.differences.push({ id: "unclassified-canonical-difference", approved: false });
              row.reason += row.differences
                .filter((d) => d.id.startsWith("D7"))
                .map((d) => ` ${d.id}: ${d.reason}`)
                .join("");
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
        spawnSync(
          "git",
          [
            "diff",
            "--quiet",
            p.sourceCommit,
            "HEAD",
            "--",
            "crates",
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "tools/runner-node",
            ".cargo",
          ],
          { cwd: ROOT, stdio: "ignore" },
        ).status === 0,
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
      `Request bytes are RECORDED_NOT_JUDGED under ${RULINGS}, 2026-10-06 13:26Z M4: normalized retained content is identical; the remaining 27 bytes are unretained client fields. This supersedes 06:12Z item 1.`,
      `L3 D4/D5: ${INVESTIGATION}, approved by closure ruling 3. D7(a) resume echo read time and D7(b) CURRENT re-issuing resumed bytes are approved by ${RULINGS}, 2026-10-06 13:26Z M1. Residual differences remain unapproved.`,
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
  if (relative(ROOT, out) === evidence.evidencePath) {
    const formatted = spawnSync(join(ROOT, "conformance/node_modules/.bin/oxfmt"), [out], {
      cwd: ROOT,
    });
    if (formatted.status !== 0) throw new Error("comparison formatting failed");
    const buildRecordPath = "spec/compatibility/closure/evidence/FS-LISTEN-SDK-build.json";
    const buildRecordSha256 = hash(readFileSync(join(ROOT, buildRecordPath)));
    const comparisonSha256 = hash(readFileSync(out));
    for (const condition of closure.conditions) {
      const compared = conditions.find((c) => c.conditionId === condition.conditionId);
      condition.evidence = {
        ...condition.evidence,
        comparisonPath: evidence.evidencePath,
        comparisonSha256,
        finalArtifactSha256: evidence.artifactSha256,
        sourceCommit: evidence.sourceCommit,
        buildRecordPath,
        buildRecordSha256,
        runnerTreeSha256: evidence.runnerTree.workingTreeSha256,
        rows: condition.conditionId.endsWith("/final-artifact-regression")
          ? evidence.summary
          : compared.counts,
      };
    }
    closure.profileComparison.productionComparison = "RECORDED_WITH_APPROVED_DIFFERENCES";
    const cache = closure.conditions.find((c) =>
      c.conditionId.endsWith("/backend-cache-transitions"),
    );
    cache.note =
      "The decoded residual names D4/D5 under closure ruling 3 and D7(a) resume echo read time and D7(b) CURRENT re-issuing resumed bytes under the 2026-10-06 13:26Z M1 ruling. Additional residual differences remain blockers. One production recording is approved by owner ledger 921.";
    const final = closure.conditions.find((c) =>
      c.conditionId.endsWith("/final-artifact-regression"),
    );
    final.note =
      "The final release replay is bound to closure base aad8cee2a. Named differences D4/D5/D7 and the explicit native rows are approved by the coordinator; residual differences remain blockers. Independent closure review remains pending. Runtime build inputs and the runner working tree are bound separately.";
    closure.note =
      "Nine saved production recordings were compared offline with the strict release binary from closure base aad8cee2a. Closure rulings 1-5 and the 2026-10-06 13:26Z review rulings cover the named declared differences. Parent remains IMPLEMENTING and closure review remains PENDING_REVIEW; no promotion or production request was made.";
    Object.assign(closure.integratedRegression, {
      release: "closure-base-aad8cee2a",
      integrationCommit: evidence.sourceCommit,
      releaseBinarySha256: evidence.artifactSha256,
      buildReceiptPath: buildRecordPath,
      buildReceiptSha256: buildRecordSha256,
      comparisons: [
        {
          path: evidence.evidencePath,
          sha256: comparisonSha256,
          rows: rows.length,
          summary: evidence.summary,
        },
      ],
      note: "Replay uses the unchanged closure-base-aad8cee2a binary. D4/D5 and D7(a)/(b) remain approved declared differences; residual differences remain blockers. The six production windows contain eight CURRENT/global NO_CHANGE pairs, all sharing token bytes. Binding a future release tag is a follow-up. Parent remains IMPLEMENTING and independent closure review is pending.",
    });
    const closurePath = join(ROOT, "spec/compatibility/closure/FS-LISTEN-SDK.json");
    writeFileSync(closurePath, `${JSON.stringify(closure, null, 2)}\n`);
    if (
      spawnSync(join(ROOT, "conformance/node_modules/.bin/oxfmt"), [closurePath], { cwd: ROOT })
        .status !== 0
    )
      throw new Error("closure formatting failed");
  }
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
