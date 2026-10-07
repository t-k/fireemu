// Offline evidence proposal; this never writes or promotes the canonical EVENTARC closure record.
// node closure-evidence.mjs --inputs <comparison manifest.json> --out target/codex-out/EVENTARC-comparison.json
// The manifest contains {artifact, reports:[<B,C,D,H1,H2-A,H2-B,W comparison paths>]}.
// Each measurement names its frozen facets as EVENTARC/<condition>/<case>; unmapped cases stay unjudged.
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve, basename } from "node:path";
import { fileURLToPath } from "node:url";
import { DECLARED_DIFFERENCES, writeEvidence } from "./h-compare.mjs";

/** Bind stage B/C/D measurements to capture rows by request number, never by total comparison counts. */
export function stageFacets(row) {
  const facets = [],
    add = (condition, ...cases) => facets.push(...cases.map((c) => `EVENTARC/${condition}/${c}`));
  if (["cleanup", "preconditions"].includes(row.case)) return facets;
  const op = row.op,
    body = row.request?.body,
    response = row.response;
  if (op === "createChannel") {
    if (response?.status >= 200 && response.status < 300)
      add("channel-lifecycle", "providerless-create-capability");
    if (response?.status === 409) add("channel-lifecycle", "duplicate-channel");
    if (
      response?.status === 400 &&
      (row.case === "channel-ids" || row.case === "channel-lifecycle")
    )
      add("channel-lifecycle", "invalid-channel-name");
  }
  if (op === "getChannel") {
    add("channel-lifecycle", "get-channel");
    if (response?.status === 200) add("channel-lifecycle", "readiness-shape");
  }
  if (op === "listChannels") add("channel-lifecycle", "list-channels");
  if (op === "deleteChannel") add("channel-lifecycle", "delete-owned-channel");
  if (row.case === "auth-errors") {
    if (row.tokenMode === "none") add("errors-authentication", "no-token");
    if (row.tokenMode === "invalid") add("errors-authentication", "invalid-token");
  }
  if (response?.status >= 400 && response.status < 500)
    add("errors-authentication", "canonical-error-shape");
  if (row.case === "locations" || /fireemu-no-such-project/.test(row.request?.path ?? ""))
    add("errors-authentication", "wrong-project-location");
  if (!["publishEvents", "sdk.publishEvents"].includes(op)) return facets;
  add("publish-envelope", "response-shape");
  if (response?.status === 404) add("errors-authentication", "missing-channel");
  const events = body?.events;
  if (!Array.isArray(events)) return facets;
  if (!events.length) add("publish-envelope", "empty-batch");
  if (events.length === 1 && response?.status === 200) add("publish-envelope", "single-event");
  if (events.length > 1 && response?.status === 200) add("publish-envelope", "multiple-events");
  for (const e of events) {
    if (["id", "source", "specVersion", "type"].some((k) => !Object.hasOwn(e, k)))
      add("publish-envelope", "required-attributes");
    const attrs = Object.values(e.attributes ?? {});
    if (attrs.some((v) => v.ceFoo !== undefined) || e.attributes?.time?.ceString !== undefined)
      add("publish-envelope", "invalid-attribute-type");
    if (e.attributes?.time?.ceTimestamp === "not-a-time")
      add("publish-envelope", "invalid-timestamp");
    if (row.case !== "publish-content") continue;
    if (e.binaryData !== undefined && e.textData !== undefined)
      add("publish-content", "oneof-collision");
    else if (e.binaryData !== undefined)
      add(
        "publish-content",
        e.binaryData === "***not base64***" ? "invalid-base64" : "binary-data",
      );
    else if (e.textData === undefined) add("publish-content", "absent-data");
    else if (e.attributes?.datacontenttype?.ceString === "text/plain")
      add("publish-content", "text");
    else if (e.attributes?.datacontenttype?.ceString === "application/json") {
      try {
        const data = JSON.parse(e.textData);
        add(
          "publish-content",
          data === null
            ? "json-null"
            : Array.isArray(data)
              ? "json-array"
              : typeof data === "object"
                ? "json-object"
                : "json-scalar",
        );
      } catch {
        add("publish-content", "invalid-json");
      }
    }
  }
  return [...new Set(facets)];
}

export function bindStageReport({ packet, capture, comparison, production, artifact }) {
  const rows = capture.filter((r) => r.request && r.response);
  const compared = comparison.rows ?? comparison.results;
  if (!Array.isArray(compared)) throw new Error("stage comparison requires measured rows");
  const byNumber = new Map();
  for (const r of compared) {
    if (byNumber.has(r.n)) throw new Error("duplicate stage comparison row");
    byNumber.set(r.n, r);
  }
  const positions = new Map();
  return {
    packet,
    production,
    artifact,
    rows: rows.map((native) => {
      const base = `${native.case}/${native.op}`,
        index = positions.get(base) ?? 0;
      positions.set(base, index + 1);
      const r = byNumber.get(native.n);
      const verdict =
        { match: "MATCH", diverge: "DIVERGES", skipped: "NOT_COMPARABLE" }[r?.verdict] ??
        r?.verdict ??
        "NOT_COMPARABLE";
      return {
        case: base,
        variant: `${base}#${index}`,
        n: native.n,
        verdict,
        facets: stageFacets(native),
        declaredDifferences: r?.declaredDifferences ?? [],
        reason: r?.reason ?? "uncompared-native-row",
      };
    }),
  };
}

export function buildEvidence({ closure, reports, artifact }) {
  if (!artifact?.binarySha256 || !artifact.runnerSha256)
    throw new Error("missing artifact binding");
  const facets = new Set(
    closure.conditions.flatMap((c) => c.cases.map((k) => `${c.conditionId}/${k}`)),
  );
  for (const report of reports) {
    if (!["B", "C", "D", "H1", "H2-A", "H2-B", "W"].includes(report.packet))
      throw new Error("unknown recording packet");
    if (
      report.artifact?.binarySha256 !== artifact.binarySha256 ||
      report.artifact?.runnerSha256 !== artifact.runnerSha256
    )
      throw new Error("comparison artifact mismatch");
    for (const row of report.rows) {
      if (!["MATCH", "DIVERGES", "NOT_COMPARABLE"].includes(row.verdict))
        throw new Error("invalid comparison verdict");
      if ((row.declaredDifferences ?? []).some((d) => !DECLARED_DIFFERENCES.includes(d)))
        throw new Error("unknown declared difference");
      if ((row.facets ?? []).some((f) => !facets.has(f))) throw new Error("unknown frozen case");
    }
  }
  const rows = closure.conditions.flatMap((condition) =>
    condition.cases.map((caseId) => {
      const facet = `${condition.conditionId}/${caseId}`;
      const evidence = reports.flatMap((report) =>
        report.rows
          .filter((r) => r.facets?.includes(facet))
          .map((r) => ({
            packet: report.packet,
            runId: report.production?.runId,
            closed: report.production?.closed === true,
            recordingSha256: report.production?.sha256,
            case: r.case,
            variant: r.variant ?? r.case,
            verdict:
              r.wire && /EVENTARC\/(publish-|admin-sdk)/.test(facet)
                ? r.wire.verdict
                : r.delivery
                  ? r.delivery.verdict
                  : r.verdict,
            declaredDifferences: r.declaredDifferences ?? [],
            reason: r.reason,
          })),
      );
      // Count distinct closed production runs for each measured variant, never repeated rows or A2 files.
      const variants = [...new Set(evidence.map((e) => e.variant))];
      const accepted = evidence.filter(
        (e) =>
          e.closed &&
          e.runId &&
          e.recordingSha256 &&
          (e.verdict === "MATCH" ||
            (e.verdict === "NOT_COMPARABLE" &&
              e.declaredDifferences.length === 1 &&
              {
                "numeric-project-alias": "project-number-not-configured",
                "remote-credential-validity-scope": "remote-credential-state",
                "channel-publication-propagation": "recorded-channel-propagation",
              }[e.declaredDifferences[0]] === e.reason)),
      );
      const productionRuns = [...new Set(accepted.map((e) => e.runId))];
      const repeated =
        variants.length > 0 &&
        variants.every(
          (v) => new Set(accepted.filter((e) => e.variant === v).map((e) => e.runId)).size >= 2,
        );
      const status = evidence.some((e) => e.verdict === "DIVERGES")
        ? "DIVERGES"
        : repeated
          ? "MATCH"
          : "NOT_COMPARABLE";
      return {
        conditionId: condition.conditionId,
        caseId,
        status,
        productionRuns,
        evidence,
        reason:
          status === "MATCH"
            ? "two-independent-closed-recordings"
            : status === "DIVERGES"
              ? "strict-divergence"
              : "missing-two-comparable-recordings",
        declaredDifferences: [...new Set(evidence.flatMap((e) => e.declaredDifferences))],
      };
    }),
  );
  return {
    schemaVersion: 1,
    parent: "EVENTARC",
    artifact,
    closureReview: { decision: "PENDING" },
    scopeDecisions: [
      "channel-list-unrecorded-order",
      "numeric-project-alias",
      "remote-credential-validity-scope",
      "channel-publication-propagation",
    ].map((id) => ({
      id,
      authority: "docs.local/runs/eventarc-lane/coordinator-rulings.md",
      decision: "DECLARED",
    })),
    missingPackets: ["B", "C", "D", "H1", "H2-A", "H2-B", "W"].filter(
      (p) => !reports.some((r) => r.packet === p),
    ),
    conditions: closure.conditions.map((c) => {
      const cases = rows.filter((r) => r.conditionId === c.conditionId);
      return {
        conditionId: c.conditionId,
        canonicalStatus: c.status,
        status: cases.some((r) => r.status === "DIVERGES")
          ? "DIVERGES"
          : cases.every((r) => r.status === "MATCH")
            ? "MATCH"
            : "NOT_COMPARABLE",
      };
    }),
    rows,
  };
}

export function main(argv) {
  const options = {};
  for (let i = 0; i < argv.length; i += 2) {
    if (!["--inputs", "--out"].includes(argv[i]) || !argv[i + 1])
      throw new Error("usage: --inputs <manifest> --out <private evidence>");
    options[argv[i].slice(2)] = argv[i + 1];
  }
  if (!options.inputs || !options.out) throw new Error("--inputs and --out are required");
  const read = (path) => {
    if (/private-inputs|credential|secret|token|\.env/i.test(basename(path)))
      throw new Error("credential and launch-input files are forbidden");
    return JSON.parse(readFileSync(path));
  };
  const inputs = read(options.inputs);
  const closure = read(
    fileURLToPath(new URL("../../../spec/compatibility/closure/EVENTARC.json", import.meta.url)),
  );
  const reports = inputs.reports.map((input) => {
    if (typeof input === "string") return read(input);
    const bytes = readFileSync(input.capture);
    const capture = bytes
      .toString()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l));
    return bindStageReport({
      packet: input.packet,
      capture,
      comparison: read(input.comparison),
      artifact: inputs.artifact,
      production: {
        runId: capture.find((r) => r.note === "run-start")?.runId,
        closed: read(input.summary).closureReady === true,
        sha256: createHash("sha256").update(bytes).digest("hex"),
      },
    });
  });
  const report = buildEvidence({ closure, reports, artifact: inputs.artifact });
  writeEvidence(options.out, report);
  process.stdout.write(
    JSON.stringify(
      Object.fromEntries(
        ["MATCH", "DIVERGES", "NOT_COMPARABLE"].map((v) => [
          v,
          report.rows.filter((r) => r.status === v).length,
        ]),
      ),
    ) + "\n",
  );
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    main(process.argv.slice(2));
  } catch {
    process.stderr.write("EVENTARC evidence failed; check comparison bindings and frozen cases\n");
    process.exitCode = 1;
  }
}
