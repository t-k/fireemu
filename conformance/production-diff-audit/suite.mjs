/**
 * A bounded response-mutation audit, not a production/runtime test runner.
 * The production projection is immutable. Only synthetic local controls change.
 */
import { createHash } from "node:crypto";

export const TASK = "COMPAT-COMPARE-AUDIT-001";
export const SCHEMA = "fireemu-comparison-audit-v1";
export const SUPPORTED_CASE = "fs.batch-write.saved-20260907.v1";
const MAX_PROBES = 160;
const MAX_DEPTH = 16;
const MAX_INPUT_BYTES = 128 * 1024;
const clone = (value) => structuredClone(value);
const own = (value, key) => Object.prototype.hasOwnProperty.call(value, key);
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const fail = (code) => {
  throw new Error(code);
};
const requireValue = (value, code) => {
  if (!value) fail(code);
};

// Independent of the subject's equality implementation. No-op mutations must not
// count as surviving bugs, and bool/number/string must stay distinct.
export function canonical(value, depth = 0) {
  requireValue(depth <= MAX_DEPTH, "audit-input-too-deep");
  if (value === null || typeof value === "boolean" || typeof value === "string")
    return JSON.stringify(value);
  if (typeof value === "number") {
    requireValue(Number.isFinite(value), "audit-input-not-json");
    return JSON.stringify(value);
  }
  if (Array.isArray(value))
    return "[" + value.map((item) => canonical(item, depth + 1)).join(",") + "]";
  requireValue(
    object(value) && [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    "audit-input-not-json",
  );
  return (
    "{" +
    Object.keys(value)
      .sort()
      .map((key) => JSON.stringify(key) + ":" + canonical(value[key], depth + 1))
      .join(",") +
    "}"
  );
}
export const fingerprint = (value) => createHash("sha256").update(canonical(value)).digest("hex");
const rawFingerprint = (value) => createHash("sha256").update(JSON.stringify(value)).digest("hex");
const pointer = (segments) =>
  "/" + segments.map((s) => String(s).replaceAll("~", "~0").replaceAll("/", "~1")).join("/");

export function syntheticControl(entry, production) {
  requireValue(
    entry?.id === SUPPORTED_CASE && entry.programId === "writes/batch-write",
    "unsupported-audit-case",
  );
  requireValue(
    Array.isArray(entry.stepIds) && entry.stepIds.length === 5 && new Set(entry.stepIds).size === 5,
    "audit-case-shape",
  );
  const programs = production?.programs;
  requireValue(
    Array.isArray(programs) && programs.length === 1 && programs[0].id === entry.programId,
    "audit-projection-shape",
  );
  const steps = programs[0].steps;
  requireValue(
    object(steps) && JSON.stringify(Object.keys(steps)) === JSON.stringify(entry.stepIds),
    "audit-projection-steps",
  );
  const local = { [entry.programId]: { steps: {} } };
  for (const id of entry.stepIds) {
    const row = steps[id]?.production;
    requireValue(
      object(row) &&
        Number.isInteger(row.status) &&
        row.status >= 200 &&
        row.status <= 599 &&
        /^[A-Z][A-Z_]*$/.test(row.code ?? "") &&
        row.missing !== true &&
        (row.code !== "OK" || own(row, "body")),
      "audit-projection-row",
    );
    local[entry.programId].steps[id] = clone(row);
  }
  requireValue(Buffer.byteLength(canonical(local)) <= MAX_INPUT_BYTES, "audit-input-too-large");
  return local;
}

function replaceAt(root, path, value) {
  let node = root;
  for (const part of path.slice(0, -1)) node = node[part];
  node[path.at(-1)] = value;
}
function deleteAt(root, path) {
  let node = root;
  for (const part of path.slice(0, -1)) node = node[part];
  delete node[path.at(-1)];
}
function leaves(value, path = [], result = []) {
  if (object(value)) {
    for (const key of Object.keys(value).sort()) leaves(value[key], [...path, key], result);
  } else if (Array.isArray(value)) {
    // This first audit does not invent an array oracle when none was recorded.
  } else result.push({ path, value });
  return result;
}
function differentScalar(value) {
  if (typeof value === "string")
    return /^-?\d+$/.test(value) ? (BigInt(value) + 1n).toString() : value + ":audit";
  if (typeof value === "boolean") return !value;
  if (typeof value === "number") return value === 0 ? 1 : 0;
  return false;
}
function reverseObjectKeys(value) {
  if (Array.isArray(value)) return value.map(reverseObjectKeys);
  return object(value)
    ? Object.fromEntries(
        Object.keys(value)
          .reverse()
          .map((k) => [k, reverseObjectKeys(value[k])]),
      )
    : value;
}
const executionControl = () => ({
  origin: "synthetic-audit-control-no-process",
  freshLocalExecution: false,
  state: "completed",
  cleanup: { state: "confirmed" },
  process: { state: "stopped" },
});

/** Finite catalog for the existing five-step BatchWrite pilot. No input DSL. */
export function buildProbes(entry, local) {
  const probes = [];
  function add(id, group, dimension, path, mutate, expected, refusalCodes = []) {
    requireValue(!probes.some((p) => p.id === id), "duplicate-audit-probe");
    probes.push({ id, group, dimension, path: pointer(path), mutate, expected, refusalCodes });
    requireValue(probes.length <= MAX_PROBES, "audit-probe-cap");
  }
  const programId = entry.programId;
  for (const id of entry.stepIds) {
    const path = [programId, "steps", id];
    const row = local[programId].steps[id];
    const base = id.replaceAll("/", ".");
    add(
      `status.${base}`,
      "semantic",
      "http-status",
      [...path, "status"],
      (state) => {
        state.local[programId].steps[id].status =
          row.status === 200 ? 201 : row.status === 400 ? 409 : 403;
      },
      "MISMATCH",
    );
    add(
      `code.${base}`,
      "semantic",
      "canonical-code",
      [...path, "code"],
      (state) => {
        state.local[programId].steps[id].code =
          row.code === "OK"
            ? "INTERNAL"
            : row.code === "INVALID_ARGUMENT"
              ? "FAILED_PRECONDITION"
              : "PERMISSION_DENIED";
      },
      "MISMATCH",
    );
    add(
      `missing.${base}`,
      "integrity",
      "row-completeness",
      path,
      (state) => deleteAt(state.local, path),
      "INDETERMINATE",
    );
    add(
      `timeout.${base}`,
      "integrity",
      "transport-completeness",
      path,
      (state) => replaceAt(state.local, path, { status: 0, code: "no-response" }),
      "INDETERMINATE",
    );
    add(
      `flag-missing.${base}`,
      "integrity",
      "row-completeness",
      path,
      (state) => {
        state.local[programId].steps[id].missing = true;
      },
      "INDETERMINATE",
    );
    add(
      `status-type.${base}`,
      "integrity",
      "row-schema",
      [...path, "status"],
      (state) => {
        state.local[programId].steps[id].status = String(row.status);
      },
      "INDETERMINATE",
    );
    if (row.code !== "OK") {
      add(
        `accepted.${base}`,
        "semantic",
        "acceptance-vs-refusal",
        path,
        (state) => replaceAt(state.local, path, { status: 200, code: "OK", body: {} }),
        "MISMATCH",
      );
      add(
        `message.${base}`,
        "tolerance",
        "error-prose-excluded",
        [...path, "message"],
        (state) => {
          state.local[programId].steps[id].message = "deliberately different diagnostic prose";
        },
        "MATCH",
      );
      add(
        `message-missing.${base}`,
        "tolerance",
        "error-prose-excluded",
        [...path, "message"],
        (state) => {
          delete state.local[programId].steps[id].message;
        },
        "MATCH",
      );
    } else {
      add(
        `refused.${base}`,
        "semantic",
        "acceptance-vs-refusal",
        path,
        (state) => replaceAt(state.local, path, { status: 404, code: "NOT_FOUND" }),
        "MISMATCH",
      );
      add(
        `body-missing.${base}`,
        "integrity",
        "row-completeness",
        [...path, "body"],
        (state) => {
          delete state.local[programId].steps[id].body;
        },
        "INDETERMINATE",
      );
      add(
        `body-null.${base}`,
        "semantic",
        "body-presence-and-type",
        [...path, "body"],
        (state) => {
          state.local[programId].steps[id].body = null;
        },
        "MISMATCH",
      );
      add(
        `body-extra.${base}`,
        "semantic",
        "field-presence",
        [...path, "body"],
        (state) => {
          state.local[programId].steps[id].body.__auditExtra = null;
        },
        "MISMATCH",
      );
      for (const key of Object.keys(row.body).sort()) {
        add(
          `body-delete.${base}.${key}`,
          "semantic",
          "field-presence",
          [...path, "body", key],
          (state) => {
            delete state.local[programId].steps[id].body[key];
          },
          "MISMATCH",
        );
      }
      for (const { path: fieldPath, value } of leaves(row.body)) {
        const fieldId = fieldPath.join(".");
        add(
          `value.${base}.${fieldId}`,
          "semantic",
          fieldPath.at(-1) === "name"
            ? "resource-identity"
            : value === "<now>"
              ? "normalized-placeholder-shape"
              : "retained-field-value",
          [...path, "body", ...fieldPath],
          (state) => {
            replaceAt(state.local, [...path, "body", ...fieldPath], differentScalar(value));
          },
          "MISMATCH",
        );
        add(
          `type.${base}.${fieldId}`,
          "semantic",
          "json-value-type",
          [...path, "body", ...fieldPath],
          (state) => {
            replaceAt(
              state.local,
              [...path, "body", ...fieldPath],
              typeof value === "boolean" ? Number(value) : true,
            );
          },
          "MISMATCH",
        );
      }
    }
  }
  const doc = [programId, "steps", "existing-was-deleted", "body", "fields", "a"];
  add(
    "post-state.boolean-instead-of-integer",
    "semantic",
    "firestore-value-type",
    doc,
    (state) => {
      replaceAt(state.local, doc, { booleanValue: true });
    },
    "MISMATCH",
  );
  add(
    "post-state.double-instead-of-integer",
    "semantic",
    "firestore-value-type",
    doc,
    (state) => {
      replaceAt(state.local, doc, { doubleValue: 1 });
    },
    "MISMATCH",
  );
  add(
    "post-state.field-deleted",
    "semantic",
    "refusal-post-state",
    doc,
    (state) => deleteAt(state.local, doc),
    "MISMATCH",
  );
  add(
    "rows.extra",
    "integrity",
    "row-completeness",
    [programId, "steps"],
    (state) => {
      state.local[programId].steps.extra = { status: 200, code: "OK", body: {} };
    },
    "INDETERMINATE",
  );
  add(
    "rows.reordered",
    "integrity",
    "operation-order",
    [programId, "steps"],
    (state) => {
      state.local[programId].steps = Object.fromEntries(
        Object.entries(state.local[programId].steps).reverse(),
      );
    },
    "INDETERMINATE",
  );
  add(
    "setup.failure",
    "integrity",
    "setup-completeness",
    [programId, "seedError"],
    (state) => {
      state.local[programId].seedError = "synthetic setup failure";
    },
    "INDETERMINATE",
  );
  add(
    "program.extra",
    "integrity",
    "program-identity",
    ["extra"],
    (state) => {
      state.local.extra = { steps: {} };
    },
    "INDETERMINATE",
  );
  add(
    "request.changed",
    "binding",
    "same-id-changed-input",
    ["program", "steps", 0, "body", "writes"],
    (state) => {
      state.program.steps[0].body.writes.pop();
    },
    "REFUSED",
    ["program-input-drift"],
  );
  add(
    "seed.changed",
    "binding",
    "same-id-changed-setup",
    ["program", "seed", 0, "fields"],
    (state) => {
      state.program.seed[0].fields.a.integerValue = "2";
    },
    "REFUSED",
    ["program-input-drift"],
  );
  add(
    "request.reordered",
    "binding",
    "same-id-changed-sequence",
    ["program", "steps"],
    (state) => {
      state.program.steps.reverse();
    },
    "REFUSED",
    ["program-step-set"],
  );
  add(
    "object-keys.reordered",
    "tolerance",
    "json-object-key-order",
    [programId, "steps", "existing-was-deleted", "body"],
    (state) => {
      const row = state.local[programId].steps["existing-was-deleted"];
      row.body = reverseObjectKeys(row.body);
    },
    "MATCH",
  );
  for (const [id, change] of [
    [
      "cleanup-unconfirmed",
      (state) => {
        state.execution.cleanup.state = "unconfirmed";
      },
    ],
    [
      "process-unconfirmed",
      (state) => {
        state.execution.process.state = "unconfirmed";
      },
    ],
    [
      "execution-failed",
      (state) => {
        state.execution.state = "failed";
      },
    ],
    [
      "cleanup-missing",
      (state) => {
        delete state.execution.cleanup;
      },
    ],
    [
      "process-missing",
      (state) => {
        delete state.execution.process;
      },
    ],
  ])
    add(
      `envelope.${id}`,
      "envelope",
      "execution-admission",
      ["execution"],
      change,
      "INDETERMINATE",
    );
  return probes;
}

function validateComparison(comparison, entry) {
  requireValue(
    object(comparison) && ["MATCH", "MISMATCH", "INDETERMINATE"].includes(comparison.verdict),
    "audit-subject-result-shape",
  );
  requireValue(
    Array.isArray(comparison.rows) &&
      comparison.rows.length === entry.stepIds.length &&
      JSON.stringify(comparison.rows.map((r) => r?.stepId)) === JSON.stringify(entry.stepIds),
    "audit-subject-row-set",
  );
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of comparison.rows) {
    requireValue(
      ["MATCH", "MISMATCH", "INDETERMINATE"].includes(row.comparison),
      "audit-subject-row-verdict",
    );
    counts[row.comparison.toLowerCase()]++;
  }
  requireValue(canonical(counts) === canonical(comparison.counts), "audit-subject-counts");
  const expected = counts.indeterminate ? "INDETERMINATE" : counts.mismatch ? "MISMATCH" : "MATCH";
  requireValue(comparison.verdict === expected, "audit-subject-verdict-contradiction");
  return comparison.verdict;
}

function summarize(outcomes) {
  const groups = {};
  for (const group of ["semantic", "integrity", "binding", "envelope", "tolerance"]) {
    const rows = outcomes.filter((r) => r.group === group);
    groups[group] = {
      total: rows.length,
      passed: rows.filter((r) => r.passed).length,
      failed: rows.filter((r) => !r.passed).length,
      errors: rows.filter((r) => r.observed === "ERROR" || r.observed === "NO_OP").length,
    };
  }
  const semantic = outcomes.filter((r) => r.group === "semantic");
  return {
    groups,
    semanticDetected: semantic.filter((r) => r.passed).length,
    semanticMissed: semantic.filter((r) => r.observed === "MATCH").length,
    semanticWrongClassification: semantic.filter((r) =>
      ["INDETERMINATE", "REFUSED"].includes(r.observed),
    ).length,
    semanticErrors: semantic.filter((r) => ["ERROR", "NO_OP"].includes(r.observed)).length,
    semanticTotal: semantic.length,
  };
}

/**
 * Subject interface is internal, not a dynamically loaded user plugin:
 * {entry, program, production, compare(actual, program), envelope(comparison, execution)}.
 * identity is supplied by the trusted installed adapter or explicitly test-only fixture.
 */
export function auditSubject(subject, identity) {
  const report = {
    schema: SCHEMA,
    taskId: TASK,
    caseId: subject.entry?.id ?? null,
    evidenceKind: "comparator-response-mutation-audit",
    productionExecuted: false,
    nativeRuntimeExecuted: false,
    freshLocalExecution: false,
    acquisitionValidated: false,
    parentPromotion: false,
    compatibilityEstablished: false,
    baselineKind: "synthetic-local-control-from-saved-production-projection",
    auditPassed: false,
    auditState: "INDETERMINATE",
    baseline: null,
    identity: clone(identity),
    outcomes: [],
    summary: summarize([]),
    errors: [],
    notEstablished: [
      "This is not a runtime/source-code mutation test or a new production observation.",
      "The synthetic local control is not an observed fireemu execution.",
      "Array ordering: no ordered success array occurs in this pilot; not exercised.",
      "Timestamp relationships: erased by the historical recorder; not recoverable here.",
      "Error prose is excluded by the existing contract; tolerance tests are not detections.",
      "Auth, Rules, tenant identities, SDKs, Listen, concurrency and other limit cases are not exercised.",
      "A passing audit is not G1/G2 completion, source attestation, or independent approval.",
    ],
  };
  let local, original, baseline;
  try {
    local = syntheticControl(subject.entry, subject.production);
    original = rawFingerprint({ program: subject.program, production: subject.production });
    const actual = clone(local),
      program = clone(subject.program),
      before = rawFingerprint({ actual, program });
    baseline = subject.compare(actual, program);
    requireValue(rawFingerprint({ actual, program }) === before, "audit-subject-mutated-input");
    requireValue(
      validateComparison(baseline, subject.entry) === "MATCH",
      "audit-baseline-not-match",
    );
    const envelope = subject.envelope(clone(baseline), executionControl());
    requireValue(
      envelope?.gatePassed === true &&
        envelope.complete === true &&
        envelope.comparison?.verdict === "MATCH",
      "audit-baseline-envelope",
    );
    report.baseline = {
      passed: true,
      rowCount: baseline.rows.length,
      localControlSha256: fingerprint(local),
    };
  } catch {
    report.errors.push("baseline-or-contract-not-usable");
    report.baseline = { passed: false };
    return report;
  }
  let probes;
  try {
    probes = buildProbes(subject.entry, local);
  } catch {
    report.errors.push("probe-generation-failed");
    return report;
  }
  for (const probe of probes) {
    const state = {
      local: clone(local),
      program: clone(subject.program),
      execution: executionControl(),
    };
    const before = rawFingerprint(state);
    const row = {
      id: probe.id,
      group: probe.group,
      dimension: probe.dimension,
      path: probe.path,
      expected: probe.expected,
      observed: "ERROR",
      passed: false,
      mutationApplied: false,
    };
    try {
      probe.mutate(state);
      row.mutationApplied = before !== rawFingerprint(state);
      requireValue(row.mutationApplied, "audit-no-op");
      row.syntheticInputSha256 = rawFingerprint(state);
      const untouched = rawFingerprint(state);
      try {
        if (probe.group === "envelope") {
          const envelope = subject.envelope(clone(baseline), state.execution);
          requireValue(
            envelope?.complete === false &&
              envelope?.gatePassed === false &&
              envelope?.comparison?.verdict === "INDETERMINATE",
            "audit-envelope-not-rejected",
          );
          row.observed = "INDETERMINATE";
        } else {
          row.observed = validateComparison(
            subject.compare(state.local, state.program),
            subject.entry,
          );
        }
      } catch (error) {
        if (probe.expected === "REFUSED" && probe.refusalCodes.includes(error?.message))
          row.observed = "REFUSED";
        else throw error;
      }
      requireValue(rawFingerprint(state) === untouched, "audit-subject-mutated-input");
      row.passed = row.observed === probe.expected;
    } catch (error) {
      row.observed = error?.message === "audit-no-op" ? "NO_OP" : "ERROR";
      row.passed = false;
      // Never publish exception text, response payloads or stack traces.
    }
    report.outcomes.push(row);
  }
  report.summary = summarize(report.outcomes);
  report.inputUnchanged =
    rawFingerprint({ program: subject.program, production: subject.production }) === original;
  if (!report.inputUnchanged) report.errors.push("subject-source-input-mutated");
  report.auditPassed =
    report.inputUnchanged &&
    report.summary.semanticTotal > 0 &&
    report.outcomes.length === probes.length &&
    report.outcomes.every((r) => r.passed);
  report.auditState = report.auditPassed ? "PASSED" : "FAILED";
  return report;
}

export function auditExitCode(report) {
  return report.auditPassed ? 0 : report.auditState === "FAILED" ? 1 : 2;
}
export function renderReport(report) {
  const lines = [
    "# Comparator response-mutation audit",
    "",
    `Case: ${report.caseId}`,
    `Audit: ${report.auditState}`,
    `Baseline: ${report.baselineKind}`,
    `Evidence: ${report.evidenceKind}`,
    "New production requests: 0. Native fireemu executions: 0.",
    "",
    "## Counts (not a compatibility percentage)",
    "",
    "| Group | Applied probes | Expected result obtained | Failed | Harness errors/no-op |",
    "|---|---:|---:|---:|---:|",
  ];
  for (const [name, row] of Object.entries(report.summary.groups))
    lines.push(`| ${name} | ${row.total} | ${row.passed} | ${row.failed} | ${row.errors} |`);
  lines.push(
    "",
    "## Probe outcomes",
    "",
    "| ID | Expected | Observed | Pass |",
    "|---|---|---|---|",
  );
  for (const row of report.outcomes)
    lines.push(`| ${row.id} | ${row.expected} | ${row.observed} | ${row.passed} |`);
  lines.push("", "## Not established", ...report.notEstablished.map((x) => "- " + x), "");
  return lines.join("\n");
}
