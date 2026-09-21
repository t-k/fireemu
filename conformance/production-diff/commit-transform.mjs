// Case adapter for fs.commit-transform-limits.saved-031c74bfe.v1.
//
// Unlike the BatchWrite case (legacy.mjs), the raw production request/response journal for this
// campaign is not published: spec/compatibility/broad-runs/fs-commit-transform-limits-*.json are
// digest/summary records only ("Raw nonce, credentials, owned resource names and document
// payloads are retained privately and are not published here" -- both files, and
// docs/compatibility/fs-commit-transform-limits-production-result.md, say this explicitly). This
// module therefore does not attempt byte-for-byte replay of the private journal. Instead it:
//
//   1. Compiles the exact same deterministic request plan the campaign's own compiler produces
//      (commit-transform-plan.mjs, a pinned, test-cross-checked port of transform_compiler.py),
//      using a locally chosen project/nonce instead of the private production one.
//   2. Builds a typed per-row reference from that plan's own declared `expect`/`documents`
//      structure plus the one piece of production evidence that IS published verbatim: the
//      literal refusal message text in conditionObserved.refused, pinned by this module against
//      the immutable production-result.json.
//   3. Compares the local fireemu execution against that typed reference: HTTP status and
//      canonical error code for every row, plus typed body content (write-result count, the
//      literal refusal message, and post-state field identity) for the rows the campaign's own
//      classification says those checks are meaningful for.
//
// What this does NOT establish: byte-exact parity with the private production request/response
// bytes, or the resource-name-normalized message parity the repaired Python comparator
// (transform_comparator.py) verifies for the four typed-absence rows -- this module deliberately
// does not compare error messages for typed-absence rows, because the real message differs by
// project/nonce and this case cannot reproduce the private normalization without the real
// journal. See registry.mjs's `notEstablished` for the complete, disclosed scope.
import { requireThat, sha256, digestJson, equal, canonical } from "./core.mjs";
import { readSource, gitState } from "./io.mjs";
import { pin, adapterSourceDigests } from "./legacy.mjs";
import { compilePlan } from "./commit-transform-plan.mjs";

function labelOf(plan, resource) {
  for (const [label, doc] of Object.entries(plan.documents))
    if (doc.resource === resource) return label;
  return null;
}
export function stepIdOf(plan, op) {
  return `${op.kind}:${labelOf(plan, op.resource ?? op.resources?.[0])}`;
}
export function planOperations(plan) {
  return [...plan.observation, ...plan.recovery];
}

/** The typed, per-row reference this case compares local execution against. Not raw production
 * bytes (see module docstring): status/code/typed-body content derived from the plan's own
 * declared contract, plus the one literal message pinned from the saved production record. */
export function documentedReference(plan, entry) {
  return planOperations(plan).map((op) => {
    const label = labelOf(plan, op.resource ?? op.resources?.[0]);
    const doc = plan.documents[label];
    const base = {
      stepId: stepIdOf(plan, op),
      kind: op.kind,
      resource: op.resource ?? op.resources?.[0],
    };
    switch (op.kind) {
      case "preflight-typed-absence":
      case "cleanup-verify-absence":
        return { ...base, check: "status-and-code", status: 404, code: "NOT_FOUND" };
      case "create-only-patch":
      case "baseline-readback":
        return { ...base, check: "status-and-fields", status: 200, fields: doc.fields };
      case "poststate-readback":
      case "poststate-control-readback":
        return {
          ...base,
          check: "status-and-fields",
          status: 200,
          fields: op.expect.postState === "transformed" ? doc.expectedFields : doc.fields,
        };
      case "cleanup-ownership-read":
        return {
          ...base,
          check: "status-and-fields",
          status: 200,
          fields: doc.transformCount === 500 ? doc.expectedFields : doc.fields,
        };
      case "cleanup-conditional-delete":
        return { ...base, check: "status-only", status: 200 };
      case "commit-transform":
        if (op.expect.outcome === "accepted") {
          // One writeResult per write (Firestore's Commit contract), each carrying its own
          // transformResults array sized to that write's own fieldTransforms -- not one flat
          // array sized to the total transform count across every write.
          const transformResultCounts = op.body.writes.map(
            (w) => w.transform.fieldTransforms.length,
          );
          return {
            ...base,
            check: "status-and-write-count",
            status: 200,
            writeResultCount: op.body.writes.length,
            transformResultCounts,
          };
        }
        return {
          ...base,
          check: "status-code-and-message",
          status: 400,
          code: "INVALID_ARGUMENT",
          message: entry.refusedCommitMessage,
        };
      default:
        throw new Error("unknown-operation-kind");
    }
  });
}

function checkRow(reference, actualRow) {
  if (!actualRow || typeof actualRow.status !== "number") return false;
  if (actualRow.status !== reference.status) return false;
  const body = actualRow.body;
  switch (reference.check) {
    case "status-only":
      return true;
    case "status-and-code":
      return body?.error?.status === reference.code && body?.error?.code === reference.status;
    case "status-and-fields":
      return equal(body?.fields, reference.fields) && body?.name === reference.resource;
    case "status-and-write-count":
      return (
        Array.isArray(body?.writeResults) &&
        body.writeResults.length === reference.writeResultCount &&
        equal(
          body.writeResults.map((w) =>
            Array.isArray(w?.transformResults) ? w.transformResults.length : -1,
          ),
          reference.transformResultCounts,
        )
      );
    case "status-code-and-message":
      return (
        body?.error?.status === reference.code &&
        body?.error?.code === reference.status &&
        body?.error?.message === reference.message
      );
    default:
      return false;
  }
}

export function validateCommitPlan(plan, entry) {
  requireThat(
    canonical(plan) === canonical(compilePlan(entry.project, entry.database, entry.nonce)),
    "commit-plan-compiler-drift",
  );
  requireThat(plan.planDigest === entry.programDigest, "commit-plan-digest-drift");
  requireThat(
    equal(
      planOperations(plan).map((op) => stepIdOf(plan, op)),
      entry.stepIds,
    ),
    "commit-plan-step-set",
  );
  return plan;
}

export async function prepareCommitTransform(repo, entry) {
  const state = gitState(repo);
  const productionResultBytes = pin(
    await readSource(repo, entry.productionResultPath),
    entry.productionResultBlob,
  );
  const productionResult = JSON.parse(productionResultBytes);
  const savedResultBytes = pin(
    await readSource(repo, entry.savedResultPath),
    entry.savedResultBlob,
  );
  const savedResult = JSON.parse(savedResultBytes);
  pin(await readSource(repo, entry.compilerPath), entry.compilerBlob);
  pin(await readSource(repo, entry.comparatorPath), entry.comparatorBlob);
  // The literal refusal message text is the one piece of raw production evidence that IS
  // published (inside the immutable summary record). Self-consistency: derive it from that
  // record rather than trusting only the copy pinned into registry.mjs.
  const refusedMatch = /"([^"]+)"\s*$/.exec(productionResult.conditionObserved?.refused ?? "");
  requireThat(refusedMatch?.[1] === entry.refusedCommitMessage, "refusal-message-pin-mismatch");
  requireThat(
    equal(productionResult.comparison?.rowClassificationCounts, {
      MATCH: 13,
      SEMANTIC_MISMATCH: 4,
    }) && equal(savedResult.rowClassificationCounts, { MATCH: 17 }),
    "saved-record-classification-drift",
  );
  const plan = validateCommitPlan(compilePlan(entry.project, entry.database, entry.nonce), entry);
  const production = documentedReference(plan, entry);
  return {
    entry,
    state,
    program: plan,
    production,
    provenance: {
      repository: state,
      oracle: {
        productionResultPath: entry.productionResultPath,
        productionResultBlob: entry.productionResultBlob,
        productionResultSha256: sha256(productionResultBytes),
        savedResultPath: entry.savedResultPath,
        savedResultBlob: entry.savedResultBlob,
        savedResultSha256: sha256(savedResultBytes),
        productionSourceCommit: productionResult.sourceCommit,
        savedRecompareCommit: savedResult.sourceCommit,
        localPlanDigest: plan.planDigest,
        historicalRawAvailable: false,
        evidenceNote:
          "typed reference derived from the published summary + compiled plan contract; see commit-transform.mjs docstring",
      },
      implementation: {
        adapterSha256: await adapterSourceDigests(),
        compilerBlob: entry.compilerBlob,
        comparatorBlob: entry.comparatorBlob,
        comparatorSliceSha256: null,
        sessionBlob: null,
        credentialsBlob: null,
      },
    },
  };
}

export async function commitTransformSourceUnchanged(repo, entry, before, adapterBefore) {
  try {
    if (gitState(repo).head !== before.head) return false;
    requireThat(
      digestJson(await adapterSourceDigests()) === digestJson(adapterBefore),
      "adapter-source-changed",
    );
    for (const [path, hash] of [
      [entry.productionResultPath, entry.productionResultBlob],
      [entry.savedResultPath, entry.savedResultBlob],
      [entry.compilerPath, entry.compilerBlob],
      [entry.comparatorPath, entry.comparatorBlob],
    ])
      pin(await readSource(repo, path), hash);
    return true;
  } catch {
    return false;
  }
}

/** Wrap, do not reinterpret, the typed per-row reference built by documentedReference(). */
export function compareCommitTransform({ entry, program, production, actual }) {
  validateCommitPlan(program, entry);
  const issues = [];
  if (
    !actual ||
    actual.schema !== "fireemu-commit-transform-local-rows-v1" ||
    actual.caseId !== entry.id ||
    !Array.isArray(actual.rows)
  )
    issues.push("local-record-shape");
  const localRows = actual?.rows ?? [];
  if (localRows.length !== production.length) issues.push("local-row-count");
  const rows = production.map((reference, index) => {
    const local = localRows[index];
    const valid = !issues.length && local?.stepId === reference.stepId;
    return {
      stepId: reference.stepId,
      comparison: valid ? (checkRow(reference, local) ? "MATCH" : "MISMATCH") : "INDETERMINATE",
      production: { status: reference.status, check: reference.check },
      local: local ? { status: local.status } : null,
    };
  });
  const counts = { match: 0, mismatch: 0, indeterminate: 0 };
  for (const row of rows) counts[row.comparison.toLowerCase()]++;
  const verdict = counts.indeterminate ? "INDETERMINATE" : counts.mismatch ? "MISMATCH" : "MATCH";
  return {
    verdict,
    counts,
    rows,
    issues,
    legacySummary: null,
    legacyMismatchesIncludesIndeterminate: false,
  };
}
