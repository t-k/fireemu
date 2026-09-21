// A byte-faithful JS port of compile_plan() from
// tools/compat-broad/fs-commit-transform-limits/transform_compiler.py (read, not imported or
// modified; pinned by entry.compilerBlob in registry.mjs and cross-checked against the real
// Python source in test/commit-transform-plan.test.mjs). This is the same deterministic,
// credential-free compiler the FS-DATA-WRITE-COMMIT-TRANSFORMS-03 campaign used to build its
// request plan. This module runs it locally, with a caller-chosen project/database/nonce, to
// generate the identical *shape* of Commit requests -- not to replay the private production
// nonce/journals, which are not published (see registry.mjs and README.md for what evidence
// this case does and does not establish).
import { requireThat, digestJson } from "./core.mjs";

export const MAX_TRANSFORMS = 500;
export const CAMPAIGN = "FS-DATA-WRITE-COMMIT-TRANSFORMS-03";
const NONCE = /^[0-9a-f]{32}$/;
const TARGET = /^[A-Za-z0-9_-]+$/;

function fields(resource) {
  return {
    _sharedOwner: { referenceValue: resource },
    seed: { integerValue: "0" },
  };
}

function operation(kind, method, path, { body = null, expect, ...extra } = {}) {
  return {
    kind,
    service: "firestore",
    method,
    path,
    body,
    privileged: true,
    form: false,
    expect,
    ...extra,
  };
}

function commitBody(resource, count, outcome) {
  const first = Math.floor(count / 2);
  const second = count - first;
  const writes = [];
  let start = 0;
  for (const size of [first, second]) {
    writes.push({
      transform: {
        document: resource,
        fieldTransforms: Array.from({ length: size }, (_, i) => ({
          fieldPath: `t${start + i}`,
          increment: { integerValue: "1" },
        })),
      },
      currentDocument: { exists: true },
    });
    start += size;
  }
  return {
    writes,
    expect:
      outcome === "accepted"
        ? { outcome: "accepted", status: 200 }
        : { outcome, statusClass: "4xx" },
  };
}

export function compilePlan(project, database, nonce) {
  requireThat(typeof project === "string" && TARGET.test(project), "malformed-project");
  requireThat(
    typeof database === "string" && (database === "(default)" || TARGET.test(database)),
    "malformed-database",
  );
  requireThat(typeof nonce === "string" && NONCE.test(nonce), "malformed-nonce");

  const scope = `projects/${project}/databases/${database}/documents/oracle/${nonce}/commit-limits-03`;
  const resources = { "exact-500": `${scope}/exact-500`, "over-501": `${scope}/over-501` };
  const counts = { "exact-500": MAX_TRANSFORMS, "over-501": MAX_TRANSFORMS + 1 };
  const documents = {};
  for (const label of ["exact-500", "over-501"]) {
    const resource = resources[label];
    const count = counts[label];
    const base = fields(resource);
    documents[label] = {
      resource,
      fields: base,
      transformCount: count,
      expectedFields:
        label === "exact-500"
          ? {
              ...base,
              ...Object.fromEntries(
                Array.from({ length: count }, (_, i) => [`t${i}`, { integerValue: "1" }]),
              ),
            }
          : base,
    };
  }

  const observation = [];
  for (const label of ["exact-500", "over-501"]) {
    const resource = resources[label];
    observation.push(
      operation("preflight-typed-absence", "GET", "/v1/" + resource, {
        expect: { status: 404, typed: "NOT_FOUND" },
        resource,
      }),
    );
  }
  for (const label of ["exact-500", "over-501"]) {
    const resource = resources[label];
    observation.push(
      operation("create-only-patch", "PATCH", "/v1/" + resource + "?currentDocument.exists=false", {
        body: { name: resource, fields: structuredClone(documents[label].fields) },
        expect: { status: 200, marker: "owned" },
        resource,
      }),
    );
  }
  for (const label of ["exact-500", "over-501"]) {
    const resource = resources[label];
    observation.push(
      operation("baseline-readback", "GET", "/v1/" + resource, {
        expect: { status: 200, postState: "baseline" },
        resource,
      }),
    );
  }
  for (const [label, count, outcome] of [
    ["exact-500", MAX_TRANSFORMS, "accepted"],
    ["over-501", MAX_TRANSFORMS + 1, "refused"],
  ]) {
    const resource = resources[label];
    const body = commitBody(resource, count, outcome);
    const expectation = body.expect;
    delete body.expect;
    observation.push(
      operation(
        "commit-transform",
        "POST",
        "/v1/projects/" + project + "/databases/" + database + "/documents:commit",
        { body, expect: expectation, resources: [resource], transformCount: count },
      ),
    );
    observation.push(
      operation("poststate-readback", "GET", "/v1/" + resource, {
        expect: { status: 200, postState: outcome === "accepted" ? "transformed" : "unchanged" },
        resource,
      }),
    );
  }
  observation.push(
    operation("poststate-control-readback", "GET", "/v1/" + resources["exact-500"], {
      expect: { status: 200, postState: "transformed" },
      resource: resources["exact-500"],
    }),
  );

  const recovery = [];
  for (const label of ["exact-500", "over-501"]) {
    const resource = resources[label];
    recovery.push(
      operation("cleanup-ownership-read", "GET", "/v1/" + resource, {
        expect: { statuses: [200, 404], marker: "owned" },
        resource,
      }),
      operation("cleanup-conditional-delete", "DELETE", "/v1/" + resource, {
        expect: { status: 200, marker: "owned" },
        resource,
        versionFrom: recovery.length,
      }),
      operation("cleanup-verify-absence", "GET", "/v1/" + resource, {
        expect: { status: 404, typed: "NOT_FOUND" },
        resource,
      }),
    );
  }

  const plan = {
    schemaVersion: 1,
    campaignId: CAMPAIGN,
    project,
    database,
    nonce,
    ownedScope: scope,
    ownedResources: Object.values(resources),
    documents,
    observation,
    recovery,
    budget: {
      observationRequests: observation.length,
      recoveryRequests: recovery.length,
      requestUpperBound: observation.length + recovery.length,
      resourceUpperBound: 2,
      concurrencyUpperBound: 1,
    },
    productionReady: false,
  };
  plan.planDigest = digestJson(plan);
  return plan;
}
