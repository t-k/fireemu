// The signer role and binding of the signed PUT observer (owner ledger 2216, same form as
// AUTH-CONFIG-SDK K6): a custom role holding only iam.serviceAccounts.signBlob, granted to the
// owner's user on the Firebase Admin SDK service account of the sandbox project with a time
// condition, and removed after the run, on failure too. Nothing else about IAM is ever changed:
// every policy this module writes is checked to differ from the policy it read by exactly the
// run's own binding.

import { GuardError, POLICY_VERSION_PARAM, isUnknownStatus } from "./guard.mjs";
import { UnknownAnswer } from "./wire.mjs";
import {
  MAX_REMOVE_ATTEMPTS,
  MAX_ROLE_READS,
  MAX_WINDOW_MINUTES,
  ROLE_ID,
  SIGNER_PERMISSION,
  STORAGE_PERMISSIONS,
} from "./plan.mjs";

export const MIN_WINDOW_MINUTES = 10;

export const roleName = (project) => `projects/${project}/roles/${ROLE_ID}`;

export class IamStop extends Error {}

const stop = (message) => {
  throw new IamStop(message);
};

export function validateMember(value) {
  if (typeof value !== "string" || !/^user:[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$/.test(value)) {
    throw new GuardError("request refused: the member must be user:<email>");
  }
  return value;
}

export function validateWindow(minutes) {
  if (!Number.isInteger(minutes) || minutes < MIN_WINDOW_MINUTES || minutes > MAX_WINDOW_MINUTES) {
    throw new GuardError(
      `request refused: the window must be ${MIN_WINDOW_MINUTES} to ${MAX_WINDOW_MINUTES} whole minutes`,
    );
  }
  return minutes;
}

/** The time condition: the binding stops applying at `endMs` whatever else happens. */
export function conditionFor(runId, endMs) {
  const end = new Date(endMs).toISOString().replace(/\.\d{3}Z$/, "Z");
  return {
    title: `storage-signed-put-${runId}`,
    description: "signBlob for the signed PUT observation; removed after the run",
    expression: `request.time < timestamp("${end}")`,
  };
}

export function ourBinding({ project, member, runId, endMs }) {
  return { role: roleName(project), members: [member], condition: conditionFor(runId, endMs) };
}

/** The body of the role create request (signBlob and nothing else). */
export function roleBody() {
  return {
    roleId: ROLE_ID,
    role: {
      title: "fireemu signed PUT signer",
      description: "signBlob only; created and removed by the signed PUT observer",
      includedPermissions: [SIGNER_PERMISSION],
      stage: "GA",
    },
  };
}

const conditionKey = (condition) =>
  condition ? `${condition.title ?? ""}\u0000${condition.expression ?? ""}` : "";

/** Bindings in a canonical order, for comparison apart from etag and version. */
export function normalizePolicy(policy) {
  const bindings = (policy?.bindings ?? [])
    .map((b) => ({
      role: b.role,
      members: [...(b.members ?? [])].toSorted(),
      condition: b.condition
        ? {
            title: b.condition.title ?? "",
            description: b.condition.description ?? "",
            expression: b.condition.expression ?? "",
          }
        : null,
    }))
    .toSorted((a, b) =>
      `${a.role}\u0001${conditionKey(a.condition)}`.localeCompare(
        `${b.role}\u0001${conditionKey(b.condition)}`,
      ),
    );
  return { bindings, auditConfigs: policy?.auditConfigs ?? [] };
}

export const samePolicy = (a, b) =>
  JSON.stringify(normalizePolicy(a)) === JSON.stringify(normalizePolicy(b));

/**
 * Whether any binding names the signer role or a role id that starts with it. IAM reports a
 * conditional binding as `<role>_withcond_<hash>` without its condition when the policy is read as
 * version 1, so the prefix is what must fail closed.
 */
export const holdsRole = (policy, role) =>
  (policy?.bindings ?? []).some((b) => typeof b.role === "string" && b.role.startsWith(role));

export const validEtag = (etag) => typeof etag === "string" && etag.length > 0;

const needEtag = (policy) => {
  if (!validEtag(policy?.etag))
    throw new GuardError("request refused: the policy to write has no etag");
};

const isOurs = (binding, ours) =>
  binding.role === ours.role &&
  conditionKey(binding.condition) === conditionKey(ours.condition) &&
  (binding.members ?? []).includes(ours.members[0]);

/** The policy plus the run's binding, at policy version 3 (conditions need it). */
export function withBinding(policy, ours) {
  if (holdsRole(policy, ours.role)) stop("the signer's policy already holds the signer role");
  return {
    ...policy,
    version: 3,
    bindings: [...(policy.bindings ?? []), ours],
  };
}

/** The policy without the run's binding; other bindings, even of the same role, stay. */
export function withoutBinding(policy, ours) {
  const bindings = [];
  for (const binding of policy.bindings ?? []) {
    if (!isOurs(binding, ours)) {
      bindings.push(binding);
      continue;
    }
    const members = binding.members.filter((m) => m !== ours.members[0]);
    if (members.length > 0) bindings.push({ ...binding, members });
  }
  return { ...policy, version: 3, bindings };
}

/** Throws unless `after` is `before` with exactly the run's binding added. */
export function assertGrantShape(before, after, ours) {
  needEtag(before);
  if (!samePolicy(after, withBinding(before, ours))) {
    throw new GuardError(
      "request refused: the policy to write differs from the one read by more than the run's binding",
    );
  }
  if (after.etag !== before.etag)
    throw new GuardError("request refused: the policy to write carries another etag");
}

/** Throws unless `after` is `before` with exactly the run's binding removed. */
export function assertRemovalShape(before, after, ours) {
  needEtag(before);
  if (!samePolicy(after, withoutBinding(before, ours))) {
    throw new GuardError(
      "request refused: the policy to write differs from the one read by more than the run's binding",
    );
  }
  if (after.etag !== before.etag)
    throw new GuardError("request refused: the policy to write carries another etag");
}

/** Roles bound to the signer without a condition, in the given policies. */
export function signerRoles(signer, policies) {
  const roles = new Set();
  let conditional = 0;
  for (const policy of policies) {
    for (const binding of policy?.bindings ?? []) {
      if (!(binding.members ?? []).includes(`serviceAccount:${signer}`)) continue;
      if (binding.condition) conditional += 1;
      else roles.add(binding.role);
    }
  }
  return { roles: [...roles].toSorted(), conditional };
}

/** Whether the permissions of the signer's existing roles cover what the observation needs. */
export function storageVerdict(roleDefinitions) {
  const held = new Set();
  for (const permissions of roleDefinitions.values()) for (const p of permissions) held.add(p);
  const missing = STORAGE_PERMISSIONS.filter((p) => !held.has(p));
  return { ok: missing.length === 0, missing };
}

const json = (response) => JSON.parse(response.body.toString("utf8"));

/** `serviceAccounts.getIamPolicy`: the version is a query parameter and the request has no body. */
export const signerPolicyRequest = (target) => ({
  method: "POST",
  url: `https://iam.googleapis.com/v1/projects/${target.project}/serviceAccounts/${target.signer}:getIamPolicy?${POLICY_VERSION_PARAM}=3`,
});

async function readSignerPolicy(io, target, label) {
  const read = await io.wire(label, signerPolicyRequest(target));
  if (read.status !== 200) throw new IamStop(`${label} answered ${read.status}`);
  const policy = json(read);
  if (!validEtag(policy.etag)) throw new IamStop(`${label} returned a policy without an etag`);
  return policy;
}
const post = (body) => ({
  headers: { "content-type": "application/json" },
  body: Buffer.from(JSON.stringify(body)),
});
const POLICY_OPTIONS = { options: { requestedPolicyVersion: 3 } };

/**
 * Everything read before any change: the signer's policy and the signer role must be as the packet
 * expects (the role absent, no binding of it on the signer), and the signer's existing roles must
 * already cover object create, get and delete in the default bucket. Nothing is granted here.
 */
export async function iamPreflight({ io, target }) {
  const base = `https://iam.googleapis.com/v1/projects/${target.project}`;
  const saPolicy = await readSignerPolicy(io, target, "signer-policy");
  if (holdsRole(saPolicy, roleName(target.project))) {
    stop("the signer's policy already holds the signer role");
  }
  const role = await io.wire("role-absent", { method: "GET", url: `${base}/roles/${ROLE_ID}` });
  if (role.status !== 404) stop(`the signer role is not absent (read answered ${role.status})`);

  const project = await io.wire(
    "project-policy",
    {
      method: "POST",
      url: `https://cloudresourcemanager.googleapis.com/v1/projects/${target.project}:getIamPolicy`,
      ...post(POLICY_OPTIONS),
    },
    { context: { requestJson: POLICY_OPTIONS } },
  );
  if (project.status !== 200) stop(`project policy read answered ${project.status}`);
  const bucket = await io.wire("bucket-policy", {
    method: "GET",
    url: `https://storage.googleapis.com/storage/v1/b/${target.bucket}/iam?optionsRequestedPolicyVersion=3`,
  });
  if (bucket.status !== 200) stop(`bucket policy read answered ${bucket.status}`);

  const { roles, conditional } = signerRoles(target.signer, [json(project), json(bucket)]);
  if (roles.length > MAX_ROLE_READS)
    stop(`the signer holds ${roles.length} roles, more than ${MAX_ROLE_READS} to read`);
  const definitions = new Map();
  for (const name of roles) {
    if (!name.startsWith("roles/") && !name.startsWith(`projects/${target.project}/roles/`)) {
      stop(`the signer holds a role outside the predefined and project roles: ${name}`);
    }
    const read = await io.wire("role-read", {
      method: "GET",
      url: `https://iam.googleapis.com/v1/${name}`,
    });
    if (read.status !== 200) stop(`role ${name} read answered ${read.status}`);
    definitions.set(name, json(read).includedPermissions ?? []);
  }
  const verdict = storageVerdict(definitions);
  if (!verdict.ok) {
    stop(
      `the signer's existing roles (${roles.join(", ") || "none"}) lack ${verdict.missing.join(", ")}; nothing was granted`,
    );
  }
  return { saPolicy, roles, conditional, roleReads: roles.length };
}

/**
 * Creates the role and adds the binding. `ctx` records the attempts before they are sent, so
 * removal runs even when an answer is unknown.
 */
export async function iamGrant({ io, target, ctx, ours }) {
  const base = `https://iam.googleapis.com/v1/projects/${target.project}`;
  ctx.roleCreateAttempted = true;
  let created;
  try {
    created = await io.wire(
      "role-create",
      { method: "POST", url: `${base}/roles`, ...post(roleBody()) },
      { context: { requestJson: roleBody() } },
    );
  } catch (error) {
    if (error instanceof UnknownAnswer) {
      io.events.push({ resource: "role", event: "create", status: error.status });
    }
    throw error;
  }
  io.events.push({ resource: "role", event: "create", status: created.status });
  if (created.status !== 200) {
    // A definitive refusal created nothing, so the removal must not delete a role this run did not make.
    ctx.roleCreateAttempted = false;
    stop(`role create answered ${created.status}`);
  }
  const next = withBinding(ctx.saPolicy, ours);
  assertGrantShape(ctx.saPolicy, { ...next, etag: ctx.saPolicy.etag }, ours);
  const body = { policy: { ...next, etag: ctx.saPolicy.etag } };
  ctx.grantAttempted = true;
  let set;
  try {
    set = await io.wire(
      "signer-grant",
      {
        method: "POST",
        url: `${base}/serviceAccounts/${target.signer}:setIamPolicy`,
        ...post(body),
      },
      { context: { requestJson: body } },
    );
  } catch (error) {
    if (error instanceof UnknownAnswer) {
      io.events.push({ resource: "binding", event: "grant", status: error.status });
    }
    throw error;
  }
  io.events.push({ resource: "binding", event: "grant", status: set.status });
  if (set.status !== 200) stop(`signer grant answered ${set.status}`);
  const back = await io.wire("signer-grant-readback", signerPolicyRequest(target));
  if (back.status !== 200) stop(`signer policy read-back answered ${back.status}`);
  if (!samePolicy(json(back), { ...next }))
    stop("the signer's policy does not read back as granted");
  io.events.push({ resource: "binding", event: "read", status: 200, present: true });
}

/**
 * Removes the binding and, when this run created it, the role; then reads both back. Reads the
 * current policy first and writes only that policy minus the run's binding, on its etag; an etag
 * conflict (409, a definitive refusal) is retried on a fresh read. An unknown answer is never
 * re-sent. Returns whether the final policy equals the preflight one apart from the etag.
 */
export async function iamRemove({ io, target, ctx, ours }) {
  const base = `https://iam.googleapis.com/v1/projects/${target.project}`;
  const policyUrl = `${base}/serviceAccounts/${target.signer}`;
  const readPolicy = (label) => readSignerPolicy(io, target, label);
  let unknownRemoval = false;
  if (ctx.grantAttempted) {
    for (let attempt = 0; attempt < MAX_REMOVE_ATTEMPTS; attempt += 1) {
      const current = await readPolicy("signer-policy-before-removal");
      const foreign = (current.bindings ?? []).filter(
        (b) => typeof b.role === "string" && b.role.startsWith(ours.role) && !isOurs(b, ours),
      );
      if (foreign.length > 0) {
        throw new IamStop(
          "the signer's policy holds a binding of the signer role that is not the run's binding; nothing was written",
        );
      }
      if ((current.bindings ?? []).some((b) => isOurs(b, ours))) {
        io.events.push({ resource: "binding", event: "read", status: 200, present: true });
      }
      const target2 = withoutBinding(current, ours);
      if (samePolicy(target2, current)) break;
      assertRemovalShape(current, { ...target2, etag: current.etag }, ours);
      const body = { policy: { ...target2, etag: current.etag } };
      let set;
      try {
        set = await io.wire(
          "signer-removal",
          { method: "POST", url: `${policyUrl}:setIamPolicy`, ...post(body) },
          { context: { requestJson: body } },
        );
      } catch (error) {
        if (!(error instanceof UnknownAnswer)) throw error;
        io.events.push({ resource: "binding", event: "remove", status: error.status });
        unknownRemoval = true;
        break;
      }
      io.events.push({ resource: "binding", event: "remove", status: set.status });
      if (set.status === 200) break;
      if (set.status !== 409) throw new IamStop(`signer removal answered ${set.status}`);
    }
    const final = await readPolicy("signer-policy-after-removal");
    ctx.finalPolicy = final;
    io.events.push({
      resource: "binding",
      event: "final-read",
      status: 200,
      equalsPreflight: samePolicy(final, ctx.saPolicy),
      present: holdsRole(final, ours.role),
    });
  }
  // A role still referenced by a binding that could not be removed is kept, and reported.
  const stillBound =
    ctx.finalPolicy && (ctx.finalPolicy.bindings ?? []).some((b) => isOurs(b, ours));
  if (ctx.roleCreateAttempted && !unknownRemoval && !stillBound) {
    let deleted;
    try {
      deleted = await io.wire("role-delete", { method: "DELETE", url: `${base}/roles/${ROLE_ID}` });
    } catch (error) {
      if (error instanceof UnknownAnswer) {
        io.events.push({ resource: "role", event: "delete", status: error.status });
      }
      throw error;
    }
    io.events.push({ resource: "role", event: "delete", status: deleted.status });
    const read = await io.wire("role-after-delete", {
      method: "GET",
      url: `${base}/roles/${ROLE_ID}`,
    });
    io.events.push({
      resource: "role",
      event: "final-read",
      status: read.status,
      deleted: read.status === 200 && json(read).deleted === true,
    });
  }
}

/**
 * Settlement of the IAM changes, by the sandbox rules (presubmission checklist 3), as unresolved
 * items. A binding or role whose grant or create answer was unknown settles only through an own
 * positive read followed by its removal; a 404 or an absent binding never settles it. An unknown
 * removal or delete is sticky. The final policy must equal the preflight one apart from the etag.
 */
export function settleIam(events, { touched }) {
  if (!touched) return [];
  const unresolved = [];
  const of = (resource) => events.filter((e) => e.resource === resource);
  const binding = of("binding");
  const grant = binding.find((e) => e.event === "grant");
  if (grant) {
    const sawPresent = binding.some((e) => e.event === "read" && e.present === true);
    const grantConfirmed = grant.status >= 200 && grant.status < 300;
    const grantUnknown = isUnknownStatus(grant.status);
    const removals = binding.filter((e) => e.event === "remove");
    const finalRead = binding.findLast((e) => e.event === "final-read");
    if (removals.some((e) => isUnknownStatus(e.status))) {
      unresolved.push({ name: "signer binding", reason: "unknown removal" });
    } else if (grantUnknown && !sawPresent) {
      unresolved.push({ name: "signer binding", reason: "unknown grant, no positive read" });
    } else if ((grantConfirmed || sawPresent) && !finalRead) {
      unresolved.push({ name: "signer binding", reason: "granted, not read back after removal" });
    }
    if (finalRead && (finalRead.present || !finalRead.equalsPreflight)) {
      unresolved.push({
        name: "signer policy",
        reason: "does not equal the preflight policy apart from the etag",
      });
    }
  }
  const role = of("role");
  const create = role.find((e) => e.event === "create");
  if (create) {
    const del = role.find((e) => e.event === "delete");
    const finalRead = role.findLast((e) => e.event === "final-read");
    const createConfirmed = create.status >= 200 && create.status < 300;
    if (isUnknownStatus(create.status) && !(del && del.status >= 200 && del.status < 300)) {
      unresolved.push({
        name: "signer role",
        reason: "unknown create, no positive read and delete",
      });
    } else if (createConfirmed || isUnknownStatus(create.status)) {
      if (del && isUnknownStatus(del.status))
        unresolved.push({ name: "signer role", reason: "unknown delete" });
      else if (!del) unresolved.push({ name: "signer role", reason: "created, not deleted" });
      else if (!finalRead?.deleted)
        unresolved.push({ name: "signer role", reason: "deleted, not read back as deleted" });
    }
  }
  return unresolved;
}
