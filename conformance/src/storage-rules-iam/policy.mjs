import { createHash } from "node:crypto";

// Stage 2b: the one IAM change the Storage Rules observation may need. Firebase Storage Rules that read Firestore (`firestore.get`,
// `firestore.exists`) work only when the project's Cloud Storage for Firebase service agent holds the Firestore-reading role; the
// owner approved that grant in principle (ledger row 169), with the role, the target and whether to remove it fixed in the
// pre-send review. This module is the pure part: what a policy is, whether the grant is there, what the policy looks like with
// it added or removed, and when two policies are the same apart from the grant. It sends nothing.
export const GRANT_ROLE = "roles/firebaserules.firestoreServiceAgent";
export const POLICY_VERSION = 3;
const MAX_BINDINGS = 1500;
const MAX_MEMBERS = 1500;
const plain = (value) => value !== null && typeof value === "object" && Object.getPrototypeOf(value) === Object.prototype;
const sha = (value) => createHash("sha256").update(value).digest("hex");
const refuse = (message) => { throw new Error(message); };

/** The member string of the Cloud Storage for Firebase service agent of a project. */
export function storageAgentMember(projectNumber) {
  if (typeof projectNumber !== "string" || !/^[1-9]\d{0,19}$/.test(projectNumber)) refuse("invalid project number");
  return `serviceAccount:service-${projectNumber}@gcp-sa-firebasestorage.iam.gserviceaccount.com`;
}

const canonical = (value) => (Array.isArray(value) ? value.map(canonical) : plain(value) ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value);

/** A policy as a response gave it: an etag, a version and the bindings (members and any condition), or a refusal. */
export function parsePolicy(body) {
  if (!plain(body) || typeof body.etag !== "string" || body.etag === "" || body.etag.length > 1024) refuse("invalid policy");
  if (body.version !== undefined && (!Number.isSafeInteger(body.version) || body.version < 0 || body.version > POLICY_VERSION)) refuse("invalid policy");
  const raw = body.bindings ?? [];
  if (!Array.isArray(raw) || raw.length > MAX_BINDINGS) refuse("invalid policy");
  const bindings = raw.map((binding) => {
    if (!plain(binding) || typeof binding.role !== "string" || binding.role === "" || binding.role.length > 256 || !Array.isArray(binding.members) || binding.members.length > MAX_MEMBERS) refuse("invalid policy");
    if (binding.members.some((member) => typeof member !== "string" || member === "" || member.length > 512)) refuse("invalid policy");
    if (binding.condition !== undefined && !plain(binding.condition)) refuse("invalid policy");
    return { role: binding.role, members: [...binding.members], ...(binding.condition === undefined ? {} : { condition: structuredClone(binding.condition) }) };
  });
  return Object.freeze({ etag: body.etag, version: body.version ?? 0, bindings: Object.freeze(bindings) });
}

/** Whether the grant is absent, present once without a condition, or ambiguous (conditional, or present more than once). */
export function assess(policy, member) {
  let unconditional = 0;
  for (const binding of policy.bindings) {
    if (binding.role !== GRANT_ROLE || !binding.members.includes(member)) continue;
    if (binding.condition !== undefined) return { state: "ambiguous", reason: "the grant is conditional" };
    unconditional += binding.members.filter((entry) => entry === member).length;
  }
  if (unconditional === 0) return { state: "absent" };
  return unconditional === 1 ? { state: "present" } : { state: "ambiguous", reason: "the grant appears more than once" };
}

const clone = (bindings) => bindings.map((binding) => ({ role: binding.role, members: [...binding.members], ...(binding.condition === undefined ? {} : { condition: structuredClone(binding.condition) }) }));

/** The policy to send to add the grant: every binding as it was, the member appended to the unconditional binding of the role (or a new one). */
export function withGrant(policy, member) {
  if (assess(policy, member).state !== "absent") refuse("the grant is not absent");
  const bindings = clone(policy.bindings);
  const target = bindings.find((binding) => binding.role === GRANT_ROLE && binding.condition === undefined);
  if (target === undefined) bindings.push({ role: GRANT_ROLE, members: [member] });
  else target.members.push(member);
  return Object.freeze({ version: POLICY_VERSION, etag: policy.etag, bindings: Object.freeze(bindings) });
}

/** The policy to send to remove the grant again: the member taken out of the unconditional binding of the role, and that binding dropped if taking the member out emptied it. */
export function withoutGrant(policy, member) {
  if (assess(policy, member).state !== "present") refuse("the grant is not present");
  const bindings = [];
  for (const binding of clone(policy.bindings)) {
    if (binding.role !== GRANT_ROLE || binding.condition !== undefined || !binding.members.includes(member)) { bindings.push(binding); continue; }
    const rest = binding.members.filter((entry) => entry !== member);
    if (rest.length > 0) bindings.push({ ...binding, members: rest });
  }
  return Object.freeze({ version: POLICY_VERSION, etag: policy.etag, bindings: Object.freeze(bindings) });
}

/** The bindings in a form that ignores the order of bindings and members. */
export function canonicalBindings(policy) {
  return policy.bindings
    .map((binding) => ({ role: binding.role, members: [...new Set(binding.members)].sort(), condition: binding.condition === undefined ? null : canonical(binding.condition) }))
    .sort((a, b) => (JSON.stringify([a.role, a.condition]) < JSON.stringify([b.role, b.condition]) ? -1 : JSON.stringify([a.role, a.condition]) > JSON.stringify([b.role, b.condition]) ? 1 : 0));
}

export const sameBindings = (left, right) => JSON.stringify(canonicalBindings(left)) === JSON.stringify(canonicalBindings(right));

/** A digest of the bindings for the journal: never the members. */
export const bindingsDigest = (policy) => sha(JSON.stringify(canonicalBindings(policy)));

/** The request body of setIamPolicy for a policy built here: only the bindings and the etag are written. */
export function setBody(policy) {
  return { policy: { version: POLICY_VERSION, etag: policy.etag, bindings: policy.bindings.map((binding) => ({ role: binding.role, members: [...binding.members], ...(binding.condition === undefined ? {} : { condition: binding.condition }) })) }, updateMask: "bindings,etag" };
}
