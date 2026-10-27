// The project's IAM bindings as a sorted set of role and member pairs, read before and after a run.

const RESOURCE_MANAGER_HOST = "https://cloudresourcemanager.googleapis.com";

/** The sorted, de-duplicated `role|member` pairs of a policy; a condition is part of the pair. */
export function policyPairs(policy) {
  if (policy === null || typeof policy !== "object") throw new Error("IAM policy is invalid");
  const bindings = policy.bindings ?? [];
  if (!Array.isArray(bindings)) throw new Error("IAM policy bindings are invalid");
  const pairs = new Set();
  for (const binding of bindings) {
    if (typeof binding?.role !== "string" || !Array.isArray(binding.members)) {
      throw new Error("IAM policy binding is invalid");
    }
    const condition = binding.condition
      ? `|${JSON.stringify(Object.fromEntries(Object.entries(binding.condition).toSorted()))}`
      : "";
    for (const member of binding.members) pairs.add(`${binding.role}|${member}${condition}`);
  }
  return [...pairs].toSorted();
}

export function diffPairs(before, after) {
  const prior = new Set(before);
  const current = new Set(after);
  return {
    added: after.filter((pair) => !prior.has(pair)),
    removed: before.filter((pair) => !current.has(pair)),
  };
}

export async function readProjectIam(control, projectNumber) {
  if (!/^\d{6,16}$/u.test(projectNumber)) throw new Error("invalid private project number");
  const reply = await control(
    "POST",
    `${RESOURCE_MANAGER_HOST}/v3/projects/${projectNumber}:getIamPolicy`,
    { options: { requestedPolicyVersion: 3 } },
    "control",
  );
  return policyPairs(reply.value);
}
