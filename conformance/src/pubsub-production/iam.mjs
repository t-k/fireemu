// Resource-local CAS edits. An ambiguous write is never retried or treated as a clean restore.
export const IAM_WAIT_MS = 900_000;
export const IAM_CONVERGENCE_CLAIM = false;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const complete = (reply) =>
  reply?.ok === true &&
  reply.unknown !== true &&
  (reply.status === undefined || (reply.status >= 200 && reply.status < 300)) &&
  object(reply.body);

export function readPolicy(policy) {
  if (
    !object(policy) ||
    typeof policy.etag !== "string" ||
    !policy.etag ||
    (policy.version !== undefined && ![1, 3].includes(policy.version)) ||
    (policy.bindings !== undefined && !Array.isArray(policy.bindings)) ||
    (policy.bindings ?? []).some(
      (binding) =>
        !object(binding) ||
        typeof binding.role !== "string" ||
        !Array.isArray(binding.members) ||
        binding.members.some((member) => typeof member !== "string" || !member) ||
        (binding.condition !== undefined &&
          (!object(binding.condition) || typeof binding.condition.expression !== "string")),
    )
  )
    throw new Error("unreadable IAM policy; needs-review");
  return structuredClone(policy);
}
const owns = (binding, role, principal) =>
  binding.role === role && binding.condition === undefined && binding.members.includes(principal);
export function addOwnBinding(value, role, principal) {
  const policy = readPolicy(value);
  policy.bindings ??= [];
  if (policy.bindings.some((binding) => owns(binding, role, principal)))
    return { policy, added: false };
  const binding = policy.bindings.find(
    (item) => item.role === role && item.condition === undefined,
  );
  if (binding) binding.members.push(principal);
  else policy.bindings.push({ role, members: [principal] });
  policy.version = 3;
  return { policy, added: true };
}
export function removeOwnBinding(value, role, principal) {
  const policy = readPolicy(value);
  policy.bindings = (policy.bindings ?? []).flatMap((binding) => {
    if (!owns(binding, role, principal)) return [binding];
    const members = binding.members.filter((member) => member !== principal);
    return members.length ? [{ ...binding, members }] : [];
  });
  return policy;
}
const sameBindings = (a, b) =>
  JSON.stringify(a.bindings ?? []) === JSON.stringify(b.bindings ?? []);
const hasOwn = (policy, role, principal) =>
  (policy.bindings ?? []).some((binding) => owns(binding, role, principal));

export function createIamOwnership({
  journal,
  assertOwned,
  now = () => performance.now(),
  replay = [],
}) {
  const entries = [];
  const persist = (row) => journal.write({ ...row, at: new Date().toISOString() });
  // Replay durable intents, including writes whose process died before recording the answer.
  for (const row of replay) {
    assertOwned(row.resource);
    if (row.phase === "grant-intent") {
      if (entries.some((item) => item.resource === row.resource))
        throw new Error("duplicate IAM grant intent");
      entries.push({
        resource: row.resource,
        role: row.role,
        principal: row.principal,
        state: "grant-unknown",
      });
    } else {
      const entry = entries.find((item) => item.resource === row.resource);
      if (!entry) throw new Error("IAM answer without owned intent");
      if (row.phase === "grant-confirmed") entry.state = "granted";
      else if (row.phase === "restore-intent") entry.state = "restore-unknown";
      else if (row.phase === "restore-confirmed") entry.state = "restored";
      else if (!["grant-unknown", "restore-unknown"].includes(row.phase))
        throw new Error("unreadable IAM journal phase");
    }
  }
  return Object.freeze({
    async grant(client, resource, role, principal) {
      assertOwned(resource);
      if (
        !["roles/pubsub.subscriber", "roles/pubsub.publisher"].includes(role) ||
        !/^serviceAccount:service-\d{1,20}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(
          principal,
        ) ||
        entries.some((entry) => entry.resource === resource)
      )
        throw new Error("invalid own grant scope");
      const before = await client.getIamPolicy(resource);
      if (!complete(before)) throw new Error("grant policy read needs-review");
      const { policy, added } = addOwnBinding(before.body, role, principal);
      if (!added) throw new Error("grant binding preexists; not owned by this run");
      const entry = { resource, role, principal, state: "grant-unknown" };
      entries.push(entry);
      persist({
        phase: "grant-intent",
        resource,
        role,
        principal,
        before: before.body,
        requested: policy,
      });
      const written = await client.setIamPolicy(resource, policy);
      if (!complete(written)) {
        persist({ phase: "grant-unknown", resource });
        throw new Error("grant answer ambiguous; retain lock for coordinator recovery");
      }
      const grantedAt = now();
      const check = await client.getIamPolicy(resource);
      if (
        !complete(check) ||
        !sameBindings(readPolicy(check.body), policy) ||
        !hasOwn(check.body, role, principal)
      )
        throw new Error("grant readback needs-review; owned intent remains open");
      entry.state = "granted";
      persist({ phase: "grant-confirmed", resource, role, principal });
      return { grantedAt, resource };
    },
    async restore(client) {
      const restored = [];
      const unsettled = [];
      for (const entry of [...entries].reverse()) {
        if (entry.state === "restored") continue;
        if (entry.state !== "granted") {
          unsettled.push({ ...entry });
          continue;
        }
        try {
          const before = await client.getIamPolicy(entry.resource);
          if (!complete(before)) throw new Error("restore policy read needs-review");
          const current = readPolicy(before.body);
          const next = removeOwnBinding(current, entry.role, entry.principal);
          if (hasOwn(current, entry.role, entry.principal)) {
            entry.state = "restore-unknown";
            persist({
              phase: "restore-intent",
              resource: entry.resource,
              role: entry.role,
              principal: entry.principal,
              requested: next,
            });
            const written = await client.setIamPolicy(entry.resource, next);
            if (!complete(written)) throw new Error("restore answer ambiguous");
            const check = await client.getIamPolicy(entry.resource);
            if (
              !complete(check) ||
              !sameBindings(readPolicy(check.body), next) ||
              hasOwn(check.body, entry.role, entry.principal)
            )
              throw new Error("restore readback needs-review");
          }
          entry.state = "restored";
          persist({ phase: "restore-confirmed", resource: entry.resource });
          restored.push(entry.resource);
        } catch {
          unsettled.push({ ...entry });
        }
      }
      return { restored, unsettled };
    },
    outstanding: () =>
      entries.filter((entry) => entry.state !== "restored").map((entry) => ({ ...entry })),
  });
}

export async function waitAfterLastGrant({ grantedAt, now = () => performance.now(), sleep }) {
  if (!Number.isFinite(grantedAt)) throw new Error("missing last confirmed grant time");
  while (now() - grantedAt < IAM_WAIT_MS) {
    const elapsed = now() - grantedAt;
    if (!Number.isFinite(elapsed) || elapsed < 0) throw new Error("invalid IAM monotonic clock");
    await sleep(IAM_WAIT_MS - elapsed);
  }
}
