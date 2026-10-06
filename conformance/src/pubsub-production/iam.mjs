import { readFileSync } from "node:fs";
const recordedIam = JSON.parse(
  readFileSync(new URL("./fixtures/recorded-v2-iam.json", import.meta.url)),
);
// This compares parsed request/response shapes only. It does not infer physical bytes or permission propagation.
const evidenceShape = (value, key = "") => {
  if (Array.isArray(value)) return value.map((item) => evidenceShape(item));
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((name) => [name, evidenceShape(value[name], name)]),
    );
  if (typeof value !== "string") return value;
  if (key === "etag" && /^[A-Za-z0-9+/]+={0,2}$/.test(value))
    return (
      "A".repeat(value.replace(/=+$/, "").length) +
      "=".repeat(value.length - value.replace(/=+$/, "").length)
    );
  if (/^serviceAccount:service-\d{12}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(value))
    return "serviceAccount:service-123456789012@gcp-sa-pubsub.iam.gserviceaccount.com";
  if (key === "path") {
    const match =
      /^\/v1\/projects\/[^/]+\/(topics|subscriptions)\/[^/:?]+:(getIamPolicy|setIamPolicy)$/.exec(
        value,
      );
    if (match) return `${match[1]}:${match[2]}`;
  }
  return value;
};
export function assessIamExchange(row) {
  const unknown = { status: "needs-review", evidence: [] };
  if (
    row.iamPhase?.startsWith("restore") ||
    row.response?.status !== 200 ||
    row.response?.unknown === true ||
    row.response?.ok === false
  )
    return unknown;
  const shape = JSON.stringify(
    evidenceShape({
      request: row.request,
      response: { status: row.response.status, body: row.response.body },
    }),
  );
  const matching = recordedIam.filter(
    (item) =>
      JSON.stringify(evidenceShape({ request: item.request, response: item.response })) === shape,
  );
  return matching.length
    ? {
        status: "recorded-shape",
        evidence: matching.map(({ runId, line, n }) => ({ runId, line, n })),
      }
    : unknown;
}

// Resource-local CAS edits. An ambiguous write is never retried or treated as a clean restore.
export const IAM_WAIT_MS = 900_000;
export const IAM_CONVERGENCE_CLAIM = false;
const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const complete = (reply) =>
  reply?.ok === true && reply.unknown !== true && reply.status === 200 && object(reply.body);

export function readPolicy(policy) {
  if (
    Buffer.byteLength(JSON.stringify(policy) ?? "") > 65_536 ||
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
  reportEvidence = () => {},
}) {
  const entries = [];
  const callPolicy = async (client, resource, phase, policy) => {
    const request =
      policy === undefined
        ? { method: "GET", path: `/v1/${resource}:getIamPolicy?options.requestedPolicyVersion=3` }
        : { method: "POST", path: `/v1/${resource}:setIamPolicy`, body: { policy } };
    const response =
      policy === undefined
        ? await client.getIamPolicy(resource, { requestedPolicyVersion: 3 })
        : await client.setIamPolicy(resource, policy);
    const assessment = assessIamExchange({ request, response, iamPhase: phase });
    reportEvidence({ resource, iamPhase: phase, assessment });
    return response;
  };

  const persist = (row) => journal.write({ ...row, at: new Date().toISOString() });
  const validScope = (resource, role, principal) =>
    ((role === "roles/pubsub.subscriber" && /\/subscriptions\/[^/]+$/.test(resource)) ||
      (role === "roles/pubsub.publisher" && /\/topics\/[^/]+$/.test(resource))) &&
    /^serviceAccount:service-\d{1,20}@gcp-sa-pubsub\.iam\.gserviceaccount\.com$/.test(
      principal ?? "",
    );
  const confirmed = (reply, requested) => {
    try {
      return complete(reply) && sameBindings(readPolicy(reply.body), requested);
    } catch {
      return false;
    }
  };
  // Confirmation labels are insufficient: replay re-evaluates the exact owned delta and raw proofs.
  for (const row of replay) {
    assertOwned(row.resource);
    if (row.phase === "grant-intent") {
      if (
        !validScope(row.resource, row.role, row.principal) ||
        entries.some((item) => item.resource === row.resource)
      )
        throw new Error("invalid IAM grant intent scope");
      const expected = addOwnBinding(row.before, row.role, row.principal);
      if (!expected.added || JSON.stringify(expected.policy) !== JSON.stringify(row.requested))
        throw new Error("invalid IAM grant ownership proof");
      entries.push({
        resource: row.resource,
        role: row.role,
        principal: row.principal,
        state: "grant-unknown",
        stage: "grant-pending",
        requested: row.requested,
      });
      continue;
    }
    const entry = entries.find((item) => item.resource === row.resource);
    if (!entry) throw new Error("IAM answer without owned intent");
    if (
      row.phase === "grant-confirmed" &&
      entry.stage === "grant-pending" &&
      confirmed(row.setAnswer, entry.requested) &&
      confirmed(row.readback, entry.requested)
    ) {
      entry.state = "granted";
      entry.stage = "granted";
    } else if (row.phase === "grant-unknown" && entry.stage === "grant-pending") {
      entry.stage = "grant-terminal";
    } else if (
      row.phase === "restore-intent" &&
      entry.stage === "granted" &&
      JSON.stringify(removeOwnBinding(row.before, entry.role, entry.principal)) ===
        JSON.stringify(row.requested)
    ) {
      entry.state = "restore-unknown";
      entry.stage = "restore-pending";
      entry.requested = row.requested;
    } else if (row.phase === "restore-unknown" && entry.stage === "restore-pending") {
      entry.stage = "restore-terminal";
    } else if (
      row.phase === "restore-confirmed" &&
      ((entry.stage === "restore-pending" &&
        confirmed(row.setAnswer, entry.requested) &&
        confirmed(row.readback, entry.requested) &&
        !hasOwn(row.readback.body, entry.role, entry.principal)) ||
        (entry.stage === "granted" &&
          row.proof === "already-absent" &&
          complete(row.readback) &&
          !hasOwn(readPolicy(row.readback.body), entry.role, entry.principal)))
    ) {
      entry.state = "restored";
      entry.stage = "restored";
    } else throw new Error("invalid IAM replay transition or confirmation proof");
  }
  return Object.freeze({
    async grant(client, resource, role, principal) {
      assertOwned(resource);
      if (
        !validScope(resource, role, principal) ||
        entries.some((entry) => entry.resource === resource)
      )
        throw new Error("invalid own grant scope");
      const before = await callPolicy(client, resource, "grant");
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
      const written = await callPolicy(client, resource, "grant", policy);
      if (!confirmed(written, policy)) {
        persist({ phase: "grant-unknown", resource });
        throw new Error("grant answer ambiguous; retain lock for coordinator recovery");
      }
      const grantedAt = now();
      const check = await callPolicy(client, resource, "grant");
      if (
        !complete(check) ||
        !sameBindings(readPolicy(check.body), policy) ||
        !hasOwn(check.body, role, principal)
      )
        throw new Error("grant readback needs-review; owned intent remains open");
      entry.state = "granted";
      persist({
        phase: "grant-confirmed",
        resource,
        role,
        principal,
        setAnswer: written,
        readback: check,
      });
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
          const before = await callPolicy(client, entry.resource, "restore");
          if (!complete(before)) throw new Error("restore policy read needs-review");
          const current = readPolicy(before.body);
          const next = removeOwnBinding(current, entry.role, entry.principal);
          let written;
          let check = before;
          const absent = !hasOwn(current, entry.role, entry.principal);
          if (!absent) {
            entry.state = "restore-unknown";
            persist({
              phase: "restore-intent",
              resource: entry.resource,
              role: entry.role,
              principal: entry.principal,
              before: current,
              requested: next,
            });
            written = await callPolicy(client, entry.resource, "restore", next);
            if (!confirmed(written, next)) throw new Error("restore answer ambiguous");
            check = await callPolicy(client, entry.resource, "restore");
            if (
              !complete(check) ||
              !sameBindings(readPolicy(check.body), next) ||
              hasOwn(check.body, entry.role, entry.principal)
            )
              throw new Error("restore readback needs-review");
          }
          entry.state = "restored";
          persist({
            phase: "restore-confirmed",
            resource: entry.resource,
            ...(absent ? { proof: "already-absent" } : { setAnswer: written }),
            readback: check,
          });
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
  const initial = now() - grantedAt;
  if (!Number.isFinite(initial) || initial < 0) throw new Error("invalid IAM monotonic clock");
  while (true) {
    const elapsed = now() - grantedAt;
    if (!Number.isFinite(elapsed) || elapsed < 0) throw new Error("invalid IAM monotonic clock");
    if (elapsed >= IAM_WAIT_MS) return;
    await sleep(IAM_WAIT_MS - elapsed);
  }
}
