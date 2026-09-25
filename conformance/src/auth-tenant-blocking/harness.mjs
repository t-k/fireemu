// Normalization of the AUTH-TENANT-BLOCKING sandbox harness. It is part of the fixture's
// harness digest (run.mjs): a change here makes the saved rows stale.
//
// On top of the AUTH-MFA normalization (tokens decoded; secrets, session infos, ids, run-window
// times, the project, its number and the API key as placeholders; second factors named per
// program), tenants are named per program. A tenant the harness creates is named by its corpus
// label; a tenant a recorded step creates is named by the order in which the program first saw
// it. Either placeholder keeps the shape of the id: the display-name prefix production derives it
// from and the length of the random suffix (`<tenant:a:atb-sel-a-*5>`), or `other` for an id of
// another shape. Nothing here performs I/O.

import { normalizeMfaResponse } from "../auth-mfa/harness.mjs";

/** A tenant id as production issues it: the display name, a hyphen, five of [a-z0-9]. */
const DISPLAY_NAME_ID = /^([A-Za-z][A-Za-z0-9-]{3,19})-([a-z0-9]{5})$/;
/** Where an answer names a tenant: a resource name. */
const TENANT_RESOURCE = /(?:^|\/)tenants\/([^/\s"]+)/g;
/** Keys whose string value is a tenant id. */
const TENANT_KEYS = new Set(["tenantId", "tenant", "tenant_id"]);

/** The shape of a tenant id, without its random part. */
export function tenantShape(id) {
  const match = DISPLAY_NAME_ID.exec(id);
  return match ? `${match[1]}-*${match[2].length}` : "other";
}

/**
 * Per-program names of tenants. `label(id, name)` names a tenant the harness created;
 * `apply(recorded)` names every tenant an answer mentions and replaces each occurrence.
 */
export function createTenantRegistry() {
  const names = new Map();
  let unlabelled = 0;
  const name = (id, label) => {
    if (!names.has(id)) {
      unlabelled += label === undefined ? 1 : 0;
      names.set(id, `<tenant:${label ?? unlabelled}:${tenantShape(id)}>`);
    }
    return names.get(id);
  };
  const collect = (value, key) => {
    if (typeof value === "string") {
      if (TENANT_KEYS.has(key) && value.length > 0 && !value.startsWith("<")) name(value);
      if (key === "name") for (const [, id] of value.matchAll(TENANT_RESOURCE)) name(id);
    } else if (Array.isArray(value)) for (const v of value) collect(v, key);
    else if (value && typeof value === "object")
      for (const [k, v] of Object.entries(value)) collect(v, k);
  };
  const replaceText = (text) => {
    let out = text;
    // Longest first, so an id that prefixes another is not replaced inside it.
    for (const [id, placeholder] of [...names].toSorted(([a], [b]) => b.length - a.length))
      out = out.replaceAll(id, placeholder);
    return out;
  };
  const replace = (value) => {
    if (typeof value === "string") return replaceText(value);
    if (Array.isArray(value)) return value.map(replace);
    if (value && typeof value === "object")
      return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, replace(v)]));
    return value;
  };
  return {
    label(id, label) {
      if (names.has(id)) throw new Error(`tenant ${id} is already named`);
      name(id, label);
    },
    apply(recorded) {
      collect(recorded, "");
      return replace(recorded);
    },
    replace,
    /** Every tenant id this program has seen, harness-created or not. */
    ids: () => [...names.keys()],
  };
}

/**
 * The recorded form of one HTTP answer: the AUTH-MFA normalization, then tenants named by the
 * program's registry. `project` limits a config answer to one top-level member.
 */
export function normalizeTenantResponse(status, text, ctx, registries, options = {}) {
  const recorded = normalizeMfaResponse(status, text, ctx, registries.enrollments, options);
  return registries.tenants.apply(recorded);
}
