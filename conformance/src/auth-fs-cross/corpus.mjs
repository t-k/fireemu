// The AUTH-FS-CROSS corpus and its static guard.

import { RPCS } from "../fs-rules/harness.mjs";
import { PRINCIPALS, PROGRAMS } from "./programs.mjs";
import { RULESET_IDS } from "./rulesets.mjs";

export { PRINCIPALS, PROGRAMS };

/** Recorded requests of one recording may not exceed this; a recording records it twice. */
export const REQUEST_CAP = 200;
const ACTIONS = new Set(["refresh", "publish", "seed", "sleep", "delete-tenant"]);
const PROVIDERS = new Set(["password", "admin-password", "foreign"]);
const TENANT_SLOTS = new Set(["t1", "t2"]);

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

/**
 * Refuses a corpus that could address anything but a relative document path of this lane's
 * collections, use an unknown principal, provider, tenant slot, action, RPC or ruleset, or exceed
 * the request cap. Returns the number of recorded requests.
 */
export function validateCorpus(programs, principals = PRINCIPALS) {
  for (const [name, spec] of Object.entries(principals)) {
    if (!PROVIDERS.has(spec.provider))
      throw new Error(`${name}: unknown provider ${spec.provider}`);
    if (spec.tenant !== undefined && !TENANT_SLOTS.has(spec.tenant))
      throw new Error(`${name}: unknown tenant slot ${spec.tenant}`);
    if (spec.sameUid && spec.provider !== "admin-password")
      throw new Error(`${name}: only the administrator can choose a local id`);
  }
  let requests = 0;
  const ids = new Set();
  const known = new Set([...Object.keys(principals), "none"]);
  for (const program of programs) {
    if (!/^auth-fs-cross\/[a-z-]+\/[a-z0-9-]+$/.test(program.id))
      throw new Error(`bad program id ${program.id}`);
    if (ids.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    ids.add(program.id);
    if (!RULESET_IDS.includes(program.ruleset))
      throw new Error(`${program.id}: unknown ruleset ${program.ruleset}`);
    const stepIds = new Set();
    const deleted = new Set();
    for (const step of program.steps) {
      if (step.action) {
        if (!ACTIONS.has(step.action))
          throw new Error(`${program.id}: unknown action ${step.action}`);
        if (step.action === "delete-tenant") {
          if (!TENANT_SLOTS.has(step.tenant))
            throw new Error(`${program.id}: unknown tenant slot ${step.tenant}`);
          deleted.add(step.tenant);
        }
        continue;
      }
      if (stepIds.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (!known.has(step.as))
        throw new Error(`${program.id}#${step.id}: unknown principal ${step.as}`);
      if (!Object.hasOwn(RPCS, step.rpc))
        throw new Error(`${program.id}#${step.id}: unknown rpc ${step.rpc}`);
      for (const text of walkStrings({ doc: step.doc, body: step.body })) {
        if (text.startsWith("/"))
          throw new Error(`${program.id}#${step.id}: path must be relative`);
        if (/(^|\/)\.\.?(\/|$)/.test(text))
          throw new Error(`${program.id}#${step.id}: path must not climb`);
      }
      const path = step.doc ?? "";
      if (path && !/^afc-[a-z-]+\/[a-z0-9-]+$/.test(path))
        throw new Error(`${program.id}#${step.id}: documents must be this lane's (afc-*)`);
      requests += 1;
    }
    // A tenant is deleted by at most one program, and it is the last to use that tenant.
    for (const slot of deleted) {
      const later = programs.slice(programs.indexOf(program) + 1);
      const uses = later.some((next) =>
        next.steps.some(({ as }) => principals[as]?.tenant === slot),
      );
      if (uses) throw new Error(`${program.id}: tenant ${slot} is used after its deletion`);
    }
  }
  if (requests > REQUEST_CAP) throw new Error(`${requests} requests exceed the cap ${REQUEST_CAP}`);
  return requests;
}
