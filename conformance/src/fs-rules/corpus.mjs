// The FS-RULES corpus and its static guard.

import { PRINCIPALS, PROGRAMS } from "./programs/index.mjs";
import { REQUEST_CAP, RPCS, TEST_PHONES } from "./harness.mjs";
import { RULESET_IDS } from "./rulesets.mjs";

export { PRINCIPALS, PROGRAMS };

const ACTIONS = new Set([
  "principal",
  "refresh",
  "snapshot",
  "claims",
  "revoke",
  "disable",
  "delete-account",
  "publish",
  "seed",
  "sleep",
]);

function* walkStrings(value) {
  if (typeof value === "string") yield value;
  else if (Array.isArray(value)) for (const v of value) yield* walkStrings(v);
  else if (value && typeof value === "object")
    for (const v of Object.values(value)) yield* walkStrings(v);
}

/**
 * Refuses a corpus that could address anything but a relative document path, wait anywhere but
 * in the last program, use an unknown principal, action, RPC or ruleset, or exceed the request
 * cap. Returns the number of recorded requests.
 */
export function validateCorpus(programs, principals = PRINCIPALS) {
  let requests = 0;
  const ids = new Set();
  const known = new Set(Object.keys(principals));
  for (const phone of Object.values(principals)
    .map((spec) => spec.phone)
    .filter((p) => p !== undefined)) {
    if (!TEST_PHONES[phone])
      throw new Error(`principal phone ${phone} is not a configured test phone`);
  }
  programs.forEach((program, index) => {
    if (!/^fs-rules\/[a-z-]+\/[a-z0-9-]+$/.test(program.id))
      throw new Error(`bad program id ${program.id}`);
    if (ids.has(program.id)) throw new Error(`duplicate program ${program.id}`);
    ids.add(program.id);
    if (
      program.ruleset !== null &&
      program.ruleset !== undefined &&
      !RULESET_IDS.includes(program.ruleset)
    )
      throw new Error(`${program.id}: unknown ruleset ${program.ruleset}`);
    const local = new Set(known);
    const stepIds = new Set();
    for (const step of program.steps) {
      if (step.action) {
        if (!ACTIONS.has(step.action))
          throw new Error(`${program.id}: unknown action ${step.action}`);
        if (step.action === "principal") local.add(step.principal);
        else if (step.principal && !local.has(step.principal))
          throw new Error(`${program.id}: action on unknown principal ${step.principal}`);
        continue;
      }
      requests += 1;
      if (!/^[a-z0-9-]+$/.test(step.id)) throw new Error(`${program.id}: bad step id ${step.id}`);
      if (stepIds.has(step.id)) throw new Error(`${program.id}: duplicate step ${step.id}`);
      stepIds.add(step.id);
      if (step.waitUntil && index !== programs.length - 1)
        throw new Error(`${program.id}#${step.id}: only the last program may wait`);
      if (step.compile !== undefined) {
        if (typeof step.compile !== "string") throw new Error(`${step.id}: compile takes a source`);
        continue;
      }
      if (!RPCS[step.rpc]) throw new Error(`${program.id}#${step.id}: unknown rpc ${step.rpc}`);
      if (!["rest", "grpc", undefined].includes(step.transport))
        throw new Error(`${step.id}: unknown transport`);
      const principal = typeof step.as === "string" ? step.as.split("@")[0] : step.as?.of;
      if (principal && principal !== "none" && !local.has(principal))
        throw new Error(`${program.id}#${step.id}: unknown principal ${principal}`);
      for (const path of [step.doc, step.collection, step.parent].filter(Boolean)) {
        if (/^[a-z]+:|^\/|\.\./i.test(path))
          throw new Error(`${program.id}#${step.id}: path must be relative`);
      }
      for (const text of walkStrings({ body: step.body, params: step.params })) {
        for (const [, domain] of text.matchAll(/@([^\s@"'<>/?#&]+)/g)) {
          if (domain.toLowerCase() !== "example.com")
            throw new Error(`${step.id}: email outside example.com`);
        }
      }
    }
  });
  if (requests > REQUEST_CAP)
    throw new Error(`corpus exceeds the request cap (${requests} > ${REQUEST_CAP})`);
  return requests;
}
