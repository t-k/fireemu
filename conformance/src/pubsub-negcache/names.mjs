// Resource names of one run. Every name carries the run id; anything else is refused before sending.

export const PROJECT = "fireemu-oracle-idp";
const KIND_PATH = { topic: "topics", subscription: "subscriptions", snapshot: "snapshots" };
const RUN_ID = /^[a-f0-9]{12}$/;
// Roles that are created by the program, and roles that are never created.
const ROLE_KIND = {
  X: "subscription",
  W: "subscription",
  Y: "snapshot",
  T: "topic",
  S: "subscription",
  M: "topic",
  M2: "subscription",
  Z: "snapshot",
};
export const NEVER_CREATED = new Set(["M", "M2", "Z"]);
const RUN_LEVEL = new Set(["T", "S"]);

export function resourceId(runId, cellId, role) {
  if (!RUN_ID.test(runId)) throw new Error("run id must be 12 hex characters");
  if (!(role in ROLE_KIND)) throw new Error(`unknown role ${role}`);
  const scope = RUN_LEVEL.has(role) ? "run" : String(cellId).toLowerCase();
  const id = `fireemu-observe-${runId}-nc-${scope}-${role.toLowerCase()}`;
  if (!/^[a-z][a-z0-9._-]{2,254}$/.test(id)) throw new Error("invalid resource id");
  return id;
}

/** Full name `projects/<project>/<collection>/<id>`; `kind` overrides the role's own kind (K1 names a snapshot X). */
export function fullName(runId, cellId, role, kind = ROLE_KIND[role]) {
  return `projects/${PROJECT}/${KIND_PATH[kind]}/${resourceId(runId, cellId, role)}`;
}

export function isOwned(name, runId) {
  if (typeof name !== "string" || !RUN_ID.test(runId)) return false;
  return new RegExp(
    `^projects/${PROJECT}/(topics|subscriptions|snapshots)/fireemu-observe-${runId}-nc-[a-z0-9][a-z0-9._-]*$`,
  ).test(name);
}

export const kindOfName = (name) =>
  name.includes("/topics/") ? "topic" : name.includes("/snapshots/") ? "snapshot" : "subscription";

export const roleKind = (role) => ROLE_KIND[role];
