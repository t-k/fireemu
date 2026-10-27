// A fake of the production APIs the CV14 RTDB wiring talks to: the management plane (API, instance),
// the Rules, and a data plane that applies the REST writes with the tree model of sequence.mjs. Shared by
// the RTDB tests and the integration test; `onItemChange(id, before, after)` is told of every change of
// an item under the run prefix (the integration test turns it into the frames the handlers would print).

import { createHash } from "node:crypto";

import { PREFIX } from "./frames.mjs";
import { applyWrite } from "./sequence.mjs";

export const N = "000000000000";
export const P = "demo-project";
export const BASE = '// baseline\n{"rules":{".read":false,".write":false}}';
export const json = (status, value) => ({
  status,
  text: async () => (typeof value === "string" ? value : JSON.stringify(value)),
});

/** A fake of the production APIs: management plane, Rules, and a data plane that applies the REST writes. */
export function fakeWorld(faults = [], { onItemChange } = {}) {
  const w = { api: "DISABLED", inst: "DELETED", rules: BASE, tree: {}, ops: 0, sent: [], auth: [] };
  const inst = (state) => ({
    name: `projects/${N}/locations/us-central1/instances/fireemu-q-rtdb2`,
    type: "USER_DATABASE",
    state,
  });
  function apply(method, u, body) {
    const p = u.pathname;
    if (u.host === "serviceusage.googleapis.com") {
      if (p.startsWith("/v1/operations/")) return json(200, { name: p.slice(4), done: true });
      if (method === "GET") {
        return json(200, {
          name: `projects/${N}/services/firebasedatabase.googleapis.com`,
          state: w.api,
        });
      }
      w.api = p.endsWith(":enable") ? "ENABLED" : "DISABLED";
      return json(200, { name: `operations/op${++w.ops}`, done: w.ops % 2 === 0 });
    }
    if (u.host === "firebasedatabase.googleapis.com") {
      if (p.endsWith("/-/instances")) {
        return json(200, { instances: w.inst === "DELETED" ? [] : [inst(w.inst)] });
      }
      const verb = p.split(":")[1];
      if (method === "DELETE") w.inst = "DELETED";
      else if (verb)
        w.inst = { undelete: "DISABLED", reenable: "ACTIVE", disable: "DISABLED" }[verb];
      return json(200, inst(w.inst));
    }
    const key = decodeURIComponent(p.replace(/\.json$/u, "").slice(1));
    if (key === ".settings/rules") {
      if (method === "PUT") {
        w.rules = body;
        return json(200, { status: "ok" });
      }
      return json(200, w.rules);
    }
    if (method === "GET") {
      const value = key.split("/").reduce((node, part) => node?.[part], w.tree);
      return json(200, value ?? null);
    }
    const segments = key.split("/");
    const item = segments[0] === PREFIX && segments[1] === "items" ? segments[2] : undefined;
    const before = item === undefined ? null : (w.tree[PREFIX]?.items?.[item] ?? null);
    w.tree = applyWrite(w.tree, method, segments, body);
    if (item !== undefined) onItemChange?.(item, before, w.tree[PREFIX]?.items?.[item] ?? null);
    return json(200, method === "DELETE" ? null : body);
  }
  w.fetch = async (url, init) => {
    const u = new URL(url);
    const body =
      init.body === undefined
        ? undefined
        : /rules/u.test(u.pathname)
          ? init.body
          : JSON.parse(init.body);
    w.sent.push(`${init.method} ${u.host}${u.pathname}`);
    w.auth.push([init.method, u.pathname, init.headers.authorization ?? null]);
    if (init.method === "GET" && w.forbid?.path.test(u.pathname) && w.forbid.remaining-- > 0) {
      return json(w.forbid.status ?? 403, { error: { code: 403, status: "PERMISSION_DENIED" } });
    }
    const fault = faults.find(
      (f) => !f.used && f.method === init.method && f.path.test(u.pathname) && !(f.skip-- > 0),
    );
    if (!fault) return apply(init.method, u, body);
    fault.used = true;
    if (fault.kind === "timeout") throw new Error("timeout");
    if (fault.kind === "lie") return json(200, init.method === "DELETE" ? null : {});
    return json(503, "");
  };
  w.baseline = () =>
    w.api === "DISABLED" &&
    w.inst === "DELETED" &&
    w.rules === BASE &&
    Object.keys(w.tree).length === 0;
  return w;
}

export const packet = {
  projectId: P,
  projectNumber: N,
  baselineRulesSha256: createHash("sha256").update(BASE).digest("hex"),
};
