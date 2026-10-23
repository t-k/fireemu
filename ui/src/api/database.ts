import { request, requestText } from "./client";

export type DatabaseScope = { session: string; project: string; namespace: string };
export type DatabaseInstance = { name: string; project: string };
export type DataMethod = "GET" | "PUT" | "PATCH" | "DELETE";

/** The scope is encoded once; it never supplies a destination host or credential. */
export const databaseTarget = (
  action: string,
  scope: DatabaseScope,
  path = "/",
  query = "",
): string => {
  const params = new URLSearchParams({ session: scope.session, project: scope.project });
  if (action !== "instances") params.set("namespace", scope.namespace);
  if (action !== "instances" && action !== "rules") params.set("path", path);
  if (query) params.set("query", query);
  return `database/${action}?${Array.from(params, ([key, value]) => `${encodeURIComponent(key)}=${encodeURIComponent(value)}`).join("&")}`;
};
export const databaseInstances = (session: string, project: string) =>
  request<{ instances: DatabaseInstance[] }>(
    "GET",
    databaseTarget("instances", { session, project, namespace: "" }),
  );
export const databaseRead = (scope: DatabaseScope, path: string) =>
  requestText("GET", databaseTarget("data", scope, path));
export const databaseWrite = (
  scope: DatabaseScope,
  path: string,
  method: DataMethod,
  source?: string,
) => requestText(method, databaseTarget("data", scope, path), source);
export const databaseRules = (scope: DatabaseScope) =>
  requestText("GET", databaseTarget("rules", scope));
export const databaseSaveRules = (scope: DatabaseScope, source: string) =>
  requestText("PUT", databaseTarget("rules", scope), source);
/** Probes are anonymous and may show denied native responses; they do not install a fake user. */
export const databaseProbe = (
  scope: DatabaseScope,
  path: string,
  method: DataMethod,
  query: string,
  source?: string,
) => requestText(method, databaseTarget("request", scope, path, query), source, true);
