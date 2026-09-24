// gRPC google.firestore.admin.v1 steps (scope decision C7): the reviewed methods, request
// construction and guard, and the projection of a decoded answer to the JSON a REST answer
// would carry, so both are normalized alike. Nothing here performs I/O.

import { createRequire } from "node:module";

import { FOREIGN_PROJECT, programDatabases, resolveValue } from "./harness.mjs";

const require = createRequire(import.meta.url);
const firestoreRequire = createRequire(require.resolve("@google-cloud/firestore"));
const protobuf = createRequire(firestoreRequire.resolve("google-gax"))("protobufjs");

/** The admin, longrunning, rpc and well-known types the gRPC client ships. */
export const ROOT = protobuf.Root.fromJSON(firestoreRequire("../protos/admin_v1.json"));

const ADMIN = "google.firestore.admin.v1.FirestoreAdmin";
const OPERATIONS = "google.longrunning.Operations";

/** The reviewed methods, with the request field the routing header names. */
export const GRPC_METHODS = {
  CreateDatabase: { service: ADMIN, routing: "parent" },
  GetDatabase: { service: ADMIN, routing: "name" },
  ListDatabases: { service: ADMIN, routing: "parent" },
  DeleteDatabase: { service: ADMIN, routing: "name" },
  CreateIndex: { service: ADMIN, routing: "parent" },
  GetIndex: { service: ADMIN, routing: "name" },
  ExportDocuments: { service: ADMIN, routing: "name" },
  ImportDocuments: { service: ADMIN, routing: "name" },
  GetOperation: { service: OPERATIONS, routing: "name" },
};

function methodTypes(rpc) {
  const spec = GRPC_METHODS[rpc];
  if (!spec) throw new Error(`gRPC ${rpc} is not reviewed`);
  const method = ROOT.lookupService(spec.service).methods[rpc];
  method.resolve();
  return {
    ...spec,
    path: `/${spec.service}/${rpc}`,
    requestType: method.resolvedRequestType,
    responseType: method.resolvedResponseType,
  };
}

/** The method, path, codecs and request message of one gRPC step. */
export function buildGrpcRequest(step, ctx, program, raw) {
  const types = methodTypes(step.grpc.rpc);
  const request = resolveValue(step.grpc.request ?? {}, ctx, program, raw);
  if (step.grpc.nameFrom) {
    const source = raw.get(step.grpc.nameFrom.$from);
    const found = String(step.grpc.nameFrom.path)
      .split(".")
      .reduce((v, k) => (v == null ? v : v[k]), source);
    if (!found)
      throw new Error(
        `step ${step.grpc.nameFrom.$from} recorded nothing at ${step.grpc.nameFrom.path}`,
      );
    request.name = found;
  }
  const errors = types.requestType.verify(types.requestType.fromObject(request));
  if (errors) throw new Error(`${program.id}#${step.id}: ${errors}`);
  return {
    ...types,
    rpc: step.grpc.rpc,
    request,
    routingValue: request[types.routing],
    serialize: (message) =>
      types.requestType.encode(types.requestType.fromObject(message)).finish(),
    deserialize: (bytes) => types.responseType.decode(bytes),
  };
}

/**
 * A gRPC request may name only the sandbox project (or read the foreign one), this program's
 * databases, ids production refuses before creating anything, and the run bucket.
 */
export function guardGrpcRequest(built, ctx, program, uncreated) {
  const own = programDatabases(ctx, program);
  const visit = (text) => {
    for (const [, project] of String(text).matchAll(/projects\/([^/\s"]+)/g)) {
      if (project === FOREIGN_PROJECT && built.rpc.startsWith("Get")) continue;
      if (project === FOREIGN_PROJECT && built.rpc === "ListDatabases") continue;
      if (project !== ctx.project)
        throw new Error(`gRPC request names another project: ${project}`);
    }
    for (const [, database] of String(text).matchAll(/databases\/([^/\s"]+)/g)) {
      if (
        database === "(default)" &&
        built.rpc === "GetDatabase" &&
        String(text).endsWith("/databases/(default)")
      )
        continue;
      if (!own.has(database) && !uncreated.has(database))
        throw new Error(`gRPC request names a database this program does not own: ${database}`);
    }
    for (const [, bucket] of String(text).matchAll(/gs:\/\/([^/\s"]+)/g)) {
      if (bucket !== ctx.bucket && !bucket.startsWith("fireemu-no-such-bucket"))
        throw new Error(`gRPC request names another bucket: ${bucket}`);
    }
  };
  const walk = (value) => {
    if (typeof value === "string") visit(value);
    else if (Array.isArray(value)) value.forEach(walk);
    else if (value && typeof value === "object") Object.values(value).forEach(walk);
  };
  walk(built.request);
  if (built.rpc === "CreateDatabase") {
    const id = built.request.databaseId;
    if (!own.has(id) && !uncreated.has(id))
      throw new Error(`gRPC create names a database this program does not own: ${id}`);
  }
}

function timestampText(seconds, nanos) {
  const base = new Date(Number(seconds) * 1000).toISOString().replace(/\.\d{3}Z$/, "");
  const fraction = String(nanos ?? 0)
    .padStart(9, "0")
    .replace(/0+$/, "");
  return `${base}${fraction ? `.${fraction}` : ""}Z`;
}

/** A decoded message as proto3 JSON: timestamps and durations as text, Any expanded. */
export function projectMessage(message, type) {
  const object = type.toObject(message, { longs: String, enums: String, bytes: String });
  return projectObject(object, type);
}

function projectObject(object, type) {
  switch (type.fullName) {
    case ".google.protobuf.Timestamp":
      return timestampText(object.seconds ?? 0, object.nanos ?? 0);
    case ".google.protobuf.Duration": {
      const fraction = String(object.nanos ?? 0)
        .padStart(9, "0")
        .replace(/0+$/, "");
      return `${Number(object.seconds ?? 0)}${fraction ? `.${fraction}` : ""}s`;
    }
    case ".google.protobuf.Any": {
      const typeUrl = object.typeUrl ?? object.type_url;
      const inner = ROOT.lookupType(String(typeUrl).replace(/^.*\//, ""));
      const decoded = inner.decode(Buffer.from(object.value ?? "", "base64"));
      const projected = projectMessage(decoded, inner);
      return typeof projected === "object"
        ? { "@type": typeUrl, ...projected }
        : { "@type": typeUrl, value: projected };
    }
    default:
      break;
  }
  const out = {};
  for (const [key, value] of Object.entries(object)) {
    const field = type.fields[key];
    if (!field) continue;
    field.resolve();
    const project = (v) =>
      field.resolvedType instanceof protobuf.Type ? projectObject(v, field.resolvedType) : v;
    if (field.map)
      out[key] = Object.fromEntries(Object.entries(value).map(([k, v]) => [k, project(v)]));
    else if (field.repeated) out[key] = value.map(project);
    else out[key] = project(value);
  }
  return out;
}

/** google.rpc.Status details from the trailer, as `{typeUrl, bytes}` pairs. */
export function statusDetails(metadata) {
  const bin = metadata?.get?.("grpc-status-details-bin")?.[0];
  if (!bin) return [];
  try {
    const Status = ROOT.lookupType("google.rpc.Status");
    const status = Status.toObject(Status.decode(bin), { bytes: String });
    return (status.details ?? []).map((any) => ({ "@type": any.typeUrl }));
  } catch {
    return [{ undecodable: true }];
  }
}
