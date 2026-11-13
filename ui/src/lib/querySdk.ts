import type { CompiledQuery } from "./firestoreQuery";

/** Translate REST JSON's well-known values to protobuf objects without numeric coercion. */
const protobufValues = (value: unknown): unknown => {
  if (Array.isArray(value)) return value.map(protobufValues);
  if (value === null || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => {
      if (key === "timestampValue" && typeof item === "string") {
        const fraction = /\.(\d+)(?:Z|[+-]\d\d:\d\d)$/.exec(item)?.[1] ?? "";
        return [
          key,
          { seconds: Math.floor(Date.parse(item) / 1000), nanos: Number(fraction.padEnd(9, "0")) },
        ];
      }
      if (key === "nullValue" && item === null) return [key, "NULL_VALUE"];
      return [key, protobufValues(item)];
    }),
  );
};

export const querySdkRequest = (
  query: CompiledQuery,
): { parent: string; structuredQuery: Record<string, unknown> } => ({
  parent: query.path
    .slice("firestore/v1/".length, -":runQuery".length)
    .split("/")
    .map(decodeURIComponent)
    .join("/"),
  structuredQuery: {
    ...(protobufValues(query.body.structuredQuery) as Record<string, unknown>),
    limit: { value: query.body.structuredQuery.limit },
  },
});

/** A low-level SDK preserves REST value distinctions (including integer versus double). */
export const querySdkSource = (
  query: CompiledQuery,
): string => `// npm install @google-cloud/firestore @grpc/grpc-js
// Save as query.cjs. Run: FIRESTORE_EMULATOR_HOST=127.0.0.1:8080 node query.cjs
// Local administrator query, like the console; this does not test client Security Rules.
const { v1 } = require("@google-cloud/firestore");
const { credentials } = require("@grpc/grpc-js");
const endpoint = process.env.FIRESTORE_EMULATOR_HOST;
if (!endpoint || !/^(localhost|127\\.0\\.0\\.1|\\[::1\\]):[0-9]+$/.test(endpoint)) {
  throw new Error("Set FIRESTORE_EMULATOR_HOST to a loopback host:port");
}
const target = new URL("http://" + endpoint);
const client = new v1.FirestoreClient({
  apiEndpoint: target.hostname.replace(/^\\[|\\]$/g, ""),
  port: Number(target.port),
  sslCreds: credentials.createInsecure(),
});
const request = JSON.parse(${JSON.stringify(JSON.stringify(querySdkRequest(query)))});
async function main() {
  try {
    for await (const response of client.runQuery(request, {
      timeout: 10000,
      otherArgs: { headers: { authorization: "Bearer owner" } },
    })) console.log(JSON.stringify(response));
  } finally { await client.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });`;
