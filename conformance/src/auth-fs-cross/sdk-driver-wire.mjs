// Installs the SDK driver's wire guard before any Firebase module is evaluated: the SDK may take
// `fetch` and `http2.connect` when its module loads, so this module is imported first.

import { createHash } from "node:crypto";
import { createRequire } from "node:module";

import {
  createWireLedger,
  createS5bAdmission,
  installSocketGuard,
  installWireGuard,
  PRODUCTION_HOSTS,
} from "./sdk-wire.mjs";

const started = Date.now();
export const emit = (event) =>
  process.stdout.write(`${JSON.stringify({ t: Date.now() - started, ...event })}\n`);
export const sha256 = (text) => createHash("sha256").update(text).digest("hex");
export const config = JSON.parse(process.env.AFC_SDK_CONFIG ?? "{}");
export const local = config.mode === "local";
export const transactionAdmission = config.s5bAdmission === undefined ? null : createS5bAdmission(config, emit);
/** Which uid each ID token (by hash) belonged to, as the SDK obtained them. */
export const tokenOwner = new Map();

const ledger = createWireLedger({
  hosts: local ? ["127.0.0.1", "localhost"] : transactionAdmission ? ["firestore.googleapis.com"] : PRODUCTION_HOSTS,
  cap: config.wireCap ?? 400,
  // Every socket the process opens counts, whether or not a request follows on it.
  connectionCap: config.connectionCap ?? 20,
  onConnection: ({ n, host }) => emit({ event: "connection", n, host }),
  onRecord: ({ n, host, path, bearer }) =>
    emit({
      event: "wire",
      n,
      host,
      path,
      principal: bearer === null ? null : (tokenOwner.get(bearer) ?? "unknown"),
    }),
  // A refused request marks the rows of this client as the harness's limit, not behavior, and
  // ends the client: its SDK would otherwise retry at once, without end.
  onRefuse: ({ host, path, reason }) => {
    process.stdout.write(`${JSON.stringify({ event: "wire-refused", host, path, reason })}\n`, () =>
      process.exit(3),
    );
  },
});
let capture;
if ((local || transactionAdmission) && config.transactionCapture === true) {
  const require = createRequire(import.meta.url);
  const firestoreRequire = createRequire(require.resolve("@google-cloud/firestore/package.json"));
  const { protobuf } = firestoreRequire("google-gax");
  const root = protobuf.Root.fromJSON(firestoreRequire("./build/protos/v1.json"));
  capture = {
    ...(transactionAdmission ? { beforeTransaction: transactionAdmission.beforeTransaction } : {}),
    onTransaction: (evidence) => emit({ event: "transaction-wire", ...evidence }),
    decodeGrpc(method, bytes, response) {
      const type = root.lookupType(
        `google.firestore.v1.${method}${response ? "Response" : "Request"}`,
      );
      const messages = [];
      for (let offset = 0; offset < bytes.length;) {
        if (offset + 5 > bytes.length || bytes[offset] !== 0) throw new Error("invalid gRPC frame");
        const length = bytes.readUInt32BE(offset + 1);
        if (offset + 5 + length > bytes.length) throw new Error("truncated gRPC frame");
        messages.push(
          type.toObject(type.decode(bytes.subarray(offset + 5, offset + 5 + length)), {
            longs: String,
          }),
        );
        offset += 5 + length;
      }
      if (!response && messages.length !== 1) throw new Error("request frame count");
      return response && method === "BatchGetDocuments" ? messages : messages[0];
    },
  };
}
if (transactionAdmission && !capture) throw new Error("S5b production capture is required");
installWireGuard(ledger, capture);
installSocketGuard(ledger);
