import { pathToFileURL } from "node:url";
import { types } from "node:util";
import { nativeClosed, nativeDigest, nativeSnapshot } from "./management-native-manifest.mjs";
import { projectNativeTransportResponse } from "./management-native-record.mjs";
import { createSingleAttemptHttpsTransport } from "./http-transport.mjs";

/** Offline injection only. Its counters and receipts never issue an actual ROOT capability. */
export function createNativeSyntheticTransport(options) {
  nativeClosed(
    options,
    ["requestImpl", "writeIntent", "writeAttempt", "writeTiming", "maxAttempts"],
    "synthetic transport",
  );
  const { requestImpl, writeIntent, writeAttempt, writeTiming, maxAttempts } = options;
  if (
    [requestImpl, writeIntent, writeAttempt, writeTiming].some(
      (fn) => typeof fn !== "function" || types.isProxy(fn),
    ) ||
    !Number.isSafeInteger(maxAttempts) ||
    maxAttempts < 1 ||
    maxAttempts > 10000
  )
    throw new Error("invalid synthetic transport");
  let busy = false,
    poisoned = false,
    unknown = false,
    attempts = 0,
    physicalAttempts = 0,
    permit = false;
  const transport = createSingleAttemptHttpsTransport({
    requestImpl(...args) {
      if (!permit) throw new Error("undeclared synthetic physical attempt");
      permit = false;
      physicalAttempts++;
      return requestImpl(...args);
    },
  });
  return Object.freeze({
    validate: (spec) => transport.validate(nativeSnapshot(spec, "synthetic request")),
    async send(input) {
      if (busy || poisoned || unknown || attempts >= maxAttempts)
        throw new Error("synthetic transport unavailable");
      const spec = nativeSnapshot(input, "synthetic request");
      transport.validate(spec);
      busy = true;
      try {
        const attempt = attempts + 1;
        await writeIntent(Object.freeze({ attempt, requestSha256: nativeDigest(spec) }));
        attempts++;
        await writeAttempt(Object.freeze({ attempt }));
        permit = true;
        let response;
        try {
          response = await transport.send(spec);
        } catch {
          unknown = true;
          throw new Error("synthetic transport outcome unknown; never retry");
        }
        const projected = projectNativeTransportResponse(response);
        await writeTiming(Object.freeze({ attempt, ...projected.timing }));
        return projected.raw;
      } catch (error) {
        poisoned = true;
        throw error;
      } finally {
        permit = false;
        busy = false;
      }
    },
    snapshot: () =>
      Object.freeze({
        evidenceKind: "SYNTHETIC_ONLY",
        sendAuthorized: false,
        closureReady: false,
        parentClaim: false,
        attempts,
        physicalAttempts,
        busy,
        poisoned,
        unknown,
        maxAttempts,
      }),
  });
}

// No actual authority reader is connected. Caller markers and supplied files cannot grant a send.
export async function withNativeRootRecording() {
  return Object.freeze({
    status: "HOLD",
    reason: "fresh ROOT authority unavailable",
    sendAuthorized: false,
    closureReady: false,
    parentClaim: false,
  });
}

export async function runNativeEntryCommand({ out = () => {} } = {}) {
  out("HOLD: fresh ROOT authority unavailable");
  return 3;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href)
  process.exitCode = await runNativeEntryCommand({
    out: (line) => process.stderr.write(`${line}\n`),
  });
