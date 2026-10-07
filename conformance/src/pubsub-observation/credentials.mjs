// Constructed only after source, ledger proofs and live lock admission. Never log a token or child output.
import { execFile } from "node:child_process";
export function createCredentials({ now = Date.now } = {}) {
  let token = null,
    issued = 0;
  return async ({ timeoutMs, signal }) => {
    if (token !== null && now() - issued < 2400000) return token;
    const output = await new Promise((resolve, reject) =>
      execFile(
        "gcloud",
        ["auth", "application-default", "print-access-token"],
        { timeout: timeoutMs, signal, maxBuffer: 65536 },
        (error, stdout) =>
          error ? reject(new Error("credential retrieval failed")) : resolve(stdout),
      ),
    );
    const value = String(output).trim();
    if (!/^[A-Za-z0-9._~+/=-]{20,4096}$/.test(value)) throw new Error("invalid credential output");
    token = value;
    issued = now();
    return token;
  };
}
