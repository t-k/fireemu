// The access token of a production recording: the owner's Application Default Credentials, through
// `gcloud auth application-default print-access-token` (the way docs.local/sandbox-oracles.md names),
// run without a shell. The token is cached for a while and never written anywhere by this module; an
// error never contains it.

import { execFile as nodeExecFile } from "node:child_process";

const TOKEN = /^[A-Za-z0-9._~+/=-]{20,4096}$/;

const defaultExecFile = (file, args, options) =>
  new Promise((resolve, reject) => {
    nodeExecFile(file, args, options, (error, stdout) =>
      error ? reject(new Error("gcloud could not print an access token")) : resolve(stdout),
    );
  });

export function createTokenProvider({
  execFile = defaultExecFile,
  now = Date.now,
  ttlMs = 40 * 60 * 1000,
  command = "gcloud",
} = {}) {
  let cached = null;
  let issuedAt = 0;
  let calls = 0;
  return Object.freeze({
    async get() {
      if (cached !== null && now() - issuedAt < ttlMs) return cached;
      calls += 1;
      let output;
      try {
        output = await execFile(command, ["auth", "application-default", "print-access-token"], {
          timeout: 30_000,
          maxBuffer: 64 * 1024,
        });
      } catch {
        // Whatever the failure said, it is not repeated: it could carry the token.
        throw new Error("gcloud could not print an access token");
      }
      const token = String(output).trim();
      if (!TOKEN.test(token))
        throw new Error("gcloud printed something that is not an access token");
      cached = token;
      issuedAt = now();
      return token;
    },
    invalidate() {
      cached = null;
    },
    /** How many times gcloud was run. */
    calls: () => calls,
  });
}
