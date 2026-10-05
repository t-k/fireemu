// A real access token of a narrower scope than the recorder's own, for the wrong-scope probe: the
// owner's Application Default Credentials through `gcloud auth application-default print-access-token
// --scopes=<scope>`, run without a shell. It is the wrong-scope request's bearer and is never written
// anywhere. When gcloud cannot print one (the credential was not granted that scope) the answer is null
// and the probe is skipped with a note; the failure message is never repeated, as it could carry a token.

import { execFile as nodeExecFile } from "node:child_process";

const SCOPE = /^https:\/\/www\.googleapis\.com\/auth\/[a-z.]+$/;
const TOKEN = /^[A-Za-z0-9._~+/=-]{20,4096}$/;

const defaultExecFile = (file, args, options) =>
  new Promise((resolve, reject) => {
    nodeExecFile(file, args, options, (error, stdout) => (error ? reject(error) : resolve(stdout)));
  });

export function createScopedToken({ execFile = defaultExecFile, command = "gcloud" } = {}) {
  return async (scope) => {
    if (typeof scope !== "string" || !SCOPE.test(scope)) throw new Error("not an OAuth scope");
    let output;
    try {
      output = await execFile(
        command,
        ["auth", "application-default", "print-access-token", `--scopes=${scope}`],
        { timeout: 30_000, maxBuffer: 64 * 1024 },
      );
    } catch {
      return null;
    }
    const token = String(output).trim();
    return TOKEN.test(token) ? token : null;
  };
}
