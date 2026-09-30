import { execFileSync } from "node:child_process";
import { delimiter, isAbsolute, join } from "node:path";

/** Select the certificate tool only for the federation comparisons, without changing their frozen harness. */
export function federationEnvironment(id, env, execute = execFileSync) {
  if (!["R15", "R16", "R17"].includes(id)) return env;
  const directory = env.FIREEMU_FEDERATION_OPENSSL_DIR;
  if (directory !== undefined && (!directory || !isAbsolute(directory) || directory.includes(delimiter))) {
    throw new Error("FIREEMU_FEDERATION_OPENSSL_DIR must be an absolute directory without PATH delimiters");
  }
  const selected = directory ? { ...env, PATH: `${directory}${env.PATH ? delimiter + env.PATH : ""}` } : env;
  const requirement = `${id} requires OpenSSL >= 3.4 for the frozen federation certificate fixture`;
  let version;
  try {
    version = execute(directory ? join(directory, "openssl") : "openssl", ["version"], {
      env: selected,
      encoding: "utf8",
      timeout: 5000,
    }).trim();
  } catch (error) {
    throw new Error(`${requirement}: ${error.message}`, { cause: error });
  }
  const match = /^OpenSSL (\d+)\.(\d+)\.(\d+)(?:\s|$)/.exec(version);
  if (!match || Number(match[1]) < 3 || (Number(match[1]) === 3 && Number(match[2]) < 4)) {
    throw new Error(`${requirement}; found ${version || "an empty version response"}`);
  }
  return selected;
}
