/** Connect to the installed pilot. Never fall back to fixtures or live acquisition. */
import { promises as fs } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { SUPPORTED_CASE } from "./suite.mjs";

const sha256 = (data) => createHash("sha256").update(data).digest("hex");
const PILOT_FILES = [
  "core.mjs",
  "registry.mjs",
  "legacy.mjs",
  "io.mjs",
  "local-session.mjs",
  "network.mjs",
  "pilot.mjs",
];
const AUDIT_FILES = ["audit.mjs", "installed.mjs", "suite.mjs"];
const EXECUTED_AUDIT_DIR = dirname(fileURLToPath(import.meta.url));

async function readRegular(root, relative) {
  let path = root;
  for (const part of relative.split("/")) {
    path = join(path, part);
    if ((await fs.lstat(path)).isSymbolicLink()) throw new Error("audit-source-symlink");
  }
  const info = await fs.stat(path);
  if (!info.isFile() || info.size > 1024 * 1024) throw new Error("audit-source-size-or-type");
  const bytes = await fs.readFile(path);
  if (bytes.length > 1024 * 1024) throw new Error("audit-source-size-or-type");
  return bytes;
}
async function sourceHashes(repo) {
  const values = {};
  for (const name of PILOT_FILES) {
    const path = `conformance/production-diff/${name}`;
    values[path] = sha256(await readRegular(repo, path));
  }
  for (const name of AUDIT_FILES) {
    // --repo can select another checkout. Hash the audit code actually running,
    // not an unexecuted copy of that code in the selected checkout.
    values[`executed-audit/${name}`] = sha256(await readRegular(EXECUTED_AUDIT_DIR, name));
  }
  return values;
}

export async function loadInstalled(repo) {
  const root = await fs.realpath(resolve(repo));
  let hashes;
  try {
    hashes = await sourceHashes(root);
  } catch (error) {
    if (error?.code === "ENOENT") throw new Error("required-pilot-or-audit-not-installed");
    throw error;
  }
  // Trusted, reviewed repository modules only. This is not an arbitrary plugin API.
  const moduleUrl = (name) => pathToFileURL(join(root, "conformance/production-diff", name)).href;
  const [legacy, core, io] = await Promise.all([
    import(moduleUrl("legacy.mjs")),
    import(moduleUrl("core.mjs")),
    import(moduleUrl("io.mjs")),
  ]);
  const prepared = await legacy.prepare(root);
  if (prepared.entry.id !== SUPPORTED_CASE) throw new Error("unsupported-audit-case");
  if (JSON.stringify(hashes) !== JSON.stringify(await sourceHashes(root)))
    throw new Error("audit-source-changed");
  return {
    root,
    subject: {
      entry: prepared.entry,
      program: prepared.program,
      production: prepared.production,
      compare: (actual, program) => core.compareRecords({ ...prepared, actual, program }),
      envelope: (comparison, execution) =>
        core.resultEnvelope({
          entry: prepared.entry,
          comparison,
          execution,
          provenance: { syntheticAuditControl: true },
        }),
    },
    identity: {
      kind: "installed-pilot-pinned-source",
      repository: prepared.state,
      oracle: prepared.provenance.oracle,
      implementation: prepared.provenance.implementation,
      sourceSha256: hashes,
      completeRepositoryValidation: true,
      nativeBuildValidated: false,
    },
    unchanged: async () =>
      JSON.stringify(hashes) === JSON.stringify(await sourceHashes(root)) &&
      (await legacy.sourceUnchanged(
        root,
        prepared.entry,
        prepared.state,
        prepared.provenance.implementation.adapterSha256,
      )),
    createOutput: (output) => io.newPrivateDirectory(output, root),
    // result.json is the authoritative last publication. A report.md alone is incomplete.
    publish: async (directory, report, markdown) => {
      await io.publish(join(directory, "report.md"), markdown);
      await io.publishJson(join(directory, "result.json"), report);
    },
  };
}
