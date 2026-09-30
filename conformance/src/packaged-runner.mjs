// Where the Functions runner of an installed fireemu package sits, mirroring the daemon's own
// search (`runner_candidates` in crates/fireemu/src/functions.rs): `runner-node/index.mjs` beside
// the real executable, then one directory above it. The release gate uses this to insist that the
// runner under test is the one the package ships, never the checkout's.
import { realpathSync, statSync } from "node:fs";
import { dirname, join } from "node:path";

const isFile = (path) => {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
};

/** The runner scripts a package would ship beside `binary`, in the order the daemon tries them. */
export function packagedRunnerCandidates(binary, realpath = realpathSync) {
  const dir = dirname(realpath(binary));
  return [join(dir, "runner-node", "index.mjs"), join(dir, "..", "runner-node", "index.mjs")];
}

/** The packaged runner script beside `binary`, or undefined when the package ships none. */
export function findPackagedRunner(binary, { exists = isFile, realpath = realpathSync } = {}) {
  return packagedRunnerCandidates(binary, realpath).find((path) => exists(path));
}
