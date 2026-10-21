// Whether a module is the script Node was started with, for the CLIs of the sandbox runner.
// `import.meta.main` decides where Node sets it (24.2 and 22.18 on); before that the paths are
// compared after resolving links, so a launch through a symlinked directory, /tmp or a path
// that needs escaping still runs the CLI (a skipped CLI would exit 0 having checked nothing).

import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";

export function isMainModule(meta, argv1 = process.argv[1]) {
  if (typeof meta.main === "boolean") return meta.main;
  if (argv1 === undefined) return false;
  try {
    return realpathSync(fileURLToPath(meta.url)) === realpathSync(argv1);
  } catch {
    return false;
  }
}
