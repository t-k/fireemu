// Writes (or checks) the pinned manifest of the TASK-QUEUE-FUNCTIONS program: `node corpus-manifest.mjs write|check`.
// `write` is followed by `oxfmt` in conformance/ (the committed bytes are the formatted ones, and the closure record pins
// their sha256); `check` compares the parsed content, so formatting never changes what it means.
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { corpusManifest } from "./corpus.mjs";

export const MANIFEST_PATH = fileURLToPath(new URL("./corpus.manifest.json", import.meta.url));
export const manifestText = () => JSON.stringify(corpusManifest(), null, 2) + "\n";

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [command] = process.argv.slice(2);
  if (command === "write") writeFileSync(MANIFEST_PATH, manifestText());
  else if (command === "check") {
    if (
      JSON.stringify(JSON.parse(readFileSync(MANIFEST_PATH, "utf8"))) !==
      JSON.stringify(corpusManifest())
    ) {
      console.error("corpus.manifest.json is not the manifest of corpus.mjs; run `write`");
      process.exitCode = 1;
    }
  } else {
    console.error("usage: corpus-manifest.mjs write|check");
    process.exitCode = 2;
  }
}
