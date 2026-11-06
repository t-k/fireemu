import { readFileSync } from "node:fs";
import { publicEvidence } from "./evidence.mjs";

try {
  publicEvidence(JSON.parse(readFileSync(0, "utf8")));
} catch {
  process.stderr.write("public evidence validation failed\n");
  process.exitCode = 1;
}
