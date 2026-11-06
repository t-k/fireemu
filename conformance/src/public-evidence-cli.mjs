import { readFileSync } from "node:fs";
import { publicEvidenceBytes } from "./evidence.mjs";

try {
  publicEvidenceBytes(readFileSync(0));
} catch {
  process.stderr.write("public evidence validation failed\n");
  process.exitCode = 1;
}
