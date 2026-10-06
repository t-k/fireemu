// A plain Node process exercises runtime admission without inheriting node:test execution flags.
import { runtimeIdentity } from "../admission.mjs";
if (process.argv[2] === "preload") process.env.NODE_OPTIONS = "--require /unreviewed-preload.cjs";
try {
  process.stdout.write(`${JSON.stringify(runtimeIdentity())}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 2;
}
