// A plain Node process exercises admission without inheriting node:test execution flags.
import { runtimeIdentity, describeSource, verifyDescriptor } from "../admission.mjs";
if (process.argv[2] === "preload") process.env.NODE_OPTIONS = "--require /unreviewed-preload.cjs";
try {
  if (process.argv[2] === "source-omission" || process.argv[2] === "runtime-mismatch") {
    const descriptor = describeSource();
    if (process.argv[2] === "source-omission") descriptor.sources = descriptor.sources.filter((pin) => !pin.path.endsWith("/admission.mjs"));
    else descriptor.runtime.node = "v0.0.0";
    verifyDescriptor(descriptor);
    process.stdout.write("unexpected descriptor acceptance\n");
  } else process.stdout.write(`${JSON.stringify(runtimeIdentity())}\n`);
} catch (error) {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 2;
}
