// Local-only SDK interoperability check; the disposable world always binds ephemeral ports.
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { withTestWorld } from "../../npm/fireemu/testing.mjs";

await withTestWorld(
  {
    binaryPath:
      process.env.FIREEMU_BINARY ??
      fileURLToPath(new URL("../../target/debug/fireemu", import.meta.url)),
    projectId: "demo-text-search",
    services: ["firestore"],
    config: {
      schemaVersion: 1,
      profile: "strict",
      firestore: {
        edition: "enterprise",
        apiMode: "native",
        indexFile: fileURLToPath(new URL("./firestore.indexes.json", import.meta.url)),
      },
    },
  },
  async (world) => {
    const result = await world.run(process.execPath, [
      fileURLToPath(new URL("./local-smoke.mjs", import.meta.url)),
    ]);
    process.stdout.write(result.stdout);
    process.stderr.write(result.stderr);
    assert.equal(result.code, 0);
  },
);
console.log("Text-search test world disposed");
