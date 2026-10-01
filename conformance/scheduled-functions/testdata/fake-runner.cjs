"use strict";
// A stand-in for the Functions runner in the launch-accounting harness tests (offline only). It
// loads the fixture, which runs a control preamble first when there is one, reports the
// manifest, then answers one JSON request per line until its input closes.
const { join } = require("node:path");
const readline = require("node:readline");

const source = process.argv[process.argv.indexOf("--source") + 1];
const loaded = require(join(source, "index.cjs"));
const manifest = Object.entries(loaded).map(([name, value]) => ({ name, ...value.__endpoint }));
process.stdout.write(JSON.stringify(manifest) + "\n");
const lines = readline.createInterface({ input: process.stdin });
lines.on("line", async (line) => {
  const request = JSON.parse(line);
  const answer = request.invoke
    ? await loaded[request.invoke].run(request.event)
    : await loaded.calendarReceipt.run();
  process.stdout.write(JSON.stringify(answer ?? null) + "\n");
});
lines.on("close", () => process.exit(0));
