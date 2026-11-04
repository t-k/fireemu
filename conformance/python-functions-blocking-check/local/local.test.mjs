// The local dry run's fixed parts: the golden frames (the fixture's output under fireemu, run id and account id replaced)
// judged in the local mode, and the dry run's argument parsing. The dry run itself needs a built fireemu and a Python
// environment, so it is run by hand and recorded in the packet's notes, not here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { judge } from "../record/judge.mjs";
import { parseFramesFromText } from "../record/logs.mjs";
import { emailOf } from "../record/script.mjs";
import { parseArgs } from "./dry-run.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const RUN = "0123456789abcdef";
const LOCAL_ID = "Wd3kJ9xQ2mP7sT4vB8nL5cZ6yH1a";
const golden = () =>
  parseFramesFromText(
    readFileSync(join(here, "golden-frames.txt"), "utf8")
      .replaceAll("RUNID", RUN)
      .replaceAll("LOCALID", LOCAL_ID),
  );

test("the golden frames parse, with nothing ignored: one raw line and one SDK line", () => {
  const { frames, ignored } = golden();
  assert.equal(ignored, 0);
  assert.deepEqual(
    frames.map((f) => f.frame.kind),
    ["blocking-raw", "blocking-sdk"],
  );
});

test("the golden frames judge, in the local mode, as the dry run did: every delivered case as expected", () => {
  const r = judge({
    email: emailOf(RUN),
    localId: LOCAL_ID,
    frames: golden().frames,
    mode: "local",
    observed: { signUp: { class: "2xx", status: 200, localId: LOCAL_ID } },
  });
  assert.deepEqual(Object.fromEntries(Object.entries(r.cases).map(([id, c]) => [id, c.status])), {
    "signup-allowed": "as-expected",
    "trigger-registered": "not-sent",
    "invoker-public": "not-sent",
    "blocking-request": "as-expected",
    "blocking-claims": "as-expected",
    "blocking-sdk": "as-expected",
    "sdk-versions": "as-expected",
  });
  assert.equal(
    r.cases["blocking-request"].observed.tokenHeader.alg,
    "none",
    "the emulator's token is unsigned",
  );
});

test("the golden frames carry no address, no token and no password", () => {
  const text = readFileSync(join(here, "golden-frames.txt"), "utf8");
  assert.ok(
    !/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(
      text.replaceAll("127.0.0.1", "loopback").replace(/"versions": \{[^}]*\}/g, ""),
    ),
    "no IPv4 address but the loopback",
  );
  assert.ok(!/eyJ[A-Za-z0-9_-]{10,}/.test(text), "no token");
  assert.ok(!/Pcblock-/.test(text), "no password");
});

test("the dry run's arguments: pairs of flags, strict by default", () => {
  assert.deepEqual(parseArgs(["--fireemu", "/f", "--venv", "/v", "--out", "/o"]), {
    profile: "strict",
    fireemu: "/f",
    venv: "/v",
    out: "/o",
  });
  assert.equal(parseArgs(["--profile", "emulator"]).profile, "emulator");
  assert.throws(() => parseArgs(["--fireemu"]), /bad arguments/);
  assert.throws(() => parseArgs(["fireemu", "x"]), /bad arguments/);
});
