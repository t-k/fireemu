import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { test } from "node:test";
import { admitRun } from "./breadth-record.mjs";

const gitSha = "b".repeat(40);
const rulesSha = "a".repeat(64);
const packet = Buffer.from(
  `\`\`\`json cv14-pins\n${JSON.stringify({ baselineRulesSha256: rulesSha })}\n\`\`\`\n`,
);
const digest = (value) => createHash("sha256").update(value).digest("hex");

for (const failure of ["paths", "tree", "ignored", "approval", "digest", "pins", "sources"]) {
  test(`admission refuses ${failure} without a request`, async () => {
    let requests = 0;
    const fetchStub = () => {
      requests++;
      throw Error("unexpected request");
    };
    const content = failure === "pins" ? Buffer.from("no pins") : packet;
    const approval = `Decision: ${failure === "approval" ? "REJECT" : "APPROVE"}\ngitSha: ${gitSha}\npacketSha256: ${failure === "digest" ? rulesSha : digest(content)}\n`;
    const deps = {
      git: async (args) =>
        args[0] === "rev-parse"
          ? gitSha
          : failure === "tree"
            ? " M file"
            : failure === "ignored" && args.includes("--ignored")
              ? "!! fixture"
              : "",
      readFile: async (path) => (path.endsWith("review") ? approval : content),
      requiredSources: async () => {
        if (failure === "sources") throw Error("source mismatch");
      },
      adcVerdict: async () => fetchStub(),
    };
    const env = {
      FIREEMU_CV14_REVIEW: failure === "paths" ? "" : "/private/review",
      FIREEMU_CV14_PACKET: "/private/packet",
    };
    await assert.rejects(() => admitRun({ env, privateRoot: "/private", root: "/repo", deps }));
    assert.equal(requests, 0);
  });
}

test("admission refuses an invalid ADC verdict", async () => {
  const deps = {
    git: async (args) => (args[0] === "rev-parse" ? gitSha : ""),
    readFile: async (path) =>
      path.endsWith("review")
        ? `Decision: APPROVE\ngitSha: ${gitSha}\npacketSha256: ${digest(packet)}\n`
        : packet,
    requiredSources: async () => {},
    adcVerdict: async () => ({ ok: false, reason: "invalid" }),
  };
  await assert.rejects(
    () =>
      admitRun({
        env: { FIREEMU_CV14_REVIEW: "/private/review", FIREEMU_CV14_PACKET: "/private/packet" },
        privateRoot: "/private",
        root: "/repo",
        deps,
      }),
    /ADC token is not usable/,
  );
});

test("journal redacts current secrets from every row", async () => {
  const { mkdtemp, readFile, rm } = await import("node:fs/promises");
  const { tmpdir } = await import("node:os");
  const { join } = await import("node:path");
  const { executeRun } = await import("./breadth-record.mjs");
  const { makeWorld } = await import("./breadth-flow.fake.mjs");
  const dir = await mkdtemp(join(tmpdir(), "breadth-test-"));
  const secrets = ["sentinel-key", "sentinel-password", "sentinel-token"];
  try {
    const world = makeWorld({ preflightFails: true });
    await executeRun({
      environment: {
        projectId: "project",
        projectNumber: "12345",
        secrets,
        budget: { snapshot: () => ({ cliDeploy: 0 }) },
      },
      runDir: dir,
      packetPins: { baselineRulesSha256: rulesSha },
      assemble: ({ log }) => ({
        deps: {
          ...world.deps,
          log: async (action, detail) => log(action, `${detail} ${secrets.join(" ")}`),
        },
        uploads: { close() {} },
        forms: { summary: () => ({}), maskedLines: () => [] },
        grants: {},
      }),
    });
    const journal = await readFile(join(dir, "journal.jsonl"), "utf8");
    for (const secret of secrets) assert.ok(!journal.includes(secret));
    assert.match(journal, /\*\*\*/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
