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
