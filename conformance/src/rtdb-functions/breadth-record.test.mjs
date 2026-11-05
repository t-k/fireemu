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

for (const failure of [
  "paths",
  "tree",
  "ignored",
  "approval",
  "digest",
  "pins",
  "sources",
  "adc",
]) {
  test(`admission refuses ${failure} without a request`, async () => {
    let requests = 0;
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
      adcVerdict: async () => {
        return { ok: false, reason: "invalid" };
      },
    };
    const env = {
      FIREEMU_CV14_REVIEW: failure === "paths" ? "" : "/private/review",
      FIREEMU_CV14_PACKET: "/private/packet",
    };
    await assert.rejects(async () => {
      await admitRun({ env, privateRoot: "/private", root: "/repo", deps });
      requests++;
    });
    assert.equal(requests, 0);
  });
}
