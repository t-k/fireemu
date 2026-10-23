import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PROGRAMS } from "./fs-ent-pipeline/text-corpus.mjs";

const cases = ["rank-asc", "retrieval-zero", "language-auto", "language-invalid"];
const ids = new Set(cases.flatMap((id) => [id, `${id}-grpc`]));
export const projection = {
  schema: "text-refusal-requests/v1",
  source: "src/fs-ent-pipeline/text-corpus.mjs",
  programs: PROGRAMS.map(({ id, steps }) => ({
    id,
    steps: steps.filter((step) => ids.has(step.id)),
  })),
};
test("text refusal projection preserves the eight complete corpus requests", async () => {
  const bytes = await readFile(
    new URL("../fs-ent-text-refusal-requests.json", import.meta.url),
    "utf8",
  );
  assert.equal(bytes, `${JSON.stringify(projection)}\n`);
  assert.equal(projection.programs.flatMap(({ steps }) => steps).length, 8);
  const production = JSON.parse(
    await readFile(new URL("../fs-ent-text-production.json", import.meta.url), "utf8"),
  );
  for (const program of projection.programs) {
    for (const step of program.steps) {
      const answer = production.programs[program.id].steps[step.id];
      if (step.transport === "grpc") {
        assert.equal(answer.transport, "grpc");
        assert.equal(answer.code, 3);
        assert.equal(typeof answer.message, "string");
      } else {
        assert.equal(answer.status, 400);
        const body = Array.isArray(answer.body) ? answer.body[0] : answer.body;
        assert.equal(body.error.status, "INVALID_ARGUMENT");
        assert.equal(typeof body.error.message, "string");
      }
    }
  }
});
