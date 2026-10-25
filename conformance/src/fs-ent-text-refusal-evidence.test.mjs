import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { PROGRAMS } from "./fs-ent-pipeline/text-corpus.mjs";

const cases = ["rank-asc", "retrieval-zero", "language-auto", "language-invalid"];
const ids = new Set(cases.flatMap((id) => [id, `${id}-grpc`]));
const fn = (name, ...args) => ({ functionValue: { name, args } });
const score = () => fn("score");
const rootOr = {
  id: "fs-ent-text/v1/search-root-or-refusal",
  source:
    "A single recorded Enterprise Native REST search-root OR refusal; the original synthetic collection and all query options are preserved.",
  steps: [
    {
      id: "root-or",
      rpc: "executePipeline",
      body: {
        structuredPipeline: {
          pipeline: {
            stages: [
              {
                name: "collection",
                args: [{ referenceValue: "/score-boolean-a-20261025" }],
              },
              {
                name: "search",
                args: [],
                options: {
                  add_fields: { mapValue: { fields: { rank: score() } } },
                  query: fn(
                    "or",
                    fn("document_matches", { stringValue: "cedar" }),
                    fn("document_matches", { stringValue: "mango" }),
                  ),
                  query_enhancement: { stringValue: "disabled" },
                  sort: {
                    arrayValue: {
                      values: [
                        {
                          mapValue: {
                            fields: {
                              expression: score(),
                              direction: { stringValue: "descending" },
                            },
                          },
                        },
                      ],
                    },
                  },
                },
              },
            ],
          },
        },
      },
    },
  ],
};
export const projection = {
  schema: "text-refusal-requests/v1",
  source: "src/fs-ent-pipeline/text-corpus.mjs",
  programs: [
    ...PROGRAMS.map(({ id, steps }) => ({
      id,
      steps: steps.filter((step) => ids.has(step.id)),
    })),
    rootOr,
  ],
};
test("text refusal projection preserves the original eight requests and the exact root OR request", async () => {
  const bytes = await readFile(
    new URL("../fs-ent-text-refusal-requests.json", import.meta.url),
    "utf8",
  );
  assert.deepEqual(JSON.parse(bytes), projection);
  assert.equal(projection.programs[0].steps.length, 8);
  assert.equal(projection.programs.flatMap(({ steps }) => steps).length, 9);
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
