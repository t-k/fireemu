import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  exchangeOf,
  readLocalJournal,
  readProductionRecording,
  splitRecipes,
} from "./storage-object-compare/recording.mjs";

const capture = (sequence, extra = {}) => ({
  sequence,
  request: { method: "GET", url: `https://x.example/o/${sequence}` },
  response: {
    status: 200,
    headers: { "Content-Type": "application/json" },
    bodyBase64: Buffer.from("{}").toString("base64"),
  },
  ...extra,
});
const finish = (recipeId, firstSequence, lastSequence) => ({
  type: "recipe-finish",
  recipeId,
  firstSequence,
  lastSequence,
});
const lines = (rows) => `${rows.map((row) => JSON.stringify(row)).join("\n")}\n`;

test("a capture line is an exchange with lower-cased headers and a body buffer", () => {
  const exchange = exchangeOf(capture(5));
  assert.equal(exchange.sequence, 5);
  assert.equal(exchange.method, "GET");
  assert.deepEqual(exchange.headers, { "content-type": "application/json" });
  assert.deepEqual(exchange.body, Buffer.from("{}"));
  assert.equal(exchange.bodyBytes, null);
  assert.equal(exchangeOf(capture(5, { response: { status: 200, bodyBytes: 74 } })).bodyBytes, 74);
  assert.equal(
    exchangeOf(capture(5, { response: { status: 200, bodyBytes: "74" } })).bodyBytes,
    null,
  );
  assert.deepEqual(exchangeOf(capture(5, { response: { status: 204 } })).body, Buffer.alloc(0));
});

test("a line that is not a request with a response is not an exchange", () => {
  for (const row of [
    null,
    {},
    { kind: "rules-read", url: "x", status: 200 },
    capture(1, { request: { method: "GET" } }),
    capture(1, { sequence: "1" }),
    capture(1, { response: {} }),
    capture(1, { response: { status: "200" } }),
  ])
    assert.equal(exchangeOf(row), null);
});

test("a line with only a request, or only a response, is not an exchange", () => {
  assert.equal(
    exchangeOf({ sequence: 1, request: { method: "GET", url: "https://x.example/o" } }),
    null,
  );
  assert.equal(exchangeOf({ sequence: 1, response: { status: 200 } }), null);
  assert.equal(
    exchangeOf({
      sequence: 1,
      request: { method: "GET", url: "https://x.example/o" },
      response: null,
    }),
    null,
  );
});

test("captures are split by the recipes' sequence ranges, in order, and a capture in no range is left out", () => {
  const recipes = splitRecipes({
    captureRows: [
      capture(5),
      capture(2),
      capture(9),
      capture(1),
      { kind: "rules-read", status: 200, url: "u" },
      capture(3),
    ],
    eventRows: [
      { type: "recipe-begin", recipeId: "a" },
      finish("storage-object/a", 2, 4),
      finish("storage-object/b", 5, 8),
    ],
  });
  assert.deepEqual(
    recipes.map((recipe) => [
      recipe.recipeId,
      recipe.exchanges.map((exchange) => exchange.sequence),
    ]),
    [
      ["storage-object/a", [2, 3]],
      ["storage-object/b", [5]],
    ],
  );
});

test("the ends of a range belong to the recipe", () => {
  const [recipe] = splitRecipes({
    captureRows: [capture(1), capture(2), capture(3), capture(4)],
    eventRows: [finish("storage-object/a", 2, 3)],
  });
  assert.deepEqual(
    recipe.exchanges.map((exchange) => exchange.sequence),
    [2, 3],
  );
});

test("a recipe that finishes twice is refused", () => {
  assert.throws(
    () =>
      splitRecipes({
        captureRows: [],
        eventRows: [finish("storage-object/a", 1, 2), finish("storage-object/a", 3, 4)],
      }),
    /finishes twice/,
  );
});

test("a production recording is read from its directory, and needs a run ID", () => {
  const directory = mkdtempSync(join(tmpdir(), "compare-recording-"));
  writeFileSync(
    join(directory, "meta.json"),
    JSON.stringify({ runId: "056c7ca3a8c6daa38e0a", outcome: "recorded", failedRecipes: [] }),
  );
  writeFileSync(join(directory, "captures.jsonl"), lines([capture(2), capture(3)]));
  writeFileSync(join(directory, "events.jsonl"), lines([finish("storage-object/a", 2, 3)]));
  const recording = readProductionRecording(directory);
  assert.equal(recording.runId, "056c7ca3a8c6daa38e0a");
  assert.equal(recording.outcome, "recorded");
  assert.deepEqual(recording.failedRecipes, []);
  assert.equal(recording.recipes[0].exchanges.length, 2);
  writeFileSync(join(directory, "meta.json"), JSON.stringify({ runId: "short" }));
  assert.throws(() => readProductionRecording(directory), /no run ID/);
  writeFileSync(join(directory, "meta.json"), JSON.stringify({ outcome: "recorded" }));
  assert.throws(() => readProductionRecording(directory), /no run ID/);
});

test("a local journal gives its run ID from the first recipe's prefix, and its captures from lean-capture lines", () => {
  const directory = mkdtempSync(join(tmpdir(), "compare-journal-"));
  mkdirSync(directory, { recursive: true });
  const path = join(directory, "aggregate-events.jsonl");
  writeFileSync(
    path,
    lines([
      {
        type: "recipe-begin",
        recipeId: "storage-object/a",
        prefix: "storage-object/aaaabbbbccccdddd0001/",
        sequence: 1,
      },
      { type: "lean-capture", ...capture(2) },
      { type: "response", operationId: "x", status: 200 },
      { type: "lean-capture", ...capture(3) },
      finish("storage-object/a", 2, 3),
    ]),
  );
  const journal = readLocalJournal(path);
  assert.equal(journal.runId, "aaaabbbbccccdddd0001");
  assert.equal(journal.recipes[0].exchanges.length, 2);
  writeFileSync(
    path,
    lines([
      { type: "recipe-finish", recipeId: "storage-object/a", firstSequence: 1, lastSequence: 2 },
    ]),
  );
  assert.throws(() => readLocalJournal(path), /no recipe-begin/);
  writeFileSync(path, lines([{ type: "recipe-begin", prefix: "elsewhere/x/" }]));
  assert.throws(() => readLocalJournal(path), /no recipe-begin/);
});

test("a recipe's exchanges are in sequence order whatever order the captures were written in", () => {
  const [recipe] = splitRecipes({
    captureRows: [capture(4), capture(2), capture(3), capture(5)],
    eventRows: [finish("storage-object/a", 2, 5)],
  });
  assert.deepEqual(
    recipe.exchanges.map((exchange) => exchange.sequence),
    [2, 3, 4, 5],
  );
});
