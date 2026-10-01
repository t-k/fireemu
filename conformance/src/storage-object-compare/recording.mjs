// Reads the private record of one recorder run (production, or a local rehearsal's journal) into
// the exchanges of each recipe, in order. The record is `captures.jsonl` (one line per request that
// went through the wire, with its response) and `events.jsonl` (the recipe boundaries); a local
// rehearsal's single `aggregate-events.jsonl` has both, with the captures as `lean-capture` lines.

import { readFileSync } from "node:fs";
import { join } from "node:path";

const parseLines = (text) =>
  text
    .split("\n")
    .filter((line) => line.trim() !== "")
    .map((line) => JSON.parse(line));

/** One capture line as an exchange the normalizer takes, or null for a line that is not a request. */
export function exchangeOf(row) {
  const request = row?.request;
  const response = row?.response;
  if (!request || !response || typeof request.url !== "string") return null;
  if (!Number.isSafeInteger(row.sequence) || !Number.isSafeInteger(response.status)) return null;
  return {
    sequence: row.sequence,
    method: request.method,
    url: request.url,
    status: response.status,
    headers: Object.fromEntries(
      Object.entries(response.headers ?? {}).map(([name, value]) => [
        name.toLowerCase(),
        String(value),
      ]),
    ),
    body: Buffer.from(response.bodyBase64 ?? "", "base64"),
    // The length the recorder received; the stored body of a JSON answer is re-serialized compactly.
    bodyBytes: Number.isSafeInteger(response.bodyBytes) ? response.bodyBytes : null,
  };
}

/**
 * Split capture lines into recipes by the recipe boundaries. A boundary row is
 * `{ type: "recipe-finish", recipeId, firstSequence, lastSequence }`; a capture belongs to the
 * recipe whose range holds its sequence, and a capture in no range (the fixed-Rules reads) is
 * left out.
 */
export function splitRecipes({ captureRows, eventRows }) {
  const recipes = eventRows
    .filter((row) => row?.type === "recipe-finish" && typeof row.recipeId === "string")
    .map((row) => ({
      recipeId: row.recipeId,
      firstSequence: row.firstSequence,
      lastSequence: row.lastSequence,
      exchanges: [],
    }));
  const seen = new Set();
  for (const recipe of recipes) {
    if (seen.has(recipe.recipeId)) throw new Error(`recipe ${recipe.recipeId} finishes twice`);
    seen.add(recipe.recipeId);
  }
  for (const row of captureRows) {
    const exchange = exchangeOf(row);
    if (!exchange) continue;
    const recipe = recipes.find(
      (candidate) =>
        exchange.sequence >= candidate.firstSequence && exchange.sequence <= candidate.lastSequence,
    );
    if (recipe) recipe.exchanges.push(exchange);
  }
  for (const recipe of recipes)
    recipe.exchanges.sort((left, right) => left.sequence - right.sequence);
  return recipes;
}

/** A production recording: a directory with `captures.jsonl`, `events.jsonl` and `meta.json`. */
export function readProductionRecording(directory) {
  const meta = JSON.parse(readFileSync(join(directory, "meta.json"), "utf8"));
  if (typeof meta.runId !== "string" || !/^[0-9a-f]{20}$/.test(meta.runId))
    throw new Error("the recording's meta.json has no run ID");
  return {
    runId: meta.runId,
    outcome: meta.outcome,
    failedRecipes: meta.failedRecipes ?? [],
    recipes: splitRecipes({
      captureRows: parseLines(readFileSync(join(directory, "captures.jsonl"), "utf8")),
      eventRows: parseLines(readFileSync(join(directory, "events.jsonl"), "utf8")),
    }),
  };
}

/** A local rehearsal: the journal of `local-aggregate.mjs`, with the run's prefix in its first recipe. */
export function readLocalJournal(path) {
  const rows = parseLines(readFileSync(path, "utf8"));
  const begin = rows.find((row) => row?.type === "recipe-begin");
  const runId = /^storage-object\/([0-9a-f]{8,32})\//.exec(begin?.prefix ?? "")?.[1];
  if (!runId) throw new Error("the journal has no recipe-begin with a run prefix");
  return {
    runId,
    recipes: splitRecipes({
      captureRows: rows.filter((row) => row?.type === "lean-capture"),
      eventRows: rows,
    }),
  };
}
