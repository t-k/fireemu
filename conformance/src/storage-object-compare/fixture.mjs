// The committed fixture: one file per recipe, each row an exchange normalized by `normalize.mjs`,
// plus an index that says where the rows came from and what was masked. The fixture is built from
// one or more recordings; when there are several, they must normalize to the same rows (that is
// what the equivalence digests state).

import { createHash } from "node:crypto";
import {
  createContext,
  NORMALIZATION_VERSION,
  NORMALIZATIONS,
  normalizeExchange,
} from "./normalize.mjs";

export const FIXTURE_SCHEMA_VERSION = 1;

export const recipeSlug = (recipeId) =>
  recipeId.replace(/^storage-object\//, "").replaceAll("/", "--");

/** The recipe's exchanges, normalized, numbered from 1 in the recording's order. */
export function normalizeRecipe(recipe, { runId, bucket, project }) {
  // Objects whose bytes carry the run ID have digests that differ for each run. Only the bytes of
  // a media read count: a name in a JSON body carries the ID in every recipe.
  const needle = Buffer.from(runId);
  const contentCarriesRun = recipe.exchanges.some(
    (exchange) =>
      exchange.url.includes("alt=media") &&
      [200, 206].includes(exchange.status) &&
      exchange.body.includes(needle),
  );
  const ctx = createContext({ runId, bucket, project, contentCarriesRun });
  return recipe.exchanges.map((exchange, index) => ({
    n: index + 1,
    ...normalizeExchange(exchange, ctx),
  }));
}

export const digestRows = (rows) => createHash("sha256").update(JSON.stringify(rows)).digest("hex");

/**
 * Build the fixture from recordings: `recordings` are `{ runId, recipes }`. The first is the one
 * whose rows are written; every other must have the same recipes with the same rows.
 */
export function buildFixture({ recordings, bucket, project, source }) {
  if (recordings.length === 0) throw new Error("no recording");
  const [primary, ...others] = recordings;
  const recipes = primary.recipes.map((recipe) => {
    const rows = normalizeRecipe(recipe, { runId: primary.runId, bucket, project });
    const digests = {
      [primary.runId]: digestRows(rows),
    };
    for (const other of others) {
      const twin = other.recipes.find((candidate) => candidate.recipeId === recipe.recipeId);
      if (!twin) throw new Error(`${recipe.recipeId} is missing from run ${other.runId}`);
      digests[other.runId] = digestRows(
        normalizeRecipe(twin, { runId: other.runId, bucket, project }),
      );
    }
    return { recipeId: recipe.recipeId, rows, digests };
  });
  for (const other of others)
    if (other.recipes.length !== primary.recipes.length)
      throw new Error(`run ${other.runId} has a different set of recipes`);
  const equivalent = recipes.every((recipe) => new Set(Object.values(recipe.digests)).size === 1);
  return {
    index: {
      schemaVersion: FIXTURE_SCHEMA_VERSION,
      normalizationVersion: NORMALIZATION_VERSION,
      normalizations: NORMALIZATIONS,
      source,
      runIds: recordings.map((recording) => recording.runId),
      recipes: recipes.map((recipe) => ({
        recipeId: recipe.recipeId,
        file: `${recipeSlug(recipe.recipeId)}.json`,
        rows: recipe.rows.length,
        digests: recipe.digests,
      })),
      equivalentRecordings: equivalent,
    },
    recipes,
  };
}

/** One recipe's file: one row per line, so that a diff names the exchange. */
export function recipeFileText(recipe) {
  const header = {
    schemaVersion: FIXTURE_SCHEMA_VERSION,
    recipeId: recipe.recipeId,
    rows: recipe.rows.length,
  };
  return `${JSON.stringify(header).slice(0, -1)},"exchanges":[\n${recipe.rows.map((row) => JSON.stringify(row)).join(",\n")}\n]}\n`;
}

export const indexText = (index) => `${JSON.stringify(index, null, 2)}\n`;
