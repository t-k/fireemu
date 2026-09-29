import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyProductionCase } from "../evidence.mjs";
import { productionStatusLegend } from "./run.mjs";

test("the production matrix legend defines every status a row can have", () => {
  const answer = (status) => ({ status, code: status === 200 ? "OK" : "X" });
  const statuses = new Set([
    classifyProductionCase({ localOnly: true }),
    classifyProductionCase({ needsIndex: true }),
    classifyProductionCase({ evidenceValid: false }),
    classifyProductionCase({ production: answer(0), fireemu: answer(200) }),
    classifyProductionCase({
      production: answer(200),
      emulator: answer(200),
      fireemu: answer(200),
    }),
    classifyProductionCase({
      production: answer(200),
      emulator: answer(400),
      fireemu: answer(200),
    }),
    classifyProductionCase({
      production: answer(200),
      emulator: answer(200),
      fireemu: answer(400),
    }),
    classifyProductionCase({
      production: answer(200),
      emulator: answer(400),
      fireemu: answer(400),
    }),
    classifyProductionCase({
      production: answer(200),
      emulator: answer(400),
      fireemu: answer(404),
    }),
  ]);
  assert.equal(statuses.size, 8);
  const legend = productionStatusLegend({ "excluded-local-only": 21, unverified: 1 });
  const rows = new Map(
    legend
      .slice(2)
      .map((line) => line.split("|").map((cell) => cell.trim()))
      .map(([, status, count, meaning]) => [status, { count, meaning }]),
  );
  assert.deepEqual(new Set(rows.keys()), statuses);
  assert.equal(rows.get("excluded-local-only").count, "21");
  assert.equal(rows.get("parity").count, "0");
  for (const { meaning } of rows.values()) assert.ok(meaning.length > 0);
});
