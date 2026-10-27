import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import { createBudget } from "./harness.mjs";
import { runCases } from "./session.mjs";

const corpus = JSON.parse(readFileSync(new URL("./corpus.json", import.meta.url), "utf8"));

test("the same session records corpus cases twice with one request per case", async () => {
  const program = corpus.programs[0];
  const budget = createBudget();
  const sent = [];
  const fetchImpl = async (url, init) => {
    sent.push({ url, method: init.method, redirect: init.redirect });
    return new Response(JSON.stringify({ method: init.method, path: new URL(url).pathname }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  const endpoints = { http: "http://127.0.0.1:5001/demo/us-central1/fireemuHttpProbe" };
  const first = await runCases(program, endpoints, {}, budget, { fetchImpl });
  const second = await runCases(program, endpoints, {}, budget, { fetchImpl });
  assert.equal(Object.keys(first).length, program.cases.length);
  assert.deepEqual(first, second);
  assert.equal(sent.length, program.cases.length * 2);
  assert.equal(budget.snapshot().invocation, program.cases.length * 2);
  assert.ok(sent.every(({ redirect }) => redirect === "manual"));
});

test("a streaming abort records only the first line and cancels the response", async () => {
  const program = corpus.programs.find((entry) => entry.id === "functions-http/http/streaming");
  const step = program.cases.find((entry) => entry.id === "client-disconnect");
  let cancelled = false;
  const fetchImpl = async () =>
    new Response(
      new ReadableStream({
        start(controller) {
          controller.enqueue(new TextEncoder().encode("first\nsecond\n"));
        },
        cancel() {
          cancelled = true;
        },
      }),
      { status: 200, headers: { "content-type": "text/plain" } },
    );
  const result = await runCases(
    { id: program.id, cases: [step] },
    {
      http: "http://127.0.0.1:5001/demo/us-central1/fireemuHttpProbe",
    },
    {},
    createBudget(),
    { fetchImpl },
  );
  assert.deepEqual(result[step.id].body, { firstLine: "first" });
  assert.equal(cancelled, true);
});

test("a case whose target is a spec finds its endpoint by the canonical key", async () => {
  const target = {
    functionName: "cv14DbCreatedV2",
    region: "us-central1",
    codebase: "rtdb-functions-oracle",
    generation: "gcfv2",
  };
  const program = {
    id: "functions-http/x/y",
    cases: [{ ...corpus.programs[0].cases[0], target }],
  };
  const sent = [];
  const fetchImpl = async (url) => {
    sent.push(url);
    return new Response("{}", { status: 200, headers: { "content-type": "application/json" } });
  };
  await runCases(program, { cv14DbCreatedV2: "http://127.0.0.1:1/x" }, {}, createBudget(), {
    fetchImpl,
  });
  assert.equal(sent.length, 1);
  assert.ok(sent[0].startsWith("http://127.0.0.1:1/x"));
  await assert.rejects(
    () => runCases(program, { other: "http://127.0.0.1:1/x" }, {}, createBudget(), { fetchImpl }),
    /no reviewed endpoint/,
  );
});
