import "./record/isolation.mjs";
import assert from "node:assert/strict";
import test from "node:test";

import { answerLayouts, withAnswerLayouts } from "./journal-layout.mjs";

const row = (
  id,
  text,
  contentType = "application/json; charset=UTF-8",
  state = "response-persisted",
) =>
  JSON.stringify({
    id,
    state,
    status: 200,
    contentType,
    bodyBase64: Buffer.from(text).toString("base64"),
    bodyBytes: String(Buffer.byteLength(text)),
  });

test("a journal's step answers are reduced to their layouts", () => {
  const journal = [
    row("identity", '{\n  "projectNumber": "1"\n}\n'),
    row("step-a", '{\n  "name": "n",\n  "view": "BASIC"\n}\n'),
    row("step-b", '{"error":{"code":400}}', "application/json"),
    row("step-a", "second answer is ignored"),
    row("step-c", "{}", "application/json", "response-headers"),
  ].join("\n");
  const layouts = answerLayouts(journal);
  assert.deepEqual(Object.keys(layouts), ["a", "b"]);
  assert.deepEqual(layouts.a, {
    contentType: "application/json; charset=UTF-8",
    style: "indent2-newline",
    keyOrder: { "": ["name", "view"] },
    bytes: 37,
  });
  assert.equal(layouts.b.style, "compact");
  assert.equal(layouts.b.contentType, "application/json");
  assert.ok(!JSON.stringify(layouts).includes("BASIC"), "no answer text is kept");
});

test("a body that is not whole is refused", () => {
  const broken = JSON.stringify({
    id: "step-a",
    state: "response-persisted",
    contentType: "t",
    bodyBase64: Buffer.from("{}").toString("base64"),
    bodyBytes: "99",
  });
  assert.throws(() => answerLayouts(broken), /not whole/);
});

test("each answer of a result gets its layout, and a missing or different one is refused", () => {
  const layouts = answerLayouts(row("step-a", "{}\n"));
  const result = {
    judged: { cases: { a: { answer: { status: 200, bodyBytes: 3 } }, none: { answer: null } } },
  };
  withAnswerLayouts(result, layouts);
  assert.deepEqual(result.judged.cases.a.answer.layout, {
    contentType: "application/json; charset=UTF-8",
    style: "indent2-newline",
    keyOrder: { "": [] },
  });
  assert.equal("bytes" in result.judged.cases.a.answer.layout, false);
  assert.throws(
    () =>
      withAnswerLayouts(
        { judged: { cases: { x: { answer: { status: 200, bodyBytes: 3 } } } } },
        layouts,
      ),
    /no journal answer for x/,
  );
  assert.throws(
    () =>
      withAnswerLayouts(
        { judged: { cases: { a: { answer: { status: 200, bodyBytes: 4 } } } } },
        layouts,
      ),
    /differs/,
  );
});
