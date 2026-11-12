// The layout of every answer of a recording, read from the recorder's private journal (which holds each response's content type and
// raw bytes) and reduced to what is published: the content type, the style and the order of the fields. No text is kept.
import { layoutOfAnswer } from "./project.mjs";

const STEP = "step-";

/** `{ [case key]: layout }` from the journal's JSON lines; a step answered twice keeps its first answer. */
export function answerLayouts(journalText) {
  const layouts = {};
  for (const line of journalText.split("\n")) {
    if (!line) continue;
    const row = JSON.parse(line);
    if (row.state !== "response-persisted" || !String(row.id).startsWith(STEP)) continue;
    const key = row.id.slice(STEP.length);
    if (key in layouts) continue;
    const text = Buffer.from(row.bodyBase64 ?? "", "base64").toString("utf8");
    if (Buffer.byteLength(text) !== Number(row.bodyBytes))
      throw new Error(`the journal's body of ${row.id} is not whole`);
    layouts[key] = { ...layoutOfAnswer(text, row.contentType), bytes: Number(row.bodyBytes) };
  }
  return layouts;
}

/** Puts each case's layout on its answer; a case with an answer and no layout is refused. */
export function withAnswerLayouts(result, layouts) {
  for (const [key, record] of Object.entries(result.judged.cases)) {
    if (!record.answer) continue;
    const layout = layouts[key];
    if (!layout) throw new Error(`no journal answer for ${key}`);
    if (record.answer.bodyBytes !== layout.bytes)
      throw new Error(`the journal's body of ${key} differs from the result's`);
    const { bytes: _bytes, ...published } = layout;
    record.answer.layout = published;
  }
  return result;
}
