// What the object probes (probe-v3, probe-v4) share: the request as the lean wire takes it, one
// exchange that records every answer and never judges one, and the cleanup that does not read any
// answer of the recording (fixed names, a metadata read, a delete, an absence read, and a final
// list that decides the closing row and lists what is left so it can be removed by name).

import { emptyList } from "./probe.mjs";

export const OWNER = "Bearer owner";
export const GENERATION = /^[1-9][0-9]{0,19}$/;
export const EXTRA_DELETES = 10;

export const firstLine = (error) =>
  String(error?.message ?? error)
    .split("\n")[0]
    .slice(0, 200);

export const parse = (text) => {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

const bytesOf = (body) => {
  if (body?.base64 !== undefined) return Buffer.from(body.base64, "base64");
  if (body?.json !== undefined) return JSON.stringify(body.json);
  return undefined;
};

/** A corpus step as the placeholder URL and init the lean wire takes. */
export function requestOf(step, origins, { query, href } = {}) {
  let target = href;
  if (target === undefined) {
    const url = new URL(step.path, origins.storage);
    for (const [key, value] of Object.entries(query ?? step.query ?? {}))
      url.searchParams.set(key, value);
    target = url.href;
  }
  const body = bytesOf(step.body);
  return {
    href: target,
    init: {
      method: step.method,
      headers: { ...step.headers, authorization: OWNER },
      ...(body === undefined ? {} : { body }),
    },
  };
}

/**
 * The record of one run and its one way of sending. `exchange` resolves with `{ status, text,
 * headers }`, or `null` when the wire's route table refused the request before sending it (recorded
 * as skipped); any other failure is thrown, tagged with the step and what was answered so far.
 */
export function createExchange({ wire, origins }) {
  const answers = [];
  const stop = (error, id) => {
    error.probeStep = id;
    error.answered = answers;
    return error;
  };
  async function exchange(id, { href, init }) {
    let response;
    let text;
    try {
      response = await wire.fetch(href, init);
      text = await response.text();
    } catch (error) {
      if (error?.routeRefused === true) {
        answers.push({ id, skipped: firstLine(error) });
        return null;
      }
      throw stop(error, id);
    }
    answers.push({ id, status: response.status });
    return { status: response.status, text, headers: response.headers };
  }
  const skip = (id, reason) => answers.push({ id, skipped: reason });
  const placeholders = Object.values(origins);
  const sessionUrl = (result, header) => {
    if (!result || result.status >= 300) return null;
    const url = result.headers.get(header);
    return typeof url === "string" && placeholders.some((origin) => url.startsWith(`${origin}/`))
      ? url
      : null;
  };
  return { answers, exchange, skip, sessionUrl };
}

/** A GCS JSON request on one object, with the owner credential. */
export function gcsObjectRequest({ bucket, origins }, method, name, query = {}) {
  const url = new URL(`/storage/v1/b/${bucket}/o/${encodeURIComponent(name)}`, origins.storage);
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  return { href: url.href, init: { method, headers: { authorization: OWNER } } };
}

/**
 * Remove every fixed name and read the prefix. For each name: a metadata read; nothing more if it
 * is absent; otherwise a delete (on the generation the read gave, or by name when it gave none),
 * then an absence read. The last list of the prefix decides the closing row; what it still holds
 * under the prefix (at most ten names) is removed by name and the list is read once more.
 * `plan` has `bucket`, `scope` and `objects`.
 */
export async function cleanUpAndList({ exchange, answers, plan, origins }) {
  const request = (method, name, query) =>
    gcsObjectRequest({ bucket: plan.bucket, origins }, method, name, query);
  for (const [index, name] of plan.objects.entries()) {
    const metadata = await exchange(`cleanup-metadata-${index}`, request("GET", name));
    if (metadata === null) continue;
    if (metadata.status === 404) continue;
    const generation = parse(metadata.text)?.generation;
    const conditional = metadata.status === 200 && GENERATION.test(generation ?? "");
    await exchange(
      `cleanup-delete-${index}`,
      request("DELETE", name, conditional ? { ifGenerationMatch: generation } : {}),
    );
    await exchange(`cleanup-absent-${index}`, request("GET", name));
  }
  const finalList = async (id) => {
    const url = new URL(`/storage/v1/b/${plan.bucket}/o`, origins.storage);
    url.searchParams.set("prefix", plan.scope);
    url.searchParams.set("maxResults", "1000");
    const result = await exchange(id, {
      href: url.href,
      init: { method: "GET", headers: { authorization: OWNER } },
    });
    if (result === null) return null;
    const row = answers.at(-1);
    row.prefixEmpty = emptyList(result.status, result.text);
    return result;
  };
  const first = await finalList("final-list");
  if (first !== null && answers.at(-1).prefixEmpty !== true) {
    const items = parse(first.text)?.items;
    const left = (Array.isArray(items) ? items : [])
      .map((item) => item?.name)
      .filter((name) => typeof name === "string" && name.startsWith(plan.scope))
      .slice(0, EXTRA_DELETES);
    if (left.length > 0) {
      for (const [index, name] of left.entries())
        await exchange(`cleanup-extra-delete-${index}`, request("DELETE", name));
      await finalList("final-list-again");
    }
  }
}

/** The list row the closing row is decided on: the last one of the run. */
export function finalListRow(answers) {
  return answers.findLast((row) => row.id.startsWith("final-list"));
}
