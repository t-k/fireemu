// Field proofs from two recordings; arbitrary message data and user maps remain exact.
import { isDeepStrictEqual } from "node:util";

const coordinate = (row) => JSON.stringify([row.case, row.step, row.op, row.transport]);
const read = (object, path) => path.reduce((value, key) => value?.[key], object);
const timeShape = (value) =>
  typeof value === "string" &&
  /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}\+00:00$/.test(value) &&
  Number.isFinite(Date.parse(value))
    ? { type: "RFC3339", width: 29, precision: 3, zone: "+00:00" }
    : null;

export function createFieldNormalization(capture, peer) {
  const starts = [capture, peer].map((rows) => rows.filter((row) => row.note === "run-start"));
  if (
    starts.some(
      (rows) =>
        rows.length !== 1 ||
        rows[0].suite !== "stream-dlq-v2" ||
        !/^[a-f0-9]{12}$/.test(rows[0].runId),
    ) ||
    starts[0][0].runId === starts[1][0].runId
  )
    throw new Error("two distinct recorded run identities required for normalization");
  const runs = starts.map((rows) => rows[0].runId);
  const policies = new Map();
  const evidence = [];
  const messages = ["receivedMessages", 0, "message"];
  for (const row of capture.filter((r) => r.request && r.response)) {
    const matches = peer.filter(
      (r) => r.request && r.response && coordinate(r) === coordinate(row),
    );
    if (matches.length !== 1) continue;
    const other = matches[0];
    const streaming = row.case === "stream-invalid-deadline/grpc" && row.op === "streamingPull";
    const rest =
      ["dlq-no-grant/rest", "dlq-grant-window/rest", "rest-layout-routes/rest"].includes(
        row.case,
      ) &&
      row.op === "pull" &&
      row.transport === "rest";
    if (!streaming && !rest) continue;
    const bodies = streaming
      ? [capture, peer]
          .map((rows, index) =>
            rows.filter(
              (f) =>
                f.note === "stream-frame" &&
                f.direction === "in" &&
                f.case === [row, other][index].case &&
                f.step === [row, other][index].step,
            ),
          )
          .map((frames) => (frames.length === 1 ? frames[0].body : null))
      : [row.response.body, other.response.body];
    if (rest && [row, other].some((r) => r.response.status !== 200 || r.response.unknown)) continue;
    const rules = [];
    const add = (path, classify) => {
      const values = bodies.map((body) => read(body, path));
      const shapes = values.map((value, index) => classify(value, runs[index], index));
      if (values[0] === values[1] || !shapes[0] || !isDeepStrictEqual(shapes[0], shapes[1])) return;
      rules.push({ path, classify, shape: shapes[0] });
      evidence.push({
        case: row.case,
        step: row.step,
        path: `/${path.join("/")}`,
        shape: shapes[0],
        sources: [row, other].map((r, i) => ({ runId: runs[i], n: r.n })),
      });
    };
    const prefix = streaming
      ? "stream-deadline-"
      : row.case === "rest-layout-routes/rest"
        ? "layout-"
        : "dlq-";
    const suffix = prefix === "dlq-" ? "-identity" : "";
    const published = [capture, peer].map((rows, index) =>
      rows.some(
        (r) =>
          (r.case === row.case || (streaming && r.case === `${row.case}/rest`)) &&
          r.op === "publish" &&
          r.response?.status === 200 &&
          r.response.unknown !== true &&
          r.request?.body?.messages?.some(
            (m) => m.data === Buffer.from(`${prefix}${runs[index]}${suffix}`).toString("base64"),
          ),
      ),
    );
    if (published.every(Boolean)) {
      add([...messages, "data"], (value, run) => {
        const text = `${prefix}${run}${suffix}`;
        return value === Buffer.from(text).toString("base64")
          ? {
              type: "base64",
              width: value.length,
              decodedWidth: Buffer.byteLength(text),
              padding: value.match(/=*$/)[0].length,
              template: `${prefix}<hex12>${suffix}`,
            }
          : null;
      });
      add([...messages, "attributes", "recorderRun"], (value, run) =>
        value === run ? { type: "lowercase-hex", width: 12, binding: "producer-run" } : null,
      );
    }
    if (row.case === "dlq-grant-window/rest") {
      add(
        [...messages, "attributes", "CloudPubSubDeadLetterSourceSubscription"],
        (value, run, index) => {
          const name = `fe${run}-da-r-source`;
          return value === name &&
            [capture, peer][index].some(
              (r) =>
                r.op === "pull" &&
                r.request?.path ===
                  `/v1/projects/${starts[index][0].project}/subscriptions/${name}:pull`,
            )
            ? { type: "resource-segment", width: 26, template: "fe<hex12>-da-r-source" }
            : null;
        },
      );
      add(
        [...messages, "attributes", "CloudPubSubDeadLetterSourceTopicPublishTime"],
        (value, _run, index) => {
          const shape = timeShape(value);
          return shape &&
            [capture, peer][index].some(
              (r) =>
                r.case === row.case &&
                r.op === "pull" &&
                r.response?.body?.receivedMessages?.some(
                  (m) =>
                    typeof m.message?.publishTime === "string" &&
                    m.message.publishTime.replace(/Z$/, "+00:00") === value,
                ),
            )
            ? shape
            : null;
        },
      );
    }
    if (rules.length) policies.set(coordinate(row), rules);
  }
  return {
    evidence,
    normalize(body, row) {
      const value = structuredClone(body);
      for (const rule of policies.get(coordinate(row)) ?? []) {
        const original = read(value, rule.path);
        // Run-bound classifiers reject values from a third run or a changed producer template.
        const valid =
          rule.shape.type === "RFC3339"
            ? isDeepStrictEqual(timeShape(original), rule.shape)
            : runs.some((run) =>
                isDeepStrictEqual(rule.classify(original, run, runs.indexOf(run)), rule.shape),
              );
        if (!valid) continue;
        const parent = read(value, rule.path.slice(0, -1));
        parent[rule.path.at(-1)] = { observedValue: "normalized", shape: rule.shape };
      }
      return value;
    },
  };
}
