// Exact semantic JSON shapes observed in the single capture-only REST bootstrap, not closure evidence.
import { isDeepStrictEqual } from "node:util";

export function classifyBootstrapShape({ kind, status, body, resource, topic, labels }) {
  const unknown = { shape: "unknown-shape" };
  let expected;
  const resourceMatch =
    typeof resource === "string"
      ? /^projects\/[^/]+\/(topics|subscriptions)\/([^/]+)$/.exec(resource)
      : null;
  switch (kind) {
    case "empty":
      if (status !== 200) return unknown;
      expected = {};
      break;
    case "missing":
      if (status !== 404 || !resourceMatch) return unknown;
      expected = {
        error: {
          code: 404,
          message: `Resource not found (resource=${resourceMatch[2]}).`,
          status: "NOT_FOUND",
        },
      };
      break;
    case "topic":
      if (
        status !== 200 ||
        resourceMatch?.[1] !== "topics" ||
        !labels ||
        Object.getPrototypeOf(labels) !== Object.prototype ||
        Object.values(labels).some((value) => typeof value !== "string")
      )
        return unknown;
      expected = { name: resource, labels };
      break;
    case "subscription":
      if (
        status !== 200 ||
        resourceMatch?.[1] !== "subscriptions" ||
        typeof topic !== "string" ||
        !/^projects\/[^/]+\/topics\/[^/]+$/.test(topic)
      )
        return unknown;
      expected = {
        name: resource,
        topic,
        pushConfig: {},
        ackDeadlineSeconds: 60,
        messageRetentionDuration: "604800s",
        expirationPolicy: { ttl: "2678400s" },
        state: "ACTIVE",
      };
      break;
    default:
      return unknown;
  }
  return isDeepStrictEqual(body, expected) ? { shape: "recorded-bootstrap-shape" } : unknown;
}
