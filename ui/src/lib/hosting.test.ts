import { describe, expect, it } from "vitest";
import { redirectTarget, rewriteTarget, ruleHeaders, ruleMatcher } from "./hosting";

describe("ruleMatcher", () => {
  it.each([
    [{ source: "/a/**" }, { kind: "glob", pattern: "/a/**" }],
    [
      { glob: "/g", source: "/s" },
      { kind: "glob", pattern: "/g" },
    ],
    [
      { glob: "", source: "/s" },
      { kind: "glob", pattern: "/s" },
    ],
    [
      { source: "", regex: "^/a$" },
      { kind: "regex", pattern: "^/a$" },
    ],
    [
      { source: "/s", regex: "^/a$" },
      { kind: "glob", pattern: "/s" },
    ],
    [{ regex: "^/a$" }, { kind: "regex", pattern: "^/a$" }],
    [{ source: "", regex: "" }, { kind: "none" }],
    [{ source: 3, regex: null }, { kind: "none" }],
    [{}, { kind: "none" }],
  ])("%j", (rule, expected) => {
    expect(ruleMatcher(rule)).toEqual(expected);
  });
});

describe("rewriteTarget", () => {
  it.each([
    [{ destination: "/index.html" }, { kind: "file", destination: "/index.html" }],
    [
      { destination: "/x.html", function: "api" },
      { kind: "file", destination: "/x.html" },
    ],
    [{ function: "api" }, { kind: "function", id: "api", region: "us-central1" }],
    [
      { function: { functionId: "api", region: "europe-west1", pinTag: true } },
      { kind: "function", id: "api", region: "europe-west1" },
    ],
    [{ function: {} }, { kind: "function", id: "", region: "us-central1" }],
    [{ function: 3 }, { kind: "function", id: "", region: "us-central1" }],
    [{ function: null }, { kind: "function", id: "", region: "us-central1" }],
    [{ run: null }, { kind: "run", id: "", region: "us-central1" }],
    [
      { run: { serviceId: "web", region: "us-central1" } },
      { kind: "run", id: "web", region: "us-central1" },
    ],
    [{ run: "web" }, { kind: "run", id: "web", region: "us-central1" }],
    // The rule's own region applies when the target names none (hosting.rs `proxy`).
    [
      { source: "/api/**", function: "api", region: "europe-west1" },
      { kind: "function", id: "api", region: "europe-west1" },
    ],
    [
      { function: { functionId: "api" }, region: "asia-east1" },
      { kind: "function", id: "api", region: "asia-east1" },
    ],
    [
      { run: { serviceId: "web" }, region: "europe-west4" },
      { kind: "run", id: "web", region: "europe-west4" },
    ],
    // The target's region wins over the rule's.
    [
      { function: { functionId: "api", region: "us-east1" }, region: "europe-west1" },
      { kind: "function", id: "api", region: "us-east1" },
    ],
    // A present target region that is no string still wins, leaving the default.
    [
      { function: { functionId: "api", region: 7 }, region: "europe-west1" },
      { kind: "function", id: "api", region: "us-central1" },
    ],
    [
      { function: { functionId: "api", region: null }, region: "europe-west1" },
      { kind: "function", id: "api", region: "us-central1" },
    ],
    // A rule region that is no string leaves the default; an array target has no region key.
    [
      { function: "api", region: 3 },
      { kind: "function", id: "api", region: "us-central1" },
    ],
    [
      { function: ["x"], region: "europe-west1" },
      { kind: "function", id: "", region: "europe-west1" },
    ],
    [
      { function: "f", run: { serviceId: "r" } },
      { kind: "function", id: "f", region: "us-central1" },
    ],
    [
      { destination: "", run: { serviceId: "r" } },
      { kind: "run", id: "r", region: "us-central1" },
    ],
    [{ dynamicLinks: true }, { kind: "none" }],
    [{}, { kind: "none" }],
  ])("%j", (rule, expected) => {
    expect(rewriteTarget(rule)).toEqual(expected);
  });
});

describe("redirectTarget", () => {
  it.each([
    [
      { destination: "/new", type: 302 },
      { destination: "/new", status: 302 },
    ],
    [{ destination: "/new" }, { destination: "/new", status: 301 }],
    [
      { destination: "/new", type: "302" },
      { destination: "/new", status: 301 },
    ],
    [
      { destination: "/new", type: 301.5 },
      { destination: "/new", status: 301 },
    ],
    [{}, { destination: "", status: 301 }],
  ])("%j", (rule, expected) => {
    expect(redirectTarget(rule)).toEqual(expected);
  });
});

describe("ruleHeaders", () => {
  it("keeps string pairs in order and skips every other entry", () => {
    expect(
      ruleHeaders({
        headers: [
          { key: "A", value: "1" },
          { key: "B" },
          { value: "x" },
          { key: "C", value: 3 },
          null,
          "D: 4",
          { key: "E", value: "" },
        ],
      }),
    ).toEqual([
      { key: "A", value: "1" },
      { key: "E", value: "" },
    ]);
  });
  it("is empty for a rule without a list", () => {
    expect(ruleHeaders({})).toEqual([]);
    expect(ruleHeaders({ headers: "A: 1" })).toEqual([]);
  });
});
