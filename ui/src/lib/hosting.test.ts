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
    [{ function: "api" }, { kind: "function", id: "api", region: null }],
    [
      { function: { functionId: "api", region: "europe-west1", pinTag: true } },
      { kind: "function", id: "api", region: "europe-west1" },
    ],
    [{ function: {} }, { kind: "function", id: "", region: null }],
    [{ function: 3 }, { kind: "function", id: "", region: null }],
    [{ function: null }, { kind: "function", id: "", region: null }],
    [{ run: null }, { kind: "run", id: "", region: null }],
    [
      { run: { serviceId: "web", region: "us-central1" } },
      { kind: "run", id: "web", region: "us-central1" },
    ],
    [{ run: "web" }, { kind: "run", id: "web", region: null }],
    [
      { function: "f", run: { serviceId: "r" } },
      { kind: "function", id: "f", region: null },
    ],
    [
      { destination: "", run: { serviceId: "r" } },
      { kind: "run", id: "r", region: null },
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
