// The SDK path of the production dependencies, driven against the real SDK code with the network
// replaced: which request `getSignedUrl` really makes, and that it passes the guard, is counted by
// the observer's meter and goes through the lock lease. `File#exists()` is not driven here: the SDK
// sends it through its own HTTP client, outside the guard, so the observer reads existence from its
// metered metadata GET instead (the SDK's exists() is that same GET).

import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import { describe, it } from "node:test";

import { createProductionDeps, installEgressGuard } from "./storage-signed-put/deps.mjs";
import { classifyRequest } from "./storage-signed-put/guard.mjs";
import { UnknownAnswer } from "./storage-signed-put/observe.mjs";
import { BUCKET, PROJECT, SIGNER, runPrefix } from "./storage-signed-put/plan.mjs";

// No test here may reach a network: any outbound http(s) request or fetch throws.
installEgressGuard([]);
globalThis.fetch = () => {
  throw new Error("fetch is not allowed in this test");
};

const RUN = "sp-0123abcd";
const target = { name: "production", bucket: BUCKET, project: PROJECT, signer: SIGNER };
const NAME = `${runPrefix(RUN)}rec1/ok.png`;

function harness(respond) {
  const sent = [];
  const metered = [];
  const events = [];
  const lease = {
    verifyHeld: async () => events.push("verify"),
    dispatch: async (work) => {
      events.push("dispatch");
      try {
        return await work();
      } catch (error) {
        events.push("dispatch-failed");
        throw error;
      }
    },
  };
  const meter = {
    request: (label, request) => {
      classifyRequest(target, request, runPrefix(RUN));
      metered.push({ label, method: request.method, url: request.url });
    },
    after: (label, status) => {
      metered.push({ label, status });
      if (status >= 500 || !Number.isInteger(status)) throw new UnknownAnswer(label, status);
    },
  };
  const deps = createProductionDeps({
    accessToken: "synthetic-token",
    lease,
    transport: async (options) => {
      sent.push(options);
      return respond(options);
    },
  });
  return { deps, sent, metered, events, meter };
}

const signBlobAnswer = (options) => {
  assert.match(String(options.url), /:signBlob$/);
  return {
    status: 200,
    data: { keyId: "k", signedBlob: Buffer.from("ab".repeat(8), "hex").toString("base64") },
  };
};

describe("production dependencies: SDK paths", () => {
  it("signs with one signBlob request as the signer, with retries off, through the meter and the lease", async () => {
    const { deps, sent, metered, events, meter } = harness(signBlobAnswer);
    try {
      const now = Date.now();
      const url = await deps.sign(
        { name: NAME, contentType: "image/png", range: "0,10485760", expires: now + 300_000 },
        meter,
      );
      assert.equal(sent.length, 1);
      assert.equal(sent[0].method, "POST");
      assert.equal(
        String(sent[0].url),
        `https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/${SIGNER}:signBlob`,
      );
      assert.equal(sent[0].retry, false);
      assert.deepEqual(
        metered.map((m) => m.label),
        ["signBlob", "signBlob"],
      );
      assert.equal(metered[1].status, 200);
      assert.deepEqual(events, ["verify", "dispatch"]);
      const parsed = new URL(url);
      assert.equal(parsed.origin, "https://storage.googleapis.com");
      assert.equal(parsed.pathname, `/${BUCKET}/${NAME}`);
      assert.equal(parsed.searchParams.get("X-Goog-Algorithm"), "GOOG4-RSA-SHA256");
      assert.equal(
        parsed.searchParams.get("X-Goog-SignedHeaders"),
        "content-type;host;x-goog-content-length-range",
      );
      assert.match(
        parsed.searchParams.get("X-Goog-Credential"),
        new RegExp(`^${SIGNER.replace(/\./g, "\\.")}/\\d{8}/auto/storage/goog4_request$`),
      );
      assert.equal(parsed.searchParams.get("X-Goog-Signature"), "ab".repeat(8));
      assert.equal(parsed.searchParams.get("X-Goog-Expires"), "300");
      classifyRequest(target, { method: "PUT", url }, runPrefix(RUN));
    } finally {
      await deps.close();
    }
  });

  it("signs the shortest lifetime the SDK allows: accessibleAt on a whole second, one second later", async () => {
    const { deps, meter } = harness(signBlobAnswer);
    try {
      const accessibleAt = Math.floor(Date.now() / 1000) * 1000;
      const url = await deps.sign(
        {
          name: NAME,
          contentType: "image/png",
          range: null,
          expires: accessibleAt + 1000,
          accessibleAt,
        },
        meter,
      );
      const parsed = new URL(url);
      assert.equal(parsed.searchParams.get("X-Goog-Expires"), "1");
      assert.equal(parsed.searchParams.get("X-Goog-SignedHeaders"), "content-type;host");
      assert.match(parsed.searchParams.get("X-Goog-Date"), /^\d{8}T\d{6}Z$/);
    } finally {
      await deps.close();
    }
  });

  it("omits the content type from the signature when the case signs none", async () => {
    const { deps, meter } = harness(signBlobAnswer);
    try {
      const url = await deps.sign(
        { name: NAME, contentType: null, range: null, expires: Date.now() + 60_000 },
        meter,
      );
      assert.equal(new URL(url).searchParams.get("X-Goog-SignedHeaders"), "host");
    } finally {
      await deps.close();
    }
  });

  it("refuses an SDK request made outside an observer step", async () => {
    const { deps } = harness(signBlobAnswer);
    try {
      await assert.rejects(
        deps.sign(
          { name: NAME, contentType: "image/png", range: null, expires: Date.now() + 60_000 },
          null,
        ),
      );
    } finally {
      await deps.close();
    }
  });

  it("turns a 5xx or a transport failure from signBlob into an unknown answer that fails the lease", async () => {
    for (const failure of [503, "socket"]) {
      const { deps, events, meter } = harness(() => {
        const error = new Error("boom");
        if (failure !== "socket") {
          error.response = { status: failure, data: {}, headers: {}, config: { data: {} } };
        }
        throw error;
      });
      try {
        await assert.rejects(
          deps.sign(
            { name: NAME, contentType: "image/png", range: null, expires: Date.now() + 60_000 },
            meter,
          ),
          // The SDK wraps the error as a SigningError and keeps its message.
          (error) => /unknown answer: signBlob|boom/.test(error.message),
        );
        assert.ok(events.includes("dispatch-failed"), String(failure));
      } finally {
        await deps.close();
      }
    }
  });

  it("keeps a definitive 403 from signBlob as an answer, not a failed dispatch", async () => {
    const { deps, metered, events, meter } = harness(() => {
      const error = new Error("The caller does not have permission");
      error.response = {
        status: 403,
        data: { error: { status: "PERMISSION_DENIED" } },
        headers: {},
        config: { data: {} },
      };
      throw error;
    });
    try {
      await assert.rejects(
        deps.sign(
          { name: NAME, contentType: "image/png", range: null, expires: Date.now() + 60_000 },
          meter,
        ),
        /permission/,
      );
      assert.equal(metered.at(-1).status, 403);
      assert.ok(!events.includes("dispatch-failed"));
    } finally {
      await deps.close();
    }
  });

  it("refuses an http(s) request to any host once the egress guard is installed", () => {
    assert.throws(() => https.request("https://storage.googleapis.com/"), /egress refused/);
    assert.throws(
      () => http.get({ hostname: "metadata.google.internal", path: "/" }),
      /egress refused/,
    );
  });
});
