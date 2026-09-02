// Callable Cloud Functions rows: the success and error envelopes, and the Auth context a
// callable sees for an anonymous caller, a signed-in caller and a forged credential.

import { randomBytes } from "node:crypto";
import { createServer } from "node:http";

import { signInWithEmailAndPassword } from "firebase/auth";

import { PROJECT, VARIANTS } from "../config.mjs";
import { emailFor } from "./context.mjs";

const openTwoPartyLatch = async () => {
  const token = randomBytes(16).toString("hex");
  const firstReadWaiters = new Map();
  const actionWaiters = new Map();
  const retryObservers = new Set();
  const sockets = new Set();
  const server = createServer((request, response) => {
    request.resume();
    const parts = new URL(request.url, "http://127.0.0.1").pathname.split("/").filter(Boolean);
    if (
      request.method !== "POST" ||
      parts.length !== 3 ||
      parts[1] !== token ||
      (parts[2] !== "0" && parts[2] !== "1")
    ) {
      response.writeHead(404).end();
      return;
    }
    const participant = parts[2];
    if (parts[0] === "arrive") {
      if (firstReadWaiters.has(participant)) {
        response.writeHead(409).end();
        return;
      }
      firstReadWaiters.set(participant, response);
      if (firstReadWaiters.size === 2) {
        const arrivals = [...firstReadWaiters.values()];
        firstReadWaiters.clear();
        for (const arrival of arrivals) arrival.writeHead(204).end();
      }
      return;
    }
    if (parts[0] === "retry-observed") {
      if (retryObservers.has(participant)) {
        response.writeHead(409).end();
        return;
      }
      retryObservers.add(participant);
      response.writeHead(204).end();
      for (const waiter of actionWaiters.values()) waiter.writeHead(204).end();
      actionWaiters.clear();
      return;
    }
    if (parts[0] === "await-retry") {
      if (retryObservers.size > 0) {
        response.writeHead(204).end();
      } else if (actionWaiters.has(participant)) {
        response.writeHead(409).end();
      } else {
        actionWaiters.set(participant, response);
      }
      return;
    }
    response.writeHead(404).end();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    const onError = (error) => reject(error);
    server.once("error", onError);
    server.listen({ host: "127.0.0.1", port: 0 }, () => {
      server.off("error", onError);
      resolve();
    });
  });
  const address = server.address();
  if (address == null || typeof address === "string") throw new Error("latch did not bind a port");
  return {
    port: address.port,
    token,
    async close() {
      for (const response of [...firstReadWaiters.values(), ...actionWaiters.values()]) {
        response.writeHead(503).end();
      }
      firstReadWaiters.clear();
      actionWaiters.clear();
      const closed = new Promise((resolve) => server.close(resolve));
      server.closeAllConnections?.();
      for (const socket of sockets) socket.destroy();
      await closed;
    },
  };
};

const callable = async (ctx, name, data, headers = {}) => {
  const response = await fetch(ctx.functionUrl(name), {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify({ data }),
  });
  const text = await response.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = { nonJsonBodyLength: text.length };
  }
  return { status: response.status, body };
};

const errorEnvelope = {
  id: "functions/callable-error-envelope",
  product: "functions",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "The callable protocol envelope for a result and for every HttpsError code",
  async run(ctx) {
    await ctx.step("result-envelope", () => callable(ctx, "confAdd", { a: 2, b: 3 }));

    await ctx.step("invalid-argument-from-the-handler", () =>
      callable(ctx, "confAdd", { a: "not a number" }),
    );

    for (const code of [
      "permission-denied",
      "unauthenticated",
      "not-found",
      "failed-precondition",
      "resource-exhausted",
      "unavailable",
    ]) {
      // Serial on purpose: the corpus is a recorded sequence, not a load test.
      await ctx.step(`https-error-${code}`, () => callable(ctx, "confThrow", { code }));
    }

    // An uncaught non-HttpsError must collapse to INTERNAL with no handler message.
    await ctx.step("uncaught-error-collapses-to-internal", () => callable(ctx, "confCrash", {}));

    await ctx.step("missing-data-envelope", async () => {
      const response = await fetch(ctx.functionUrl("confAdd"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({}),
      });
      return { status: response.status, body: await response.json() };
    });

    await ctx.step("wrong-content-type", async () => {
      const response = await fetch(ctx.functionUrl("confAdd"), {
        method: "POST",
        headers: { "content-type": "text/plain" },
        body: "not json",
      });
      const text = await response.text();
      return { status: response.status, bodyLength: text.length };
    });

    await ctx.step("get-instead-of-post", async () => {
      const response = await fetch(ctx.functionUrl("confAdd"));
      const text = await response.text();
      return { status: response.status, bodyLength: text.length };
    });

    await ctx.step("unknown-callable", async () => {
      const response = await fetch(ctx.functionUrl("confDefinitelyMissing"), {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ data: {} }),
      });
      const text = await response.text();
      return { status: response.status, bodyLength: text.length };
    });
  },
};

const authContext = {
  id: "functions/callable-auth-context",
  product: "functions",
  variant: VARIANTS.baseline,
  sdks: ["rest", "firebase/auth"],
  title: "The Auth context a callable receives for anonymous, signed-in and forged credentials",
  async run(ctx) {
    await ctx.step("anonymous-caller-has-no-auth-context", () => callable(ctx, "confWhoAmI", {}));

    const email = emailFor("functions-auth", "caller");
    await ctx.step("create-and-sign-in-a-caller", async () => {
      const auth = ctx.shared.liteAuth();
      const signUp = await fetch(
        `http://${ctx.hosts.auth}/identitytoolkit.googleapis.com/v1/accounts:signUp?key=fake-api-key`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email, password: "password123", returnSecureToken: true }),
        },
      );
      const credential = await signInWithEmailAndPassword(auth, email, "password123");
      ctx.shared.scratch.callerIdToken = await credential.user.getIdToken();
      // The callable context echoes the uid back; it is generated and differs per run.
      ctx.redact(credential.user.uid, "<uid>");
      return { signUpStatus: signUp.status, signedIn: credential.user.email === email };
    });

    await ctx.step("signed-in-caller-populates-auth-context", () =>
      callable(
        ctx,
        "confWhoAmI",
        {},
        {
          authorization: `Bearer ${ctx.shared.scratch.callerIdToken}`,
        },
      ),
    );

    await ctx.step("a-forged-bearer-token-is-not-an-identity", () =>
      callable(ctx, "confWhoAmI", {}, { authorization: "Bearer not-a-jwt" }),
    );

    // `Bearer owner` is the privileged emulator credential, never a callable user identity.
    await ctx.step("bearer-owner-is-not-a-callable-identity", () =>
      callable(ctx, "confWhoAmI", {}, { authorization: "Bearer owner" }),
    );

    await ctx.step("an-http-function-sees-the-raw-request", async () => {
      const response = await fetch(`${ctx.functionUrl("confEcho")}/some/path`);
      return { status: response.status, body: await response.json() };
    });
  },
};

// The routing rows below address the functions port directly rather than through
// `ctx.functionUrl`, because the URL under test is the point.
const at = (ctx, path) => `http://${ctx.hosts.functions}${path}`;

const text = async (response) => ({
  status: response.status,
  contentType: response.headers.get("content-type"),
  body: await response.text(),
});

const httpRouting = {
  id: "functions/http-routing-cors-and-timeouts",
  product: "functions",
  variant: VARIANTS.baseline,
  sdks: ["rest"],
  title: "Function URLs, the 404 for an unknown function, CORS preflights and timeoutSeconds",
  async run(ctx) {
    // The route the emulator serves, and the three ways of missing it.
    await ctx.step("unknown-function-names-the-key-and-lists-the-valid-ones", () =>
      fetch(at(ctx, `/${PROJECT}/us-central1/confNotThere`)).then(text),
    );

    await ctx.step("an-existing-function-in-the-wrong-region-is-a-different-key", () =>
      fetch(at(ctx, `/${PROJECT}/europe-west1/confAdd`)).then(text),
    );

    await ctx.step("a-path-under-another-project-is-not-a-function-route", () =>
      fetch(at(ctx, `/demo-somewhere-else/us-central1/confAdd`)).then(text),
    );

    await ctx.step("a-path-with-too-few-segments-is-not-a-function-route", () =>
      fetch(at(ctx, `/confAdd`)).then(text),
    );

    // A function that declares its own region is reachable there, and only there.
    await ctx.step("a-regional-function-answers-at-its-own-region", () =>
      fetch(at(ctx, `/${PROJECT}/europe-west1/confRegional`)).then(text),
    );
    await ctx.step("a-regional-function-is-absent-from-the-default-region", () =>
      fetch(at(ctx, `/${PROJECT}/us-central1/confRegional`)).then(text),
    );

    // Everything after the function name is the path the handler sees, query string included.
    await ctx.step("the-path-and-query-below-the-mount-point-reach-the-handler", () =>
      fetch(at(ctx, `/${PROJECT}/us-central1/confEcho/a/b?x=1&y=2`)).then(text),
    );

    // CORS. The official emulator starts its runtime with
    // FIREBASE_DEBUG_FEATURES={"skipTokenVerification":true,"enableCors":true}, which makes
    // firebase-functions wrap every handler in `cors({origin: true})`. What that produces for
    // a preflight and for a cross-origin POST is what these rows record.
    const preflight = (name, origin) =>
      fetch(at(ctx, `/${PROJECT}/us-central1/${name}`), {
        method: "OPTIONS",
        headers: {
          origin,
          "access-control-request-method": "POST",
          "access-control-request-headers": "content-type",
        },
      }).then(async (response) => ({
        status: response.status,
        allowOrigin: response.headers.get("access-control-allow-origin"),
        allowMethods: response.headers.get("access-control-allow-methods"),
        allowHeaders: response.headers.get("access-control-allow-headers"),
        vary: response.headers.get("vary"),
      }));

    await ctx.step("preflight-on-a-callable-from-a-loopback-origin", () =>
      preflight("confAdd", "http://localhost:3000"),
    );
    await ctx.step("preflight-on-an-onrequest-from-a-loopback-origin", () =>
      preflight("confEcho", "http://localhost:3000"),
    );
    await ctx.step("preflight-on-a-callable-from-a-remote-origin", () =>
      preflight("confAdd", "https://evil.example"),
    );
    await ctx.step("a-cross-origin-post-to-a-callable", () =>
      fetch(at(ctx, `/${PROJECT}/us-central1/confAdd`), {
        method: "POST",
        headers: { "content-type": "application/json", origin: "https://evil.example" },
        body: JSON.stringify({ data: { a: 1, b: 2 } }),
      }).then(async (response) => ({
        status: response.status,
        allowOrigin: response.headers.get("access-control-allow-origin"),
        body: await response.text(),
      })),
    );

    // timeoutSeconds. `confSlow` declares one second and sleeps four.
    await ctx.step("a-function-that-overruns-its-timeout", () =>
      fetch(at(ctx, `/${PROJECT}/us-central1/confSlow`)).then(text),
    );
  },
};

const concurrentConditionalLock = {
  id: "functions/concurrent-conditional-lock",
  product: "functions",
  variant: VARIANTS.baseline,
  sdks: ["firebase-admin", "rest"],
  title: "Concurrent function requests execute one action behind a Firestore transaction lock",
  async run(ctx) {
    const db = ctx.shared.adminFirestore();
    const contextRef = db.doc("conf_fn_lock/context");
    const lockRef = db.doc("conf_fn_lock/lock");
    const actionsRef = db.doc("conf_fn_lock/actions");
    const latch = await openTwoPartyLatch();
    try {
      await ctx.step("seed", async () => {
        await Promise.all([
          contextRef.set({ enabled: true, barrierPort: latch.port, barrierToken: latch.token }),
          lockRef.set({ locked: false }),
          actionsRef.set({ count: 0 }),
        ]);
        return "seeded";
      });
      await ctx.step("only-one-request-passes-the-lock", async () => {
        const responses = await Promise.all(
          [0, 1].map((participant) =>
            fetch(ctx.functionUrl("confConditionalLock"), {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ participant }),
            }).then(async (response) => {
              const responseText = await response.text();
              try {
                return { status: response.status, body: JSON.parse(responseText) };
              } catch {
                return { status: response.status, body: responseText };
              }
            }),
          ),
        );
        const [lock, actions] = await Promise.all([lockRef.get(), actionsRef.get()]);
        return {
          responses: responses
            .map((response) =>
              response.body?.acquired === true
                ? { status: response.status, body: { acquired: true } }
                : response,
            )
            .toSorted((left, right) => left.status - right.status),
          finalLocked: lock.data().locked,
          protectedActions: actions.data().count,
        };
      });
    } finally {
      await latch.close();
    }
  },
};

export const scenarios = [errorEnvelope, authContext, httpRouting, concurrentConditionalLock];
