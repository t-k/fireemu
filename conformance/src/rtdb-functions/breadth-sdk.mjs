import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LAUNCH } from "../../../tools/sdk-smoke-database/cv11-genuine-auth.mjs";

export function createSdk({
  page,
  config,
  email,
  password,
  uid,
  nonce,
  ids = ["w10", "w11", "w12"],
}) {
  let state = "initial";
  const done = new Set();
  return {
    async signIn() {
      if (state !== "initial") throw Error("sign in unavailable");
      state = "stopped";
      let result;
      try {
        result = await page.evaluate((arg) => window.__breadth(arg), {
          action: "signIn",
          config,
          email,
          password,
          uid,
        });
      } catch {
        throw Error("sign in rejected");
      }
      if (result?.outcome !== "ok") throw Error("sign in rejected");
      state = "ready";
      return result;
    },
    async write(id) {
      if (state !== "ready" || !ids.includes(id) || done.has(id)) throw Error("write unavailable");
      done.add(id);
      state = "stopped";
      try {
        const result = await page.evaluate((arg) => window.__breadth(arg), { action: id, nonce });
        if (result?.outcome !== "ok") throw Error("write rejected");
        state = "ready";
        return result;
      } catch {
        throw Error("write rejected");
      }
    },
  };
}

export function browserRunner({
  modules,
  allowHost,
  budget = { take() {} },
  stop = {},
  pageFile,
  ids,
  caps = { http: 40, ws: 4 },
}) {
  const require = createRequire(path.resolve(modules, "x.js"));
  const { chromium } = require("playwright");
  return async (config, credentials, observe) => {
    const server = createServer((req, res) => {
      const script = req.url === "/page.js";
      res.writeHead(200, { "content-type": script ? "text/javascript" : "text/html" });
      res.end(
        script
          ? readFileSync(
              pageFile ?? fileURLToPath(new URL("./breadth-sdk-page.js", import.meta.url)),
            )
          : '<!doctype html><script type="module" src="/page.js"></script>',
      );
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    let browser;
    const counts = { http: 0, ws: 0, blocked: 0 };
    try {
      const origin = `127.0.0.1:${server.address().port}`;
      browser = await chromium.launch(LAUNCH);
      stop.closeBrowser = () => browser.close().catch(() => {});
      const context = await browser.newContext();
      if (config.emulator)
        await context
          .grantPermissions(["local-network-access"], { origin: `http://${origin}` })
          .catch(() => {});
      const page = await context.newPage();
      let exceeded = false;
      await page.route("**/*", (route) => {
        const url = new URL(route.request().url());
        if (url.host === origin) return route.continue();
        if (url.host === "www.gstatic.com" && url.pathname.startsWith("/firebasejs/12.18.0/"))
          return route.fulfill({
            contentType: "text/javascript",
            body: readFileSync(path.resolve(modules, "firebase", path.basename(url.pathname))),
          });
        if (!allowHost(url.host)) {
          counts.blocked++;
          return route.abort();
        }
        if (++counts.http > caps.http) {
          exceeded = true;
          return route.abort();
        }
        try {
          budget.take("browserHttp");
        } catch {
          exceeded = true;
          return route.abort();
        }
        return route.continue();
      });
      // Observed, never routed: the harness keeps Playwright out of the WebSocket path.
      page.on("websocket", (ws) => {
        let refused = !allowHost(new URL(ws.url()).host) || ++counts.ws > caps.ws;
        if (!refused) {
          try {
            budget.take("browserWs");
          } catch {
            refused = true;
          }
        }
        if (refused) {
          exceeded = true;
          void page.close();
        }
      });
      await page.goto(`http://${origin}/`);
      await page.waitForFunction(() => typeof window.__breadth === "function");
      const sdk = createSdk({ page, config, ids, ...credentials });
      await sdk.signIn();
      if (exceeded) throw Error("browser request cap reached");
      await observe({
        write: async (id) => {
          if (exceeded || stop.requested) throw Error("browser stopped");
          const result = await sdk.write(id);
          if (exceeded) throw Error("browser request cap reached");
          return result;
        },
      });
      return { counts };
    } finally {
      delete stop.closeBrowser;
      try {
        if (browser) await browser.close();
      } finally {
        await new Promise((resolve) => server.close(resolve));
      }
    }
  };
}

export function openSdk(runner, config, credentialsFn) {
  let running,
    ready,
    finish,
    closing = false;
  return {
    async write(id) {
      if (closing) throw Error("SDK stopped");
      if (!running) {
        ready = new Promise((resolve, reject) => {
          running = Promise.resolve()
            .then(() =>
              runner(config, credentialsFn(), async ({ write }) => {
                resolve(write);
                await new Promise((done) => {
                  finish = done;
                });
              }),
            )
            .then(
              () => {
                if (!closing) throw Error("SDK runner ended");
              },
              (error) => {
                reject(error);
                throw error;
              },
            );
          running.catch(() => {});
        });
      }
      const write = await Promise.race([ready, running]);
      let timer;
      try {
        return await Promise.race([
          write(id),
          running,
          new Promise((resolve) => {
            timer = setTimeout(() => {
              closing = true;
              resolve({ outcome: "unknown" });
            }, 60000);
          }),
        ]);
      } finally {
        clearTimeout(timer);
      }
    },
    async close() {
      if (!running) return;
      closing = true;
      if (finish) finish();
      else await Promise.race([ready.then(() => finish()), running]);
      await running;
    },
  };
}
