import { createConnection } from "node:net";

import { expect, test } from "@playwright/test";

import { PORTS } from "./global-setup";
import { api, controlToken } from "./helpers";

// A raw HTTP/1.1 request over a socket, so a test can set Host and Origin exactly (a browser
// and undici both forbid overriding them). `Connection: close` makes the daemon end the
// connection after the response, so the socket closes and the promise resolves.
const rawConfigRequest = (headerLines: string[]): Promise<{ status: number; body: string }> =>
  new Promise((resolve, reject) => {
    const socket = createConnection({ host: "127.0.0.1", port: PORTS.ui }, () => {
      socket.write(
        ["GET /ui/api/config HTTP/1.1", ...headerLines, "Connection: close", "", ""].join("\r\n"),
      );
    });
    let data = "";
    socket.setTimeout(5000, () => socket.destroy());
    socket.on("data", (chunk) => {
      data += chunk.toString();
    });
    socket.on("close", () => {
      const status = Number(/^HTTP\/1\.\d (\d+)/.exec(data)?.[1] ?? 0);
      const split = data.indexOf("\r\n\r\n");
      resolve({ status, body: split < 0 ? "" : data.slice(split + 4) });
    });
    socket.on("error", reject);
  });

test.describe("security", () => {
  test("the served page ships a Content Security Policy and frame protections", async ({
    request,
  }) => {
    const r = await request.get("/ui/");
    expect(r.ok()).toBeTruthy();
    const csp = r.headers()["content-security-policy"] ?? "";
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(r.headers()["x-frame-options"]).toBe("DENY");
    expect(r.headers()["x-content-type-options"]).toBe("nosniff");
  });

  test("a request whose Host is not loopback is refused (DNS rebinding)", async () => {
    const refused = await rawConfigRequest([
      "Host: attacker.example:14000",
      `Authorization: Bearer ${controlToken()}`,
    ]);
    expect(refused.status).toBe(403);
    expect(refused.body).toContain("FORBIDDEN_HOST");

    // The same request with a loopback Host and the token is admitted, proving the refusal is
    // the Host and nothing else.
    const admitted = await rawConfigRequest([
      `Host: 127.0.0.1:${PORTS.ui}`,
      `Authorization: Bearer ${controlToken()}`,
    ]);
    expect(admitted.status).toBe(200);
  });

  test("a request from a foreign Origin is refused", async () => {
    const refused = await rawConfigRequest([
      `Host: 127.0.0.1:${PORTS.ui}`,
      "Origin: https://evil.example",
      `Authorization: Bearer ${controlToken()}`,
    ]);
    expect(refused.status).toBe(403);
    expect(refused.body).toContain("FORBIDDEN_ORIGIN");
  });

  test("object downloads through the UI are attachments, never inline", async ({ request }) => {
    const config = (await api(request, "GET", "config")) as { project: string };
    const bucket = `${config.project}.appspot.com`;
    // A name that would break a reflected Content-Disposition filename if one existed.
    const name = 'sec/evil";inline.txt';
    const enc = encodeURIComponent(name);
    const token = controlToken();

    const up = await request.fetch(
      `/ui/api/storage/upload/storage/v1/b/${bucket}/o?uploadType=media&name=${enc}`,
      {
        method: "POST",
        headers: { authorization: `Bearer ${token}`, "content-type": "text/plain" },
        data: "hello",
      },
    );
    expect(up.ok(), `${up.status()} ${await up.text()}`).toBeTruthy();

    const down = await request.fetch(
      `/ui/api/storage/download/storage/v1/b/${bucket}/o/${enc}?alt=media`,
      { headers: { authorization: `Bearer ${token}` } },
    );
    expect(down.ok()).toBeTruthy();
    // The front replaces whatever disposition Storage set with a bare attachment: the object
    // name is never reflected into the header and nothing renders inline on this origin.
    expect(down.headers()["content-disposition"]).toBe("attachment");
    expect(down.headers()["x-content-type-options"]).toBe("nosniff");

    await request.fetch(`/ui/api/storage/storage/v1/b/${bucket}/o/${enc}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${token}` },
    });
  });

  test("oversized request bodies are refused (bounded reads)", async ({ request }) => {
    const big = "x".repeat(300 * 1024); // above MAX_JSON_BODY_BYTES (256 KiB)
    const r = await request.fetch("/ui/api/control/v1/rules", {
      method: "PUT",
      headers: { authorization: `Bearer ${controlToken()}`, "content-type": "application/json" },
      data: JSON.stringify({ source: big }),
    });
    expect(r.status()).toBe(413);
  });
});
