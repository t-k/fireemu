// Runs long-polling-page.js in headless Chromium (Playwright 1.62.1) against one server and
// returns the page's events. The page is served from a loopback origin, so Chromium lets it
// reach the loopback emulator, and the SDK bundles are the ones in node_modules/firebase,
// served in place of www.gstatic.com: nothing leaves the machine.

import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const bundles = path.join(here, 'node_modules', 'firebase');

export async function longPolling(hostPort, suffix) {
  const server = createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname === '/') {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<!doctype html><html><body><script type="module" src="/page.js"></script></body></html>');
      return;
    }
    res.writeHead(200, { 'content-type': 'text/javascript' });
    res.end(readFileSync(path.join(here, 'long-polling-page.js'), 'utf8'));
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `127.0.0.1:${server.address().port}`;
  const browser = await chromium.launch({ headless: true });
  const transport = [];
  try {
    const page = await browser.newPage();
    page.on('pageerror', (e) => transport.push(['pageerror', String(e)]));
    await page.route('**/*', async (route) => {
      const url = new URL(route.request().url());
      if (url.host === origin || url.host === hostPort) return route.continue();
      if (url.host === 'www.gstatic.com' && url.pathname.startsWith('/firebasejs/12.18.0/')) {
        return route.fulfill({
          contentType: 'text/javascript',
          body: readFileSync(path.join(bundles, path.basename(url.pathname)), 'utf8'),
        });
      }
      return route.abort();
    });
    page.on('request', (request) => {
      const url = new URL(request.url());
      if (url.host === hostPort) transport.push(['request', url.pathname]);
    });
    await page.goto(`http://${origin}/?emu=${hostPort}&suffix=${suffix}`);
    await page.waitForFunction(() => window.__result !== undefined, null, { timeout: 120000 });
    const result = await page.evaluate(() => window.__result);
    const paths = new Set(transport.filter((t) => t[0] === 'request').map((t) => t[1]));
    return { events: result, transports: [...paths].sort(), errors: transport.filter((t) => t[0] === 'pageerror') };
  } finally {
    await browser.close();
    server.close();
  }
}
