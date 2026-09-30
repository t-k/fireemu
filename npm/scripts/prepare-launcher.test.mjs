// Tests for the launcher package preparation: the npm package page is generated from the
// repository README rather than kept as a second copy.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { npmReadme, prepareLauncher, readmeRef, repositoryWebUrl } from "./prepare-launcher.mjs";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO = "https://github.com/t-k/fireemu";
const directories = new Set(["tools/bench", "docs"]);
const pathKind = (path) =>
  path === "missing.md" ? undefined : directories.has(path.replace(/\/$/, "")) ? "directory" : "file";
const render = (markdown, ref = "v1.2.3") => npmReadme(markdown, { repository: REPO, ref, pathKind });
const body = (markdown) => render(markdown).split("\n").slice(2).join("\n");

test("relative file links point at the file on GitHub at the release tag", () => {
  assert.equal(
    body("See the [schema](spec/config/fireemu.schema.json)."),
    `See the [schema](${REPO}/blob/v1.2.3/spec/config/fireemu.schema.json).`,
  );
  assert.equal(body("[notes](./CHANGELOG.md)"), `[notes](${REPO}/blob/v1.2.3/CHANGELOG.md)`);
});

test("relative directory links use the tree view", () => {
  assert.equal(body("[bench](tools/bench/)"), `[bench](${REPO}/tree/v1.2.3/tools/bench/)`);
  assert.equal(body("[docs](docs)"), `[docs](${REPO}/tree/v1.2.3/docs)`);
});

test("a fragment on a relative link is kept", () => {
  assert.equal(
    body("[CC-06](docs/compatibility-contract.md#checks)"),
    `[CC-06](${REPO}/blob/v1.2.3/docs/compatibility-contract.md#checks)`,
  );
});

test("absolute URLs, in-page anchors and mailto links are left unchanged", () => {
  for (const link of [
    "[site](https://firebase.google.com/docs)",
    "[here](#quick-start)",
    "[mail](mailto:someone@example.com)",
    "[proto](//example.com/x)",
  ]) {
    assert.equal(body(link), link);
  }
});

test("relative images point at the raw file at the release tag", () => {
  assert.equal(
    body("![logo](docs/logo.png)"),
    "![logo](https://raw.githubusercontent.com/t-k/fireemu/v1.2.3/docs/logo.png)",
  );
});

test("reference-style link definitions are rewritten too", () => {
  assert.equal(body("[contract]: docs/compatibility-contract.md"), `[contract]: ${REPO}/blob/v1.2.3/docs/compatibility-contract.md`);
  assert.equal(body("[site]: https://example.com"), "[site]: https://example.com");
});

test("a link with a title keeps the title", () => {
  assert.equal(
    body('[license](LICENSE "Apache 2.0")'),
    `[license](${REPO}/blob/v1.2.3/LICENSE "Apache 2.0")`,
  );
});

test("text inside fenced code blocks and inline code is not rewritten", () => {
  const fenced = "```sh\necho [a](docs/x.md)\n```";
  assert.equal(body(fenced), fenced);
  const tilde = "~~~\n[a](docs/x.md)\n~~~";
  assert.equal(body(tilde), tilde);
  assert.equal(body("Use `[a](docs/x.md)` literally."), "Use `[a](docs/x.md)` literally.");
});

test("a code span inside a link's text does not stop the link from being rewritten", () => {
  assert.equal(body("[`tools/bench/`](tools/bench/)"), `[\`tools/bench/\`](${REPO}/tree/v1.2.3/tools/bench/)`);
  assert.equal(body("`[a](docs/x.md)` then [b](LICENSE)"), `\`[a](docs/x.md)\` then [b](${REPO}/blob/v1.2.3/LICENSE)`);
});

test("a link to a path the repository does not have is refused", () => {
  assert.throws(() => render("[gone](missing.md)"), /names no file in the repository: missing\.md/);
  assert.throws(() => render("![gone](missing.md)"), /names no file/);
  assert.throws(() => render("[gone]: missing.md"), /names no file/);
});

test("a link that leaves the repository is refused", () => {
  assert.throws(() => render("[up](../outside.md)"), /leaves the repository/);
  assert.throws(() => render("[up](docs/../../outside.md)"), /leaves the repository/);
});

test("the generated page starts with a notice naming its source", () => {
  const [first, second] = render("# Fireemu").split("\n");
  assert.match(first, /^<!-- Generated from README\.md by npm\/scripts\/prepare-launcher\.mjs/);
  assert.equal(second, "");
});

test("the generated page has no relative link left and is otherwise the README", () => {
  const readme = readFileSync(join(repoRoot, "README.md"), "utf8");
  const page = npmReadme(readme, { repository: REPO, ref: "v9.9.9", root: repoRoot });
  const text = page.split("\n").slice(2).join("\n");
  const outsideCode = text.replace(/```[\s\S]*?```/g, "").replace(/`[^`\n]*`/g, "");
  for (const [, target] of outsideCode.matchAll(/\]\(([^)\s]+)/g)) {
    assert.match(target, /^(https?:|#|mailto:)/, `relative link left: ${target}`);
  }
  const undo = text.replaceAll(`${REPO}/blob/v9.9.9/`, "").replaceAll(`${REPO}/tree/v9.9.9/`, "");
  assert.equal(undo, readme);
  // Raw HTML links are not rewritten, so the README must not use relative ones.
  for (const [, target] of outsideCode.matchAll(/\b(?:href|src)\s*=\s*["']([^"']+)["']/gi)) {
    assert.match(target, /^(https?:|#|mailto:)/, `relative HTML link: ${target}`);
  }
});

test("every link the generated page makes points at a tracked path of the right kind", () => {
  const readme = readFileSync(join(repoRoot, "README.md"), "utf8");
  const page = npmReadme(readme, { repository: REPO, ref: "v9.9.9", root: repoRoot });
  const tracked = execFileSync("git", ["-C", repoRoot, "ls-files", "-z"], { encoding: "utf8" }).split("\0");
  const files = new Set(tracked);
  const prefixes = new Set(tracked.flatMap((file) => file.split("/").slice(0, -1).map((_, i, parts) => parts.slice(0, i + 1).join("/"))));
  const links = [...page.matchAll(new RegExp(`${REPO}/(blob|tree)/v9\\.9\\.9/([^)#\\s]+)`, "g"))];
  assert.ok(links.length > 0);
  for (const [, kind, path] of links) {
    const clean = path.replace(/\/$/, "");
    if (kind === "blob") assert.ok(files.has(clean), `blob link to an untracked file: ${path}`);
    else assert.ok(prefixes.has(clean), `tree link to an untracked directory: ${path}`);
  }
});

test("the ref is the release tag, or main for an unstamped development package", () => {
  assert.equal(readmeRef("1.2.3"), "v1.2.3");
  assert.equal(readmeRef("0.0.0-dev"), "main");
});

test("the repository URL comes from the package manifest", () => {
  assert.equal(repositoryWebUrl({ repository: { url: "git+https://github.com/t-k/fireemu.git" } }), REPO);
  assert.equal(repositoryWebUrl({ repository: "https://github.com/t-k/fireemu" }), REPO);
  assert.throws(() => repositoryWebUrl({}), /repository/);
});

test("prepareLauncher writes the generated page, the license and the notices", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-launcher-readme-"));
  try {
    mkdirSync(join(root, "npm", "fireemu"), { recursive: true });
    mkdirSync(join(root, "docs"), { recursive: true });
    writeFileSync(join(root, "README.md"), "# Fireemu\n\nSee [docs](docs) and [license](LICENSE).\n");
    writeFileSync(join(root, "LICENSE"), "project license\n");
    writeFileSync(join(root, "THIRD_PARTY_LICENSES.txt"), "third-party notices\n");
    writeFileSync(
      join(root, "npm", "fireemu", "package.json"),
      JSON.stringify({ version: "2.0.0", repository: { url: "git+https://github.com/t-k/fireemu.git" } }),
    );

    prepareLauncher(root);

    const page = readFileSync(join(root, "npm", "fireemu", "README.md"), "utf8");
    assert.match(page, /See \[docs\]\(https:\/\/github\.com\/t-k\/fireemu\/tree\/v2\.0\.0\/docs\)/);
    assert.match(page, /\[license\]\(https:\/\/github\.com\/t-k\/fireemu\/blob\/v2\.0\.0\/LICENSE\)/);
    assert.equal(readFileSync(join(root, "npm", "fireemu", "LICENSE"), "utf8"), "project license\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prepareLauncher refuses a README link to a file the repository lacks", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-launcher-deadlink-"));
  try {
    mkdirSync(join(root, "npm", "fireemu"), { recursive: true });
    writeFileSync(join(root, "README.md"), "See [notes](docs/notes.md).\n");
    writeFileSync(join(root, "LICENSE"), "x\n");
    writeFileSync(join(root, "THIRD_PARTY_LICENSES.txt"), "x\n");
    writeFileSync(join(root, "npm", "fireemu", "package.json"), JSON.stringify({ version: "1.0.0", repository: REPO }));
    assert.throws(() => prepareLauncher(root), /names no file in the repository: docs\/notes\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("prepareLauncher fails when the repository README is missing", () => {
  const root = mkdtempSync(join(tmpdir(), "fireemu-launcher-noreadme-"));
  try {
    mkdirSync(join(root, "npm", "fireemu"), { recursive: true });
    writeFileSync(join(root, "LICENSE"), "x\n");
    writeFileSync(join(root, "THIRD_PARTY_LICENSES.txt"), "x\n");
    writeFileSync(join(root, "npm", "fireemu", "package.json"), JSON.stringify({ version: "1.0.0", repository: REPO }));
    assert.throws(() => prepareLauncher(root), /README\.md/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("the old hand-kept npm page no longer exists", () => {
  assert.throws(() => readFileSync(join(repoRoot, "npm", "README.md")), /ENOENT/);
});
