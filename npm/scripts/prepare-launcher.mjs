#!/usr/bin/env node
// Puts the files the `fireemu` package publishes but does not own into `npm/fireemu/`.
//
//   node npm/scripts/prepare-launcher.mjs
//
// The package page is generated from the repository README (`README.md`), so there is one
// text to maintain. Relative links in it are rewritten to absolute GitHub URLs at the release
// tag (the npm page cannot resolve them), and a notice at the top names the source. The license
// files are copied as they are. All three generated copies are ignored by git; `npm pack` needs
// them on disk because `files` names them. Run it after `stamp-version.mjs`, so the links point
// at the tag of the version being packed; an unstamped development package links to `main`.

import { copyFileSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const DEV_VERSION = "0.0.0-dev";
const NOTICE =
  "<!-- Generated from README.md by npm/scripts/prepare-launcher.mjs at pack time. Edit README.md in the repository, not this file. -->";

/** The GitHub web URL of the repository a package manifest names. */
export function repositoryWebUrl(manifest) {
  const raw = typeof manifest.repository === "string" ? manifest.repository : manifest.repository?.url;
  if (typeof raw !== "string" || raw === "") throw new Error("package.json names no repository");
  const url = raw.replace(/^git\+/, "").replace(/\.git$/, "").replace(/\/$/, "");
  if (!/^https:\/\/github\.com\/[^/]+\/[^/]+$/.test(url)) {
    throw new Error(`package.json repository is not a GitHub URL: ${raw}`);
  }
  return url;
}

/** The git ref the page links to: the release tag, or `main` for an unstamped package. */
export function readmeRef(version) {
  return version === DEV_VERSION ? "main" : `v${version}`;
}

// A scheme or a protocol-relative URL; an in-page anchor is handled by its empty path below.
const ABSOLUTE = /^(?:[a-z][a-z0-9+.-]*:|\/\/)/i;

/** Rewrites one link target; absolute targets, anchors and scheme links are returned unchanged. */
function rewriteTarget(target, { repository, ref, pathKind, image }) {
  if (ABSOLUTE.test(target)) return target;
  const hash = target.indexOf("#");
  const path = hash === -1 ? target : target.slice(0, hash);
  const fragment = hash === -1 ? "" : target.slice(hash);
  if (path === "") return target;
  // normalize drops a leading ./ and keeps a trailing /, which marks a directory link.
  const clean = posix.normalize(path);
  if (clean === ".." || clean.startsWith("../") || path.startsWith("/")) {
    throw new Error(`README link leaves the repository: ${target}`);
  }
  // A link to a missing file would publish a dead link on the package page.
  const kind = pathKind(clean);
  if (kind === undefined) throw new Error(`README link names no file in the repository: ${target}`);
  if (image) {
    const [, owner, name] = repository.match(/^https:\/\/github\.com\/([^/]+)\/([^/]+)$/);
    return `https://raw.githubusercontent.com/${owner}/${name}/${ref}/${clean}${fragment}`;
  }
  return `${repository}/${kind === "directory" ? "tree" : "blob"}/${ref}/${clean}${fragment}`;
}

/** Rewrites the links of one line of prose, leaving inline code spans alone. */
function rewriteLine(line, options) {
  const definition = line.match(/^( {0,3}\[[^\]]+\]:\s*)(\S+)(.*)$/);
  if (definition) {
    return definition[1] + rewriteTarget(definition[2], { ...options, image: false }) + definition[3];
  }
  // Code spans that stand on their own are literal text; a code span inside a link's text is not.
  const spans = [...line.matchAll(/`+[^`]*`+/g)].map((match) => [match.index, match.index + match[0].length]);
  const insideSpan = (offset) => spans.some(([start, end]) => offset >= start && offset < end);
  return line.replace(
    /(!?)\[((?:[^\]`]|`[^`]*`)*)\]\(([^)\s]+)((?:\s+"[^"]*")?)\)/g,
    (whole, bang, text, target, title, offset) =>
      insideSpan(offset)
        ? whole
        : `${bang}[${text}](${rewriteTarget(target, { ...options, image: bang === "!" })}${title})`,
  );
}

/**
 * The npm package page for a README: a notice line, a blank line, then the README with every
 * relative link made absolute at `ref`. Fenced code blocks are copied unchanged. `pathKind`
 * answers "file", "directory" or undefined for a repository path; by default it looks under
 * `root`, and a link to a path it does not know is refused.
 */
export function npmReadme(markdown, { repository, ref, root, pathKind }) {
  const kindOf =
    pathKind ??
    ((path) => {
      try {
        return statSync(join(root, path)).isDirectory() ? "directory" : "file";
      } catch {
        return undefined;
      }
    });
  const options = { repository, ref, pathKind: kindOf };
  let fence = null;
  const lines = markdown.split("\n").map((line) => {
    const marker = line.match(/^ {0,3}(`{3,}|~{3,})/);
    if (fence) {
      if (marker && marker[1][0] === fence[0] && marker[1].length >= fence.length) fence = null;
      return line;
    }
    if (marker) {
      fence = marker[1];
      return line;
    }
    return rewriteLine(line, options);
  });
  return `${NOTICE}\n\n${lines.join("\n")}`;
}

/** Writes the package page and copies the license files into the launcher package. */
export function prepareLauncher(root = repoRoot) {
  const launcher = join(root, "npm", "fireemu");
  const manifest = JSON.parse(readFileSync(join(launcher, "package.json"), "utf8"));
  let readme;
  try {
    readme = readFileSync(join(root, "README.md"), "utf8");
  } catch (error) {
    throw new Error(`cannot read the repository README.md: ${error.message}`);
  }
  const page = npmReadme(readme, {
    repository: repositoryWebUrl(manifest),
    ref: readmeRef(manifest.version),
    root,
  });
  const written = [join(launcher, "README.md")];
  writeFileSync(written[0], page);
  for (const name of ["LICENSE", "THIRD_PARTY_LICENSES.txt"]) {
    copyFileSync(join(root, name), join(launcher, name));
    written.push(join(launcher, name));
  }
  return written;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const path of prepareLauncher()) process.stdout.write(`${path}\n`);
}
