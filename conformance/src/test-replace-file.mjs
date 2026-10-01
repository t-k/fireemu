// Replaces a file with another file of the given content, so that the new file has an inode of its
// own on every filesystem: the replacement exists next to the old file before it takes its place.
// Removing a file and writing a new one at the same path does not guarantee that: Linux filesystems
// hand the freed inode to the next file, so a test that means "another inode" would see the same one.
import { renameSync, writeFileSync } from "node:fs";
import { rename, writeFile } from "node:fs/promises";

const sibling = (path) => `${path}.replacement-${process.pid}`;

export function replaceFileSync(path, content, options) {
  const temp = sibling(path);
  writeFileSync(temp, content, options);
  renameSync(temp, path);
}

export async function replaceFile(path, content, options) {
  const temp = sibling(path);
  await writeFile(temp, content, options);
  await rename(temp, path);
}
