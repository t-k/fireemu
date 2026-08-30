// The platforms fireemu publishes, and everything that differs between them.
//
// This table is the single source of truth for the release: the workflow matrix, the platform
// package manifests, and the local pack proof all read it. The launcher does not -- it derives
// the package name from `process.platform` / `process.arch` at run time and reads the
// supported list out of its own `optionalDependencies`, so an installed copy can never
// disagree with what was actually published alongside it.
//
// Linux is built against musl and linked statically. A glibc build made on any runner carries
// that runner's glibc floor with it, which silently excludes older distributions and every
// distroless or Alpine container -- and CI containers are where a test-only emulator spends
// most of its life. The cost is musl's slower allocator; for a loopback daemon driven by test
// suites that is a trade worth making, and a glibc variant can be added later as an extra
// platform package without changing the launcher.

/** @typedef {{
 *   name: string,
 *   os: string,
 *   cpu: string,
 *   target: string,
 *   exe: string,
 *   runner: string,
 *   cross: boolean,
 *   notes: string,
 * }} Platform */

/** Every published platform package, keyed by `<node platform>-<node arch>`. @type {Platform[]} */
export const PLATFORMS = [
  {
    name: "darwin-arm64",
    os: "darwin",
    cpu: "arm64",
    target: "aarch64-apple-darwin",
    exe: "",
    runner: "macos-latest",
    cross: false,
    notes: "macOS 13 or newer on Apple silicon.",
  },
  {
    name: "darwin-x64",
    os: "darwin",
    cpu: "x64",
    target: "x86_64-apple-darwin",
    exe: "",
    runner: "macos-latest",
    cross: true,
    notes:
      "macOS 13 or newer on Intel. Cross-compiled from the Apple silicon runner against the " +
      "same universal SDK; its unit tests run on the arm64 host, which builds the same code.",
  },
  {
    name: "linux-x64",
    os: "linux",
    cpu: "x64",
    target: "x86_64-unknown-linux-musl",
    exe: "",
    runner: "ubuntu-latest",
    cross: false,
    notes:
      "Statically linked against musl: any glibc or musl distribution, including distroless and Alpine.",
  },
  {
    name: "linux-arm64",
    os: "linux",
    cpu: "arm64",
    target: "aarch64-unknown-linux-musl",
    exe: "",
    runner: "ubuntu-24.04-arm",
    cross: false,
    notes:
      "Statically linked against musl: any glibc or musl distribution, including distroless and Alpine.",
  },
  {
    name: "win32-x64",
    os: "win32",
    cpu: "x64",
    target: "x86_64-pc-windows-msvc",
    exe: ".exe",
    runner: "windows-latest",
    cross: false,
    notes:
      "Windows 10 or newer, x64. The process-census integration suites are POSIX-only; the unit tests run here.",
  },
];

/** The npm scope the platform packages live in. */
export const SCOPE = "@fireemu";

/** The public package the launcher ships in. */
export const LAUNCHER = "fireemu";

/** The version checked into the repository; a release stamps the tag over it. */
export const DEV_VERSION = "0.0.0-dev";

/** The full package name of a platform, e.g. `@fireemu/darwin-arm64`. */
export const packageName = (platform) => `${SCOPE}/${platform.name}`;

/** The platform this Node process is running on, or `undefined` if it is not published. */
export const hostPlatform = () =>
  PLATFORMS.find((p) => p.os === process.platform && p.cpu === process.arch);

/** Looks a platform up by `<os>-<cpu>` name, throwing with the supported list if unknown. */
export function platformByName(name) {
  const found = PLATFORMS.find((p) => p.name === name);
  if (!found) {
    throw new Error(
      `unknown platform ${name}; supported: ${PLATFORMS.map((p) => p.name).join(", ")}`,
    );
  }
  return found;
}
