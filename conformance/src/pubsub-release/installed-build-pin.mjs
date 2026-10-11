import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");
function readFile(file, maxBytes, resolveInstalled = false) {
  const stat = resolveInstalled ? fs.statSync(file) : fs.lstatSync(file);
  if (!stat.isFile()) throw new Error("regular file required");
  if (stat.size > maxBytes) throw new Error("file size exceeds runtime bound");
  const bytes = fs.readFileSync(file);
  if (bytes.length > maxBytes) throw new Error("file size exceeds runtime bound");
  return bytes;
}

export function stageInstalledBuildPin({ binaryPath, buildPinPath, buildPinSha256, out }) {
  if (
    typeof out !== "string" ||
    !path.isAbsolute(out) ||
    path.normalize(out) !== out ||
    path.dirname(out) === out ||
    fs.realpathSync(path.dirname(out)) !== path.dirname(out)
  ) {
    throw new Error("unsafe destination");
  }
  const originalBytes = readFile(buildPinPath, 1_000_000);
  if (digest(originalBytes) !== buildPinSha256) throw new Error("build pin digest mismatch");
  const pin = JSON.parse(originalBytes);
  const bytes = readFile(binaryPath, 100_000_000, true);
  if (digest(bytes) !== pin.sha256) throw new Error("installed binary digest mismatch");
  let inputBytes;
  if (pin.binaryInputsPath !== undefined || pin.binaryInputsSha256 !== undefined) {
    inputBytes = readFile(pin.binaryInputsPath, 10_000_000);
    if (digest(inputBytes) !== pin.binaryInputsSha256)
      throw new Error("binary inputs digest mismatch");
  }
  fs.mkdirSync(out);
  fs.mkdirSync(path.join(out, "release"));
  const stagedPath = path.join(out, "release", "fireemu");
  fs.writeFileSync(stagedPath, bytes, { flag: "wx", mode: 0o755 });
  const stagedInputsPath = path.join(out, "binary-inputs.json");
  if (inputBytes) fs.writeFileSync(stagedInputsPath, inputBytes, { flag: "wx", mode: 0o600 });
  const stagedPin = Buffer.from(
    `${JSON.stringify(
      { ...pin, path: stagedPath, ...(inputBytes ? { binaryInputsPath: stagedInputsPath } : {}) },
      null,
      2,
    )}\n`,
  );
  const stagedPinPath = path.join(out, "build-pin.json");
  fs.writeFileSync(stagedPinPath, stagedPin, { flag: "wx", mode: 0o600 });
  return { buildPinPath: stagedPinPath, buildPinSha256: digest(stagedPin) };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { values } = parseArgs({
      options: {
        bin: { type: "string" },
        "build-pin": { type: "string" },
        "build-pin-sha256": { type: "string" },
        out: { type: "string" },
      },
    });
    if (Object.values(values).length !== 4)
      throw new Error("bin, build-pin, build-pin-sha256 and out required");
    console.log(
      JSON.stringify(
        stageInstalledBuildPin({
          binaryPath: values.bin,
          buildPinPath: values["build-pin"],
          buildPinSha256: values["build-pin-sha256"],
          out: values.out,
        }),
      ),
    );
  } catch (error) {
    console.error(error.message);
    process.exitCode = 1;
  }
}
