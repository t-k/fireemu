import {
  openSync,
  closeSync,
  writeFileSync,
  fsyncSync,
  readFileSync,
  readdirSync,
  existsSync,
} from "node:fs";
import { resolve } from "node:path";
import { createHash } from "node:crypto";

export function obligations(ledger, names, intents = []) {
  const scope = new Set([...names, ...intents.map((item) => item.name)]);
  return [...scope].flatMap((name) => {
    const requests = ledger.state().get(name)?.requests ?? [];
    const pending = requests.filter(
      (request) => !["rejected", "gone", "gone-a2"].includes(request.resolution),
    );
    const additions = intents.filter((item) => item.name === name);
    if (!pending.length && !additions.length) return [];
    return [
      {
        name,
        requests: pending.map(({ id, action, transport, kind, answered, resolution }) => ({
          id,
          action,
          transport,
          kind,
          answered,
          resolution,
        })),
        intents: additions,
      },
    ];
  });
}
export function checkpoint(journal, ledger, names, cellId, intents = [], iam = []) {
  journal.recovery?.({ cellId, obligations: obligations(ledger, names, intents), iam });
}

// Reporting and disposal are inside the protection; neither can bypass cleanup or its checkpoint.
export async function protectCell({ body, report, dispose, finalize, persist }) {
  const failures = [];
  try {
    try {
      await body();
    } catch (error) {
      failures.push(error);
      try {
        await report(error);
      } catch (failure) {
        failures.push(failure);
      }
    }
  } finally {
    try {
      await dispose?.();
    } catch (error) {
      failures.push(error);
    }
    try {
      await finalize();
    } catch (error) {
      failures.finalizationFailed = true;
      failures.push(error);
    }
    try {
      await persist();
    } catch (error) {
      failures.persistenceFailed = true;
      failures.push(error);
    }
  }
  return failures;
}

// This channel never invokes the primary capture writer or its sanitization/row budget.
export function createRecoveryJournal(out, runId) {
  const fd = openSync(resolve(out, `recovery-${runId}.jsonl`), "wx", 0o600);
  let sequence = 0,
    bytes = 0,
    closed = false;
  return {
    write(value) {
      if (closed) throw new Error("closed recovery journal");
      const line = `${JSON.stringify({ schema: 1, runId, sequence: ++sequence, ...value })}\n`;
      bytes += Buffer.byteLength(line);
      if (sequence > 10000 || bytes > 8 * 1024 * 1024) throw new Error("recovery journal bound");
      writeFileSync(fd, line);
      fsyncSync(fd);
    },
    close() {
      if (!closed) {
        closed = true;
        closeSync(fd);
      }
    },
  };
}

// Invoke before a coordinator writes the started ledger row. This function never writes a ledger.
export function unusedRunPreflight({ runId, out, ledgerPath, runsRoot }) {
  if (!/^[a-f0-9]{12}$/.test(runId)) throw new Error("invalid run nonce");
  const bytes = readFileSync(ledgerPath);
  if (bytes.length > 64 * 1024 * 1024) throw new Error("preflight ledger bound");
  if (bytes.toString("utf8").includes(runId)) throw new Error("run nonce already in ledger");
  const entries = readdirSync(runsRoot);
  if (entries.length > 4096) throw new Error("preflight directory bound");
  if (
    entries.some((name) => name.includes(runId)) ||
    (existsSync(out) && readdirSync(out).length !== 0)
  )
    throw new Error("run directory already used");
  return {
    schema: 1,
    runId,
    checkedAt: new Date().toISOString(),
    ledgerSha256: createHash("sha256").update(bytes).digest("hex"),
    ledgerBytes: bytes.length,
    runDirectory: resolve(out),
    runsRoot: resolve(runsRoot),
    directoryEntries: entries.length,
    unused: true,
  };
}

export function acquireResources(acquire) {
  const closers = [];
  try {
    return acquire((close) => closers.push(close));
  } catch (error) {
    for (const close of closers.reverse())
      try {
        close();
      } catch {
        /* Preserve the acquisition failure. */
      }
    throw error;
  }
}
