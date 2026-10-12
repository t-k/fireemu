// Descriptive replay mode for the emulator profile (closure criterion "emulator-official").
//
// The strict replay drivers stop at the first point where the local server does not behave like
// the recorded production run (for example "native terminal witness mismatch"). That is the right
// gate for the strict profile, which follows production. The emulator profile reproduces the
// official emulator instead, so the same assertions describe expected differences rather than
// harness failures. In descriptive mode a failing replay step is recorded as a difference and the
// replay continues with the next source row, so every applicable row is still executed.
//
// The mode is explicit and only exists for the emulator profile: creating it for any other
// profile is refused, and the strict code paths never construct it.

export const DESCRIPTIVE_MODE = "descriptive";
export const DESCRIPTIVE_PROFILE = "emulator";
export const MAX_DIFFERENCE_MESSAGE_BYTES = 2048;
export const MAX_DIFFERENCES = 100_000;

// Assertions that bind the local run to the recorded production behaviour. When one of them
// fails in the emulator profile, the local server answered differently from production at a point
// where the strict harness demands equality.
const PRODUCTION_BINDING_ASSERTIONS = [
  /^native terminal witness mismatch$/,
  /^native half-close witness missing$/,
  /^native receive (semantic|cardinality) mismatch$/,
  /^native receive timestamp presence or structure mismatch$/,
  /^native publication timestamp mismatch$/,
  /^native expected receive missing$/,
  /^native actual outbound semantic mismatch$/,
  /^native outbound update receipt missing or mismatched$/,
  /^native actual receive (timestamp missing|violated quiet interval|observation ended before expiry)$/,
  /^native recorded quiet interval violated$/,
  /^native silence window incomplete$/,
  /^native invalid ACK observation incomplete$/,
  /^native ACK slot (requires an actual live receive|already live)$/,
  /^native unordered owned (receive missing or duplicate|multiset or live ACK slots incomplete)$/,
  /^unproven live ACK correlation$/,
  /^missing or conflicting [a-z]+ binding$/,
  /^own issued continuation unavailable$/,
  /^local issuer unavailable$/,
  /^missing supplemental dispatch$/,
];
const HARNESS_CRASH_NAMES = new Set(["TypeError", "ReferenceError", "RangeError", "SyntaxError"]);
const LOCAL_RUNTIME_FAILURES =
  /fetch failed|ECONNREFUSED|ECONNRESET|EPIPE|socket hang up|local clock advance refused/;

// Bounded, printable copy of an error message (C0 controls, DEL and lone surrogates are replaced).
export function boundedMessage(value) {
  let text = typeof value === "string" ? value : String(value);
  text = text.replace(/[\u0000-\u001f\u007f]/g, "�").toWellFormed();
  if (Buffer.byteLength(text) <= MAX_DIFFERENCE_MESSAGE_BYTES) return text;
  let cut = text.slice(0, MAX_DIFFERENCE_MESSAGE_BYTES);
  while (Buffer.byteLength(cut) > MAX_DIFFERENCE_MESSAGE_BYTES - 3) cut = cut.slice(0, -1);
  return `${cut.toWellFormed()}...`;
}

export function classifyDifference(error) {
  const name = typeof error?.name === "string" ? error.name : "Error";
  const message = typeof error?.message === "string" ? error.message : String(error);
  if (HARNESS_CRASH_NAMES.has(name)) return "harness-crash";
  if (PRODUCTION_BINDING_ASSERTIONS.some((pattern) => pattern.test(message)))
    return "production-binding-assertion";
  if (LOCAL_RUNTIME_FAILURES.test(message)) return "local-runtime-failure";
  return "unclassified-harness-assertion";
}

function plainContext(context) {
  const result = {};
  for (const key of [
    "phase",
    "sourceN",
    "sourceEvent",
    "cellId",
    "method",
    "transport",
    "direction",
  ]) {
    const value = context?.[key];
    if (value === undefined) continue;
    if (value !== null && !["string", "number"].includes(typeof value))
      throw new Error("descriptive context field must be a string, number or null");
    result[key] = typeof value === "string" ? boundedMessage(value) : value;
  }
  return result;
}

export function createDescriptiveDifferences({ profile, mode } = {}) {
  if (mode !== DESCRIPTIVE_MODE) throw new Error("descriptive replay mode required");
  if (profile !== DESCRIPTIVE_PROFILE)
    throw new Error("descriptive replay mode requires the emulator profile");
  const entries = [];
  const cellsWithDifferences = new Set();
  function record(context, error, evidence) {
    if (entries.length >= MAX_DIFFERENCES) throw new Error("descriptive difference bound");
    const where = plainContext(context);
    const cellId = where.cellId ?? null;
    const entry = {
      ordinal: entries.length + 1,
      ...where,
      errorName: boundedMessage(typeof error?.name === "string" ? error.name : "Error"),
      message: boundedMessage(typeof error?.message === "string" ? error.message : String(error)),
      classification: classifyDifference(error),
      followsEarlierDifferenceInCell: cellId !== null && cellsWithDifferences.has(cellId),
    };
    if (evidence) {
      try {
        const value = evidence();
        if (value !== undefined) entry.evidence = structuredClone(value);
      } catch (evidenceError) {
        entry.evidenceUnavailable = boundedMessage(evidenceError?.message ?? evidenceError);
      }
    }
    if (cellId !== null) cellsWithDifferences.add(cellId);
    entries.push(entry);
    return entry;
  }
  return {
    mode: DESCRIPTIVE_MODE,
    profile: DESCRIPTIVE_PROFILE,
    entries,
    record,
    // Runs one replay step. A failure is recorded and returned; success returns null.
    async attempt(context, step, evidence) {
      try {
        await step();
        return null;
      } catch (error) {
        return record(context, error, evidence);
      }
    },
    summary() {
      const byClassification = {};
      for (const entry of entries)
        byClassification[entry.classification] = (byClassification[entry.classification] ?? 0) + 1;
      return {
        mode: DESCRIPTIVE_MODE,
        profile: DESCRIPTIVE_PROFILE,
        gate: false,
        basis:
          "emulator-profile replay; production remains the oracle and every difference is descriptive, not a verdict",
        differences: entries.length,
        primaryDifferences: entries.filter((entry) => !entry.followsEarlierDifferenceInCell).length,
        byClassification,
        entries: structuredClone(entries),
      };
    },
  };
}

// Selects the mode for a replay worker: null without the flag; otherwise the flag must be
// "descriptive" and the pinned launch config (read with the caller's pinned reader) must carry the
// emulator profile.
export function selectDescriptiveMode(mode, launch, readPinned) {
  if (mode === undefined) return null;
  if (mode !== DESCRIPTIVE_MODE) throw new Error("replay mode refused");
  if (!launch || typeof launch.config !== "string" || typeof launch.configSha256 !== "string")
    throw new Error("descriptive replay launch config required");
  const config = JSON.parse(readPinned(launch.config, launch.configSha256));
  return createDescriptiveDifferences({ profile: config?.profile, mode });
}
