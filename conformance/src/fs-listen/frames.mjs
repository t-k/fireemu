// How a native Listen frame becomes a row (FS-LISTEN-SDK, packet L1). A row keeps what the frame
// says and drops what only the clock, the run or the credential decide: resume tokens (whether one
// came is kept), read times, heartbeats, the run id, the project and the index link.

/** A Firestore `Value` as plain JSON (the shapes the Listen programs write). */
export function decodeValue(value) {
  if (value === null || typeof value !== "object") return null;
  if ("nullValue" in value) return null;
  if ("booleanValue" in value) return value.booleanValue;
  if ("integerValue" in value) return Number(value.integerValue);
  if ("doubleValue" in value) return value.doubleValue;
  if ("stringValue" in value) return value.stringValue;
  if ("arrayValue" in value) return (value.arrayValue.values ?? []).map(decodeValue);
  if ("mapValue" in value) {
    // The server's member order is not stable between runs: sort it (by UTF-16 code units).
    const fields = value.mapValue.fields ?? {};
    return Object.fromEntries(
      Object.keys(fields)
        .toSorted()
        .map((key) => [key, decodeValue(fields[key])]),
    );
  }
  if ("timestampValue" in value) return "<timestamp>";
  if ("referenceValue" in value) return "<reference>";
  return "<unsupported>";
}

/** A message with the project, the run and the composite-index key replaced by placeholders. */
export function maskText(text, { project, run }) {
  return String(text ?? "")
    .replaceAll(project, "{project}")
    .replaceAll(run, "{run}")
    .replace(/create_composite=[A-Za-z0-9_%\-=.]+/g, "create_composite=<index>");
}

const isGlobalNoChange = (change) =>
  (change.targetChangeType ?? "NO_CHANGE") === "NO_CHANGE" && (change.targetIds ?? []).length === 0;

/**
 * The rows of a frame list. `names` maps a full document name to the program's logical name; a
 * name outside it is `<other>`, never printed. A run of global NO_CHANGE frames (the boundaries at
 * which a client raises its snapshot, and the heartbeats between them) counts once.
 */
export function frameRows(frames, { names, project, run }) {
  const logical = (name) => names.get(name) ?? "<other>";
  const rows = [];
  for (const frame of frames) {
    switch (frame.kind) {
      case "targetChange": {
        const change = frame.targetChange ?? {};
        if (isGlobalNoChange(change)) {
          const token = Boolean(change.resumeToken);
          // A run counts once, and says that a token came if any frame of the run carried one.
          if (rows.at(-1)?.kind === "boundary") rows.at(-1).resumeToken ||= token;
          else rows.push({ kind: "boundary", resumeToken: token });
          break;
        }
        rows.push({
          kind: "targetChange",
          type: change.targetChangeType ?? "NO_CHANGE",
          targetIds: (change.targetIds ?? []).toSorted((a, b) => a - b),
          cause: change.cause
            ? { code: change.cause.code, message: maskText(change.cause.message, { project, run }) }
            : null,
          resumeToken: Boolean(change.resumeToken),
        });
        break;
      }
      case "documentChange": {
        const change = frame.documentChange ?? {};
        rows.push({
          kind: "documentChange",
          doc: logical(change.document?.name),
          fields: decodeValue({ mapValue: { fields: change.document?.fields ?? {} } }),
          targetIds: change.targetIds ?? [],
          removedTargetIds: change.removedTargetIds ?? [],
        });
        break;
      }
      case "documentDelete":
      case "documentRemove": {
        const change = frame[frame.kind] ?? {};
        rows.push({
          kind: frame.kind,
          doc: logical(change.document),
          removedTargetIds: change.removedTargetIds ?? [],
        });
        break;
      }
      case "filter": {
        const filter = frame.filter ?? {};
        const bloom = filter.unchangedNames;
        rows.push({
          kind: "filter",
          targetId: filter.targetId,
          count: filter.count,
          unchangedNames: bloom
            ? {
                hashCount: bloom.hashCount,
                bitmapBytes: Buffer.from(bloom.bits?.bitmap ?? []).length,
                padding: bloom.bits?.padding ?? 0,
              }
            : null,
        });
        break;
      }
      default:
        rows.push({ kind: String(frame.kind) });
    }
  }
  return rows;
}

/**
 * How a stretch of frames groups the document changes: the changes between two boundaries are one
 * group (a client raises one snapshot for it). Each group lists its documents in arrival order and
 * says whether the documents share one update time, which a single Commit gives them.
 */
export function commitGroups(frames, { names }) {
  const groups = [];
  let open = null;
  const close = () => {
    if (open) groups.push(open);
    open = null;
  };
  for (const frame of frames) {
    if (frame.kind === "documentChange") {
      const { document } = frame.documentChange ?? {};
      open ??= { docs: [], updateTimes: new Set() };
      open.docs.push(names.get(document?.name) ?? "<other>");
      const time = document?.updateTime;
      open.updateTimes.add(time ? `${time.seconds}.${time.nanos ?? 0}` : "none");
    } else if (
      frame.kind === "targetChange" &&
      isGlobalNoChange(frame.targetChange ?? {}) &&
      frame.targetChange?.resumeToken
    ) {
      close();
    }
  }
  close();
  return groups.map(({ docs, updateTimes }) => ({ docs, sameUpdateTime: updateTimes.size === 1 }));
}
