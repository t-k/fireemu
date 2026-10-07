export const FRAMING_RESERVE = 4096;
// Count repeated application metadata values and conservatively bound encoded status text.
export function metadataBytes(metadata, details = "") {
  const values = Object.keys(metadata?.getMap?.() ?? {}).reduce(
    (sum, key) =>
      sum +
      metadata
        .get(key)
        .reduce(
          (total, value) =>
            total +
            Buffer.byteLength(key) +
            (Buffer.isBuffer(value) ? 4 * Math.ceil(value.length / 3) : Buffer.byteLength(value)) +
            4,
          0,
        ),
    0,
  );
  return values + (typeof details === "string" ? 3 * Buffer.byteLength(details) : 0);
}
