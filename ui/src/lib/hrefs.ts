/**
 * In-app links for names the API accepts but a URL would misread. Every segment of a
 * Firestore path or Storage prefix is percent-encoded so `#`, `?`, `%` and non-ASCII
 * characters travel as data; the router hands the splat back still encoded, and
 * `decodeSplat` restores the name. Display strings never go through these functions.
 */

const encodeSegments = (path: string): string =>
  path
    .split("/")
    .filter(Boolean)
    .map((s) => encodeURIComponent(s))
    .join("/");

const decodeSegment = (segment: string): string => {
  try {
    return decodeURIComponent(segment);
  } catch {
    // A raw `%` typed by hand is not an escape: keep the segment as it came.
    return segment;
  }
};

/** The path segments of a router splat (`params.path`), decoded, without empty ones. */
export const decodeSplat = (splat: string | undefined): string[] =>
  (splat ?? "").split("/").filter(Boolean).map(decodeSegment);

/** The Firestore browser at `path` (`""` for the root) of `db`. */
export const firestoreHref = (path: string, db: string): string => {
  const encoded = encodeSegments(path);
  return `/firestore${encoded ? `/${encoded}` : ""}?db=${encodeURIComponent(db)}`;
};

/** The Storage browser at `prefix` (a folder, with or without its trailing slash) of `bucket`. */
export const storageHref = (prefix: string, bucket: string): string => {
  const encoded = encodeSegments(prefix);
  return `/storage${encoded ? `/${encoded}` : ""}?bucket=${encodeURIComponent(bucket)}`;
};
