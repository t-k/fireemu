import { types } from "node:util";

const originalScans = new WeakSet();
const unavailable = () => new Error("SECRET_REGISTRY_UNAVAILABLE");

/** Only an original bounded scan can supply the task-wide capture predicate. */
export const isProductionSecretScan = (scan) => originalScans.has(scan);

/** A compact UTF-16 trie bounds retained edges and uses failure links for linear scans. */
export function createProductionSecretIndex(maxNodes) {
  if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > 1048576)
    throw new Error("invalid secret index configuration");
  const edges = new Map();
  let chars = new Uint16Array(maxNodes),
    first = new Int32Array(maxNodes),
    next = new Int32Array(maxNodes),
    failure = new Int32Array(maxNodes),
    terminal = new Uint8Array(maxNodes),
    matched = new Uint8Array(maxNodes);
  let nodes = 1,
    dirty = false,
    failed = false,
    closed = false;
  const halt = () => {
    failed = true;
  };
  function ready() {
    if (closed || failed) throw unavailable();
  }
  function compile() {
    if (!dirty) return;
    const queue = new Int32Array(nodes);
    let read = 0,
      write = 0,
      work = 0;
    const charge = () => {
      if (++work > maxNodes * 16) throw unavailable();
    };
    failure.fill(0);
    matched.set(terminal);
    for (let child = first[0]; child; child = next[child]) queue[write++] = child;
    while (read < write) {
      const parent = queue[read++];
      for (let child = first[parent]; child; child = next[child]) {
        charge();
        let fallback = failure[parent],
          target = edges.get(fallback * 65536 + chars[child]);
        while (fallback && target === undefined) {
          charge();
          fallback = failure[fallback];
          target = edges.get(fallback * 65536 + chars[child]);
        }
        failure[child] = target ?? 0;
        matched[child] = terminal[child] | matched[failure[child]];
        queue[write++] = child;
      }
    }
    dirty = false;
  }
  const index = Object.freeze({
    registerPatterns(patterns) {
      ready();
      try {
        if (
          types.isProxy(patterns) ||
          !Array.isArray(patterns) ||
          Object.getPrototypeOf(patterns) !== Array.prototype ||
          patterns.length > 7 ||
          Reflect.ownKeys(patterns).length !== patterns.length + 1
        )
          throw unavailable();
        const copy = Array.from({ length: patterns.length }, (_, i) => {
          const d = Object.getOwnPropertyDescriptor(patterns, String(i));
          if (
            !d?.enumerable ||
            !Object.hasOwn(d, "value") ||
            typeof d.value !== "string" ||
            !d.value ||
            d.value.length > 98304 ||
            !d.value.isWellFormed()
          )
            throw unavailable();
          return d.value;
        });
        for (const pattern of copy) {
          let parent = 0;
          for (let offset = 0; offset < pattern.length; offset++) {
            const character = pattern.charCodeAt(offset),
              key = parent * 65536 + character;
            let child = edges.get(key);
            if (child === undefined) {
              if (nodes >= maxNodes) throw unavailable();
              child = nodes++;
              edges.set(key, child);
              chars[child] = character;
              next[child] = first[parent];
              first[parent] = child;
            }
            parent = child;
          }
          terminal[parent] = 1;
        }
        dirty = true;
      } catch {
        halt();
        throw unavailable();
      }
    },
    openScan(maxCodeUnits) {
      ready();
      if (!Number.isSafeInteger(maxCodeUnits) || maxCodeUnits < 1 || maxCodeUnits > 268435456)
        throw new Error("invalid secret scan configuration");
      let work = 0;
      const charge = (amount) => {
        if (amount > maxCodeUnits - work) throw unavailable();
        work += amount;
      };
      const raw = (text) => {
        charge(text.length);
        compile();
        let state = 0;
        for (let i = 0; i < text.length; i++) {
          const character = text.charCodeAt(i);
          let target = edges.get(state * 65536 + character);
          while (state && target === undefined) {
            state = failure[state];
            target = edges.get(state * 65536 + character);
          }
          state = target ?? 0;
          if (matched[state]) return true;
        }
        return false;
      };
      const percent = (text) => {
        charge(text.length);
        return text.replace(/(?:%[a-fA-F0-9]{2})+/g, (part) => {
          try {
            return decodeURIComponent(part);
          } catch {
            return part;
          }
        });
      };
      const scan = Object.freeze({
        hasSecretCopy(text) {
          ready();
          try {
            if (typeof text !== "string" || text.length > 2097152 || !text.isWellFormed())
              throw unavailable();
            if (raw(text)) return true;
            const candidates = new Set([text, percent(text), percent(text.replaceAll("+", "%20"))]);
            for (const candidate of candidates) {
              if (candidate !== text && raw(candidate)) return true;
              for (const pattern of [/[A-Za-z0-9+/]{4,}={0,2}/g, /[A-Za-z0-9_-]{4,}/g]) {
                charge(candidate.length);
                for (const [segment] of candidate.matchAll(pattern))
                  for (let offset = 0; offset < 4 && segment.length - offset >= 4; offset++) {
                    charge(segment.length - offset);
                    const decoded = Buffer.from(segment.slice(offset), "base64").toString("utf8");
                    if (raw(decoded)) return true;
                    for (const normalized of new Set([
                      percent(decoded),
                      percent(decoded.replaceAll("+", "%20")),
                    ]))
                      if (normalized !== decoded && raw(normalized)) return true;
                  }
              }
            }
            return false;
          } catch {
            halt();
            throw unavailable();
          }
        },
        snapshot: () => Object.freeze({ scanCodeUnits: work, maxScanCodeUnits: maxCodeUnits }),
      });
      originalScans.add(scan);
      return scan;
    },
    halt,
    snapshot: () =>
      Object.freeze({
        nodes,
        edges: edges.size,
        failed,
        closed,
        typedArrayBytes: closed ? 0 : maxNodes * 16,
        maxCompileScratchBytes: maxNodes * 4,
      }),
    close() {
      closed = true;
      edges.clear();
      chars = first = next = failure = terminal = matched = null;
    },
  });
  return index;
}
