// Discover only own enumerable exports. This is codebase inspection, not a
// sandbox: user getters can still execute arbitrary code in this process.
import { invocationFailure } from './invocation-error.mjs';

// Local resource limits, not Firebase quotas. Exceeding one aborts discovery;
// never publish a seemingly complete inventory after truncating the graph.
export const DISCOVERY_LIMITS = Object.freeze({
  maxDepth: 128,
  maxEntries: 10_000,
  maxNameBytes: 1024,
});

export class DiscoveryError extends Error {
  constructor(reason) {
    super(`function export discovery failed (${reason})`);
    this.name = 'DiscoveryError';
  }
}

const namespaceRoots = new WeakMap();
const interopAliases = new Set(['default', 'module.exports']);
const hasOwn = (object, key) => Object.prototype.hasOwnProperty.call(object, key);

function keysOf(object) {
  const keys = Object.keys(object);
  if (keys.length > DISCOVERY_LIMITS.maxEntries) throw new DiscoveryError('entry limit');
  return keys;
}

// Preserve CommonJS insertion order, then fill missing named ES exports. Keep
// root accessors lazy so one throwing export is diagnosed by name without
// preventing inspection of its siblings. A null prototype makes __proto__,
// constructor and toString ordinary export names. Never execute setters while
// merging or consult inherited keys when deciding which source takes priority.
export function exportNamespace(moduleNamespace) {
  const namespace = Object.create(null);
  let count = 0;
  function add(source) {
    for (const key of keysOf(source)) {
      if (interopAliases.has(key) || hasOwn(namespace, key)) continue;
      if (++count > DISCOVERY_LIMITS.maxEntries) throw new DiscoveryError('entry limit');
      Object.defineProperty(namespace, key, {
        enumerable: true,
        get: () => {
          // An earlier export getter may remove/hide another own property.
          // Do not fall through to an inherited callback at the stale key.
          if (!Object.getOwnPropertyDescriptor(source, key)?.enumerable) return undefined;
          return Reflect.get(source, key);
        },
      });
    }
  }
  const primary = hasOwn(moduleNamespace, 'default') ? Reflect.get(moduleNamespace, 'default') : undefined;
  if (primary !== null && typeof primary === 'object') add(primary);
  add(moduleNamespace);
  namespaceRoots.set(namespace, [moduleNamespace, ...(primary !== null && typeof primary === 'object' ? [primary] : [])]);
  return namespace;
}

function exportFailure(error) {
  // Thrown values may themselves have throwing message/stack/toString hooks.
  return `the export could not be read: ${invocationFailure(error).message.split('\n')[0]}`;
}

export function collectFunctions(namespace) {
  const functions = new Map();
  const broken = new Map();
  const claimed = new Map();
  const ancestors = new Set(namespaceRoots.get(namespace) ?? []);
  const stack = [];
  let entries = 0;

  function record(name, path, fn, reason) {
    const origin = JSON.stringify(path);
    if (claimed.has(name)) {
      functions.delete(name);
      broken.set(name, `ambiguous flattened export name: ${claimed.get(name)} and ${origin}`);
      return;
    }
    claimed.set(name, origin);
    if (reason !== undefined) broken.set(name, reason);
    else functions.set(name, fn);
  }

  function enter(group, path, name) {
    if (ancestors.has(group)) {
      record(name, path, undefined, 'cyclic export group');
      return;
    }
    if (path.length > DISCOVERY_LIMITS.maxDepth) throw new DiscoveryError('depth limit');
    let keys;
    try {
      keys = Object.keys(group);
    } catch (error) {
      if (path.length === 0) throw new DiscoveryError('root enumeration');
      record(name, path, undefined, exportFailure(error));
      return;
    }
    if (keys.length > DISCOVERY_LIMITS.maxEntries) throw new DiscoveryError('entry limit');
    ancestors.add(group);
    stack.push({ group, path, keys, next: 0 });
  }

  enter(namespace, [], '');
  while (stack.length > 0) {
    const current = stack[stack.length - 1];
    if (current.next === current.keys.length) {
      ancestors.delete(current.group);
      stack.pop();
      continue;
    }
    if (++entries > DISCOVERY_LIMITS.maxEntries) throw new DiscoveryError('entry limit');
    const key = current.keys[current.next++];
    const path = [...current.path, key];
    const name = path.join('-');
    if (Buffer.byteLength(name, 'utf8') > DISCOVERY_LIMITS.maxNameBytes) {
      throw new DiscoveryError('name limit');
    }
    let value;
    let isGroup;
    let marked;
    try {
      if (!Object.getOwnPropertyDescriptor(current.group, key)?.enumerable) continue;
      value = Reflect.get(current.group, key);
      if (typeof value === 'function') marked = Boolean(value.__endpoint || value.__trigger);
      else isGroup = value !== null && typeof value === 'object' && !Array.isArray(value);
    } catch (error) {
      record(name, path, undefined, exportFailure(error));
      continue;
    }
    if (marked) record(name, path, value);
    else if (isGroup) enter(value, path, name);
  }
  return { functions, broken };
}
