// Comparing a smoke's events with a recording: equal, or the first place they differ.

/** `null` when equal, else a description of the first difference. */
export function firstDifference(expected, actual, at = '$') {
  if (Object.is(expected, actual)) return null;
  if (typeof expected !== typeof actual || expected === null || actual === null) {
    return `${at}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
  }
  if (Array.isArray(expected) !== Array.isArray(actual)) {
    return `${at}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
  }
  if (Array.isArray(expected)) {
    const n = Math.max(expected.length, actual.length);
    for (let i = 0; i < n; i += 1) {
      if (i >= expected.length) return `${at}[${i}]: unexpected ${JSON.stringify(actual[i])}`;
      if (i >= actual.length) return `${at}[${i}]: missing ${JSON.stringify(expected[i])}`;
      const d = firstDifference(expected[i], actual[i], `${at}[${i}]`);
      if (d) return d;
    }
    return null;
  }
  if (typeof expected === 'object') {
    const keys = [...new Set([...Object.keys(expected), ...Object.keys(actual)])].sort();
    for (const key of keys) {
      if (!(key in actual)) return `${at}.${key}: missing`;
      if (!(key in expected)) return `${at}.${key}: unexpected`;
      const d = firstDifference(expected[key], actual[key], `${at}.${key}`);
      if (d) return d;
    }
    return null;
  }
  return `${at}: expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`;
}
