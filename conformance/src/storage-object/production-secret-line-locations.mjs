const PERCENT = /(?:%[a-fA-F0-9]{2})+/g;
const unavailable = () => new Error("SECRET_REGISTRY_UNAVAILABLE");
const startAt = (source, offset) => (source.starts ? source.starts[offset] : offset);
const endAt = (source, offset) => (source.ends ? source.ends[offset] : offset + 1);
function mapped(text) {
  if (text.length > 6291456) throw unavailable();
  return { text, starts: new Int32Array(text.length), ends: new Int32Array(text.length) };
}
function copyRange(source, target, first, last, output) {
  for (let i = first; i < last; i++, output++) {
    target.starts[output] = startAt(source, i);
    target.ends[output] = endAt(source, i);
  }
  return output;
}
function plus(source, charge) {
  const text = source.text.replaceAll("+", "%20");
  charge(source.text.length + text.length);
  const target = mapped(text);
  let output = 0;
  for (let i = 0; i < source.text.length; i++) {
    const width = source.text[i] === "+" ? 3 : 1;
    for (let j = 0; j < width; j++, output++) {
      target.starts[output] = startAt(source, i);
      target.ends[output] = endAt(source, i);
    }
  }
  return target;
}
function percent(source, charge) {
  charge(source.text.length * 2);
  const decode = (part) => {
    try {
      return decodeURIComponent(part);
    } catch {
      return part;
    }
  };
  const target = mapped(source.text.replace(PERCENT, decode));
  let previous = 0,
    output = 0;
  for (const match of source.text.matchAll(PERCENT)) {
    const part = match[0],
      first = match.index,
      decoded = decode(part);
    output = copyRange(source, target, previous, first, output);
    if (decoded === part) output = copyRange(source, target, first, first + part.length, output);
    else {
      let byte = 0;
      for (const character of decoded) {
        const width = Buffer.byteLength(character);
        const beginning = startAt(source, first + byte * 3);
        const ending = endAt(source, first + (byte + width) * 3 - 1);
        for (let unit = 0; unit < character.length; unit++, output++) {
          target.starts[output] = beginning;
          target.ends[output] = ending;
        }
        byte += width;
      }
      if (byte * 3 !== part.length) throw unavailable();
    }
    previous = first + part.length;
  }
  output = copyRange(source, target, previous, source.text.length, output);
  if (output !== target.text.length) throw unavailable();
  return target;
}
function utf8Width(bytes, offset) {
  const first = bytes[offset];
  if (first < 0x80) return 1;
  const expected =
    first >= 0xc2 && first <= 0xdf
      ? 2
      : first >= 0xe0 && first <= 0xef
        ? 3
        : first >= 0xf0 && first <= 0xf4
          ? 4
          : 1;
  let consumed = 1;
  while (consumed < expected && offset + consumed < bytes.length) {
    const value = bytes[offset + consumed];
    if (
      value < 0x80 ||
      value > 0xbf ||
      (consumed === 1 &&
        ((first === 0xe0 && value < 0xa0) ||
          (first === 0xed && value > 0x9f) ||
          (first === 0xf0 && value < 0x90) ||
          (first === 0xf4 && value > 0x8f)))
    )
      break;
    consumed++;
  }
  return consumed;
}
function base64(source, match, offset, charge) {
  const segment = match[0].slice(offset);
  charge(segment.length);
  const bytes = Buffer.from(segment, "base64"),
    target = mapped(bytes.toString("utf8"));
  charge(bytes.length + target.text.length);
  let unit = 0;
  for (let byte = 0; byte < bytes.length;) {
    const width = utf8Width(bytes, byte);
    const character = bytes.subarray(byte, byte + width).toString("utf8");
    if (character !== target.text.slice(unit, unit + character.length)) throw unavailable();
    const first = match.index + offset + Math.floor(byte / 3) * 4;
    const last =
      match.index +
      offset +
      Math.min(segment.length, (Math.floor((byte + width - 1) / 3) + 1) * 4) -
      1;
    for (let i = 0; i < character.length; i++, unit++) {
      target.starts[unit] = startAt(source, first);
      target.ends[unit] = endAt(source, last);
    }
    byte += width;
  }
  if (unit !== target.text.length) throw unavailable();
  return target;
}

/** Every transformed match retains its original source line interval; decoded newlines cannot invent file lines. */
export function locateProductionSecretLines(text, charge, scanRanges) {
  charge(text.length * 3 + 1);
  const starts = new Uint32Array(text.length + 1);
  let lineCount = 1;
  for (let i = 0; i < text.length; i++) if (text[i] === "\n") starts[lineCount++] = i + 1;
  const difference = new Int32Array(lineCount + 1);
  function lineAt(offset) {
    if (!Number.isSafeInteger(offset) || offset < 0 || offset >= text.length) throw unavailable();
    let low = 0,
      high = lineCount;
    while (low + 1 < high) {
      charge(1);
      const middle = Math.floor((low + high) / 2);
      if (starts[middle] <= offset) low = middle;
      else high = middle;
    }
    return low;
  }
  function scan(source) {
    scanRanges(source.text, (first, last) => {
      const beginning = lineAt(startAt(source, first)),
        ending = lineAt(endAt(source, last - 1) - 1);
      if (beginning > ending) throw unavailable();
      difference[beginning]++;
      difference[ending + 1]--;
    });
  }
  const source = { text, starts: null, ends: null };
  function candidate(sourceCandidate) {
    scan(sourceCandidate);
    for (const pattern of [/[A-Za-z0-9+/]{4,}={0,2}/g, /[A-Za-z0-9_-]{4,}/g]) {
      charge(sourceCandidate.text.length);
      for (const match of sourceCandidate.text.matchAll(pattern))
        for (let offset = 0; offset < 4 && match[0].length - offset >= 4; offset++) {
          const decoded = base64(sourceCandidate, match, offset, charge);
          scan(decoded);
          scan(percent(decoded, charge));
          scan(percent(plus(decoded, charge), charge));
        }
    }
  }
  candidate(source);
  candidate(percent(source, charge));
  candidate(percent(plus(source, charge), charge));
  let active = 0,
    matchedLineCount = 0;
  const lineNumbers = [];
  charge(lineCount);
  for (let line = 0; line < lineCount; line++) {
    active += difference[line];
    if (active > 0) {
      matchedLineCount++;
      if (lineNumbers.length < 20) lineNumbers.push(line + 1);
    }
  }
  return Object.freeze({
    lineNumbers: Object.freeze(lineNumbers),
    matchedLineCount,
    truncated: matchedLineCount > 20,
  });
}
