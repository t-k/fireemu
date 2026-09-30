// Canonical REST-style inputs encoded as native protobuf bytes through the pinned descriptor.
const camel = (name) => name.replace(/_([a-z])/g, (_, letter) => letter.toUpperCase());
const snake = (name) => name.replace(/[A-Z]/g, (letter) => "_" + letter.toLowerCase());
function refusal() {
  return Object.assign(new Error("input cannot be represented by the native message"), {
    code: "CLIENT_INPUT_UNREPRESENTABLE",
  });
}
function duration(value) {
  const match = /^(-?)(\d+)(?:\.(\d{1,9}))?s$/.exec(value);
  if (!match) throw refusal();
  return {
    seconds: match[1] + match[2],
    nanos: (match[1] ? -1 : 1) * Number((match[3] ?? "").padEnd(9, "0")),
  };
}
function timestamp(value) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(
    value,
  );
  if (!match) throw refusal();
  const [hour, minute, second] = match[1].slice(11).split(":").map(Number);
  if (hour > 23 || minute > 59 || second > 59) throw refusal();
  const [year, month, day] = match[1].slice(0, 10).split("-").map(Number);
  const calendar = new Date(0);
  calendar.setUTCFullYear(year, month - 1, day);
  if (
    calendar.getUTCFullYear() !== year ||
    calendar.getUTCMonth() !== month - 1 ||
    calendar.getUTCDate() !== day
  )
    throw refusal();
  const milliseconds = Date.parse(match[1] + match[3]);
  if (!Number.isFinite(milliseconds)) throw refusal();
  return { seconds: String(milliseconds / 1000), nanos: Number((match[2] ?? "").padEnd(9, "0")) };
}
function primitive(field, value) {
  if (field.type === "bytes") {
    if (Buffer.isBuffer(value) || value instanceof Uint8Array) return Buffer.from(value);
    if (
      typeof value !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) ||
      Buffer.from(value, "base64").toString("base64") !== value
    )
      throw refusal();
    return Buffer.from(value, "base64");
  }
  if (
    (field.type === "string" && typeof value !== "string") ||
    (field.type === "bool" && typeof value !== "boolean")
  )
    throw refusal();
  if (/^(?:u?int|sint|fixed|sfixed)32$/.test(field.type)) {
    const unsigned = /^(?:uint|fixed)/.test(field.type);
    if (
      !Number.isInteger(value) ||
      value < (unsigned ? 0 : -2147483648) ||
      value > (unsigned ? 4294967295 : 2147483647)
    )
      throw refusal();
  }
  if (field.type.endsWith("64")) {
    if (
      !(
        (typeof value === "string" && /^-?\d+$/.test(value)) ||
        (typeof value === "number" && Number.isSafeInteger(value))
      )
    )
      throw refusal();
    const integer = BigInt(value),
      unsigned = /^(?:uint|fixed)/.test(field.type);
    if (
      integer < (unsigned ? 0n : -(1n << 63n)) ||
      integer > (unsigned ? (1n << 64n) - 1n : (1n << 63n) - 1n)
    )
      throw refusal();
  }
  if (field.resolvedType?.values) {
    if (
      (typeof value === "string" && !Object.hasOwn(field.resolvedType.values, value)) ||
      (typeof value !== "string" && !Number.isInteger(value))
    )
      throw refusal();
  }
  return value;
}
function input(type, value) {
  if (type.fullName === ".google.protobuf.Duration" && typeof value === "string")
    value = duration(value);
  if (type.fullName === ".google.protobuf.Timestamp" && typeof value === "string")
    value = timestamp(value);
  if (type.fullName === ".google.protobuf.FieldMask" && typeof value === "string")
    value = { paths: value.split(",").map((path) => path.split(".").map(snake).join(".")) };
  if (!value || typeof value !== "object" || Array.isArray(value) || Buffer.isBuffer(value))
    throw refusal();
  const result = {};
  for (const [key, member] of Object.entries(value)) {
    const field =
      type.fields[key] ??
      type.fieldsArray.find((item) => camel(item.name) === key || snake(item.name) === key);
    if (!field || Object.hasOwn(result, field.name)) throw refusal();
    function one(v) {
      return field.resolvedType?.fields ? input(field.resolvedType, v) : primitive(field, v);
    }
    if (field.map) {
      if (!member || typeof member !== "object" || Array.isArray(member)) throw refusal();
      result[field.name] = Object.fromEntries(
        Object.entries(member).map(([name, v]) => [name, one(v)]),
      );
    } else if (field.repeated) {
      if (!Array.isArray(member)) throw refusal();
      result[field.name] = member.map(one);
    } else result[field.name] = one(member);
  }
  for (const group of type.oneofsArray)
    if (group.oneof.filter((name) => Object.hasOwn(result, name)).length > 1) throw refusal();
  return result;
}
export function createNativeCodec(root) {
  if (typeof root?.lookupType !== "function")
    throw new Error("pinned resolved protobuf descriptor required");
  function type(name) {
    return root.lookupType(name.includes(".") ? name : "google.pubsub.v1." + name);
  }
  function serialize(name, value) {
    const messageType = type(name),
      converted = messageType.fromObject(input(messageType, value));
    if (messageType.verify(converted)) throw refusal();
    return Buffer.from(messageType.encode(converted).finish());
  }
  function deserialize(name, bytes) {
    return type(name).decode(bytes);
  }
  function fieldType(name, path) {
    let messageType = type(name),
      field;
    for (const part of path.split(".")) {
      field =
        messageType.fields[part] ??
        messageType.fieldsArray.find((item) => camel(item.name) === part);
      if (!field) throw refusal();
      messageType = field.resolvedType;
    }
    return field.type;
  }
  return { serialize, deserialize, fieldType };
}
