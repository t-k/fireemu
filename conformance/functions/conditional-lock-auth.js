const { timingSafeEqual } = require("node:crypto");

const TOKEN_PATTERN = /^[0-9a-f]{32}$/;

const bearerToken = (header) => {
  if (typeof header !== "string") return null;
  const match = /^Bearer ([0-9a-f]{32})$/.exec(header);
  return match?.[1] ?? null;
};

const tokenMatches = (presented, expected) => {
  if (!TOKEN_PATTERN.test(presented) || !TOKEN_PATTERN.test(expected)) return false;
  return timingSafeEqual(Buffer.from(presented, "ascii"), Buffer.from(expected, "ascii"));
};

module.exports = { bearerToken, tokenMatches };
