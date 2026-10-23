const str = (stringValue) => ({ stringValue });
const fn = (name, ...args) => ({ functionValue: { name, args } });
const array = (...values) => ({ arrayValue: { values } });
const map = (fields) => ({ mapValue: { fields } });
const score = () => fn("score");

function baseSeed() {
  const filler = Array(20).fill("filler").join(" ");
  const documents = [
    ["a", "fox", "neutral"],
    ["b", "fox fox", "neutral"],
    ["c", "fox fox fox", "neutral"],
    ["d", "fox fox fox fox fox fox fox", "neutral"],
    ["e", `fox ${filler}`, "neutral"],
    ["f", "padding", "neutral"],
    ["g", "quick fox", "neutral"],
    ["h", `quick fox ${filler}`, "neutral"],
    ["i", "quick quick fox", "neutral"],
    ["j", "quick", "fox"],
    ["k", "fox", "fox"],
    ["l", "fox fox fox", "fox fox fox fox"],
    ["m", "padding", "fox"],
    ["n", "neutral", "fox"],
    ["o", "neutral", "fox fox fox"],
    ["p", "fox fox", "fox neutral"],
  ];
  return documents.map(([id, title, body]) => [
    `textobs1/c-${id}`,
    { title: str(title), body: str(body) },
  ]);
}

function documentFrequencySeed() {
  const seed = baseSeed();
  seed.find(([path]) => path === "textobs1/c-f")[1].title = str("fox");
  seed.find(([path]) => path === "textobs1/c-m")[1].title = str("quick");
  return seed;
}

function paddedSeed() {
  const seed = baseSeed();
  const filler = Array(20).fill("filler").join(" ");
  for (let index = 1; index <= 8; index += 1) {
    seed.push([
      `textobs1/c-pad-${index}`,
      { title: str(`padding ${filler}`), body: str("neutral") },
    ]);
  }
  return seed;
}

function denominatorSeed() {
  return [
    ...baseSeed(),
    ["textobs1/c-q", {}],
    ["textobs1/c-r", { title: { integerValue: "7" }, body: { nullValue: null } }],
    ["textobs1/c-s", { title: str(""), body: str("") }],
  ];
}

function queries() {
  return [
    ["fox", "fox"],
    ["quick", "quick"],
    ["conjunction", "quick fox"],
    ["duplicate", "fox fox"],
    ["phrase", '"quick fox"'],
    ["enhancement-disabled", "fox"],
  ].map(([id, text]) => {
    const options = {
      add_fields: map({ rank: score() }),
      sort: array(map({ expression: score(), direction: str("descending") })),
    };
    if (id === "enhancement-disabled") {
      options.query_enhancement = str("disabled");
    }
    return { id, text, options };
  });
}

function phase(id, indexFields, seed) {
  return { id, indexFields, seed, queries: queries() };
}

export const CALIBRATION_PHASES = [
  phase("one-field", ["title"], baseSeed()),
  phase("two-fields", ["title", "body"], baseSeed()),
  phase("document-frequency-control", ["title", "body"], documentFrequencySeed()),
  phase("padded-corpus-control", ["title", "body"], paddedSeed()),
  phase("denominator-control", ["title", "body"], denominatorSeed()),
];
