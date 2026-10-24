// A finite production observation corpus. Local success is not production equivalence.
import { str, int, nul } from "../fs-query-index/values.mjs";

const fn = (name, ...args) => ({ functionValue: { name, args } });
const array = (...values) => ({ arrayValue: { values } });
const map = (fields) => ({ mapValue: { fields } });
const score = () => fn("score");
const ordering = (direction) => array(map({ expression: score(), direction: str(direction) }));
const collection = { name: "collection", args: [{ referenceValue: "/textobs1" }] };

export const INDEXES = {
  indexes: [
    {
      collectionGroup: "textobs1",
      queryScope: "COLLECTION",
      fields: ["title", "body"].map((fieldPath) => ({
        fieldPath,
        searchConfig: {
          textSpec: { indexSpecs: [{ indexType: "TOKENIZED", matchType: "MATCH_GLOBALLY" }] },
        },
      })),
      searchIndexOptions: { textLanguage: "en", textLanguageOverrideFieldPath: "language" },
    },
  ],
  fieldOverrides: [],
};

const seed = [
  ["short", { title: str("fox"), body: str("red fox") }],
  ["frequent", { title: str("fox fox fox"), body: str("fox fox fox fox") }],
  [
    "long",
    {
      title: str("fox"),
      body: str("a long quiet story about a fox in the green forest beside the river"),
    },
  ],
  ["phrase", { title: str("quick brown fox"), body: str("jumps over coffee") }],
  ["cross", { title: str("quick"), body: str("brown fox") }],
  ["reverse", { title: str("brown quick fox"), body: str("waffles") }],
  ["inflected", { title: str("running runners run runs"), body: str("dogs jumped jumping") }],
  [
    "fold",
    { title: str("Straße STRASSE İSTANBUL café cafe\u0301 ＦＯＸ"), body: str("don't co-operate") },
  ],
  ["japanese", { title: str("東京都の猫と東京駅"), body: str("猫🐈と犬") }],
  ["french", { title: str("chevaux cheval mangent manger"), body: str("café") }],
  ["non-string", { title: int(7), body: nul() }],
  ["missing", { unrelated: str("fox") }],
].map(([name, fields]) => [`textobs1/${name}`, fields]);

function search(id, query, options = {}) {
  const body = {
    structuredPipeline: {
      pipeline: {
        stages: [
          collection,
          {
            name: "search",
            args: [],
            options: { query: fn("document_matches", str(query)), ...options },
          },
        ],
      },
    },
  };
  return [
    { id, rpc: "executePipeline", body },
    { id: `${id}-grpc`, rpc: "executePipeline", transport: "grpc", body },
  ];
}

const queries = [
  ["term", "fox"],
  ["case", "FOX"],
  ["conjunction", "quick fox"],
  ["phrase", '"quick brown"'],
  ["phrase-reverse", '"brown quick"'],
  ["phrase-cross-field", '"quick brown fox"'],
  ["exclusion", "fox -coffee"],
  ["excluded-phrase", 'fox -"quick brown"'],
  ["negative-only", "-fox"],
  ["field-title", "title:fox"],
  ["field-body", "body:fox"],
  ["field-missing", "unknown:fox"],
  ["unicode-fold", "strasse"],
  ["unicode-accent", "café"],
  ["unicode-combining", "cafe\u0301"],
  ["unicode-width", "ＦＯＸ"],
  ["unicode-turkish", "istanbul"],
  ["cjk", "東京"],
  ["cjk-character", "京"],
  ["emoji-boundary", "猫"],
  ["apostrophe", "don't"],
  ["hyphen", "co-operate"],
  ["stemming", "run"],
  ["french-stemming", "cheval"],
  ["stopword", "the"],
  ["empty", ""],
  ["punctuation", "!!!"],
  ["unclosed-quote", '"fox'],
  ["boolean-or", "fox OR waffles"],
  ["default-order", "fox"],
];

export const PROGRAMS = [
  {
    id: "fs-ent-text/v1/lexical",
    seed,
    steps: [
      ...queries.flatMap(([id, query]) => search(id, query)),
      ...search("rank-desc", "fox", {
        sort: ordering("descending"),
        add_fields: map({ rank: score() }),
      }),
      ...search("rank-asc", "fox", {
        sort: ordering("ascending"),
        add_fields: map({ rank: score() }),
      }),
      ...search("multi-term-rank", "quick fox", {
        sort: ordering("descending"),
        add_fields: map({ rank: score() }),
      }),
      ...search("offset-limit", "fox", {
        sort: ordering("descending"),
        offset: int(1),
        limit: int(2),
      }),
      ...search("retrieval-depth", "fox", {
        retrieval_depth: int(2),
        sort: ordering("descending"),
      }),
      ...search("retrieval-zero", "fox", { retrieval_depth: int(0) }),
      ...search("language-en", "run", { language_code: str("en") }),
      ...search("language-ja", "東京", { language_code: str("ja") }),
      ...search("language-auto", "東京", { language_code: str("auto") }),
      ...search("language-invalid", "fox", { language_code: str("not a language") }),
      ...search("enhancement-disabled", "fox", { query_enhancement: str("disabled") }),
      {
        id: "update",
        rpc: "commit",
        body: {
          writes: [
            {
              update: {
                name: "{docs}/textobs1/short",
                fields: { title: str("pancakes"), body: str("pancakes now") },
              },
            },
          ],
        },
      },
      ...search("after-update", "fox"),
      { id: "delete", rpc: "commit", body: { writes: [{ delete: "{docs}/textobs1/frequent" }] } },
      ...search("after-delete", "fox"),
      {
        id: "change-type",
        rpc: "commit",
        body: {
          writes: [
            { update: { name: "{docs}/textobs1/long", fields: { title: int(9), body: nul() } } },
          ],
        },
      },
      ...search("after-type-change", "fox"),
    ],
  },
];
