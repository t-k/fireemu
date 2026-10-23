const str = (stringValue) => ({ stringValue });
const fn = (name, ...args) => ({ functionValue: { name, args } });
const array = (...values) => ({ arrayValue: { values } });
const map = (fields) => ({ mapValue: { fields } });
const score = () => fn('score');

function seed(includeCorpusSizeControls = false) {
  const filler = Array(20).fill('filler').join(' ');
  const documents = [
    ['a', 'fox', 'neutral'],
    ['b', 'fox fox', 'neutral'],
    ['c', 'fox fox fox', 'neutral'],
    ['d', 'fox fox fox fox fox fox fox', 'neutral'],
    ['e', `fox ${filler}`, 'neutral'],
    ['f', 'padding', 'neutral'],
    ['g', 'quick fox', 'neutral'],
    ['h', `quick fox ${filler}`, 'neutral'],
    ['i', 'quick quick fox', 'neutral'],
    ['j', 'quick', 'fox'],
    ['k', 'fox', 'fox'],
    ['l', 'fox fox fox', 'fox fox fox fox'],
    ['m', 'padding', 'fox'],
  ];
  if (includeCorpusSizeControls) {
    for (let index = 1; index <= 8; index += 1) {
      documents.push([`pad-${index}`, `padding ${filler}`, 'neutral']);
    }
  }
  return documents.map(([id, title, body]) => [
    `textobs1/c-${id}`,
    { title: str(title), body: str(body) },
  ]);
}

function queries() {
  return [
    ['fox', 'fox'],
    ['quick', 'quick'],
    ['conjunction', 'quick fox'],
    ['duplicate', 'fox fox'],
    ['phrase', '"quick fox"'],
    ['enhancement-disabled', 'fox'],
  ].map(([id, text]) => {
    const options = {
      add_fields: map({ rank: score() }),
      sort: array(map({ expression: score(), direction: str('descending') })),
    };
    if (id === 'enhancement-disabled') {
      options.query_enhancement = str('disabled');
    }
    return { id, text, options };
  });
}

export const CALIBRATION_PHASES = [
  {
    id: 'one-field',
    indexFields: ['title'],
    seed: seed(),
    queries: queries(),
  },
  {
    id: 'two-fields',
    indexFields: ['title', 'body'],
    seed: seed(),
    queries: queries(),
  },
  {
    id: 'corpus-size-control',
    indexFields: ['title', 'body'],
    seed: seed(true),
    queries: queries(),
  },
];
