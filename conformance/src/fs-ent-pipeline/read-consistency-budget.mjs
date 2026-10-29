// Claims are monotone; three cleanup calls and two separately admitted safety reads remain held.
export function createReadConsistencyBudget(){let count=0;return {async claim(op){const cleanup=['rollback','delete-owned','verify-absence','recovery-read'].includes(op);if(count>=33)throw Error('request ceiling');if(!cleanup&&count>=28)throw Error('cleanup reserve');count++;},used:()=>count};}
