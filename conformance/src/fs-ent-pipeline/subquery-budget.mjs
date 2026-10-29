// Five cleanup calls and two separately admitted safety reads stay reserved.
export function createSubqueryBudget(){let count=0;return {async claim(op){const cleanup=['delete-owned','verify-absence','group-absence','recovery-read'].includes(op);if(count>=37)throw Error('request ceiling');if(!cleanup&&count>=30)throw Error('cleanup reserve');count++;},used:()=>count};}
