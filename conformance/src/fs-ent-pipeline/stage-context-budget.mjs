// Claims are monotone: failed or uncertain transport attempts are never refunded.
export function createStageBudget({maximum, cleanupReserve, initialUsed=0}) {
  if (!Number.isInteger(maximum) || !Number.isInteger(cleanupReserve) || maximum < 1 || cleanupReserve < 0 || cleanupReserve > maximum || !Number.isInteger(initialUsed) || initialUsed < 0 || initialUsed > maximum) throw new Error('invalid request budget');
  let count=initialUsed;
  return {
    async claim(action) {
      const cleanup=['delete-owned','verify-absence','end-describe','end-baseline','end-delete','end-poll','end-list','end-get','recovery-read'].includes(action);
      if (count >= maximum) throw new Error('request ceiling reached');
      if (!cleanup && count >= maximum-cleanupReserve) throw new Error('cleanup reserve reached');
      count++;
    },
    used:()=>count,
  };
}
