// Claims are monotone: failed or uncertain transport attempts are never refunded.
export function createStageBudget({maximum, cleanupReserve}) {
  if (!Number.isInteger(maximum) || !Number.isInteger(cleanupReserve) || maximum < 1 || cleanupReserve < 0 || cleanupReserve > maximum) throw new Error('invalid request budget');
  let count=0;
  return {
    async claim(action) {
      const cleanup=['delete-owned','verify-absence'].includes(action);
      if (count >= maximum) throw new Error('request ceiling reached');
      if (!cleanup && count >= maximum-cleanupReserve) throw new Error('cleanup reserve reached');
      count++;
    },
    used:()=>count,
  };
}
