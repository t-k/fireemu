const MICRO_USD = 1_000_000;
const GIB = 1024 ** 3;

function boundedInteger(value) {
  if (!Number.isSafeInteger(value) || value < 0) throw new Error("invalid budget bound");
  return value;
}

function usdMicros(value) {
  if (
    typeof value !== "number" ||
    !Number.isFinite(value) ||
    value <= 0 ||
    !/^(?:0|[1-9]\d*)(?:\.\d{1,6})?$/.test(String(value))
  )
    throw new Error("invalid budget reservation or estimate");
  return boundedInteger(Math.round(value * MICRO_USD));
}

/** A planned upper quote, conditional on the caller enforcing the complete HTTP inventory and byte caps. */
export function estimateStage3Budget(plan) {
  const requests = boundedInteger(plan.maxRequests);
  boundedInteger(plan.maxRequestBytes);
  const responseBytes = boundedInteger(plan.maxResponseBytes);
  const accounts = boundedInteger(plan.maxOwnedAuthAccounts);
  if (!requests || !plan.maxRequestBytes || !responseBytes || !accounts)
    throw new Error("empty budget bound");
  // Conservative Standard Class A, ingress-to-client and Tier 1 MAU inputs reviewed on 2026-09-28.
  const requestMicroUsd = boundedInteger(requests * 13);
  const responseMicroUsd = Math.ceil(boundedInteger(responseBytes * 230_000) / GIB);
  const storageAllowanceMicroUsd = 100_000;
  const authMicroUsd = boundedInteger(accounts * 5500);
  const totalMicroUsd = boundedInteger(
    requestMicroUsd + responseMicroUsd + storageAllowanceMicroUsd + authMicroUsd,
  );
  const estimatedMicroUsd = usdMicros(plan.estimatedUsd);
  const reservedMicroUsd = usdMicros(plan.maxUsdReservation);
  if (totalMicroUsd > estimatedMicroUsd)
    throw new Error("budget estimate cannot cover the whole planned bound");
  if (estimatedMicroUsd > reservedMicroUsd)
    throw new Error("budget reservation cannot cover the estimate");
  return Object.freeze({
    requestMicroUsd,
    responseMicroUsd,
    storageAllowanceMicroUsd,
    authMicroUsd,
    totalMicroUsd,
    estimatedMicroUsd,
    reservedMicroUsd,
    status: "PLANNED_COST_BOUND_NOT_BILLING_PROOF",
  });
}
