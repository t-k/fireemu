// The read-only preflight of a Secure Token body recording: what the sandbox holds before
// anything is created. Every call is a GET or the read-only account count, built and guarded like
// the recording's own requests; a refused preflight leaves nothing behind.

import { buildRequest, guardRequest, requests as R, withProject } from "./harness.mjs";
import { openRuns, preflightProblems } from "./judge.mjs";

export async function preflight(
  ctx,
  ledgerText = "",
  { now = Date.now(), fetchImpl = fetch, timeoutMs = 60_000 } = {},
) {
  const read = async (spec) => {
    const request = buildRequest(ctx, withProject(spec, ctx.project));
    guardRequest(request, ctx);
    try {
      const response = await fetchImpl(request.url, {
        ...request.init,
        redirect: "error",
        signal: AbortSignal.timeout(timeoutMs),
      });
      const text = await response.text();
      let json = null;
      try {
        json = JSON.parse(text);
      } catch {
        /* an unreadable body is a failed read */
      }
      return { status: response.status, json };
    } catch (error) {
      return { status: 0, json: null, transport: error?.cause?.code ?? error?.name ?? "error" };
    }
  };
  const config = await read(R.readConfig());
  const accounts = await read(R.countAccounts());
  const tenancy = config.json?.multiTenant?.allowTenants === true;
  // With multi-tenancy off the tenant list is not asked for; the session lists it once it is on.
  const tenants = tenancy ? await read(R.listTenants()) : undefined;
  const reads = { config, accounts, ...(tenants ? { tenants } : {}) };
  const report = {
    failedReads: Object.entries(reads)
      .filter(([, { status }]) => status !== 200)
      .map(([name, { status }]) => `${name} (HTTP ${status})`),
    projectAccounts: Number(accounts.json?.recordsCount ?? -1),
    passwordEnabled: config.json?.signIn?.email?.enabled === true,
    multiTenancy: tenancy,
    tenantsListed: tenants !== undefined,
    tenants: tenants ? (tenants.json?.tenants ?? []).length : 0,
    openRuns: openRuns(ledgerText, ctx.project, now),
  };
  return { report, problems: preflightProblems(report) };
}
