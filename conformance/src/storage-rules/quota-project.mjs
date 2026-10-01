// Which requests carry the quota project header (`x-goog-user-project`). It is a property of the route: the owner's user
// credential names the project it is billed to on every API that bills a project, and the header is dropped where the
// endpoint is not a project-billed API. The one such endpoint the run calls is the OAuth2 userinfo of the owner's own
// token: with the header it answers 403 USER_PROJECT_DENIED (consumer project without openidconnect.googleapis.com).
// The dispatch gate decides this from the target it is about to send, so a credential provider cannot add the header
// where the route must not have it, and the run cannot start with a header set nobody reviewed.
export const NO_QUOTA_PROJECT_ROUTES = Object.freeze(["GET https://www.googleapis.com/oauth2/v2/userinfo"]);
const EXEMPT = new Set(NO_QUOTA_PROJECT_ROUTES);

/** Whether a request to this target carries the quota project header when its credential is the owner's. */
export function quotaProjectRequired({ method, url }) {
  let parsed;
  try { parsed = new URL(url); } catch { return true; }
  return !EXEMPT.has(`${method} ${parsed.origin}${parsed.pathname}`);
}
