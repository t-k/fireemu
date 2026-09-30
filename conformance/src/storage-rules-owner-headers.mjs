// Test provider of credential headers with the shape the real provider has: the owner's bearer, and the quota project
// header exactly when the dispatch gate says the route carries it. Any other credential gets a bearer and no quota header.
export const ownerHeadersFor = (bearer) => (credential, context) => (credential === "anonymous" ? {} : { authorization: `Bearer ${bearer}`, ...(credential === "admin" && context?.quotaProject === true ? { "x-goog-user-project": context.project } : {}) });
