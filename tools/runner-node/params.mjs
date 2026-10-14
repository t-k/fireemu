// Parameters declared with `defineString`, `defineInt`, `defineBoolean`, `defineFloat` and
// `defineList` are resolved by `firebase deploy` before any function runs: a value from the
// dotenv files wins, a declared `default` fills the gap, and a parameter with neither stops the
// deploy (a non-interactive deploy cannot prompt for it). The deployed runtime therefore never
// sees an unresolved parameter. The SDK only reads `process.env[name]` at runtime, so the same
// resolution has to happen here, after the codebase has declared its parameters and before any
// endpoint option that references one is evaluated.
//
// Secrets (`defineSecret`, `defineJsonSecret`) are not resolved here: their values come from
// `.secret.local`, bound per function by the daemon.

const SECRET_TYPE = 'secret';

function typeOf(param) {
  const type = param?.constructor?.type;
  return typeof type === 'string' ? type : 'string';
}

// A declared default is a literal or another parameter / expression. Expressions are evaluated
// with the environment as resolved so far, in declaration order.
function defaultOf(param) {
  const value = param?.options?.default;
  if (value === undefined) return undefined;
  if (value !== null && typeof value === 'object' && typeof value.runtimeValue === 'function') {
    return value.runtimeValue();
  }
  return value;
}

// The environment spelling of a resolved value, as the Firebase CLI writes it.
export function serializeDefault(value) {
  if (Array.isArray(value)) return JSON.stringify(value);
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return undefined;
}

// Applies each declared default to `env` and reports what stayed unresolved.
//
// A variable that is present, even empty, is a value (`NAME=` in a dotenv file is the empty
// string, which is a legitimate string value). Only an absent variable falls back to the
// default, and only an absent variable with no default is missing.
export function resolveDeclaredParams(declared, env = process.env) {
  const missing = [];
  const defaulted = [];
  for (const param of declared ?? []) {
    const name = param?.name;
    const type = typeOf(param);
    if (typeof name !== 'string' || name === '' || type === SECRET_TYPE) continue;
    if (env[name] !== undefined) continue;
    let text;
    try {
      text = serializeDefault(defaultOf(param));
    } catch {
      text = undefined;
    }
    if (text === undefined) {
      missing.push({ name, type });
      continue;
    }
    env[name] = text;
    defaulted.push({ name, type });
  }
  return { missing, defaulted };
}

// A parameter's default has to be in the environment from the moment the parameter is declared,
// not only after the codebase has loaded: `.value()` at the top level of a module reads the
// environment right then, and a deployed function sees the default there. The SDK registers each
// declaration with `declaredParams.push`, so wrapping that one method resolves each parameter as
// it is declared. `resolveDeclaredParams` after the load stays the authority for what is missing.
export function resolveWhenDeclared(declared, env = process.env) {
  if (!Array.isArray(declared) || Object.prototype.hasOwnProperty.call(declared, 'push')) {
    return false;
  }
  const push = declared.push;
  declared.push = function pushAndResolve(...items) {
    resolveDeclaredParams(items, env);
    return push.apply(this, items);
  };
  return true;
}
