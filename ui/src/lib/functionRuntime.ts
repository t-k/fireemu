import type { FunctionRuntime } from "../api/functions";

const LANGUAGE_NAME = { node: "Node.js", python: "Python" } as const;

/** `Python (python312)`, `Node.js (nodejs22)`, or the bare language when none was declared. */
export const runtimeLabel = (runtime: FunctionRuntime): string => {
  const name = LANGUAGE_NAME[runtime.language];
  return runtime.declared === null ? name : `${name} (${runtime.declared})`;
};
