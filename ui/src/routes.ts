import { lazy } from "solid-js";
import type { RouteDefinition } from "@solidjs/router";

export const routes: RouteDefinition[] = [
  { path: "/", component: lazy(() => import("./pages/Overview")) },
  { path: "/firestore/*path", component: lazy(() => import("./pages/Firestore")) },
  { path: "/auth", component: lazy(() => import("./pages/Auth")) },
  { path: "/storage/*path", component: lazy(() => import("./pages/Storage")) },
  { path: "/functions", component: lazy(() => import("./pages/Functions")) },
  { path: "/rules", component: lazy(() => import("./pages/Rules")) },
  { path: "/runtime", component: lazy(() => import("./pages/Runtime")) },
  { path: "*404", component: lazy(() => import("./pages/Overview")) },
];
