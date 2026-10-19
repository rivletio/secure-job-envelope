import { createRouter } from "@tanstack/react-router";
import { AppErrorComponent } from "@/lib/error-component";
import { routeTree } from "./routeTree.gen";

// When the app is built for a subpath (the static desk export sets Vite `base`),
// the router must route under that same prefix. In the default root build
// BASE_URL is "/", so basepath resolves to "" and nothing changes.
const basepath = import.meta.env.BASE_URL.replace(/\/+$/, "");

export function getRouter() {
  return createRouter({
    routeTree,
    defaultErrorComponent: AppErrorComponent,
    ...(basepath ? { basepath } : {}),
  });
}
