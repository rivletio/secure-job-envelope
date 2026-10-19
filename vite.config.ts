import { defineConfig } from "vite";
import { tanstackStart } from "@tanstack/react-start/plugin/vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { nitro } from "nitro/vite";

// DESK_STATIC=1 produces a fully static, client-only SPA export of the desk for
// GitHub Pages (served from DESK_BASE, default /secure-job-envelope/desk/). The
// desk holds all its state client-side (localStorage) and runs all crypto in the
// browser, so SPA mode prerenders the app shell and the client router takes over.
// Unset, this gate changes nothing: the default build stays the SSR node-server app.
const deskStatic = process.env.DESK_STATIC === "1";
const deskBase = process.env.DESK_BASE ?? "/secure-job-envelope/desk/";

export default defineConfig(({ command, isPreview }) => ({
  base: deskStatic ? deskBase : "/",
  plugins: [
    tailwindcss(),
    tanstackStart(
      // A bare SPA shell (no route crawling): the desk is fully client-rendered from
      // localStorage, so prerendering route content only causes hydration mismatches.
      // One shell serves every route (the Pages 404 fallback hands deep links to it).
      deskStatic
        ? {
            spa: { enabled: true, prerender: { crawlLinks: false } },
            prerender: { failOnError: false },
          }
        : undefined,
    ),
    // The static desk export is a client-only SPA, so it adds no server: the nitro
    // node-server runtime is only for the default SSR build/preview.
    ...(!deskStatic && (command === "build" || isPreview)
      ? [nitro({ preset: "node-server" })]
      : []),
    viteReact(),
  ],
}));
