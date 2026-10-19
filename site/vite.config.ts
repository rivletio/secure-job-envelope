import { defineConfig } from "vite";
import { resolve } from "node:path";

/** Standalone STATIC build of the SJE demo PWAs — plain Vite, no TanStack Start and
 *  no server, so the output is fully static and hostable on GitHub Pages. The demos
 *  import the real library from ../src/lib and run it entirely in the browser
 *  (post-quantum ML-KEM / ML-DSA included). `SITE_BASE` overrides the base path
 *  (default `/secure-job-envelope/` for a build; `/` while developing). */
export default defineConfig(({ command }) => ({
  root: import.meta.dirname,
  base: process.env.SITE_BASE ?? (command === "build" ? "/secure-job-envelope/" : "/"),
  build: {
    outDir: resolve(import.meta.dirname, "dist"),
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, "index.html"),
        lifecycle: resolve(import.meta.dirname, "lifecycle.html"),
        exchange: resolve(import.meta.dirname, "exchange.html"),
      },
    },
  },
}));
