/** Vite plugin for the desk build: nothing in the bundle may create an inline `<style>`.
 *
 *  The published desk's Content-Security-Policy is `style-src 'self'` with no
 *  'unsafe-inline' (scripts/pages-csp.mjs). A static page cannot hand out nonces, so the only
 *  way to keep that strict is for the bundle not to inject styles at all. Two dependencies
 *  did; each is redirected, at build time, to an equivalent that is not inline:
 *
 *   1. sonner (toasts) appends a <style> with its whole stylesheet when the module loads.
 *      The same stylesheet ships as sonner/dist/styles.css, which src/styles.css imports into
 *      the app bundle; this plugin removes the now redundant injector call.
 *   2. react-style-singleton (under Radix Dialog's scroll lock) appends a <style> with rules
 *      computed at run time. The package name is aliased to src/lib/style-singleton.ts,
 *      which holds the same rules in a constructed stylesheet instead.
 *
 *  scripts/build-pages.mjs fails the Pages build if either injector is back in the shipped
 *  desk. (The dev server pre-bundles sonner, so its injector survives there — harmless: the
 *  policy is written into the production output only.)
 */
import { resolve } from "node:path";
import type { Plugin } from "vite";

const SONNER_ENTRY = /[\\/]node_modules[\\/]sonner[\\/]dist[\\/]index\.m?js$/;
const SONNER_INJECTOR_CALL = /^__insertCSS\("(?:[^"\\]|\\.)*"\);?$/gm;

export function noInlineStyles(): Plugin {
  return {
    name: "sje:no-inline-styles",
    enforce: "pre",
    config(config) {
      const shim = resolve(config.root ?? process.cwd(), "src/lib/style-singleton.ts");
      return { resolve: { alias: { "react-style-singleton": shim } } };
    },
    transform(code, id) {
      if (!SONNER_ENTRY.test(id.split("?")[0] ?? id)) return null;
      const calls = code.match(SONNER_INJECTOR_CALL) ?? [];
      if (calls.length !== 1) {
        // Fail rather than ship an injector the policy will refuse (unstyled toasts and a
        // violation on every load). If sonner changed how it delivers its CSS, re-check that
        // sonner/dist/styles.css is still the same stylesheet, then update this plugin.
        this.error(
          `expected exactly one __insertCSS("…") call in ${id}, found ${calls.length}: ` +
            "sonner's style injection changed — see scripts/vite-plugin-no-inline-styles.ts",
        );
      }
      return { code: code.replace(SONNER_INJECTOR_CALL, ""), map: null };
    },
  };
}
