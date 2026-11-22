/**
 * Stand-in for the `react-style-singleton` package. The build aliases the package name to
 * this file (scripts/vite-plugin-no-inline-styles.ts), so the libraries that depend on it get
 * this module instead — in practice react-remove-scroll, which Radix Dialog uses to lock page
 * scroll while a dialog is open.
 *
 * Why: the original adds its rules by appending a `<style>` element to <head>. The published
 * desk's Content-Security-Policy is `style-src 'self'` with no 'unsafe-inline' (see
 * scripts/pages-csp.mjs), which refuses every inline <style>; a static page cannot hand out
 * nonces, and the rules are computed at run time (they carry the measured scrollbar width),
 * so they cannot be allowed by hash either. A constructed stylesheet adopted by the document
 * is not an inline style: it holds the same rules, with the same lifetime, and the policy
 * stays strict. Same exports and the same add-on-first-user / remove-with-last-user
 * behaviour as the original.
 *
 * Where constructed stylesheets are missing (Safari < 16.4, Firefox < 101) no rules are
 * added — deliberately not a fallback to <style>, which the policy would refuse: a dialog
 * still opens and traps focus and wheel/touch scrolling, only the page scrollbar stays.
 */
import { useEffect } from "react";

type Singleton = { add: (css: string) => void; remove: () => void };

function adopt(css: string): CSSStyleSheet | null {
  if (typeof document === "undefined" || typeof CSSStyleSheet === "undefined") return null;
  if (!("adoptedStyleSheets" in document)) return null;
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(css);
    document.adoptedStyleSheets = [...document.adoptedStyleSheets, sheet];
    return sheet;
  } catch {
    return null;
  }
}

export function stylesheetSingleton(): Singleton {
  let users = 0;
  let sheet: CSSStyleSheet | null = null;
  return {
    add(css) {
      if (users === 0) sheet = adopt(css);
      users += 1;
    },
    remove() {
      users -= 1;
      if (users === 0 && sheet) {
        const gone = sheet;
        document.adoptedStyleSheets = document.adoptedStyleSheets.filter((s) => s !== gone);
        sheet = null;
      }
    },
  };
}

export function styleHookSingleton() {
  const sheet = stylesheetSingleton();
  return function useStyle(styles: string, isDynamic?: boolean) {
    useEffect(() => {
      sheet.add(styles);
      return () => sheet.remove();
      // As upstream: the rules are applied once, and re-applied on change only when the
      // caller marks them dynamic.
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [styles && isDynamic]);
  };
}

export function styleSingleton() {
  const useStyle = styleHookSingleton();
  return function Sheet({ styles, dynamic }: { styles: string; dynamic?: boolean }) {
    useStyle(styles, dynamic);
    return null;
  };
}
