// @ts-check
// The Content-Security-Policy of the published site, and the checks that keep it honest.
//
// GitHub Pages cannot send response headers, so the policy ships inside every HTML document
// as <meta http-equiv="Content-Security-Policy">. scripts/build-pages.mjs writes it into the
// assembled output (production only: the dev servers inject inline styles and a websocket,
// which this policy would rightly refuse) and then fails the build unless every emitted
// document passes auditDocument() below.
//
// What a <meta> policy cannot do, so none of it is attempted here: `frame-ancestors`,
// `sandbox` and `report-uri` are ignored when delivered by <meta> (and `report-to` needs a
// header to name its endpoint). Framing protection and violation reporting therefore need a
// host that can set headers.
import { createHash } from "node:crypto";

/** @typedef {"site" | "desk"} PageKind  which of the two published apps a document belongs to */

/**
 * @typedef {object} HtmlElement
 * @property {string} name   lower-cased tag name
 * @property {Record<string, string>} attrs  lower-cased names, entity-decoded values
 * @property {number} start  offset of the "<" of the start tag
 * @property {number} end    offset just past the ">" of the start tag
 * @property {string | null} text  raw content, for raw-text elements (script, style, …)
 * @property {boolean} inHead
 */

export const CSP_HEADER = "Content-Security-Policy";

/**
 * The policy, as [directive, sources] pairs in the order they are written.
 *
 * Everything is denied (`default-src 'none'`) and then only what the built output actually
 * uses is allowed back, each to this origin alone:
 *   script-src   external module scripts; inline scripts only by SHA-256 hash (never
 *                'unsafe-inline', never 'unsafe-eval' — the crypto is pure JS, no WASM)
 *   style-src    the bundled stylesheet; no inline <style>, no style="" attributes
 *   img-src      the favicon / app icon
 *   font-src     desk only: the self-hosted Fraunces / Archivo / IBM Plex Mono files
 *   connect-src  'none': neither app makes a network call of its own (fetch, XHR, WebSocket,
 *                EventSource, sendBeacon) — the desk is local-only by design
 *   manifest-src, worker-src   site only: the demo PWA's manifest and service worker
 *   base-uri, form-action      'none' (they do not fall back to default-src)
 * @param {PageKind} kind
 * @param {readonly string[]} inlineScriptHashes  'sha256-…' source expressions
 * @returns {[string, string[]][]}
 */
function directives(kind, inlineScriptHashes) {
  /** @type {[string, string[]][]} */
  const list = [
    ["default-src", ["'none'"]],
    ["script-src", ["'self'", ...inlineScriptHashes]],
    ["style-src", ["'self'"]],
    ["img-src", ["'self'"]],
  ];
  if (kind === "desk") list.push(["font-src", ["'self'"]]);
  list.push(["connect-src", ["'none'"]]);
  if (kind === "site") list.push(["manifest-src", ["'self'"]], ["worker-src", ["'self'"]]);
  list.push(["base-uri", ["'none'"]], ["form-action", ["'none'"]], ["object-src", ["'none'"]]);
  return list;
}

/**
 * @param {PageKind} kind
 * @param {readonly string[]} [inlineScriptHashes]
 */
export function buildPolicy(kind, inlineScriptHashes = []) {
  return directives(kind, [...new Set(inlineScriptHashes)])
    .map(([name, sources]) => `${name} ${sources.join(" ")}`)
    .join("; ");
}

/**
 * The CSP source expression for an inline script: 'sha256-<base64 of SHA-256 of its text>'.
 * The browser hashes the script's text as parsed, and the HTML parser normalises newlines
 * (CRLF and lone CR become LF) before that — so do the same here.
 * @param {string} text
 */
export function scriptHash(text) {
  const normalised = text.replace(/\r\n?/g, "\n");
  return `'sha256-${createHash("sha256").update(normalised, "utf8").digest("base64")}'`;
}

const RAW_TEXT = new Set(["script", "style", "textarea", "title", "xmp", "iframe", "noembed"]);

/** @param {string} value */
function decodeEntities(value) {
  /** @type {Record<string, string>} */
  const named = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'" };
  return value.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);/gi, (whole, ref) => {
    const r = String(ref).toLowerCase();
    if (!r.startsWith("#")) return named[r] ?? whole;
    const code = r.startsWith("#x")
      ? Number.parseInt(r.slice(2), 16)
      : Number.parseInt(r.slice(1), 10);
    return code <= 0x10ffff ? String.fromCodePoint(code) : whole;
  });
}

/**
 * Walk the start tags of an HTML document. This is a small tokenizer for documents our own
 * build emits — not a general HTML parser — but it follows the parser where it matters for
 * a policy check: comments and raw-text elements are skipped as the browser skips them, and
 * attribute values may be double-quoted, single-quoted or bare.
 * @param {string} html
 * @returns {HtmlElement[]}
 */
export function scanHtml(html) {
  /** @type {HtmlElement[]} */
  const elements = [];
  const isSpace = (/** @type {string | undefined} */ c) => c !== undefined && /\s/.test(c);
  let inHead = false;
  let i = 0;
  while (i < html.length) {
    const lt = html.indexOf("<", i);
    if (lt === -1) break;
    i = lt;
    if (html.startsWith("<!--", i)) {
      const close = html.indexOf("-->", i + 4);
      i = close === -1 ? html.length : close + 3;
      continue;
    }
    const next = html[i + 1] ?? "";
    if (next === "!" || next === "?") {
      const close = html.indexOf(">", i);
      i = close === -1 ? html.length : close + 1;
      continue;
    }
    if (next === "/") {
      const close = html.indexOf(">", i);
      const name = html.slice(i + 2, close === -1 ? html.length : close).trim();
      if (name.toLowerCase() === "head") inHead = false;
      i = close === -1 ? html.length : close + 1;
      continue;
    }
    if (!/[a-z]/i.test(next)) {
      i += 1; // a literal "<" in text
      continue;
    }

    const start = i;
    i += 1;
    let nameEnd = i;
    while (nameEnd < html.length && !/[\s/>]/.test(html[nameEnd] ?? "")) nameEnd += 1;
    const name = html.slice(i, nameEnd).toLowerCase();
    i = nameEnd;

    /** @type {Record<string, string>} */
    const attrs = {};
    for (;;) {
      while (i < html.length && (isSpace(html[i]) || html[i] === "/")) i += 1;
      if (i >= html.length || html[i] === ">") break;
      let attrEnd = i;
      while (attrEnd < html.length && !/[\s/>=]/.test(html[attrEnd] ?? "")) attrEnd += 1;
      // A stray "=" where a name should start is, to the parser, part of the name.
      if (attrEnd === i) attrEnd += 1;
      const attr = html.slice(i, attrEnd).toLowerCase();
      i = attrEnd;
      while (isSpace(html[i])) i += 1;
      let value = "";
      if (html[i] === "=") {
        i += 1;
        while (isSpace(html[i])) i += 1;
        const quote = html[i];
        if (quote === '"' || quote === "'") {
          const close = html.indexOf(quote, i + 1);
          const valueEnd = close === -1 ? html.length : close;
          value = html.slice(i + 1, valueEnd);
          i = Math.min(valueEnd + 1, html.length);
        } else {
          let valueEnd = i;
          while (valueEnd < html.length && !/[\s>]/.test(html[valueEnd] ?? "")) valueEnd += 1;
          value = html.slice(i, valueEnd);
          i = valueEnd;
        }
      }
      // The first occurrence of an attribute wins, as in the parser.
      if (!(attr in attrs)) attrs[attr] = decodeEntities(value);
    }
    i = Math.min(i + 1, html.length); // past ">"
    const end = i;

    if (name === "head") inHead = true;
    if (name === "body") inHead = false;

    /** @type {string | null} */
    let text = null;
    if (RAW_TEXT.has(name)) {
      const closer = new RegExp(`</${name}(?=[\\s/>])`, "gi");
      closer.lastIndex = i;
      const found = closer.exec(html);
      const textEnd = found ? found.index : html.length;
      text = html.slice(i, textEnd);
      const close = html.indexOf(">", textEnd);
      i = found && close !== -1 ? close + 1 : html.length;
    }
    elements.push({ name, attrs, start, end, text, inHead: inHead && name !== "head" });
  }
  return elements;
}

/** @param {HtmlElement} el */
const isPolicyMeta = (el) =>
  el.name === "meta" && (el.attrs["http-equiv"] ?? "").toLowerCase() === CSP_HEADER.toLowerCase();

/** @param {HtmlElement} el */
const isInlineScript = (el) => el.name === "script" && !("src" in el.attrs);

/**
 * The hashes of every inline <script> in a document — whatever its type: a hash only ever
 * allows that exact text, so listing a non-executing data block costs nothing, and nothing
 * executable can be missed by misjudging a type attribute.
 * @param {readonly HtmlElement[]} elements
 */
function inlineScriptHashes(elements) {
  return elements.filter(isInlineScript).map((el) => {
    const text = el.text ?? "";
    // "<!--" switches the HTML parser into the script-data-escaped states, where a later
    // "</script>" may not end the element. This tokenizer does not model that; refuse rather
    // than hash the wrong text.
    if (text.includes("<!--")) {
      throw new Error('an inline script contains "<!--"; its extent cannot be determined safely');
    }
    return scriptHash(text);
  });
}

/**
 * Write the policy for `kind` into a document: a <meta> placed as early in <head> as it can
 * be — directly after <meta charset> when that comes first (the charset must stay inside the
 * first 1024 bytes and loads nothing), otherwise directly after <head> — so that everything
 * the document goes on to load is governed by it.
 * @param {string} html
 * @param {PageKind} kind
 */
export function hardenDocument(html, kind) {
  const elements = scanHtml(html);
  if (elements.some(isPolicyMeta)) {
    throw new Error("the document already carries a Content-Security-Policy <meta>");
  }
  const headIndex = elements.findIndex((el) => el.name === "head");
  const head = elements[headIndex];
  if (!head) throw new Error("the document has no <head>");
  const first = elements[headIndex + 1];
  const at = first && first.name === "meta" && "charset" in first.attrs ? first.end : head.end;
  const policy = buildPolicy(kind, inlineScriptHashes(elements));
  const meta = `<meta http-equiv="${CSP_HEADER}" content="${policy}">`;
  return html.slice(0, at) + meta + html.slice(at);
}

/**
 * @param {string} policy
 * @returns {Map<string, string[]>}
 */
export function parsePolicy(policy) {
  /** @type {Map<string, string[]>} */
  const map = new Map();
  for (const part of policy.split(";")) {
    const [name, ...sources] = part.trim().split(/\s+/);
    // As in the browser: a repeated directive is ignored, the first one stands.
    if (name && !map.has(name.toLowerCase())) map.set(name.toLowerCase(), sources);
  }
  return map;
}

/** Directives that do nothing when the policy arrives in a <meta> element. */
const IGNORED_IN_META = ["frame-ancestors", "sandbox", "report-uri", "report-to"];

const HASH_SOURCE = /^'sha(256|384|512)-[A-Za-z0-9+/]+={0,2}'$/;

/**
 * Problems with a policy string on its own terms: it must deny by default, must not carry a
 * directive a <meta> policy ignores, and every source must be this origin, nothing, or a hash
 * — no 'unsafe-inline', no 'unsafe-eval', no scheme, host or wildcard.
 * @param {string} policy
 * @returns {string[]}
 */
export function auditPolicy(policy) {
  /** @type {string[]} */
  const problems = [];
  const map = parsePolicy(policy);
  if ((map.get("default-src") ?? []).join(" ") !== "'none'") {
    problems.push("default-src must be exactly 'none'");
  }
  for (const name of ["base-uri", "form-action"]) {
    if ((map.get(name) ?? []).join(" ") !== "'none'") problems.push(`${name} must be 'none'`);
  }
  for (const name of IGNORED_IN_META) {
    if (map.has(name)) problems.push(`${name} is ignored in a <meta> policy; do not ship it`);
  }
  for (const [name, sources] of map) {
    for (const source of sources) {
      if (source === "'self'" || source === "'none'" || HASH_SOURCE.test(source)) continue;
      problems.push(`${name} allows ${source}; only 'self', 'none' and hashes are permitted`);
    }
  }
  return problems;
}

/** Attributes whose value is fetched, submitted to, or navigated by the browser on its own. */
const URL_ATTRS = [
  "src",
  "srcset",
  "imagesrcset",
  "href",
  "xlink:href",
  "data",
  "poster",
  "background",
  "manifest",
  "action",
  "formaction",
  "ping",
];

/** @param {string} url */
const isRelativeSameOrigin = (url) => {
  const u = url.trim();
  // A scheme ("https:", "data:", "javascript:"), or "//host" — browsers also read "\" as "/".
  return !/^[a-z][a-z0-9+.-]*:/i.test(u) && !/^[/\\]{2}/.test(u);
};

/**
 * @param {HtmlElement} el
 * @returns {{ attr: string, url: string }[]}  every URL the element makes the browser load
 */
function loadedUrls(el) {
  /** @type {{ attr: string, url: string }[]} */
  const urls = [];
  for (const attr of URL_ATTRS) {
    const value = el.attrs[attr];
    if (value === undefined || value.trim() === "") continue;
    // A link the visitor chooses to follow is a navigation, not a load.
    if (attr === "href" && (el.name === "a" || el.name === "area")) continue;
    if (attr === "srcset" || attr === "imagesrcset") {
      for (const candidate of value.split(",")) {
        const url = candidate.trim().split(/\s+/)[0];
        if (url) urls.push({ attr, url });
      }
    } else {
      urls.push({ attr, url: value.trim() });
    }
  }
  if (el.name === "meta" && (el.attrs["http-equiv"] ?? "").toLowerCase() === "refresh") {
    const target = /url\s*=\s*['"]?([^'"]+)/i.exec(el.attrs["content"] ?? "");
    if (target?.[1]) urls.push({ attr: "content", url: target[1].trim() });
  }
  return urls;
}

/**
 * Every reference in an HTML document that the browser acts on by itself and that is not a
 * same-origin relative URL: <link>, <script src>, images, frames, form targets, …
 * Plain <a href> links are navigation the visitor chooses, and are not reported.
 * @param {string} html
 * @returns {string[]}
 */
export function externalRefsInHtml(html) {
  return scanHtml(html).flatMap((el) =>
    loadedUrls(el)
      .filter(({ url }) => !isRelativeSameOrigin(url))
      .map(({ attr, url }) => `<${el.name} ${attr}="${url}">`),
  );
}

/**
 * Every url(...) and import-rule target in a stylesheet, comments excluded.
 * @param {string} css
 * @returns {string[]}
 */
export function cssUrls(css) {
  const code = css.replace(/\/\*[\s\S]*?\*\//g, "");
  /** @type {string[]} */
  const urls = [];
  for (const m of code.matchAll(/url\(\s*(?:"([^"]*)"|'([^']*)'|([^)]*?))\s*\)/gi)) {
    urls.push((m[1] ?? m[2] ?? m[3] ?? "").trim());
  }
  for (const m of code.matchAll(/@import\s+(?:"([^"]*)"|'([^']*)')/gi)) {
    urls.push((m[1] ?? m[2] ?? "").trim());
  }
  return urls.filter((url) => url !== "");
}

/**
 * The stylesheet references that are not same-origin relative URLs (a third-party font or
 * imported stylesheet, but also data: — the policy allows neither).
 * @param {string} css
 * @returns {string[]}
 */
export function externalRefsInCss(css) {
  return cssUrls(css).filter((url) => !isRelativeSameOrigin(url));
}

/**
 * The same-origin URLs an HTML document loads on its own, for checking that they exist.
 * @param {string} html
 * @returns {string[]}
 */
export function localRefsInHtml(html) {
  return scanHtml(html).flatMap((el) =>
    loadedUrls(el)
      .map(({ url }) => url)
      .filter((url) => isRelativeSameOrigin(url) && !url.startsWith("#")),
  );
}

/**
 * Everything wrong with a shipped HTML document, as the policy for `kind` sees it. Empty
 * means: the document carries exactly that policy, early enough to govern all it loads, and
 * contains nothing the policy would refuse at run time or that reaches another origin.
 * @param {string} html
 * @param {PageKind} kind
 * @returns {string[]}
 */
export function auditDocument(html, kind) {
  /** @type {string[]} */
  const problems = [];
  const elements = scanHtml(html);

  const metas = elements.filter(isPolicyMeta);
  if (metas.length === 0) return [`no <meta http-equiv="${CSP_HEADER}">`];
  if (metas.length > 1) problems.push(`${metas.length} policy <meta> elements; expected one`);
  const meta = /** @type {HtmlElement} */ (metas[0]);
  const policy = meta.attrs["content"] ?? "";
  const sources = parsePolicy(policy);

  if (!meta.inHead) problems.push("the policy <meta> is not inside <head>");
  for (const el of elements) {
    if (el === meta) break;
    const harmless =
      el.name === "html" || el.name === "head" || (el.name === "meta" && "charset" in el.attrs);
    if (!harmless) {
      problems.push(`<${el.name}> comes before the policy <meta> and is not governed by it`);
    }
  }

  problems.push(...auditPolicy(policy));

  const allowedScripts = new Set(sources.get("script-src") ?? []);
  /** @type {string[]} */
  let hashes = [];
  try {
    hashes = inlineScriptHashes(elements);
  } catch (err) {
    problems.push(err instanceof Error ? err.message : String(err));
  }
  for (const hash of hashes) {
    if (!allowedScripts.has(hash)) {
      problems.push(`an inline script is not allowed by the policy (its hash is ${hash})`);
    }
  }
  const expected = buildPolicy(kind, hashes);
  if (policy !== expected) {
    problems.push(
      `the policy is not the ${kind} policy.\n  found:    ${policy}\n  expected: ${expected}`,
    );
  }

  // What the policy refuses at run time: catch it at build time instead.
  const styleAttr = sources.get("style-src-attr") ?? sources.get("style-src") ?? [];
  const styleElem = sources.get("style-src-elem") ?? sources.get("style-src") ?? [];
  for (const el of elements) {
    for (const attr of Object.keys(el.attrs)) {
      if (/^on[a-z]/.test(attr)) {
        problems.push(`<${el.name} ${attr}="…">: inline event handlers are refused by script-src`);
      }
    }
    if ("style" in el.attrs && !styleAttr.includes("'unsafe-inline'")) {
      problems.push(`<${el.name} style="…">: inline styles are refused by style-src`);
    }
    if (el.name === "style" && !styleElem.includes("'unsafe-inline'")) {
      problems.push("an inline <style> element is refused by style-src");
    }
    if (el.name === "base") problems.push("<base> is refused by base-uri 'none'");
    for (const attr of ["href", "xlink:href", "src", "action", "formaction"]) {
      if (/^\s*javascript:/i.test(el.attrs[attr] ?? "")) {
        problems.push(`<${el.name} ${attr}="javascript:…"> is refused by script-src`);
      }
    }
  }

  for (const ref of externalRefsInHtml(html)) {
    problems.push(`${ref} is not a same-origin relative reference`);
  }
  return problems;
}
