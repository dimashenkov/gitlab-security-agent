import type { Page } from 'playwright';

export interface LinksOptions {
  hrefPattern?: string;
  textPattern?: string;
  sameOriginOnly?: boolean;
  max?: number;
  includeUnlabeled?: boolean;
}

export interface LinkInfo {
  text: string;
  href: string;
  ref?: string;
}



const COLLECT_FN = `(opts) => {
  const { hrefPattern, textPattern, sameOriginOnly, framePrefix, pageOrigin, includeUnlabeled } = opts;

  // Substring by default. Regex only when wrapped /.../flags AND flags match
  // /^[gimsuy]*$/. Keeps slash-prefixed substrings like "/inventory/used"
  // from being parsed as pattern "inventory" with flags "used" (issue #21).
  let hrefTest;
  if (hrefPattern) {
    let rx = null;
    if (hrefPattern.length > 2 && hrefPattern.startsWith('/')) {
      const last = hrefPattern.lastIndexOf('/');
      if (last > 0) {
        const flags = hrefPattern.slice(last + 1);
        if (/^[gimsuy]*$/.test(flags)) {
          try {
            rx = new RegExp(hrefPattern.slice(1, last), flags);
          } catch (_e) {
            rx = null;
          }
        }
      }
    }
    if (rx) {
      hrefTest = (h) => rx.test(h || '');
    } else {
      hrefTest = (h) => (h || '').includes(hrefPattern);
    }
  } else {
    hrefTest = () => true;
  }

  const textTest = textPattern
    ? (t) => t.toLowerCase().includes(String(textPattern).toLowerCase())
    : () => true;

  const anchors = [];
  const stack = [document.documentElement];
  while (stack.length) {
    const n = stack.pop();
    if (n && n.nodeType === 1) {
      if (n.tagName === 'A') anchors.push(n);
      if (n.children) for (const c of Array.from(n.children)) stack.push(c);
      if (n.shadowRoot) for (const c of Array.from(n.shadowRoot.children)) stack.push(c);
    }
  }

  const out = [];
  for (const a of anchors) {
    const rawHref = a.getAttribute('href');
    if (!rawHref) continue;
    let href;
    try { href = new URL(rawHref, document.baseURI).href; } catch { continue; }
    if (!hrefTest(href)) continue;
    if (sameOriginOnly) {
      try {
        const u = new URL(href);
        if (u.origin !== pageOrigin) continue;
      } catch { continue; }
    }
    // Fallback chain: visible text → aria-label → title → alt of nested img.
    let text = (a.textContent || '').replace(/\\s+/g, ' ').trim();
    if (!text) text = (a.getAttribute('aria-label') || '').trim();
    if (!text) text = (a.getAttribute('title') || '').trim();
    if (!text) {
      const img = a.querySelector && a.querySelector('img[alt]');
      if (img) text = (img.getAttribute('alt') || '').trim();
    }
    const ref = a.getAttribute('data-browse-ref') || undefined;
    if (!text && includeUnlabeled) {
      // Final fallback: slug from href path's last meaningful segment.
      try {
        const u = new URL(href);
        const segs = u.pathname.split('/').filter(Boolean);
        let slug = segs.length ? segs[segs.length - 1] : '';
        // Strip trailing extension like .html, .php
        slug = slug.replace(/\\.[a-zA-Z0-9]{1,5}$/, '');
        try { slug = decodeURIComponent(slug); } catch (_e) {}
        slug = slug.replace(/[_-]+/g, ' ').trim();
        if (slug) text = slug;
      } catch (_e) {}
    }
    if (!text && !ref && !includeUnlabeled) continue;
    text = text.slice(0, 120);
    if (!textTest(text)) continue;
    const entry = { text, href };
    if (ref) entry.ref = framePrefix ? (ref) : ref;
    out.push(entry);
  }
  return out;
}`;

export async function collectLinks(page: Page, opts: LinksOptions): Promise<LinkInfo[]> {
  const max = opts.max ?? 200;
  const frames = page.frames();
  const mainOrigin = await page.evaluate(() => location.origin);
  const out: LinkInfo[] = [];
  const seen = new Set<string>();

  for (let i = 0; i < frames.length; i++) {
    if (out.length >= max) break;
    const frame = frames[i];
    const framePrefix = i === 0 ? '' : `f${i}`;

    if (i !== 0) {
      try {
        const url = frame.url();
        if (url && url !== 'about:blank') {
          const u = new URL(url);
          if (u.origin !== mainOrigin) continue;
        }
      } catch {
        continue;
      }
    }
    let items: LinkInfo[];
    try {
      items = (await frame.evaluate(
        `(${COLLECT_FN})(${JSON.stringify({
          hrefPattern: opts.hrefPattern,
          textPattern: opts.textPattern,
          sameOriginOnly: !!opts.sameOriginOnly,
          framePrefix,
          pageOrigin: mainOrigin,
          includeUnlabeled: !!opts.includeUnlabeled,
        })})`,
      )) as LinkInfo[];
    } catch {
      continue;
    }
    for (const it of items) {
      if (out.length >= max) break;
      const key = `${framePrefix}::${it.href}::${it.text}`;
      if (seen.has(key)) continue;
      seen.add(key);

      if (it.ref && framePrefix) it.ref = framePrefix + it.ref;
      out.push(it);
    }
  }
  return out;
}
