import type { Page } from 'playwright';

export interface ExtractOptions {
  hrefPattern?: string;
  requireText?: string;
  containerSelector?: string;
  groupBy?: 'href' | 'row' | 'auto';
}

export interface LinkInfo {
  text: string;
  href: string;
}

export interface Listing {
  href: string;
  title: string;
  text: string;
  year: number | null;
  price: string | null;
  distanceMi: number | null;
  location: string | null;
  imageUrl: string | null;
  isNew: boolean;
  isUsed: boolean;
  meta?: LinkInfo[];
}











const COLLECT_FN = `(opts) => {
  const { hrefPattern, requireText, containerSelector, groupBy } = opts;
  const mode = groupBy || 'auto';

  // Build href matcher. Treat as substring by default. Switch to regex ONLY
  // when the input is wrapped /.../flags AND flags validate against
  // /^[gimsuy]*$/ — otherwise a value like "/inventory/used" would be parsed
  // as pattern "inventory" with flags "used", which throws (issue #21).
  let hrefTest;
  if (hrefPattern) {
    let regex = null;
    if (hrefPattern.length > 2 && hrefPattern.startsWith('/')) {
      const last = hrefPattern.lastIndexOf('/');
      if (last > 0) {
        const flags = hrefPattern.slice(last + 1);
        if (/^[gimsuy]*$/.test(flags)) {
          try {
            regex = new RegExp(hrefPattern.slice(1, last), flags);
          } catch (_e) {
            regex = null;
          }
        }
      }
    }
    if (regex) {
      hrefTest = (h) => regex.test(h || '');
    } else {
      hrefTest = (h) => (h || '').includes(hrefPattern);
    }
  } else {
    hrefTest = () => true;
  }

  const textTest = requireText
    ? (t) => t.toLowerCase().includes(requireText.toLowerCase())
    : () => true;

  // Collect all anchors from main doc + shadow roots, scoped if requested
  const rootEls = containerSelector
    ? Array.from(document.querySelectorAll(containerSelector))
    : [document.documentElement];

  const anchors = [];
  for (const root of rootEls) {
    const stack = [root];
    while (stack.length) {
      const n = stack.pop();
      if (n && n.nodeType === 1) {
        if (n.tagName === 'A') anchors.push(n);
        if (n.children) for (const c of Array.from(n.children)) stack.push(c);
        if (n.shadowRoot) for (const c of Array.from(n.shadowRoot.children)) stack.push(c);
      }
    }
  }

  // Keep only anchors matching the filters
  const matched = [];
  for (const a of anchors) {
    const rawHref = a.getAttribute('href') || '';
    const href = a.href || rawHref;
    if (!hrefTest(rawHref) && !hrefTest(href)) continue;
    const text = (a.textContent || '').replace(/\\s+/g, ' ').trim();
    matched.push({ el: a, href, text });
  }

  // Structured parsing over an element + its text
  function parseListing(href, title, text, rootEl, metaLinks) {
    const yearMatch = text.match(/\\b(19|20)\\d{2}\\b/);
    const year = yearMatch ? parseInt(yearMatch[0], 10) : null;
    const priceMatch = text.match(/\\$[\\d,]+(?:\\.\\d{2})?/);
    const distMatch = text.match(/\\((\\d+(?:\\.\\d+)?)\\s*mi\\)/i) || text.match(/\\b(\\d+(?:\\.\\d+)?)\\s*mi(?:les?)?\\b/i);
    const locMatch = text.match(/\\b([A-Z][A-Za-z]+(?:\\s[A-Z][A-Za-z]+)*),\\s*([A-Z]{2})\\b/);
    const imgEl = rootEl && rootEl.querySelector ? rootEl.querySelector('img') : null;
    const imageUrl = imgEl ? (imgEl.src || imgEl.getAttribute('data-src') || null) : null;
    const isNew = /\\bNew\\b/.test(' ' + text + ' ') && !/Used|Pre-?owned/i.test(text);
    const isUsed = /\\bUsed\\b|Pre-?owned/i.test(text);
    const out = {
      href,
      title,
      text: text.slice(0, 500),
      year,
      price: priceMatch ? priceMatch[0] : null,
      distanceMi: distMatch ? parseFloat(distMatch[1]) : null,
      location: locMatch ? locMatch[1] + ', ' + locMatch[2] : null,
      imageUrl,
      isNew,
      isUsed,
    };
    if (metaLinks && metaLinks.length) out.meta = metaLinks;
    return out;
  }

  // ---- 'href' mode ----
  function runHrefMode() {
    const byHref = new Map();
    for (const m of matched) {
      const prev = byHref.get(m.href);
      if (!prev || m.text.length > prev.text.length) byHref.set(m.href, m);
    }
    const listings = [];
    for (const [href, { el, text }] of byHref.entries()) {
      if (!textTest(text)) continue;
      const titleSpan = el.querySelector ? el.querySelector('[class*="title"], [title]') : null;
      const title = titleSpan
        ? (titleSpan.getAttribute('title') || titleSpan.textContent || '').replace(/\\s+/g, ' ').trim()
        : text.slice(0, 100);
      listings.push(parseListing(href, title, text, el, null));
    }
    return listings;
  }

  // ---- 'row' mode ----
  // Signature for an element: tag plus sorted class list. Anchors or
  // text-node-only divs don't make good row containers; we want the repeated
  // structural wrapper (e.g. tr.athing, li.row, article.post).
  function sig(el) {
    if (!el || el.nodeType !== 1) return '';
    const cls = (el.className && typeof el.className === 'string')
      ? el.className.trim().split(/\\s+/).filter(Boolean).sort().join('.')
      : '';
    return el.tagName + (cls ? '.' + cls : '');
  }

  const JUNK_RE = /^(?:\\s*)(?:\\d+(?:[.,]\\d+)?\\s*(?:points?|pts?|votes?)?|\\d+\\s*(?:comments?|replies?|reply)|comments?|reply|replies|share|save|hide|flag|report|edit|delete|permalink|source|discuss|via|tags?|read more|more|\\d+\\s*(?:second|minute|hour|day|week|month|year)s?\\s*ago|just now|yesterday|today)(?:\\s*)$/i;

  function isJunkTitle(t) {
    if (!t) return true;
    if (/^\\s*\\d+\\s*$/.test(t)) return true;                   // pure number
    if (/\\bago\\b/i.test(t) && t.length < 40) return true;      // relative time
    if (/^\\s*(?:just now|yesterday|today)\\s*$/i.test(t)) return true;
    if (JUNK_RE.test(t)) return true;
    return false;
  }

  function runRowMode() {
    if (matched.length < 3) return null;

    // For each anchor, walk ancestors; at each level count how many OTHER
    // matched anchors sit under an ancestor-at-same-depth with the same
    // signature. The shallowest level where the repeat count >= 3 is the
    // row template for that anchor.
    // Implementation: build a map (signature -> Set<ancestor-element>) for
    // ancestor elements containing any matched anchor. Then for each anchor,
    // walk up and stop at the first ancestor whose signature bucket has >= 3
    // distinct elements. That ancestor is the row.

    // Collect ancestors (up to 8 levels) per matched anchor.
    const sigBuckets = new Map(); // sig -> Set<Element>
    const ancestorsPerAnchor = [];
    for (const m of matched) {
      const chain = [];
      let cur = m.el.parentElement;
      let depth = 0;
      while (cur && depth < 8) {
        chain.push(cur);
        const s = sig(cur);
        if (s) {
          let set = sigBuckets.get(s);
          if (!set) { set = new Set(); sigBuckets.set(s, set); }
          set.add(cur);
        }
        cur = cur.parentElement;
        depth++;
      }
      ancestorsPerAnchor.push(chain);
    }

    // Pick row per anchor: shallowest ancestor whose signature repeats >= 3
    // times and whose signature isn't trivial (empty/no class on bare div/span
    // which would match the whole page).
    function rowFor(chain) {
      for (const anc of chain) {
        const s = sig(anc);
        if (!s) continue;
        // Skip ancestors with no class that are generic containers — they'd
        // group everything together. Exception: structural tags like LI, TR,
        // ARTICLE are fine with no class.
        const hasClass = s.indexOf('.') !== -1;
        const tag = anc.tagName;
        const structural = tag === 'LI' || tag === 'TR' || tag === 'ARTICLE' || tag === 'SECTION';
        if (!hasClass && !structural) continue;
        const bucket = sigBuckets.get(s);
        if (bucket && bucket.size >= 3) return anc;
      }
      return null;
    }

    const rowMap = new Map(); // row element -> { row, anchors: [matched] }
    for (let i = 0; i < matched.length; i++) {
      const row = rowFor(ancestorsPerAnchor[i]);
      if (!row) continue;
      let entry = rowMap.get(row);
      if (!entry) { entry = { row, anchors: [] }; rowMap.set(row, entry); }
      entry.anchors.push(matched[i]);
    }

    if (rowMap.size < 2) return null; // detection failed

    const listings = [];
    for (const { row, anchors: rowAnchors } of rowMap.values()) {
      // Pick title anchor: longest non-junk text.
      let title = null;
      let best = null;
      for (const a of rowAnchors) {
        if (isJunkTitle(a.text)) continue;
        if (!best || a.text.length > best.text.length) best = a;
      }
      if (!best) continue; // all junk -> skip row
      title = best.text;
      const rowText = (row.textContent || '').replace(/\\s+/g, ' ').trim();
      if (!textTest(rowText)) continue;

      const meta = [];
      for (const a of rowAnchors) {
        if (a === best) continue;
        if (!a.text) continue;
        meta.push({ text: a.text, href: a.href });
      }

      listings.push(parseListing(best.href, title.slice(0, 200), rowText, row, meta));
    }
    return listings;
  }

  if (mode === 'href') {
    return runHrefMode();
  }
  if (mode === 'row') {
    const r = runRowMode();
    return r || [];
  }
  // auto
  const hrefOut = runHrefMode();
  const rowOut = runRowMode();
  if (rowOut && rowOut.length >= Math.ceil(hrefOut.length / 3) && rowOut.length > 0) {
    return rowOut;
  }
  return hrefOut;
}`;

export async function extractListings(page: Page, opts: ExtractOptions = {}): Promise<Listing[]> {
  const result = (await page.evaluate(`(${COLLECT_FN})(${JSON.stringify(opts)})`)) as Listing[];
  return result;
}
