import type { Page, Frame, Locator } from 'playwright';

export interface SnapshotOptions {
  interactive?: boolean;
  maxDepth?: number;
  selector?: string;
  cursorInteractive?: boolean;
  noCollapse?: boolean;
}




const PAGE_FN = `(framePrefix, scopeSelector) => {
  const INTERACTIVE_TAGS = new Set(['A','BUTTON','INPUT','TEXTAREA','SELECT','SUMMARY','OPTION']);
  const INTERACTIVE_ROLES = new Set(['button','link','textbox','checkbox','radio','combobox','menuitem','option','searchbox','switch','tab']);

  const isVisible = (el) => {
    try {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none' || s.opacity === '0') return false;
      return true;
    } catch { return false; }
  };

  const isInteractive = (el) => {
    if (INTERACTIVE_TAGS.has(el.tagName)) return true;
    const role = el.getAttribute && el.getAttribute('role');
    if (role && INTERACTIVE_ROLES.has(role)) return true;
    if (el.hasAttribute && el.hasAttribute('onclick')) return true;
    if (typeof el.tabIndex === 'number' && el.tabIndex >= 0 && el.tagName !== 'DIV' && el.tagName !== 'SPAN') return true;
    return false;
  };

  const NOISE_NAME_TAGS = new Set(['SCRIPT','STYLE','NOSCRIPT','TEMPLATE','LINK']);
  const looksLikeCode = (s) => {
    if (!s) return false;
    if (s.length > 200 && /[{};=]/.test(s) && !/\\s[A-Za-z]{3,}\\s[A-Za-z]{3,}/.test(s.slice(0, 200))) return true;
    return /^(\\(function|function\\s*\\(|!function|var\\s|let\\s|const\\s|window\\.|document\\.|@media|@keyframes|@import|@font-face|body\\s*\\{|html\\s*\\{|\\.[\\w-]+\\s*\\{|#[\\w-]+\\s*\\{|\\/\\*)/.test(s);
  };
  // Collect text content skipping script/style/noscript/template descendants.
  const textExcludingNoise = (el, limit) => {
    let t = '';
    const stack = [el];
    while (stack.length && t.length < limit) {
      const n = stack.pop();
      if (!n) continue;
      if (n.nodeType === 3) { t += n.textContent || ''; continue; }
      if (n.nodeType !== 1) continue;
      if (NOISE_NAME_TAGS.has(n.tagName)) continue;
      if (n.childNodes) for (let i = n.childNodes.length - 1; i >= 0; i--) stack.push(n.childNodes[i]);
    }
    return t;
  };

  const accName = (el) => {
    try {
      if (NOISE_NAME_TAGS.has(el.tagName)) return '';
      if (el.getAttribute('aria-label')) return el.getAttribute('aria-label').trim();
      if (el.tagName === 'INPUT' && el.labels && el.labels[0]) return el.labels[0].textContent.trim();
      if (el.getAttribute('placeholder')) return el.getAttribute('placeholder').trim();
      if (el.getAttribute('alt')) return el.getAttribute('alt').trim();
      if (el.getAttribute('title')) return el.getAttribute('title').trim();
      let t = '';
      for (const c of el.childNodes) {
        if (c.nodeType === 3) t += c.textContent;
        else if (c.nodeType === 1 && NOISE_NAME_TAGS.has(c.tagName)) continue;
      }
      t = t.trim();
      if (t) return t.slice(0, 100);
      const full = textExcludingNoise(el, 200).trim();
      if (looksLikeCode(full)) return '';
      return full.slice(0, 80);
    } catch { return ''; }
  };

  const roleOf = (el) => {
    const explicit = el.getAttribute && el.getAttribute('role');
    if (explicit) return explicit;
    const t = el.tagName;
    if (t === 'A') return el.getAttribute('href') ? 'link' : 'generic';
    if (t === 'BUTTON') return 'button';
    if (t === 'INPUT') {
      const ty = (el.getAttribute('type') || 'text').toLowerCase();
      if (ty === 'checkbox') return 'checkbox';
      if (ty === 'radio') return 'radio';
      if (ty === 'submit' || ty === 'button') return 'button';
      return 'textbox';
    }
    if (t === 'TEXTAREA') return 'textbox';
    if (t === 'SELECT') return 'combobox';
    if (t === 'IMG') return 'img';
    if (/^H[1-6]$/.test(t)) return 'heading';
    if (t === 'NAV') return 'navigation';
    if (t === 'MAIN') return 'main';
    if (t === 'HEADER') return 'banner';
    if (t === 'FOOTER') return 'contentinfo';
    if (t === 'UL' || t === 'OL') return 'list';
    if (t === 'LI') return 'listitem';
    if (t === 'FORM') return 'form';
    if (t === 'LABEL') return 'label';
    if (t === 'IFRAME') return 'iframe';
    return 'generic';
  };

  // First pass: strip old refs across the whole frame (incl. shadow roots)
  const stripAll = (root) => {
    const stack = [root];
    while (stack.length) {
      const node = stack.pop();
      if (node.nodeType === 1) {
        if (node.hasAttribute && node.hasAttribute('data-browse-ref')) node.removeAttribute('data-browse-ref');
      }
      if (node.children) for (const c of Array.from(node.children)) stack.push(c);
      if (node.shadowRoot) for (const c of Array.from(node.shadowRoot.children)) stack.push(c);
    }
  };
  stripAll(document.documentElement);

  // Second pass: tag interactive visible elements (@e) and cursor-pointer
  // non-interactive elements (@c — useful for React apps that skip semantic HTML).
  let eCounter = 0, cCounter = 0;
  const tag = (root) => {
    const stack = [root];
    while (stack.length) {
      const node = stack.pop();
      if (node.nodeType === 1 && isVisible(node)) {
        if (isInteractive(node)) {
          node.setAttribute('data-browse-ref', framePrefix + 'e' + (++eCounter));
        } else {
          try {
            const s = getComputedStyle(node);
            if (s.cursor === 'pointer') {
              node.setAttribute('data-browse-ref', framePrefix + 'c' + (++cCounter));
            }
          } catch {}
        }
      }
      if (node.children) for (const c of Array.from(node.children)) stack.push(c);
      if (node.shadowRoot) for (const c of Array.from(node.shadowRoot.children)) stack.push(c);
    }
  };
  tag(document.documentElement);
  const counter = eCounter;
  const cursorCounter = cCounter;

  // Third pass: build text tree (pierce shadow DOM, mark iframes as leaves)
  const SKIP_TAGS = new Set(['SCRIPT','STYLE','NOSCRIPT','META','LINK','HEAD','TEMPLATE']);
  const build = (el, depth) => {
    if (!el || el.nodeType !== 1) return null;
    if (SKIP_TAGS.has(el.tagName)) return null;
    if (!isVisible(el) && el.tagName !== 'BODY' && el.tagName !== 'HTML') return null;
    const ref = el.getAttribute && el.getAttribute('data-browse-ref');
    const interactive = !!ref;
    const role = roleOf(el);
    const name = accName(el);
    const node = {
      ref,
      tag: el.tagName,
      role,
      name,
      interactive,
      isIframe: el.tagName === 'IFRAME',
      iframeSrc: el.tagName === 'IFRAME' ? (el.getAttribute('src') || '') : undefined,
      children: [],
      shadow: !!el.shadowRoot,
    };
    // Regular children
    if (el.children) for (const c of Array.from(el.children)) {
      const sub = build(c, depth + 1);
      if (sub) node.children.push(sub);
    }
    // Shadow root children merged in-line
    if (el.shadowRoot && el.shadowRoot.children) {
      for (const c of Array.from(el.shadowRoot.children)) {
        const sub = build(c, depth + 1);
        if (sub) node.children.push(sub);
      }
    }
    return node;
  };

  let rootEl = document.documentElement;
  let scopeMatched = true;
  if (scopeSelector) {
    try {
      const match = document.querySelector(scopeSelector);
      if (match) { rootEl = match; scopeMatched = true; }
      else { scopeMatched = false; }
    } catch { scopeMatched = false; }
  }
  const tree = scopeMatched ? build(rootEl, 0) : null;
  const iframes = [];
  if (document.querySelectorAll) {
    document.querySelectorAll('iframe').forEach((f, i) => {
      iframes.push({ index: i, src: f.getAttribute('src') || '' });
    });
  }
  return { tree, iframes, tagged: counter, cursorTagged: cursorCounter, scopeMatched };
}`;

interface FrameResult {
  tree: any;
  iframes: { index: number; src: string }[];
  tagged: number;
  scopeMatched?: boolean;
}

interface FrameData {
  framePrefix: string;
  frame: Frame;
  url: string;
  result: FrameResult;
}

async function runInFrame(
  frame: Frame,
  framePrefix: string,
  scopeSelector?: string,
): Promise<FrameData | null> {
  try {
    const args = `${JSON.stringify(framePrefix)}, ${JSON.stringify(scopeSelector || '')}`;
    const result = (await frame.evaluate(`(${PAGE_FN})(${args})`)) as FrameResult;
    return { framePrefix, frame, url: frame.url(), result };
  } catch {
    return null;
  }
}

export async function collectFrames(page: Page, scopeSelector?: string): Promise<FrameData[]> {
  const frames = page.frames();
  const out: FrameData[] = [];
  for (let i = 0; i < frames.length; i++) {
    const f = frames[i];

    const prefix = i === 0 ? '' : `f${i}`;

    const data = await runInFrame(f, prefix, i === 0 ? scopeSelector : undefined);
    if (data) out.push(data);
  }
  return out;
}

function isCursorRef(ref: string | undefined): boolean {
  if (!ref) return false;

  return /^(?:f\d+)?c\d+$/.test(ref);
}



const CODE_LIKE_RE =
  /^(\(function|function\s*\(|!function|var\s|let\s|const\s|window\.|document\.|@media|@keyframes|@import|@font-face|body\s*\{|html\s*\{|\.[\w-]+\s*\{|#[\w-]+\s*\{|\/\*)/;
function isNoisyName(role: string, name: string): boolean {
  if (role !== 'generic' || !name) return false;
  if (CODE_LIKE_RE.test(name)) return true;
  if (name.length > 200 && /[{};=]/.test(name)) return true;
  return false;
}



const STRUCTURAL_ROLES = new Set([
  'heading',
  'navigation',
  'main',
  'banner',
  'contentinfo',
  'complementary',
  'region',
  'form',
  'search',
  'list',
  'listitem',
  'article',
  'section',
]);




function isCollapsibleGeneric(node: any): boolean {
  if (!node || node.role !== 'generic') return false;
  if (node.ref) return false;
  if (node.isIframe || node.shadow) return false;
  if (!node.children || node.children.length !== 1) return false;
  const child = node.children[0];
  if (!child) return false;
  const cleanName =
    node.name && !isNoisyName(node.role, String(node.name)) ? String(node.name).trim() : '';
  if (!cleanName) return true;


  const childName = child.name ? String(child.name).trim() : '';
  if (childName && cleanName === childName) return true;
  return false;
}

export function renderTree(
  node: any,
  opts: {
    interactive?: boolean;
    maxDepth?: number;
    cursorInteractive?: boolean;
    noCollapse?: boolean;
  } = {},
  depth = 0,
): string {
  if (!node) return '';


  if (!opts.noCollapse) {
    while (isCollapsibleGeneric(node)) {
      node = node.children[0];
    }
  }
  const lines: string[] = [];

  const refIsCursor = isCursorRef(node.ref);
  const effectivelyInteractive = node.interactive && (!refIsCursor || opts.cursorInteractive);
  const showThis =
    !opts.interactive ||
    effectivelyInteractive ||
    node.role === 'heading' ||
    hasInteractiveDescendant(node, opts.cursorInteractive);

  if (showThis) {
    const indent = '  '.repeat(depth);
    const refStr = node.ref ? `@${node.ref} ` : '';
    const cleanName =
      node.name && !isNoisyName(node.role, String(node.name)) ? String(node.name) : '';
    const nameStr = cleanName ? ` "${cleanName.replace(/\s+/g, ' ').slice(0, 80)}"` : '';
    const levelAttr = typeof node.tag === 'string' ? node.tag.match(/^H(\d)$/) : null;
    const extra: string[] = [];
    if (levelAttr) extra.push(`level=${levelAttr[1]}`);
    if (node.shadow) extra.push('shadow');
    if (node.isIframe) extra.push(`iframe src="${(node.iframeSrc || '').slice(0, 60)}"`);
    const extraStr = extra.length ? ` [${extra.join(' ')}]` : '';
    lines.push(`${indent}${refStr}[${node.role}]${nameStr}${extraStr}`);
  }

  if (node.children && (opts.maxDepth === undefined || depth < opts.maxDepth)) {


    let prevFirstLine: string | null = null;
    for (const c of node.children) {
      const sub = renderTree(c, opts, depth + 1);
      if (!sub) continue;
      const firstLine = sub.split('\n', 1)[0];
      if (
        !opts.noCollapse &&
        prevFirstLine !== null &&
        firstLine === prevFirstLine &&

        /^\s*\[generic\]/.test(firstLine) &&
        sub === firstLine
      ) {
        continue;
      }
      lines.push(sub);
      prevFirstLine = firstLine;
    }
  }
  return lines.join('\n');
}



export { STRUCTURAL_ROLES };

function hasInteractiveDescendant(node: any, includeCursor = false): boolean {
  if (!node.children) return false;
  for (const c of node.children) {
    if (c.interactive && (includeCursor || !isCursorRef(c.ref))) return true;
    if (hasInteractiveDescendant(c, includeCursor)) return true;
  }
  return false;
}

export async function snapshot(page: Page, opts: SnapshotOptions = {}): Promise<string> {
  const frames = await collectFrames(page, opts.selector);
  if (frames.length === 0) return '(no frames)';


  if (opts.selector) {
    const main = frames.find((f) => f.framePrefix === '');
    if (main && main.result && main.result.scopeMatched === false) {
      return `(no element matched selector ${JSON.stringify(opts.selector)})`;
    }
  }

  const parts: string[] = [];
  for (const fd of frames) {
    if (!fd.result?.tree) continue;
    const renderOpts = {
      interactive: opts.interactive,
      maxDepth: opts.maxDepth,
      cursorInteractive: opts.cursorInteractive,
      noCollapse: opts.noCollapse,
    };
    if (fd.framePrefix === '') {
      const rendered = renderTree(fd.result.tree, renderOpts);
      if (rendered.trim()) parts.push(rendered);
    } else {

      if (opts.selector) continue;
      const rendered = renderTree(fd.result.tree, renderOpts);
      if (rendered.trim()) {
        parts.push(`\n--- frame ${fd.framePrefix} (${fd.url}) ---\n${rendered}`);
      }
    }
  }
  return parts.join('\n') || '(empty)';
}

export interface ResolvedRef {
  frame: Frame;
  selector: string;
}

export function parseRef(ref: string): { frameIdx: number; local: string } {
  const r = ref.startsWith('@') ? ref.slice(1) : ref;
  const m = r.match(/^f(\d+)(e\d+)$/);
  if (m) return { frameIdx: parseInt(m[1], 10), local: m[2] };
  return { frameIdx: 0, local: r };
}

export async function resolveRef(
  page: Page,
  ref: string,
): Promise<{ locator: Locator; selector: string; frameIdx: number }> {
  const { frameIdx, local } = parseRef(ref);
  const frames = page.frames();
  if (frameIdx < 0 || frameIdx >= frames.length) {
    throw new Error(`Frame index ${frameIdx} not found (page has ${frames.length} frames)`);
  }
  const frame = frames[frameIdx];
  const prefix = frameIdx === 0 ? '' : `f${frameIdx}`;
  const selector = `[data-browse-ref="${prefix}${local}"]`;
  return { locator: frame.locator(selector), selector, frameIdx };
}
