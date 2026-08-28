import type { Page, Frame } from 'playwright';

export interface FindOptions {
  text: string;
  role?: string;
  exact?: boolean;
  caseSensitive?: boolean;
  visible?: boolean;
}



const FIND_FN = `(opts) => {
  const { text, role, exact, caseSensitive, visible } = opts;
  const q = caseSensitive ? text : text.toLowerCase();

  const isVisible = (el) => {
    try {
      const r = el.getBoundingClientRect();
      if (r.width === 0 || r.height === 0) return false;
      const s = getComputedStyle(el);
      if (s.visibility === 'hidden' || s.display === 'none' || s.opacity === '0') return false;
      return true;
    } catch { return false; }
  };

  const roleMatches = (el) => {
    if (!role) return true;
    const explicit = el.getAttribute && el.getAttribute('role');
    if (explicit === role) return true;
    const tagRoleMap = { button: ['BUTTON'], link: ['A'], textbox: ['INPUT','TEXTAREA'], heading: ['H1','H2','H3','H4','H5','H6'] };
    const tags = tagRoleMap[role];
    if (tags && tags.includes(el.tagName)) return true;
    return false;
  };

  const textMatches = (s) => {
    const sn = caseSensitive ? s : s.toLowerCase();
    return exact ? sn.trim() === q : sn.includes(q);
  };

  const check = (el) => {
    if (visible !== false && !isVisible(el)) return false;
    if (!roleMatches(el)) return false;
    const aria = (el.getAttribute && el.getAttribute('aria-label')) || '';
    if (aria && textMatches(aria)) return true;
    const title = (el.getAttribute && el.getAttribute('title')) || '';
    if (title && textMatches(title)) return true;
    const placeholder = (el.getAttribute && el.getAttribute('placeholder')) || '';
    if (placeholder && textMatches(placeholder)) return true;
    // Use direct text (trim) only — avoid matching ancestors with huge textContent
    let direct = '';
    for (const c of el.childNodes) if (c.nodeType === 3) direct += c.textContent;
    direct = direct.trim();
    if (direct && textMatches(direct)) return true;
    // Fallback: full textContent for small elements only
    const tc = (el.textContent || '').trim();
    if (tc && tc.length < 200 && textMatches(tc)) return true;
    return false;
  };

  const stack = [document.documentElement];
  while (stack.length) {
    const n = stack.pop();
    if (n && n.nodeType === 1) {
      if (check(n)) {
        // Mark with a unique attribute so Playwright can locate it
        const marker = 'find-' + Date.now() + '-' + Math.random().toString(36).slice(2, 8);
        n.setAttribute('data-browse-find', marker);
        return {
          marker,
          tag: n.tagName,
          role: (n.getAttribute && n.getAttribute('role')) || '',
          text: (n.textContent || '').trim().slice(0, 100),
        };
      }
      if (n.children) for (const c of Array.from(n.children)) stack.push(c);
      if (n.shadowRoot) for (const c of Array.from(n.shadowRoot.children)) stack.push(c);
    }
  }
  return null;
}`;

export interface FoundElement {
  marker: string;
  tag: string;
  role: string;
  text: string;
  frame: Frame;
  selector: string;
}

export async function findByText(page: Page, opts: FindOptions): Promise<FoundElement | null> {

  for (const frame of page.frames()) {
    try {
      const result = (await frame.evaluate(`(${FIND_FN})(${JSON.stringify(opts)})`)) as {
        marker: string;
        tag: string;
        role: string;
        text: string;
      } | null;
      if (result) {
        return {
          ...result,
          frame,
          selector: `[data-browse-find="${result.marker}"]`,
        };
      }
    } catch {

    }
  }
  return null;
}

export async function waitForText(
  page: Page,
  opts: FindOptions,
  timeoutMs: number,
): Promise<FoundElement> {
  const start = Date.now();
  const pollInterval = 250;
  while (Date.now() - start < timeoutMs) {
    const hit = await findByText(page, opts);
    if (hit) return hit;
    await new Promise((r) => setTimeout(r, pollInterval));
  }
  throw new Error(`Timed out after ${timeoutMs}ms waiting for text ${JSON.stringify(opts.text)}`);
}
