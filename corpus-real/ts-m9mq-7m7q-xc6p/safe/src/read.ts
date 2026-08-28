import type { Page } from 'playwright';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';








const require_ = createRequire(import.meta.url);
let readabilitySrc: string | null = null;

function loadReadability(): string {
  if (readabilitySrc) return readabilitySrc;
  const path = require_.resolve('@mozilla/readability/Readability.js');
  readabilitySrc = readFileSync(path, 'utf8');
  return readabilitySrc;
}

export interface ReadabilityArticle {
  title: string;
  byline: string | null;
  siteName: string | null;
  lang: string | null;
  content: string;
  textContent: string;
  length: number;
  excerpt: string | null;
}

export interface ReadOptions {
  url?: string;
  format?: 'markdown' | 'text' | 'json';
}

export async function readArticle(
  page: Page,
  opts: ReadOptions,
): Promise<ReadabilityArticle | null> {
  if (opts.url) {
    await page.goto(opts.url, { waitUntil: 'domcontentloaded' });
  }
  const src = loadReadability();




  const expr = `(() => {
    try {
      ${src}
    } catch (_e) {
      return { __readError: 'inject failed: ' + (_e && _e.message ? _e.message : String(_e)) };
    }
    const R = (window && window.Readability) || (typeof Readability !== 'undefined' ? Readability : null);
    if (!R) return null;
    try {
      const clone = document.cloneNode(true);
      const parsed = new R(clone).parse();
      if (!parsed) return null;
      return {
        title: parsed.title || '',
        byline: parsed.byline || null,
        siteName: parsed.siteName || null,
        lang: parsed.lang || document.documentElement.lang || null,
        content: parsed.content || '',
        textContent: parsed.textContent || '',
        length: parsed.length || 0,
        excerpt: parsed.excerpt || null,
      };
    } catch (_e) {
      return null;
    }
  })()`;
  const result = (await page.evaluate(expr)) as
    | (ReadabilityArticle & { __readError?: string })
    | null;
  if (result && (result as any).__readError) return null;
  return result as ReadabilityArticle | null;
}


export function htmlToMarkdown(html: string): string {




  const tokens = tokenize(html);
  const root: Node = { type: 'elem', tag: 'root', attrs: {}, children: [] };
  const stack: Node[] = [root];
  const VOID = new Set(['br', 'img', 'hr', 'meta', 'link', 'input']);
  for (const tok of tokens) {
    const top = stack[stack.length - 1];
    if (tok.type === 'text') {
      top.children!.push({ type: 'text', value: tok.value });
    } else if (tok.type === 'open') {
      const node: Node = { type: 'elem', tag: tok.tag, attrs: tok.attrs, children: [] };
      top.children!.push(node);
      if (!VOID.has(tok.tag) && !tok.selfClosing) stack.push(node);
    } else if (tok.type === 'close') {

      for (let i = stack.length - 1; i > 0; i--) {
        if (stack[i].tag === tok.tag) {
          stack.length = i;
          break;
        }
      }
    }
  }
  return (
    render(root)
      .replace(/\n{3,}/g, '\n\n')
      .trim() + '\n'
  );
}

interface Node {
  type: 'elem' | 'text';
  tag?: string;
  attrs?: Record<string, string>;
  children?: Node[];
  value?: string;
}

type Token =
  | { type: 'text'; value: string }
  | { type: 'open'; tag: string; attrs: Record<string, string>; selfClosing: boolean }
  | { type: 'close'; tag: string };

function tokenize(html: string): Token[] {
  const out: Token[] = [];
  let i = 0;
  while (i < html.length) {
    if (html[i] === '<') {

      if (html.startsWith('<!--', i)) {
        const end = html.indexOf('-->', i + 4);
        i = end === -1 ? html.length : end + 3;
        continue;
      }

      if (html[i + 1] === '!') {
        const end = html.indexOf('>', i);
        i = end === -1 ? html.length : end + 1;
        continue;
      }
      const end = html.indexOf('>', i);
      if (end === -1) {
        out.push({ type: 'text', value: html.slice(i) });
        break;
      }
      const raw = html.slice(i + 1, end);
      i = end + 1;
      if (raw.startsWith('/')) {
        out.push({ type: 'close', tag: raw.slice(1).trim().toLowerCase() });
      } else {
        const selfClosing = raw.endsWith('/');
        const body = selfClosing ? raw.slice(0, -1) : raw;
        const m = body.match(/^([a-zA-Z][a-zA-Z0-9-]*)\s*([\s\S]*)$/);
        if (!m) continue;
        const tag = m[1].toLowerCase();
        const attrs = parseAttrs(m[2]);
        out.push({ type: 'open', tag, attrs, selfClosing });
      }
    } else {
      const next = html.indexOf('<', i);
      const end = next === -1 ? html.length : next;
      const value = html.slice(i, end);
      if (value) out.push({ type: 'text', value: decodeEntities(value) });
      i = end;
    }
  }
  return out;
}

function parseAttrs(s: string): Record<string, string> {
  const out: Record<string, string> = {};
  const re = /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*(?:=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const name = m[1].toLowerCase();
    const value = m[2] ?? m[3] ?? m[4] ?? '';
    out[name] = decodeEntities(value);
  }
  return out;
}

function decodeEntities(s: string): string {
  return s
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, ' ')
    .replace(/&#(\d+);/g, (_, n) => String.fromCharCode(parseInt(n, 10)))
    .replace(/&#x([0-9a-f]+);/gi, (_, n) => String.fromCharCode(parseInt(n, 16)));
}

function render(
  node: Node,
  ctx: { listType?: 'ul' | 'ol'; listIndex?: number; inPre?: boolean } = {},
): string {
  if (node.type === 'text') {
    const v = node.value || '';
    return ctx.inPre ? v : v.replace(/\s+/g, ' ');
  }
  const tag = node.tag!;
  const kids = node.children || [];
  const inner = (c: typeof ctx) => kids.map((k) => render(k, c)).join('');
  switch (tag) {
    case 'root':
      return inner(ctx);
    case 'h1':
      return `\n\n# ${inner(ctx).trim()}\n\n`;
    case 'h2':
      return `\n\n## ${inner(ctx).trim()}\n\n`;
    case 'h3':
      return `\n\n### ${inner(ctx).trim()}\n\n`;
    case 'h4':
      return `\n\n#### ${inner(ctx).trim()}\n\n`;
    case 'h5':
      return `\n\n##### ${inner(ctx).trim()}\n\n`;
    case 'h6':
      return `\n\n###### ${inner(ctx).trim()}\n\n`;
    case 'p':
      return `\n\n${inner(ctx).trim()}\n\n`;
    case 'br':
      return '  \n';
    case 'hr':
      return '\n\n---\n\n';
    case 'strong':
    case 'b':
      return `**${inner(ctx)}**`;
    case 'em':
    case 'i':
      return `*${inner(ctx)}*`;
    case 'a': {
      const href = node.attrs?.href || '';
      const txt = inner(ctx).trim() || href;
      return href ? `[${txt}](${href})` : txt;
    }
    case 'img': {
      const alt = node.attrs?.alt || '';
      const src = node.attrs?.src || '';
      if (!src && !alt) return '';
      return `![${alt}](${src})`;
    }
    case 'ul': {
      const items = kids
        .filter((k) => k.type === 'elem' && k.tag === 'li')
        .map((k) => `- ${render(k, { listType: 'ul' }).trim().replace(/\n/g, '\n  ')}`)
        .join('\n');
      return `\n\n${items}\n\n`;
    }
    case 'ol': {
      let n = 0;
      const items = kids
        .filter((k) => k.type === 'elem' && k.tag === 'li')
        .map((k) => `${++n}. ${render(k, { listType: 'ol' }).trim().replace(/\n/g, '\n   ')}`)
        .join('\n');
      return `\n\n${items}\n\n`;
    }
    case 'li':
      return inner(ctx);
    case 'blockquote': {
      const body = inner(ctx)
        .trim()
        .split('\n')
        .map((l) => `> ${l}`)
        .join('\n');
      return `\n\n${body}\n\n`;
    }
    case 'code':
      if (ctx.inPre) return inner(ctx);
      return `\`${inner(ctx)}\``;
    case 'pre': {
      const body = inner({ ...ctx, inPre: true });
      return `\n\n\`\`\`\n${body.replace(/\n+$/, '')}\n\`\`\`\n\n`;
    }
    case 'script':
    case 'style':
    case 'noscript':
      return '';
    default:
      return inner(ctx);
  }
}

export function formatArticle(
  article: ReadabilityArticle,
  format: 'markdown' | 'text' | 'json',
): string {
  if (format === 'json') return JSON.stringify(article, null, 2);
  if (format === 'text') return article.textContent.trim();
  const header: string[] = [];
  if (article.title) header.push(`# ${article.title}`);
  const meta: string[] = [];
  if (article.byline) meta.push(`By ${article.byline}`);
  if (article.siteName) meta.push(article.siteName);
  if (meta.length) header.push(`_${meta.join(' — ')}_`);
  const body = htmlToMarkdown(article.content);
  return `${header.join('\n\n')}\n\n${body}`.trim() + '\n';
}
