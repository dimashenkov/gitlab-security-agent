import { readFileSync, existsSync } from 'fs';
import { chromium, type Page } from 'playwright';
import { browser as manager, CDP_FILE } from './browser.js';
import { readArticle, formatArticle } from './read.js';
import { isPdfUrl, fetchPdf, extractPdfText } from './pdf.js';
import {
  searchWithBrowserFallback,
  duckDuckGoNewsSearch,
  duckDuckGoImageSearch,
  formatResults,
  formatNewsResults,
} from './search.js';
import { research } from './research.js';
import { parseCliArgs, numFlag, USAGE, type ParsedCli } from './cliArgs.js';




const out = (s: string) => process.stdout.write(s.endsWith('\n') ? s : s + '\n');
const note = (s: string) => process.stderr.write(s + '\n');

interface PageSession {
  page: Page;
  cleanup: () => Promise<void>;
}




async function acquirePage(): Promise<PageSession> {
  if (existsSync(CDP_FILE)) {
    try {
      const { port } = JSON.parse(readFileSync(CDP_FILE, 'utf8')) as { port: number };
      const b = await chromium.connectOverCDP(`http://127.0.0.1:${port}`, { timeout: 3000 });
      const ctx = b.contexts()[0] ?? (await b.newContext());
      const page = await ctx.newPage();
      note(`(attached to running browse-mcp browser on CDP port ${port})`);
      return {
        page,


        cleanup: async () => {
          await page.close().catch(() => {});
          await b.close().catch(() => {});
        },
      };
    } catch {
      note('(stale CDP discovery file — launching own browser)');
    }
  }
  try {
    const page = await manager.getPage();
    return { page, cleanup: () => manager.close() };
  } catch (e) {
    note(
      `(shared profile unavailable: ${(e as Error).message.split('\n')[0]} — running ephemeral; start the server with BROWSE_MCP_CDP=1 to share its session)`,
    );
    const b = await chromium.launch();
    const page = await (await b.newContext()).newPage();
    return { page, cleanup: () => b.close() };
  }
}

async function cmdRead(c: ParsedCli): Promise<void> {
  const url = c.positional[0];
  if (!url) throw new Error('read needs a URL or .pdf path\n\n' + USAGE);
  const format = (c.flags.format as string) || 'markdown';
  if (isPdfUrl(url)) {
    const r = await extractPdfText(await fetchPdf(url), {
      maxPages: numFlag(c.flags['max-pages']),
      maxChars: numFlag(c.flags['max-chars']),
    });
    if (!r.text.trim()) throw new Error('PDF contained no extractable text (likely scanned images)');
    if (format === 'json') {
      out(JSON.stringify({ title: r.title, url, numPages: r.numPages, pagesRead: r.pagesRead, truncated: r.truncated, text: r.text }, null, 2));
    } else {
      out(`# ${r.title || url}\n\n_PDF — ${r.pagesRead} of ${r.numPages} page(s) extracted${r.truncated ? ', truncated' : ''}_\n\n${r.text}`);
    }
    return;
  }
  const s = await acquirePage();
  try {
    const article = await readArticle(s.page, { url, format: format as 'markdown' | 'text' | 'json' });
    if (!article || (!article.content && !article.textContent)) {
      throw new Error('Readability did not detect an article on this page');
    }
    out(formatArticle(article, format as 'markdown' | 'text' | 'json'));
  } finally {
    await s.cleanup();
  }
}

async function cmdSearch(c: ParsedCli): Promise<void> {
  const query = c.positional.join(' ').trim();
  if (!query) throw new Error('search needs a query\n\n' + USAGE);
  const max = numFlag(c.flags.max) ?? 10;
  const region = typeof c.flags.region === 'string' ? c.flags.region : undefined;
  if (c.flags.news) {
    const results = await duckDuckGoNewsSearch(query, max, region);
    out(c.flags.json ? JSON.stringify(results, null, 2) : formatNewsResults(results));
    return;
  }
  if (c.flags.images) {
    out(JSON.stringify(await duckDuckGoImageSearch(query, max), null, 2));
    return;
  }
  const s = await acquirePage();
  try {
    const results = await searchWithBrowserFallback(s.page, query, max, region);
    out(c.flags.json ? JSON.stringify(results, null, 2) : formatResults(results));
  } finally {
    await s.cleanup();
  }
}

async function cmdResearch(c: ParsedCli): Promise<void> {
  const query = c.positional.join(' ').trim();
  if (!query) throw new Error('research needs a query\n\n' + USAGE);
  const s = await acquirePage();
  try {
    const { output } = await research(s.page, {
      query,
      maxResults: numFlag(c.flags.max) ?? 5,
      region: typeof c.flags.region === 'string' ? c.flags.region : undefined,
      format: ((c.flags.format as string) || 'markdown') as 'markdown' | 'text' | 'json',
    });
    out(output);
  } finally {
    await s.cleanup();
  }
}

export async function runCli(argv: string[]): Promise<void> {
  const c = parseCliArgs(argv);
  try {
    if (c.cmd === 'read') await cmdRead(c);
    else if (c.cmd === 'search') await cmdSearch(c);
    else if (c.cmd === 'research') await cmdResearch(c);
    else out(USAGE);
    process.exitCode = 0;
  } catch (e) {
    note(`Error: ${(e as Error).message}`);
    process.exitCode = 1;
  }
}
