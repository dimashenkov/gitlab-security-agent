import type { Page } from 'playwright';
import { searchWithBrowserFallback, type SearchResult } from './search.js';
import { readArticle, formatArticle } from './read.js';
import { isPdfUrl, fetchPdf, extractPdfText } from './pdf.js';

export interface ResearchOptions {
  query: string;
  maxResults?: number;
  region?: string;
  format?: 'markdown' | 'text' | 'json';
}

export interface ResearchSource {
  title: string;
  url: string;
  snippet: string;
  content?: string;
  error?: string;
  truncated?: boolean;
}


const PER_SOURCE_CAP_BYTES = 6 * 1024;

export async function research(
  page: Page,
  opts: ResearchOptions,
): Promise<{ output: string; sources: ResearchSource[] }> {
  const format = opts.format || 'markdown';
  const maxResults = opts.maxResults ?? 5;
  const results: SearchResult[] = await searchWithBrowserFallback(
    page,
    opts.query,
    maxResults,
    opts.region,
  );

  const sources: ResearchSource[] = [];
  for (const r of results) {
    const src: ResearchSource = { title: r.title, url: r.url, snippet: r.snippet };
    try {
      if (isPdfUrl(r.url)) {

        const pdf = await extractPdfText(await fetchPdf(r.url), {
          maxChars: PER_SOURCE_CAP_BYTES,
        });
        if (!pdf.text.trim()) {
          src.error = 'PDF contained no extractable text (likely scanned images)';
        } else {
          src.content = pdf.text;
          src.truncated = pdf.truncated;
        }
        sources.push(src);
        continue;
      }
      await page.goto(r.url, { waitUntil: 'domcontentloaded', timeout: 20_000 });
      const article = await readArticle(page, { url: undefined, format });
      if (!article || (!article.content && !article.textContent)) {
        src.error = 'Readability did not detect an article';
      } else {
        let body = formatArticle(article, format);
        if (body.length > PER_SOURCE_CAP_BYTES) {
          body = body.slice(0, PER_SOURCE_CAP_BYTES) + '\n\n[...truncated]';
          src.truncated = true;
        }
        src.content = body;
      }
    } catch (e: any) {
      src.error = e?.message || String(e);
    }
    sources.push(src);
  }

  const output = aggregate(sources, format, opts.query);
  return { output, sources };
}

function aggregate(
  sources: ResearchSource[],
  format: 'markdown' | 'text' | 'json',
  query: string,
): string {
  if (format === 'json') {
    return JSON.stringify(
      sources.map((s) => ({
        title: s.title,
        url: s.url,
        snippet: s.snippet,
        content: s.content,
        error: s.error,
        truncated: s.truncated,
      })),
      null,
      2,
    );
  }

  const ok = sources.filter((s) => s.content);
  const skipped = sources.filter((s) => !s.content);
  const total = sources.length;
  const anyTruncated = ok.some((s) => s.truncated);

  const parts: string[] = [];
  if (format === 'markdown') {
    parts.push(`# Research: ${query}\n`);
  } else {
    parts.push(`Research: ${query}\n`);
  }

  ok.forEach((s, idx) => {
    const header =
      format === 'markdown'
        ? `## [${s.title || s.url}](${s.url})\n_source ${idx + 1} of ${total}_\n`
        : `${s.title || s.url}\n${s.url}\n(source ${idx + 1} of ${total})\n`;
    parts.push(`${header}\n${s.content}\n\n---\n`);
  });

  if (skipped.length > 0) {
    if (format === 'markdown') {
      parts.push('## Skipped\n');
      for (const s of skipped) {
        parts.push(`- ${s.url}: ${s.error || 'unknown error'}`);
      }
      parts.push('');
    } else {
      parts.push('Skipped:');
      for (const s of skipped) {
        parts.push(`- ${s.url}: ${s.error || 'unknown error'}`);
      }
    }
  }

  if (anyTruncated) {
    const note = `_(per-source body capped at ${PER_SOURCE_CAP_BYTES} bytes; some sections were truncated.)_`;
    parts.push(
      format === 'markdown'
        ? `\n${note}\n`
        : `\n(per-source body capped at ${PER_SOURCE_CAP_BYTES} bytes; some sections were truncated.)\n`,
    );
  }

  return parts.join('\n');
}
