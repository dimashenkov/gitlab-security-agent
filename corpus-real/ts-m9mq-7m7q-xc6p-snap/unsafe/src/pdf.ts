import { readFileSync, existsSync } from 'fs';




export interface PdfExtractOptions {
  maxPages?: number;
  maxChars?: number;
}

export interface PdfExtractResult {
  text: string;
  numPages: number;
  pagesRead: number;
  truncated: boolean;
  title?: string;
}

let pdfjsPromise: Promise<typeof import('pdfjs-dist/legacy/build/pdf.mjs')> | null = null;
function loadPdfjs() {
  pdfjsPromise ??= import('pdfjs-dist/legacy/build/pdf.mjs');
  return pdfjsPromise;
}

export function isPdfUrl(url: string): boolean {
  return /\.pdf([?#].*)?$/i.test(url);
}

export function isPdfData(data: Uint8Array): boolean {

  const head = Buffer.from(data.slice(0, 1024)).toString('latin1');
  return head.includes('%PDF-');
}


export async function fetchPdf(urlOrPath: string): Promise<Uint8Array> {
  if (/^https?:\/\//i.test(urlOrPath)) {
    const res = await fetch(urlOrPath, {
      headers: { Accept: 'application/pdf,*/*' },
    });
    if (!res.ok) throw new Error(`PDF fetch failed: HTTP ${res.status} for ${urlOrPath}`);
    return new Uint8Array(await res.arrayBuffer());
  }
  if (existsSync(urlOrPath)) return new Uint8Array(readFileSync(urlOrPath));
  throw new Error(`Not an http(s) URL and no local file found: ${urlOrPath}`);
}

export async function extractPdfText(
  data: Uint8Array,
  opts: PdfExtractOptions = {},
): Promise<PdfExtractResult> {
  const maxPages = opts.maxPages ?? 50;
  const maxChars = opts.maxChars ?? 200_000;
  if (!isPdfData(data)) {
    throw new Error(
      'Data is not a PDF (no %PDF header). The server may have returned an HTML error or challenge page instead.',
    );
  }
  const pdfjs = await loadPdfjs();
  const loadingTask = pdfjs.getDocument({ data, useSystemFonts: true });
  const doc = await loadingTask.promise;
  let title: string | undefined;
  try {
    const meta = await doc.getMetadata();
    const t = (meta.info as { Title?: string } | undefined)?.Title;
    if (t && t.trim()) title = t.trim();
  } catch {

  }
  const parts: string[] = [];
  let chars = 0;
  let pagesRead = 0;
  let truncated = false;
  for (let i = 1; i <= doc.numPages; i++) {
    if (i > maxPages || chars >= maxChars) {
      truncated = true;
      break;
    }
    const page = await doc.getPage(i);
    const tc = await page.getTextContent();
    const lines: string[] = [];
    let line = '';
    for (const item of tc.items) {
      if (!('str' in item)) continue;
      line += item.str;
      if (item.hasEOL) {
        lines.push(line);
        line = '';
      } else if (item.str && !item.str.endsWith(' ')) {
        line += ' ';
      }
    }
    if (line.trim()) lines.push(line);
    const pageText = lines
      .map((l) => l.replace(/\s+$/g, ''))
      .join('\n')
      .trim();
    parts.push(`--- Page ${i} of ${doc.numPages} ---\n${pageText}`);
    pagesRead = i;
    chars += pageText.length;
  }
  await loadingTask.destroy();
  let text = parts.join('\n\n');
  if (text.length > maxChars) {
    text = text.slice(0, maxChars) + '\n\n[...truncated]';
    truncated = true;
  }
  return { text, numPages: doc.numPages, pagesRead, truncated, title };
}
