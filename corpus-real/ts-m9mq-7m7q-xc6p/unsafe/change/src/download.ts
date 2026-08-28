import type { Page } from 'playwright';
import { mkdirSync, existsSync, statSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join, basename } from 'path';
import { createHash } from 'crypto';

const DEFAULT_DIR = process.env.BROWSE_MCP_HOME
  ? join(process.env.BROWSE_MCP_HOME, 'downloads')
  : join(homedir(), '.browse-mcp', 'downloads');

export interface DownloadResult {
  url: string;
  path: string;
  filename: string;
  sizeBytes: number;
  contentType?: string;
}

export interface DownloadOptions {
  saveDir?: string;
  forceFetch?: boolean;
}

export async function downloadUrl(
  page: Page,
  url: string,
  saveDirOrOpts?: string | DownloadOptions,
  forceFetchArg?: boolean,
): Promise<DownloadResult> {

  let saveDir: string | undefined;
  let forceFetch: boolean;
  if (typeof saveDirOrOpts === 'string' || saveDirOrOpts === undefined) {
    saveDir = saveDirOrOpts as string | undefined;
    forceFetch = !!forceFetchArg;
  } else {
    saveDir = saveDirOrOpts.saveDir;
    forceFetch = !!saveDirOrOpts.forceFetch;
  }

  const dir = saveDir || DEFAULT_DIR;
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });




  const downloadTimeout = forceFetch ? 3_000 : 60_000;
  const downloadPromise = page.waitForEvent('download', { timeout: downloadTimeout });


  let navErr: Error | null = null;
  const navResult = await page.goto(url).catch((e: Error) => {
    if (/download is starting/i.test(e.message)) return 'download-triggered';
    navErr = e;
    return null;
  });

  const download = await downloadPromise.catch(() => null);
  if (!download) {
    if (forceFetch) {
      return await fetchFallback(url, dir);
    }
    const reason = navErr ? (navErr as Error).message : `nav: ${navResult}`;
    throw new Error(`URL did not trigger a download: ${url} (${reason})`);
  }

  const suggested =
    download.suggestedFilename() || basename(new URL(url).pathname) || 'download.bin';
  const outPath = join(dir, suggested);
  await download.saveAs(outPath);

  const size = existsSync(outPath) ? statSync(outPath).size : 0;
  return {
    url,
    path: outPath,
    filename: suggested,
    sizeBytes: size,
  };
}

async function fetchFallback(url: string, dir: string): Promise<DownloadResult> {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`fetch fallback: HTTP ${res.status} for ${url}`);
  }
  const buf = Buffer.from(await res.arrayBuffer());
  const contentType = res.headers.get('content-type') || undefined;

  let filename = '';
  try {
    filename = basename(new URL(url).pathname);
  } catch {

  }
  if (!filename || filename === '/' || !/\.[A-Za-z0-9]+$/.test(filename)) {
    const hash = createHash('sha1').update(url).digest('hex').slice(0, 12);
    const ext = extForContentType(contentType);
    filename = `fetched-${hash}${ext}`;
  }

  const outPath = join(dir, filename);
  writeFileSync(outPath, buf);
  return {
    url,
    path: outPath,
    filename,
    sizeBytes: buf.length,
    contentType,
  };
}

function extForContentType(ct?: string): string {
  if (!ct) return '.bin';
  const base = ct.split(';')[0].trim().toLowerCase();
  const map: Record<string, string> = {
    'image/svg+xml': '.svg',
    'image/png': '.png',
    'image/jpeg': '.jpg',
    'image/gif': '.gif',
    'image/webp': '.webp',
    'application/json': '.json',
    'application/pdf': '.pdf',
    'application/xml': '.xml',
    'text/html': '.html',
    'text/plain': '.txt',
    'text/css': '.css',
    'text/xml': '.xml',
    'text/javascript': '.js',
    'application/javascript': '.js',
    'application/zip': '.zip',
    'application/octet-stream': '.bin',
  };
  return map[base] || '.bin';
}
