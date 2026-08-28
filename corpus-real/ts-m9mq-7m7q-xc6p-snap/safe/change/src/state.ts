import { homedir } from 'os';
import { join } from 'path';
import { confineToDir } from './pathSafe.js';





export const STATE_DIR = process.env.BROWSE_MCP_HOME
  ? join(process.env.BROWSE_MCP_HOME, 'state')
  : join(homedir(), '.browse-mcp', 'state');

export function resolveStatePath(opts: { name?: string; path?: string }): string {




  if (opts.path) return confineToDir(STATE_DIR, opts.path);
  const name = (opts.name ?? 'default').trim();
  if (!/^[A-Za-z0-9._-]+$/.test(name)) {
    throw new Error(
      `Invalid state name ${JSON.stringify(name)} — use letters, digits, dot, dash, underscore, or pass an explicit path.`,
    );
  }
  return join(STATE_DIR, `${name}.json`);
}

export interface StorageStateFile {
  cookies: Array<Record<string, unknown>>;
  origins: Array<{ origin: string; localStorage: Array<{ name: string; value: string }> }>;
}

export function validateStorageState(raw: unknown): StorageStateFile {
  if (typeof raw !== 'object' || raw === null) {
    throw new Error('Storage state file is not a JSON object');
  }
  const o = raw as Record<string, unknown>;
  const cookies = Array.isArray(o.cookies) ? (o.cookies as StorageStateFile['cookies']) : [];
  const origins = Array.isArray(o.origins) ? (o.origins as StorageStateFile['origins']) : [];
  if (!Array.isArray(o.cookies) && !Array.isArray(o.origins)) {
    throw new Error(
      'Storage state file has neither a cookies nor an origins array — is this a Playwright storageState JSON?',
    );
  }
  for (const org of origins) {
    if (typeof org?.origin !== 'string' || !Array.isArray(org?.localStorage)) {
      throw new Error('Malformed origins entry in storage state file');
    }
  }
  return { cookies, origins };
}

export function summarizeState(s: StorageStateFile): string {
  const items = s.origins.reduce((n, o) => n + o.localStorage.length, 0);
  return `${s.cookies.length} cookie(s), ${s.origins.length} origin(s) with ${items} localStorage item(s)`;
}
