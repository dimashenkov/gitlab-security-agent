import { appendFile, mkdir, readFile } from 'fs/promises';
import { existsSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const LOG_DIR = process.env.BROWSE_MCP_HOME || join(homedir(), '.browse-mcp');
const LOG_FILE = join(LOG_DIR, 'issues.jsonl');

export interface Issue {
  ts: string;
  kind: 'error' | 'difficulty';
  tool?: string;
  args?: unknown;
  url?: string;
  error?: string;
  note?: string;
  context?: unknown;
}

async function ensureDir() {
  if (!existsSync(LOG_DIR)) await mkdir(LOG_DIR, { recursive: true });
}

export async function logIssue(entry: Omit<Issue, 'ts'>): Promise<void> {
  try {
    await ensureDir();
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + '\n';
    await appendFile(LOG_FILE, line, 'utf8');
  } catch {

  }
}

export async function readIssues(limit = 50): Promise<Issue[]> {
  try {
    if (!existsSync(LOG_FILE)) return [];
    const content = await readFile(LOG_FILE, 'utf8');
    const lines = content.split('\n').filter((l) => l.trim());
    return lines
      .slice(-limit)
      .map((l) => {
        try {
          return JSON.parse(l) as Issue;
        } catch {
          return null;
        }
      })
      .filter((x): x is Issue => x !== null);
  } catch {
    return [];
  }
}

export function logPath(): string {
  return LOG_FILE;
}
