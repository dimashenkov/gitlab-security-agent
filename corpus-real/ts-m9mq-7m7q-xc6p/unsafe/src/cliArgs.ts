

export const CLI_COMMANDS = new Set(['read', 'search', 'research', 'help', '--help', '-h']);


const BOOLEAN_FLAGS = new Set(['news', 'images', 'json', 'help']);

export interface ParsedCli {
  cmd: string;
  positional: string[];
  flags: Record<string, string | boolean>;
}

export function parseCliArgs(argv: string[]): ParsedCli {
  const [cmd = '', ...rest] = argv;
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    if (!a.startsWith('--')) {
      positional.push(a);
      continue;
    }
    const body = a.slice(2);
    const eq = body.indexOf('=');
    if (eq >= 0) {
      flags[body.slice(0, eq)] = body.slice(eq + 1);
    } else if (BOOLEAN_FLAGS.has(body) || i + 1 >= rest.length || rest[i + 1].startsWith('--')) {
      flags[body] = true;
    } else {
      flags[body] = rest[++i];
    }
  }
  return { cmd, positional, flags };
}

export function numFlag(v: string | boolean | undefined): number | undefined {
  if (typeof v !== 'string') return undefined;
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : undefined;
}

export const USAGE = `browse-mcp — headless-browser MCP server with a CLI for token-light reads

Server (default, no arguments): speaks MCP over stdio.

CLI commands:
  browse-mcp read <url> [--format markdown|text|json] [--max-pages N] [--max-chars N]
      Readability extraction of a page, or text extraction of a .pdf URL/path.

  browse-mcp search <query> [--max N] [--region cc] [--news | --images] [--json]
      Web search (provider chain). --news / --images switch endpoint.

  browse-mcp research <query> [--max N] [--region cc] [--format markdown|text|json]
      Search, read the top N results, emit one concatenated document.

Browser session: if a browse-mcp server is running with BROWSE_MCP_CDP set,
the CLI attaches to its live browser (same auth, same fence). Otherwise it
launches its own headless browser on the shared profile, falling back to an
ephemeral context when the profile is locked.
`;
