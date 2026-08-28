#!/usr/bin/env node
import { createRequire } from 'module';
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { CallToolRequestSchema, ListToolsRequestSchema } from '@modelcontextprotocol/sdk/types.js';
import { logIssue } from './issues.js';
import { navigation } from './tools/navigation.js';
import { snapshotTools } from './tools/snapshot.js';
import { content } from './tools/content.js';
import { search } from './tools/search.js';
import { debug } from './tools/debug.js';
import { edit } from './tools/edit.js';
import { session } from './tools/session.js';
import { issues } from './tools/issues.js';
import { text, currentUrl, type ToolDef, type Handler, type ToolModule } from './tools/types.js';
import { CLI_COMMANDS } from './cliArgs.js';


const { version } = createRequire(import.meta.url)('../package.json') as { version: string };

const server = new Server({ name: 'browse-mcp', version }, { capabilities: { tools: {} } });


const MODULES: ToolModule[] = [
  navigation,
  snapshotTools,
  content,
  search,
  debug,
  edit,
  session,
  issues,
];

const tools: ToolDef[] = MODULES.flatMap((m) => m.tools);
const handlers: Record<string, Handler> = Object.assign({}, ...MODULES.map((m) => m.handlers));





const TOOL_BUNDLES: Record<string, string[]> = {
  core: [
    'browser_navigate',
    'browser_navigate_back',
    'browser_navigate_forward',
    'browser_snapshot',
    'browser_click',
    'browser_type',
    'browser_select_option',
    'browser_press_key',
    'browser_wait_for',
    'browser_eval',
    'browser_close',
  ],
  search: ['browser_search', 'browser_search_news', 'browser_search_images', 'browser_research'],
  content: ['browser_read', 'browser_links', 'browser_extract_listings'],
  visual: ['browser_screenshot', 'browser_screenshot_annotated', 'browser_responsive'],
  debug: [
    'browser_console',
    'browser_network',
    'browser_a11y_audit',
    'browser_inspect_css',
    'browser_report_difficulty',
    'browser_review_issues',
  ],
  edit: ['browser_modify_style', 'browser_undo_style', 'browser_cleanup'],
  vision: ['browser_click_xy', 'browser_move_xy', 'browser_drag_xy'],
  session: [
    'browser_tabs',
    'browser_switch_tab',
    'browser_handoff',
    'browser_resume',
    'browser_download',
    'browser_reset_profile',
    'browser_hover',
    'browser_scroll',
    'browser_find_text',
    'browser_wait_for_text',
    'browser_file_upload',
    'browser_handle_dialog',
    'browser_drag',
    'browser_save_state',
    'browser_load_state',
    'browser_context',
  ],
};



const OPT_IN_TOOLS = new Set(TOOL_BUNDLES.vision);
function filterTools(all: ToolDef[]): ToolDef[] {
  const raw = process.env.BROWSE_MCP_TOOLS;
  if (!raw) return all.filter((t) => !OPT_IN_TOOLS.has(t.name));
  const allowed = new Set<string>();
  for (const tok of raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)) {
    if (TOOL_BUNDLES[tok]) for (const n of TOOL_BUNDLES[tok]) allowed.add(n);
    else allowed.add(tok);
  }
  return all.filter((t) => allowed.has(t.name));
}
const exposedTools = filterTools(tools);
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: exposedTools }));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  const a = args as Record<string, any>;

  try {
    const handler = handlers[name];
    if (!handler) return text(`Unknown tool: ${name}`, true);
    return await handler(a);
  } catch (err: any) {
    await logIssue({
      kind: 'error',
      tool: name,
      args: a,
      error: err?.message || String(err),
      url: await currentUrl(),
    });
    return text(`Error: ${err.message}`, true);
  }
});

async function main() {


  const first = process.argv[2];
  if (first && CLI_COMMANDS.has(first)) {
    const { runCli } = await import('./cli.js');
    await runCli(process.argv.slice(2));
    return;
  }
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
