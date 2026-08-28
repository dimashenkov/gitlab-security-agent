import { rm, mkdir, readFile, readdir, chmod } from 'fs/promises';
import { existsSync } from 'fs';
import { dirname } from 'path';
import { browser, DEFAULT_DATA_DIR } from '../browser.js';
import { snapshot } from '../snapshot.js';
import { downloadUrl } from '../download.js';
import { resolveStatePath, validateStorageState, summarizeState, STATE_DIR } from '../state.js';
import { text, type ToolModule } from './types.js';

export const session: ToolModule = {
  tools: [
    {
      name: 'browser_tabs',
      description:
        'List all open browser tabs as JSON: [{index, url, title, active}]. Use together with browser_switch_tab to drive multi-tab workflows (links that open in a new tab, popup windows, etc.).',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'browser_switch_tab',
      description:
        'Switch the active tab by index (from browser_tabs). Subsequent browse tools act on the chosen tab. Returns the new active URL.',
      inputSchema: {
        type: 'object',
        properties: {
          index: { type: 'number', description: 'Tab index from browser_tabs' },
        },
        required: ['index'],
      },
    },
    {
      name: 'browser_handoff',
      description:
        'Open the current page in a visible Chrome window so the user can interact (CAPTCHA, MFA, OAuth). State (cookies, localStorage, tabs) is preserved via a persistent profile. Because the profile at ~/.browse-mcp/chromium-profile/ survives across sessions, cookies/localStorage/auth persist too — so OAuth/MFA/CAPTCHA typically only needs to be completed once per service. After the user is done, call browser_resume to return to headless. USE SPARINGLY — only when you genuinely cannot proceed headlessly.',
      inputSchema: {
        type: 'object',
        properties: {
          reason: { type: 'string', description: 'Short reason shown to the user' },
        },
      },
    },
    {
      name: 'browser_resume',
      description:
        'Return from handoff to headless mode. Closes the visible Chrome window, reopens the page headlessly at the same URL with preserved state, and returns a fresh interactive snapshot so you can see where the user left off.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'browser_download',
      description:
        'Download a URL that triggers a file download (PDF with attachment disposition, binary file, etc.). Returns the saved file path and size. Use when browser_navigate fails with "Download is starting". Pass force_fetch=true to fall back to a raw fetch() when the URL does not trigger a browser download event (useful for plain SVG/HTML/JSON URLs).',
      inputSchema: {
        type: 'object',
        properties: {
          url: { type: 'string', description: 'URL to download' },
          save_dir: {
            type: 'string',
            description:
              'Optional subdirectory under the download root ~/.browse-mcp/downloads (default: the root itself). Confined to that root: absolute paths and ".." escapes are rejected. Relocate the root with BROWSE_MCP_HOME.',
          },
          force_fetch: {
            type: 'boolean',
            description:
              'If the page does not trigger a download within ~3s, fall back to a raw fetch() of the URL (default false).',
          },
        },
        required: ['url'],
      },
    },
    {
      name: 'browser_context',
      description:
        'Manage isolated browser contexts (incognito-style). "open" creates a named in-memory context that shares NOTHING with the persistent profile — no cookies, no auth — and switches to it. "switch" changes which context all other tools act on. "close" destroys one. "list" shows contexts with tab counts. Isolated contexts are lost on browser_close and browser_handoff. Combine with browser_load_state to inject scoped auth into a clean context.',
      inputSchema: {
        type: 'object',
        properties: {
          action: {
            type: 'string',
            enum: ['open', 'switch', 'close', 'list'],
            description: 'What to do',
          },
          name: {
            type: 'string',
            description: 'Context name (required for open/switch/close)',
          },
        },
        required: ['action'],
      },
    },
    {
      name: 'browser_save_state',
      description:
        'Export the session storage state (cookies + localStorage) to a JSON file so auth can be moved to another machine or restored later. WARNING: the file contains live session tokens — treat it like a password file. Default location: ~/.browse-mcp/state/<name>.json.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'State name (default "default")' },
          path: {
            type: 'string',
            description:
              'Explicit file path under the state dir ~/.browse-mcp/state (overrides name). Confined to that dir: absolute paths and ".." escapes are rejected. Relocate it with BROWSE_MCP_HOME.',
          },
        },
      },
    },
    {
      name: 'browser_load_state',
      description:
        'Import a previously saved storage state JSON (cookies + localStorage) into the current browser context. Cookies apply immediately; localStorage requires briefly visiting each origin in the file. Merges into existing state.',
      inputSchema: {
        type: 'object',
        properties: {
          name: { type: 'string', description: 'State name (default "default")' },
          path: {
            type: 'string',
            description:
              'Explicit file path under the state dir ~/.browse-mcp/state (overrides name). Confined to that dir: absolute paths and ".." escapes are rejected. Relocate it with BROWSE_MCP_HOME.',
          },
        },
      },
    },
    {
      name: 'browser_reset_profile',
      description:
        'Destructively reset the persistent Chromium profile directory. Closes the browser and recursively deletes the profile (cookies, localStorage, auth, cache). Use when the profile is in a bad state. Requires confirm=true.',
      inputSchema: {
        type: 'object',
        properties: {
          confirm: { type: 'boolean', description: 'Must be true to proceed' },
        },
        required: ['confirm'],
      },
    },
  ],
  handlers: {
    async browser_tabs() {
      await browser.getPage();
      const pages = browser.getAllPages();
      const active = (browser as any).page;
      const list = await Promise.all(
        pages.map(async (p, index) => ({
          index,
          url: p.url(),
          title: await p.title().catch(() => ''),
          active: p === active,
        })),
      );
      return text(JSON.stringify(list, null, 2));
    },

    async browser_switch_tab(a) {
      await browser.getPage();
      const pages = browser.getAllPages();
      const idx = a.index;
      if (typeof idx !== 'number' || idx < 0 || idx >= pages.length) {
        return text(`Invalid tab index ${idx}. Have ${pages.length} tab(s).`, true);
      }
      const target = pages[idx];
      browser.setActivePage(target);
      await target.bringToFront().catch(() => {});
      return text(`Switched to tab ${idx}: ${target.url()}`);
    },

    async browser_handoff(a) {
      const page = await browser.getPage();
      const url = page.url();
      await browser.switchMode('headed', url, a.reason || 'handoff');
      return text(
        `Visible Chrome window opened at ${url}. Reason: ${a.reason || '(unspecified)'}. ` +
          `Cookies/localStorage/auth persist across sessions via the profile at ~/.browse-mcp/chromium-profile/, so OAuth/MFA/CAPTCHA typically only needs to be completed once per service. ` +
          `Ask the user to complete the task, then call browser_resume.`,
      );
    },

    async browser_resume() {
      const currentUrl = await (async () => {
        try {
          const p = (browser as any).page;
          return p && !p.isClosed() ? p.url() : undefined;
        } catch {
          return undefined;
        }
      })();
      await browser.switchMode('headless', currentUrl);
      const page = await browser.getPage();
      const tree = await snapshot(page, { interactive: true });
      return text(`Resumed headless at ${page.url()}\n\n${tree}`);
    },

    async browser_download(a) {
      const page = await browser.getPage();
      const result = await downloadUrl(page, a.url, {
        saveDir: a.save_dir,
        forceFetch: !!a.force_fetch,
      });
      return text(
        `Downloaded ${result.filename}\n  path: ${result.path}\n  size: ${result.sizeBytes} bytes\n  from: ${result.url}`,
      );
    },

    async browser_context(a) {
      if (a.action === 'list') {
        await browser.getPage();
        return text(JSON.stringify(browser.listContexts(), null, 2));
      }
      const name = (a.name ?? '').trim();
      if (!/^[A-Za-z0-9._-]+$/.test(name)) {
        return text(
          `Action ${JSON.stringify(a.action)} needs a name (letters, digits, dot, dash, underscore).`,
          true,
        );
      }
      if (a.action === 'open') {
        await browser.openIsolatedContext(name);
        return text(
          `Opened isolated context "${name}" and switched to it. Clean slate: no cookies/auth from the persistent profile. In-memory only — lost on browser_close/browser_handoff.`,
        );
      }
      if (a.action === 'switch') {
        browser.switchContext(name);
        const page = await browser.getPage();
        return text(`Switched to context "${name}" — active tab: ${page.url()}`);
      }
      if (a.action === 'close') {
        await browser.closeContext(name);
        return text(`Closed context "${name}". Now on "${browser.getActiveContextName()}".`);
      }
      return text(`Unknown action: ${a.action}`, true);
    },

    async browser_save_state(a) {
      const page = await browser.getPage();
      const file = resolveStatePath({ name: a.name, path: a.path });
      await mkdir(dirname(file), { recursive: true });
      const state = await page.context().storageState({ path: file });
      await chmod(file, 0o600).catch(() => {});
      const summary = summarizeState(validateStorageState(state));
      return text(
        `Saved storage state to ${file}: ${summary}.\nWARNING: this file contains live session tokens — treat it like a password file.`,
      );
    },

    async browser_load_state(a) {
      const file = resolveStatePath({ name: a.name, path: a.path });
      if (!existsSync(file)) {
        const available = existsSync(STATE_DIR)
          ? (await readdir(STATE_DIR)).filter((f) => f.endsWith('.json')).join(', ') || '(none)'
          : '(none)';
        return text(`No state file at ${file}. Saved states in ${STATE_DIR}: ${available}`, true);
      }
      const state = validateStorageState(JSON.parse(await readFile(file, 'utf8')));
      const page = await browser.getPage();
      const context = page.context();
      if (state.cookies.length) {
        await context.addCookies(state.cookies as unknown as Parameters<typeof context.addCookies>[0]);
      }
      const lines: string[] = [];
      for (const o of state.origins) {

        const tmp = await context.newPage();
        try {
          await tmp.goto(o.origin, { waitUntil: 'domcontentloaded', timeout: 15_000 });
          await tmp.evaluate((items) => {
            for (const it of items) localStorage.setItem(it.name, it.value);
          }, o.localStorage);
          lines.push(`  ${o.origin}: ${o.localStorage.length} localStorage item(s) applied`);
        } catch (e) {
          lines.push(`  ${o.origin}: FAILED (${(e as Error).message})`);
        } finally {
          await tmp.close().catch(() => {});
        }
      }
      return text(
        `Loaded ${summarizeState(state)} from ${file} (merged into existing state).${lines.length ? '\n' + lines.join('\n') : ''}`,
      );
    },

    async browser_reset_profile(a) {
      if (browser.isEphemeral()) {
        await browser.close();
        return text(
          'Ephemeral mode (BROWSE_MCP_EPHEMERAL=1): no persistent profile to delete. Browser closed; next call starts a fresh context.',
        );
      }
      if (a.confirm !== true) {
        return text(
          'browser_reset_profile destructively deletes the persistent Chromium profile ' +
            `(at ${DEFAULT_DATA_DIR}), clearing all cookies, localStorage, saved auth, and cache. ` +
            'This cannot be undone. Re-call with confirm: true to proceed.',
          true,
        );
      }
      await browser.close();
      const path = browser.getDataDir();
      await rm(path, { recursive: true, force: true });
      return text(`Profile reset. Removed: ${path}`);
    },
  },
};
