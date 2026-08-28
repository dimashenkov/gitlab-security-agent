import { browser } from '../browser.js';
import { resolveRef } from '../snapshot.js';
import { runAxeAudit, formatA11yResult } from '../a11y.js';
import { inspectElement, formatInspect } from '../inspect.js';
import { text, type ToolModule } from './types.js';

export const debug: ToolModule = {
  tools: [
    {
      name: 'browser_console',
      description:
        'Get captured browser console messages (log/warn/error/etc). Set clear=true to reset the buffer after reading.',
      inputSchema: {
        type: 'object',
        properties: {
          errors_only: { type: 'boolean', description: 'Only error/warning entries' },
          clear: { type: 'boolean', description: 'Clear buffer after reading' },
          all_tabs: {
            type: 'boolean',
            description: 'Include entries from every tab (prefixed with [tab N])',
          },
        },
      },
    },
    {
      name: 'browser_network',
      description: 'Get captured network requests from the current session.',
      inputSchema: {
        type: 'object',
        properties: {
          failed_only: {
            type: 'boolean',
            description: 'Only failed (status >= 400 or no response) requests',
          },
          clear: { type: 'boolean', description: 'Clear buffer after reading' },
          all_tabs: {
            type: 'boolean',
            description: 'Include entries from every tab (prefixed with [tab N])',
          },
        },
      },
    },
    {
      name: 'browser_a11y_audit',
      description:
        'Run an axe-core WCAG accessibility audit on the current page. Returns violations grouped by rule, with impact, help text, and up to 5 offending nodes per rule. Use before shipping UI changes or when auditing a site for a11y issues.',
      inputSchema: { type: 'object', properties: {} },
    },
    {
      name: 'browser_inspect_css',
      description:
        'Deep CSS inspection via Chrome DevTools Protocol. Returns the full cascade (matched rules in origin order), inline style, selected computed styles, and box model for one element. Great for debugging why styles look wrong.',
      inputSchema: {
        type: 'object',
        properties: {
          selector: {
            type: 'string',
            description: 'CSS selector or @ref of the element to inspect',
          },
          include_user_agent: {
            type: 'boolean',
            description: 'Include user-agent stylesheet rules (default: false)',
          },
        },
        required: ['selector'],
      },
    },
  ],
  handlers: {
    async browser_console(a) {
      await browser.getPage();
      let entries = a.all_tabs ? browser.getAllConsoleLogs() : browser.consoleLog;
      if (a.errors_only)
        entries = entries.filter((e) => e.type === 'error' || e.type === 'warning');
      const out = entries
        .map((e) => {
          const prefix = a.all_tabs ? `[tab ${e.tabIndex ?? '?'}] ` : '';
          return `${prefix}[${e.type}] ${e.text}${e.location ? ` (${e.location})` : ''}`;
        })
        .join('\n');
      if (a.clear) browser.clearConsole();
      return text(out || '(no console messages)');
    },

    async browser_network(a) {
      await browser.getPage();
      let entries = a.all_tabs ? browser.getAllNetworkLogs() : browser.networkLog;
      if (a.failed_only)
        entries = entries.filter((e) => e.status === undefined || (e.status && e.status >= 400));
      const out = entries
        .map((e) => {
          const prefix = a.all_tabs ? `[tab ${e.tabIndex ?? '?'}] ` : '';
          return `${prefix}${e.method} ${e.status ?? 'pending'} ${e.url}`;
        })
        .join('\n');
      if (a.clear) browser.clearNetwork();
      return text(out || '(no network activity)');
    },

    async browser_a11y_audit() {
      const page = await browser.getPage();
      const result = await runAxeAudit(page);
      return text(formatA11yResult(result));
    },

    async browser_inspect_css(a) {
      const page = await browser.getPage();
      let sel = a.selector;
      if (typeof sel === 'string' && sel.startsWith('@')) {
        const { selector } = await resolveRef(page, sel);
        sel = selector;
      }
      const cdp = await browser.getCdp();
      const result = await inspectElement(page, cdp, sel, !!a.include_user_agent);
      return text(formatInspect(result));
    },
  },
};
