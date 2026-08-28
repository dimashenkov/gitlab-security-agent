import { browser } from '../browser.js';
import { cleanup } from '../cleanup.js';
import { applyStyle, undoStyle, styleHistory } from '../style.js';
import { text, type ToolModule } from './types.js';

export const edit: ToolModule = {
  tools: [
    {
      name: 'browser_modify_style',
      description:
        'Set a CSS property on element(s) matching a selector. Returns a change-id that can be passed to browser_undo_style. Useful for dogfooding design changes live. Applies inline styles — reload reverts.',
      inputSchema: {
        type: 'object',
        properties: {
          selector: {
            type: 'string',
            description: 'CSS selector (not @ref — applies to all matches)',
          },
          property: { type: 'string', description: 'CSS property name (e.g. "background-color")' },
          value: { type: 'string', description: 'CSS value (e.g. "#1a1a1a" or "20px")' },
          important: { type: 'boolean', description: 'Add !important (default false)' },
        },
        required: ['selector', 'property', 'value'],
      },
    },
    {
      name: 'browser_undo_style',
      description:
        'Undo the last N style modifications (default 1). Pass count to undo multiple at once.',
      inputSchema: {
        type: 'object',
        properties: {
          count: { type: 'number', description: 'How many changes to undo (default 1)' },
          show_history: {
            type: 'boolean',
            description: 'Just list the current undo stack without undoing',
          },
        },
      },
    },
    {
      name: 'browser_cleanup',
      description:
        'Remove visual clutter from the page. Flags: ads, cookies (cookie/GDPR banners), sticky (fixed/sticky headers + footers), social (share bars, newsletter popups), or all. Useful before taking clean screenshots or reducing snapshot noise.',
      inputSchema: {
        type: 'object',
        properties: {
          ads: { type: 'boolean' },
          cookies: { type: 'boolean' },
          sticky: { type: 'boolean' },
          social: { type: 'boolean' },
          all: { type: 'boolean', description: 'Apply all cleanup categories' },
        },
      },
    },
  ],
  handlers: {
    async browser_modify_style(a) {
      const page = await browser.getPage();
      const change = await applyStyle(page, a.selector, a.property, a.value, !!a.important);
      return text(
        `#${change.id} set ${change.property}=${change.newValue}${change.important ? ' !important' : ''} on ${change.matchCount} element(s). ` +
          `Previous: ${change.previousValue || '(unset)'}. Undo with browser_undo_style.`,
      );
    },

    async browser_undo_style(a) {
      if (a.show_history) {
        const h = styleHistory();
        if (h.length === 0) return text('(undo stack empty)');
        return text(
          h
            .map(
              (c) =>
                `#${c.id} ${c.selector} { ${c.property}: ${c.newValue}${c.important ? ' !important' : ''}; } (prev: ${c.previousValue || '(unset)'})`,
            )
            .join('\n'),
        );
      }
      const page = await browser.getPage();
      const count = typeof a.count === 'number' ? a.count : 1;
      const undone = await undoStyle(page, count);
      if (undone.length === 0) return text('(nothing to undo)');
      return text(`Undid ${undone.length} change(s): ${undone.map((c) => `#${c.id}`).join(', ')}`);
    },

    async browser_cleanup(a) {
      const page = await browser.getPage();
      const removed = await cleanup(page, {
        ads: !!a.ads,
        cookies: !!a.cookies,
        sticky: !!a.sticky,
        social: !!a.social,
        all: !!a.all,
      });
      return text(`Removed ${removed} element(s)`);
    },
  },
};
