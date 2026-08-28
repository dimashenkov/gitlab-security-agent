import type { Page, CDPSession } from 'playwright';

export interface CSSRule {
  origin: string;
  selector: string;
  source?: string;
  properties: Array<{ name: string; value: string; important?: boolean; disabled?: boolean }>;
}

export interface InspectResult {
  selector: string;
  tagName: string;
  attributes: Record<string, string>;
  matchedRules: CSSRule[];
  inlineStyle: Record<string, string>;
  computedSelected: Record<string, string>;
  boxModel: { width: number; height: number; x: number; y: number } | null;
}




const SHORTHAND_LONGHANDS: Record<string, string[]> = {
  margin: ['margin-top', 'margin-right', 'margin-bottom', 'margin-left'],
  padding: ['padding-top', 'padding-right', 'padding-bottom', 'padding-left'],
  border: [
    'border-top-width',
    'border-right-width',
    'border-bottom-width',
    'border-left-width',
    'border-top-style',
    'border-right-style',
    'border-bottom-style',
    'border-left-style',
    'border-top-color',
    'border-right-color',
    'border-bottom-color',
    'border-left-color',
    'border-width',
    'border-style',
    'border-color',
  ],
  'border-top': ['border-top-width', 'border-top-style', 'border-top-color'],
  'border-right': ['border-right-width', 'border-right-style', 'border-right-color'],
  'border-bottom': ['border-bottom-width', 'border-bottom-style', 'border-bottom-color'],
  'border-left': ['border-left-width', 'border-left-style', 'border-left-color'],
  font: [
    'font-style',
    'font-variant',
    'font-weight',
    'font-stretch',
    'font-size',
    'line-height',
    'font-family',
  ],
  background: [
    'background-color',
    'background-image',
    'background-repeat',
    'background-attachment',
    'background-position',
    'background-position-x',
    'background-position-y',
    'background-size',
    'background-origin',
    'background-clip',
  ],
  animation: [
    'animation-name',
    'animation-duration',
    'animation-timing-function',
    'animation-delay',
    'animation-iteration-count',
    'animation-direction',
    'animation-fill-mode',
    'animation-play-state',
  ],
  transition: [
    'transition-property',
    'transition-duration',
    'transition-timing-function',
    'transition-delay',
  ],
  flex: ['flex-grow', 'flex-shrink', 'flex-basis'],
  grid: [
    'grid-template-rows',
    'grid-template-columns',
    'grid-template-areas',
    'grid-auto-rows',
    'grid-auto-columns',
    'grid-auto-flow',
    'grid-row-gap',
    'grid-column-gap',
  ],
  'list-style': ['list-style-type', 'list-style-position', 'list-style-image'],
  outline: ['outline-width', 'outline-style', 'outline-color'],
  overflow: ['overflow-x', 'overflow-y'],
  'place-items': ['align-items', 'justify-items'],
  'place-content': ['align-content', 'justify-content'],
  'place-self': ['align-self', 'justify-self'],
};

const INTERESTING_COMPUTED = [
  'display',
  'position',
  'top',
  'left',
  'right',
  'bottom',
  'width',
  'height',
  'margin',
  'padding',
  'border',
  'background-color',
  'color',
  'font-size',
  'font-family',
  'font-weight',
  'line-height',
  'text-align',
  'flex-direction',
  'justify-content',
  'align-items',
  'gap',
  'grid-template-columns',
  'grid-template-rows',
  'z-index',
  'opacity',
  'transform',
  'visibility',
  'overflow',
  'cursor',
];

export async function inspectElement(
  page: Page,
  cdp: CDPSession,
  selector: string,
  includeUserAgent = false,
): Promise<InspectResult> {

  const handle = await page.locator(selector).first().elementHandle();
  if (!handle) throw new Error(`Element not found: ${selector}`);


  await cdp.send('DOM.enable' as any, {}).catch(() => {});
  await cdp.send('CSS.enable' as any, {}).catch(() => {});


  const { root } = (await cdp.send('DOM.getDocument' as any, { depth: -1 })) as any;
  const { nodeId } = (await cdp.send('DOM.querySelector' as any, {
    nodeId: root.nodeId,
    selector,
  })) as any;
  if (!nodeId) throw new Error(`Element not found via CDP: ${selector}`);

  const { attributes: attrArray = [] } = (await cdp
    .send('DOM.getAttributes' as any, { nodeId })
    .catch(() => ({ attributes: [] }))) as any;
  const attributes: Record<string, string> = {};
  for (let i = 0; i + 1 < attrArray.length; i += 2) attributes[attrArray[i]] = attrArray[i + 1];

  const matched = (await cdp
    .send('CSS.getMatchedStylesForNode' as any, { nodeId })
    .catch(() => null)) as any;

  const rules: CSSRule[] = [];
  if (matched) {


    const inline = matched.inlineStyle;
    if (inline && inline.cssProperties && inline.cssProperties.length > 0) {
      rules.push({
        origin: 'inline',
        selector: '(inline style)',
        properties: inline.cssProperties
          .filter((p: any) => p.name)
          .map((p: any) => ({
            name: p.name,
            value: p.value,
            important: !!p.important,
            disabled: !!p.disabled,
          })),
      });
    }

    for (const m of matched.matchedCSSRules || []) {
      const r = m.rule;
      if (!r) continue;
      const origin = r.origin || 'unknown';
      if (origin === 'user-agent' && !includeUserAgent) continue;
      const sel = r.selectorList?.text || '(anonymous)';
      const source = r.styleSheetId ? `stylesheet ${r.styleSheetId}` : undefined;
      rules.push({
        origin,
        selector: sel,
        source,
        properties: (r.style?.cssProperties || [])
          .filter((p: any) => p.name)
          .map((p: any) => ({
            name: p.name,
            value: p.value,
            important: !!p.important,
            disabled: !!p.disabled,
          })),
      });
    }
  }


  const inlineStyle: Record<string, string> = {};
  const inline = matched?.inlineStyle?.cssProperties || [];
  for (const p of inline) if (p.name) inlineStyle[p.name] = p.value;


  const computedSelected = await page.evaluate(
    ({ sel, props }) => {
      const el = document.querySelector(sel);
      if (!el) return {};
      const s = getComputedStyle(el);
      const out: Record<string, string> = {};
      for (const p of props) out[p] = s.getPropertyValue(p);
      return out;
    },
    { sel: selector, props: INTERESTING_COMPUTED },
  );


  let boxModel: InspectResult['boxModel'] = null;
  try {
    const b = await handle.boundingBox();
    if (b) boxModel = { width: b.width, height: b.height, x: b.x, y: b.y };
  } catch {

  }

  const tag = await page.evaluate((s) => {
    const el = document.querySelector(s);
    return el ? el.tagName : '';
  }, selector);

  return {
    selector,
    tagName: tag,
    attributes,
    matchedRules: rules,
    inlineStyle,
    computedSelected,
    boxModel,
  };
}

export function formatInspect(r: InspectResult): string {
  const lines: string[] = [];
  lines.push(
    `${r.tagName.toLowerCase()}${
      Object.keys(r.attributes).length
        ? ' ' +
          Object.entries(r.attributes)
            .map(([k, v]) => `${k}="${v}"`)
            .join(' ')
        : ''
    }`,
  );
  if (r.boxModel)
    lines.push(`box: ${r.boxModel.width}x${r.boxModel.height} @ (${r.boxModel.x},${r.boxModel.y})`);
  lines.push('');

  if (Object.keys(r.inlineStyle).length) {
    lines.push('inline style:');
    for (const [k, v] of Object.entries(r.inlineStyle)) lines.push(`  ${k}: ${v}`);
    lines.push('');
  }

  lines.push('matched rules (author first):');
  const author = r.matchedRules.filter((x) => x.origin === 'regular' || x.origin === 'author');
  const other = r.matchedRules.filter(
    (x) => x.origin !== 'regular' && x.origin !== 'author' && x.origin !== 'inline',
  );
  for (const rule of [
    ...r.matchedRules.filter((x) => x.origin === 'inline'),
    ...author,
    ...other,
  ]) {
    lines.push(`  [${rule.origin}] ${rule.selector}${rule.source ? ` (${rule.source})` : ''}`);
    const declared = new Set(rule.properties.map((p) => p.name));
    const suppressed = new Set<string>();
    for (const name of declared) {
      const longhands = SHORTHAND_LONGHANDS[name];
      if (!longhands) continue;
      for (const lh of longhands) {
        if (declared.has(lh)) suppressed.add(lh);
      }
    }
    for (const p of rule.properties) {
      if (suppressed.has(p.name)) continue;
      lines.push(`    ${p.name}: ${p.value}${p.important ? ' !important' : ''}`);
    }
  }
  lines.push('');
  lines.push('selected computed:');
  for (const [k, v] of Object.entries(r.computedSelected)) {
    if (v && v !== 'none' && v !== 'normal' && v !== '0px' && v !== 'auto' && v !== '') {
      lines.push(`  ${k}: ${v}`);
    }
  }
  return lines.join('\n');
}
