import type { Page } from 'playwright';
import sharp from 'sharp';

export interface AnnotateOptions {
  color?: string;
  labelBg?: string;
  labelFg?: string;
  strokeWidth?: number;
  fontSize?: number;
}




const COLLECT_FN = `() => {
  const out = [];
  const walk = (root) => {
    const stack = [root];
    while (stack.length) {
      const node = stack.pop();
      if (node.nodeType === 1) {
        const ref = node.getAttribute && node.getAttribute('data-browse-ref');
        if (ref) {
          const r = node.getBoundingClientRect();
          if (r.width > 0 && r.height > 0 &&
              r.right >= 0 && r.bottom >= 0 &&
              r.left <= window.innerWidth && r.top <= window.innerHeight) {
            out.push({
              ref,
              x: Math.max(0, r.left),
              y: Math.max(0, r.top),
              w: r.width,
              h: r.height,
            });
          }
        }
      }
      if (node.children) for (const c of Array.from(node.children)) stack.push(c);
      if (node.shadowRoot) for (const c of Array.from(node.shadowRoot.children)) stack.push(c);
    }
  };
  walk(document.documentElement);
  return out;
}`;

export async function annotatedScreenshot(page: Page, opts: AnnotateOptions = {}): Promise<Buffer> {
  const color = opts.color || '#ff0044';
  const labelBg = opts.labelBg || '#ff0044';
  const labelFg = opts.labelFg || '#ffffff';
  const stroke = opts.strokeWidth ?? 2;
  const fontSize = opts.fontSize || 12;

  const viewport = page.viewportSize();
  if (!viewport) throw new Error('No viewport set');


  const mainBoxesRaw = (await page.evaluate(`(${COLLECT_FN})()`)) as
    | Array<{ ref: string; x: number; y: number; w: number; h: number }>
    | undefined
    | null;


  const mainBoxes = Array.isArray(mainBoxesRaw) ? mainBoxesRaw : [];


  const allBoxes = [...mainBoxes];
  const frames = page.frames();
  for (let i = 1; i < frames.length; i++) {
    try {
      const frameEl = await frames[i].frameElement();
      const box = await frameEl.boundingBox();
      if (!box) continue;

      const framedRaw = (await frames[i].evaluate(`(${COLLECT_FN})()`)) as
        | Array<any>
        | undefined
        | null;
      const framed = Array.isArray(framedRaw) ? framedRaw : [];
      for (const b of framed) {
        allBoxes.push({
          ref: b.ref,
          x: b.x + box.x,
          y: b.y + box.y,
          w: b.w,
          h: b.h,
        });
      }
    } catch {

    }
  }

  const screenshot = await page.screenshot({ type: 'png' });

  const escapeXml = (s: string) =>
    s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const parts: string[] = [];
  for (const b of allBoxes) {
    const labelText = `@${b.ref}`;
    const labelW = labelText.length * (fontSize * 0.6) + 6;
    const labelH = fontSize + 4;
    parts.push(
      `<rect x="${b.x}" y="${b.y}" width="${b.w}" height="${b.h}" fill="none" stroke="${color}" stroke-width="${stroke}"/>`,
      `<rect x="${b.x}" y="${Math.max(0, b.y - labelH)}" width="${labelW}" height="${labelH}" fill="${labelBg}"/>`,
      `<text x="${b.x + 3}" y="${Math.max(labelH - 4, b.y - 4)}" font-family="monospace" font-size="${fontSize}" fill="${labelFg}">${escapeXml(labelText)}</text>`,
    );
  }

  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${viewport.width}" height="${viewport.height}">${parts.join('')}</svg>`;

  return await sharp(screenshot)
    .composite([{ input: Buffer.from(svg), top: 0, left: 0 }])
    .png()
    .toBuffer();
}
