import type { Page } from 'playwright';
import { readFileSync } from 'fs';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
let AXE_SOURCE: string | null = null;

function getAxeSource(): string {
  if (AXE_SOURCE) return AXE_SOURCE;
  const axePath = require.resolve('axe-core/axe.min.js');
  AXE_SOURCE = readFileSync(axePath, 'utf8');
  return AXE_SOURCE;
}

export interface A11yViolation {
  id: string;
  impact: string | null;
  description: string;
  help: string;
  helpUrl: string;
  nodes: Array<{
    target: string[];
    html: string;
    failureSummary?: string;
  }>;
}

export interface A11yResult {
  violations: A11yViolation[];
  passes: number;
  incomplete: number;
  timestamp: string;
  url: string;
}

export async function runAxeAudit(page: Page): Promise<A11yResult> {
  const source = getAxeSource();
  await page.evaluate(source);

  const result = await page.evaluate(async () => {
    // @ts-expect-error - axe is injected into window by the prior evaluate
    const r = await window.axe.run();
    return {
      violations: r.violations,
      passes: r.passes.length,
      incomplete: r.incomplete.length,
      timestamp: r.timestamp,
      url: r.url,
    };
  });
  return result as A11yResult;
}

export function formatA11yResult(r: A11yResult): string {
  const lines: string[] = [];
  lines.push(`axe-core audit — ${r.url}`);
  lines.push(
    `passes: ${r.passes}  incomplete: ${r.incomplete}  violations: ${r.violations.length}`,
  );
  lines.push('');
  if (r.violations.length === 0) {
    lines.push('No violations.');
    return lines.join('\n');
  }
  for (const v of r.violations) {
    lines.push(`[${v.impact ?? 'unknown'}] ${v.id} — ${v.help}`);
    lines.push(`  ${v.description}`);
    lines.push(`  ${v.helpUrl}`);
    lines.push(`  ${v.nodes.length} node(s):`);
    for (const n of v.nodes.slice(0, 5)) {
      lines.push(`    - ${n.target.join(' > ')}`);
      if (n.failureSummary) {
        for (const fl of n.failureSummary.split('\n').slice(0, 3)) {
          lines.push(`      ${fl.trim()}`);
        }
      }
    }
    if (v.nodes.length > 5) lines.push(`    ... (${v.nodes.length - 5} more)`);
    lines.push('');
  }
  return lines.join('\n');
}
