import { resolve, sep, posix } from 'path';















export function confineToDir(root: string, requested?: string): string {
  const base = resolve(root);
  if (requested == null || requested === '') return base;
  const target = resolve(base, requested);
  if (target !== base && !target.startsWith(base + sep)) {
    throw new Error(
      `Refusing path outside the allowed directory: ${JSON.stringify(requested)} ` +
        `resolves outside ${base}. Pass a path under it, or relocate the root with BROWSE_MCP_HOME.`,
    );
  }
  return target;
}







export function safeBasename(name: string): string {
  const b = posix.basename(String(name).replace(/\\/g, '/'));
  if (!b || b === '.' || b === '..') return '';
  return b;
}
