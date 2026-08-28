
import { browser } from '../browser.js';

export type ToolDef = {
  name: string;
  description: string;
  inputSchema: Record<string, any>;
};

export type ToolResult = {
  content: Array<
    { type: 'text'; text: string } | { type: 'image'; data: string; mimeType: string }
  >;
  isError?: boolean;
};

export type Handler = (a: Record<string, any>) => Promise<ToolResult>;

export type ToolModule = {
  tools: ToolDef[];
  handlers: Record<string, Handler>;
};

export function text(t: string, isError = false): ToolResult {
  return { content: [{ type: 'text' as const, text: t }], isError };
}

export function image(buf: Buffer): ToolResult {
  return {
    content: [
      {
        type: 'image' as const,
        data: buf.toString('base64'),
        mimeType: 'image/png',
      },
    ],
  };
}

export async function currentUrl(): Promise<string | undefined> {
  try {

    const page = (browser as any).page;
    if (page && !page.isClosed()) return page.url();
  } catch {

  }
  return undefined;
}
