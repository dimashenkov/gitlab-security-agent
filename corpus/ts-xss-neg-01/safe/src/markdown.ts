import { marked } from "marked";

export function toHtml(source: string): string {
  return marked.parse(source, { async: false }) as string;
}
