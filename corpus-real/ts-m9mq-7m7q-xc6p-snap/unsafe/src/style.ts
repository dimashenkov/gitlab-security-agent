import type { Page } from 'playwright';

export interface StyleChange {
  id: number;
  selector: string;
  property: string;
  newValue: string;
  previousValue: string;
  important: boolean;
  matchCount: number;
  ts: number;
}

let nextId = 1;
const history: StyleChange[] = [];

const APPLY_FN = `({ selector, property, value, important }) => {
  const els = document.querySelectorAll(selector);
  let prev = null;
  let matchCount = 0;
  for (const el of els) {
    if (matchCount === 0) prev = el.style.getPropertyValue(property) || null;
    el.style.setProperty(property, value, important ? 'important' : '');
    matchCount++;
  }
  return { previousValue: prev ?? '', matchCount };
}`;

const RESTORE_FN = `({ selector, property, previousValue, important }) => {
  const els = document.querySelectorAll(selector);
  for (const el of els) {
    if (previousValue === '' || previousValue == null) {
      el.style.removeProperty(property);
    } else {
      el.style.setProperty(property, previousValue, important ? 'important' : '');
    }
  }
}`;

export async function applyStyle(
  page: Page,
  selector: string,
  property: string,
  value: string,
  important = false,
): Promise<StyleChange> {
  const { previousValue, matchCount } = (await page.evaluate(
    `(${APPLY_FN})(${JSON.stringify({ selector, property, value, important })})`,
  )) as { previousValue: string; matchCount: number };
  if (matchCount === 0) throw new Error(`No elements match selector: ${selector}`);
  const change: StyleChange = {
    id: nextId++,
    selector,
    property,
    newValue: value,
    previousValue,
    important,
    matchCount,
    ts: Date.now(),
  };
  history.push(change);
  return change;
}

export async function undoStyle(page: Page, count = 1): Promise<StyleChange[]> {
  const undone: StyleChange[] = [];
  for (let i = 0; i < count && history.length > 0; i++) {
    const last = history.pop()!;
    await page.evaluate(
      `(${RESTORE_FN})(${JSON.stringify({
        selector: last.selector,
        property: last.property,
        previousValue: last.previousValue,
        important: last.important,
      })})`,
    );
    undone.push(last);
  }
  return undone;
}

export function styleHistory(): StyleChange[] {
  return [...history];
}

export function clearStyleHistory() {
  history.length = 0;
  nextId = 1;
}
