type DiffOp = { type: ' ' | '+' | '-'; line: string; aIdx: number; bIdx: number };

export function unifiedDiff(a: string, b: string, context = 3): string {
  const aLines = a.split('\n');
  const bLines = b.split('\n');
  const lcs = buildLcs(aLines, bLines);
  let i = aLines.length,
    j = bLines.length;
  const stack: DiffOp[] = [];
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && aLines[i - 1] === bLines[j - 1]) {
      stack.push({ type: ' ', line: aLines[i - 1], aIdx: i - 1, bIdx: j - 1 });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || lcs[i][j - 1] >= lcs[i - 1][j])) {
      stack.push({ type: '+', line: bLines[j - 1], aIdx: i, bIdx: j - 1 });
      j--;
    } else {
      stack.push({ type: '-', line: aLines[i - 1], aIdx: i - 1, bIdx: j });
      i--;
    }
  }
  stack.reverse();


  const out: string[] = [];
  let pending: DiffOp[] = [];
  let lastChange = -1;

  const flush = () => {
    if (pending.length === 0) return;
    const trimStart = Math.max(0, findFirstChange(pending) - context);
    const trimEnd = Math.min(pending.length, findLastChange(pending) + 1 + context);
    const hunk = pending.slice(trimStart, trimEnd);
    out.push(`@@ -${hunk[0].aIdx + 1} +${hunk[0].bIdx + 1} @@`);
    for (const op of hunk) out.push(`${op.type}${op.line}`);
    pending = [];
  };

  for (let k = 0; k < stack.length; k++) {
    const op = stack[k];
    pending.push(op);
    if (op.type !== ' ') lastChange = k;
    if (op.type === ' ' && lastChange >= 0 && k - lastChange > context * 2) {
      flush();
      lastChange = -1;
    }
  }
  if (lastChange >= 0) flush();
  if (out.length === 0) return '(no changes)';
  return out.join('\n');
}

function buildLcs(a: string[], b: string[]): number[][] {
  const m = a.length,
    n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) dp[i][j] = dp[i - 1][j - 1] + 1;
      else dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp;
}

function findFirstChange(ops: Array<{ type: string }>): number {
  for (let i = 0; i < ops.length; i++) if (ops[i].type !== ' ') return i;
  return 0;
}

function findLastChange(ops: Array<{ type: string }>): number {
  for (let i = ops.length - 1; i >= 0; i--) if (ops[i].type !== ' ') return i;
  return ops.length - 1;
}
