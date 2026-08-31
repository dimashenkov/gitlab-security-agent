# Round 1 was frozen and never run

Frozen 2026-08-31: 62 cases, 124 reviews, 48 with a baseline. The manifest has
been deleted rather than kept, because a frozen file that describes a product
about to change looks authoritative and is not.

Two reasons, and either alone was enough.

**The product is changing underneath it.** A `/usage` reading that day showed the
session allowance exhausted with 97% of it spent above 150k context — many turns
over an already huge conversation rather than many turns. Bounding tool output
and rotating the Claude session changes what the reviewer is shown, so a pass
run after that change cannot be compared with the 2026-08-29/30 baselines the
round existed to compare against. Buying 124 reviews of the old context regime
would have measured a product we had already decided to replace.

**The execution path was not trustworthy enough to spend on.** Codex found four
defects in it, all in code written the same day:

- nothing verified a result against the frozen `case_digest`, so a row about a
  different version of a case could be counted as a valid verdict;
- every attempt wrote to the same target file, so an incomplete artifact left
  for inspection could be mistaken for a new attempt's output;
- an incomplete case was popped from the queue and counted as done, so a run
  could report completion with verdicts missing;
- `compare` returned success with cases missing or the environment drifted,
  which makes a partial report look like a finished round.

The number is not reused. The next freeze is round 2, so the numbering records
that a round was prepared and abandoned rather than hiding it.
