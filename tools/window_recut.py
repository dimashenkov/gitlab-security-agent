#!/usr/bin/env python3
"""What ran in the hours before a refusal, from every source there is.

    tools/window_recut.py

Three sources, and the third was found by checking rather than by design:
corpus reviews in `measurements/`, conversation turns in
`~/.claude/projects/`, and subagent messages in the harness's own task
transcripts. The last of those held 4490 messages and 375 million tokens
outside every count made of that day.

Both transcript trees are read by default. Reading one on request was how the
subagents went missing for three days, and the number that stood on them — "8
subagents", counted by hand — turned out to be 79 messages.

Several lookbacks are printed on purpose. The window boundary is a choice
nobody here can make correctly, and watching a number move with it is the
finding; any single value of it is not.
"""
import glob
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone

FIELDS = ("input_tokens", "output_tokens", "cache_read_tokens",
          "cache_write_tokens")


def ledger(since):
    out = subprocess.run(["python3", "tools/session_ledger.py", "--since", since],
                         capture_output=True, text=True, check=False).stdout
    for line in out.splitlines():
        if line.strip():
            yield json.loads(line)


def reviews():
    """Corpus reviews, from the measurements. One row per member run."""
    for path in glob.glob("measurements/*.json"):
        try:
            with open(path, encoding="utf-8") as handle:
                body = json.loads(handle.read())
        except (OSError, ValueError):
            continue
        for row in body if isinstance(body, list) else []:
            if not isinstance(row, dict) or not row.get("ran_at"):
                continue
            for name, member in (row.get("members") or {}).items():
                usage = member.get("usage") or {}
                yield {"kind": "review", "started_at": row["ran_at"],
                       "who": "{}/{}".format(row.get("case_id"), name),
                       **{f: usage.get(f) for f in FIELDS}}


def stamp(row):
    return datetime.fromisoformat(
        row["started_at"].replace("Z", "+00:00")).astimezone(timezone.utc)


everything = [*ledger("2026-08-28"), *reviews()]
for row in everything:
    row["ts"] = stamp(row)
everything.sort(key=lambda r: r["ts"])

# The ends of the three windows: the last thing that ran before each refusal.
ENDS = [datetime(2026, 8, 28, 23, 59, tzinfo=timezone.utc),
        datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
        datetime(2026, 8, 29, 18, 0, tzinfo=timezone.utc)]

print("{:<22} {:>6} {:>9} {:>10} {:>8} {:>15}".format(
    "window ends (UTC)", "hours", "reviews", "subagent", "session", "tokens"))

for lookback in (2, 4, 6, 8):
    print("\n-- counting everything in the {} hours before each end".format(lookback))
    for end in ENDS:
        start = end - timedelta(hours=lookback)
        inside = [r for r in everything if start <= r["ts"] <= end]
        counts = defaultdict(int)
        tokens = 0
        for row in inside:
            counts[row["kind"]] += 1
            tokens += sum(row.get(f) or 0 for f in FIELDS)
        print("{:<22} {:>6} {:>9} {:>10} {:>8} {:>15,}".format(
            end.strftime("%m-%d %H:%M"), lookback,
            counts["review"], counts["subagent-message"],
            counts["session-message"], tokens))
