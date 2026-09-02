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

Windows that did not end in a refusal are dropped **by default**, not left for
the reader to remember. A window stopped early — because `--pairs` reserved
room to work, or because the corpus ran out — says only that the limit was
above that number, and mixing it with a window that ran to refusal is how the
last cluster fell apart. `--include-early` puts them back for somebody who
wants to look at them on purpose; nothing else should.
"""
import argparse
import glob
import json
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

FIELDS = ("input_tokens", "output_tokens", "cache_read_tokens",
          "cache_write_tokens")
ROOT_LOG = Path("measurements/queue/log.jsonl")


def ledger(since):
    out = subprocess.run(["python3", "tools/session_ledger.py", "--since", since],
                         capture_output=True, text=True, check=False).stdout
    for line in out.splitlines():
        if line.strip():
            yield json.loads(line)


def reviews():
    """Corpus reviews, from the measurements. One row per member run."""
    # Including the queue's own files. Without them a run made through the
    # queue counted as zero reviews, and this is what estimates how much of a
    # window the work takes.
    for path in (glob.glob("measurements/*.json")
                 + glob.glob("measurements/queue/*.json")):
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


def early_windows():
    """Windows the queue closed for a reason that is not the limit.

    Read from the queue's own log rather than inferred. A reader who has to
    remember to filter is a reader who will one day not, and this is the exact
    contamination the tag was added to prevent.
    """
    path = ROOT_LOG
    if not path.is_file():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("kind") != "window":
            continue
        if row.get("window_termination") == "refused":
            continue
        # A window row with no identifier would otherwise put `None` in the
        # drop set, and every corpus review carries no `window` key at all — so
        # one malformed line silently erased every review from the analysis and
        # printed smaller numbers without saying anything had gone.
        if row.get("window"):
            out.add(row["window"])
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--include-early", action="store_true",
        help="also count windows the queue closed for a reason other than a "
             "refusal — deliberately off, because such a window says only that "
             "the limit was above its own number")
    parser.add_argument("--since", default="2026-08-28")
    args = parser.parse_args()

    dropped = set() if args.include_early else early_windows()
    everything = [*ledger(args.since), *reviews()]
    for row in everything:
        row["ts"] = stamp(row)
    everything = [r for r in everything if r.get("window") not in dropped]
    everything.sort(key=lambda r: r["ts"])

    if dropped:
        print("{} window(s) dropped: closed by something other than a refusal, so "
              "they bound the limit from below and say nothing else{}\n".format(
                  len(dropped),
                  "" if not args.include_early else " (kept anyway, as asked)"))

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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
