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
    """The transcript rows, and whether reading them worked.

    Returns `(rows, problem)`. It used to take `.stdout` from a `check=False`
    subprocess and iterate it — so a `session_ledger.py` that raised gave an
    empty string, no rows, and a table printing zero subagent and zero session
    messages beside a full review count. Two of the three sources would have
    silently gone missing from the analysis the quota estimate rests on, and
    the output looks exactly like a quiet day.
    """
    proc = subprocess.run(["python3", "tools/session_ledger.py", "--since", since],
                          capture_output=True, text=True, check=False)
    rows, bad = [], 0
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except ValueError:
            bad += 1
    problem = None
    if proc.returncode != 0:
        problem = "session_ledger.py exited {}: {}".format(
            proc.returncode,
            (proc.stderr or "").strip().splitlines()[-1] if proc.stderr else
            "no message")
    elif bad:
        problem = "{} unreadable line(s) from session_ledger.py".format(bad)
    elif not rows:
        problem = "session_ledger.py produced no rows"
    return rows, problem


def result_files():
    """Every file a paid run has written, in all four places it writes them.

    Batches at the top level, one per case under `queue/`, one per case under
    `experiment-*/pass-*/`, and one per case under `round-*/`. Reading only the
    first two left 27 experiment files unread out of 72 — reviews that were
    bought, that consumed a window, and that this tool exists to count.
    """
    return sorted(set(glob.glob("measurements/*.json")
                      + glob.glob("measurements/queue/*.json")
                      + glob.glob("measurements/experiment-*/pass-*/*.json")
                      + glob.glob("measurements/round-*/*.json")))


def rows_in(body):
    """The rows a result file holds, whichever of the three shapes it is.

    A batch is a list, an experiment writes one bare object per file, and
    `{"results": [...]}` is a shape two other tools here accept. Iterating only
    lists opened each experiment file, parsed it, and then read it as nothing.
    """
    if isinstance(body, list):
        return [row for row in body if isinstance(row, dict)]
    if isinstance(body, dict):
        found = body.get("results")
        if isinstance(found, list):
            return [row for row in found if isinstance(row, dict)]
        return [body]
    return []


def review_windows(path=ROOT_LOG):
    """`(case_id, member) -> window`, from the queue's own log.

    Without this the drop filter could not do anything: no row out of
    `reviews()` carries a `window` key, so `r.get("window") not in dropped` was
    true for every review ever, while the banner above the table announced that
    windows had been dropped. Two windows named, nothing removed, and a printed
    sentence saying otherwise.
    """
    out = {}
    if not Path(path).is_file():
        return out
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if row.get("kind") != "review" or not row.get("window"):
            continue
        # Keyed by the moment as well as the case. `(case_id, member)` with
        # `setdefault` kept the *first* window seen and then stamped it on
        # every measurement of that case — so a case run again in a later
        # window had all its history attributed to the first one. With the
        # drop filter now actually removing rows, that mis-attribution can
        # remove valid later measurements, or keep ones that should go.
        key = (row.get("case_id"), row.get("member"),
               row.get("started_at") or row.get("finished_at"))
        out.setdefault(key, row["window"])
    return out


def reviews(windows=None):
    """Corpus reviews, from the measurements. One row per member run.

    Each row carries `usage_complete`. A member whose usage the CLI reported
    only in part has real tokens nobody recorded, and adding its missing stages
    in as zero produces a total that is a floor and prints as a measurement.
    """
    windows = review_windows() if windows is None else windows
    for path in result_files():
        try:
            with open(path, encoding="utf-8") as handle:
                body = json.loads(handle.read())
        except (OSError, ValueError):
            continue
        for row in rows_in(body):
            if not row.get("ran_at"):
                continue
            for name, member in (row.get("members") or {}).items():
                usage = member.get("usage") or {}
                out = {"kind": "review", "started_at": row["ran_at"],
                       "who": "{}/{}".format(row.get("case_id"), name),
                       # `is True`, not `is not False`. A row that never
                       # recorded whether its usage was complete was read as
                       # complete — the absence-is-agreement defect, one step
                       # inside the fix written against it. 38 rows on disk
                       # carry no such field, and their sums were printed
                       # without the `≥` that says the number is a floor.
                       "usage_complete": usage.get("complete") is True,
                       **{f: usage.get(f) for f in FIELDS}}
                # Matched on the moment as well, so a case measured twice is
                # attributed to the window each measurement actually ran in.
                # Looked up by `ran_at` first and by the pair only as a
                # fallback for rows the log recorded before it carried a
                # timestamp — and that fallback is used only when the case has
                # exactly one window, because otherwise it is a guess.
                window = windows.get((row.get("case_id"), name, row["ran_at"]))
                if not window:
                    seen = {value for (case, member, _when), value
                            in windows.items()
                            if case == row.get("case_id") and member == name}
                    window = seen.pop() if len(seen) == 1 else None
                if window:
                    out["window"] = window
                yield out


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


def main(argv=None) -> int:
    # `argv` so the report itself can be exercised. Reading `sys.argv` directly
    # left every one of the printed claims — the dropped-window banner most of
    # all — reachable only by running the tool and looking at it.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--include-early", action="store_true",
        help="also count windows the queue closed for a reason other than a "
             "refusal — deliberately off, because such a window says only that "
             "the limit was above its own number")
    parser.add_argument("--since", default="2026-08-28")
    args = parser.parse_args(argv)

    dropped = set() if args.include_early else early_windows()
    transcripts, problem = ledger(args.since)
    everything = [*transcripts, *reviews()]
    for row in everything:
        row["ts"] = stamp(row)
    kept = [r for r in everything if r.get("window") not in dropped]
    removed = len(everything) - len(kept)
    everything = kept
    everything.sort(key=lambda r: r["ts"])

    if problem:
        # Loud, and above the table. Two of the three sources come through the
        # ledger, and a table missing them looks like a quiet day rather than
        # like a tool that could not read its own input.
        print("!! the transcript sources could not be read: {}\n"
              "   the subagent and session columns below are not counts, they "
              "are absences.\n".format(problem))

    if dropped:
        # The count of rows removed, not only of windows named. The filter had
        # nothing to match on — no review carried a `window` — so this line
        # announced two dropped windows above a table from which nothing at all
        # had been dropped, for as long as anybody had read it.
        print("{} window(s) dropped, removing {} row(s): closed by something "
              "other than a refusal, so they bound the limit from below and say "
              "nothing else{}\n".format(
                  len(dropped), removed,
                  "" if not args.include_early else " (kept anyway, as asked)"))

    # The ends of the three windows: the last thing that ran before each refusal.
    ENDS = [datetime(2026, 8, 28, 23, 59, tzinfo=timezone.utc),
            datetime(2026, 8, 29, 10, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 29, 18, 0, tzinfo=timezone.utc)]

    print("{:<22} {:>6} {:>9} {:>10} {:>8} {:>16} {:>9}".format(
        "window ends (UTC)", "hours", "reviews", "subagent", "session",
        "tokens", "partial"))

    partial_anywhere = False
    for lookback in (2, 4, 6, 8):
        print("\n-- counting everything in the {} hours before each end".format(lookback))
        for end in ENDS:
            start = end - timedelta(hours=lookback)
            inside = [r for r in everything if start <= r["ts"] <= end]
            counts = defaultdict(int)
            tokens = partial = 0
            for row in inside:
                counts[row["kind"]] += 1
                tokens += sum(row.get(f) or 0 for f in FIELDS)
                # A run whose usage the CLI reported only in part still spent
                # the tokens of the stages it did not report. Summing `or 0`
                # over them puts a zero where a number belongs, and the result
                # printed under a column called `tokens` as though it were the
                # figure. 57 of the 156 member runs in this corpus are such
                # runs. The total is a floor and now says so.
                if row["kind"] == "review" and not row.get("usage_complete", True):
                    partial += 1
            partial_anywhere = partial_anywhere or bool(partial)
            print("{:<22} {:>6} {:>9} {:>10} {:>8} {:>16} {:>9}".format(
                end.strftime("%m-%d %H:%M"), lookback,
                counts["review"], counts["subagent-message"],
                counts["session-message"],
                ("≥{:,}" if partial else "{:,}").format(tokens),
                partial))

    if partial_anywhere:
        print("\n`partial` counts member runs whose usage the CLI reported only "
              "in part. Their unreported stages are added in as zero, so every "
              "token total marked ≥ is a floor and not a measurement.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
