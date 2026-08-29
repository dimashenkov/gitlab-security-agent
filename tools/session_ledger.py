#!/usr/bin/env python3
"""Every invocation this machine made, in the queue's own row format.

`run_queue` logs the reviews it runs. It cannot log the conversation that
launched it — that runs in another process — or the subagents that conversation
spawned, and those draw on the same allowance. A window half eaten by a long
conversation would otherwise look like an inexplicably low limit.

Claude Code writes a JSONL transcript per session under `~/.claude/projects/`,
and every assistant message in it carries the provider's usage block. That is
the missing half of the ledger, and it is already on disk.

    tools/session_ledger.py --since 2026-08-28 > measurements/queue/sessions.jsonl

Two sources, because subagents are not in the first one. `~/.claude/projects/`
holds the conversations; a subagent's messages are written to the harness's own
task transcript and appear nowhere under that directory. Checked, not assumed:
on a day with 22 subagent runs the projects tree carried 2634 rows and not one
of them was marked as a sidechain, while the task transcripts held 4490
assistant messages and 375 million tokens. That load sat outside every count
made of that day, including the window analysis that concluded from it.

One row per message, the same shape `run_queue` writes: both ends of the call,
the kind, and the four token counts separately. Nothing summed — adding the
four gives a number that is 99% cache reads, and any total containing them says
the conversation dominates whatever else is true.

Only counts and timestamps are read. No message content is opened, and none is
written out.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
from pathlib import Path

# The provider's spelling, read off these transcripts rather than guessed.
FIELDS = {"input_tokens": "input_tokens",
          "output_tokens": "output_tokens",
          "cache_creation_input_tokens": "cache_write_tokens",
          "cache_read_input_tokens": "cache_read_tokens"}


def rows(pattern: str, since: str, kind: str = "session-message"):
    for path in sorted(glob.glob(os.path.expanduser(pattern))):
        # The directory Claude Code derives from the working directory. A
        # corpus review runs in a temporary checkout, so its transcript lands
        # somewhere else entirely — which is how a subagent is told apart from
        # the conversation without reading a word of either.
        project = Path(path).parent.name
        session = Path(path).stem
        try:
            with open(path, encoding="utf-8", errors="replace") as handle:
                lines = list(handle)
        except OSError:
            continue
        for line in lines:
            if '"usage"' not in line:
                continue
            try:
                body = json.loads(line)
            except ValueError:
                continue
            usage = (body.get("message") or {}).get("usage") or body.get("usage")
            stamp = body.get("timestamp")
            if not isinstance(usage, dict) or not stamp or stamp < since:
                continue
            row = {
                # `session-message`, not `interactive`: whether a message
                # in a conversation counts the same as a corpus review is
                # the open question, and naming it by what it *is* rather
                # than by what it costs keeps the question open.
                "kind": kind,
                "project": project, "session": session[:8],
                "started_at": stamp, "finished_at": stamp,
                "is_sidechain": bool(body.get("isSidechain")),
                "usage_reported": True,
            }
            for source, name in FIELDS.items():
                row[name] = usage.get(source)
            yield row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--since", default="2026-01-01",
                        help="ISO date; rows before it are skipped")
    parser.add_argument("--pattern", default="~/.claude/projects/*/*.jsonl")
    parser.add_argument(
        "--tasks", default="/private/tmp/claude-501/*/*/tasks/a*.output",
        help="the harness's own transcripts, where subagent messages land")
    parser.add_argument("--count", action="store_true",
                        help="print a count per day instead of the rows")
    args = parser.parse_args()

    everything = list(rows(args.pattern, args.since, "session-message"))
    everything += list(rows(args.tasks, args.since, "subagent-message"))
    everything.sort(key=lambda r: r["started_at"])

    if not args.count:
        for row in everything:
            print(json.dumps(row, ensure_ascii=False))
        return 0

    from collections import Counter
    per_day = Counter()
    for row in everything:
        per_day[(row["started_at"][:10], row["kind"])] += 1
    for key in sorted(per_day):
        print("{}  {:<18} {:>6} message(s)".format(key[0], key[1], per_day[key]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
