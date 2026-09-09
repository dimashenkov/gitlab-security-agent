#!/usr/bin/env python3
"""What the reviews on this machine cost, from artifacts already written.

    tools/spend.py                      # every artifact under .security-scan and journal
    tools/spend.py --since 2026-08-01
    tools/spend.py path/to/findings.json ...
    tools/spend.py --by month

**Nothing is sent anywhere.** It reads files this machine already wrote and
prints. A security reviewer that reads private code and then reports usage
outward is a tool many teams will not run at all, and the number is just as
useful on the machine that produced it.

## The distinction the whole tool is built around

`total_cost_usd` is not a bill. The Claude Code CLI reports it on a subscription
too — a two-token reply on a Max plan came back as $0.29 — so on that path it is
what the run *would* have cost at API list price and nobody was charged it. This
project has already built three wrong rules about its weekly allowance by reading
that number as money spent, so the split is not a footnote here: billed and
notional are counted separately, printed separately, and never added together.

Which one a run is comes from `provenance.provider`, not from the size of the
number.

## Absent is not zero

A run whose provider reported no cost contributes to a count of unreported runs
and to no total. Padding it with 0.00 would drag a median toward the floor while
looking like a cheap run, which is the same defect one level up from the one
`Usage` exists to prevent. The same applies to the token counts: `Usage` carries
`unreported_stages` precisely so a total can admit which of its parts it could
not see, and that admission is printed rather than dropped.
"""

from __future__ import annotations

import argparse
import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
import glob
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

ROOT = Path(__file__).resolve().parents[1]

# Where an artifact lands by default. `SECURITY_SCAN_OUTPUT_DIR` moves it, so a
# caller with a different layout passes paths instead.
DEFAULT_GLOBS = (".security-scan/**/findings.json", "journal/**/findings.json",
                 # This repository's own kept artifacts. Without it the tool
                 # reported "no artifacts found" in the tree that has spent the
                 # most, because the first two are where a *user's* run writes.
                 "measurements/**/findings.json",
                 # Many runs in one file, which `read_runs` unpacks. The
                 # ordinary-changes measurement writes only this — 27 reviews
                 # that the counter did not see at all until 2026-09-06.
                 "measurements/**/rows.json")

# The queue writes one row per invocation, and that is a different record from
# an artifact: the corpus runs kept an artifact only for the members that
# failed. Read as a separate source and never merged, because a review can
# appear in both and nothing keys them together — summing them would inflate
# the one number this tool exists to state carefully.
QUEUE_LOG = "measurements/queue/log.jsonl"
# And the same log under a round: `run_queue --round N` rebinds both the queue
# directory and its log to `measurements/round-N/`. A whole round's rows were
# invisible to the one command that answers "what has this cost", because this
# constant named one path and nothing looked for the others.
# The rounds only. The queue's own log is `QUEUE_LOG` above and is read
# through that name, so a caller — or a test — that repoints it still moves
# what this reads. A second copy of the same path here would be one more place
# for the two to drift.
ROUND_LOGS = "measurements/round-*/log.jsonl"
# Set by `queue_rows`: lines it could not parse, or -1 for a log it
# could not read at all.
QUEUE_SKIPPED = 0

BILLED = "anthropic-api"
NOTIONAL = "claude-cli"

TOKEN_FIELDS = ("input_tokens", "output_tokens",
                "cache_read_tokens", "cache_write_tokens")

# **Classification comes from the billing arrangement, not the tool's name.**
# For each vendor this repository calls, one question: if we make one more call
# right now, does a bill go up? The answer is written here with the date it was
# established, so nobody re-derives it from the name.
#
# `None` means nobody has established it. That is not "probably free": it is the
# state that stops this tool printing a total, because a figure that silently
# omits a spend is the defect the whole file exists to prevent.
# `kind` is `metered` or `flat`, and nothing else is accepted — an arrangement
# this tool cannot read is treated exactly as one nobody wrote.
FLAT = "flat"
METERED = "metered"

# Anthropic is deliberately **not** in this table. Codex, 2026-09-06: it had an
# entry with a third `kind`, `per-row`, which the invariant above does not
# admit — a table whose own contents break its rule. The arrangement there is
# genuinely per row rather than per vendor: the `anthropic-api` path is metered
# and every other path is the Claude subscription, established 2026-08-30 with
# the price worked out ($53 at the median for the corpus remainder) and the
# owner's decision that an API key is never used. `paid_by` decides it from the
# provenance of each review, and this table is for vendors whose whole ledger
# shares one arrangement.
BILLING_ARRANGEMENT: Dict[str, Optional[Dict[str, str]]] = {
    # Established by the owner on 2026-09-06, answering the one question this
    # table is for: a SuperGrok Lite subscription at €20 a month, so one more
    # call moves no bill. `total_cost_usd` on that path is list price for
    # tokens nobody was charged for — the same shape as Claude Code's, and the
    # same trap: it is the most tempting number here because it looks exactly
    # like an invoice.
    #
    # `docs/grok-on-this-machine.md` said on line 141 that "every call spends
    # the owner's money" while line 72 called the figure notional. The owner's
    # answer settles it: line 141 was wrong and is corrected there.
    "xai": {"kind": FLAT, "established": "2026-09-06",
            "why": "SuperGrok Lite, €20 a month; one more call moves no bill"},
}

# Spending this counter cannot see, named rather than omitted. The test is not
# "is it large" but "does the counter see it" — and asserting which is largest
# would be the same unmeasured claim the file refuses everywhere else.
INVISIBLE = (
    "the agent session itself, billed to a plan no artifact here records",
    "Codex review rounds, on a different account and not logged in this tree",
)


def _looks_like_a_run(row: Any) -> bool:
    """Does this element describe one review, or is it something else in a list.

    Asked before the element is read as a run, not after. A list of strings, or
    of the per-case scores some tool happens to write, would otherwise be
    counted as that many runs with no cost reported — which reads in the report
    as "runs whose price nobody recorded", the one sentence this tool exists to
    keep honest.
    """
    return isinstance(row, dict) and (
        "cost_usd" in row or isinstance(row.get("provenance"), dict))


def read_runs(paths: Iterable[Path]) -> tuple:
    """The runs among `paths`, and how many files could not be read as any.

    Two shapes, and the file says which it is rather than the reader guessing:
    an object is one review's artifact, and an array is a file of many — which
    is what `ordinary_noise.py` writes, 27 runs in one `rows.json`. Until
    2026-09-06 the array fell through an `isinstance(body, dict)` and was
    dropped without a word, so the whole ordinary-changes measurement was
    invisible to the counter that is quoted in every report. Absence read as
    agreement, in the tool whose entire job is to say what was spent.

    Unreadable is counted, not skipped silently: a shorter report that does not
    say it is shorter is the failure this project keeps finding in itself.
    """
    out: List[Dict[str, Any]] = []
    bad = 0
    # **Each file once, by identity.** `tools/spend.py PATH PATH` read the
    # same artifact twice and printed `$10.00 charged, from 2 metered call(s)`
    # for one $5.00 call — flatly, with no `≥` and no qualification, exit 0.
    # A hard link or two paths to one file does the same. `_rows_and_artifacts
    # _together` only warns when a file literally named `rows.json` is
    # present, so nothing caught it.
    #
    # By inode rather than by path text: `a/../a/x.json` and `a/x.json` are
    # one file and compare unequal as strings, and the whole point of this
    # tool is that a number nobody can trace is worse than no number.
    seen_files = set()
    for path in paths:
        try:
            fingerprint = path.stat()
            identity = (fingerprint.st_dev, fingerprint.st_ino)
        except OSError:
            identity = None
        if identity is not None:
            if identity in seen_files:
                continue
            seen_files.add(identity)
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            bad += 1
            continue
        # A lone object is one record and is asked what it is on the same
        # terms as an element of a list. Codex, 2026-09-06: the classifier was
        # applied to array elements only, so any object at all — a summary, a
        # scorer's output, a config — became a review whose price nobody
        # reported, which is a sentence this tool prints and means.
        records = list(enumerate(body)) if isinstance(body, list) \
            else [(None, body)]
        for index, record in records:
            if not _looks_like_a_run(record):
                # Counted, one per record, rather than skipped. A mixed file
                # used to be accepted whole as long as one element looked
                # right, and the elements that did not simply vanished.
                bad += 1
                continue
            record["_path"] = str(path) if index is None \
                else "{}[{}]".format(path, index)
            out.append(record)
    return out, bad


def artifacts(paths: Iterable[Path]) -> List[Dict[str, Any]]:
    """The runs alone, for callers that do not report the unreadable count."""
    return read_runs(paths)[0]


def _provenance(row: Dict[str, Any]) -> Dict[str, Any]:
    value = row.get("provenance")
    return value if isinstance(value, dict) else {}


def as_money(value: Any) -> Optional[float]:
    """`value` as dollars, or None when it is not money at all.

    Finite and not negative, checked rather than assumed. Codex, 2026-09-05:
    `float(value)` accepted `-1`, `inf` and `nan`, and each does something
    worse than being wrong on its own — a negative cost reduces a total, and
    one `nan` anywhere turns every total containing it into `nan`. A value that
    is not money is not a cheap run; it is a record nobody can price.

    One function, because there are two places money is read — a review
    artifact and a vendor ledger — and the second was doing it without any of
    this. Codex the same day, on the version that had only fixed the first.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    if number != number or number in (float("inf"), float("-inf")) \
            or number < 0:
        return None
    return number


def cost_of(row: Dict[str, Any]) -> Optional[float]:
    """The reported cost of one review, or None when there is no usable one."""
    return as_money(_provenance(row).get("reported_cost_usd"))


MONEY, ABSENT, UNREADABLE = "money", "absent", "unreadable"


def money_state(holder: Dict[str, Any], field: str) -> str:
    """`money`, `absent`, or `unreadable` for one field — three answers.

    `as_money` collapses the last two into `None`, which is right for
    arithmetic and wrong for a report: a record that says nothing bounds a
    total from below, and one that says something nobody can read does not
    bound it at all.

    One function for both kinds of record. Codex found this same distinction
    missing in three places on 2026-09-06 — the headline, the breakdown table,
    and the vendor ledger — because each had its own spelling of it. `null` is
    the JSON spelling of "no value" and is absent wherever it appears:
    `run_queue.py` always writes its cost key and puts `None` in it when the
    provider reported nothing.
    """
    if field not in holder or holder[field] is None:
        return ABSENT
    return MONEY if as_money(holder[field]) is not None else UNREADABLE


def cost_state(row: Dict[str, Any]) -> str:
    """`money_state` for one review's recorded cost."""
    return money_state(_provenance(row), "reported_cost_usd")


def money(amount: float) -> str:
    """Dollars without losing the ones that matter here.

    Two decimals was the whole format, and a single model call costs about
    $0.006 — so every one of them rendered as `$0.00`, which reads as free.
    Codex, 2026-09-05. Small amounts keep four decimals; a positive amount
    that would still round to nothing says so rather than printing zero.
    """
    if amount and amount < 0.0001:
        return "<$0.0001"
    return "${:.4f}".format(amount) if amount < 1 else "${:.2f}".format(amount)


# Three, because two could not express the case that matters. The first
# version had `billed()` returning a bool keyed on `provider`, and it was wrong
# in exactly the way this tool exists to prevent: `claude-cli` is how the run
# was launched, not who paid for it. `Authentication.method` is `claude.ai` for
# a subscription login and `api-key` or `console` for a billed one, so a CLI run
# whose stored login is an API key is charged — and was being reported as
# notional. A subscription figure and a bill were about to be added under the
# wrong heading by the tool written to keep them apart.
CHARGED = "charged"
NOTIONAL_ = "notional"
UNKNOWN = "unknown"


def paid_by(row: Dict[str, Any]) -> str:
    """`charged`, `notional`, or `unknown` — never inferred from the number.

    `unknown` is a real answer and is never folded into either money column.
    Guessing it as notional would understate a bill, and understating a cost is
    believed while overstating one prompts a question.
    """
    prov = _provenance(row)
    # A string, or nobody established it. Codex, 2026-09-05: `.strip()` was
    # called on whatever was truthy, so `"auth_method": 1` raised
    # `AttributeError` and the command printed neither a figure nor a
    # diagnostic — a crash where "I could not tell" belongs, in the function
    # whose whole job is telling those apart.
    raw = prov.get("auth_method")
    method = raw.strip() if isinstance(raw, str) else ""
    # And the subscription by the same rule. Codex, 2026-09-05, immediately
    # after the fix above: any truthy value counted, so
    # `"auth_subscription": 1` or `"   "` classified the run as a subscription
    # and the command printed "$0.00 charged" and exited 0 from provenance
    # nobody could read. The false answer this tool exists to prevent, from the
    # one branch that produces it.
    plan = prov.get("auth_subscription")
    named = isinstance(plan, str) and bool(plan.strip())

    # **Signals gathered, then weighed** — not a chain of `if`s where whichever
    # is written first wins. Codex, 2026-09-05, twice in two rounds: the first
    # version let `provider == anthropic-api` decide over a `claude.ai` login,
    # and the fix for that was another special case, which left `api-key`
    # together with a named plan resolving by branch order in exactly the same
    # way. A contradiction is not a thing to rank; it is a thing nobody
    # established, and this file counts that in neither column.
    #
    # Billed evidence: the Messages API path, or a login that is a key.
    # Subscription evidence: a plan named at all.
    charged_because = []
    if prov.get("provider") == BILLED:
        charged_because.append("the provider is the Messages API")
    if method in ("api-key", "console"):
        charged_because.append("the login is {!r}".format(method))

    subscription_because = []
    # `claude.ai` is subscription evidence in its own right, and the first
    # version of this gathering counted only a named plan — so
    # `{"provider": "anthropic-api", "auth_method": "claude.ai"}` came back
    # charged from a record whose two halves disagree. Codex, 2026-09-05, the
    # third round on this one function.
    if method == "claude.ai":
        subscription_because.append("the login is `claude.ai`")
    if named:
        subscription_because.append("a plan is named")

    if charged_because and subscription_because:
        return UNKNOWN
    if charged_because:
        return CHARGED
    # **The two thresholds are deliberately different, and the asymmetry is the
    # point.** One subscription signal is enough to *contradict* billed
    # evidence, because a contradiction means nobody can tell. Both are
    # required to *classify* a run as a subscription, because that classifies
    # its money as nothing — and this file's own rule is that understating a
    # cost is believed while overstating one prompts a question.
    #
    # A plan recorded beside no login says which subscription the machine has,
    # not that this run drew on it. A `claude.ai` login with no plan named is
    # the CLI reporting half of an answer. Neither is a reason to write $0.
    #
    # Codex argued on 2026-09-05 that gathering a signal and then not acting on
    # it alone is inconsistent. It is asymmetric on purpose: the cost of a
    # wrong `unknown` is a question, and the cost of a wrong `notional` is a
    # spend that never appears.
    if named and method == "claude.ai":
        return NOTIONAL_
    # An empty method is the CLI declining to say, an unparseable answer, or a
    # timeout. All three are "nobody established this".
    return UNKNOWN


def billed(row: Dict[str, Any]) -> bool:
    """Kept for readers that want the yes/no; `paid_by` is the honest answer."""
    return paid_by(row) == CHARGED


def who_paid(row: Dict[str, Any]) -> str:
    prov = _provenance(row)
    state = paid_by(row)
    if state == CHARGED:
        return "API key — billed"
    if state == NOTIONAL_:
        return "subscription ({}) — notional".format(prov.get("auth_subscription"))
    return "not established — counted in neither column"


def when(row: Dict[str, Any]) -> str:
    return str(row.get("generated_at") or "")


def tokens(row: Dict[str, Any]) -> Dict[str, Optional[int]]:
    usage = row.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    return {name: usage.get(name) for name in TOKEN_FIELDS}


def unreported_stages(row: Dict[str, Any]) -> int:
    usage = row.get("usage")
    value = usage.get("unreported_stages") if isinstance(usage, dict) else None
    return value if isinstance(value, int) else 0


def queue_logs(root: Path) -> list:
    """Every log the queue writes, in the two places it writes them.

    `--round N` rebinds `LOG` to `measurements/round-N/log.jsonl`, so a round
    bought 52 pairs into a file this tool never opened.
    """
    out = [root / QUEUE_LOG]
    out.extend(sorted(Path(p) for p in glob.glob(str(root / ROUND_LOGS))))
    return out


def queue_rows(path: Path) -> List[Dict[str, Any]]:
    """The queue's own log, reshaped into the fields `summarise` reads.

    Every row is notional by construction: the queue runs on `claude-cli`, and
    the log says so in `notional_api_cost_source` rather than leaving a reader
    to infer it from the provider.
    """
    # Reset first, on every path through. Codex, 2026-09-05: the absent-file
    # branch returned without touching it, so a run that had found a broken log
    # left `-1` behind and the next call — with no log at all — reported that
    # earlier failure as its own. Module state that outlives the call it
    # describes is a wrong answer waiting for a second invocation.
    globals()["QUEUE_SKIPPED"] = 0
    if not path.is_file():
        return []
    out: List[Dict[str, Any]] = []
    try:
        body = path.read_text(encoding="utf-8")
    except OSError:
        # `is_file()` passing does not make the read succeed, and a report that
        # silently loses the whole log is the failure this tool is about.
        globals()["QUEUE_SKIPPED"] = -1
        return []
    skipped = 0
    for line in body.splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(row, dict) or row.get("kind") != "review":
            continue
        cost = row.get("notional_api_cost")
        provenance: Dict[str, Any] = {
            "provider": NOTIONAL,
            "model_requested": row.get("model", ""),
            # Carried when the row has them. Rows written before the queue
            # recorded these classify as unknown, which is what they are: the
            # log did not say, and the cost cannot be assigned to a pot on the
            # strength of the runner's name.
            "auth_method": row.get("auth_method") or "",
            "auth_subscription": row.get("auth_subscription") or "",
        }
        # The raw value, carried through as it was written. Codex, 2026-09-06:
        # this used to filter on `isinstance(..., (int, float))`, which both
        # dropped a present-but-unreadable `"1.25"` — so it arrived downstream
        # as "no cost recorded" and printed a floor — and let `True` through as
        # `$1.00`. Sanitising at the reader takes the judgement away from the
        # one function that makes it, and hands the report a value nobody
        # weighed. Absence stays absence; anything present reaches `as_money`.
        if "notional_api_cost" in row:
            provenance["reported_cost_usd"] = cost
        usage: Dict[str, Any] = {name: row.get(name) for name in TOKEN_FIELDS}
        # `usage_reported` false means the run finished and its figures never
        # arrived: an admitted gap, not four zeros.
        usage["unreported_stages"] = 0 if row.get("usage_reported") else 1
        out.append({
            "generated_at": row.get("started_at", ""),
            "provenance": provenance,
            "usage": usage,
            "_path": "{}:{}/{}".format(path, row.get("case_id"), row.get("member")),
        })
    # Counted, not swallowed. The artifact path promises unreadable records are
    # reported; this one had the same obligation and dropped them in silence.
    globals()["QUEUE_SKIPPED"] = skipped
    return out


# Where a paid call to a vendor other than Anthropic is recorded, and the block
# holding one entry per call. Both tools write `vendor` at the top and key their
# attempts by the unit of *work* — a case id, a finding id — which is not the
# unit of *billing*. Codex, 2026-09-05: the billing identity is
# `(vendor, request_id)`; a retry has a new request id and is a second charge,
# and the same response copied into two aggregates is one.
VENDOR_GLOBS = ("measurements/**/grok-adjudication.json",
                "measurements/**/alarm-classification.json")
VENDOR_CALL_BLOCKS = ("cases", "findings")


def _vendor_blocks(body: Any) -> Optional[List[str]]:
    """The per-call blocks a vendor ledger holds, or `None` if it is not one.

    One predicate, used by the detector and by the reader. Codex, 2026-09-05:
    they had drifted by a single word — the detector asked `any` and the reader
    required exactly one — so a file carrying both `cases` and `findings` was
    excluded from the reviews as a ledger and then refused as a ledger, and
    disappeared from both counts leaving only an error. Two definitions of one
    thing, and the gap between them was a file nobody counted.
    """
    if not isinstance(body, dict):
        return None
    vendor = body.get("vendor")
    if not isinstance(vendor, str) or not vendor.strip():
        return None
    return [name for name in VENDOR_CALL_BLOCKS
            if isinstance(body.get(name), dict)]


def _looks_like_a_vendor_ledger(path: Path) -> bool:
    """Whether a named file is *shaped* like a metered vendor's ledger.

    By its content, not its name: a caller who renamed the file still means the
    same thing, and a review artifact that happened to be called
    `grok-adjudication.json` is still a review. Unreadable is `False` — the
    artifact reader reports what it could not read, and one file counted in
    neither place would be worse than one counted as the wrong kind.

    **Shape, and not validity.** Codex, 2026-09-05: this used `_vendor_blocks`,
    which requires a usable `vendor`, so a ledger that named no vendor was
    routed to the review reader and came back as an unclassified review rather
    than the "records no vendor" ledger problem it is. A malformed record of a
    kind is still a record of that kind, and it belongs in front of the reader
    that can say what is wrong with it.
    """
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    if not isinstance(body, dict):
        return False
    # A review artifact carries `provenance`; a ledger carries per-call blocks.
    # Asking for both keeps a review that happens to hold a `cases` key on the
    # review side, where its provenance can still be read.
    #
    # `name in body`, not `isinstance(..., dict)`. Codex, 2026-09-05, on the
    # version that had just been widened once: asking for the right *type* is
    # still validation, so `{"vendor": "xai", "cases": []}` went to the review
    # reader and came back as an unclassified review. The reader below says
    # what is wrong with a block; this only says which reader should look.
    return ("provenance" not in body
            and any(name in body for name in VENDOR_CALL_BLOCKS))


def vendor_calls(paths: Iterable[Path]) -> Dict[str, Any]:
    """Every recorded call to a metered vendor, keyed by its billing identity.

    Returns `{"calls": {(vendor, request_id): row}, "problems": [...]}`.
    Anything that cannot be keyed is a problem rather than a row: a call with
    no `request_id` cannot be told apart from another, so counting it risks
    both double-counting and hiding a duplicate.
    """
    calls: Dict[Any, Dict[str, Any]] = {}
    problems: List[str] = []
    for path in paths:
        try:
            body = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            problems.append("{}: could not be read ({})".format(
                path, type(exc).__name__))
            continue
        if not isinstance(body, dict):
            problems.append("{}: is not an object".format(path))
            continue
        blocks = _vendor_blocks(body)
        if blocks is None:
            problems.append("{}: records no vendor".format(path))
            continue
        vendor = body["vendor"]
        if len(blocks) != 1:
            problems.append(
                "{}: holds {} of the blocks that carry one entry per call "
                "({}), and it takes exactly one".format(
                    path, len(blocks), ", ".join(VENDOR_CALL_BLOCKS)))
            continue
        for work_id, attempt in sorted(body[blocks[0]].items()):
            if not isinstance(attempt, dict):
                problems.append("{}: {} is not a record".format(path, work_id))
                continue
            request_id = attempt.get("request_id")
            if not isinstance(request_id, str) or not request_id.strip():
                problems.append(
                    "{}: {} records no `request_id`, so nothing says which "
                    "charge it is".format(path, work_id))
                continue
            key = (vendor.strip(), request_id.strip())
            if key in calls:
                # Not summed. The same response appearing twice is either a
                # copy — in which case adding it invents a charge — or two
                # charges the records cannot tell apart.
                problems.append(
                    "{}: {} repeats a response already counted ({}), so one "
                    "charge and two are indistinguishable here".format(
                        path, work_id, request_id))
                continue
            calls[key] = {
                "vendor": vendor.strip(),
                "request_id": request_id.strip(),
                "cost_usd": attempt.get("cost_usd"),
                "when": attempt.get("asked_at") or body.get("started_at") or "",
                "_path": "{}:{}".format(path, work_id),
            }
    return {"calls": calls, "problems": problems}


def instant(stamp: str) -> Optional[datetime]:
    """`stamp` as an aware UTC datetime, or None when it cannot be read.

    Parsed rather than compared as text. Every other tool here compares ISO
    strings and is correct only while everything writes UTC — which breaks the
    moment one record carries a local offset, because `2026-08-31T01:00+03:00`
    sorts after `2026-08-30` and belongs before it. A tool whose purpose is
    accounting should not knowingly keep a boundary that is wrong.

    A timestamp with no offset is *not* assumed to be UTC. Guessing a timezone
    moves a run between days, and this returns None so it is reported as undated
    instead.
    """
    if not stamp:
        return None
    try:
        parsed = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _period(stamp: str, by: str) -> str:
    moment = instant(stamp)
    if moment is None:
        return "undated"
    return moment.strftime("%Y-%m" if by == "month" else "%Y-%m-%d")


def summarise(rows: List[Dict[str, Any]], by: str = "day",
              unreadable: int = 0, source: str = "artifacts",
              skipped_lines: int = 0) -> int:
    if not rows:
        print("Nothing to report. No records were found — which is not the "
              "same as nothing having been spent.")
        return 2

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        groups[_period(when(row), by)].append(row)

    print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
        by, "runs", "charged $", "notional $", "unknown", "no cost"))
    print("-" * 62)

    totals: Dict[str, Any] = {CHARGED: [], NOTIONAL_: [], "unknown": 0,
                              "silent": 0, "runs": 0}
    for period in sorted(groups):
        members = groups[period]
        pots: Dict[str, List[float]] = {CHARGED: [], NOTIONAL_: []}
        unknown = silent = unreadable_cost = 0
        for row in members:
            cost = cost_of(row)
            if cost is None:
                # The same three-way split the headline makes. Codex,
                # 2026-09-06: this counted every unusable cost as "reported no
                # cost at all", so a queue row carrying `"1.25"` was filed
                # under absent here while the line above it said the figure
                # could not be established — two readers of one row, disagreeing
                # in one report.
                if cost_state(row) == "unreadable":
                    unreadable_cost += 1
                else:
                    silent += 1
                continue
            state = paid_by(row)
            if state == UNKNOWN:
                # A figure exists and nobody established which pot it belongs
                # in. Putting it in the cheaper one would understate a bill, so
                # it is counted as a run and its money is reported nowhere.
                unknown += 1
                continue
            pots[state].append(cost)
        for state in (CHARGED, NOTIONAL_):
            totals[state] += pots[state]
        totals["unknown"] += unknown
        totals["silent"] += silent
        totals["unreadable_cost"] = totals.get(
            "unreadable_cost", 0) + unreadable_cost
        totals["runs"] += len(members)
        print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
            period, len(members),
            "{:.2f}".format(sum(pots[CHARGED])) if pots[CHARGED] else "—",
            "{:.2f}".format(sum(pots[NOTIONAL_])) if pots[NOTIONAL_] else "—",
            unknown or "—", silent or "—"))

    print("-" * 62)
    print("{:<12} {:>5} {:>11} {:>12} {:>9} {:>9}".format(
        "total", totals["runs"],
        "{:.2f}".format(sum(totals[CHARGED])) if totals[CHARGED] else "—",
        "{:.2f}".format(sum(totals[NOTIONAL_])) if totals[NOTIONAL_] else "—",
        totals["unknown"] or "—", totals["silent"] or "—"))

    # Never added. One number that is part bill and part list price is the exact
    # confusion this tool exists to prevent, and it would be the number quoted.
    print("\nThe money columns are separate on purpose and are not added.")
    if totals[CHARGED]:
        print("  charged:  ${:.2f} across {} run(s) — an API key paid this"
              .format(sum(totals[CHARGED]), len(totals[CHARGED])))
    if totals[NOTIONAL_]:
        median = statistics.median(totals[NOTIONAL_])
        print("  notional: ${:.2f} across {} run(s), ${:.2f} median — API list "
              "price for the tokens used, charged to nobody"
              .format(sum(totals[NOTIONAL_]), len(totals[NOTIONAL_]), median))
    if totals["unknown"]:
        print("  {} run(s) reported a cost with no established billing. Their "
              "money is in neither column, because assigning it to the cheaper "
              "one would understate a bill.".format(totals["unknown"]))
    # These two sentences are about **this table's columns**, and they used to
    # be about "the total" — a claim that only holds for a row that could have
    # been charged. Codex, 2026-09-06: with `--breakdown` a subscription review
    # carrying an absent or malformed notional figure was described as failing
    # to bound a total it was never part of, while the headline above had just
    # been fixed to call the same figure irrelevant. The counts here are right;
    # what they were said to mean was not.
    if totals["silent"]:
        print("  {} run(s) reported no cost at all, and are in neither money "
              "column. Absent, not $0.00.".format(totals["silent"]))
    if totals.get("unreadable_cost"):
        print("  {} run(s) recorded something other than money where a cost "
              "belongs, and are in neither column. Not the same as recording "
              "nothing: the headline says which of the two bounds its figure "
              "and which does not.".format(totals["unreadable_cost"]))

    # The four counts, named, or nothing. The previous version printed a
    # sentence about "the token counts above" being a floor while the table
    # carried no token columns at all, and a test passed against it.
    counted = [tokens(r) for r in rows]
    sums = {name: sum(v[name] for v in counted if isinstance(v[name], int))
            for name in TOKEN_FIELDS}
    missing = sum(1 for v in counted
                  if any(not isinstance(v[name], int) for name in TOKEN_FIELDS))
    if any(sums.values()):
        print("\ntokens: " + " · ".join(
            "{} {:,}".format(name.replace("_tokens", ""), sums[name])
            for name in TOKEN_FIELDS))
        print("  Not summed into one figure: cache reads are a tenth of the "
              "input rate and cache writes are twice it, so a total of the four "
              "is dominated by the cheapest of them.")
        gaps = sum(unreported_stages(r) for r in rows)
        if gaps or missing:
            print("  A floor, not a total: {} stage(s) ran without reporting, "
                  "and {} run(s) are missing at least one count."
                  .format(gaps, missing))

    if source == "artifacts":
        print("\nSource: retained artifacts. This repository keeps an artifact "
              "for the members that failed, so this is a selected sample and "
              "not total spend.")
    else:
        print("\nSource: the queue's own log — one row per invocation it ran, "
              "and nothing it did not.")
    if unreadable:
        print("  {} file(s) could not be read and are in no number here."
              .format(unreadable))
    if skipped_lines == -1:
        print("  The queue log exists and could not be read at all.")
    elif skipped_lines:
        print("  {} line(s) of the queue log did not parse and are in no "
              "number here.".format(skipped_lines))
    return 0


def one_figure(rows: List[Dict[str, Any]], vendor: Dict[str, Any],
               unreadable: int = 0, skipped_lines: int = 0,
               scope: str = "", since: str = "",
               may_double_count: bool = False) -> int:
    """The whole report, in the form the owner asked for: one line.

    Not a table. He asked for one figure and a breakdown only when he asks for
    one, and the figure appears in every report from here on — which is exactly
    why it must not be a number that reads as an answer when it is not.

    **`$0.00 charged` is refused as a headline.** Codex, 2026-09-05: printing it
    while paid subscription capacity was demonstrably consumed invites "nothing
    was spent", and this counter cannot establish that. When any observed usage
    has an unestablished billing arrangement the line says `indeterminate` and
    names what would settle it. A figure appears only when every call the
    counter saw could be priced *and* classified.
    """
    # Nothing seen is not nothing spent — the invariant `summarise` has carried
    # since it was written, and this path had lost it. Codex, 2026-09-05: with
    # no artifacts, no vendor ledgers and no errors, every counter is empty and
    # the headline said "$0.00 charged — every call the counter saw runs on a
    # flat subscription" about no calls at all, and exited 0.
    #
    # `unreadable` and `skipped_lines` are in the condition because the first
    # version left them out, and Codex found it on the next pass: an invocation
    # holding only an unreadable artifact printed "no records were found",
    # which is a different and more comfortable sentence than "records existed
    # and could not be read". The shortcut is for a genuinely empty ledger, and
    # anything else falls through to the diagnostics below.
    if not rows and not vendor["calls"] and not vendor["problems"] \
            and not unreadable and not skipped_lines:
        print("Spend: indeterminate — no records were found, which is not the "
              "same as nothing having been spent")
        print("  scope: {} · as of {}".format(
            scope or "this repository's records",
            datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ")))
        print("  not counted anywhere, and nothing here can count it: "
              "{}".format("; ".join(INVISIBLE)))
        return 2

    charged: List[float] = []
    malformed: List[str] = []
    # Printed and never counted: things worth surfacing that cannot change
    # the figure. Kept apart from `integrity` on purpose — one stops the
    # answer and the other does not, and folding them makes every note a
    # refusal.
    notes: List[str] = []
    subscription = unestablished = silent = made_no_call = 0

    for row in rows:
        cost = cost_of(row)
        state = paid_by(row)
        # Not named `money`: that is the formatting function this same
        # function calls twenty lines further down, and shadowing it would
        # have turned every printed figure into a `TypeError`.
        recorded = cost_state(row)

        # **Who paid is decided before the cost is judged**, and it was the
        # other way round. Codex, 2026-09-06: a review on a named subscription
        # with a malformed cost made the whole figure indeterminate, while the
        # identical case on a flat vendor was a note — the same rule applied to
        # one side and not the other. A number that is list price charged to
        # nobody cannot make the charged total unknowable, whatever it says.
        if state == NOTIONAL_:
            subscription += 1
            if recorded == UNREADABLE:
                notes.append(
                    "a subscription review records {!r} where a cost belongs "
                    "— not in any total, because that path is flat".format(
                        _provenance(row).get("reported_cost_usd")))
            continue

        # A run that recorded no cost at all is counted apart from one that
        # recorded a cost nobody can place. The first cannot change a total it
        # contributes nothing to, so it makes the figure a **floor** rather
        # than stopping it; the second is money this tool can see and cannot
        # assign, and that stops it. "Absent, not $0.00" is this file's oldest
        # rule, and the distinction is which of the two sentences is owed.
        if recorded == ABSENT:
            # **A run that made no provider call is not a run whose price is
            # missing.** The artifact records `usage.requests`, and this tool
            # never read it — so all eight of today's unpriced runs, every one
            # of them `requests: 0` with `stop_reason: error`, are reported as
            # "recorded no cost at all", which reads as a price nobody wrote
            # down. The field that separates them is in the same file.
            #
            # `is None` and not falsiness: a run that recorded no `requests`
            # key is a third thing again, and reading its absence as zero
            # would be the mistake this whole file is about.
            requests = (row.get("usage") or {}).get("requests")
            if isinstance(requests, int) and requests == 0:
                made_no_call += 1
            else:
                silent += 1
        elif recorded == UNREADABLE:
            malformed.append(
                "a review records {!r} where a cost belongs".format(
                    _provenance(row).get("reported_cost_usd")))
        elif state == CHARGED:
            charged.append(cost)
        else:
            unestablished += 1

    # Named apart in the line below, because "it cost nothing because it did
    # nothing" and "nobody wrote the price down" send a reader to two
    # different places.
    vendor_unestablished: Dict[str, int] = defaultdict(int)
    vendor_unpriced: List[str] = []
    for key, call in sorted(vendor["calls"].items()):
        arrangement = BILLING_ARRANGEMENT.get(call["vendor"])
        kind = arrangement.get("kind") if isinstance(arrangement, dict) else None
        if kind not in (FLAT, METERED):
            # No arrangement, or one this tool cannot read. Both are "nobody
            # established it" — a `kind` it does not know is not a licence to
            # pick one.
            vendor_unestablished[call["vendor"]] += 1
            continue
        if kind == FLAT:
            # Counted as a call and its figure counted nowhere. The number in
            # the record is list price for tokens nobody was charged for, and
            # adding it is the trap this whole file is built around: it looks
            # exactly like an invoice.
            subscription += 1
            # A note, not a refusal. Codex proposed making a malformed
            # `cost_usd` here indeterminate; the ruling on 2026-09-06 went the
            # other way and the reason is worth keeping: for a FLAT
            # arrangement this field is neither added nor used to classify, so
            # its contents cannot make the money answer unknowable. Refusing
            # over it would conflate record hygiene with arithmetic integrity.
            # It is surfaced because the arrangement can change, and from that
            # day the same value becomes load-bearing and blocking.
            if money_state(call, "cost_usd") == UNREADABLE:
                notes.append(
                    "{} {} records {!r} where a cost belongs — not in any "
                    "total, because this vendor is flat".format(
                        key[0], key[1], call.get("cost_usd")))
            continue
        # Through the same predicate the reviews go through. It was reading
        # `isinstance(..., (int, float))` and adding whatever it found, so a
        # ledger for a vendor with an established arrangement could print a
        # total that was reduced by a negative, or `nan`, and exit 0.
        state = money_state(call, "cost_usd")
        if state == ABSENT:
            # The same floor a review with no recorded cost gets. Codex,
            # 2026-09-06: the vendor path had its own spelling of this and made
            # a `null` cost an indeterminate hole, while the identical case on
            # the review side was a floor. One function decides it now.
            silent += 1
            continue
        if state == UNREADABLE:
            vendor_unpriced.append("{} {} records {!r} where money belongs"
                                   .format(key[0], key[1],
                                           call.get("cost_usd")))
            continue
        charged.append(as_money(call["cost_usd"]))

    # Ledger integrity, which is a different question from what was spent.
    # Codex, 2026-09-05: exit 2 belongs to "these records cannot be trusted to
    # add up", not to every exclusion — a known flat fee left out of a metered
    # total is the tool working, and the permanently invisible agent plan
    # forcing 2 forever turns the status into noise.
    integrity = list(vendor["problems"]) + vendor_unpriced + malformed
    if unreadable:
        integrity.append("{} artifact(s) could not be read".format(unreadable))
    if skipped_lines == -1:
        integrity.append("the queue log could not be read at all")
    elif skipped_lines:
        integrity.append(
            "{} line(s) of the queue log did not parse".format(skipped_lines))

    # A call nobody could price stops the figure exactly as a call nobody could
    # classify does. Codex, 2026-09-05: `vendor_unpriced` reached the ledger
    # line and not the decision, so one metered call recording `nan` printed
    # "$0.00 charged — every call runs on a flat subscription" — the headline
    # contradicting the diagnostic three lines under it. Unpriced and
    # unclassified are two ways of not knowing, and the figure needs both.
    total_unestablished = unestablished + sum(vendor_unestablished.values())
    cannot_price = len(vendor_unpriced) + len(malformed)

    # And any ledger failure at all. Codex, 2026-09-05, on the version that had
    # just wired the unpriced count in: an unreadable artifact, a malformed
    # queue line, a call with no `request_id`, a duplicated response — each
    # left the headline saying "$0.00 charged, every call runs on a flat
    # subscription" while the line beneath it reported the error and the exit
    # code was 2. Records that cannot be trusted to add up do not justify a
    # number, whatever the reason they cannot.
    if total_unestablished or cannot_price or integrity:
        reasons = []
        for name, count in sorted(vendor_unestablished.items()):
            reasons.append(
                "{} {} call(s) — nothing here establishes whether one more "
                "raises a bill".format(count, name))
        if unestablished:
            reasons.append(
                "{} review(s) that recorded a cost and no login to place it "
                "against".format(unestablished))
        if cannot_price:
            reasons.append(
                "{} call(s) recording something other than money where a cost "
                "belongs".format(cannot_price))
        if not reasons:
            reasons.append(
                "{} problem(s) with the records themselves, so nothing here "
                "can be trusted to add up".format(len(integrity)))
        print("Spend: indeterminate — {}{}".format(
            "; ".join(reasons),
            "; {} charged so far from {} call(s) that could be classified"
            .format(money(sum(charged)), len(charged)) if charged else ""))
    elif charged or silent:
        # `≥`, and the word "floor", whenever a run recorded no cost at all.
        # Such a run cannot move a total it contributes nothing to, so it does
        # not stop the figure — but it did happen, and printing its absence as
        # nothing is the "absent is not zero" defect this file was written
        # against, one level up.
        #
        # **Unless a run may be counted twice.** `gpt-6-astra`, 2026-09-06:
        # `≥` asserts a lower bound, and a duplicate breaks it in the other
        # direction. One $5.00 run written in both shapes, beside one run whose
        # unreported cost was $1.00, prints "≥ $10.00 charged" against $6.00
        # actually spent. The diagnostic three lines below cannot repair an
        # inequality in the headline, so the headline stops claiming one.
        bound = "≥ " if silent and not may_double_count else ""
        # Seven placeholders for seven clauses. The `made_no_call` clause was
        # added without one, and `str.format` drops a surplus argument in
        # silence — so the *duplicate* warning, which is last, stopped
        # printing. A qualification lost to an argument count, in the line
        # this whole file exists to qualify.
        print("Spend: {}{} charged{}{}{}{}{}".format(
            bound, money(sum(charged)),
            ", from {} metered call(s)".format(len(charged)) if charged
            else " — nothing metered was recorded",
            "; {} call(s) on a flat subscription, not in that figure".format(
                subscription) if subscription else "",
            "; a floor, not the answer — {} run(s) recorded no cost at all"
            .format(silent) if silent and not may_double_count else "",
            # A run that made no provider call is not a hole in the figure:
            # it cost nothing because nothing was asked of anybody. Named so
            # that the sentence above stops carrying it, and so a reader is
            # not sent looking for a price that was never owed.
            "; {} run(s) made no provider call at all".format(made_no_call)
            if made_no_call else "",
            # **Said whether or not anything else is missing.** The eight
            # states of this line were printed side by side rather than
            # reasoned about, and one of them was wrong: with metered runs, no
            # silent ones and a possible duplicate, the figure came out as an
            # exact charge with no qualification at all — $5.00 stated flatly
            # for something that could be $2.50. The duplicate was only
            # mentioned when a *silent* run happened to be there too, because
            # both sentences hung off the same condition.
            ("; {} run(s) recorded no cost, and a run written in two shapes "
             "would be counted twice".format(silent) if silent else
             "; not established as a total — a run written in two shapes "
             "would be counted twice")
            if may_double_count else ""))
    else:
        # The no-call runs are named here too. They were named on the other
        # headline and not on this one, which is the "two ends of one rule"
        # shape this repository keeps finding — and this is the branch that
        # prints `$0.00 charged`, the strongest claim the tool makes, so a
        # qualification missing here is missing where it matters most.
        print("Spend: $0.00 charged — every call the counter saw runs on a "
              "flat subscription{}{}".format(
                  " ({} of them)".format(subscription) if subscription else "",
                  "; {} run(s) made no provider call at all".format(
                      made_no_call) if made_no_call else ""))

    # The scope and the instant, because a bare figure quoted in a report is
    # about *something* as of *some time*, and two identical reports written on
    # different days would otherwise carry different numbers with nothing
    # saying why. Codex, 2026-09-05, who also named the sharper case: `--since`
    # filters the review rows and does not filter the vendor calls, so the two
    # halves of one figure would cover different windows in silence.
    print("  scope: {} · as of {}{}".format(
        scope or "this repository's records",
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%MZ"),
        " · `--since {}` filters the reviews and not the vendor calls, so the "
        "two halves cover different windows".format(since) if since else ""))

    if integrity:
        print("  ledger: {}".format("; ".join(integrity[:3])))
        if len(integrity) > 3:
            print("  ledger: and {} more".format(len(integrity) - 3))
    if notes:
        print("  noted, and it changes no number above: {}{}".format(
            "; ".join(notes[:2]),
            " and {} more".format(len(notes) - 2) if len(notes) > 2 else ""))
    print("  not counted anywhere, and nothing here can count it: {}".format(
        "; ".join(INVISIBLE)))

    # 2 only for a ledger this tool cannot trust to add up, and for spending it
    # saw and could not classify. Exit 0 cannot certify that every call was
    # recorded — only that every record found was valid — and the line above
    # does not claim otherwise.
    # A floor is not a clean answer either. Exit 0 is for a figure with nothing
    # missing behind it; a run that happened and recorded no cost is missing.
    return 2 if (integrity or total_unestablished or cannot_price
                 or silent) else 0


def detail(rows: List[Dict[str, Any]]) -> None:
    print("\n{:<22} {:<10} {:<38} {}".format("when", "cost", "who paid", "model"))
    print("-" * 96)
    for row in sorted(rows, key=when):
        # The fourth reader of the same three-way answer, and the last one to
        # be wired to it. Codex, 2026-09-06: it rendered `absent` and
        # `unreadable` identically as "not reported", so `--detail` showed a
        # malformed `"1.25"` as a run that reported nothing while the headline
        # above called the figure indeterminate over it.
        state = cost_state(row)
        print("{:<22} {:<10} {:<38} {}".format(
            when(row)[:19] or "undated",
            "{:.3f}".format(cost_of(row)) if state == MONEY
            else "not reported" if state == ABSENT else "unreadable",
            who_paid(row),
            _provenance(row).get("model_requested", "")))


def _rows_and_artifacts_together(paths: List[Path]) -> List[Path]:
    """Directories holding both shapes, which is where a run may be counted
    twice. Reported rather than resolved: see `fold_representations`."""
    roots = {p.parent for p in paths if p.name == "rows.json"}
    return sorted({root for root in roots
                   for path in paths
                   if path.name != "rows.json" and root in path.parents})


def fold_representations(paths: List[Path]) -> tuple:
    """Nothing is folded, and the reason is that nothing here can key a run.

    A run can be written twice — once as its own `findings.json`, once as a row
    in the `rows.json` its runner keeps — and reading both counts its cost
    twice. That is real, and it is the failure this tool already refuses
    between the artifacts and the queue log, where the answer was to read one
    source and say so rather than to guess which rows correspond.

    Two rules were tried here on 2026-09-06 and both were wrong, in opposite
    directions, for the same reason:

    * **By directory.** Every artifact under a directory holding a `rows.json`
      was set aside. Directory ancestry does not establish that two files
      describe one run: two $5.00 metered artifacts under a rows file of one
      subscription run were counted as $0.00 while the diagnostic said they had
      been "counted once, from the rows".
    * **By provider and cost.** Then an artifact was folded only when a row
      reported the same cost from the same vendor. Equal prices are not
      identity: three distinct $5.00 API runs — one row, two artifacts —
      collapsed to $5.00 instead of $15.00, and the tests written for it
      encoded that as correct. The reverse is also true: one genuine duplicate
      whose two records round differently is counted twice.

    `gpt-6-astra` found both, the second on the gate pass for the first. The
    conclusion is not a third heuristic. **No field in these artifacts keys a
    run** — no request id, no run id, nothing an artifact and a row could be
    joined on — and every rule that guesses at the join is wrong in one
    direction or the other. So this folds nothing, and the report names the
    directories where both shapes are present, which is the same treatment the
    queue log already gets and the one this repository can defend.

    **The report says what cannot be established, not what happened.** Codex,
    the fourth gate on this change: two shapes sharing a directory is not
    duplication, and the first warning announced one as the other — "a run
    written in both shapes is counted twice" — from evidence that shows only
    that both shapes are there. The tests build three distinct runs of equal
    cost to make exactly that point, so the warning contradicted them.

    Kept as a function rather than deleted because the honest answer is a
    statement in the report, and the place that statement is decided is here.
    """
    return paths, []


def collect(args: argparse.Namespace) -> tuple:
    if args.paths:
        return fold_representations([Path(p) for p in args.paths])
    found: List[Path] = []
    for pattern in DEFAULT_GLOBS:
        found += sorted(ROOT.glob(pattern))
    return fold_representations(found)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="*", help="artifacts to read")
    parser.add_argument("--by", default="day", choices=("day", "month"))
    parser.add_argument("--since", default="", help="ISO date; earlier runs are skipped")
    parser.add_argument("--detail", action="store_true", help="one line per run")
    parser.add_argument(
        "--breakdown", action="store_true",
        help="the table, by day or month. Without it this prints one line, "
             "which is what the owner asked to read in every report")
    parser.add_argument(
        "--source", default="artifacts", choices=("artifacts", "queue"),
        help="artifacts written by a review, or the queue's own log. Separate "
             "on purpose: a review can be in both and nothing keys them "
             "together, so adding them would double-count")
    args = parser.parse_args(argv)

    if args.source == "queue":
        # **Accumulated, not read once at the end.** `queue_rows` resets
        # `QUEUE_SKIPPED` on entry and sets it on exit, so with more than one
        # log only the *last* one's count survived — a healthy round log
        # erased the unparseable lines in the queue's own, and the headline
        # then printed `$0.00 charged`, the sentence this file exists to never
        # print while anything is unestablished. Introduced the same afternoon
        # the round logs were added, and the two tests written for it covered
        # one log each and never both.
        #
        # `-1` means "could not be read at all" and must survive being mixed
        # with a number: a log nobody could open is not fewer bad lines than a
        # log with two.
        rows = []
        skipped = 0
        for log in queue_logs(ROOT):
            rows.extend(queue_rows(log))
            if QUEUE_SKIPPED < 0 or skipped < 0:
                skipped = -1
            else:
                skipped += QUEUE_SKIPPED
        unreadable = 0
        # The queue log is one source and holds no artifacts, so the question
        # below does not arise on this path.
        beside: List[Path] = []
    else:
        skipped = 0
        paths, _ = collect(args)
        # A vendor ledger is not a review artifact, and it used to be read as
        # both — 30 metered calls in one column and one nameless "review" in
        # the other, from one file. One record, one kind.
        paths = [p for p in paths if not _looks_like_a_vendor_ledger(p)]
        # **After that filter, not before it.** Codex, fifth gate on this
        # change: a vendor ledger under a directory holding a `rows.json` is
        # not a second representation of any run — it is counted in a separate
        # column entirely — but the check saw a file that was not `rows.json`,
        # reported "both shapes", and took away a `≥` bound that was true.
        # A warning about double counting, raised by the one kind of file that
        # cannot be double counted.
        beside = _rows_and_artifacts_together(paths)
        # Counted by the reader, not derived from `len(paths) - len(rows)`.
        # One file can hold many runs, and that subtraction then goes negative
        # and prints as a negative number of unreadable files.
        rows, unreadable = read_runs(paths)
    if args.since:
        # Compared as instants, not as text: an offset timestamp sorts by its
        # local hour and belongs at its UTC one. A run whose stamp cannot be
        # read is kept rather than dropped — a filter that silently removes
        # what it cannot parse makes the report shorter and says nothing.
        try:
            floor = instant(args.since) or instant(args.since + "T00:00:00+00:00")
        except ValueError:
            floor = None
        if floor is not None:
            rows = [r for r in rows
                    if instant(when(r)) is None or instant(when(r)) >= floor]

    # A named path is read as what it is. Codex, 2026-09-05: the first version
    # passed `[]` whenever the caller named anything, so somebody pointing this
    # tool at `grok-adjudication.json` got it parsed as a review artifact —
    # wrong classification and a diagnostic about the wrong thing. Not naming
    # any path still means "the repository's own records", and naming one still
    # means the repository's *unrelated* records stay out.
    if args.paths:
        vendor_paths = [p for p in (Path(x) for x in args.paths)
                        if _looks_like_a_vendor_ledger(p)]
    else:
        vendor_paths = sorted(p for pattern in VENDOR_GLOBS
                              for p in ROOT.glob(pattern))
    vendor = vendor_calls(vendor_paths)

    scope = ("{} named path(s)".format(len(args.paths)) if args.paths
             else "this repository's records, source " + args.source)
    # The headline first, always. The owner asked for the figure in every
    # report, and the breakdown is still a report — Codex, 2026-09-05: the
    # detail and breakdown paths went straight to `summarise`, so vendor costs
    # shrank to a call count, vendor ledger failures did not reach the exit
    # code, and a vendor-only ledger printed "no records were found" from a
    # `summarise([])` that had never been shown the calls.
    code = one_figure(rows, vendor, unreadable, skipped, scope,
                      args.since, may_double_count=bool(beside))
    if beside:
        # **Said, because it cannot be fixed here.** A run written both as its
        # own artifact and as a row is counted twice, and nothing in either
        # record keys them together — no request id, no run id. Two rules that
        # guessed at the join were tried on 2026-09-06 and each was wrong in
        # one direction; see `fold_representations`. The reader is told which
        # directories hold both shapes so the figure is read as an upper bound
        # there, rather than a silent double count.
        print("  {} director{} hold(s) both a `rows.json` and kept "
              "artifact(s). Nothing in these records keys a run, so whether "
              "any run appears in both cannot be established here — if one "
              "does it is counted twice: {}".format(
                  len(beside), "y" if len(beside) == 1 else "ies",
                  ", ".join(sorted(str(p) for p in beside)[:3])
                  + (" ..." if len(beside) > 3 else "")))
    if not args.breakdown and not args.detail:
        return code

    print()
    # The table's own exit code is discarded: it answers "was there anything to
    # group", and the headline above has already answered the question this
    # tool is for. Two exit codes from one command is one of them being ignored,
    # and it should be the narrower.
    #
    # And it is not called at all with no review rows. Codex, 2026-09-05: it
    # prints "No records were found" — a sentence about the whole report — from
    # a function that was only ever shown the reviews, so a vendor-only ledger
    # got a headline naming its calls and a paragraph underneath denying they
    # existed.
    if rows:
        summarise(rows, args.by, unreadable, args.source, skipped)
    elif unreadable or skipped or vendor["problems"]:
        # Not "the metered calls are the whole of it". Codex, 2026-09-05: that
        # sentence is true of a vendor-only ledger and false of a report whose
        # review records existed and could not be read — the difference between
        # "there were none" and "I could not see them", which is the one this
        # tool exists to keep.
        failed = (unreadable + (0 if skipped == -1 else skipped)
                  + len(vendor["problems"]))
        print("No review artifacts could be read, and {} record(s) failed. "
              "This table covers reviews, and it is empty because they could "
              "not be read rather than because there were none.".format(
                  failed or "an unknown number of"))
    elif vendor["calls"]:
        print("No review artifacts in this report. The vendor calls above are "
              "the whole of it; this table only ever covers reviews.")
    else:
        print("No review artifacts and no vendor calls. This table covers "
              "reviews, and there were none to group.")
    # "Vendor", not "metered". Codex, 2026-09-06: these lines called every
    # vendor call metered, so a flat xAI ledger reported a flat subscription in
    # the headline and contradicted it three lines down. Which arrangement a
    # vendor is on is `BILLING_ARRANGEMENT`'s answer, not a word baked into the
    # sentence that counts them.
    if vendor["calls"] or vendor["problems"]:
        print("\nVendor calls, counted apart and never added to the above: "
              "{} call(s) recorded, {} record(s) this tool could not key."
              .format(len(vendor["calls"]), len(vendor["problems"])))
    if args.source == "artifacts" and any(
            queue_rows(log) for log in queue_logs(ROOT)):
        print("\nThe queue log holds review rows this source does not: "
              "tools/spend.py --source queue. Not added to the above — a "
              "review can appear in both and nothing keys them together.")
    if args.detail and rows:
        detail(rows)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
