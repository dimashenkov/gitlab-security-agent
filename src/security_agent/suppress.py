"""Accepted-risk suppression, read from ``.security-agent-ignore.yml``.

A blocking gate needs a documented way to say "we looked at this and we are
living with it" — otherwise the first false positive on a Friday afternoon gets
resolved by deleting the job. Two properties make that safe rather than a hole:

* Entries carry a reason and, optionally, an expiry, so an accepted risk is a
  decision with a date on it rather than a permanent silence.
* Suppressed findings still appear in the report, in their own section. They are
  removed from the gate, never from view.

The file lives in the repository being reviewed, which means the same merge
request that introduces a vulnerability could add an entry suppressing it. That
is by design and it is why the file is reviewed like any other code — a diff
that touches it is visible to the humans on the merge request. The agent is told
about the file's contents but not asked to honour it.
"""

from __future__ import annotations

import datetime as _dt
import logging
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import yaml

from .models import Candidate

log = logging.getLogger(__name__)


class SuppressionError(Exception):
    """The ignore file exists but cannot be used as written."""


class Rule:
    """One accepted-risk entry."""

    def __init__(
        self,
        fingerprint: str = "",
        path: str = "",
        category: str = "",
        reason: str = "",
        expires: Optional[_dt.date] = None,
        source_index: int = 0,
    ) -> None:
        self.fingerprint = fingerprint.strip()
        self.path = path.strip()
        self.category = category.strip()
        self.reason = reason.strip()
        self.expires = expires
        self.source_index = source_index

    @property
    def label(self) -> str:
        if self.fingerprint:
            return "fingerprint {}".format(self.fingerprint)
        bits = []
        if self.path:
            bits.append("path {}".format(self.path))
        if self.category:
            bits.append("category {}".format(self.category))
        return " + ".join(bits) or "entry {}".format(self.source_index)

    def expired(self, today: _dt.date) -> bool:
        return self.expires is not None and self.expires < today

    def matches(self, candidate: Candidate) -> bool:
        if self.fingerprint:
            return self.fingerprint == candidate.fingerprint
        # A path/category rule must constrain something, or it would silence the
        # entire report. `load` rejects empty rules, so reaching here means at
        # least one of the two is set.
        if self.path and not _path_matches(self.path, candidate.finding.file):
            return False
        return not (self.category and self.category != candidate.finding.category)


def load(path: Path, today: Optional[_dt.date] = None) -> Tuple[List[Rule], List[str]]:
    """Read the ignore file. Returns (active rules, warnings).

    A missing file is normal and silent. A malformed one is loud: silently
    ignoring a broken suppression file would mean a team believes findings are
    suppressed when they are not, or the reverse.
    """
    today = today or _dt.datetime.now(_dt.timezone.utc).date()
    if not path.is_file():
        return [], []

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise SuppressionError("{} is not valid YAML: {}".format(path, exc)) from exc
    except OSError as exc:
        raise SuppressionError("cannot read {}: {}".format(path, exc)) from exc

    if raw is None:
        return [], []
    if not isinstance(raw, dict) or "ignore" not in raw:
        raise SuppressionError(
            "{}: expected a mapping with an `ignore:` list at the top level".format(path)
        )
    entries = raw.get("ignore") or []
    if not isinstance(entries, list):
        raise SuppressionError("{}: `ignore` must be a list".format(path))

    rules: List[Rule] = []
    warnings: List[str] = []
    for index, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise SuppressionError(
                "{}: entry {} must be a mapping".format(path, index))

        reason = str(entry.get("reason", "") or "").strip()
        if not reason:
            raise SuppressionError(
                "{}: entry {} needs a `reason`. An accepted risk without a "
                "recorded reason is indistinguishable from a mistake.".format(
                    path, index)
            )

        expires = _parse_date(entry.get("expires"), path, index)
        rule = Rule(
            fingerprint=str(entry.get("fingerprint", "") or ""),
            path=str(entry.get("path", "") or ""),
            category=str(entry.get("category", "") or ""),
            reason=reason,
            expires=expires,
            source_index=index,
        )
        if not (rule.fingerprint or rule.path or rule.category):
            raise SuppressionError(
                "{}: entry {} must set at least one of `fingerprint`, `path`, or "
                "`category`".format(path, index)
            )
        if rule.expired(today):
            warnings.append(
                "suppression for {} expired on {} and is no longer applied "
                "({})".format(rule.label, rule.expires, rule.reason)
            )
            continue
        rules.append(rule)

    return rules, warnings


def apply(
    candidates: Sequence[Candidate], rules: Sequence[Rule]
) -> Tuple[List[Candidate], List[Candidate]]:
    """Split candidates into (kept, suppressed), tagging the suppressed ones."""
    kept: List[Candidate] = []
    suppressed: List[Candidate] = []
    for candidate in candidates:
        rule = next((r for r in rules if r.matches(candidate)), None)
        if rule is None:
            kept.append(candidate)
            continue
        candidate.suppressed_by = "{} — {}".format(rule.label, rule.reason)
        suppressed.append(candidate)
    return kept, suppressed


def _parse_date(value, path: Path, index: int) -> Optional[_dt.date]:
    if value in (None, ""):
        return None
    if isinstance(value, _dt.datetime):
        return value.date()
    if isinstance(value, _dt.date):
        return value
    try:
        return _dt.date.fromisoformat(str(value).strip())
    except ValueError as exc:
        raise SuppressionError(
            "{}: entry {} has an invalid `expires` value {!r}; use "
            "YYYY-MM-DD".format(path, index, value)
        ) from exc


def _path_matches(pattern: str, path: str) -> bool:
    import fnmatch

    pattern = pattern.lstrip("/")
    if fnmatch.fnmatch(path, pattern):
        return True
    # A bare directory prefix is the common intent ("everything under tests/").
    if pattern.endswith("/"):
        return path.startswith(pattern)
    return False


def describe(rules: Sequence[Rule]) -> Dict[str, int]:
    return {
        "total": len(rules),
        "by_fingerprint": sum(1 for r in rules if r.fingerprint),
        "by_pattern": sum(1 for r in rules if not r.fingerprint),
    }
