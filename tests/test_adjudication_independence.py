"""Who ruled, and what a ruling is allowed to excuse.

Two defects, both found on 2026-09-03 and both of the same shape as everything
else in this repository: a channel that says nothing is read as a channel that
said the convenient thing.

The first is about authorship. `corpus-real/adjudications.yml` decides what the
corpus counts, and it was taken — in the project's own report, by the assistant
writing it — for the owner's hand judgement. It is not: the rulings were written
by the reviewer's own model in earlier sessions and committed under the owner's
git identity. A file that does not name its author will be read as naming the
reassuring one.

The second is about `verdict`. `ruled_incidental` never read it, so a ruling
saying "the reviewer was wrong" and a ruling saying "the reviewer was right
about something smaller" reached the scorer as the same instruction: excuse it.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import artifact


def ruling(**over) -> dict:
    row = {"case_id": "one", "member": "safe", "verdict": "real",
           "incidental": True, "fingerprint": "aa11",
           "adjudicated_by": "model"}
    row.update(over)
    return row


class TestARefutedClaimIsNotExcused:
    """`verdict: not_real` means the reviewer's claim is wrong.

    A wrong alert on the patched member is a false positive — the exact thing
    the corpus counts — so excusing it deletes the measurement instead of
    explaining it. "Incidental" is for a claim that is *correct* and about a
    lesser weakness than the advisory's.
    """

    def test_a_refuted_finding_stays_counted(self):
        rows = [ruling(verdict="not_real")]

        assert artifact.ruled_incidental(rows, "one", "safe") == []

    def test_a_correct_lesser_finding_is_still_excused(self):
        """The behaviour the function exists for must survive the fix."""
        rows = [ruling(verdict="real")]

        assert artifact.ruled_incidental(rows, "one", "safe") == ["aa11"]

    def test_the_live_row_that_carries_both_keys(self):
        """`php-p2ch-c2c3-4xm5-snap` is ruled `not_real` *and* `incidental`.

        Today it excuses nothing only because its fingerprint was never
        recorded — two accidents standing in for a rule. Give it the
        fingerprint it will have the next time the case runs, and the old code
        forgives a genuine false alarm.
        """
        rows = [ruling(case_id="php-p2ch-c2c3-4xm5-snap",
                       verdict="not_real", incidental=True,
                       fingerprint="8b6083c3e996ed20")]

        assert artifact.ruled_incidental(
            rows, "php-p2ch-c2c3-4xm5-snap", "safe") == []

    @pytest.mark.parametrize("verdict", ["unclear", None, "", "REAL"])
    def test_only_not_real_is_refused_and_only_real_excuses(self, verdict):
        """`unclear` does not excuse either — the corpus could not decide, and
        "could not decide" is not "the reviewer was right about something
        smaller". Nor does a missing verdict, nor a differently-cased one: a
        ruling that does not say `real` has not said it.
        """
        assert artifact.ruled_incidental([ruling(verdict=verdict)],
                                         "one", "safe") == []


class TestARefutedFindingInTheBrokenMemberEarnsNoCredit:
    """The other direction, and the one nothing guarded.

    Recall is "the reviewer found the advisory's weakness", and `is_target`
    decides it on category and file. A claim ruled `not_real` is wrong — and it
    was earning full credit for the find, and could carry the pair on its own.
    """

    def test_a_refuted_finding_is_named_by_the_new_reader(self):
        rows = [ruling(member="unsafe", verdict="not_real", incidental=None,
                       fingerprint="cc33")]

        assert artifact.ruled_false_alarm(rows, "one", "unsafe") == ["cc33"]

    def test_a_correct_finding_is_not_a_false_alarm(self):
        rows = [ruling(member="unsafe", verdict="real", fingerprint="cc33")]

        assert artifact.ruled_false_alarm(rows, "one", "unsafe") == []

    def test_an_incidental_finding_in_the_broken_member_is_not_refuted(self):
        """A correct lesser finding in the broken member says nothing about
        whether the target was found. Excusing it there would be a second
        ruling nobody made."""
        rows = [ruling(member="unsafe", verdict="real", incidental=True,
                       fingerprint="cc33")]

        assert artifact.ruled_false_alarm(rows, "one", "unsafe") == []

    def test_the_scorer_stops_giving_recall_for_a_refuted_claim(
            self, tmp_path, monkeypatch):
        """The chain, not the unit. The reader existing and the scorer calling
        it are two facts, and this repository has shipped the first without the
        second — `incidental: true` sat in the rulings file read by no code at
        all."""
        import pair_corpus
        from test_pair_corpus import LESSER_FINDING, TRAVERSAL_CASE

        case_dir = tmp_path / "one"
        (case_dir / "safe").mkdir(parents=True)
        (case_dir / "unsafe").mkdir()
        usage = dict.fromkeys(("input_tokens", "output_tokens",
                               "cache_read_tokens", "cache_write_tokens"), 0)
        payload = {"complete": True, "usage": usage,
                   "findings": [LESSER_FINDING],
                   "verdict": {"exit_code": 0, "blocking_fingerprints": []}}
        monkeypatch.setattr(pair_corpus, "build_repo",
                            lambda *a, **k: (tmp_path, "base", "head"))
        monkeypatch.setattr(pair_corpus, "review", lambda *a, **k: {
            "ok": True, "seconds": 0.0, "exit_code": 0, "payload": payload})

        scored = pair_corpus.run_case(
            dict(TRAVERSAL_CASE, _dir=case_dir),
            adjudications=[{"case_id": "one", "member": "unsafe",
                            "verdict": "not_real", "adjudicated_by": "model",
                            "fingerprint": LESSER_FINDING["fingerprint"]}])

        assert scored["unsafe_target_recall"] is False
        assert scored["unsafe_recall"] is False
        # The stored row has to agree with the score beside it. The two
        # contradicting each other inside one result is a defect this file
        # already carries a regression for on the safe member.
        assert scored["members"]["unsafe"]["target"] is None


class TestTheThreeReadersGiveOneAnswer:
    """`pair_corpus` scores a run; `stage2` and `check_accounted` re-derive the
    same verdict from the stored row. Three readers of one question, and the
    ruling was applied in one of them — so fixing the scorer alone would have
    made the tracker disagree with it, which is worse than the defect: two
    numbers for one corpus and no sign of which is which.
    """

    CASE = {"case_id": "one", "expected_category": ["path-traversal"],
            "expected_file": ["lib/websocket.rb"]}
    FINDING = {"category": "path-traversal", "file": "lib/websocket.rb",
               "severity": "high", "fingerprint": "cc33",
               "title": "arbitrary file read",
               "evidence": "lib/websocket.rb:91  File.read(params[:path])"}
    RULING = [{"case_id": "one", "member": "unsafe", "verdict": "not_real",
               "adjudicated_by": "model", "fingerprint": "cc33"}]

    def row(self):
        return {"case_id": "one", "unsafe_findings": [dict(self.FINDING)],
                "safe_findings": [], "pair_success": True,
                "ran_at": "2026-09-03T10:00:00+00:00"}

    @pytest.mark.parametrize("module,func", [("stage2", "_pair_passed"),
                                             ("check_accounted", "passed")])
    def test_a_refuted_claim_does_not_pass_the_pair_anywhere(
            self, module, func, monkeypatch, tmp_path):
        mod = __import__(module)
        monkeypatch.setattr(mod, "load_adjudications", lambda *_a: self.RULING)
        monkeypatch.setattr(mod, "ROOT", tmp_path)

        case_dir = tmp_path / "corpus-real" / "one"
        case_dir.mkdir(parents=True)
        (case_dir / "case.yml").write_text(
            "expected_category: [path-traversal]\n"
            "expected_file: [lib/websocket.rb]\n", encoding="utf-8")

        # Two readers, two argument orders. Called by name rather than by a
        # shared shim, because a shim that swallowed a `TypeError` would have
        # hidden a signature drift behind a passing test.
        reader = getattr(mod, func)
        answer = (reader(self.row(), "one") if module == "stage2"
                  else reader(self.row(), dict(self.CASE)))

        assert answer is False, (
            "{}.{} still gives recall for a claim ruled not_real".format(
                module, func))

    def test_the_same_row_passes_when_no_ruling_refutes_it(
            self, monkeypatch, tmp_path):
        """The floor. If the assertion above passed because the fixture is
        broken rather than because the ruling bites, this one fails too."""
        import check_accounted

        monkeypatch.setattr(check_accounted, "load_adjudications",
                            lambda *_a: [])
        monkeypatch.setattr(check_accounted, "ROOT", tmp_path)

        assert check_accounted.passed(self.row(), dict(self.CASE)) is True


class TestNoRulingsFileAndABrokenOneAreDifferentAnswers:
    """`load_adjudications` guarded with `is_file()`, which is False for a
    directory as well as for nothing at all — so a corpus with a directory
    where `adjudications.yml` belongs read as a corpus with no rulings, and
    every ruling was silently withdrawn from all five tools at once.

    Found by a test written to prove something else: it asserted the file was
    unreadable and the tool answered as though it were merely absent.
    """

    def test_an_absent_file_means_no_rulings(self, tmp_path):
        assert artifact.load_adjudications(tmp_path) == []

    def test_a_directory_in_its_place_is_refused(self, tmp_path):
        (tmp_path / artifact.ADJUDICATIONS).mkdir()

        with pytest.raises(OSError):
            artifact.load_adjudications(tmp_path)

    def test_a_symlink_to_nothing_is_refused(self, tmp_path):
        """`exists()` follows the link and reports False for a dangling one,
        which is indistinguishable here from nothing being there. It is not
        nothing: somebody pointed this name at a file and the file is gone.
        Checked separately from the directory case, which `exists()` does see.
        """
        (tmp_path / artifact.ADJUDICATIONS).symlink_to(tmp_path / "gone.yml")

        with pytest.raises(OSError):
            artifact.load_adjudications(tmp_path)

    def test_a_symlink_to_a_real_file_is_followed(self, tmp_path):
        """The floor. Refusing every symlink would break a corpus assembled
        with them, and that is not the defect."""
        (tmp_path / "real.yml").write_text(
            "adjudications:\n  - case_id: one\n", encoding="utf-8")
        (tmp_path / artifact.ADJUDICATIONS).symlink_to(tmp_path / "real.yml")

        assert artifact.load_adjudications(tmp_path) == [{"case_id": "one"}]

    def test_an_empty_file_means_no_rulings(self, tmp_path):
        """Different from both. An empty file is a corpus somebody has looked
        at and ruled on nothing."""
        (tmp_path / artifact.ADJUDICATIONS).write_text("", encoding="utf-8")

        assert artifact.load_adjudications(tmp_path) == []

    def test_a_malformed_file_is_not_an_empty_one(self, tmp_path):
        (tmp_path / artifact.ADJUDICATIONS).write_text(
            "adjudications: [\n", encoding="utf-8")

        with pytest.raises(Exception):
            artifact.load_adjudications(tmp_path)


class TestOneEntryPointSoTheToolsCannotDisagree:
    """Five tools each built the excusal set themselves and no two agreed.

    `stability` and `injection_corpus` called the safe-member reader for
    whichever member they were measuring, so the same corpus row moved their
    numbers and not the headline recall. `rulings_for` is the one door.
    """

    def test_the_safe_member_gets_incidental_rulings(self):
        rows = [ruling(member="safe", verdict="real", incidental=True),
                ruling(member="safe", verdict="not_real", incidental=None,
                       fingerprint="bb22")]

        assert artifact.rulings_for(rows, "one", "safe") == ["aa11"]

    def test_the_broken_member_gets_refutations(self):
        rows = [ruling(member="unsafe", verdict="real", incidental=True),
                ruling(member="unsafe", verdict="not_real", incidental=None,
                       fingerprint="bb22")]

        assert artifact.rulings_for(rows, "one", "unsafe") == ["bb22"]

    @pytest.mark.parametrize("member", ["Safe", "unsafe ", "", None, "both"])
    def test_an_unrecognised_member_is_refused_not_defaulted(self, member):
        """A typo used to pick the safe-member rule and then return `[]`,
        because no row matches a misspelt member either. Two wrong answers
        cancelling into a plausible one is how this stays invisible."""
        with pytest.raises(ValueError):
            artifact.rulings_for([ruling()], "one", member)

    @pytest.mark.parametrize("name", ["pair_corpus", "stage2",
                                      "check_accounted", "stability",
                                      "injection_corpus"])
    def test_every_tool_reads_the_rulings_through_the_one_door(self, name):
        """A grep, deliberately. The defect was five call sites, and a sixth
        added later would reintroduce it silently — every other test here would
        still pass.

        The first version of this test let three of the five keep calling the
        specific readers, which is the exact architecture its own name says it
        prevents. Each tool knows its member statically, so calling
        `ruled_incidental` directly *looks* harmless — and that is how the two
        that did not know their member statically came to call it too.
        """
        import re

        text = (ROOT / "tools" / (name + ".py")).read_text(encoding="utf-8")
        body = "\n".join(ln for ln in text.splitlines()
                         if not ln.lstrip().startswith("#"))
        calls = set(re.findall(
            r"\b(rulings_for|ruled_incidental|ruled_false_alarm)\s*\(", body))

        assert calls == {"rulings_for"}, (
            "{} must read rulings only through rulings_for; it calls "
            "{}".format(name, sorted(calls) or "nothing"))
        # An `import ruled_incidental as rulings_for` would pass the check
        # above, because it inspects the spelling at the call site and not
        # where the name came from.
        assert not re.search(r"\bruled_\w+\s+as\s+rulings_for\b", text), (
            "{} aliases a specific reader to the shared name".format(name))


class TestRemovingACaseFromTheDenominatorCostsSomething:
    """`case_is_malformed` deletes a case outright — nine of seventy-eight are
    gone this way — and it used to ask for less than any other ruling."""

    def malformed(self, tmp_path, body):
        (tmp_path / "adjudications.yml").write_text(body, encoding="utf-8")
        return artifact.malformed_cases(tmp_path)

    def test_a_ruling_must_say_why(self, tmp_path):
        assert self.malformed(tmp_path, (
            "adjudications:\n"
            "  - case_id: one\n"
            "    case_is_malformed: true\n")) == {}

    def test_an_empty_reason_is_not_a_reason(self, tmp_path):
        assert self.malformed(tmp_path, (
            "adjudications:\n"
            "  - case_id: one\n"
            "    case_is_malformed: true\n"
            "    why_malformed: '   '\n")) == {}

    def test_the_string_false_does_not_rule_a_case_out(self, tmp_path):
        """`row.get(...)` is truthy, so `"false"` deleted a case. The shape
        this repository keeps finding in itself."""
        assert self.malformed(tmp_path, (
            "adjudications:\n"
            "  - case_id: one\n"
            "    case_is_malformed: 'false'\n"
            "    why_malformed: the safe member carries the weakness\n")) == {}

    def test_the_string_false_also_leaves_the_finding_ruling_working(self):
        """The other half, and the one the first version of this file missed.

        `malformed_cases` reads `is True` and the two finding-level readers
        read `not row.get(...)`. So `case_is_malformed: "false"` left the case
        in the denominator *and* silently switched its own ruling off — one
        field giving two answers, neither of them the one the row meant.
        """
        rows = [ruling(case_is_malformed="false")]

        assert artifact.ruled_incidental(rows, "one", "safe") == ["aa11"]

    def test_a_genuinely_malformed_row_still_excuses_nothing(self):
        rows = [ruling(case_is_malformed=True)]

        assert artifact.ruled_incidental(rows, "one", "safe") == []
        assert artifact.ruled_false_alarm(rows, "one", "safe") == []

    def test_a_complete_ruling_still_works(self, tmp_path):
        assert self.malformed(tmp_path, (
            "adjudications:\n"
            "  - case_id: one\n"
            "    case_is_malformed: true\n"
            "    why_malformed: the safe member carries the weakness\n")) == {
                "one": "the safe member carries the weakness"}

    def test_every_live_malformed_ruling_still_passes(self):
        """The tightening must not silently return nine cases to the
        denominator. If it does, the numbers move and nobody asked them to."""
        ruled = artifact.malformed_cases(ROOT / "corpus-real")

        assert len(ruled) == 13, "a live ruling stopped being read"
        assert all(v.strip() for v in ruled.values())


class TestTheAuthorOfARulingIsRecorded:
    def test_a_row_that_names_nobody_is_unrecorded_and_not_human(self):
        assert artifact.adjudicator({"case_id": "one"}) == "unrecorded"
        assert artifact.adjudicator({"adjudicated_by": ""}) == "unrecorded"
        assert artifact.adjudicator({"adjudicated_by": None}) == "unrecorded"

    def test_unrecorded_does_not_count_as_independent(self):
        report = artifact.independence([{"case_id": "one"},
                                        {"adjudicated_by": "model"}])

        assert report["independent"] == 0
        assert report["total"] == 2
        assert report["by"]["unrecorded"] == 1

    def test_a_human_ruling_counts(self):
        report = artifact.independence([{"adjudicated_by": "human"}])

        assert report["independent"] == 1

    def test_no_ruling_in_the_corpus_is_independent_today(self):
        """The claim `LIMITATIONS.md` makes, as a number.

        If this ever fails because somebody adjudicated by hand, the entry in
        `LIMITATIONS.md` is out of date and the thresholds it forbids may be
        recomputed — but only then, and only for the rows that changed.
        """
        rows = artifact.load_adjudications(ROOT / "corpus-real")
        report = artifact.independence(rows)

        assert report["total"] == len(rows) > 0
        assert report["independent"] == 0, (
            "a ruling is now independent; revisit LIMITATIONS.md")
        assert report["by"].get("unrecorded", 0) == 0, (
            "every ruling must name its author")


def test_the_limitation_is_written_down():
    """The number above is checkable; the reason it matters is prose, and prose
    is what gets dropped in a rewrite. Two copies of one fact drift, so the
    file that carries the reason is asserted to still carry it."""
    text = (ROOT / "LIMITATIONS.md").read_text(encoding="utf-8")

    assert "grading its own work" in text
    assert "no threshold" in text or "no rate" in text
