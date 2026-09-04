"""The seal: the small keepable record of a drawn sample.

Separate from `test_ordinary_corpus.py` because the tool is separate, and the
tool is separate for a reason the freeze found within a minute: a file that
seals cannot be one of the files it seals. Adding a subcommand to
`ordinary_corpus.py` moved that file's whole-file digest, so the freeze read
`not done` and the seal refused its own manifest.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import ordinary_corpus as oc
import sample_seal as seal

from test_ordinary_corpus import corpus, pool, write_pool  # noqa: F401


def _sealable(tmp_path, corpus):
    """A manifest, its candidates file, and a freeze to chain the seal to."""
    path = write_pool(tmp_path, pool())
    manifest = tmp_path / "manifest.json"
    assert oc.main(["select", "--candidates", str(path), "--since", "2026-01-01",
                    "--until", "2026-07-01", "--target", "30",
                    "--corpus", str(corpus), "--out", str(manifest)]) == 0
    freeze = tmp_path / "freeze.json"
    freeze.write_text(json.dumps({
        "owner_acknowledgement": "the owner, 2026-09-04",
        "git": {"commit": "a" * 40},
        "d013": {"digest": "d013digest"},
    }), encoding="utf-8")
    return path, manifest, freeze


def test_the_seal_is_small_and_carries_the_sample_and_the_chain(
        tmp_path, corpus):
    """Small enough to keep, complete enough to find the big file again.

    The manifest is mostly a record of what was *not* drawn — 3,056 candidate
    summaries in the live one — and `check` cannot use it alone anyway: it
    needs the candidates file whose digest the manifest records. So the seal
    keeps the rows, the rules and the digests, and nothing else.
    """
    path, manifest, freeze = _sealable(tmp_path, corpus)
    out = tmp_path / "sample.seal.json"
    assert seal.main(["--manifest", str(manifest), "--candidates",
                    str(path), "--freeze", str(freeze), "--corpus",
                    str(corpus), "--out", str(out)]) == 0
    body = json.loads(out.read_text(encoding="utf-8"))

    assert body["schema"] == seal.SEAL_SCHEMA
    assert len(body["selected"]) == 30
    assert body["candidates"]["digest"] == oc.digest_file(path)
    assert body["candidates"]["records"] == 48
    assert body["freeze"]["digest"] == oc.digest_file(freeze)
    assert body["freeze"]["owner_acknowledgement"] == "the owner, 2026-09-04"
    assert body["freeze"]["d013_digest"] == "d013digest"
    # No bodies: diff text belongs to the projects it was harvested from, and
    # commit metadata carries other people's names.
    assert "candidates" not in body["selected"][0]
    assert "diff_text" not in out.read_text(encoding="utf-8")
    assert out.stat().st_size < manifest.stat().st_size


@pytest.mark.parametrize("spoil", [
    lambda m: m["selected"][0].__setitem__("stratum", "quiet"),
    lambda m: m["selected"].pop(),
    lambda m: m["counts"].__setitem__("taken", 7),
    lambda m: m["coverage"].__setitem__("checks", []),
    lambda m: m["rules"].__setitem__("target", 5),
    lambda m: m["selected"][0].__setitem__(
        "label_evidence", "authoritative"),
])
def test_the_seal_refuses_a_manifest_edited_after_the_draw(
        tmp_path, corpus, spoil):
    """The defect: the seal checked the manifest against itself.

    It compared the candidates digest with the value written *in the manifest*,
    which an edit to `selected` leaves untouched. So a row could be changed
    after the draw and the seal would hash the changed file and present that
    hash as provenance — self-attestation with a digest on it. It runs the same
    reproduction `check` runs now. Codex, 2026-09-04.

    `label_evidence` is in the list on purpose: `template` copies it through,
    so flipping it to `authoritative` tells the adjudicator the label channel
    was not blind and they skip the one check the manifest says they must make
    by hand.
    """
    path, manifest, freeze = _sealable(tmp_path, corpus)
    body = json.loads(manifest.read_text(encoding="utf-8"))
    spoil(body)
    manifest.write_text(json.dumps(body), encoding="utf-8")
    out = tmp_path / "s.json"
    assert seal.main(["--manifest", str(manifest), "--candidates",
                    str(path), "--freeze", str(freeze), "--corpus",
                    str(corpus), "--out", str(out)]) == 2
    assert not out.exists()


def test_the_seal_refuses_candidates_the_manifest_was_not_built_from(
        tmp_path, corpus):
    """Sealing them together would tie the sample to the wrong input."""
    _path, manifest, freeze = _sealable(tmp_path, corpus)
    elsewhere = tmp_path / "other"
    elsewhere.mkdir()
    other = write_pool(elsewhere, pool(n_repos=3))
    assert seal.main(["--manifest", str(manifest), "--candidates",
                    str(other), "--freeze", str(freeze), "--corpus",
                    str(corpus), "--out", str(tmp_path / "s.json")]) == 2
    assert not (tmp_path / "s.json").exists()


def test_the_seal_refuses_a_freeze_nobody_signed(tmp_path, corpus):
    """A seal chained to an unsigned freeze inherits nothing."""
    path, manifest, freeze = _sealable(tmp_path, corpus)
    freeze.write_text(json.dumps({"git": {"commit": "a" * 40}}),
                      encoding="utf-8")
    assert seal.main(["--manifest", str(manifest), "--candidates",
                    str(path), "--freeze", str(freeze), "--corpus",
                    str(corpus), "--out", str(tmp_path / "s.json")]) == 2
    assert not (tmp_path / "s.json").exists()


def test_the_seal_will_not_silently_replace_one(tmp_path, corpus):
    path, manifest, freeze = _sealable(tmp_path, corpus)
    out = tmp_path / "sample.seal.json"
    argv = ["--manifest", str(manifest), "--candidates", str(path),
            "--freeze", str(freeze), "--corpus", str(corpus),
            "--out", str(out)]
    assert seal.main(argv) == 0
    first = out.read_text(encoding="utf-8")
    assert seal.main(argv) == 2
    assert out.read_text(encoding="utf-8") == first, "refused and wrote anyway"
    assert seal.main([*argv, "--replace"]) == 0


