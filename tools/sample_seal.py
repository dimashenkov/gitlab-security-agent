#!/usr/bin/env python3
"""The sample, small enough to keep and complete enough to audit.

    tools/sample_seal.py --manifest M --candidates C --freeze F --out O

## Why this is a separate file

It was written inside `tools/ordinary_corpus.py` first, and the freeze caught
it within a minute: that file is one of the ten inputs the freeze digests, so
adding a subcommand to it made the freeze report `not done`, and `seal` itself
refused the manifest because the generator's whole-file hash had moved.

Both refusals were correct. **A tool that seals cannot live in the file it
seals.** So this one imports what it needs and adds nothing to the frozen
closure — the change that made this file necessary is the change this file
exists to avoid.

## What it writes, and what it deliberately leaves out

The manifest is 3.9 MB because it summarises every one of ~3,000 candidates,
most of them not drawn. It carries no diff text — that was assumed once and the
assumption was wrong, checked — but it is still mostly a record of what was
*not* selected, and `check` cannot use it alone: reproducing the draw needs the
44.5 MB candidates file whose digest the manifest records.

So the seal keeps the drawn rows, the rules that drew them, and the digests
that let the big file be recognised wherever it is kept. Measured on the live
sample: 19 KB against 3.87 MB.

**No bodies, deliberately.** Diff text stays the copyright of the twenty-nine
projects it was harvested from, on their own separate terms, and commit
metadata carries other people's names and addresses. "Public" is not "ours to
redistribute", and a licence review per repository is not something this tool
can do.

**It verifies before it seals, with the same check `ordinary_corpus check`
runs.** The first version compared only the candidates digest against the value
written *in the manifest* — which an edit to `selected` leaves untouched. A row
could then be changed after the draw, and the seal would hash the changed file
and present that hash as provenance: self-attestation with a digest on it.
Codex, 2026-09-04.

**It does not replace the configuration freeze and must not.** D-013 freezes
the configuration *before* the sample is built, so retaking that freeze once
the draw has been seen would weaken the ordering it exists to hold. The seal
points at the freeze instead, by digest, by commit and by the owner's
acknowledgement.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ordinary_corpus as oc

SEAL_SCHEMA = "ordinary-sample-seal/1"


class SealError(Exception):
    """Something that makes a seal not worth writing."""


def verification_problems(manifest_path: Path, candidates: Path,
                          corpus: Path) -> list:
    """Every way the manifest fails to be what the rules give.

    Runs `ordinary_corpus`'s own `check`, rather than a weaker test of its own.
    Calling the command keeps one definition of "this manifest reproduces": a
    second implementation here would drift from it, and the drift would be
    silent in the permissive direction.
    """
    argv = argparse.Namespace(manifest=str(manifest_path),
                              candidates=str(candidates), corpus=str(corpus))
    try:
        code = oc.cmd_check(argv)
    except oc.InputError as exc:
        return [str(exc)]
    except (OSError, ValueError, KeyError) as exc:
        return ["{} could not be verified: {}: {}".format(
            manifest_path, type(exc).__name__, exc)]
    if code != 0:
        return ["{} does not reproduce from {} — the reasons are printed "
                "above".format(manifest_path, candidates)]
    return []


def build_seal(manifest_path: Path, candidates: Path, freeze_path: Path,
               corpus: Path) -> dict:
    for path, what in ((manifest_path, "manifest"), (candidates, "candidates"),
                       (freeze_path, "freeze")):
        if not path.is_file():
            raise SealError(
                "{} is not a readable file; a seal over a missing {} would "
                "record digests of nothing".format(path, what))

    problems = verification_problems(manifest_path, candidates, corpus)
    if problems:
        raise SealError(
            "{} does not reproduce from its input, so there is nothing here "
            "worth sealing:\n  {}".format(manifest_path, "\n  ".join(problems)))

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    freeze = json.loads(freeze_path.read_text(encoding="utf-8"))

    acknowledgement = freeze.get("owner_acknowledgement")
    if not isinstance(acknowledgement, str) or not acknowledgement.strip():
        raise SealError(
            "{} carries no `owner_acknowledgement` — a seal chained to an "
            "unsigned freeze inherits nothing".format(freeze_path))

    selected = manifest.get("selected")
    if not isinstance(selected, list) or not selected:
        raise SealError("{} has no `selected` rows".format(manifest_path))

    return {
        "schema": SEAL_SCHEMA,
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "corpus": manifest.get("corpus", ""),
        "rules": manifest.get("rules", {}),
        "generator": manifest.get("generator", {}),
        "counts": manifest.get("counts", {}),
        "coverage": manifest.get("coverage", {}),
        "selected": selected,
        # Where the big file has to be found again, and how it is recognised
        # when it is. A path alone is not durable; the digest is what makes a
        # copy anywhere provably the same file.
        "candidates": {
            "digest": oc.digest_file(candidates),
            "bytes": candidates.stat().st_size,
            "records": len(manifest.get("candidates", []) or []),
            "path_when_sealed": str(candidates),
        },
        "manifest": {
            "digest": oc.digest_file(manifest_path),
            "bytes": manifest_path.stat().st_size,
            "path_when_sealed": str(manifest_path),
        },
        # The chain. Not a copy of the freeze: a pointer that breaks loudly if
        # the freeze is replaced.
        "freeze": {
            "digest": oc.digest_file(freeze_path),
            "commit": (freeze.get("git") or {}).get("commit"),
            "owner_acknowledgement": acknowledgement.strip(),
            "d013_digest": (freeze.get("d013") or {}).get("digest"),
        },
    }


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--candidates", required=True)
    parser.add_argument("--freeze", required=True)
    parser.add_argument("--corpus", default=str(oc.ROOT / "corpus-real"))
    parser.add_argument("--out", required=True)
    parser.add_argument("--replace", action="store_true")
    args = parser.parse_args(argv)

    out = Path(args.out)
    try:
        if out.exists() and not args.replace:
            raise SealError(
                "{} already exists. A seal silently replaced is a seal nobody "
                "can compare against — move it aside, or pass `--replace` if "
                "this round is genuinely being resealed".format(out))
        seal = build_seal(Path(args.manifest), Path(args.candidates),
                          Path(args.freeze), Path(args.corpus))
    except SealError as exc:
        # Exit 2, never 1. "I could not seal this" and "this sample says
        # something" are different answers, and this repository spends the
        # distinction everywhere else.
        print(str(exc), file=sys.stderr)
        return 2

    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(seal, indent=2, sort_keys=True) + "\n",
                   encoding="utf-8")
    print("Sealed {} change(s) into {} ({} bytes).".format(
        len(seal["selected"]), out, out.stat().st_size))
    print("The candidates file is not copied. Keep it where its digest still "
          "matches: {}".format(seal["candidates"]["digest"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
