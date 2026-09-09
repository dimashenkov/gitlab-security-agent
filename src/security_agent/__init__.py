"""AI security review gate for GitLab CI/CD.

Written by Dimitar Shenkov <dimitar.shenkov@gmail.com>, MIT licensed.
https://github.com/dimashenkov/gitlab-security-agent
"""

import functools as _functools

__version__ = "0.1.0"

# Kept here rather than duplicated into every renderer: the report, the job log
# and `--version` all sign the same work, and three copies of a URL is three
# chances for one of them to go stale.
__author__ = "Dimitar Shenkov"
__email__ = "dimitar.shenkov@gmail.com"
__license__ = "MIT"

PROJECT_NAME = "gitlab-security-agent"
PROJECT_URL = "https://github.com/dimashenkov/gitlab-security-agent"
AUTHOR_URL = "https://github.com/dimashenkov"


@_functools.lru_cache(maxsize=1)
def source_digest() -> str:
    """What this build actually is, taken from the code rather than remembered.

    `__version__` has read `0.1.0` since the first commit and through every
    change since, so an artifact produced by today's agent and one produced
    weeks ago carry the same implementation identity — and the identity key
    treats them as the same reviewer. A number that a person has to remember
    to raise is a number that will be wrong exactly when it matters, which is
    after a change nobody thought was worth a release.

    Codex, 2026-09-09: *"`agent_version = 0.1.0` is not a usable
    implementation identity. Use an automatically changing build/source digest
    or immutable release identifier. A manually remembered version bump
    recreates the same failure."*

    Every `.py` file of the package, by name and by bytes, in one hash. Names
    are included so that deleting a module changes the digest even when
    nothing that remains was touched. Computed once and held, because the
    files cannot change under a running process in any way this is meant to
    notice.

    Falls back to `__version__` when the source cannot be read — an installed
    zip, a stripped image. That is a worse identity and it is the honest one:
    it does not claim a digest it did not compute.
    """
    import hashlib
    import pathlib

    try:
        here = pathlib.Path(__file__).resolve().parent
        running = hashlib.sha256()
        seen = 0
        for path in sorted(here.glob("*.py")):
            running.update(path.name.encode("utf-8"))
            running.update(b"\0")
            running.update(path.read_bytes())
            running.update(b"\0")
            seen += 1
        if not seen:
            # **Nothing read is not "read nothing".** Codex, 2026-09-09: a
            # sourceless installation — a zipimport, a stripped image — makes
            # `glob` return an empty sequence and raise nothing at all, so the
            # loop completed and this returned the SHA-256 of no input. That
            # is one constant value, identical for every such build, which is
            # exactly the collapse `__version__` was found guilty of. The
            # docstring said it fell back here and it did not.
            return __version__
        return running.hexdigest()[:16]
    except OSError:
        return __version__
