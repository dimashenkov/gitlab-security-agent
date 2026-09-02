"""The package metadata, which nothing was reading.

`pyproject.toml` declared no runtime dependencies for ten days and nobody
noticed, because the only thing that runs `pip install -e .` is a GitHub
workflow that triggers on a pull request — and this repository has none. The
suite imports the package from `src/` and never installs it, so every test
stayed green over a package that could not be built at all.
"""

from __future__ import annotations

from pathlib import Path

try:  # 3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - 3.9 and 3.10
    import tomli as tomllib

PYPROJECT = Path(__file__).resolve().parents[1] / "pyproject.toml"


def project() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]


def test_the_package_declares_its_runtime_dependencies():
    """A TOML table header ends the table above it.

    `[project.urls]` was inserted directly above the `dependencies` array in
    `0716088`, which silently reparented it to `project.urls.dependencies`. The
    package then declared no runtime requirements — `anthropic`, `jsonschema`,
    `PyYAML` and `requests` all gone — and installing it produced something
    that imports nothing it needs.
    """
    declared = project().get("dependencies")

    assert declared, "the package declares no runtime dependencies"
    for name in ("anthropic", "jsonschema", "PyYAML", "requests"):
        assert any(name.lower() in spec.lower() for spec in declared), (
            "{} is not among the declared dependencies".format(name))


def test_every_project_url_is_a_url():
    """The shape of the reparenting, caught directly.

    `project.urls` must map names to strings; an array landing there is what a
    misplaced table header produces, and `pip install -e .` refuses the whole
    file with `must be string` rather than saying which key moved.
    """
    for name, value in (project().get("urls") or {}).items():
        assert isinstance(value, str), (
            "project.urls.{} is {!r}, which means a table header was added "
            "above something that belonged to [project]".format(name, value))


def test_nothing_bare_follows_the_urls_table():
    """The rule that keeps it from happening again, checked rather than
    written in a comment beside it.

    The first version of this test split the file on the string
    `[project.urls]` — and matched the *comment* above the table, which quotes
    it. A check satisfied by a string rather than by the structure it is about,
    in the test written against exactly that: table headers are read as
    headers here, at the start of a line, with comments ignored.
    """
    tables: dict = {}
    current = None
    for line in PYPROJECT.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped
            tables.setdefault(current, [])
            continue
        if current is not None and "=" in stripped:
            tables[current].append(stripped.split("=", 1)[0].strip())

    urls = tables.get("[project.urls]")
    assert urls, "[project.urls] is missing or empty"
    assert "dependencies" not in urls, (
        "`dependencies` is inside [project.urls]; a table header was added "
        "above something that belonged to [project]")
    assert "dependencies" in tables.get("[project]", []), (
        "`dependencies` is not in the [project] table where it belongs")
