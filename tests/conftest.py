import subprocess
from pathlib import Path

import pytest

from security_agent.config import Config, GitLabContext
from security_agent.models import Candidate, Finding


def make_finding(**overrides):
    data = {
        "title": "SQL injection in user lookup",
        "severity": "high",
        "confidence": "high",
        "category": "injection",
        "file": "app/views.py",
        "line": 14,
        "impact": "broad_data_access",
        "reachable_without_authentication": "yes",
        "requires_user_interaction": "no",
        "evidence": 'db.execute("SELECT * FROM users WHERE id = " + user_id)',
        "description": "User input is concatenated into a query.",
        "exploit_scenario": "An anonymous caller sends id=1 OR 1=1 and reads every row.",
        "recommendation": "Use a parameterised query.",
    }
    data.update(overrides)
    return Finding.from_dict(data)


def make_candidate(**overrides):
    """Build a Candidate. `severity=` pins the severity, bypassing derivation —
    most tests care about what the gate does with a rating, not how it was
    reached."""
    candidate_fields = {}
    for key in ("in_changed_lines", "evidence_located_line", "verdict",
                "verdict_reason", "votes", "severity", "confidence",
                "attributed_by", "removes_control"):
        if key in overrides:
            candidate_fields[key] = overrides.pop(key)
    return Candidate(finding=make_finding(**overrides), **candidate_fields)


@pytest.fixture
def config():
    return Config(gitlab=GitLabContext())


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """A small real repository — these paths are all about git's actual behaviour."""
    env = {
        "GIT_AUTHOR_NAME": "Test", "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "Test", "GIT_COMMITTER_EMAIL": "test@example.com",
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(tmp_path),
    }

    def git(*args):
        subprocess.run(("git", "-C", str(tmp_path), *args), check=True,
                       capture_output=True, env=env)

    git("init", "-q", "-b", "main")
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(
        'def get_user(request, db):\n'
        '    user_id = request.args.get("id")\n'
        '    return db.execute("SELECT * FROM users WHERE id = " + user_id)\n',
        encoding="utf-8",
    )
    (tmp_path / "README.md").write_text("# Test project\n", encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion": 3}\n', encoding="utf-8")
    git("add", "-A")
    git("commit", "-q", "-m", "initial")
    return tmp_path
