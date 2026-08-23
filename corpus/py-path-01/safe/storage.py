from pathlib import Path

UPLOAD_ROOT = Path("/srv/uploads")


def usage_bytes() -> int:
    return sum(p.stat().st_size for p in UPLOAD_ROOT.rglob("*") if p.is_file())
