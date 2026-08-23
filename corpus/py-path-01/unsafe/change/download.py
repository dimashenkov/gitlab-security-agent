from pathlib import Path

from flask import abort, send_file

from storage import UPLOAD_ROOT


def download(name: str):
    target = (UPLOAD_ROOT / name).resolve()
    if not target.exists():
        abort(404)
    return send_file(target)
