import hashlib
import hmac
import os
from pathlib import Path

SPOOL = Path("/var/lib/renderer/spool")
KEY = os.environ["RENDERER_SPOOL_KEY"].encode()
LIMIT = 1 << 20


def write(job_id: int, payload: bytes) -> None:
    SPOOL.mkdir(mode=0o700, parents=True, exist_ok=True)
    tag = hmac.new(KEY, payload, hashlib.sha256).digest()
    (SPOOL / "{}.state".format(job_id)).write_bytes(tag + payload)


def read(job_id: int) -> tuple:
    blob = (SPOOL / "{}.state".format(job_id)).read_bytes()
    return blob[:32], blob[32:]
