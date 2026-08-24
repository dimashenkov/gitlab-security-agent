import hashlib
import hmac
import pickle

from flask import Response, request

import spool
from raster import draw


def resume_job():
    """Continue a render job from the state spooled by an earlier request."""
    tag, payload = spool.read(int(request.args["job"]))
    expected = hmac.new(spool.KEY, payload, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        return Response("state rejected", status=409)
    state = pickle.loads(payload)
    return Response(draw(state), mimetype="image/png")
