import hashlib
import hmac
import pickle

from flask import Response, request

import spool
from raster import draw


def resume_job():
    """Continue a render job from the state sent with the request."""
    payload = request.get_data()
    digest = hmac.new(spool.KEY, payload, hashlib.sha256).hexdigest()
    if len(payload) > spool.LIMIT:
        return Response("state rejected", status=413)
    state = pickle.loads(payload)
    return Response(draw(state), mimetype="image/png", headers={"ETag": digest})
