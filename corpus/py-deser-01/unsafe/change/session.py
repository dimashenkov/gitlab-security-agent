import pickle

from cache import raw


def load_session(session_id: str) -> dict:
    """Restore a session document written by an earlier request."""
    blob = raw("session:" + session_id)
    if blob is None:
        return {}
    return pickle.loads(blob)
