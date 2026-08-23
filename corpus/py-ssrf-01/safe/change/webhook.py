from urllib.parse import urlparse

from http import get_json

ALLOWED_HOSTS = frozenset({"api.partner-a.com", "api.partner-b.com"})


def fetch_partner_profile(callback_url: str):
    """Call a partner endpoint configured by the tenant."""
    parsed = urlparse(callback_url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("callback host is not an approved partner")
    return get_json(callback_url)
