import requests

TIMEOUT = 5


def get_json(url: str):
    response = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
    response.raise_for_status()
    return response.json()
