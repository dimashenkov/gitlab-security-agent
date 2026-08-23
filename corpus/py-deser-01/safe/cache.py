import redis

client = redis.Redis(host="cache", port=6379)


def put(key: str, blob: bytes, ttl: int = 3600) -> None:
    client.setex(key, ttl, blob)


def raw(key: str) -> bytes:
    return client.get(key)
