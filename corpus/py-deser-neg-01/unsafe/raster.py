import io


def draw(state: dict) -> bytes:
    """Rasterise a render state into a PNG byte string."""
    buffer = io.BytesIO()
    state["scene"].save(buffer, format="PNG", optimize=True)
    return buffer.getvalue()
