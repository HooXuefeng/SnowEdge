def clipped_text(data: bytes, max_bytes: int) -> str:
    chunk = data[:max_bytes]
    return chunk.decode("utf-8", errors="replace")
