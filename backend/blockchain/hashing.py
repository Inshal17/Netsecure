import hashlib
import json
from typing import Any


def canonicalize(data: Any) -> str:
    """Convert data into a consistent JSON representation."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def sha256_hash(data: Any) -> str:
    """Generate SHA-256 hash for structured data."""
    canonical = canonicalize(data)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    """Generate SHA-256 hash for plain text."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()