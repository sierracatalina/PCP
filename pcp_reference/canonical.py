from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from .errors import ProtocolError


MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _check_fixture_subset(value: Any) -> None:
    """Reject values outside the deterministic ASCII fixture subset.

    Production implementations must use a complete RFC 8785 implementation.
    The reference suite deliberately limits generated vectors to strings,
    booleans, null, safe integers, arrays, and objects with ASCII strings.
    """

    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            raise ProtocolError("malformed", "integer exceeds the interoperable safe range")
        return
    if isinstance(value, float):
        raise ProtocolError("malformed", "floating-point values are outside the fixture profile")
    if isinstance(value, str):
        try:
            value.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProtocolError("malformed", "non-ASCII text is outside the fixture profile") from exc
        return
    if isinstance(value, list):
        for item in value:
            _check_fixture_subset(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError("malformed", "object keys must be strings")
            _check_fixture_subset(key)
            _check_fixture_subset(item)
        return
    raise ProtocolError("malformed", f"unsupported JSON value: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check_fixture_subset(value)
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not value or "=" in value:
        raise ProtocolError("malformed", "base64url must be unpadded")
    padding = "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except ValueError as exc:
        raise ProtocolError("malformed", "invalid base64url") from exc


def loads_no_duplicates(value: bytes) -> Any:
    def object_pairs(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ProtocolError("duplicate_property", f"duplicate property: {key}")
            result[key] = item
        return result

    try:
        return json.loads(value.decode("utf-8"), object_pairs_hook=object_pairs)
    except UnicodeDecodeError as exc:
        raise ProtocolError("malformed", "JSON must be UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError("malformed", "invalid JSON") from exc
