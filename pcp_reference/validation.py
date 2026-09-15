from __future__ import annotations

from jsonschema import ValidationError

from .errors import ProtocolError


def schema_error_code(error: ValidationError) -> str:
    if error.validator == "additionalProperties":
        return "unknown_property"
    return "malformed"


def require_identity_kind(subject_id: str, subject_kind: str) -> None:
    expected_prefix = f"urn:pcp:{subject_kind}:"
    if not subject_id.startswith(expected_prefix):
        raise ProtocolError("identity_collapse", "subject kind does not match its URN")


def require_unique_budget_units(items: list[dict[str, object]]) -> None:
    units = [item.get("unit") for item in items]
    if len(units) != len(set(units)):
        raise ProtocolError("malformed", "budget units must be unique")
