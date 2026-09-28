from __future__ import annotations

import re
from datetime import datetime
from typing import Iterable

from jsonschema import ValidationError

from .errors import ProtocolError


# First matching group wins. Group 1 classifies the authority position before
# the unsupported_version / unknown_type residuals, which would otherwise hide
# a recognized non-grant type. See docs/conformance.md.
ERROR_PRECEDENCE: tuple[tuple[str, ...], ...] = (
    (
        "malformed",
        "duplicate_property",
        "unknown_property",
        "parser_record_forbidden",
        "cl_type_forbidden",
        "recovery_is_not_a_grant",
        "unsupported_version",
        "unknown_type",
    ),
    (
        "identity_collapse",
        "unknown_subject",
        "carrier_is_not_authority",
    ),
    (
        "unsigned",
        "unknown_issuer",
        "key_binding_mismatch",
        "proof_binding_mismatch",
        "bad_signature",
    ),
    (
        "grant_binding_mismatch",
        "not_before",
        "expired",
        "revoked",
    ),
    (
        "purpose_mismatch",
        "scope_invalid",
        "delegate_forbidden",
    ),
    (
        "idempotency_conflict",
        "replay_detected",
        "reservation_not_live",
    ),
    (
        "budget_exhausted",
        "receipt_chain_invalid",
    ),
    ("verification_unavailable",),
)

PARSER_RECORD_TYPES = frozenset({"memory_parser_record", "session_receipt"})
CONTEXT_LAYER_AUTHORITY_TYPES = frozenset({
    "context_pass",
    "context_disclosure",
    "scoped_bundle",
    "pcp_context_authorization",
})
RECOVERY_AUTHORITY_TYPES = frozenset({"pcp_recovery", "pcp_key_rotation"})
HOST_ISSUER_ROLES = frozenset({"workspace", "chat_host", "agent_host"})
_KEY_ID = re.compile(r"^urn:pcp:key:[A-Za-z0-9._~-]+$")


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


def reject_non_grant_authority(presented: object) -> None:
    """Reject a recognized non-grant offered as authority.

    Callers parse JSON and reject duplicate keys first. This check reads
    ``type`` before grant-schema evaluation so a forbidden artifact is not
    reported as ``unknown_type`` or ``malformed``. A ``pcp_grant`` and every
    other unrecognized type return without error.
    """

    if not isinstance(presented, dict):
        return
    artifact_type = presented.get("type")
    if not isinstance(artifact_type, str):
        return
    if artifact_type in PARSER_RECORD_TYPES:
        raise ProtocolError(
            "parser_record_forbidden",
            "a memory-parser record or session receipt is context, not a grant",
        )
    if artifact_type in CONTEXT_LAYER_AUTHORITY_TYPES:
        raise ProtocolError(
            "cl_type_forbidden",
            "a Context Layer pass authorizes context disclosure, not an action",
        )
    if artifact_type in RECOVERY_AUTHORITY_TYPES:
        raise ProtocolError(
            "recovery_is_not_a_grant",
            "recovery or key rotation does not mint a grant",
        )


def reject_host_as_issuer(actor_role: str) -> None:
    """A host that carries an agent is a carrier, not an issuer."""

    if actor_role in HOST_ISSUER_ROLES:
        raise ProtocolError(
            "carrier_is_not_authority",
            "a hosting workspace, chat host, or agent host is not an issuer",
        )


def parse_instant(value: object, label: str) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("malformed", f"{label} must be RFC 3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("malformed", f"{label} must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("malformed", f"{label} must include a timezone")
    return parsed


def require_grant_window(grant: dict[str, object], now: datetime) -> None:
    """Require ``now`` inside ``[not_before, expires_at)``.

    v0.1 defines no clock skew and no grace past ``expires_at``. Callers
    verify the principal signature before this check. A null ``not_before``
    uses ``issued_at``, matching the binding window.
    """

    if now.tzinfo is None:
        raise ProtocolError("malformed", "observation time must include a timezone")
    start_value = grant.get("not_before")
    if start_value is None:
        start_value = grant.get("issued_at")
    start = parse_instant(start_value, "grant start")
    expiry = parse_instant(grant.get("expires_at"), "grant expiry")
    if now < start:
        raise ProtocolError("not_before", "grant is not yet valid")
    if now >= expiry:
        raise ProtocolError("expired", "grant is expired")


def rotate_published_keys(published_key_ids: Iterable[str], new_key_id: str) -> list[str]:
    """Publish ``new_key_id`` without rewriting already issued grants."""

    if not isinstance(new_key_id, str) or _KEY_ID.fullmatch(new_key_id) is None:
        raise ProtocolError("malformed", "rotated key id is malformed")
    keys = list(published_key_ids)
    if new_key_id not in keys:
        keys.append(new_key_id)
    return keys


def require_published_signing_key(published_key_ids: Iterable[str], key_id: object) -> None:
    """A removed signing key is ``unknown_issuer``. A bad key id is ``malformed``."""

    if not isinstance(key_id, str) or _KEY_ID.fullmatch(key_id) is None:
        raise ProtocolError("malformed", "signing key id is malformed")
    if key_id not in set(published_key_ids):
        raise ProtocolError("unknown_issuer", "signing key is not in the published issuer set")
