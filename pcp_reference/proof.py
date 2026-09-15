from __future__ import annotations

import copy
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64url_decode, b64url_encode, canonical_bytes, digest, loads_no_duplicates
from .errors import ProtocolError


PROOF_CONTEXT = "pcp-legatus-v1"
PROOF_FIELDS = {"context", "signer_id", "key_id", "grant_id", "purpose"}
REQUEST_FIELDS = {"profile", "signer_id", "purpose", "envelope", "proof"}
FINALIZE_FIELDS = {"profile", "authorization_id", "outcome", "envelope_id", "thread", "journal_position"}
MOVE_PURPOSES = {
    "delegate": "legatus.delegate",
    "handoff": "legatus.handoff",
    "approve": "legatus.approve",
    "fail": "legatus.fail",
    "retry": "legatus.retry",
    "cancel": "legatus.cancel",
    "resume": "legatus.resume",
}
PROOF_DENIALS = {
    "invalid_proof",
    "unsigned",
    "unknown_key",
    "unknown_issuer",
    "bad_signature",
    "proof_signer_mismatch",
    "proof_key_mismatch",
    "proof_purpose_mismatch",
    "proof_envelope_mismatch",
    "carrier_is_not_authority",
    "identity_collapse",
}
AUTHORITY_DENIALS = {
    "grant_not_found",
    "expired",
    "revoked",
    "scope_mismatch",
    "budget_exhausted",
    "unavailable",
}


def unsigned_envelope(envelope: dict[str, object]) -> dict[str, object]:
    """Return the exact Legatus candidate with only ``sig`` removed."""

    value = copy.deepcopy(envelope)
    value.pop("sig", None)
    return value


def signing_object(protected: dict[str, object], envelope: dict[str, object]) -> dict[str, object]:
    """Build the six-field object signed by the PCP-Legatus profile."""

    _check_header(protected)
    return {
        "context": protected["context"],
        "signer_id": protected["signer_id"],
        "key_id": protected["key_id"],
        "grant_id": protected["grant_id"],
        "purpose": protected["purpose"],
        "envelope": unsigned_envelope(envelope),
    }


def signing_bytes(protected: dict[str, object], envelope: dict[str, object]) -> bytes:
    """Return JCS bytes for the exact six-field signing object.

    ``canonical_bytes`` deliberately implements the documented conformance
    subset. Production callers must use a complete RFC 8785 implementation.
    """

    return canonical_bytes(signing_object(protected, envelope))


def build_protected(
    envelope: dict[str, object],
    *,
    key_id: str,
    grant_id: str,
) -> dict[str, object]:
    move = envelope.get("type")
    if move not in MOVE_PURPOSES:
        raise ProtocolError("invalid_proof", "unknown Legatus move")
    signer = envelope.get("signer")
    if not isinstance(signer, str) or not signer.startswith("urn:pcp:principal:"):
        raise ProtocolError("carrier_is_not_authority", "Legatus signer must be a PCP principal URN")
    return {
        "context": PROOF_CONTEXT,
        "signer_id": signer,
        "key_id": key_id,
        "grant_id": grant_id,
        "purpose": MOVE_PURPOSES[move],
    }


def sign_compact(
    envelope: dict[str, object],
    protected: dict[str, object],
    private_key: Ed25519PrivateKey,
) -> str:
    _check_binding(envelope, protected)
    protected_bytes = canonical_bytes(protected)
    signature = private_key.sign(signing_bytes(protected, envelope))
    return f"pcp1.{b64url_encode(protected_bytes)}.{b64url_encode(signature)}"


def decode_compact(compact: str) -> tuple[dict[str, object], bytes]:
    """Decode a compact proof and normalize format failures."""

    try:
        if not isinstance(compact, str):
            raise ProtocolError("invalid_proof", "detached proof must be a string")
        if len(compact) > 4096:
            raise ProtocolError("invalid_proof", "detached proof exceeds the profile limit")
        parts = compact.split(".")
        if len(parts) != 3 or parts[0] != "pcp1":
            raise ProtocolError("invalid_proof", "invalid detached-proof serialization")
        protected_bytes = b64url_decode(parts[1])
        if b64url_encode(protected_bytes) != parts[1]:
            raise ProtocolError("invalid_proof", "detached-proof header base64url is not canonical")
        protected = loads_no_duplicates(protected_bytes)
        if not isinstance(protected, dict):
            raise ProtocolError("invalid_proof", "detached-proof header must be an object")
        _check_header(protected)
        if canonical_bytes(protected) != protected_bytes:
            raise ProtocolError("invalid_proof", "detached-proof header is not canonical")
        signature = b64url_decode(parts[2])
        if len(signature) != 64:
            raise ProtocolError("invalid_proof", "Ed25519 signature must be 64 bytes")
        if b64url_encode(signature) != parts[2]:
            raise ProtocolError("invalid_proof", "detached-proof signature base64url is not canonical")
        return protected, signature
    except ProtocolError as exc:
        if exc.code in {"invalid_proof", "carrier_is_not_authority", "identity_collapse"}:
            raise
        raise ProtocolError("invalid_proof", exc.message) from exc


def _check_header(protected: dict[str, object]) -> None:
    if set(protected) != PROOF_FIELDS:
        raise ProtocolError("invalid_proof", "detached-proof header must contain exactly five fields")
    if protected.get("context") != PROOF_CONTEXT:
        raise ProtocolError("invalid_proof", "unknown detached-proof context")
    signer = protected.get("signer_id")
    if not isinstance(signer, str) or not signer.startswith("urn:pcp:principal:"):
        raise ProtocolError("carrier_is_not_authority", "proof signer must be a PCP principal URN")
    key_id = protected.get("key_id")
    if not isinstance(key_id, str) or not key_id.startswith("urn:pcp:key:"):
        raise ProtocolError("invalid_proof", "proof key id is malformed")
    grant_id = protected.get("grant_id")
    if not isinstance(grant_id, str) or not grant_id.startswith("urn:pcp:grant:"):
        raise ProtocolError("invalid_proof", "proof grant id is malformed")
    if protected.get("purpose") not in MOVE_PURPOSES.values():
        raise ProtocolError("invalid_proof", "proof purpose is malformed")


def _check_binding(
    envelope: dict[str, object],
    protected: dict[str, object],
    *,
    expected_signer: str | None = None,
    expected_purpose: str | None = None,
    expected_key_id: str | None = None,
) -> None:
    _check_header(protected)
    envelope_signer = envelope.get("signer")
    if not isinstance(envelope_signer, str) or not envelope_signer.startswith("urn:pcp:principal:"):
        raise ProtocolError("carrier_is_not_authority", "Legatus signer must be a PCP principal URN")
    if protected.get("signer_id") != envelope_signer:
        raise ProtocolError("proof_signer_mismatch", "proof signer does not match envelope signer")
    if expected_signer is not None and protected.get("signer_id") != expected_signer:
        raise ProtocolError("proof_signer_mismatch", "proof signer does not match verifier request")
    purpose = MOVE_PURPOSES.get(envelope.get("type"))
    if purpose is None or protected.get("purpose") != purpose:
        raise ProtocolError("proof_purpose_mismatch", "proof purpose does not match envelope move")
    if expected_purpose is not None and protected.get("purpose") != expected_purpose:
        raise ProtocolError("proof_purpose_mismatch", "proof purpose does not match verifier request")
    if expected_key_id is not None and protected.get("key_id") != expected_key_id:
        raise ProtocolError("proof_key_mismatch", "resolved key does not match protected key id")


def verify_compact(
    envelope: dict[str, object],
    public_key: Ed25519PublicKey,
    *,
    expected_signer: str | None = None,
    expected_purpose: str | None = None,
    expected_key_id: str | None = None,
) -> dict[str, object]:
    compact = envelope.get("sig")
    if not isinstance(compact, str) or not compact:
        raise ProtocolError("unsigned", "Legatus envelope has no detached proof")
    protected, signature = decode_compact(compact)
    _check_binding(
        envelope,
        protected,
        expected_signer=expected_signer,
        expected_purpose=expected_purpose,
        expected_key_id=expected_key_id,
    )
    try:
        public_key.verify(signature, signing_bytes(protected, envelope))
    except InvalidSignature as exc:
        raise ProtocolError("bad_signature", "detached proof signature does not verify") from exc
    return protected


def verify_request(
    request: dict[str, object],
    public_key: Ed25519PublicKey,
    *,
    expected_key_id: str | None = None,
) -> dict[str, object]:
    if set(request) != REQUEST_FIELDS:
        raise ProtocolError("invalid_proof", "verifier request must contain exactly five fields")
    if request.get("profile") != PROOF_CONTEXT:
        raise ProtocolError("invalid_proof", "unknown verifier profile")
    envelope = request.get("envelope")
    proof = request.get("proof")
    if not isinstance(envelope, dict):
        raise ProtocolError("invalid_proof", "verifier request envelope must be an object")
    if not isinstance(proof, str) or not proof:
        raise ProtocolError("unsigned", "verifier request has no detached proof")
    compact = envelope.get("sig")
    if not isinstance(compact, str) or not compact:
        raise ProtocolError("unsigned", "Legatus envelope has no detached proof")
    if proof != compact:
        raise ProtocolError("proof_envelope_mismatch", "request proof differs from envelope signature")
    signer = request.get("signer_id")
    if not isinstance(signer, str) or not signer.startswith("urn:pcp:principal:"):
        raise ProtocolError("carrier_is_not_authority", "request signer must be a PCP principal URN")
    purpose = request.get("purpose")
    if purpose not in MOVE_PURPOSES.values():
        raise ProtocolError("invalid_proof", "request purpose is malformed")
    return verify_compact(
        envelope,
        public_key,
        expected_signer=signer,
        expected_purpose=str(purpose),
        expected_key_id=expected_key_id,
    )


def derive_legatus_authority(
    envelope: dict[str, object],
    protected: dict[str, object],
) -> dict[str, Any]:
    """Derive verifier inputs that stay outside the signed object."""

    thread = envelope.get("thread")
    envelope_id = envelope.get("id")
    if (
        not isinstance(thread, str)
        or not thread
        or not isinstance(envelope_id, str)
        or not envelope_id
    ):
        raise ProtocolError("invalid_proof", "Legatus thread and envelope id are required")
    return {
        "envelope_digest": digest(unsigned_envelope(envelope)),
        "request_digest": digest(signing_object(protected, envelope)),
        "idempotency_key": legatus_idempotency_key(thread, envelope_id),
        "spend": [{"unit": "actions", "amount": 1}],
    }


def legatus_idempotency_key(thread: str, envelope_id: str) -> str:
    """Derive the collision-free key for one Legatus envelope.

    The profile hashes RFC 8785 JCS of exactly ``{thread, envelope_id}`` and
    prefixes the normal PCP digest representation with ``legatus:``.
    """

    if (
        not isinstance(thread, str)
        or not thread
        or not isinstance(envelope_id, str)
        or not envelope_id
    ):
        raise ProtocolError("malformed", "Legatus thread and envelope id must be non-empty strings")
    return "legatus:" + digest({"thread": thread, "envelope_id": envelope_id})


def validate_legatus_finalization(
    request: dict[str, object],
    reservation: dict[str, object],
) -> str:
    """Validate finalization fields against separately stored reservation data."""

    if set(request) != FINALIZE_FIELDS or request.get("profile") != PROOF_CONTEXT:
        raise ProtocolError("malformed", "invalid Legatus finalization request")
    comparisons = {
        "authorization": (request.get("authorization_id"), reservation.get("id")),
        "envelope": (request.get("envelope_id"), reservation.get("envelope_id")),
        "thread": (request.get("thread"), reservation.get("thread")),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            raise ProtocolError("grant_binding_mismatch", f"finalization {label} does not match reservation")
    thread = request.get("thread")
    envelope_id = request.get("envelope_id")
    if not isinstance(thread, str) or not isinstance(envelope_id, str):
        raise ProtocolError("malformed", "finalization thread and envelope id must be strings")
    if reservation.get("idempotency_key") != legatus_idempotency_key(thread, envelope_id):
        raise ProtocolError("idempotency_conflict", "finalization does not match reservation idempotency")
    outcome = request.get("outcome")
    position = request.get("journal_position")
    if outcome == "commit":
        if not isinstance(position, int) or isinstance(position, bool) or position < 1:
            raise ProtocolError("malformed", "commit finalization requires a positive journal position")
    elif outcome == "release":
        if position is not None:
            raise ProtocolError("malformed", "release finalization requires a null journal position")
    else:
        raise ProtocolError("malformed", "unknown Legatus finalization outcome")
    return outcome


def legatus_disposition(code: str) -> tuple[str, str | None]:
    if code == "unavailable":
        return "retry", None
    if code in PROOF_DENIALS:
        return "deny", "LEGATUS_E_SIG"
    if code in AUTHORITY_DENIALS:
        return "deny", None
    return "deny", "LEGATUS_E_SIG"
