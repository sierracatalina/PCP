from __future__ import annotations

import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


NOW = "2026-09-15T12:00:00Z"
LATER = "2026-09-15T13:00:00Z"
PRINCIPAL_ID = "urn:pcp:principal:alice"
KEY_ID = "urn:pcp:key:alice-1"
GRANT_ID = "urn:pcp:grant:grant-1"
FAMILY_ID = "urn:pcp:family:family-1"
SIGNATURE_VALUE = "A" * 86
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))


def public_key_value() -> str:
    raw = private_key().public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def signature() -> dict[str, str]:
    return {"alg": "Ed25519", "key_id": KEY_ID, "value": SIGNATURE_VALUE}


def grant() -> dict[str, object]:
    return {
        "spec_version": "pcp/0.1",
        "type": "pcp_grant",
        "id": GRANT_ID,
        "family_id": FAMILY_ID,
        "issuer_id": PRINCIPAL_ID,
        "subject_id": PRINCIPAL_ID,
        "subject_kind": "principal",
        "purpose": "legatus.delegate",
        "audience": "urn:pcp:audience:legatus:test",
        "scope": {
            "actions": ["legatus.delegate"],
            "resources": ["urn:legatus:thread:test-1"],
        },
        "budget": [{"unit": "actions", "limit": 1}],
        "issued_at": NOW,
        "not_before": NOW,
        "expires_at": LATER,
        "revocation_id": "urn:pcp:revocation:grant-1",
        "parent_grant_id": None,
        "allow_subdelegation": False,
        "signature": signature(),
    }


def legatus_envelope() -> dict[str, object]:
    return {
        "legatus": 0,
        "id": "env-1",
        "thread": "thread-1",
        "type": "delegate",
        "parents": [],
        "clock": {"seq": 1, "now": 100},
        "signer": PRINCIPAL_ID,
        "payload": {
            "assignee": "urn:pcp:principal:worker",
            "task_ref": "task-1",
            "gate": False,
        },
        "sig": "",
    }
