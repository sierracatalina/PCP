from __future__ import annotations

import copy
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import b64url_decode, b64url_encode, canonical_bytes, digest
from .errors import ProtocolError


def unsigned_record(record: dict[str, object]) -> dict[str, object]:
    value = copy.deepcopy(record)
    value.pop("signature", None)
    return value


def sign_record(record: dict[str, object], key_id: str, private_key: Ed25519PrivateKey) -> dict[str, object]:
    value = unsigned_record(record)
    signature = private_key.sign(canonical_bytes(value))
    value["signature"] = {
        "alg": "Ed25519",
        "key_id": key_id,
        "value": b64url_encode(signature),
    }
    return value


def verify_record(record: dict[str, object], public_key: Ed25519PublicKey) -> None:
    signature = record.get("signature")
    if not isinstance(signature, dict) or signature.get("alg") != "Ed25519":
        raise ProtocolError("unsigned", "record has no Ed25519 signature")
    encoded = signature.get("value")
    if not isinstance(encoded, str):
        raise ProtocolError("unsigned", "record signature value is missing")
    try:
        raw_signature = b64url_decode(encoded)
    except ProtocolError as exc:
        raise ProtocolError("bad_signature", "record signature encoding is invalid") from exc
    if len(raw_signature) != 64 or b64url_encode(raw_signature) != encoded:
        raise ProtocolError("bad_signature", "record signature encoding is invalid")
    try:
        public_key.verify(raw_signature, canonical_bytes(unsigned_record(record)))
    except InvalidSignature as exc:
        raise ProtocolError("bad_signature", "record signature does not verify") from exc


def receipt_digest(receipt: dict[str, object]) -> str:
    return digest(receipt)


def verify_receipt_chain(receipts: Iterable[dict[str, object]]) -> None:
    previous: dict[str, object] | None = None
    ids: set[object] = set()
    idempotency_receipts: dict[object, object] = {}
    grant_id: object | None = None
    for receipt in receipts:
        receipt_id = receipt.get("id")
        if receipt_id in ids:
            raise ProtocolError("replay_detected", "receipt id appears more than once")
        if grant_id is None:
            grant_id = receipt.get("grant_id")
        elif receipt.get("grant_id") != grant_id:
            raise ProtocolError("receipt_chain_invalid", "receipt chain changed grant id")
        supersedes = receipt.get("supersedes_receipt_id")
        if supersedes is not None and supersedes not in ids:
            raise ProtocolError("receipt_chain_invalid", "correction must supersede an earlier receipt")
        idempotency_key = receipt.get("idempotency_key")
        prior_for_key = idempotency_receipts.get(idempotency_key)
        if prior_for_key is not None and supersedes != prior_for_key:
            raise ProtocolError("replay_detected", "idempotency key has more than one unsuperseded receipt")
        reservation_id = receipt.get("reservation_id")
        budget_commit_id = receipt.get("budget_commit_id")
        if (reservation_id is None) != (budget_commit_id is None):
            raise ProtocolError("receipt_chain_invalid", "reservation and budget commit must appear together")
        expected = None if previous is None else receipt_digest(previous)
        if receipt.get("previous_receipt_digest") != expected:
            raise ProtocolError("receipt_chain_invalid", "receipt chain digest does not match")
        ids.add(receipt_id)
        idempotency_receipts[idempotency_key] = receipt_id
        previous = receipt
