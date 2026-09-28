from __future__ import annotations

import copy
import unittest
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcp_reference import ProtocolError
from pcp_reference.canonical import canonical_bytes
from pcp_reference.receipt import sign_record, verify_record
from pcp_reference.validation import (
    CONTEXT_LAYER_AUTHORITY_TYPES,
    ERROR_PRECEDENCE,
    PARSER_RECORD_TYPES,
    RECOVERY_AUTHORITY_TYPES,
    reject_host_as_issuer,
    reject_non_grant_authority,
    require_grant_window,
    require_published_signing_key,
    rotate_published_keys,
)

from tests.common import KEY_ID, LATER, NOW, grant, private_key


NEW_KEY_ID = "urn:pcp:key:alice-2"
RENEWED_EXPIRY = "2026-09-15T15:00:00Z"


def instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def second_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes(range(2, 34)))


def signed_grant(key_id: str = KEY_ID, **replacements: object) -> dict[str, object]:
    body = grant()
    body.pop("signature")
    body.update(replacements)
    signer = private_key() if key_id == KEY_ID else second_key()
    return sign_record(body, key_id, signer)


class AuthorityTests(unittest.TestCase):
    def test_non_grant_artifacts_are_not_authority(self):
        flat = [code for group in ERROR_PRECEDENCE for code in group]
        parser_at = flat.index("parser_record_forbidden")
        context_at = flat.index("cl_type_forbidden")
        recovery_at = flat.index("recovery_is_not_a_grant")
        self.assertLess(flat.index("unknown_property"), parser_at)
        self.assertLess(parser_at, context_at)
        self.assertLess(context_at, recovery_at)
        self.assertLess(recovery_at, flat.index("unsupported_version"))
        self.assertLess(recovery_at, flat.index("unknown_type"))
        self.assertLess(recovery_at, flat.index("carrier_is_not_authority"))
        self.assertLess(flat.index("bad_signature"), flat.index("expired"))
        self.assertEqual("verification_unavailable", flat[-1])

        expected = {
            **{name: "parser_record_forbidden" for name in PARSER_RECORD_TYPES},
            **{name: "cl_type_forbidden" for name in CONTEXT_LAYER_AUTHORITY_TYPES},
            **{name: "recovery_is_not_a_grant" for name in RECOVERY_AUTHORITY_TYPES},
        }
        for artifact_type, code in expected.items():
            with self.subTest(artifact_type=artifact_type):
                presented = {"type": artifact_type, "id": "record-1", "session_id": "session-1"}
                with self.assertRaises(ProtocolError) as caught:
                    reject_non_grant_authority(presented)
                self.assertEqual(code, caught.exception.code)

        for artifact_type in ("pcp_grant", "pcp_receipt", "pcp_revocation", "pcp_aaa_action_binding", "context_request"):
            with self.subTest(artifact_type=artifact_type):
                reject_non_grant_authority({"type": artifact_type})
        reject_non_grant_authority(["memory_parser_record"])
        reject_non_grant_authority({"type": None})

    def test_host_role_is_not_an_issuer(self):
        for role in ("workspace", "chat_host", "agent_host"):
            with self.subTest(role=role):
                with self.assertRaises(ProtocolError) as caught:
                    reject_host_as_issuer(role)
                self.assertEqual("carrier_is_not_authority", caught.exception.code)
        for role in ("principal", "agent", "device"):
            with self.subTest(role=role):
                reject_host_as_issuer(role)

    def test_expired_grant_has_no_grace_or_implicit_renewal(self):
        issued = signed_grant()
        verify_record(issued, private_key().public_key())
        start = instant(NOW)
        expiry = instant(LATER)
        require_grant_window(issued, start)
        require_grant_window(issued, expiry - timedelta(seconds=1))
        with self.assertRaises(ProtocolError) as expired:
            require_grant_window(issued, expiry)
        self.assertEqual("expired", expired.exception.code)
        with self.assertRaises(ProtocolError) as too_early:
            require_grant_window(issued, start - timedelta(seconds=1))
        self.assertEqual("not_before", too_early.exception.code)
        open_start = signed_grant(not_before=None)
        verify_record(open_start, private_key().public_key())
        require_grant_window(open_start, start)
        with self.assertRaises(ProtocolError) as before_issue:
            require_grant_window(open_start, start - timedelta(seconds=1))
        self.assertEqual("not_before", before_issue.exception.code)

        mutated = copy.deepcopy(issued)
        mutated["expires_at"] = RENEWED_EXPIRY
        with self.assertRaises(ProtocolError) as unsigned_edit:
            verify_record(mutated, private_key().public_key())
        self.assertEqual("bad_signature", unsigned_edit.exception.code)
        self.assertEqual(canonical_bytes(issued), canonical_bytes(signed_grant()))

        reissued = signed_grant(id="urn:pcp:grant:grant-2", expires_at=RENEWED_EXPIRY)
        verify_record(reissued, private_key().public_key())
        with self.assertRaises(ProtocolError):
            require_grant_window(issued, expiry)
        require_grant_window(reissued, expiry)
        self.assertNotEqual(canonical_bytes(issued), canonical_bytes(reissued))

    def test_key_rotation_preserves_grant_bytes(self):
        issued = signed_grant()
        before = canonical_bytes(issued)
        published = rotate_published_keys([KEY_ID], NEW_KEY_ID)
        self.assertEqual([KEY_ID, NEW_KEY_ID], published)
        self.assertEqual(before, canonical_bytes(issued))
        require_published_signing_key(published, issued["signature"]["key_id"])

        with self.assertRaises(ProtocolError) as removed:
            require_published_signing_key([NEW_KEY_ID], KEY_ID)
        self.assertEqual("unknown_issuer", removed.exception.code)
        with self.assertRaises(ProtocolError) as malformed_key:
            require_published_signing_key(published, "not-a-key")
        self.assertEqual("malformed", malformed_key.exception.code)
        with self.assertRaises(ProtocolError) as malformed_rotation:
            rotate_published_keys(published, "not-a-key")
        self.assertEqual("malformed", malformed_rotation.exception.code)

        reissued = signed_grant(NEW_KEY_ID, id="urn:pcp:grant:grant-2")
        self.assertEqual(NEW_KEY_ID, reissued["signature"]["key_id"])
        self.assertEqual(before, canonical_bytes(issued))
        self.assertNotEqual(before, canonical_bytes(reissued))
        verify_record(reissued, second_key().public_key())
        require_published_signing_key(published, NEW_KEY_ID)
