from __future__ import annotations

import copy
import unittest

from pcp_reference import ProtocolError
from pcp_reference.proof import (
    AUTHORITY_DENIALS,
    PROOF_DENIALS,
    build_protected,
    decode_compact,
    derive_legatus_authority,
    legatus_idempotency_key,
    legatus_disposition,
    sign_compact,
    signing_object,
    verify_compact,
    verify_request,
)
from pcp_reference.receipt import receipt_digest, sign_record, verify_receipt_chain, verify_record

from tests.common import (
    DIGEST_A,
    DIGEST_B,
    GRANT_ID,
    KEY_ID,
    NOW,
    PRINCIPAL_ID,
    legatus_envelope,
    private_key,
)

LEGATUS_IDEMPOTENCY_KEY = legatus_idempotency_key("thread-1", "env-1")


class DetachedProofTests(unittest.TestCase):
    def signed_envelope(self):
        envelope = legatus_envelope()
        protected = build_protected(
            envelope,
            key_id=KEY_ID,
            grant_id=GRANT_ID,
        )
        envelope["sig"] = sign_compact(envelope, protected, private_key())
        return envelope, protected

    def test_proof_round_trip_binds_exact_six_field_object(self):
        envelope, expected = self.signed_envelope()
        actual = verify_compact(
            envelope,
            private_key().public_key(),
            expected_signer=PRINCIPAL_ID,
            expected_purpose="legatus.delegate",
            expected_key_id=KEY_ID,
        )
        decoded, signature = decode_compact(envelope["sig"])
        self.assertEqual(expected, actual)
        self.assertEqual(expected, decoded)
        self.assertEqual(64, len(signature))
        signed = signing_object(expected, envelope)
        self.assertEqual(
            {"context", "signer_id", "key_id", "grant_id", "purpose", "envelope"},
            set(signed),
        )
        self.assertNotIn("sig", signed["envelope"])
        self.assertNotIn("audience", signed)
        self.assertNotIn("idempotency_key", signed)
        self.assertNotIn("spend", signed)
        derived = derive_legatus_authority(envelope, expected)
        self.assertEqual(
            "legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38",
            derived["idempotency_key"],
        )
        self.assertEqual(
            "legatus:sha256:8f1c8bf256a489d8b9a05375c45e7ac63838286790680c418e82ce8a94c14c5c",
            legatus_idempotency_key("a:b", "c"),
        )
        self.assertEqual(
            "legatus:sha256:4aebc886d9c6ada7592289f28e3b5c1ed7ae6e1878b5e0c9da82e4ca693422d5",
            legatus_idempotency_key("a", "b:c"),
        )
        self.assertNotEqual(
            legatus_idempotency_key("a:b", "c"),
            legatus_idempotency_key("a", "b:c"),
        )
        self.assertEqual([{"unit": "actions", "amount": 1}], derived["spend"])
        self.assertNotEqual(derived["envelope_digest"], derived["request_digest"])
        changed_grant = copy.deepcopy(expected)
        changed_grant["grant_id"] = "urn:pcp:grant:other"
        self.assertNotEqual(
            derived["request_digest"],
            derive_legatus_authority(envelope, changed_grant)["request_digest"],
        )

    def test_envelope_tamper_fails_binding(self):
        envelope, _ = self.signed_envelope()
        envelope["payload"]["task_ref"] = "tampered"
        with self.assertRaises(ProtocolError) as caught:
            verify_compact(envelope, private_key().public_key())
        self.assertEqual("bad_signature", caught.exception.code)

    def test_signature_and_authority_errors_have_separate_lanes(self):
        self.assertEqual(
            {
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
            },
            PROOF_DENIALS,
        )
        self.assertEqual(
            {
                "grant_not_found",
                "expired",
                "revoked",
                "scope_mismatch",
                "budget_exhausted",
                "unavailable",
            },
            AUTHORITY_DENIALS,
        )
        self.assertEqual(("deny", "LEGATUS_E_SIG"), legatus_disposition("bad_signature"))
        self.assertEqual(("deny", None), legatus_disposition("expired"))
        self.assertEqual(("retry", None), legatus_disposition("unavailable"))

    def test_request_proof_copy_must_match_compact_signature(self):
        envelope, protected = self.signed_envelope()
        _, raw_signature = decode_compact(envelope["sig"])
        request = {
            "profile": "pcp-legatus-v1",
            "signer_id": PRINCIPAL_ID,
            "purpose": "legatus.delegate",
            "envelope": envelope,
            "proof": envelope["sig"],
        }
        self.assertEqual(
            protected,
            verify_request(request, private_key().public_key(), expected_key_id=KEY_ID),
        )
        request["proof"] = envelope["sig"][:-1] + ("A" if envelope["sig"][-1] != "A" else "B")
        with self.assertRaises(ProtocolError) as caught:
            verify_request(request, private_key().public_key())
        self.assertEqual("proof_envelope_mismatch", caught.exception.code)
        self.assertEqual(64, len(raw_signature))

    def test_invalid_proof_family_maps_to_legatus_signature_lane(self):
        envelope, _ = self.signed_envelope()
        request = {
            "profile": "pcp-legatus-v1",
            "signer_id": PRINCIPAL_ID,
            "purpose": "legatus.delegate",
            "envelope": envelope,
            "proof": envelope["sig"],
        }
        variants = []

        malformed = copy.deepcopy(request)
        malformed["proof"] = malformed["envelope"]["sig"] = "bad"
        variants.append((malformed, {}, "invalid_proof"))

        wrong_signer = copy.deepcopy(request)
        wrong_signer["signer_id"] = "urn:pcp:principal:bob"
        variants.append((wrong_signer, {}, "proof_signer_mismatch"))

        wrong_purpose = copy.deepcopy(request)
        wrong_purpose["purpose"] = "legatus.handoff"
        variants.append((wrong_purpose, {}, "proof_purpose_mismatch"))

        variants.append((copy.deepcopy(request), {"expected_key_id": "urn:pcp:key:other"}, "proof_key_mismatch"))

        for candidate, kwargs, code in variants:
            with self.subTest(code=code):
                with self.assertRaises(ProtocolError) as caught:
                    verify_request(candidate, private_key().public_key(), **kwargs)
                self.assertEqual(code, caught.exception.code)
                self.assertEqual(("deny", "LEGATUS_E_SIG"), legatus_disposition(code))


class ReceiptTests(unittest.TestCase):
    def receipt(
        self,
        receipt_id: str,
        previous: str | None,
        idempotency_key: str = LEGATUS_IDEMPOTENCY_KEY,
    ) -> dict[str, object]:
        return {
            "spec_version": "pcp/0.1",
            "type": "pcp_receipt",
            "id": receipt_id,
            "issuer_id": PRINCIPAL_ID,
            "grant_id": GRANT_ID,
            "subject_id": PRINCIPAL_ID,
            "action_id": idempotency_key,
            "idempotency_key": idempotency_key,
            "request_digest": DIGEST_A,
            "result_digest": DIGEST_B,
            "outcome": "succeeded",
            "reservation_id": "urn:pcp:reservation:reservation-1",
            "budget_commit_id": "urn:pcp:commit:commit-1",
            "evidence_refs": [
                {"system": "legatus", "id": "env-1", "digest": DIGEST_A}
            ],
            "occurred_at": NOW,
            "previous_receipt_digest": previous,
            "supersedes_receipt_id": None,
        }

    def test_signed_hash_chain_verifies(self):
        first = sign_record(self.receipt("urn:pcp:receipt:first", None), KEY_ID, private_key())
        second = sign_record(
            self.receipt(
                "urn:pcp:receipt:second",
                receipt_digest(first),
                legatus_idempotency_key("thread-1", "env-2"),
            ),
            KEY_ID,
            private_key(),
        )
        verify_record(first, private_key().public_key())
        verify_record(second, private_key().public_key())
        verify_receipt_chain([first, second])
        malformed_signature = copy.deepcopy(first)
        malformed_signature["signature"]["value"] = "!"
        with self.assertRaises(ProtocolError) as caught:
            verify_record(malformed_signature, private_key().public_key())
        self.assertEqual("bad_signature", caught.exception.code)

    def test_tampered_chain_fails(self):
        first = sign_record(self.receipt("urn:pcp:receipt:first", None), KEY_ID, private_key())
        second = sign_record(
            self.receipt(
                "urn:pcp:receipt:second",
                DIGEST_A,
                legatus_idempotency_key("thread-1", "env-2"),
            ),
            KEY_ID,
            private_key(),
        )
        with self.assertRaises(ProtocolError) as caught:
            verify_receipt_chain([first, second])
        self.assertEqual("receipt_chain_invalid", caught.exception.code)

    def test_duplicate_receipt_is_replay(self):
        first = sign_record(self.receipt("urn:pcp:receipt:first", None), KEY_ID, private_key())
        with self.assertRaises(ProtocolError) as caught:
            verify_receipt_chain([first, copy.deepcopy(first)])
        self.assertEqual("replay_detected", caught.exception.code)

    def test_correction_must_reference_an_earlier_receipt(self):
        first = sign_record(self.receipt("urn:pcp:receipt:first", None), KEY_ID, private_key())
        correction_body = self.receipt("urn:pcp:receipt:correction", receipt_digest(first))
        correction_body["supersedes_receipt_id"] = "urn:pcp:receipt:missing"
        correction = sign_record(correction_body, KEY_ID, private_key())
        with self.assertRaises(ProtocolError) as caught:
            verify_receipt_chain([first, correction])
        self.assertEqual("receipt_chain_invalid", caught.exception.code)


if __name__ == "__main__":
    unittest.main()
