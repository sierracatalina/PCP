from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from pcp_reference import ProtocolError
from pcp_reference.bindings import validate_aaa_binding, validate_context_binding
from pcp_reference.canonical import digest, loads_no_duplicates
from pcp_reference.proof import (
    AUTHORITY_DENIALS,
    PROOF_DENIALS,
    build_protected,
    derive_legatus_authority,
    legatus_idempotency_key,
    sign_compact,
    validate_legatus_finalization,
)
from pcp_reference.validation import require_identity_kind, require_unique_budget_units, schema_error_code

from tests.common import (
    DIGEST_A,
    GRANT_ID,
    KEY_ID,
    LATER,
    NOW,
    PRINCIPAL_ID,
    grant,
    legatus_envelope,
    private_key,
    signature,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "schemas"
AAA_FIXTURE_DIR = ROOT / "tests" / "fixtures" / "aaa"


def load(name: str):
    return json.loads((SCHEMA_DIR / name).read_text(encoding="utf-8"))


def load_aaa(name: str):
    return json.loads((AAA_FIXTURE_DIR / name).read_text(encoding="utf-8"))


def validator(schema):
    return Draft202012Validator(schema, format_checker=FormatChecker())


class SchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.core = load("pcp.schema.json")

    def core_definition(self, name: str):
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$defs": self.core["$defs"],
            "$ref": f"#/$defs/{name}",
        }

    def assert_valid(self, schema, instance):
        errors = sorted(validator(schema).iter_errors(instance), key=lambda error: list(error.path))
        self.assertEqual([], errors, "\n".join(error.message for error in errors))

    def test_every_schema_is_valid_draft_2020_12(self):
        for path in sorted(SCHEMA_DIR.glob("*.json")):
            with self.subTest(path=path.name):
                Draft202012Validator.check_schema(json.loads(path.read_text(encoding="utf-8")))

    def test_grant_validates_and_unknown_property_has_stable_code(self):
        schema = self.core_definition("grant")
        self.assert_valid(schema, grant())
        invalid = grant()
        invalid["surprise"] = True
        error = next(validator(schema).iter_errors(invalid))
        self.assertEqual("unknown_property", schema_error_code(error))
        with self.assertRaises(ProtocolError) as duplicate:
            loads_no_duplicates(b'{"type":"pcp_grant","type":"other"}')
        self.assertEqual("duplicate_property", duplicate.exception.code)

    def test_identity_kind_and_budget_units_are_semantic_invariants(self):
        with self.assertRaises(ProtocolError) as kind_error:
            require_identity_kind("urn:pcp:device:d1", "agent")
        self.assertEqual("identity_collapse", kind_error.exception.code)
        with self.assertRaises(ProtocolError) as budget_error:
            require_unique_budget_units([
                {"unit": "actions", "limit": 1},
                {"unit": "actions", "limit": 2},
            ])
        self.assertEqual("malformed", budget_error.exception.code)

    def test_budget_command_shapes(self):
        schema = load("pcp-budget-command.schema.json")
        reserve = {
            "spec_version": "pcp/0.1",
            "type": "pcp_budget_reserve_request",
            "id": "urn:pcp:request:reserve-1",
            "grant_id": GRANT_ID,
            "subject_id": PRINCIPAL_ID,
            "purpose": "legatus.delegate",
            "audience": "urn:pcp:audience:legatus:test",
            "action_id": legatus_idempotency_key("thread-1", "env-1"),
            "idempotency_key": legatus_idempotency_key("thread-1", "env-1"),
            "request_digest": DIGEST_A,
            "spend": [{"unit": "actions", "amount": 1}],
            "observed_at": NOW,
            "reservation_expires_at": LATER,
        }
        self.assert_valid(schema, reserve)

    def test_legatus_request_and_allow_result_validate(self):
        request_schema = load("pcp-verifier-request.schema.json")
        self.assertEqual(
            {"profile", "signer_id", "purpose", "envelope", "proof"},
            set(request_schema["properties"]),
        )
        envelope = legatus_envelope()
        protected = build_protected(
            envelope,
            key_id=KEY_ID,
            grant_id=GRANT_ID,
        )
        envelope["sig"] = sign_compact(envelope, protected, private_key())
        request = {
            "profile": "pcp-legatus-v1",
            "signer_id": PRINCIPAL_ID,
            "purpose": "legatus.delegate",
            "envelope": envelope,
            "proof": envelope["sig"],
        }
        self.assert_valid(request_schema, request)
        result = {
            "profile": "pcp-legatus-v1",
            "status": "allow",
            "authorization_id": "urn:pcp:reservation:reservation-1",
        }
        self.assert_valid(load("pcp-verifier-result.schema.json"), result)
        proof_denial = {
            "profile": "pcp-legatus-v1",
            "status": "deny",
            "code": "bad_signature",
            "retriable": False,
        }
        unavailable = {
            "profile": "pcp-legatus-v1",
            "status": "deny",
            "code": "unavailable",
            "retriable": True,
        }
        result_schema = load("pcp-verifier-result.schema.json")
        denial_codes = set(result_schema["oneOf"][1]["properties"]["code"]["enum"])
        self.assertEqual(PROOF_DENIALS | AUTHORITY_DENIALS, denial_codes)
        self.assert_valid(result_schema, proof_denial)
        self.assert_valid(result_schema, unavailable)
        proof_denial["retriable"] = True
        self.assertTrue(list(validator(result_schema).iter_errors(proof_denial)))
        derived = derive_legatus_authority(envelope, protected)
        self.assertEqual(
            "legatus:sha256:38f95fbdb73b248fa82ccd3f9a91a7c5d6cf0d93edf1016b1b6ba060a3fa5c38",
            derived["idempotency_key"],
        )

        authority = {
            "legatus": 0,
            "kind": "pcp_result",
            "status": "deny",
            "code": "expired",
            "retriable": False,
            "envelope_id": "env-1",
            "thread": "thread-1",
        }
        self.assert_valid(load("pcp-result.schema.json"), authority)

    def test_legatus_finalization_distinguishes_commit_and_release(self):
        request_schema = load("pcp-finalize-request.schema.json")
        result_schema = load("pcp-finalize-result.schema.json")
        self.assertEqual(
            {"profile", "authorization_id", "outcome", "envelope_id", "thread", "journal_position"},
            set(request_schema["properties"]),
        )
        self.assertEqual(
            {"profile", "status", "authorization_id", "outcome"},
            set(result_schema["properties"]),
        )
        commit = {
            "profile": "pcp-legatus-v1",
            "authorization_id": "urn:pcp:reservation:reservation-1",
            "outcome": "commit",
            "envelope_id": "env-1",
            "thread": "thread-1",
            "journal_position": 7,
        }
        release = copy.deepcopy(commit)
        release["outcome"] = "release"
        release["journal_position"] = None
        result = {
            "profile": "pcp-legatus-v1",
            "status": "finalized",
            "authorization_id": commit["authorization_id"],
            "outcome": "commit",
        }
        self.assert_valid(request_schema, commit)
        self.assert_valid(request_schema, release)
        self.assert_valid(result_schema, result)
        reservation = {
            "id": commit["authorization_id"],
            "thread": "thread-1",
            "envelope_id": "env-1",
            "idempotency_key": legatus_idempotency_key("thread-1", "env-1"),
        }
        self.assertEqual("commit", validate_legatus_finalization(commit, reservation))
        self.assertEqual("release", validate_legatus_finalization(release, reservation))
        wrong_envelope = copy.deepcopy(commit)
        wrong_envelope["envelope_id"] = "env-2"
        with self.assertRaises(ProtocolError) as mismatch:
            validate_legatus_finalization(wrong_envelope, reservation)
        self.assertEqual("grant_binding_mismatch", mismatch.exception.code)
        release["journal_position"] = 7
        self.assertTrue(list(validator(request_schema).iter_errors(release)))

    def test_context_and_aaa_bindings_validate(self):
        context_request = {
            "id": "urn:context-layer:request:request-1",
            "requester": {"principal": PRINCIPAL_ID},
            "recipient": {"principal": "urn:context-layer:recipient:recipient-1"},
            "purpose_code": "draft.response",
            "requested_actions": ["read.claims"],
            "expires_at": LATER,
        }
        context = {
            "spec_version": "pcp/0.1",
            "type": "pcp_context_authorization",
            "id": "urn:pcp:binding:context-1",
            "issuer_id": PRINCIPAL_ID,
            "grant_id": GRANT_ID,
            "subject_id": PRINCIPAL_ID,
            "requester_principal_id": PRINCIPAL_ID,
            "context_request_id": "urn:context-layer:request:request-1",
            "context_request_digest": digest(context_request),
            "recipient_id": "urn:context-layer:recipient:recipient-1",
            "purpose_code": "draft.response",
            "requested_actions": ["read.claims"],
            "audience": "urn:context-layer:policy:test",
            "issued_at": NOW,
            "expires_at": LATER,
            "signature": signature(),
        }
        self.assert_valid(load("pcp-context-authorization.schema.json"), context)
        context_grant = grant()
        context_grant["purpose"] = "draft.response"
        context_grant["audience"] = "urn:context-layer:policy:test"
        context_grant["scope"] = {
            "actions": ["read.claims"],
            "resources": ["urn:context-layer:recipient:recipient-1"],
        }
        self.assert_valid(self.core_definition("grant"), context_grant)
        validate_context_binding(context, context_request, context_grant)
        changed_context_grant = copy.deepcopy(context_grant)
        changed_context_grant["audience"] = "urn:context-layer:policy:other"
        with self.assertRaises(ProtocolError) as context_denied:
            validate_context_binding(context, context_request, changed_context_grant)
        self.assertEqual("grant_binding_mismatch", context_denied.exception.code)
        agents_document = load_aaa("agents.json")
        instructions_document = load_aaa("ai-instructions.json")
        self.assert_valid(load_aaa("agents.schema.json"), agents_document)
        self.assert_valid(load_aaa("ai-instructions.schema.json"), instructions_document)
        aaa_grant = grant()
        aaa_grant["audience"] = "https://example.test"
        aaa_grant["purpose"] = "settings.update"
        aaa_grant["scope"] = {
            "actions": ["settings.save"],
            "resources": ["https://example.test/settings/save"],
        }
        self.assert_valid(self.core_definition("grant"), aaa_grant)
        aaa = {
            "spec_version": "pcp/0.1",
            "type": "pcp_aaa_action_binding",
            "id": "urn:pcp:binding:aaa-1",
            "issuer_id": PRINCIPAL_ID,
            "grant_id": GRANT_ID,
            "subject_id": PRINCIPAL_ID,
            "origin": "https://example.test",
            "discovery_url": "https://example.test/.well-known/agents.json",
            "discovery_document_digest": digest(agents_document),
            "instructions_url": "https://example.test/.well-known/ai-instructions.json",
            "instructions_document_digest": digest(instructions_document),
            "action_id": "settings.save",
            "endpoint": "/settings/save",
            "method": "POST",
            "audience": "https://example.test",
            "purpose": "settings.update",
            "scope_action": "settings.save",
            "human_confirmation_required": True,
            "confirmation_receipt_id": "urn:pcp:receipt:confirmation-1",
            "issued_at": NOW,
            "expires_at": LATER,
            "signature": signature(),
        }
        schema = load("pcp-aaa-action-binding.schema.json")
        self.assert_valid(schema, aaa)
        validate_aaa_binding(aaa, agents_document, instructions_document, aaa_grant)
        missing_confirmation = copy.deepcopy(aaa)
        missing_confirmation["confirmation_receipt_id"] = None
        self.assertTrue(list(validator(schema).iter_errors(missing_confirmation)))
        changed_agents = copy.deepcopy(agents_document)
        changed_agents["endpoints"][0]["path"] = "/settings/new-save"
        with self.assertRaises(ProtocolError) as drift:
            validate_aaa_binding(aaa, changed_agents, instructions_document, aaa_grant)
        self.assertEqual("grant_binding_mismatch", drift.exception.code)

        mutations = [
            ("discovery_url", "https://other.test/.well-known/agents.json"),
            ("instructions_url", "https://other.test/.well-known/ai-instructions.json"),
            ("audience", "https://other.test"),
            ("scope_action", "settings.other"),
            ("expires_at", "2026-09-15T14:00:00Z"),
        ]
        for field, value in mutations:
            with self.subTest(field=field):
                changed = copy.deepcopy(aaa)
                changed[field] = value
                with self.assertRaises(ProtocolError) as denied:
                    validate_aaa_binding(changed, agents_document, instructions_document, aaa_grant)
                self.assertEqual("grant_binding_mismatch", denied.exception.code)

        inactive_agents = copy.deepcopy(agents_document)
        inactive_agents["live"] = False
        inactive = copy.deepcopy(aaa)
        inactive["discovery_document_digest"] = digest(inactive_agents)
        with self.assertRaises(ProtocolError) as denied:
            validate_aaa_binding(inactive, inactive_agents, instructions_document, aaa_grant)
        self.assertEqual("grant_binding_mismatch", denied.exception.code)


if __name__ == "__main__":
    unittest.main()
