from __future__ import annotations

from datetime import datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

from .canonical import digest
from .errors import ProtocolError


def _deny(message: str) -> None:
    raise ProtocolError("grant_binding_mismatch", message)


def _instant(value: Any, label: str) -> datetime:
    if not isinstance(value, str):
        raise ProtocolError("malformed", f"{label} must be RFC 3339")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ProtocolError("malformed", f"{label} must be RFC 3339") from exc
    if parsed.tzinfo is None:
        raise ProtocolError("malformed", f"{label} must include a timezone")
    return parsed


def _https_origin(value: Any, label: str, *, origin_only: bool = False) -> str:
    if not isinstance(value, str):
        _deny(f"{label} must be an HTTPS URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ProtocolError("grant_binding_mismatch", f"{label} is malformed") from exc
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or "*" in parsed.hostname
        or any(character.isspace() for character in parsed.netloc)
    ):
        _deny(f"{label} must be an HTTPS URL without user information")
    if parsed.fragment:
        _deny(f"{label} must not contain a fragment")
    if origin_only and (parsed.path not in {"", "/"} or parsed.query):
        _deny(f"{label} must contain only an origin")
    host = parsed.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    authority = host if port in {None, 443} else f"{host}:{port}"
    return f"https://{authority}"


def _resolve_from_origin(origin: str, declared: Any, label: str) -> str:
    if not isinstance(declared, str) or not declared:
        _deny(f"AAA {label} is missing")
    absolute = urljoin(origin + "/", declared)
    if _https_origin(absolute, f"AAA {label}") != origin:
        _deny(f"AAA {label} leaves the declared origin")
    return absolute


def validate_context_binding(
    binding: dict[str, Any],
    request: dict[str, Any],
    grant: dict[str, Any],
) -> None:
    requester = request.get("requester")
    recipient = request.get("recipient")
    if not isinstance(requester, dict) or not isinstance(recipient, dict):
        _deny("Context Layer request has no requester or recipient")
    comparisons = {
        "context request id": (binding.get("context_request_id"), request.get("id")),
        "context request digest": (binding.get("context_request_digest"), digest(request)),
        "requester principal": (binding.get("requester_principal_id"), requester.get("principal")),
        "recipient": (binding.get("recipient_id"), recipient.get("principal")),
        "purpose code": (binding.get("purpose_code"), request.get("purpose_code")),
        "requested actions": (binding.get("requested_actions"), request.get("requested_actions")),
    }
    for label, (actual, expected) in comparisons.items():
        if actual != expected:
            _deny(f"{label} does not match the bound Context Layer request")
    grant_comparisons = {
        "grant id": (binding.get("grant_id"), grant.get("id")),
        "grant issuer": (binding.get("issuer_id"), grant.get("issuer_id")),
        "grant subject": (binding.get("subject_id"), grant.get("subject_id")),
        "grant purpose": (binding.get("purpose_code"), grant.get("purpose")),
        "grant audience": (binding.get("audience"), grant.get("audience")),
    }
    for label, (actual, expected) in grant_comparisons.items():
        if actual != expected:
            _deny(f"Context Layer {label} binding differs from the grant")
    scope = grant.get("scope")
    requested_actions = binding.get("requested_actions")
    if not isinstance(scope, dict) or not isinstance(requested_actions, list):
        _deny("Context Layer grant scope or requested actions are malformed")
    allowed_actions = scope.get("actions")
    if (
        not isinstance(allowed_actions, list)
        or any(not isinstance(item, str) for item in allowed_actions + requested_actions)
        or not set(requested_actions).issubset(allowed_actions)
    ):
        _deny("Context Layer requested actions exceed the grant scope")
    binding_issued = _instant(binding.get("issued_at"), "binding issue time")
    binding_expiry = _instant(binding.get("expires_at"), "binding expiry")
    request_expiry = _instant(request.get("expires_at"), "request expiry")
    if binding_expiry > request_expiry:
        _deny("PCP binding outlives the Context Layer request")
    grant_start = _instant(grant.get("not_before") or grant.get("issued_at"), "grant start")
    grant_expiry = _instant(grant.get("expires_at"), "grant expiry")
    if binding_issued < grant_start or binding_expiry > grant_expiry or binding_expiry <= binding_issued:
        _deny("Context Layer binding falls outside the grant authorization window")


def validate_aaa_binding(
    binding: dict[str, Any],
    agents_document: dict[str, Any],
    instructions_document: dict[str, Any],
    grant: dict[str, Any],
) -> None:
    """Validate one PCP binding against complete AAA documents and its grant."""

    origin = _https_origin(binding.get("origin"), "AAA origin", origin_only=True)
    if binding.get("origin") != origin:
        _deny("AAA origin must use its normalized HTTPS form")
    if binding.get("audience") != origin:
        _deny("AAA audience must equal the declared origin")

    discovery_url = binding.get("discovery_url")
    instructions_url = binding.get("instructions_url")
    if _https_origin(discovery_url, "AAA discovery URL") != origin:
        _deny("AAA discovery URL leaves the declared origin")
    if _https_origin(instructions_url, "AAA instructions URL") != origin:
        _deny("AAA instructions URL leaves the declared origin")

    if binding.get("discovery_document_digest") != digest(agents_document):
        _deny("AAA discovery document digest changed")
    if binding.get("instructions_document_digest") != digest(instructions_document):
        _deny("AAA instructions document digest changed")

    for label, document in (("agents", agents_document), ("instructions", instructions_document)):
        if document.get("status") != "active" or document.get("live") is not True:
            _deny(f"AAA {label} document must be active and live")
        if document.get("http_action_api") != "declared":
            _deny(f"AAA {label} document must declare the HTTP action API")

    agent_card = agents_document.get("agent_card")
    instructions_discovery = instructions_document.get("discovery")
    if not isinstance(agent_card, dict) or not isinstance(agent_card.get("endpoints"), dict):
        _deny("AAA agent card has no declared discovery endpoint")
    if not isinstance(instructions_discovery, dict):
        _deny("AAA instructions have no discovery object")
    declared_instructions = _resolve_from_origin(
        origin,
        agent_card["endpoints"].get("discovery"),
        "instructions endpoint",
    )
    declared_agents = _resolve_from_origin(
        origin,
        instructions_discovery.get("actions"),
        "actions endpoint",
    )
    if declared_instructions != instructions_url or declared_agents != discovery_url:
        _deny("AAA document links do not match the bound URLs")

    actions = agents_document.get("endpoints")
    if not isinstance(actions, list):
        _deny("AAA document has no declared HTTP actions")
    action = next(
        (item for item in actions if isinstance(item, dict) and item.get("name") == binding.get("action_id")),
        None,
    )
    if action is None:
        _deny("AAA action is absent from the bound document")
    if action.get("path") != binding.get("endpoint") or action.get("method") != binding.get("method"):
        _deny("AAA action endpoint or method changed")
    action_path = action.get("path")
    if isinstance(action_path, str) and action_path.startswith("https://"):
        if _https_origin(action_path, "AAA action endpoint") != origin:
            _deny("AAA action endpoint leaves the declared origin")
    if binding.get("scope_action") != binding.get("action_id"):
        _deny("PCP scope action must equal the AAA action id")

    if binding.get("grant_id") != grant.get("id"):
        _deny("AAA binding names a different grant")
    if binding.get("subject_id") != grant.get("subject_id"):
        _deny("AAA binding subject differs from the grant")
    if binding.get("audience") != grant.get("audience"):
        _deny("AAA binding audience differs from the grant")
    if binding.get("purpose") != grant.get("purpose"):
        _deny("AAA binding purpose differs from the grant")
    scope = grant.get("scope")
    grant_actions = scope.get("actions") if isinstance(scope, dict) else None
    if not isinstance(grant_actions, list) or binding.get("scope_action") not in grant_actions:
        _deny("AAA action is outside the grant scope")

    binding_issued = _instant(binding.get("issued_at"), "AAA binding issue time")
    binding_expiry = _instant(binding.get("expires_at"), "AAA binding expiry")
    grant_start = _instant(grant.get("not_before") or grant.get("issued_at"), "grant start")
    grant_expiry = _instant(grant.get("expires_at"), "grant expiry")
    if binding_issued < grant_start or binding_expiry > grant_expiry or binding_expiry <= binding_issued:
        _deny("AAA binding falls outside the grant authorization window")

    safety = instructions_document.get("safety")
    policy = instructions_document.get("policy", {})
    if not isinstance(safety, dict) or not isinstance(policy, dict):
        raise ProtocolError("malformed", "AAA instructions safety and policy must be objects")
    safety_confirmations = safety.get("require_human_confirmation_for", [])
    policy_confirmations = policy.get("require_human_approval_for", [])
    if not isinstance(safety_confirmations, list) or not isinstance(policy_confirmations, list):
        raise ProtocolError("malformed", "AAA confirmation rules must be arrays")
    if any(not isinstance(item, str) for item in safety_confirmations + policy_confirmations):
        raise ProtocolError("malformed", "AAA confirmation rule identifiers must be strings")
    confirmation_ids = set(safety_confirmations)
    confirmation_ids.update(policy_confirmations)
    required = binding.get("action_id") in confirmation_ids or binding.get("endpoint") in confirmation_ids
    if binding.get("human_confirmation_required") != required:
        _deny("AAA confirmation requirement does not match instructions")
    if required and not binding.get("confirmation_receipt_id"):
        _deny("AAA action requires a confirmation receipt")
