from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping

from .errors import ProtocolError


def _require_aware(value: datetime, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ProtocolError("malformed", f"{name} must include an offset")
    return value.astimezone(timezone.utc)


def _stable_id(kind: str, *parts: str) -> str:
    material = "\x00".join(parts).encode("utf-8")
    token = hashlib.sha256(material).hexdigest()[:32]
    return f"urn:pcp:{kind}:{token}"


@dataclass
class _Reservation:
    id: str
    grant_id: str
    idempotency_key: str
    request_digest: str
    spend: dict[str, int]
    created_at: datetime
    expires_at: datetime
    state: str = "reserved"
    result_digest: str | None = None
    receipt_id: str | None = None
    terminal_reason: str | None = None
    event_id: str | None = None

    def public(self, *, replayed: bool, revision: int) -> dict[str, object]:
        return {
            "id": self.id,
            "grant_id": self.grant_id,
            "idempotency_key": self.idempotency_key,
            "request_digest": self.request_digest,
            "spend": copy.deepcopy(self.spend),
            "created_at": self.created_at.isoformat().replace("+00:00", "Z"),
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "state": self.state,
            "result_digest": self.result_digest,
            "receipt_id": self.receipt_id,
            "terminal_reason": self.terminal_reason,
            "event_id": self.event_id,
            "replayed": replayed,
            "ledger_revision": revision,
        }


class AuthorityLedger:
    """Linearizable in-memory reference for budget transition semantics.

    A production ledger must place the same transaction under durable
    serialization by grant id. This class supplies deterministic behavior for
    protocol tests; process memory is not production durability.
    """

    def __init__(
        self,
        limits: Mapping[str, Mapping[str, int]],
        *,
        families: Mapping[str, str] | None = None,
    ):
        self._limits = {grant: dict(units) for grant, units in limits.items()}
        self._families = dict(families or {})
        self._lock = threading.RLock()
        self._revision = 0
        self._reservations: dict[str, _Reservation] = {}
        self._idempotency: dict[tuple[str, str], str] = {}
        self._events: list[dict[str, object]] = []
        self._revoked_grants: set[str] = set()
        self._revoked_families: set[str] = set()
        self._revocation_events: dict[tuple[str | None, str | None], dict[str, object]] = {}
        for grant_id, units in self._limits.items():
            if not grant_id.startswith("urn:pcp:grant:"):
                raise ProtocolError("malformed", "grant id must use the PCP grant URN")
            if not units or any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in units.values()):
                raise ProtocolError("malformed", "budget limits must be positive integers")
        if any(grant_id not in self._limits for grant_id in self._families):
            raise ProtocolError("malformed", "family mapping names an unknown grant")

    @property
    def revision(self) -> int:
        with self._lock:
            return self._revision

    def _advance(self, event: dict[str, object]) -> int:
        self._revision += 1
        event = copy.deepcopy(event)
        event["ledger_revision"] = self._revision
        self._events.append(event)
        return self._revision

    def _release_record_locked(self, reservation: _Reservation, reason_code: str, now: datetime) -> int:
        reservation.state = "released"
        reservation.terminal_reason = reason_code
        reservation.event_id = _stable_id("release", reservation.id, reason_code)
        return self._advance(
            {
                "type": "pcp_budget_release",
                "id": reservation.event_id,
                "reservation_id": reservation.id,
                "reason_code": reason_code,
                "released_at": now.isoformat().replace("+00:00", "Z"),
            }
        )

    def _release_expired_locked(self, now: datetime) -> None:
        for reservation in sorted(self._reservations.values(), key=lambda item: item.id):
            if reservation.state == "reserved" and now >= reservation.expires_at:
                self._release_record_locked(reservation, "reservation_expired", now)

    def _is_revoked_locked(self, grant_id: str) -> bool:
        family_id = self._families.get(grant_id)
        return grant_id in self._revoked_grants or (
            family_id is not None and family_id in self._revoked_families
        )

    def _charged_locked(self, grant_id: str, unit: str) -> int:
        return sum(
            reservation.spend.get(unit, 0)
            for reservation in self._reservations.values()
            if reservation.grant_id == grant_id and reservation.state in {"reserved", "committed"}
        )

    def reserve(
        self,
        *,
        grant_id: str,
        idempotency_key: str,
        request_digest: str,
        spend: Mapping[str, int],
        now: datetime,
        expires_at: datetime,
    ) -> dict[str, object]:
        now = _require_aware(now, "now")
        expires_at = _require_aware(expires_at, "expires_at")
        if expires_at <= now:
            raise ProtocolError("malformed", "reservation expiry must be after creation")
        normalized = dict(sorted(spend.items()))
        if not normalized or any(not isinstance(v, int) or isinstance(v, bool) or v < 1 for v in normalized.values()):
            raise ProtocolError("malformed", "spend amounts must be positive integers")

        with self._lock:
            self._release_expired_locked(now)
            if grant_id not in self._limits:
                raise ProtocolError("unknown_subject", "budget ledger does not know the grant")
            if self._is_revoked_locked(grant_id):
                raise ProtocolError("revoked", "grant or grant family is revoked")

            idempotency_slot = (grant_id, idempotency_key)
            existing_id = self._idempotency.get(idempotency_slot)
            if existing_id is not None:
                existing = self._reservations[existing_id]
                same_request = existing.request_digest == request_digest and existing.spend == normalized
                if not same_request:
                    raise ProtocolError("idempotency_conflict", "idempotency key was used for different bytes")
                if existing.state == "released":
                    raise ProtocolError("reservation_not_live", "the idempotent reservation is released")
                return existing.public(replayed=True, revision=self._revision)

            for unit, amount in normalized.items():
                limit = self._limits[grant_id].get(unit)
                if limit is None:
                    raise ProtocolError("scope_invalid", f"grant has no budget for unit {unit}")
                if self._charged_locked(grant_id, unit) + amount > limit:
                    raise ProtocolError("budget_exhausted", f"budget exhausted for unit {unit}")

            reservation_id = _stable_id("reservation", grant_id, idempotency_key)
            reservation = _Reservation(
                id=reservation_id,
                grant_id=grant_id,
                idempotency_key=idempotency_key,
                request_digest=request_digest,
                spend=normalized,
                created_at=now,
                expires_at=expires_at,
            )
            self._reservations[reservation_id] = reservation
            self._idempotency[idempotency_slot] = reservation_id
            revision = self._advance(
                {
                    "type": "pcp_budget_reservation",
                    "id": reservation.id,
                    "grant_id": grant_id,
                    "idempotency_key": idempotency_key,
                    "request_digest": request_digest,
                    "spend": copy.deepcopy(normalized),
                    "created_at": now.isoformat().replace("+00:00", "Z"),
                    "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
                }
            )
            return reservation.public(replayed=False, revision=revision)

    def commit(
        self,
        *,
        reservation_id: str,
        idempotency_key: str,
        result_digest: str,
        receipt_id: str,
        now: datetime,
    ) -> dict[str, object]:
        now = _require_aware(now, "now")
        with self._lock:
            self._release_expired_locked(now)
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                raise ProtocolError("reservation_not_live", "reservation does not exist")
            if reservation.idempotency_key != idempotency_key:
                raise ProtocolError("idempotency_conflict", "idempotency key does not match reservation")
            if reservation.state == "committed":
                if reservation.result_digest != result_digest or reservation.receipt_id != receipt_id:
                    raise ProtocolError("idempotency_conflict", "commit replay changed the result")
                return reservation.public(replayed=True, revision=self._revision)
            if reservation.state != "reserved":
                raise ProtocolError("reservation_not_live", "reservation cannot be committed")

            reservation.state = "committed"
            reservation.result_digest = result_digest
            reservation.receipt_id = receipt_id
            reservation.event_id = _stable_id("commit", reservation.id, result_digest, receipt_id)
            revision = self._advance(
                {
                    "type": "pcp_budget_commit",
                    "id": reservation.event_id,
                    "reservation_id": reservation.id,
                    "result_digest": result_digest,
                    "receipt_id": receipt_id,
                    "committed_at": now.isoformat().replace("+00:00", "Z"),
                }
            )
            return reservation.public(replayed=False, revision=revision)

    def release(
        self,
        *,
        reservation_id: str,
        idempotency_key: str,
        reason_code: str,
        now: datetime,
    ) -> dict[str, object]:
        now = _require_aware(now, "now")
        with self._lock:
            self._release_expired_locked(now)
            reservation = self._reservations.get(reservation_id)
            if reservation is None:
                raise ProtocolError("reservation_not_live", "reservation does not exist")
            if reservation.idempotency_key != idempotency_key:
                raise ProtocolError("idempotency_conflict", "idempotency key does not match reservation")
            if reservation.state == "released":
                if reservation.terminal_reason != reason_code:
                    raise ProtocolError("idempotency_conflict", "release replay changed the reason")
                return reservation.public(replayed=True, revision=self._revision)
            if reservation.state != "reserved":
                raise ProtocolError("reservation_not_live", "committed budget cannot be released")

            revision = self._release_record_locked(reservation, reason_code, now)
            return reservation.public(replayed=False, revision=revision)

    def revoke(
        self,
        *,
        grant_id: str | None = None,
        family_id: str | None = None,
        now: datetime,
    ) -> dict[str, object]:
        now = _require_aware(now, "now")
        if grant_id is None and family_id is None:
            raise ProtocolError("malformed", "revocation must name a grant or family")
        key = (grant_id, family_id)
        with self._lock:
            existing = self._revocation_events.get(key)
            if existing is not None:
                result = copy.deepcopy(existing)
                result["replayed"] = True
                result["ledger_revision"] = self._revision
                return result
            if grant_id is not None:
                self._revoked_grants.add(grant_id)
            if family_id is not None:
                self._revoked_families.add(family_id)
            event = {
                "type": "pcp_revocation",
                "id": _stable_id("revocation", grant_id or "", family_id or ""),
                "grant_id": grant_id,
                "family_id": family_id,
                "effective_at": now.isoformat().replace("+00:00", "Z"),
                "replayed": False,
            }
            revision = self._advance(event)
            event["ledger_revision"] = revision
            self._revocation_events[key] = copy.deepcopy(event)
            return event

    def authorize_execution(self, reservation_id: str, *, now: datetime) -> dict[str, object]:
        now = _require_aware(now, "now")
        with self._lock:
            self._release_expired_locked(now)
            reservation = self._reservations.get(reservation_id)
            if reservation is None or reservation.state != "reserved":
                raise ProtocolError("reservation_not_live", "reservation cannot authorize execution")
            if self._is_revoked_locked(reservation.grant_id):
                self._release_record_locked(reservation, "grant_revoked", now)
                raise ProtocolError("revoked", "grant was revoked before execution")
            return reservation.public(replayed=True, revision=self._revision)

    def available(self, grant_id: str, unit: str, *, now: datetime) -> int:
        now = _require_aware(now, "now")
        with self._lock:
            self._release_expired_locked(now)
            if grant_id not in self._limits or unit not in self._limits[grant_id]:
                raise ProtocolError("scope_invalid", "unknown budget unit")
            return self._limits[grant_id][unit] - self._charged_locked(grant_id, unit)

    def events(self) -> list[dict[str, object]]:
        with self._lock:
            return copy.deepcopy(self._events)
