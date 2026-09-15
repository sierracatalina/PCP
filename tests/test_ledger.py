from __future__ import annotations

import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

from pcp_reference import AuthorityLedger, ProtocolError

from tests.common import DIGEST_A, DIGEST_B, GRANT_ID


class LedgerTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 9, 15, 12, 0, tzinfo=timezone.utc)
        self.ledger = AuthorityLedger({GRANT_ID: {"actions": 1, "api_calls": 2}})

    def reserve(self, key: str = "idem-key-0001", digest: str = DIGEST_A):
        return self.ledger.reserve(
            grant_id=GRANT_ID,
            idempotency_key=key,
            request_digest=digest,
            spend={"actions": 1},
            now=self.now,
            expires_at=self.now + timedelta(minutes=5),
        )

    def test_identical_reserve_replay_returns_original(self):
        first = self.reserve()
        replay = self.reserve()
        self.assertEqual(first["id"], replay["id"])
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(1, self.ledger.revision)

    def test_idempotency_key_cannot_change_request(self):
        self.reserve()
        with self.assertRaisesRegex(ProtocolError, "different bytes") as caught:
            self.reserve(digest=DIGEST_B)
        self.assertEqual("idempotency_conflict", caught.exception.code)

    def test_concurrent_final_unit_has_one_winner(self):
        def attempt(index: int) -> str:
            try:
                self.reserve(key=f"idem-key-{index:04d}", digest="sha256:" + str(index) * 64)
                return "allowed"
            except ProtocolError as error:
                return error.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = sorted(pool.map(attempt, [1, 2]))
        self.assertEqual(["allowed", "budget_exhausted"], outcomes)
        self.assertEqual(0, self.ledger.available(GRANT_ID, "actions", now=self.now))

    def test_release_restores_budget_and_replay_is_stable(self):
        reservation = self.reserve()
        released = self.ledger.release(
            reservation_id=reservation["id"],
            idempotency_key="idem-key-0001",
            reason_code="action_rejected",
            now=self.now,
        )
        replay = self.ledger.release(
            reservation_id=reservation["id"],
            idempotency_key="idem-key-0001",
            reason_code="action_rejected",
            now=self.now,
        )
        self.assertEqual("released", released["state"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(1, self.ledger.available(GRANT_ID, "actions", now=self.now))

    def test_commit_is_terminal_and_idempotent(self):
        reservation = self.reserve()
        committed = self.ledger.commit(
            reservation_id=reservation["id"],
            idempotency_key="idem-key-0001",
            result_digest=DIGEST_B,
            receipt_id="urn:pcp:receipt:receipt-1",
            now=self.now,
        )
        replay = self.ledger.commit(
            reservation_id=reservation["id"],
            idempotency_key="idem-key-0001",
            result_digest=DIGEST_B,
            receipt_id="urn:pcp:receipt:receipt-1",
            now=self.now,
        )
        self.assertEqual("committed", committed["state"])
        self.assertTrue(replay["replayed"])
        with self.assertRaises(ProtocolError) as caught:
            self.ledger.release(
                reservation_id=reservation["id"],
                idempotency_key="idem-key-0001",
                reason_code="request_cancelled",
                now=self.now,
            )
        self.assertEqual("reservation_not_live", caught.exception.code)

    def test_expiry_emits_release_and_requires_new_key(self):
        reservation = self.reserve()
        after_expiry = self.now + timedelta(minutes=6)
        self.assertEqual(1, self.ledger.available(GRANT_ID, "actions", now=after_expiry))
        with self.assertRaises(ProtocolError) as caught:
            self.ledger.commit(
                reservation_id=reservation["id"],
                idempotency_key="idem-key-0001",
                result_digest=DIGEST_B,
                receipt_id="urn:pcp:receipt:late",
                now=after_expiry,
            )
        self.assertEqual("reservation_not_live", caught.exception.code)
        self.assertEqual("pcp_budget_release", self.ledger.events()[-1]["type"])

    def test_revocation_linearizes_with_reserve_and_blocks_execution(self):
        ledger = AuthorityLedger(
            {GRANT_ID: {"actions": 1}},
            families={GRANT_ID: "urn:pcp:family:family-1"},
        )
        reservation = ledger.reserve(
            grant_id=GRANT_ID,
            idempotency_key="idem-key-revocation",
            request_digest=DIGEST_A,
            spend={"actions": 1},
            now=self.now,
            expires_at=self.now + timedelta(minutes=5),
        )
        ledger.revoke(family_id="urn:pcp:family:family-1", now=self.now)
        with self.assertRaises(ProtocolError) as caught:
            ledger.authorize_execution(reservation["id"], now=self.now)
        self.assertEqual("revoked", caught.exception.code)
        self.assertEqual(1, ledger.available(GRANT_ID, "actions", now=self.now))
        with self.assertRaises(ProtocolError) as future:
            ledger.reserve(
                grant_id=GRANT_ID,
                idempotency_key="idem-key-after-revoke",
                request_digest=DIGEST_B,
                spend={"actions": 1},
                now=self.now,
                expires_at=self.now + timedelta(minutes=5),
            )
        self.assertEqual("revoked", future.exception.code)


if __name__ == "__main__":
    unittest.main()
