from __future__ import annotations

import unittest
from datetime import UTC, datetime, timedelta

from app.services.remediation import RemediationService


class FakeRepository:
    def __init__(self) -> None:
        self.item = {"case_id": "case-1", "version": 3, "status": "open"}
        self.updates = []

    def update(self, case_id, changes, *, expected_version, comment):
        self.updates.append((case_id, changes, expected_version, comment))
        self.item = {**self.item, **changes, "version": expected_version + 1}
        return self.item

    def get(self, case_id):
        return self.item if case_id == "case-1" else None

    def asset_ids(self):
        return []


class RemediationServiceTests(unittest.TestCase):
    def setUp(self):
        self.repository = FakeRepository()
        self.service = RemediationService(self.repository, stale_days=7)  # type: ignore[arg-type]

    def test_resolved_status_requires_scan_evidence(self):
        with self.assertRaisesRegex(ValueError, "complete refresh"):
            self.service.update("case-1", {"expected_version": 3, "status": "resolved"})

    def test_risk_acceptance_requires_reason_and_future_expiration(self):
        with self.assertRaisesRegex(ValueError, "requires a reason"):
            self.service.update("case-1", {"expected_version": 3, "status": "risk_accepted"})
        future = (datetime.now(UTC) + timedelta(days=10)).isoformat()
        item = self.service.update(
            "case-1",
            {"expected_version": 3, "status": "risk_accepted", "risk_reason": "Компенсирующая мера", "risk_expires_at": future},
        )
        self.assertEqual(item["status"], "risk_accepted")
        self.assertEqual(self.repository.updates[-1][2], 3)

    def test_bulk_update_uses_current_version(self):
        result = self.service.bulk_update(["case-1", "case-1", "missing"], {"status": "in_progress"})
        self.assertEqual(result["updated_count"], 1)
        self.assertEqual(self.repository.updates[0][2], 3)


if __name__ == "__main__":
    unittest.main()
