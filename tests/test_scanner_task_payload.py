from __future__ import annotations

import unittest

from app import db
from app.api.schemas import ScannerTaskRequest
from app.mpvm_client import build_scanner_task_payload


class ScannerTaskPayloadTests(unittest.TestCase):
    def test_linux_credential_uses_ssh_transport_with_sudo(self) -> None:
        payload = build_scanner_task_payload(
            name="SSH",
            description="",
            scope_id="scope-1",
            profile_id="profile-linux",
            include_targets=["10.252.205.0/24", "10.252.206.0/24"],
            agent_ids=["agent-1"],
            credential_id="credential-1",
            credential_transport="ssh",
            host_discovery_enabled=True,
            host_discovery_profile_id="discovery-1",
            time_zone="+05:00",
        )

        self.assertEqual(
            payload["overrides"],
            {
                "transports": {
                    "terminal": {
                        "ssh": {
                            "connection": {
                                "auth": {
                                    "ref_value": "credential-1",
                                    "ref_type": "credential",
                                },
                                "privilege_elevation": {"sudo": {}},
                            }
                        }
                    }
                }
            },
        )
        self.assertNotIn("windows", payload["overrides"]["transports"])
        self.assertEqual(db._credential_id_from_payload(payload), "credential-1")

    def test_windows_transport_remains_the_default(self) -> None:
        payload = build_scanner_task_payload(
            name="Windows",
            description="",
            scope_id="scope-1",
            profile_id="profile-windows",
            include_targets=["10.0.0.0/24"],
            credential_id="credential-1",
        )

        self.assertEqual(
            payload["overrides"]["transports"]["windows"]["wmi_and_rpc_and_re"]
            ["connection"]["auth"]["ref_value"],
            "credential-1",
        )

    def test_schedule_and_denied_periods_are_serialized_into_mpvm_payload(self) -> None:
        request = ScannerTaskRequest(
            name="Scheduled audit",
            scope_id="scope-1",
            profile_id="profile-1",
            include_targets=["192.0.2.1"],
            trigger_parameters={
                "isEnabled": True,
                "fromDate": "2026-10-03T00:00:00Z",
                "timeZone": "+05:00",
                "type": "Weekly",
                "atTime": "01:30:00",
                "daysOfWeek": ["monday", "friday"],
            },
            denied_scan_settings={
                "isEnabled": True,
                "periods": [
                    {
                        "daysOfWeek": ["saturday"],
                        "timeZone": "+05:00",
                        "isAllDay": False,
                        "fromTime": "00:00:00",
                        "toTime": "06:00:00",
                    }
                ],
            },
        )

        from app.main import scanner_task_payload

        payload = scanner_task_payload(request)
        self.assertEqual(payload["triggerParameters"]["type"], "Weekly")
        self.assertEqual(payload["triggerParameters"]["daysOfWeek"], ["monday", "friday"])
        self.assertEqual(payload["deniedScanSettings"]["periods"][0]["toTime"], "06:00:00")

    def test_schedule_model_rejects_unsupported_mpvm_fields(self) -> None:
        with self.assertRaises(ValueError):
            ScannerTaskRequest(
                name="Invalid",
                scope_id="scope-1",
                profile_id="profile-1",
                include_targets=["192.0.2.1"],
                trigger_parameters={"type": "Daily", "isEnabled": True, "arbitrary": "forwarded"},
            )

    def test_enabled_schedule_and_denied_time_require_complete_periods(self) -> None:
        from app.api.schemas import DeniedScanSettings, TaskTriggerParameters

        with self.assertRaises(ValueError):
            TaskTriggerParameters(isEnabled=True, type="Weekly", atTime="09:00:00")
        with self.assertRaises(ValueError):
            DeniedScanSettings(isEnabled=True, periods=[])

    def test_raw_payload_is_rebuilt_from_validated_fields(self) -> None:
        from app.main import scanner_task_payload

        request = ScannerTaskRequest(
            name="Fallback",
            scope_id="scope-fallback",
            profile_id="profile-fallback",
            include_targets=["192.0.2.1"],
            raw_payload={
                "name": "Validated raw payload",
                "scope": "scope-1",
                "profile": "profile-1",
                "include": {"targets": ["192.0.2.10"]},
                "triggerParameters": {"isEnabled": True, "type": "Daily", "atTime": "09:00:00"},
                "arbitrary": "must not reach MP VM",
            },
        )
        payload = scanner_task_payload(request)
        self.assertEqual(payload["name"], "Validated raw payload")
        self.assertEqual(payload["include"]["targets"], ["192.0.2.10"])
        self.assertNotIn("arbitrary", payload)


if __name__ == "__main__":
    unittest.main()
