from __future__ import annotations

import unittest

from app import db
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


if __name__ == "__main__":
    unittest.main()
