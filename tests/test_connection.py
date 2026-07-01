from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import BackgroundTasks

from app import main
from app.mpvm_client import AuthConfig, MpVmClient


class ConnectionTokenTests(unittest.TestCase):
    def make_client(self, token: str) -> MpVmClient:
        return MpVmClient(
            AuthConfig(
                api_url="https://fixture",
                token_url="https://fixture:3334/connect/token",
                access_token=token,
            )
        )

    def test_raw_bearer_token_is_accepted(self):
        client = self.make_client(" token-value ")
        try:
            self.assertEqual(client.ensure_access_token(), "token-value")
        finally:
            client.session.close()

    def test_bearer_prefix_is_not_duplicated(self):
        client = self.make_client("Bearer token-value")
        try:
            self.assertEqual(client.ensure_access_token(), "token-value")
        finally:
            client.session.close()

    def test_scan_resume_is_deferred_until_after_connection_response(self):
        background_tasks = BackgroundTasks()
        runtime_session = SimpleNamespace(
            client=None,
            access_token=None,
            api_url=None,
            token_url=None,
            username=None,
            verify_tls=True,
        )
        payload = main.ConnectionRequest(
            api_url="https://fixture",
            access_token="Bearer token-value",
        )

        with (
            patch.object(main, "SESSION", runtime_session),
            patch.object(main, "resume_scan_postprocess_runs") as resume,
        ):
            result = main.connect_session(payload, background_tasks)

        try:
            self.assertTrue(result["connected"])
            self.assertEqual(runtime_session.access_token, "token-value")
            resume.assert_not_called()
            self.assertEqual(len(background_tasks.tasks), 1)
        finally:
            runtime_session.client.session.close()


if __name__ == "__main__":
    unittest.main()
