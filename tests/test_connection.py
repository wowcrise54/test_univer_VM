from __future__ import annotations

import unittest

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


if __name__ == "__main__":
    unittest.main()
