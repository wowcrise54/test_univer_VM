from __future__ import annotations

import unittest

from app import main
from app.mpvm_client import MpVmApiError


class MpVmRateLimitTests(unittest.TestCase):
    def test_rate_limit_preserves_status_and_retry_after(self):
        error = MpVmApiError("too many requests", status_code=429, retry_after="7")

        http_error = main.http_error(error)

        self.assertEqual(http_error.status_code, 429)
        self.assertEqual(http_error.headers, {"Retry-After": "7"})
        self.assertEqual(http_error.detail["code"], "MPVM_RATE_LIMITED")
        self.assertTrue(http_error.detail["retryable"])

    def test_other_mpvm_errors_remain_bad_gateway(self):
        error = MpVmApiError("bad gateway", status_code=502)

        self.assertEqual(main.http_error(error).status_code, 502)


if __name__ == "__main__":
    unittest.main()
