import io
import json
from threading import Event

import pytest
import requests

from app.services.wazuh_snapshot import collect_snapshot
from app.services.wazuh_snapshot_download import SnapshotUnavailable, download_snapshot


def test_snapshot_keeps_only_local_supported_rules_and_prioritizes_installed_packages():
    def record(cve, package, severity):
        return {
            "name": cve,
            "payload": {
                "cveMetadata": {"cveId": cve},
                "containers": {"cna": {
                    "providerMetadata": {"shortName": "debian"},
                    "metrics": [{"cvssV3_1": {"baseScore": severity}}],
                    "affected": [{
                        "vendor": "debian", "product": package, "platforms": ["bookworm"],
                        "versions": [{"status": "affected", "version": "0", "lessThan": "2", "versionType": "deb"}],
                    }],
                }},
            },
        }

    records = [
        record("CVE-2025-1000", "other", 9.8),
        record("CVE-2025-1001", "installed", 5.0),
        record("CVE-2025-1002", "installed", 10.0),
    ]
    stream = io.BytesIO(b"\n".join(json.dumps(item).encode() for item in records))
    results, seen, errors = collect_snapshot(
        stream,
        {"CVE-2025-1000": False, "CVE-2025-1001": False},
        {("debian", "bookworm", "installed")},
        Event(),
        lambda: None,
    )
    assert [row[0] for row in results] == ["wazuh-cti:CVE-2025-1001", "wazuh-cti:CVE-2025-1000"]
    assert seen == 2
    assert errors == []


@pytest.mark.parametrize("accepts_range", [True, False])
def test_snapshot_download_resumes_after_body_timeout(tmp_path, accepts_range):
    seen = []

    class Response:
        def __init__(self, status, headers, interrupted):
            self.status_code = status
            self.headers = headers
            self.interrupted = interrupted

        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def iter_content(self, chunk_size):
            if self.interrupted:
                yield b"abc"
                raise requests.ConnectionError("read timed out")
            yield b"def"

    class Session:
        def get(self, url, *, headers, **options):
            seen.append(headers)
            if len(seen) == 1:
                return Response(200, {"Content-Length": "6", "ETag": '"v1"'}, True)
            if accepts_range:
                return Response(206, {"Content-Range": "bytes 3-5/6", "ETag": '"v1"'}, False)
            return Response(200, {"Content-Length": "6", "ETag": '"v1"'}, False)

    args = (Session(), "https://example.invalid/test.zip", tmp_path, Event(), lambda *_: None)
    if accepts_range:
        assert download_snapshot(*args).read_bytes() == b"abcdef"
    else:
        with pytest.raises(SnapshotUnavailable, match="Range"):
            download_snapshot(*args)
        assert (tmp_path / "snapshot.zip.part").read_bytes() == b"abc"
    assert seen[1]["Range"] == "bytes=3-"
    assert seen[1]["If-Range"] == '"v1"'
