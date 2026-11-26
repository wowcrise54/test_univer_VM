import io
import json
from threading import Event

from app.services.wazuh_snapshot import collect_snapshot


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
