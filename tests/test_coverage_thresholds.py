from __future__ import annotations

import json
import sys

from scripts import check_coverage_ratchet, check_coverage_thresholds


def test_branch_gate_rejects_report_without_branch_measurement(tmp_path, monkeypatch, capsys):
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps({
            "meta": {"branch_coverage": False},
            "files": {"app/auth.py": {"summary": {"covered_branches": 0, "num_branches": 0}}},
        }),
        encoding="utf-8",
    )
    monkeypatch.setattr(sys, "argv", ["check_coverage_thresholds.py", "--report", str(report)])

    assert check_coverage_thresholds.main() == 1
    assert "branch measurement" in capsys.readouterr().out


def test_line_ratchet_uses_statement_coverage_with_branch_report(tmp_path):
    report = tmp_path / "coverage.json"
    report.write_text(
        json.dumps({"totals": {"percent_covered": 62.47, "percent_statements_covered": 66.13}}),
        encoding="utf-8",
    )

    assert check_coverage_ratchet.percentage(report, "python") == 66.13
