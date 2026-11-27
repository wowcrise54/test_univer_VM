"""Coverage gates must fail on real regressions and incomplete measurements."""

import json

import pytest

from scripts import check_coverage_ratchet as ratchet
from scripts import check_coverage_thresholds as thresholds


def write_json(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    return path


@pytest.mark.parametrize("lines,branches,result", [(10, 2, 0), (9, 2, 1), (10, 1, 1), (10, 0, 0)])
def test_module_floors_check_lines_and_branches_independently(tmp_path, monkeypatch, capsys, lines, branches, result):
    report = write_json(
        tmp_path / "report.json",
        {
            "meta": {"branch_coverage": True},
            "files": {
                "app/critical.py": {
                    "summary": {
                        "covered_lines": lines,
                        "num_statements": 10,
                        "covered_branches": branches,
                        "num_branches": 0 if branches == 0 else 2,
                    }
                }
            },
        },
    )
    baseline = write_json(
        tmp_path / "floors.json",
        {
            "critical_branch": 0.0,
            "other_branch": 0.0,
            "module_floors": {"app/critical.py": {"lines": 100.0, "branches": 100.0}},
        },
    )
    monkeypatch.setattr("sys.argv", ["gate", "--report", str(report), "--thresholds", str(baseline)])
    assert thresholds.main() == result
    output = capsys.readouterr().out
    assert "app/critical.py" in output
    assert ("Coverage threshold gate failed" in output) is bool(result)


def test_module_missing_from_measurement_cannot_pass_the_floor(tmp_path, monkeypatch, capsys):
    report = write_json(tmp_path / "report.json", {"meta": {"branch_coverage": True}, "files": {}})
    baseline = write_json(tmp_path / "floors.json", {"module_floors": {"app/missing.py": {"lines": 100.0}}})
    monkeypatch.setattr("sys.argv", ["gate", "--report", str(report), "--thresholds", str(baseline)])
    assert thresholds.main() == 1
    assert "app/missing.py is missing" in capsys.readouterr().out


def test_branch_gate_rejects_a_report_without_branch_instrumentation(tmp_path, monkeypatch, capsys):
    report = write_json(tmp_path / "report.json", {"meta": {}, "files": {}})
    monkeypatch.setattr("sys.argv", ["gate", "--report", str(report)])
    assert thresholds.main() == 1
    assert "no branch measurement" in capsys.readouterr().out


@pytest.mark.parametrize(
    "kind,pct,result", [("python", 50.0, 0), ("python", 49.9, 1), ("frontend", 50.0, 0), ("frontend", 49.9, 1)]
)
def test_total_line_ratchet_rejects_each_runtime_regression(tmp_path, monkeypatch, capsys, kind, pct, result):
    python_report = write_json(
        tmp_path / "python.json",
        {"totals": {"percent_statements_covered": pct if kind == "python" else 100.0, "percent_covered": 1.0}},
    )
    frontend_report = write_json(
        tmp_path / "frontend.json", {"total": {"lines": {"pct": pct if kind == "frontend" else 100.0}}}
    )
    baseline = write_json(tmp_path / "baseline.json", {"python_lines": 50.0, "frontend_lines": 50.0})
    monkeypatch.setattr(
        "sys.argv",
        ["gate", "--python", str(python_report), "--frontend", str(frontend_report), "--baseline", str(baseline)],
    )
    assert ratchet.main() == result
    assert ("Coverage ratchet failed" in capsys.readouterr().out) is bool(result)


def test_older_python_coverage_reports_keep_the_previous_percentage_fallback(tmp_path):
    report = write_json(tmp_path / "legacy.json", {"totals": {"percent_covered": 75.0}})
    assert ratchet.percentage(report, "python") == 75.0
