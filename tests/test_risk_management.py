import inspect

from app import auth
from app.repositories.remediation import RemediationRepository
from app.repositories.risk import MODEL_VERSION, RiskRepository, _risk_sql


def test_risk_model_is_versioned_and_bounded():
    sql = _risk_sql()
    assert MODEL_VERSION == "local-risk-v1"
    assert "LEAST(100" in sql
    assert "GREATEST(0" in sql
    assert "criticality" in sql
    assert "exposure" in sql
    assert "due_at<NOW()" in sql


def test_context_rejects_unknown_classification_before_database_access():
    repository = RiskRepository()
    try:
        repository.set_contexts(["asset-1"], {"criticality": "mission-critical"}, "operator")
    except ValueError as exc:
        assert "criticality" in str(exc)
    else:
        raise AssertionError("Unknown context classification was accepted")


def test_risk_and_context_permissions_are_separated():
    assert auth.required_permission("GET", "/api/risk/queue") == "risk.read"
    assert auth.required_permission("PATCH", "/api/assets/context") == "risk.manage"
    assert "risk.read" in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "risk.manage" not in auth.BUILTIN_ROLE_PERMISSIONS["viewer"]
    assert "risk.manage" in auth.BUILTIN_ROLE_PERMISSIONS["operator"]


def test_existing_remediation_queue_does_not_require_risk_schema():
    source = inspect.getsource(RemediationRepository.list) + inspect.getsource(RemediationRepository.get)
    assert "asset_contexts" not in source
    assert "remediation_campaigns" not in source
