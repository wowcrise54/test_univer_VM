"""HTTP contract tests with isolated services; no MP VM calls or SQL substitutes."""
from datetime import date
from types import SimpleNamespace
from unittest.mock import Mock

import psycopg
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import asset_groups, attention, compliance, remediation, risk, vm, vulnerabilities


@pytest.fixture
def http_services():
    services = SimpleNamespace(
        asset_groups=Mock(), vulnerabilities=Mock(), vm_workflows=Mock(),
        risk=Mock(), compliance=Mock(), remediation=Mock(), coverage=Mock(), attention=Mock(),
    )
    application = FastAPI()
    application.state.container = SimpleNamespace(services=services, settings=SimpleNamespace(attention_search_enabled=True))
    application.state.identity = {"username": "operator", "permissions": ["risk.manage", "remediation.manage", "tasks.execute", "assets.read", "remediation.read", "risk.read", "operations.read"]}

    @application.middleware("http")
    async def identity(request, call_next):
        if application.state.identity is not None:
            request.state.user = application.state.identity
        return await call_next(request)

    for router in (asset_groups.router, risk.router, compliance.dashboard_router, compliance.report_router, remediation.router, remediation.coverage_router, attention.router, vm.router, vulnerabilities.router):
        application.include_router(router)
    with TestClient(application) as client:
        yield client, services, application


@pytest.mark.parametrize("path,method,arguments", [
    ("", "tree", {}), ("/tree", "tree", {}),
    ("/precheck-stats", "precheck_stats", {}),
    ("/precheck-runs?limit=7", "precheck_runs", {"limit": 7}),
])
def test_group_listing_contract(http_services, path, method, arguments):
    client, services, _ = http_services
    target = getattr(services.asset_groups, method)
    target.return_value = {"rows": [{"group_id": "g"}]}
    response = client.get("/api/asset-groups" + path)
    assert response.status_code == 200
    assert response.json() == target.return_value
    target.assert_called_once_with(**arguments)


def test_group_create_update_preview_and_overrides(http_services):
    client, services, application = http_services
    groups = services.asset_groups
    groups.create.return_value = {"group_id": "g", "name": "Production"}
    response = client.post("/api/asset-groups", json={"name": " Production ", "query": {"version": 1}})
    assert response.status_code == 201
    groups.create.assert_called_once_with(actor="operator", name="Production", description="", parent_id=None, query={"version": 1})
    groups.update.return_value = {"group_id": "g", "description": "changed"}
    assert client.patch("/api/asset-groups/g", json={"description": "changed"}).status_code == 200
    groups.update.assert_called_once_with("g", {"description": "changed"})
    groups.preview.return_value = {"total": 2, "rows": []}
    assert client.post("/api/asset-groups/preview", json={"query": {}, "limit": 2}).json()["total"] == 2
    groups.preview.assert_called_once_with({}, limit=2)
    groups.set_override.return_value = {"action": "include"}
    application.state.identity = None
    assert client.put("/api/asset-groups/g/overrides/a", json={"action": "include"}).status_code == 200
    groups.set_override.assert_called_once_with("g", "a", "include", actor=None)
    groups.delete_override.return_value = False
    assert client.delete("/api/asset-groups/g/overrides/a").json() == {"deleted": False}
    groups.delete_override.assert_called_once_with("g", "a")


@pytest.mark.parametrize("endpoint,http_method,payload,service_method", [
    ("/preview", "post", {"query": {}}, "preview"),
    ("", "post", {"name": "Group", "query": {}}, "create"),
    ("/from-vulnerability", "post", {"name": "Group", "selector": "CVE-2026-1"}, "create_from_asset_ids"),
    ("/g", "patch", {"name": "Changed"}, "update"),
    ("/g/evaluate", "post", None, "evaluate"),
    ("/g/members", "get", None, "members"),
    ("/g/overrides/a", "put", {"action": "exclude"}, "set_override"),
])
@pytest.mark.parametrize("error,status,code", [
    (LookupError("missing"), 404, "ASSET_GROUP_NOT_FOUND"),
    (ValueError("invalid query"), 422, "INVALID_ASSET_GROUP"),
    (psycopg.errors.UniqueViolation("duplicate"), 409, "ASSET_GROUP_NAME_EXISTS"),
])
def test_group_domain_errors_preserve_http_contract(http_services, endpoint, http_method, payload, service_method, error, status, code):
    client, services, _ = http_services
    getattr(services.asset_groups, service_method).side_effect = error
    services.vulnerabilities.hosts.return_value = {"rows": [], "total": 0}
    response = client.request(http_method, "/api/asset-groups" + endpoint, json=payload)
    assert response.status_code == status
    assert response.json()["detail"]["code"] == code


def test_group_unexpected_errors_propagate_instead_of_becoming_validation_errors(http_services):
    client, services, _ = http_services
    services.asset_groups.preview.side_effect = RuntimeError("repository unavailable")
    with pytest.raises(RuntimeError, match="repository unavailable"):
        client.post("/api/asset-groups/preview", json={"query": {}})


def test_group_members_bulk_and_archive_contract(http_services):
    client, services, _ = http_services
    groups = services.asset_groups
    groups.get.return_value = {"group_id": "g"}
    assert client.get("/api/asset-groups/g").json() == {"group_id": "g"}
    groups.get.return_value = None
    assert client.get("/api/asset-groups/missing").status_code == 404
    groups.members.return_value = {"rows": [], "total": 5}
    assert client.get("/api/asset-groups/g/members?limit=3&offset=2").json()["total"] == 5
    groups.members.assert_called_once_with("g", limit=3, offset=2)
    groups.bulk_action.return_value = {"updated": 2}
    assert client.post("/api/asset-groups/bulk-action", json={"group_ids": ["g", "h"], "action": "archive"}).json() == {"updated": 2}
    groups.bulk_action.assert_called_once_with(["g", "h"], "archive")
    groups.archive.return_value = True
    assert client.post("/api/asset-groups/g/archive").json() == {"group_id": "g", "archived": True}
    groups.archive.return_value = False
    assert client.post("/api/asset-groups/missing/archive").status_code == 404
    groups.update.return_value = None
    assert client.patch("/api/asset-groups/missing", json={}).status_code == 404
    groups.evaluate.return_value = {"member_count": 2}
    assert client.post("/api/asset-groups/g/evaluate").json() == {"member_count": 2}


@pytest.mark.parametrize("pages,expected", [
    ([{"rows": [{"asset_id": "a"}, {"asset_id": None}], "total": 3}, {"rows": [{"asset_id": 123}], "total": 3}], ["a", "123"]),
    ([{"rows": [{"asset_id": "a"}], "total": 100}, {"rows": [], "total": 100}], ["a"]),
    ([{"rows": [{"asset_id": "a"}]}], ["a"]),
])
def test_group_from_vulnerability_pages_all_hosts_and_stops_on_empty_page(http_services, pages, expected):
    client, services, _ = http_services
    services.vulnerabilities.hosts.side_effect = pages
    services.asset_groups.create_from_asset_ids.return_value = {"group_id": "new"}
    response = client.post("/api/asset-groups/from-vulnerability", json={"name": "Hosts", "selector": "CVE-2026-1", "parent_id": "parent"})
    assert response.status_code == 201
    services.asset_groups.create_from_asset_ids.assert_called_once_with(name="Hosts", description="", parent_id="parent", asset_ids=expected, actor="operator")
    assert services.vulnerabilities.hosts.call_count == len(pages)
    if len(pages) > 1:
        assert services.vulnerabilities.hosts.call_args.kwargs["offset"] == len(pages[0]["rows"])


@pytest.mark.parametrize("action,workflow_method", [("scan", "start_asset_group_scan"), ("verify", "start_asset_group_verification")])
@pytest.mark.parametrize("payload", [None, {"template_task_id": "template", "start_options": {"wait_for_finish": True}}])
def test_group_workflows_forward_actor_options_targets_and_idempotency(http_services, action, workflow_method, payload):
    client, services, _ = http_services
    services.asset_groups.target_asset_ids.return_value = ["a", "b"]
    target = getattr(services.vm_workflows, workflow_method)
    target.return_value = ({"workflow_id": "workflow", "status": "queued"}, True)
    response = client.post(f"/api/asset-groups/g/{action}", json=payload, headers={"X-Idempotency-Key": "same-request"})
    assert response.status_code == 202
    assert response.json() == {"workflow": {"workflow_id": "workflow", "status": "queued"}, "workflow_id": "workflow", "asset_count": 2, "idempotent_replay": True}
    arguments = target.call_args.kwargs
    assert arguments["asset_group_id"] == "g" and arguments["asset_ids"] == ["a", "b"]
    assert arguments["actor"] == "operator" and arguments["idempotency_key"] == "same-request"
    assert arguments["options"]["template_task_id"] == (payload or {}).get("template_task_id")
    assert arguments["options"]["start_options"]["wait_for_finish"] == bool(payload)


@pytest.mark.parametrize("action,workflow_method", [("scan", "start_asset_group_scan"), ("verify", "start_asset_group_verification")])
@pytest.mark.parametrize("error,status,code", [(ValueError("different request"), 409, "IDEMPOTENCY_KEY_CONFLICT"), (LookupError("missing"), 404, "ASSET_GROUP_NOT_FOUND")])
def test_group_workflow_conflicts_and_missing_targets(http_services, action, workflow_method, error, status, code):
    client, services, _ = http_services
    services.asset_groups.target_asset_ids.return_value = ["a"]
    getattr(services.vm_workflows, workflow_method).side_effect = error
    response = client.post(f"/api/asset-groups/g/{action}")
    assert response.status_code == status and response.json()["detail"]["code"] == code


@pytest.mark.parametrize("method,path,payload", [
    ("post", "/api/asset-groups", {"name": "   ", "query": {}}),
    ("post", "/api/asset-groups/preview", {"query": {}, "limit": 501}),
    ("put", "/api/asset-groups/g/overrides/a", {"action": "delete"}),
    ("get", "/api/asset-groups/g/members?offset=-1", None),
    ("get", "/api/asset-groups/precheck-runs?limit=0", None),
    ("patch", "/api/assets/context", {"asset_ids": [], "values": {}}),
    ("patch", "/api/assets/context", {"asset_ids": ["a"], "values": {"exposure": "public"}}),
    ("post", "/api/remediation/campaigns", {"name": "Campaign", "case_ids": []}),
    ("get", "/api/risk/queue?level=critical", None),
    ("get", "/api/risk/queue?limit=501", None),
    ("get", "/api/vulnerabilities/compliance/unknown/summary", None),
    ("get", "/api/vulnerabilities/compliance/internet/findings?limit=0", None),
    ("post", "/api/reports/vulnerabilities/compliance/internet/csv", {}),
])
def test_invalid_http_input_never_reaches_services(http_services, method, path, payload):
    client, services, _ = http_services
    assert client.request(method, path, json=payload).status_code == 422
    for service in vars(services).values():
        assert not service.mock_calls


def test_risk_context_queue_and_summary_contract(http_services):
    client, services, application = http_services
    target = services.risk
    target.set_contexts.return_value = {"updated": 1}
    assert client.patch("/api/assets/context", json={"asset_ids": ["a"], "values": {"owner": None, "tags": ["critical"]}}).json() == {"updated": 1}
    target.set_contexts.assert_called_once_with(["a"], {"owner": None, "tags": ["critical"]}, "operator")
    target.set_contexts.side_effect = ValueError("invalid asset")
    response = client.patch("/api/assets/context", json={"asset_ids": ["a"], "values": {}})
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INVALID_ASSET_CONTEXT"
    target.import_contexts.return_value = {"updated": 2}
    application.state.identity = None
    assert client.post("/api/assets/context/import", json={"csv_text": "asset_id,owner\na,Team"}).status_code == 200
    target.import_contexts.assert_called_once_with("asset_id,owner\na,Team", None)
    target.queue.return_value = {"rows": [], "total": 0}
    response = client.get("/api/risk/queue?level=urgent&owner=Team&environment=production&criticality=critical&exposure=external&tag=api&limit=7&offset=3")
    assert response.status_code == 200
    target.queue.assert_called_once_with(level="urgent", owner="Team", environment="production", criticality="critical", exposure="external", tag="api", limit=7, offset=3)
    target.summary.return_value = {"urgent": 2}
    assert client.get("/api/risk/summary").json() == {"urgent": 2}


def test_campaign_lifecycle_keeps_explicit_nulls_and_serializes_dates(http_services):
    client, services, _ = http_services
    target = services.risk
    target.create_campaign.return_value = {"campaign_id": "campaign"}
    response = client.post("/api/remediation/campaigns", json={"name": "Critical", "case_ids": ["case"], "due_at": "2026-10-01T12:00:00Z"})
    assert response.status_code == 201
    values, actor = target.create_campaign.call_args.args
    assert values["due_at"] == "2026-10-01T12:00:00Z" and actor == "operator"
    target.list_campaigns.return_value = {"rows": [{"campaign_id": "campaign"}]}
    assert client.get("/api/remediation/campaigns").json() == target.list_campaigns.return_value
    target.get_campaign.return_value = {"campaign_id": "campaign"}
    assert client.get("/api/remediation/campaigns/campaign").status_code == 200
    target.get_campaign.return_value = None
    assert client.get("/api/remediation/campaigns/missing").status_code == 404
    target.update_campaign.return_value = {"campaign_id": "campaign", "assignee": None}
    assert client.patch("/api/remediation/campaigns/campaign", json={"assignee": None}).status_code == 200
    target.update_campaign.assert_called_once_with("campaign", {"assignee": None}, "operator")
    target.update_campaign.return_value = None
    assert client.patch("/api/remediation/campaigns/missing", json={"status": "cancelled"}).status_code == 404


@pytest.mark.parametrize("missing", ["risk.manage", "remediation.manage", "tasks.execute", "all"])
def test_campaign_verification_requires_every_permission_before_starting(http_services, missing):
    client, services, application = http_services
    permissions = application.state.identity["permissions"]
    application.state.identity["permissions"] = [] if missing == "all" else [value for value in permissions if value != missing]
    response = client.post("/api/remediation/campaigns/campaign/verify")
    assert response.status_code == 403 and response.json()["detail"]["code"] == "PERMISSION_DENIED"
    services.vm_workflows.start_verification.assert_not_called()


def test_campaign_verification_returns_replayed_workflow_and_not_found(http_services):
    client, services, _ = http_services
    workflow = {"workflow_id": "w", "operation_id": "o", "status": "queued"}
    services.vm_workflows.start_verification.return_value = (workflow, True, ["a"])
    response = client.post("/api/remediation/campaigns/campaign/verify", headers={"X-Idempotency-Key": "request"})
    assert response.status_code == 202
    assert response.json() == {"campaign_id": "campaign", "asset_ids": ["a"], "workflow_id": "w", "operation_id": "o", "status": "queued", "workflow": workflow, "idempotent_replay": True}
    services.vm_workflows.start_verification.assert_called_once_with(campaign_id="campaign", options={}, actor="operator", idempotency_key="request")
    services.vm_workflows.start_verification.return_value = (None, False, [])
    assert client.post("/api/remediation/campaigns/missing/verify").status_code == 404


@pytest.mark.parametrize("scope", ["internet", "organization"])
@pytest.mark.parametrize("assessment", [None, "2026-09-30"])
def test_compliance_summary_date_and_scope(http_services, scope, assessment):
    client, services, _ = http_services
    services.compliance.summary.return_value = {"critical_findings": 3}
    query = f"?assessment_date={assessment}" if assessment else ""
    assert client.get(f"/api/vulnerabilities/compliance/{scope}/summary{query}").json() == {"critical_findings": 3}
    services.compliance.summary.assert_called_once_with(scope=scope, assessment_date=date.fromisoformat(assessment) if assessment else date.today())


@pytest.mark.parametrize("endpoint,method,sort", [("findings", "findings", "cvss_score"), ("stale-assets", "stale_assets", "age_days")])
def test_compliance_pagination_rejects_domain_query_errors(http_services, endpoint, method, sort):
    client, services, _ = http_services
    target = getattr(services.compliance, method)
    target.return_value = {"rows": [], "total": 0}
    assert client.get(f"/api/vulnerabilities/compliance/internet/{endpoint}").status_code == 200
    target.assert_called_once_with(scope="internet", assessment_date=date.today(), limit=50, offset=0, sort_by=sort, sort_dir="desc")
    target.side_effect = ValueError("Unsupported sort column")
    response = client.get(f"/api/vulnerabilities/compliance/internet/{endpoint}?sort_by=unsafe&sort_dir=asc&limit=5&offset=2")
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INVALID_COMPLIANCE_QUERY"


@pytest.mark.parametrize("report_format,content_type", [("pdf", "application/pdf"), ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")])
@pytest.mark.parametrize("asset_ids,normalized", [(None, None), ([], None), ([" a ", "a", " ", "b"], ["a", "b"])])
def test_compliance_export_normalizes_selection_and_records_audit(http_services, monkeypatch, report_format, content_type, asset_ids, normalized):
    client, services, _ = http_services
    dataset = SimpleNamespace(findings=[{"asset_id": "a"}], stale_assets=[{}, {}])
    services.compliance.report_dataset.return_value = dataset
    renderer = Mock(return_value=b"fixture-document")
    monkeypatch.setattr(compliance, f"render_compliance_{report_format}", renderer)
    audit = Mock()
    monkeypatch.setattr(compliance.app_auth, "audit_event", audit)
    response = client.post(f"/api/reports/vulnerabilities/compliance/internet/{report_format}", json={"assessment_date": "2026-09-30", "asset_ids": asset_ids})
    assert response.status_code == 200 and response.content == b"fixture-document"
    assert response.headers["content-type"] == content_type
    assert f"critical-vulnerabilities-internet-2026-09-30.{report_format}" in response.headers["content-disposition"]
    services.compliance.report_dataset.assert_called_once_with(scope="internet", assessment_date=date(2026, 9, 30), asset_ids=normalized)
    renderer.assert_called_once_with(dataset)
    assert audit.call_args.kwargs["event_type"] == "report_download"
    assert audit.call_args.kwargs["permission_key"] == "imports_exports.read"
    assert audit.call_args.kwargs["details"] == {"assessment_date": "2026-09-30", "selected_assets": len(normalized or []), "critical_findings": 1, "stale_assets": 2}

@pytest.mark.parametrize("path,service_name,method", [
    ("/api/remediation/summary", "remediation", "summary"),
    ("/api/remediation/policy", "remediation", "policy"),
    ("/api/coverage/summary", "coverage", "summary"),
    ("/api/vm/overview", "vm_workflows", "overview"),
])
def test_read_endpoints_return_service_results(http_services, path, service_name, method):
    client, services, _ = http_services
    target = getattr(getattr(services, service_name), method)
    target.return_value = {"total": 7}
    assert client.get(path).json() == {"total": 7}
    target.assert_called_once_with()


def test_remediation_list_detail_update_and_policy_contract(http_services):
    client, services, _ = http_services
    service = services.remediation
    service.list.return_value = {"rows": [], "total": 0}
    assert client.get("/api/remediation/cases?q=CVE&status=open&severity=high&assignee=Team&overdue=true&limit=5&offset=2").status_code == 200
    service.list.assert_called_once_with(q="CVE", status="open", severity="high", assignee="Team", overdue=True, limit=5, offset=2)
    service.get.return_value = {"case_id": "case"}
    assert client.get("/api/remediation/cases/case").json() == {"case_id": "case"}
    service.get.return_value = None
    assert client.get("/api/remediation/cases/missing").status_code == 404
    service.update.return_value = {"case_id": "case", "version": 3}
    assert client.patch("/api/remediation/cases/case", json={"expected_version": 2, "assignee": None}).status_code == 200
    service.update.assert_called_once_with("case", {"expected_version": 2, "assignee": None})
    service.update.return_value = None
    assert client.patch("/api/remediation/cases/missing", json={"expected_version": 1}).status_code == 404
    service.bulk_update.return_value = {"updated_count": 1, "conflicts": ["case-b"]}
    assert client.post("/api/remediation/cases/bulk-update", json={"case_ids": ["case", "case-b"], "status": "in_progress"}).json()["conflicts"] == ["case-b"]
    service.bulk_update.assert_called_once_with(["case", "case-b"], {"status": "in_progress"})
    policy = {"critical_days": 1, "high_days": 2, "medium_days": 30, "low_days": 90, "near_due_days": 3}
    service.update_policy.return_value = policy
    assert client.put("/api/remediation/policy", json={**policy, "apply_to_open": True}).json() == policy
    service.update_policy.assert_called_once_with(policy, apply_to_open=True)
    service.resolution_stats.return_value = {"resolved": 2}
    assert client.get("/api/remediation/resolution-stats?days=60&recent_limit=3").json() == {"resolved": 2}
    service.resolution_stats.assert_called_once_with(days=60, recent_limit=3)
    services.coverage.list_assets.return_value = {"rows": []}
    assert client.get("/api/coverage/assets?q=server&issue=stale&limit=5&offset=1").status_code == 200
    services.coverage.list_assets.assert_called_once_with(q="server", issue="stale", limit=5, offset=1)


@pytest.mark.parametrize("error,status,code", [(ValueError("invalid status"), 422, "INVALID_CASE_UPDATE"), (RuntimeError("version mismatch"), 409, "VERSION_CONFLICT")])
def test_remediation_update_rejects_invalid_state_and_stale_version(http_services, error, status, code):
    client, services, _ = http_services
    services.remediation.update.side_effect = error
    response = client.patch("/api/remediation/cases/case", json={"expected_version": 1, "status": "in_progress"})
    assert response.status_code == status and response.json()["detail"]["code"] == code


def test_bulk_case_domain_validation(http_services):
    client, services, _ = http_services
    services.remediation.bulk_update.side_effect = ValueError("Missing reason")
    response = client.post("/api/remediation/cases/bulk-update", json={"case_ids": ["case"], "status": "risk_accepted"})
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INVALID_CASE_UPDATE"


@pytest.mark.parametrize("missing", ["assets.read", "remediation.read", "remediation.manage"])
def test_remediation_start_requires_each_permission_before_mutation(http_services, missing):
    client, services, application = http_services
    application.state.identity["permissions"].remove(missing)
    response = client.post("/api/remediation/cases/start", json={"asset_id": "a", "vulnerability_selector": "id:v"})
    assert response.status_code == 403
    services.remediation.start_for_finding.assert_not_called()


def test_remediation_start_keeps_finding_selection_and_resume_option(http_services):
    client, services, _ = http_services
    services.remediation.start_for_finding.return_value = {"case_id": "case"}
    response = client.post("/api/remediation/cases/start", json={"asset_id": "a", "vulnerability_selector": "id:v", "resume_exception": True})
    assert response.status_code == 200
    services.remediation.start_for_finding.assert_called_once_with(asset_id="a", vulnerability_selector="id:v", assignee=None, due_at=None, comment=None, resume_exception=True)


@pytest.mark.parametrize("error,status,code", [(ValueError("blank"), 422, "INVALID_CASE_START"), (LookupError("missing"), 404, "FINDING_NOT_FOUND")])
def test_remediation_start_reports_missing_finding_and_invalid_input(http_services, error, status, code):
    client, services, _ = http_services
    services.remediation.start_for_finding.side_effect = error
    response = client.post("/api/remediation/cases/start", json={"asset_id": "a", "vulnerability_selector": "id:v"})
    assert response.status_code == status and response.json()["detail"]["code"] == code


@pytest.mark.parametrize("path", ["/api/attention", "/api/search?q=server"])
def test_attention_feature_flag_prevents_queries(http_services, path):
    client, services, application = http_services
    application.state.container.settings.attention_search_enabled = False
    response = client.get(path)
    assert response.status_code == 404 and response.json()["detail"]["code"] == "FEATURE_DISABLED"
    assert not services.attention.mock_calls


@pytest.mark.parametrize("mine", [True, False])
def test_attention_filters_and_owner_use_authenticated_identity(http_services, mine):
    client, services, application = http_services
    services.attention.attention.return_value = {"rows": [], "cursor": None}
    response = client.get(f"/api/attention?type=operation&priority=high&limit=7&cursor=page-2&mine={str(mine).lower()}")
    assert response.status_code == 200
    services.attention.attention.assert_called_once_with(permissions=set(application.state.identity["permissions"]), limit=7, cursor="page-2", owner="operator" if mine else None, kind="operation", priority="high")


@pytest.mark.parametrize("path,method", [("/api/attention?cursor=bad", "attention"), ("/api/search?q=server&cursor=bad", "search")])
def test_attention_and_search_reject_invalid_cursors(http_services, path, method):
    client, services, _ = http_services
    getattr(services.attention, method).side_effect = ValueError("Invalid cursor")
    response = client.get(path)
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INVALID_CURSOR"


def test_search_validation_and_permission_scoping(http_services):
    client, services, application = http_services
    response = client.get("/api/search?q=%20%20")
    assert response.status_code == 422 and response.json()["detail"]["code"] == "INVALID_QUERY"
    services.attention.search.assert_not_called()
    application.state.identity = None
    services.attention.search.return_value = {"rows": []}
    assert client.get("/api/search?q=server&type=asset&limit=3&cursor=page").status_code == 200
    services.attention.search.assert_called_once_with(query="server", kind="asset", permissions=set(), limit=3, cursor="page")


@pytest.mark.parametrize("missing", ["operations.read", "assets.read", "remediation.read", "risk.read"])
def test_vm_overview_requires_all_domain_permissions(http_services, missing):
    client, services, application = http_services
    application.state.identity["permissions"].remove(missing)
    assert client.get("/api/vm/overview").status_code == 403
    services.vm_workflows.overview.assert_not_called()


def test_vm_workflow_list_details_cancel_and_retry(http_services):
    client, services, _ = http_services
    service = services.vm_workflows
    service.list.return_value = {"rows": []}
    assert client.get("/api/vm/workflows?status=failed&kind=scan&limit=7&offset=3").status_code == 200
    service.list.assert_called_once_with(status="failed", kind="scan", limit=7, offset=3)
    service.get.return_value = {"workflow_id": "w"}
    assert client.get("/api/vm/workflows/w").json() == {"workflow_id": "w"}
    service.get.return_value = None
    assert client.get("/api/vm/workflows/missing").status_code == 404
    service.cancel.return_value = {"workflow_id": "w", "status": "cancelling"}
    assert client.post("/api/vm/workflows/w/cancel").json()["status"] == "cancelling"
    service.cancel.return_value = None
    assert client.post("/api/vm/workflows/missing/cancel").status_code == 404
    service.retry.return_value = ({"workflow_id": "retry"}, True)
    response = client.post("/api/vm/workflows/w/retry", headers={"X-Idempotency-Key": "same-request"})
    assert response.status_code == 202 and response.json()["idempotent_replay"] is True
    service.retry.assert_called_once_with("w", "operator", "same-request")
    service.retry.return_value = (None, False)
    response = client.post("/api/vm/workflows/w/retry")
    assert response.status_code == 409 and response.json()["detail"]["code"] == "VM_WORKFLOW_NOT_RETRYABLE"
    service.retry.side_effect = ValueError("conflict")
    response = client.post("/api/vm/workflows/w/retry")
    assert response.status_code == 409 and response.json()["detail"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"


@pytest.mark.parametrize("can_execute", [True, False])
def test_vm_scan_preflight_receives_execution_permission(http_services, can_execute):
    client, services, application = http_services
    if not can_execute:
        application.state.identity["permissions"].remove("tasks.execute")
    services.vm_workflows.scan_preflight.return_value = {"allowed": can_execute}
    response = client.post("/api/vm/workflows/scan/preflight", json={"task_id": "task", "options": {"wait_for_finish": True}})
    assert response.json() == {"allowed": can_execute}
    services.vm_workflows.scan_preflight.assert_called_once_with(task_id="task", options={"wait_for_finish": True}, can_execute=can_execute)


def test_vm_scan_workflow_and_preflight_errors(http_services):
    from app.services.vm_workflows import VmPreflightBlocked
    client, services, application = http_services
    application.state.identity = None
    services.vm_workflows.start_scan.return_value = ({"workflow_id": "w", "status": "queued"}, False)
    response = client.post("/api/vm/workflows/scan", json={"task_id": "task"}, headers={"X-Idempotency-Key": "key"})
    assert response.status_code == 202 and response.json()["workflow_id"] == "w"
    services.vm_workflows.start_scan.assert_called_once_with(task_id="task", options={}, actor=None, idempotency_key="key")
    services.vm_workflows.start_scan.side_effect = VmPreflightBlocked({"allowed": False, "blockers": ["offline"]})
    response = client.post("/api/vm/workflows/scan", json={"task_id": "task"})
    assert response.status_code == 409 and response.json()["detail"]["preflight"]["allowed"] is False
    services.vm_workflows.start_scan.side_effect = ValueError("conflict")
    response = client.post("/api/vm/workflows/scan", json={"task_id": "task"})
    assert response.status_code == 409 and response.json()["detail"]["code"] == "IDEMPOTENCY_KEY_CONFLICT"


@pytest.mark.parametrize("endpoint,method,code", [("/summary", "summary", "INVALID_FILTER"), ("", "list", "INVALID_SORT"), ("/hosts?selector=id:v", "hosts", "INVALID_SORT"), ("/trends", "trends", "INVALID_RANGE")])
def test_vulnerability_query_domain_errors(http_services, endpoint, method, code):
    client, services, _ = http_services
    getattr(services.vulnerabilities, method).side_effect = ValueError("Invalid query")
    response = client.get("/api/vulnerabilities" + endpoint)
    assert response.status_code == 422 and response.json()["detail"]["code"] == code


@pytest.mark.parametrize("can_read_cases", [True, False])
def test_vulnerability_hosts_protect_remediation_data_and_keep_asset_scope(http_services, can_read_cases):
    client, services, application = http_services
    if not can_read_cases:
        application.state.identity["permissions"].remove("remediation.read")
    services.vulnerabilities.hosts.return_value = {"rows": [{"asset_id": "a", "remediation": {"assignee": "private-owner"}}], "total": 1}
    response = client.get("/api/vulnerabilities/hosts?selector=id:v&asset_id=a&severity=high&source=os&limit=7&offset=2&sort_by=display_name&sort_dir=asc")
    assert response.status_code == 200
    assert ("remediation" in response.json()["rows"][0]) is can_read_cases
    arguments = services.vulnerabilities.hosts.call_args.kwargs
    assert arguments["asset_id"] == "a" and arguments["selector"] == "id:v"
    assert arguments["limit"] == 7 and arguments["offset"] == 2


def test_vulnerability_summary_list_trending_and_date_range(http_services):
    client, services, _ = http_services
    service = services.vulnerabilities
    filters = "?q=CVE&host_q=server&os=Linux&asset_type=host&asset_id=a&severity=high&source=os&has_fix=yes&fix_q=update"
    for endpoint, method in (("/summary", "summary"), ("", "list")):
        target = getattr(service, method)
        target.return_value = {"rows": []}
        assert client.get("/api/vulnerabilities" + endpoint + filters).status_code == 200
        assert target.call_args.kwargs["asset_id"] == "a"
        assert target.call_args.kwargs["has_fix"] == "yes"
    service.trending.return_value = {"rows": []}
    assert client.get("/api/vulnerabilities/trending?limit=5&context=docker").status_code == 200
    service.trending.assert_called_once_with(limit=5, context="docker")
    service.trends.return_value = {"rows": []}
    assert client.get("/api/vulnerabilities/trends?from=2026-09-01T00:00:00Z&to=2026-09-30T00:00:00Z&bucket=week").status_code == 200
    arguments = service.trends.call_args.kwargs
    assert arguments["from_at"].isoformat() == "2026-09-01T00:00:00+00:00"
    assert arguments["bucket"] == "week"