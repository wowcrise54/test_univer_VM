"""Exercise MP VM transport contracts entirely with synthetic HTTP responses."""

import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from app import mpvm_client as module
from app.mpvm_client import AuthConfig, MpVmApiError, MpVmClient


def response(payload=None, *, status=200, raw=None):
    result = requests.Response()
    result.status_code = status
    result._content = raw if raw is not None else json.dumps(payload).encode("utf-8")
    return result


@pytest.fixture
def client(monkeypatch):
    session = MagicMock(spec=requests.Session)
    monkeypatch.setattr(module, "build_session", lambda **kwargs: session)
    instance = MpVmClient(
        AuthConfig(
            api_url="https://vm.example/",
            token_url="https://vm.example/token",
            access_token="fixture-token",
            timeout=17,
            verify_tls=False,
        )
    )
    return instance


@pytest.fixture
def virtual_clock(monkeypatch):
    ticks = {"now": 0.0}

    def sleep(seconds):
        ticks["now"] += seconds

    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: ticks["now"], sleep=sleep))
    return sleep


@pytest.mark.parametrize("method", ["fetch_asset_grid_data", "fetch_asset_grid_group_data"])
@pytest.mark.parametrize("offset", [None, 0, 25])
def test_grid_pages_preserve_limits_and_explicit_zero_offset(client, method, offset):
    client.session.get.return_value = response({"items": []})
    assert getattr(client, method)("token", "query-token", limit=7, offset=offset) == {"items": []}
    params = client.session.get.call_args.kwargs["params"]
    assert params == {"limit": 7, "pdqlToken": "query-token", **({"offset": offset} if offset is not None else {})}
    assert client.session.get.call_args.kwargs["timeout"] == 17


def test_grid_token_keeps_asset_and_group_selection_and_reports_missing_token(client):
    client.session.post.return_value = response({"token": "grid-token"})
    assert (
        client.create_pdql_token(
            "token",
            "select fixture",
            utc_offset="+03:00",
            selected_group_ids=["g"],
            asset_ids=["a"],
            include_nested_groups=False,
        )
        == "grid-token"
    )
    body = client.session.post.call_args.kwargs["json"]
    assert body["additionalFilterParameters"] == {"groupIds": ["g"], "assetIds": ["a"]}
    assert body["utcOffset"] == "+03:00" and body["includeNestedGroups"] is False
    client.session.post.return_value = response({})
    with pytest.raises(MpVmApiError, match="does not contain token"):
        client.create_pdql_token("token", "select fixture")
    assert client.ensure_access_token() == "fixture-token"
    assert not MpVmClient._build_retry_adapter().max_retries.is_retry("POST", 503)


def test_csv_decodes_utf8_bom_and_exports_stream_without_empty_chunks(client, tmp_path):
    client.session.get.return_value = response(raw="\ufeffasset_id,name\na,Сервер\n".encode())
    assert client.fetch_csv("token", "grid-token").startswith("asset_id,name")
    streamed = response(raw=b"unused")
    streamed.iter_content = MagicMock(return_value=iter([b"first", b"", b"second"]))
    client.session.get.return_value = streamed
    output = tmp_path / "nested" / "export.csv"
    client.export_csv_file("token", "grid-token", output)
    assert output.read_bytes() == b"firstsecond"
    assert client.session.get.call_args.kwargs["stream"] is True
    streamed.iter_content.assert_called_once_with(chunk_size=1024 * 1024)


@pytest.mark.parametrize(
    "method,args",
    [
        ("create_dynamic_asset_group", {"name": "Group", "predicate": "fixture"}),
        ("remove_asset_groups", {"group_ids": ["g"]}),
        ("remove_assets", {"asset_ids": ["a"]}),
    ],
)
def test_remote_operations_require_an_operation_identifier(client, method, args):
    client.session.post.return_value = response({"operationId": "operation"})
    assert getattr(client, method)("token", **args) == "operation"
    client.session.post.return_value = response({})
    with pytest.raises(MpVmApiError, match="operationId"):
        getattr(client, method)("token", **args)


@pytest.mark.parametrize(
    "payload,expected",
    [(" group ", "group"), ({"groupId": "group"}, "group"), ({"id": "group"}, "group"), ({"result": "group"}, "group")],
)
def test_creation_result_accepts_supported_shapes_and_quotes_operation_id(client, payload, expected):
    client.session.get.return_value = response(payload)
    assert client.get_asset_group_creation_result("token", "operation/a") == expected
    assert "operation%2Fa" in client.session.get.call_args.args[0]


@pytest.mark.parametrize("payload", [None, [], {}, ""])
def test_creation_result_rejects_missing_group(client, payload):
    client.session.get.return_value = response(payload)
    with pytest.raises(MpVmApiError, match="Unexpected"):
        client.get_asset_group_creation_result("token", "operation")


def test_creation_result_handles_pending_and_malformed_json(client):
    client.session.get.return_value = response(status=202, raw=b"")
    assert client.get_asset_group_creation_result("token", "operation") is None
    client.session.get.return_value = response(raw=b"not-json")
    with pytest.raises(MpVmApiError, match="Cannot parse"):
        client.get_asset_group_creation_result("token", "operation")


def test_creation_polling_completes_and_times_out_using_virtual_time(client, virtual_clock):
    client.session.get.side_effect = [response(status=202, raw=b""), response({"groupId": "g"})]
    assert client.wait_for_asset_group_creation("token", "operation", timeout_seconds=5, poll_seconds=1) == "g"
    client.session.get.side_effect = None
    client.session.get.return_value = response(status=202, raw=b"")
    with pytest.raises(MpVmApiError, match="timed out"):
        client.wait_for_asset_group_creation("token", "operation", timeout_seconds=2, poll_seconds=1)


@pytest.mark.parametrize("already_cancelled", [True, False])
def test_creation_polling_honors_cancellation_before_and_during_wait(client, already_cancelled):
    client.session.get.return_value = response(status=202, raw=b"")
    cancellation = MagicMock()
    cancellation.is_set.return_value = already_cancelled
    cancellation.wait.return_value = True
    with pytest.raises(MpVmApiError, match="cancelled"):
        client.wait_for_asset_group_creation("token", "operation", cancel_event=cancellation)
    assert client.session.get.call_count == (0 if already_cancelled else 1)


def test_hierarchy_filters_invalid_rows_and_find_searches_nested_children(client):
    hierarchy = [{"id": "root", "children": [{"id": "child", "name": "Child"}, None]}, None, "invalid"]
    client.session.get.return_value = response(hierarchy)
    assert client.get_asset_group_hierarchy("token") == hierarchy[:1]
    assert MpVmClient.find_asset_group(hierarchy[:1], group_id="child")["name"] == "Child"
    assert MpVmClient.find_asset_group(hierarchy[:1], name="Child")["id"] == "child"
    assert MpVmClient.find_asset_group(hierarchy[:1], group_id="missing") is None
    client.session.get.return_value = response({})
    with pytest.raises(MpVmApiError, match="Unexpected"):
        client.get_asset_group_hierarchy("token")
    client.session.get.return_value = response(raw=b"malformed")
    with pytest.raises(MpVmApiError, match="Cannot parse"):
        client.get_asset_group_hierarchy("token")


def test_group_removal_waits_until_absent_and_reports_timeout(client, virtual_clock):
    client.session.get.side_effect = [response([{"id": "g"}]), response([])]
    assert client.wait_for_asset_group_absent("token", "g", timeout_seconds=5, poll_seconds=1) is None
    client.session.get.side_effect = None
    client.session.get.return_value = response([{"id": "g"}])
    with pytest.raises(MpVmApiError, match="not removed"):
        client.wait_for_asset_group_absent("token", "g", timeout_seconds=2, poll_seconds=1)


@pytest.mark.parametrize(
    "method,args",
    [
        ("get_vulnerability_passport", ("passport/a",)),
        ("get_asset_tree_root", ("timeline",)),
        ("get_asset_metadata", ("type/a",)),
        ("get_asset_tree_node", ("type/a", "node/a", "timeline")),
        ("get_asset_tree_collection", ("type/a", "node/a", "collection/a", "timeline")),
        ("get_asset_vulnerabilities_header", ("timeline/a",)),
        ("get_asset_vulnerability_groups", ("HostOSVulnerabilities", "timeline/a")),
        ("get_asset_vulnerability_groups", ("HostSoftVulnerabilities", "timeline/a")),
    ],
)
def test_card_and_passport_reads_validate_dictionary_payload(client, method, args):
    client.session.get.return_value = response({"safe": True})
    assert getattr(client, method)("token", *args) == {"safe": True}
    client.session.get.return_value = response([])
    with pytest.raises(MpVmApiError, match="Unexpected"):
        getattr(client, method)("token", *args)


@pytest.mark.parametrize(
    "payload,expected",
    [
        ([{"id": "v"}, None], [{"id": "v"}]),
        ({"items": [{"id": "v"}]}, [{"id": "v"}]),
        ({"data": [{"id": "v"}, "bad"]}, [{"id": "v"}]),
        ({"items": []}, []),
    ],
)
def test_vulnerability_collection_handles_list_and_envelope_shapes(client, payload, expected):
    client.session.get.return_value = response(payload)
    assert (
        client.get_asset_vulnerability_collection(
            "token", "HostOSVulnerabilities", "timeline/a", "collection/a", limit=5, offset=2
        )
        == expected
    )
    assert client.session.get.call_args.kwargs["params"] == {"offset": 2, "limit": 5}
    assert "timeline%2Fa" in client.session.get.call_args.args[0]


@pytest.mark.parametrize(
    "method,args",
    [
        ("get_asset_vulnerability_groups", ("unknown", "timeline")),
        ("get_asset_vulnerability_collection", ("unknown", "timeline", "collection")),
    ],
)
def test_unsupported_collection_type_is_rejected_before_http(client, method, args):
    with pytest.raises(ValueError, match="Unsupported"):
        getattr(client, method)("token", *args)
    client.session.get.assert_not_called()


def test_timeline_token_and_invalid_json_contract(client):
    client.session.get.return_value = response({"token": "timeline"})
    assert client.create_asset_timeline_token("token", "asset/a", 123) == "timeline"
    assert client.session.get.call_args.kwargs["params"] == {"datetime": 123}
    assert "asset%2Fa" in client.session.get.call_args.args[0]
    client.session.get.return_value = response({})
    with pytest.raises(MpVmApiError, match="does not contain token"):
        client.create_asset_timeline_token("token", "a", 123)
    client.session.get.return_value = response(raw=b"not-json")
    with pytest.raises(MpVmApiError, match="Cannot parse JSON"):
        client.get_json("token", "/read")


@pytest.mark.parametrize("method", ["list_credentials", "list_scopes", "list_scanner_profiles"])
def test_lookup_reads_reject_non_list_results(client, method):
    client.session.get.return_value = response([{"id": "a"}])
    assert getattr(client, method)("token") == [{"id": "a"}]
    client.session.get.return_value = response(None)
    with pytest.raises(MpVmApiError):
        getattr(client, method)("token")


def test_scanner_task_create_update_and_listing_accept_empty_responses(client):
    client.session.post.return_value = response({"id": "task"})
    assert client.create_scanner_task("token", {"name": "Task"}) == "task"
    client.session.post.return_value = response({})
    with pytest.raises(MpVmApiError, match="does not contain id"):
        client.create_scanner_task("token", {})
    client.session.post.return_value = response(raw=b"")
    assert client.list_remote_scanner_tasks("token", offset=2, limit=5, main_filter="scheduled") == {}
    assert client.session.post.call_args.kwargs["params"] == {"offset": 2, "limit": 5, "mainFilter": "scheduled"}
    client.session.post.return_value = response({"items": []})
    assert client.list_remote_scanner_tasks("token") == {"items": []}
    client.session.put.return_value = response(status=204, raw=b"")
    assert client.update_scanner_task("token", "task", {}) == {"id": "task"}
    client.session.put.return_value = response({"id": "task", "name": "Updated"})
    assert client.update_scanner_task("token", "task", {})["name"] == "Updated"


@pytest.mark.parametrize("mode", ["delete_v3", "put_v4"])
@pytest.mark.parametrize("state", ["empty", "json", "already-deleted", "failure"])
def test_scanner_deletion_is_idempotent_but_preserves_real_failures(client, mode, state):
    transport = client.session.put if mode == "put_v4" else client.session.delete
    transport.return_value = {
        "empty": response(status=204, raw=b""),
        "json": response({"id": "task"}),
        "already-deleted": response({"message": "Scanner task not found"}, status=404),
        "failure": response({"message": "Denied"}, status=403),
    }[state]
    if state == "failure":
        with pytest.raises(MpVmApiError) as failure:
            client.delete_scanner_task("token", "task", mode=mode)
        assert failure.value.status_code == 403
    else:
        result = client.delete_scanner_task("token", "task", mode=mode)
        assert result["id"] == "task"
        assert bool(result.get("alreadyDeleted")) is (state == "already-deleted")


@pytest.mark.parametrize("status,expected", [(200, (True, None)), (400, (False, '{"message":"invalid"}'))])
def test_scanner_validation_reports_input_errors(client, status, expected):
    client.session.get.return_value = response({"message": "invalid"}, status=status)
    assert client.validate_scanner_task("token", "task") == expected


@pytest.mark.parametrize("payload", [{"ok": True}, None, []])
def test_connection_check_start_tolerates_empty_and_non_dict_responses(client, payload):
    client.session.post.return_value = response(payload)
    assert client.start_scanner_task_connection_check("token", "task") == (payload if isinstance(payload, dict) else {})
    client.session.post.return_value = response(raw=b"not-json")
    assert client.start_scanner_task_connection_check("token", "task") == {}
    client.session.post.return_value = response(status=204, raw=b"")
    assert client.start_scanner_task_connection_check("token", "task") == {}


def test_run_jobs_are_paginated_without_truncating_full_batches(client):
    client.session.get.side_effect = [
        response({"items": [{"id": "a"}, {"id": "b"}]}),
        response({"items": [{"id": "c"}]}),
    ]
    assert client.get_all_run_jobs("token", "run", target_pattern="", orderby="startedAt desc", batch_size=2) == [
        {"id": "a"},
        {"id": "b"},
        {"id": "c"},
    ]
    params = [call.kwargs["params"] for call in client.session.get.call_args_list]
    assert params == [
        {"offset": 0, "limit": 2, "targetPattern": "", "orderby": "startedAt desc"},
        {"offset": 2, "limit": 2, "targetPattern": "", "orderby": "startedAt desc"},
    ]


@pytest.mark.parametrize(
    "payload,expected",
    [
        ({"totalItems": "3"}, 3),
        ({"totalCount": 2}, 2),
        ({"totalItems": "invalid"}, 0),
        ({"totalItems": None}, 0),
        ([], 0),
    ],
)
def test_job_error_counts_handle_unexpected_remote_values(client, payload, expected):
    client.session.get.return_value = response(payload)
    assert client.get_job_errors_count("token", "job") == expected


def test_stop_best_effort_does_not_mask_transport_failures(client):
    client.session.post.return_value = response(status=204, raw=b"")
    assert client.stop_scanner_task_best_effort("token", "task") == "stop requested"
    client.session.post.side_effect = requests.Timeout("fixture timeout")
    assert "fixture timeout" in client.stop_scanner_task_best_effort("token", "task")


def test_asset_removal_pending_and_invalid_results(client):
    client.session.get.return_value = response(status=202, raw=b" ")
    assert client.get_asset_removal_operation("token", "op")["status"] == "processing"
    for value in ([], "invalid"):
        client.session.get.return_value = response(value)
        with pytest.raises(MpVmApiError, match="Unexpected"):
            client.get_asset_removal_operation("token", "op")
    client.session.get.return_value = response(raw=b"not-json")
    with pytest.raises(MpVmApiError, match="Cannot parse"):
        client.get_asset_removal_operation("token", "op")


@pytest.mark.parametrize("payload", [{}, None, {"items": "invalid"}])
def test_vulnerability_collection_rejects_malformed_envelopes(client, payload):
    client.session.get.return_value = response(payload)
    with pytest.raises(MpVmApiError, match="Unexpected"):
        client.get_asset_vulnerability_collection("token", "HostSoftVulnerabilities", "timeline", "collection")


def test_tree_collection_forwards_explicit_partial_page_options(client):
    client.session.get.return_value = response({"data": []})
    assert client.get_asset_tree_collection(
        "token", "type", "node", "collection", "timeline", full=False, limit=3, offset=7
    ) == {"data": []}
    assert client.session.get.call_args.kwargs["params"] == {
        "full": "false",
        "limit": 3,
        "offset": 7,
        "token": "timeline",
    }


def test_task_runs_include_the_requested_time_boundary(client):
    client.session.get.return_value = response({"items": [{"id": "run"}]})
    assert client.get_task_runs("token", "task", time_from="2026-09-30T12:00:00Z") == [{"id": "run"}]
    assert client.session.get.call_args.kwargs["params"] == {
        "offset": 0,
        "limit": 1,
        "timeFrom": "2026-09-30T12:00:00Z",
    }


@pytest.mark.parametrize("method", ["start_scanner_task_with_retry", "start_connection_check_with_retry"])
def test_start_retries_only_eventual_consistency_not_permission_failures(client, virtual_clock, method):
    client.session.post.side_effect = [
        response({"message": "Scanner task not found"}, status=404),
        response({"id": "task", "status": "running"}),
    ]
    assert getattr(client, method)("token", "task", timeout_seconds=5, poll_seconds=1)["status"] == "running"
    assert client.session.post.call_count == 2
    client.session.post.reset_mock()
    client.session.post.side_effect = None
    client.session.post.return_value = response({"message": "Forbidden"}, status=403)
    with pytest.raises(MpVmApiError) as error:
        getattr(client, method)("token", "task", timeout_seconds=5, poll_seconds=1)
    assert error.value.status_code == 403 and client.session.post.call_count == 1
    client.session.post.reset_mock()
    client.session.post.return_value = response({"message": "Scanner task not found"}, status=404)
    with pytest.raises(MpVmApiError):
        getattr(client, method)("token", "task", timeout_seconds=1, poll_seconds=1)
    assert client.session.post.call_count == 2


def test_validation_retries_missing_task_but_returns_other_validation_errors(client, virtual_clock):
    client.session.get.side_effect = [
        response({"message": "Scanner task not found"}, status=400),
        response({"valid": True}),
    ]
    assert client.validate_scanner_task_with_retry("token", "task", timeout_seconds=5, poll_seconds=1) == (True, None)
    client.session.get.side_effect = None
    client.session.get.return_value = response({"message": "Invalid targets"}, status=400)
    result = client.validate_scanner_task_with_retry("token", "task", timeout_seconds=5, poll_seconds=1)
    assert result[0] is False and "Invalid targets" in result[1]
    client.session.get.return_value = response({"message": "Scanner task not found"}, status=400)
    assert client.validate_scanner_task_with_retry("token", "task", timeout_seconds=1, poll_seconds=1)[0] is False


def test_removal_waits_for_completion_and_reports_timeout_with_last_known_state(client, virtual_clock):
    client.session.get.side_effect = [response(status=202, raw=b""), response({"status": "completed"})]
    done = client.wait_for_asset_removal("token", "operation", timeout_seconds=5, poll_seconds=1)
    assert done[0] is True and done[2] == {"status": "completed"}
    client.session.get.side_effect = None
    client.session.get.return_value = response(status=202, raw=b"")
    timeout = client.wait_for_asset_removal("token", "operation", timeout_seconds=2, poll_seconds=1)
    assert timeout[0] is False and "timeout" in timeout[1]
    assert timeout[2]["status"] == "processing"


@pytest.mark.parametrize("already_cancelled", [True, False])
def test_removal_wait_honors_cancellation_without_claiming_success(client, already_cancelled):
    client.session.get.return_value = response(status=202, raw=b"")
    cancellation = MagicMock()
    cancellation.is_set.return_value = already_cancelled
    cancellation.wait.return_value = True
    result = client.wait_for_asset_removal("token", "operation", cancel_event=cancellation)
    assert result[0] is False and result[1] == "cancelled by operator"
    assert client.session.get.call_count == (0 if already_cancelled else 1)


@pytest.mark.parametrize(
    "run_error,job_error,job_status,clean,error_count,expected,message",
    [
        (None, None, "completed", False, 0, True, "ok"),
        ("warning", "yellow", "completed", False, 4, True, "ok"),
        ("red", None, "completed", False, 0, False, "errorStatus"),
        ("warning", None, "completed", True, 0, False, "errorStatus"),
        (None, "red", "completed", False, 0, False, "failed job(s)"),
        (None, None, "failed", False, 0, False, "failed job(s)"),
        (None, "warning", "completed", True, 0, False, "non-green"),
        (None, None, "completed", True, 1, False, "job_errors"),
        (None, None, "completed", True, 0, True, "ok"),
    ],
)
def test_task_completion_distinguishes_blocking_errors_warnings_and_clean_job_requirements(
    client, virtual_clock, run_error, job_error, job_status, clean, error_count, expected, message
):
    client.get_task_runs = MagicMock(return_value=[{"id": "run", "status": "completed", "errorStatus": run_error}])
    client.get_run_jobs = MagicMock(return_value=[{"id": "job", "status": job_status, "errorStatus": job_error}])
    client.get_job_errors_count = MagicMock(return_value=error_count)
    ok, detail = client.wait_for_task_success("token", "task", "from", 2, 1, require_clean_jobs=clean)
    assert ok is expected and message in detail
    if clean and run_error is None and job_error is None and job_status == "completed":
        client.get_job_errors_count.assert_called_once_with("token", "job")
    else:
        client.get_job_errors_count.assert_not_called()


def test_task_completion_polls_missing_and_running_runs_before_a_finished_run(client, virtual_clock):
    client.get_task_runs = MagicMock(
        side_effect=[
            [],
            [{"id": "run", "status": "running", "finishedAt": "premature"}],
            [{"id": "run", "status": "finished"}],
        ]
    )
    client.get_run_jobs = MagicMock(return_value=[])
    assert client.wait_for_task_success("token", "task", "from", 4, 1) == (True, "ok")
    assert client.get_task_runs.call_count == 3
    client.get_run_jobs.assert_called_once_with("token", "run")


@pytest.mark.parametrize("stop", [True, False])
def test_task_timeout_only_stops_when_requested(client, virtual_clock, stop):
    client.get_task_runs = MagicMock(return_value=[])
    client.stop_scanner_task_best_effort = MagicMock(return_value="stop requested")
    ok, message = client.wait_for_task_success("token", "task", "from", 2, 1, stop_on_timeout=stop)
    assert ok is False and "timeout" in message
    assert ("stop requested" in message) is stop
    assert client.stop_scanner_task_best_effort.call_count == int(stop)


@pytest.mark.parametrize("job", [{"status": "failed"}, {"errorStatus": "yellow"}])
def test_task_failure_details_remain_useful_for_jobs_without_identifiers(client, virtual_clock, job):
    client.get_task_runs = MagicMock(return_value=[{"id": "run", "status": "finished"}])
    client.get_run_jobs = MagicMock(return_value=[job])
    ok, detail = client.wait_for_task_success("token", "task", "from", 2, 1, require_clean_jobs=True)
    assert ok is False and json.dumps(job, separators=(",", ":")) in detail


def test_finished_task_requires_a_run_identifier(client, virtual_clock):
    client.get_task_runs = MagicMock(return_value=[{"status": "finished"}])
    ok, message = client.wait_for_task_success("token", "task", "from", 1, 1)
    assert not ok and "finished run does not contain id" in message


def green_connection_job(*targets):
    return {
        "runMode": "connectionCheck",
        "status": "completed",
        "targets": list(targets),
        "connectionCheckResults": [{"status": "success", "errors": []}],
    }


@pytest.mark.parametrize(
    "run,jobs,expected,detail",
    [
        ({"id": "run", "status": "finished"}, [], [], "no jobs with full connection success"),
        ({"id": "run", "status": "finished", "errorStatus": "red"}, [], [], "errorStatus"),
        ({"status": "finished"}, [], [], "run does not contain id"),
        ({"id": "run", "status": "finished"}, [green_connection_job("a", "a", "b")], ["a", "b"], "run run"),
        ({"id": "run", "status": "finished", "errorStatus": "red"}, [green_connection_job("a")], ["a"], "run run"),
    ],
)
def test_connection_precheck_uses_per_target_results_and_validates_run_envelope(
    client, virtual_clock, run, jobs, expected, detail
):
    client.get_task_runs = MagicMock(return_value=[run])
    client.get_run_jobs = MagicMock(return_value=jobs)
    targets, message = client.wait_for_connection_check_targets("token", "task", "from", 3, 0, 1, 17)
    assert targets == expected and detail in message
    if run.get("id"):
        client.get_run_jobs.assert_called_once_with(
            "token", "run", target_pattern="", orderby="startedAt desc", limit=17
        )


@pytest.mark.parametrize("has_targets", [True, False])
@pytest.mark.parametrize("stop_early", [True, False])
def test_precheck_keeps_partial_successes_when_stopped_or_timed_out(client, virtual_clock, has_targets, stop_early):
    client.get_task_runs = MagicMock(return_value=[{"id": "run", "status": "running"}])
    client.get_run_jobs = MagicMock(return_value=[green_connection_job("a")] if has_targets else [])
    client.stop_scanner_task_best_effort = MagicMock(return_value="stop requested")
    targets, message = client.wait_for_connection_check_targets(
        "token", "task", "from", 3, 1 if stop_early else 0, 1, 10
    )
    assert targets == (["a"] if has_targets else [])
    assert ("stopped run" if stop_early else "timeout") in message
    assert ("using 1 successful target(s)" in message) is has_targets
    assert client.stop_scanner_task_best_effort.call_count == int(stop_early)


def test_precheck_stops_after_deadline_even_if_the_task_has_no_run(client, virtual_clock):
    client.get_task_runs = MagicMock(return_value=[])
    client.stop_scanner_task_best_effort = MagicMock(return_value="stop failed")
    targets, message = client.wait_for_connection_check_targets("token", "task", "from", 3, 1, 1, 10)
    assert targets == [] and "no run found" in message and "stop failed" in message
    client.stop_scanner_task_best_effort.assert_called_once_with("token", "task")


def test_precheck_accumulates_targets_across_pages_and_waits_for_a_run(client, virtual_clock):
    client.get_task_runs = MagicMock(
        side_effect=[[], [{"id": "run", "status": "running"}], [{"id": "run", "status": "finished"}]]
    )
    client.get_run_jobs = MagicMock(side_effect=[[green_connection_job("a")], [green_connection_job("b", "a")]])
    assert client.wait_for_connection_check_targets("token", "task", "from", 4, 0, 1, 10) == (["a", "b"], "run run")


@pytest.mark.parametrize(
    "value,expected",
    [
        (None, False),
        ("", False),
        ("green", False),
        ("With errors", True),
        (["green", "red"], True),
        (["green"], False),
        ({"item": "warning"}, True),
        ({"item": "success"}, False),
        (0, False),
        (1, True),
    ],
)
def test_nested_error_status_accepts_only_known_non_error_values(value, expected):
    assert module.has_error_status(value) is expected


@pytest.mark.parametrize(
    "value,expected",
    [
        ("yellow", False),
        ("warning", False),
        ("with warnings", False),
        ("red", True),
        (["warning", "red"], True),
        ({"status": "warning"}, False),
        (1, True),
        (0, False),
    ],
)
def test_nested_blocking_error_status_allows_warnings_but_not_failures(value, expected):
    assert module.has_blocking_error_status(value) is expected


@pytest.mark.parametrize(
    "value,expected", [("success", True), ({"value": ["succeeded"]}, True), ("failed", False), (None, False)]
)
def test_success_status_is_normalized_across_supported_shapes(value, expected):
    assert module.has_success_status(value) is expected


@pytest.mark.parametrize(
    "change,reason",
    [
        ({"runMode": "scan"}, "non_connection_check"),
        ({"status": "running"}, "job_not_finished"),
        ({"status": "failed"}, "job_status_failed"),
        ({"errorStatus": "red"}, "job_error_status"),
        ({"connectionCheckResults": []}, "no_results"),
        ({"connectionCheckResults": [{"status": "success", "errors": ["error"]}]}, "result_not_success"),
        ({"targets": []}, "no_targets"),
    ],
)
def test_rejection_diagnostics_explain_why_a_precheck_job_did_not_count(change, reason):
    job = {**green_connection_job("a"), **change}
    assert module._connection_check_rejection_counts([job, job]) == {reason: 2}
    assert module._connection_check_rejection_counts([green_connection_job("a")]) == {}


@pytest.mark.parametrize("collection", [module.ensure_list, module.ensure_items])
def test_lookup_normalizers_reject_non_dictionary_entries(collection):
    with pytest.raises(MpVmApiError, match="Unexpected item"):
        collection([{"id": "good"}, "bad"], "lookups")
    with pytest.raises(MpVmApiError, match="Unexpected lookups"):
        collection({"items": "bad"}, "lookups")
    assert collection([], "lookups") == []


@pytest.mark.parametrize(
    "target,predicate",
    [
        ("192.0.2.1", "Host.@IpAddresses contains 192.0.2.1"),
        ("192.0.2.17/24", "Host.@IpAddresses.Item in 192.0.2.0/24"),
        ("2001:db8::1", "Host.@IpAddresses contains 2001:db8::1"),
        ("host'\\name", "Host.Fqdn = 'host\\'\\\\name'"),
    ],
)
def test_asset_resolution_queries_normalize_addresses_and_quote_host_names(target, predicate):
    assert module.build_asset_resolution_pdql(target) == f"filter({predicate}) | {module.ASSET_RESOLUTION_PDQL}"


def test_empty_asset_resolution_is_rejected_and_ip_filters_ignore_invalid_input():
    with pytest.raises(MpVmApiError, match="empty target"):
        module.build_asset_resolution_pdql("  ")
    assert module.build_asset_id_pdql_for_ips(["bad", ""]) == module.ASSET_ID_PDQL
    assert "[192.0.2.1, 2001:db8::1]" in module.build_asset_id_pdql_for_ips([" 192.0.2.1 ", "2001:db8::1", "bad"])


def test_csv_extractors_handle_empty_text_bom_dialects_invalid_ips_and_uuid_fallback():
    first = "00000000-0000-0000-0000-000000000001"
    second = "00000000-0000-0000-0000-000000000002"
    csv_text = f"\ufeffAsset ID;Host IP Address;note\n{first};192.0.2.1;ignored\n{first};invalid;{second}\n;2001:db8::1;{second}\n"
    assert module.extract_asset_ids_from_csv(csv_text) == [first, second]
    assert module.extract_ips_from_csv(csv_text) == ["192.0.2.1", "2001:db8::1"]
    assert module.extract_asset_ids_from_csv(" ") == []
    assert module.extract_ips_from_csv(" ") == []
    assert module.asset_id_from_csv_row({"id": None, "note": "bad"}) is None
    assert module.extract_uuid(None) is None
    assert module.normalize_csv_key(None) == ""
    # A one-column file has no delimiter for Sniffer to infer.
    assert module.extract_asset_ids_from_csv(f"Id\n{first}\n") == [first]


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://vm.example:999/api", "https://vm.example:3334/connect/token"),
        ("https://[2001:db8::1]/api", "https://[2001:db8::1]:3334/connect/token"),
    ],
)
def test_default_token_url_handles_explicit_ports_and_ipv6(url, expected):
    assert module.build_default_token_url(url) == expected


@pytest.mark.parametrize("url", ["", "vm.example", "https:///missing-host"])
def test_client_urls_require_a_scheme_and_host(url):
    with pytest.raises(MpVmApiError):
        module.normalize_url(url)


def test_credentials_in_the_api_url_are_rejected_and_compact_details_redact_secrets(monkeypatch):
    with pytest.raises(MpVmApiError, match="Credentials"):
        module.build_default_token_url("https://user:password@vm.example")
    detail = module.compact_json_summary({"access_token": "never-display-this", "long": "x" * 1500})
    assert "never-display-this" not in detail and len(detail) <= 1000
    monkeypatch.setattr(module, "redact", lambda data: object())
    assert module.compact_json_summary({}) == "unserializable response"
    assert module.format_limited_list(["a", "b"], limit=1) == "a, ... (+1 more)"


@pytest.mark.parametrize("error_count", [0, 1])
def test_clean_scan_job_selection_excludes_connection_checks_discovery_and_jobs_with_errors(client, error_count):
    jobs = [
        {"id": "green", "status": "finished", "errorStatus": "success"},
        {"status": "finished", "errorStatus": "green"},
        {"id": "discovery", "profile": {"name": "Host Discovery"}},
        {"runMode": "connectionCheck", "status": "finished"},
        {"status": "running"},
        {"status": "finished", "errorStatus": "red"},
    ]
    client.get_all_run_jobs = MagicMock(return_value=jobs)
    client.get_job_errors_count = MagicMock(return_value=error_count)
    tracked, successful = client.split_successful_run_jobs("token", "run", require_clean_jobs=True)
    assert [job.get("id") for job in tracked] == ["green", None, None, None, None]
    assert successful == ([jobs[0], jobs[1]] if not error_count else [jobs[1]])
    client.get_job_errors_count.assert_called_once_with("token", "green")


def test_validation_surfaces_non_validation_http_failures(client):
    client.session.get.return_value = response({"message": "forbidden"}, status=403)
    with pytest.raises(MpVmApiError, match="HTTP 403"):
        client.validate_scanner_task("token", "task")
    client.session.post.return_value = response([])
    with pytest.raises(MpVmApiError, match="Unexpected JSON payload"):
        client.start_scanner_task("token", "task")
    empty = response(status=500, raw=b"")
    with pytest.raises(MpVmApiError) as failure:
        client._raise_for_status(empty, "test")
    assert "non-JSON response" in str(failure.value)


@pytest.mark.parametrize("transport", ["windows", "ssh"])
def test_credential_overrides_are_optional_and_reject_unsupported_transports(transport):
    assert module.build_credential_overrides(None, transport) == {}
    assert module.build_windows_credential_overrides("credential") == module.build_credential_overrides(
        "credential", "windows"
    )
    with pytest.raises(ValueError, match="Unsupported credential transport"):
        module.build_credential_overrides("credential", "ftp")


@pytest.mark.parametrize(
    "payload,done,ok",
    [
        ({"state": "error"}, True, False),
        ({"status": "completed", "failedCount": 1}, True, False),
        ({"status": "completed"}, True, True),
        ({"status": "running"}, False, True),
    ],
)
def test_asset_removal_understands_terminal_states_without_count_fields(payload, done, ok):
    assert module.parse_asset_removal_operation(payload)[:2] == (done, ok)


@pytest.mark.parametrize("envelope", ["items", "scopes", "profiles", "credentials", "data", "values"])
def test_lookup_collection_supports_each_documented_envelope(envelope):
    assert module.ensure_list({envelope: [{"id": "value"}]}, "lookups") == [{"id": "value"}]


@pytest.mark.parametrize(
    "change",
    [
        {"targets": None},
        {"targets": [None, 1, "", "good"]},
        {"runMode": "scan"},
        {"status": "running"},
        {"connectionCheckResults": []},
        {"connectionCheckResults": [None]},
        {"connectionCheckResults": [{"status": "failed"}]},
    ],
)
def test_only_full_connection_results_produce_valid_string_targets(change):
    targets = module.extract_successful_connection_targets([{**green_connection_job("a"), **change}])
    assert targets == (["good"] if change.get("targets") == [None, 1, "", "good"] else [])
    assert module.status_strings(1) == set()
    assert module.is_scanner_task_not_found(None) is False
