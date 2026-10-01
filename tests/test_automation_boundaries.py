from concurrent.futures import Future
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from app import db
from app.automations.repository import AutomationRepository
from app.automations.service import AutomationService
from app.core.config import Settings


@pytest.fixture
def automation(monkeypatch):
    repository = MagicMock()
    repository.get_run_by_idempotency_key.return_value = None
    repository.get_runbook.return_value = {"runbook_id": "book", "name": "Inventory"}
    repository.create_notification.return_value = {"notification_id": "notification"}
    run = {
        "run_id": "run",
        "runbook_id": "book",
        "dry_run": False,
        "cancel_requested": False,
        "definition": {"steps": [{"step_id": "query", "type": "asset_query", "config": {}, "on_error": "stop"}]},
        "steps": [],
    }
    repository.get_run.return_value = run
    runner = MagicMock()
    runner.submit.side_effect = lambda *_args: Future()
    handler = MagicMock(return_value={"operation_id": "child"})
    register = MagicMock()
    monkeypatch.setattr(db, "register_operation", register)
    service = AutomationService(repository, runner, Settings(_env_file=None), handler, lambda: True)
    return SimpleNamespace(
        repository=repository, runner=runner, handler=handler, register=register, service=service, run=run
    )


@pytest.mark.parametrize(
    "definition,message",
    [
        ({}, "at least one"),
        ({"steps": []}, "at least one"),
        ({"steps": [{"type": "asset_query"}] * 51}, "more than 50"),
        ({"steps": ["invalid"]}, "must be an object"),
        ({"steps": [{"type": "unknown"}]}, "Unsupported step type"),
        ({"steps": [{"type": "asset_query", "step_id": " "}]}, "must be unique"),
        (
            {"steps": [{"type": "asset_query", "step_id": "x"}, {"type": "asset_query", "step_id": "x"}]},
            "must be unique",
        ),
        ({"steps": [{"type": "asset_query", "max_retries": -1}]}, "max_retries"),
        ({"steps": [{"type": "asset_query", "max_retries": 4}]}, "max_retries"),
        ({"steps": [{"type": "asset_query", "on_error": "ignore"}]}, "on_error"),
        (
            {"steps": [{"type": "asset_query", "config": {"nested": [{"PASSWORD": "synthetic"}]}}]},
            "nested\\[0\\].PASSWORD",
        ),
    ],
)
def test_invalid_definitions_are_rejected_before_persistence(definition, message, automation):
    with pytest.raises(ValueError, match=message):
        automation.service.create_runbook("Invalid", "", definition)
    automation.repository.create_runbook.assert_not_called()
    automation.repository.audit.assert_not_called()


@pytest.mark.parametrize("selection", ["all", "stale"])
@pytest.mark.parametrize("parallelism", [-1, 11])
def test_asset_card_batch_parallelism_rejects_out_of_range_values(selection, parallelism):
    with pytest.raises(ValueError, match="parallelism"):
        AutomationService.normalize_step_config(
            "asset_card_build", {"selection": selection, "parallelism": parallelism}
        )


def test_valid_definition_normalizes_nonobject_config_condition_and_batch_parallelism():
    definition = AutomationService.validate_definition(
        {
            "steps": [
                {"type": "asset_query", "config": "invalid", "condition": "invalid"},
                {"type": "asset_card_build", "config": {"selection": "all"}},
            ]
        }
    )
    assert definition["steps"][0]["config"] == {}
    assert definition["steps"][0]["condition"] is None
    assert definition["steps"][1]["config"]["parallelism"] == 10


@pytest.mark.parametrize(
    "operator,expected,result",
    [
        ("eq", 5, True),
        ("ne", 4, True),
        ("truthy", None, True),
        ("gt", 4, True),
        ("gte", 5, True),
        ("lt", 6, True),
        ("lte", 5, True),
        ("unknown", 1, False),
        ("gt", "invalid", False),
    ],
)
def test_conditions_compare_nested_saved_step_outputs(operator, expected, result):
    context = {"steps": {"source": {"result": {"count": 5}}}}
    condition = {"step_id": "source", "field": "result.count", "operator": operator, "value": expected}
    assert AutomationService._condition_matches(condition, context) is result
    assert (
        AutomationService._condition_matches({"step_id": "missing", "field": "a.b", "operator": "truthy"}, context)
        is False
    )


@pytest.mark.parametrize(
    "value,expected", [(None, {}), ({"count": 2}, {"count": 2}), ([1, 2], [1, 2]), ("invalid-json", {}), (123, {})]
)
def test_persisted_step_decoding_handles_legacy_native_json_and_damaged_payloads(value, expected):
    result = AutomationRepository._decode_step({"input_json": value, "output_json": value})
    assert result["input"] == expected
    assert result["output"] == expected


@pytest.mark.parametrize("exists", [False, True])
def test_runbook_updates_audit_only_existing_records(automation, exists):
    state = automation
    state.repository.update_runbook.return_value = {"runbook_id": "book"} if exists else None
    result = state.service.update_runbook("book", " Name ", " Description ", {"steps": [{"type": "asset_query"}]})
    assert bool(result) is exists
    assert state.repository.update_runbook.call_args.kwargs["name"] == "Name"
    assert state.repository.update_runbook.call_args.kwargs["description"] == "Description"
    assert state.repository.audit.call_count == int(exists)


def test_creation_and_missing_publication_preserve_audit_boundaries(automation):
    state = automation
    state.repository.create_runbook.return_value = {"runbook_id": "book"}
    result = state.service.create_runbook(" Name ", " Description ", {"steps": [{"type": "asset_query"}]})
    assert result["runbook_id"] == "book"
    state.repository.audit.assert_called_once_with("runbook.created", runbook_id="book")
    state.repository.audit.reset_mock()
    state.repository.get_runbook.return_value = None
    assert state.service.publish("missing", None) is None
    state.repository.publish_runbook.assert_not_called()
    state.repository.audit.assert_not_called()


@pytest.mark.parametrize(
    "version,exception",
    [
        (None, ValueError),
        (
            {
                "definition": {"steps": [{"type": "pdql_export", "config": {"delete_assets_after_export": True}}]},
                "destructive_approved": False,
            },
            PermissionError,
        ),
    ],
)
def test_unpublished_and_unapproved_versions_never_create_runs(automation, version, exception):
    state = automation
    state.repository.get_version.return_value = version
    with pytest.raises(exception):
        state.service.start_run("book")
    state.repository.create_run.assert_not_called()
    state.runner.submit.assert_not_called()


def test_missing_runbook_is_reported_without_submitting_a_worker(automation):
    state = automation
    state.repository.get_version.return_value = {"version": 1, "definition": state.run["definition"]}
    state.repository.create_run.return_value = state.run
    state.repository.get_runbook.return_value = None
    with pytest.raises(ValueError, match="Runbook not found"):
        state.service.start_run("book")
    state.runner.submit.assert_not_called()


@pytest.mark.parametrize("matches", [False, True])
def test_resume_keeps_completed_outputs_and_evaluates_following_conditions(automation, matches):
    state = automation
    state.run["definition"]["steps"] = [
        {"step_id": "saved", "type": "asset_query", "config": {}},
        {
            "step_id": "next",
            "type": "asset_query",
            "condition": {"step_id": "saved", "field": "count", "value": 3 if matches else 0},
        },
    ]
    state.run["steps"] = [{"step_index": 0, "step_id": "saved", "status": "completed", "output": {"count": 3}}]
    state.service.execute_run("run")
    assert state.handler.call_count == int(matches)
    assert state.repository.set_run_status.call_args.args == ("run", "completed")
    if matches:
        context = state.handler.call_args.args[2]
        assert context["steps"]["saved"] == {"count": 3}
        assert context["_is_cancel_requested"]() is False
        assert state.repository.set_step_status.call_args.kwargs["child_operation_id"] == "child"
    else:
        assert state.repository.set_step_status.call_args.args == ("run", 1, "skipped")
        assert state.repository.set_step_status.call_args.kwargs["output"] == {"reason": "condition"}


def test_operator_cancellation_before_step_never_calls_handler(automation):
    state = automation
    state.run["cancel_requested"] = True
    state.service.execute_run("run")
    state.handler.assert_not_called()
    state.repository.set_step_status.assert_called_once_with("run", 0, "cancelled")
    assert state.repository.set_run_status.call_args.args == ("run", "cancelled")


def test_handler_failure_stops_run_and_limits_persisted_error_length(automation):
    state = automation
    state.handler.side_effect = RuntimeError("e" * 2500)
    state.service.execute_run("run")
    assert state.repository.set_run_status.call_args.args == ("run", "failed")
    assert len(state.repository.set_run_status.call_args.kwargs["error"]) == 2000
    assert state.repository.create_notification.call_args.kwargs["level"] == "error"


def test_unexpected_configuration_failure_is_preserved_as_needs_attention(automation):
    state = automation
    state.run["definition"]["steps"][0].update(type="asset_card_build", config={"selection": "all", "parallelism": 99})
    state.service.execute_run("run")
    state.handler.assert_not_called()
    assert state.repository.set_run_status.call_args.args == ("run", "needs_attention")
    assert "parallelism" in state.repository.set_run_status.call_args.kwargs["error"]


def test_notification_step_queues_webhook_without_remote_execution(automation):
    state = automation
    state.service.settings = Settings(_env_file=None, automation_webhook_url="https://example.test/hook")
    state.run["definition"]["steps"][0].update(type="notification", config={"title": "Scan ready", "level": "warning"})
    state.service.execute_run("run")
    state.handler.assert_not_called()
    assert state.repository.set_step_status.call_args.kwargs["output"] == {"notification_id": "notification"}
    assert state.repository.queue_webhook.call_count == 2
    assert state.repository.create_notification.call_args_list[0].kwargs["title"] == "Scan ready"


def test_deleted_run_and_disabled_webhook_have_no_effects(automation):
    state = automation
    state.repository.get_run.return_value = None
    state.service.execute_run("missing")
    state.service.webhook_tick()
    state.repository.set_run_status.assert_not_called()
    state.repository.due_webhooks.assert_not_called()


def test_scheduler_deduplicates_workers_and_survives_tick_failure(automation):
    state = automation
    state.service.start_scheduler()
    state.service.start_scheduler()
    assert state.runner.submit.call_count == 1
    state.service.stop_scheduler()
    assert state.service._scheduler_stop.is_set()
    state.service._scheduler_future.set_result(None)
    state.service.start_scheduler()
    assert state.runner.submit.call_count == 2
    state.service._scheduler_stop = MagicMock()
    state.service._scheduler_stop.wait.side_effect = [False, False, True]
    state.service.scheduler_tick = MagicMock(side_effect=[RuntimeError("transient"), None])
    state.service.webhook_tick = MagicMock()
    state.service.housekeeping = MagicMock()
    state.service._scheduler_loop()
    assert state.service.scheduler_tick.call_count == 2
    state.service.webhook_tick.assert_called_once()
    state.service.housekeeping.assert_called_once()


def test_invalid_cron_expression_returns_actionable_error():
    with pytest.raises(ValueError, match="Invalid cron expression"):
        AutomationService.next_run("invalid", "UTC", after=datetime(2026, 1, 1, tzinfo=UTC))


def test_deleted_run_does_not_start_a_remote_step(automation):
    state = automation
    state.repository.get_run.side_effect = (
        lambda *_args, **_kwargs: state.run if state.repository.get_run.call_count == 1 else None
    )
    state.service.execute_run("run")
    state.handler.assert_not_called()
    state.repository.set_step_status.assert_not_called()
    state.repository.create_notification.assert_not_called()

    assert state.register.call_args.kwargs["status"] == "cancelled"
    assert state.register.call_args.kwargs["finished_at"] is not None


@pytest.mark.parametrize("published", [False, True])
def test_missed_schedule_advances_without_recreating_a_recorded_skip(automation, published):
    state = automation
    current = datetime(2026, 1, 1, 12, tzinfo=UTC)
    schedule = {
        "schedule_id": "scheduled",
        "runbook_id": "book",
        "next_run_at": "2026-01-01T11:00:00+00:00",
        "cron_expression": "0 * * * *",
        "timezone": "UTC",
    }
    state.repository.due_schedules.return_value = [schedule]
    state.repository.get_version.return_value = (
        {"version": 1, "definition": state.run["definition"]} if published else None
    )
    state.repository.get_run_by_idempotency_key.return_value = {"run_id": "previous-skip"}
    state.service.scheduler_tick(current)
    state.repository.create_run.assert_not_called()
    state.runner.submit.assert_not_called()
    assert state.repository.advance_schedule.call_args.kwargs["status"] == "skipped:missed"
    assert state.repository.advance_schedule.call_args.kwargs["next_run_at"] == "2026-01-01T13:00:00+00:00"
    assert state.repository.create_notification.call_count == int(published)
    if published:
        assert state.repository.audit.call_args.kwargs["run_id"] == "previous-skip"
    else:
        state.repository.audit.assert_not_called()


def test_conditions_can_compare_the_entire_saved_output():
    output = {"count": 2, "asset_ids": ["asset"]}
    assert AutomationService._condition_matches({"step_id": "query", "value": output}, {"steps": {"query": output}})


def test_scheduler_runs_without_an_optional_housekeeping_callback(automation):
    state = automation
    state.service.housekeeping = None
    state.service._scheduler_stop = MagicMock()
    state.service._scheduler_stop.wait.side_effect = [False, True]
    state.service.scheduler_tick = MagicMock()
    state.service.webhook_tick = MagicMock()
    state.service._scheduler_loop()
    state.service.scheduler_tick.assert_called_once()
    state.service.webhook_tick.assert_called_once()
