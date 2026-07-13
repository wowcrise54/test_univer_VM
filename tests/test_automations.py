from __future__ import annotations

import hashlib
import hmac
import unittest
from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import patch

from app.automations.service import AutomationService, AutomationStepCancelled
from app.core.config import Settings
from app.core.runtime import OperationRunner


class FakeRepository:
    def __init__(self) -> None:
        self.runbook = {
            "runbook_id": "runbook-1",
            "name": "Dangerous export",
            "draft": {
                "steps": [
                    {
                        "step_id": "export",
                        "type": "pdql_export",
                        "config": {"delete_assets_after_export": True},
                        "on_error": "stop",
                        "max_retries": 0,
                    }
                ]
            },
        }
        self.published = None
        self.schedules = []
        self.advanced = []
        self.created_runs = []
        self.deliveries = []
        self.finished_deliveries = []
        self.run = None
        self.run_statuses = []
        self.step_statuses = []
        self.notifications = []

    def get_runbook(self, _runbook_id):
        return self.runbook

    def publish_runbook(self, runbook_id, **values):
        self.published = {"runbook_id": runbook_id, **values}
        return self.published

    def audit(self, *_args, **_kwargs):
        return None

    def due_schedules(self, _now):
        return self.schedules

    def get_version(self, _runbook_id):
        return {"version": 1, "definition": self.runbook["draft"], "destructive_approved": True}

    def get_run_by_idempotency_key(self, _key):
        return None

    def has_active_run(self, _runbook_id):
        return False

    def create_run(self, **values):
        self.created_runs.append(values)
        return {"run_id": "run-1", **values}

    def advance_schedule(self, *args, **kwargs):
        self.advanced.append((args, kwargs))

    def due_webhooks(self, _now):
        return self.deliveries

    def finish_webhook_attempt(self, *args, **kwargs):
        self.finished_deliveries.append((args, kwargs))

    def get_run(self, _run_id, include_steps=True):
        return self.run

    def set_run_status(self, *args, **kwargs):
        self.run_statuses.append((args, kwargs))

    def set_step_status(self, *args, **kwargs):
        self.step_statuses.append((args, kwargs))

    def create_notification(self, **values):
        result = {"notification_id": "notification-1", **values}
        self.notifications.append(result)
        return result

    def queue_webhook(self, _notification_id):
        return None


def service(repository: FakeRepository, **settings) -> AutomationService:
    runner = OperationRunner({"automation-run": 1, "automation-scheduler": 1})
    return AutomationService(
        repository,
        runner,
        Settings(_env_file=None, **settings),
        lambda *_args: {},
        lambda: False,
    )


class DefinitionTests(unittest.TestCase):
    def test_normalizes_steps_and_limits_retries(self):
        definition = AutomationService.validate_definition(
            {"steps": [{"step_id": "scan", "type": "scanner_task_start", "config": {"task_id": "task-1"}}]}
        )
        self.assertEqual(definition["steps"][0]["on_error"], "stop")
        self.assertEqual(definition["steps"][0]["max_retries"], 0)
        with self.assertRaises(ValueError):
            AutomationService.validate_definition(
                {"steps": [{"step_id": "scan", "type": "scanner_task_start", "max_retries": 4}]}
            )
        with self.assertRaises(ValueError):
            AutomationService.validate_definition(
                {
                    "steps": [
                        {
                            "step_id": "unsafe",
                            "type": "notification",
                            "config": {"headers": {"authorization": "Bearer secret"}},
                        }
                    ]
                }
            )

    def test_destructive_publish_requires_exact_name(self):
        repository = FakeRepository()
        automation = service(repository)
        with self.assertRaises(PermissionError):
            automation.publish("runbook-1", "wrong")
        result = automation.publish("runbook-1", "Dangerous export")
        self.assertTrue(result["destructive_approved"])
        self.assertEqual(result["definition_hash"], AutomationService.definition_hash(result["definition"]))

    def test_pdql_export_without_delete_flag_is_normalized_to_safe_default(self):
        definition = AutomationService.validate_definition(
            {"steps": [{"step_id": "export", "type": "pdql_export", "config": {}}]}
        )

        self.assertIs(definition["steps"][0]["config"]["delete_assets_after_export"], False)
        self.assertFalse(AutomationService.is_destructive(definition))

        destructive = AutomationService.validate_definition(
            {
                "steps": [
                    {
                        "step_id": "export",
                        "type": "pdql_export",
                        "config": {"delete_assets_after_export": True},
                    }
                ]
            }
        )
        self.assertTrue(AutomationService.is_destructive(destructive))

    def test_legacy_pdql_export_without_delete_flag_executes_safely(self):
        repository = FakeRepository()
        repository.run = {
            "run_id": "run-1",
            "runbook_id": "runbook-1",
            "dry_run": False,
            "cancel_requested": False,
            "definition": {
                "steps": [
                    {
                        "step_id": "export",
                        "type": "pdql_export",
                        "config": {},
                        "on_error": "stop",
                        "max_retries": 0,
                    }
                ]
            },
            "steps": [{"step_index": 0, "step_id": "export", "status": "pending", "output": {}}],
        }
        received_configs = []
        automation = AutomationService(
            repository,
            OperationRunner({"automation-run": 1}),
            Settings(_env_file=None),
            lambda _step_type, config, *_args: received_configs.append(config) or {},
            lambda: False,
        )

        with patch("app.automations.service.db.register_operation"):
            automation.execute_run("run-1")

        self.assertEqual(received_configs, [{"delete_assets_after_export": False}])

    def test_conditions_read_previous_step_output(self):
        context = {"steps": {"scan": {"failed_count": 2}}}
        self.assertTrue(
            AutomationService._condition_matches(
                {"step_id": "scan", "field": "failed_count", "operator": "gt", "value": 0}, context
            )
        )
        self.assertFalse(
            AutomationService._condition_matches(
                {"step_id": "scan", "field": "failed_count", "operator": "eq", "value": 0}, context
            )
        )

    def test_dry_run_executes_all_steps_without_remote_calls(self):
        repository = FakeRepository()
        repository.run = {
            "run_id": "run-1",
            "runbook_id": "runbook-1",
            "dry_run": True,
            "cancel_requested": False,
            "definition": {
                "steps": [
                    {
                        "step_id": "scan",
                        "type": "scanner_task_start",
                        "config": {"task_id": "task-1"},
                        "on_error": "stop",
                        "max_retries": 0,
                    },
                    {
                        "step_id": "notify",
                        "type": "notification",
                        "config": {"title": "Done"},
                        "on_error": "stop",
                        "max_retries": 0,
                    },
                ]
            },
            "steps": [
                {"step_index": 0, "step_id": "scan", "status": "pending", "output": {}},
                {"step_index": 1, "step_id": "notify", "status": "pending", "output": {}},
            ],
        }
        automation = service(repository)
        with patch("app.automations.service.db.register_operation"):
            automation.execute_run("run-1")
        completed = [entry for entry in repository.step_statuses if entry[0][2] == "completed"]
        self.assertEqual(len(completed), 2)
        self.assertEqual(repository.run_statuses[-1][0][1], "completed")
        self.assertEqual(repository.notifications[-1]["event_type"], "automation.completed")

    def test_running_child_is_recorded_before_a_cancelled_step_finishes(self):
        repository = FakeRepository()
        repository.run = {
            "run_id": "run-1",
            "runbook_id": "runbook-1",
            "dry_run": False,
            "cancel_requested": False,
            "definition": {
                "steps": [{
                    "step_id": "asset-card",
                    "type": "asset_card_build",
                    "config": {"asset_id": "asset-1"},
                    "on_error": "stop",
                    "max_retries": 0,
                }]
            },
            "steps": [{"step_index": 0, "step_id": "asset-card", "status": "pending", "output": {}}],
        }

        def handler(_step_type, _config, context, *_args):
            context["_register_child_operation"]("postprocess-1")
            raise AutomationStepCancelled()

        automation = AutomationService(
            repository,
            OperationRunner({"automation-run": 1}),
            Settings(_env_file=None),
            handler,
            lambda: False,
        )
        with patch("app.automations.service.db.register_operation"):
            automation.execute_run("run-1")

        child_updates = [kwargs for _args, kwargs in repository.step_statuses if kwargs.get("child_operation_id")]
        self.assertEqual(child_updates[0]["child_operation_id"], "postprocess-1")
        self.assertTrue(any(args[2] == "cancelled" for args, _kwargs in repository.step_statuses))
        self.assertEqual(repository.run_statuses[-1][0][1], "cancelled")

    def test_continue_policy_records_warning_after_retry(self):
        repository = FakeRepository()
        repository.run = {
            "run_id": "run-1",
            "runbook_id": "runbook-1",
            "dry_run": False,
            "cancel_requested": False,
            "definition": {
                "steps": [
                    {
                        "step_id": "scan",
                        "type": "scanner_task_start",
                        "config": {"task_id": "task-1"},
                        "on_error": "continue",
                        "max_retries": 1,
                    }
                ]
            },
            "steps": [{"step_index": 0, "step_id": "scan", "status": "pending", "output": {}}],
        }
        runner = OperationRunner({"automation-run": 1})
        automation = AutomationService(
            repository,
            runner,
            Settings(_env_file=None),
            lambda *_args: (_ for _ in ()).throw(RuntimeError("remote failed")),
            lambda: False,
        )
        with patch("app.automations.service.db.register_operation"), patch("app.automations.service.time.sleep"):
            automation.execute_run("run-1")
        self.assertTrue(any(entry[0][2] == "warning" for entry in repository.step_statuses))
        self.assertEqual(repository.run_statuses[-1][0][1], "completed_with_warnings")

    def test_start_run_registers_operation_and_submits_worker(self):
        repository = FakeRepository()
        automation = service(repository)
        with (
            patch("app.automations.service.db.register_operation") as register,
            patch.object(automation.runner, "submit") as submit,
        ):
            result = automation.start_run("runbook-1", dry_run=True, idempotency_key="manual-1")
        self.assertEqual(result["run_id"], "run-1")
        self.assertEqual(repository.created_runs[0]["idempotency_key"], "manual-1")
        register.assert_called_once()
        submit.assert_called_once()


class SchedulerTests(unittest.TestCase):
    def test_unknown_timezone_is_rejected(self):
        with self.assertRaises(ValueError):
            AutomationService.next_run("0 2 * * *", "Mars/Olympus")

    def test_cron_uses_iana_timezone(self):
        next_run = AutomationService.next_run(
            "0 2 * * *", "Asia/Yekaterinburg", after=datetime(2026, 7, 8, 0, 0, tzinfo=UTC)
        )
        self.assertEqual(next_run, "2026-07-08T21:00:00+00:00")

    def test_missed_schedule_is_recorded_as_skipped(self):
        repository = FakeRepository()
        repository.schedules = [
            {
                "schedule_id": "schedule-1",
                "runbook_id": "runbook-1",
                "cron_expression": "* * * * *",
                "timezone": "UTC",
                "next_run_at": "2026-07-08T09:00:00+00:00",
            }
        ]
        automation = service(repository, automation_scheduler_poll_seconds=30)
        automation.scheduler_tick(datetime(2026, 7, 8, 10, 0, tzinfo=UTC))
        self.assertEqual(repository.created_runs[0]["status"], "skipped")
        self.assertEqual(repository.advanced[0][1]["status"], "skipped:missed")


class WebhookTests(unittest.TestCase):
    def test_webhook_url_requires_https(self):
        with self.assertRaises(ValueError):
            Settings(_env_file=None, automation_webhook_url="http://example.test/hook")

    def test_webhook_is_hmac_signed_and_marked_delivered(self):
        repository = FakeRepository()
        repository.deliveries = [
            {
                "delivery_id": "delivery-1",
                "notification_id": "event-1",
                "attempt": 0,
                "level": "error",
                "title": "Failed",
                "message": "Run failed",
                "event_type": "automation.failed",
                "runbook_id": "runbook-1",
                "run_id": "run-1",
                "details": {},
                "notification_created_at": "2026-07-08T10:00:00+00:00",
            }
        ]
        automation = service(
            repository,
            automation_webhook_url="https://hooks.example.test/mpvm",
            automation_webhook_secret="secret",
        )
        response = SimpleNamespace(status_code=204)
        with patch("app.automations.service.requests.post", return_value=response) as post:
            automation.webhook_tick(datetime(2026, 7, 8, 10, 0, tzinfo=UTC))
        body = post.call_args.kwargs["data"]
        expected = hmac.new(b"secret", body, hashlib.sha256).hexdigest()
        self.assertEqual(post.call_args.kwargs["headers"]["X-MPVM-Signature"], f"sha256={expected}")
        self.assertEqual(repository.finished_deliveries[0][1]["status"], "delivered")


if __name__ == "__main__":
    unittest.main()
