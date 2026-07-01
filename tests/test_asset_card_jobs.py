from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from fastapi import BackgroundTasks
from fastapi import HTTPException

from app import db
from app import main


class FakeSession:
    def close(self) -> None:
        pass


class SlowClient:
    delay = 0.1
    active = 0
    max_active = 0
    lock = threading.Lock()

    def __init__(self, auth) -> None:
        self.auth = auth
        self.session = FakeSession()

    def slow(self, value: int) -> int:
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(self.delay)
            return value
        finally:
            with self.lock:
                type(self).active -= 1


class FixtureAssetClient:
    def __init__(self, auth) -> None:
        self.auth = auth
        self.session = FakeSession()

    def create_asset_timeline_token(self, _token, _asset_id, _timestamp):
        return "timeline"

    def get_asset_tree_root(self, _token, _timeline):
        return {
            "objectId": "asset-1",
            "type": "Host",
            "displayName": "Fixture host",
            "data": {"hostname": "fixture"},
        }

    def get_asset_metadata(self, _token, _asset_type):
        return {"properties": [{"name": "hostname", "title": "Hostname", "type": "string"}]}

    def get_asset_vulnerabilities_header(self, _token, _timeline):
        return {"osSoftVulnerabilitiesCount": 4}

    def get_asset_vulnerability_groups(self, _token, collection_type, _timeline):
        suffix = "os" if collection_type == "HostOSVulnerabilities" else "soft"
        return {
            "level": "high",
            "vulnerabilitiesCount": 2,
            "items": [
                {
                    "name": suffix,
                    "vulnerabilitiesCount": 2,
                    "vulnerabilities": {"key": f"group-{suffix}"},
                }
            ],
        }

    def get_asset_vulnerability_collection(
        self,
        _token,
        _collection_type,
        _timeline,
        collection_id,
        *,
        limit,
        offset,
    ):
        if offset:
            return []
        return [
            {"id": f"{collection_id}-1", "name": "One", "cveName": "CVE-1"},
            {"id": f"{collection_id}-2", "name": "Two", "cveName": "CVE-2"},
        ][:limit]


class PartialFailureAssetClient(FixtureAssetClient):
    def get_asset_vulnerability_collection(
        self,
        token,
        collection_type,
        timeline,
        collection_id,
        *,
        limit,
        offset,
    ):
        if collection_id == "group-os":
            raise main.requests.RequestException("fixture child failure")
        return super().get_asset_vulnerability_collection(
            token,
            collection_type,
            timeline,
            collection_id,
            limit=limit,
            offset=offset,
        )


class AssetCardExecutorTests(unittest.TestCase):
    def test_one_hundred_requests_complete_under_two_seconds_with_limit_ten(self):
        SlowClient.active = 0
        SlowClient.max_active = 0
        with patch.object(main, "MpVmClient", SlowClient):
            executor = main.AssetCardRequestExecutor(
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                workers=10,
            )
            started = time.perf_counter()
            try:
                values = executor.map([
                    (lambda client, value=value: client.slow(value))
                    for value in range(100)
                ])
            finally:
                executor.close()
        elapsed = time.perf_counter() - started

        self.assertEqual(values, list(range(100)))
        self.assertLess(elapsed, 2.0)
        self.assertLessEqual(SlowClient.max_active, 10)
        self.assertGreaterEqual(SlowClient.max_active, 8)

    def test_cancellation_stops_scheduling_after_the_current_bounded_batch(self):
        cancel_event = threading.Event()
        with patch.object(main, "MpVmClient", SlowClient):
            executor = main.AssetCardRequestExecutor(
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                workers=2,
                cancel_event=cancel_event,
            )
            operations = [
                lambda _client: (cancel_event.set(), 0)[1],
                *[(lambda client, value=value: client.slow(value)) for value in range(1, 25)],
            ]
            try:
                with self.assertRaises(main.AssetCardBuildCancelled):
                    executor.map_settled(operations)
            finally:
                executor.close()

        self.assertEqual(executor.discovered, 2)

    def test_parallel_and_sequential_fixture_cards_match(self):
        auth = SimpleNamespace(api_url="https://fixture")
        main.ASSET_METADATA_CACHE.clear()
        sequential = main.build_asset_card(
            client=FixtureAssetClient(auth),
            token="token",
            asset_id="asset-1",
            timeline_timestamp=1,
            limit_per_collection=1000,
            max_items_per_collection=1000,
            max_depth=8,
        )
        main.ASSET_METADATA_CACHE.clear()
        with patch.object(main, "MpVmClient", FixtureAssetClient):
            executor = main.AssetCardRequestExecutor(auth=auth, token="token", workers=10)
            try:
                parallel = main.build_asset_card(
                    client=FixtureAssetClient(auth),
                    token="token",
                    asset_id="asset-1",
                    timeline_timestamp=1,
                    limit_per_collection=1000,
                    max_items_per_collection=1000,
                    max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()

        parallel_clean = main.sanitize_asset_card_for_response(parallel)
        sequential_clean = main.sanitize_asset_card_for_response(sequential)
        parallel_clean["stats"].pop("elapsed_ms", None)
        sequential_clean["stats"].pop("elapsed_ms", None)
        self.assertEqual(parallel_clean, sequential_clean)

    def test_child_request_failure_becomes_a_warning_and_other_groups_finish(self):
        auth = SimpleNamespace(api_url="https://fixture")
        main.ASSET_METADATA_CACHE.clear()
        with patch.object(main, "MpVmClient", PartialFailureAssetClient):
            executor = main.AssetCardRequestExecutor(auth=auth, token="token", workers=10)
            try:
                card = main.build_asset_card(
                    client=None,
                    token="token",
                    asset_id="asset-1",
                    timeline_timestamp=1,
                    limit_per_collection=1000,
                    max_items_per_collection=1000,
                    max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()

        self.assertEqual(card["vulnerabilities"]["stats"]["findings"], 2)
        self.assertTrue(any("fixture child failure" in warning for warning in card["stats"]["warnings"]))


class AssetCardJobApiTests(unittest.TestCase):
    def test_create_job_returns_before_background_task_runs(self):
        client = SimpleNamespace(auth=SimpleNamespace(api_url="https://fixture"))
        job = {"job_id": "job-1", "asset_id": "asset-1", "status": "queued", "stage": "queued"}
        background_tasks = BackgroundTasks()
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main.db, "get_active_asset_card_build_job", return_value=None),
            patch.object(main.db, "asset_card_exists", return_value=False),
            patch.object(main.db, "create_asset_card_build_job", return_value=job),
        ):
            response = main.create_asset_card_build_job(
                main.AssetCardBuildJobRequest(asset_id="asset-1"),
                background_tasks,
            )
        main.unregister_asset_card_build_job("job-1")

        self.assertEqual(response["job"]["status"], "queued")
        self.assertEqual(len(background_tasks.tasks), 1)

    def test_second_active_build_is_rejected(self):
        with patch.object(
            main.db,
            "get_active_asset_card_build_job",
            return_value={"job_id": "active", "status": "running"},
        ):
            with self.assertRaises(HTTPException) as raised:
                main.create_asset_card_build_job(
                    main.AssetCardBuildJobRequest(asset_id="asset-1"),
                    BackgroundTasks(),
                )
        self.assertEqual(raised.exception.status_code, 409)

    def test_slot_lost_during_atomic_insert_is_rejected_without_background_task(self):
        client = SimpleNamespace(auth=SimpleNamespace(api_url="https://fixture"))
        background_tasks = BackgroundTasks()
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(
                main.db,
                "get_active_asset_card_build_job",
                side_effect=[None, {"job_id": "winner", "status": "queued"}],
            ),
            patch.object(main.db, "asset_card_exists", return_value=False),
            patch.object(main.db, "create_asset_card_build_job", return_value=None),
        ):
            with self.assertRaises(HTTPException) as raised:
                main.create_asset_card_build_job(
                    main.AssetCardBuildJobRequest(asset_id="asset-1"),
                    background_tasks,
                )

        self.assertEqual(raised.exception.status_code, 409)
        self.assertEqual(raised.exception.detail["job"]["job_id"], "winner")
        self.assertEqual(len(background_tasks.tasks), 0)

    def test_cancelled_job_does_not_save_a_partial_card(self):
        cancel_event = threading.Event()
        cancel_event.set()
        with (
            patch.object(main.db, "start_asset_card_build_job", return_value={"status": "running"}),
            patch.object(main.db, "finish_asset_card_build_job") as finish,
            patch.object(main.db, "upsert_asset_card") as save,
        ):
            main.run_asset_card_build_job(
                job_id="job-cancelled",
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                request={"asset_id": "asset-1"},
                cancel_event=cancel_event,
            )

        save.assert_not_called()
        self.assertEqual(finish.call_args.kwargs["status"], "cancelled")

    def test_stage_progress_is_monotonic_and_completion_reaches_one_hundred(self):
        cancel_event = threading.Event()
        progress_values = []

        def build_fixture(*, stage_callback, **_kwargs):
            for stage in ("timeline", "root", "tree_and_vulnerabilities", "tree_ready", "assembling"):
                stage_callback(stage)
            return {
                "asset_id": "asset-1",
                "stats": {"nodes": 1, "collections": 2, "warnings": []},
                "vulnerabilities": {"stats": {"findings": 3}},
            }

        def record_progress(_job_id, **kwargs):
            progress_values.append(kwargs["progress_percent"])
            return kwargs

        with (
            patch.object(main.db, "start_asset_card_build_job", return_value={"status": "running"}),
            patch.object(main.db, "update_asset_card_build_job", side_effect=record_progress),
            patch.object(main.db, "upsert_asset_card", return_value={"asset_id": "asset-1"}),
            patch.object(main.db, "finish_asset_card_build_job") as finish,
            patch.object(main, "build_asset_card", side_effect=build_fixture),
        ):
            main.run_asset_card_build_job(
                job_id="job-progress",
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                request={"asset_id": "asset-1"},
                cancel_event=cancel_event,
            )

        self.assertEqual(progress_values, sorted(progress_values))
        self.assertEqual(progress_values[-1], 100)
        self.assertEqual(finish.call_args.kwargs["status"], "completed")


class AssetCardDatabaseTests(unittest.TestCase):
    def test_job_slot_conflict_is_silent_and_returns_none(self):
        result = MagicMock()
        result.fetchone.return_value = None
        connection = MagicMock()
        connection.execute.return_value = result
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            job = db.create_asset_card_build_job(
                "job-1",
                trace_id="trace-1",
                asset_id="asset-1",
                operation="create",
                request={"asset_id": "asset-1"},
            )

        self.assertIsNone(job)
        self.assertIn("ON CONFLICT DO NOTHING", connection.execute.call_args.args[0])

    def test_passport_link_reconciliation_uses_two_set_based_statements(self):
        connection = MagicMock()
        connection.execute.side_effect = [
            SimpleNamespace(rowcount=3),
            SimpleNamespace(rowcount=2),
        ]
        created = db.reconcile_asset_card_vulnerability_passport_links(
            connection,
            None,
            "2026-01-01T00:00:00+00:00",
            asset_id="asset-1",
        )

        self.assertEqual(created, 5)
        self.assertEqual(connection.execute.call_count, 2)

    def test_restart_interrupts_all_active_asset_card_jobs(self):
        connection = MagicMock()
        connection.execute.return_value = SimpleNamespace(rowcount=3)
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection
        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            interrupted = db.interrupt_active_asset_card_build_jobs()

        self.assertEqual(interrupted, 3)
        sql = connection.execute.call_args.args[0]
        self.assertIn("status = 'interrupted'", sql)
        self.assertIn("'queued', 'running', 'cancelling'", sql)

    def test_asset_findings_serialize_zero_one_and_multiple_passports(self):
        passport_sets = [
            [],
            [{"internal_id": "passport-1", "name": "One", "match_method": "cve"}],
            [
                {"internal_id": "passport-1", "name": "One", "match_method": "cve"},
                {"internal_id": "passport-2", "name": "Two", "match_method": "vulner_id"},
            ],
        ]
        for passports in passport_sets:
            with self.subTest(passport_count=len(passports)):
                stored_result = MagicMock()
                stored_result.fetchone.return_value = {
                    "vulnerabilities_json": '{"sources":[{"source":"os","groups":[]}]}'
                }
                groups_result = MagicMock()
                groups_result.fetchall.return_value = [{
                    "id": 7,
                    "source_type": "os",
                    "collection_type": "HostOSVulnerabilities",
                    "collection_id": "group-1",
                    "name": "OS",
                    "severity": "high",
                    "vulnerability_count": 1,
                    "cvss_score": 8.1,
                    "group_order": 0,
                    "truncated": False,
                    "group_json": "{}",
                }]
                findings_result = MagicMock()
                findings_result.fetchall.return_value = [{
                    "vulnerability_json": "{}",
                    "severity": "high",
                    "name": "Finding",
                    "cve_name": "CVE-2026-0001",
                    "description_key": None,
                    "cvss_score": 8.1,
                    "object_id": "object-1",
                    "vulnerability_id": "vulnerability-1",
                    "vulnerability_instance_id": "instance-1",
                    "passport_ids": [item["internal_id"] for item in passports],
                    "passports": passports,
                }]
                connection = MagicMock()
                connection.execute.side_effect = [stored_result, groups_result, findings_result]

                result = db.load_asset_card_vulnerabilities(connection, "asset-1")
                finding = result["sources"][0]["groups"][0]["items"][0]

                self.assertEqual(finding["passports"], passports)
                self.assertEqual(finding["passport_ids"], [item["internal_id"] for item in passports])

    def test_progress_decoder_clamps_database_values(self):
        base = {
            "job_id": "job-1",
            "trace_id": "trace-1",
            "asset_id": "asset-1",
            "status": "running",
            "stage": "saving",
        }
        self.assertEqual(db.decode_asset_card_build_job({**base, "progress_percent": -5})["progress_percent"], 0)
        self.assertEqual(db.decode_asset_card_build_job({**base, "progress_percent": 120})["progress_percent"], 100)
        self.assertEqual(db.decode_asset_card_build_job(base)["trace_id"], "trace-1")


if __name__ == "__main__":
    unittest.main()
