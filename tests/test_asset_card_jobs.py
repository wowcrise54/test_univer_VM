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


class ParallelTreeAssetClient(FixtureAssetClient):
    delay = 0.02
    active = 0
    max_active = 0
    lock = threading.Lock()
    collection_names = tuple(f"collection{index}" for index in range(8))

    @classmethod
    def reset_metrics(cls):
        cls.active = 0
        cls.max_active = 0

    def _delay(self, factor=1.0):
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(self.delay * factor)
        finally:
            with self.lock:
                type(self).active -= 1

    def get_asset_tree_root(self, _token, _timeline):
        return {
            "objectId": "asset-1",
            "type": "Host",
            "displayName": "Parallel host",
            "data": {name: {"hasItems": True} for name in self.collection_names},
        }

    def get_asset_metadata(self, _token, asset_type):
        if asset_type == "Host":
            return {
                "properties": [
                    {"name": name, "title": name, "isCollection": True}
                    for name in self.collection_names
                ]
            }
        return {"properties": [{"name": "value", "title": "Value", "type": "string"}]}

    def get_asset_tree_collection(
        self,
        _token,
        _parent_type,
        _object_id,
        name,
        _timeline,
        *,
        full,
        limit,
        offset,
    ):
        collection_index = int(name.removeprefix("collection"))
        self._delay((8 - collection_index) / 4)
        self.assert_full = full
        items = [
            {
                "objectId": "shared-node" if index == 0 else f"{name}-node-{index}",
                "type": "Leaf",
                "displayName": f"{name} node {index}",
                "data": {"value": f"embedded-{index}"},
            }
            for index in range(4)
        ]
        return {"items": items[offset : offset + limit], "count": len(items)}

    def get_asset_tree_node(self, _token, asset_type, object_id, _timeline):
        self._delay()
        return {
            "objectId": object_id,
            "type": asset_type,
            "displayName": object_id,
            "data": {"value": object_id},
        }


class StreamingTreeAssetClient(FixtureAssetClient):
    slow_finished = threading.Event()
    nested_started_early = threading.Event()

    @classmethod
    def reset_metrics(cls):
        cls.slow_finished.clear()
        cls.nested_started_early.clear()

    def get_asset_tree_root(self, _token, _timeline):
        return {
            "objectId": "asset-1",
            "type": "Host",
            "displayName": "Streaming host",
            "data": {"slow": {"hasItems": True}, "fast": {"hasItems": True}},
        }

    def get_asset_metadata(self, _token, asset_type):
        if asset_type == "Host":
            return {"properties": [
                {"name": "slow", "isCollection": True},
                {"name": "fast", "isCollection": True},
            ]}
        if asset_type == "Branch":
            return {"properties": [{"name": "nested", "isCollection": True}]}
        return {"properties": []}

    def get_asset_tree_collection(
        self, _token, _parent_type, _object_id, name, _timeline, *, full, limit, offset
    ):
        if name == "slow":
            time.sleep(0.25)
            type(self).slow_finished.set()
            return {"items": [], "count": 0}
        if name == "fast":
            time.sleep(0.01)
            return {"items": [{"objectId": "branch-1", "type": "Branch", "displayName": "Branch"}], "count": 1}
        if name == "nested":
            if not type(self).slow_finished.is_set():
                type(self).nested_started_early.set()
            return {"items": [], "count": 0}
        return {"items": [], "count": 0}

    def get_asset_tree_node(self, _token, asset_type, object_id, _timeline):
        time.sleep(0.01)
        return {
            "objectId": object_id,
            "type": asset_type,
            "displayName": object_id,
            "data": {"nested": {"hasItems": True}},
        }


class VulnerabilityPagingClient(FixtureAssetClient):
    active = 0
    max_active = 0
    lock = threading.Lock()

    @classmethod
    def reset_metrics(cls):
        cls.active = 0
        cls.max_active = 0

    def get_asset_vulnerability_groups(self, _token, collection_type, _timeline):
        suffix = "os" if collection_type == "HostOSVulnerabilities" else "soft"
        return {
            "vulnerabilitiesCount": 8,
            "items": [{
                "name": suffix,
                "vulnerabilitiesCount": 8,
                "vulnerabilities": {"key": f"group-{suffix}"},
            }],
        }

    def get_asset_vulnerability_collection(
        self, _token, _collection_type, _timeline, collection_id, *, limit, offset
    ):
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(0.03)
            items = [
                {"id": f"{collection_id}-{index}", "name": str(index), "cveName": f"CVE-{index}"}
                for index in range(8)
            ]
            return items[offset : offset + limit]
        finally:
            with self.lock:
                type(self).active -= 1


class MetadataParallelClient(ParallelTreeAssetClient):
    metadata_active = 0
    metadata_max_active = 0
    metadata_lock = threading.Lock()

    @classmethod
    def reset_metrics(cls):
        super().reset_metrics()
        cls.metadata_active = 0
        cls.metadata_max_active = 0

    def get_asset_metadata(self, token, asset_type):
        if asset_type == "Host":
            return super().get_asset_metadata(token, asset_type)
        with self.metadata_lock:
            type(self).metadata_active += 1
            type(self).metadata_max_active = max(type(self).metadata_max_active, type(self).metadata_active)
        try:
            time.sleep(0.03)
            return {"properties": [{"name": "value", "type": "string"}]}
        finally:
            with self.metadata_lock:
                type(self).metadata_active -= 1

    def get_asset_tree_collection(
        self, _token, _parent_type, _object_id, name, _timeline, *, full, limit, offset
    ):
        collection_index = int(name.removeprefix("collection"))
        items = [
            {
                "objectId": f"{name}-node-{index}",
                "type": f"Type{collection_index}_{index}",
                "displayName": f"{name} node {index}",
            }
            for index in range(4)
        ]
        return {"items": items[offset : offset + limit], "count": len(items)}


def semantic_card(card):
    cleaned = main.sanitize_asset_card_for_response(card)
    stats = cleaned.get("stats") or {}
    for key in (
        "elapsed_ms",
        "stage_duration_ms",
        "peak_active_requests",
        "queue_wait_ms",
        "request_counts",
        "request_duration_ms",
        "request_latency_ms",
        "save_duration_ms",
        "scheduler_idle_ms",
        "critical_path_ms",
        "concurrency_min",
        "concurrency_initial",
        "concurrency_max",
        "concurrency_final",
        "concurrency_changes",
        "throttle_events",
        "concurrency_mode",
        "configured_workers",
        "dispatcher_idle_ms",
        "metadata_duration_ms",
        "requests_per_second",
    ):
        stats.pop(key, None)
    return cleaned


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

    def test_executor_enforces_one_shared_initial_window_across_all_submitters(self):
        SlowClient.active = 0
        SlowClient.max_active = 0
        with patch.object(main, "MpVmClient", SlowClient):
            executor = main.AssetCardRequestExecutor(
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                workers=16,
                initial_workers=8,
                min_workers=4,
            )
            try:
                futures = [executor.submit(lambda client, value=value: client.slow(value)) for value in range(16)]
                values = [future.result() for future in futures]
            finally:
                executor.close()

        self.assertEqual(values, list(range(16)))
        self.assertLessEqual(SlowClient.max_active, 8)
        self.assertEqual(executor.telemetry()["concurrency_final"], 10)

    def test_fixed_mode_runs_sixty_four_requests_without_adaptive_throttling(self):
        SlowClient.active = 0
        SlowClient.max_active = 0
        with patch.object(main, "MpVmClient", SlowClient):
            executor = main.AssetCardRequestExecutor(
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                workers=64,
                concurrency_mode="fixed",
            )
            try:
                values = executor.map([
                    (lambda client, value=value: client.slow(value))
                    for value in range(64)
                ])
            finally:
                executor.close()

        self.assertEqual(values, list(range(64)))
        self.assertEqual(SlowClient.max_active, 64)
        telemetry = executor.telemetry()
        self.assertEqual(telemetry["concurrency_mode"], "fixed")
        self.assertEqual(telemetry["configured_workers"], 64)
        self.assertEqual(telemetry["concurrency_final"], 64)

    def test_cancellation_stops_scheduling_without_filling_another_window(self):
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

        self.assertGreaterEqual(executor.discovered, 1)
        self.assertLessEqual(executor.discovered, 2)

    def test_sliding_window_schedules_after_fast_completion_without_waiting_for_slow_head(self):
        slow_finished = threading.Event()
        third_started_before_slow_finished = threading.Event()

        def operation(_client, value):
            if value == 0:
                time.sleep(0.2)
                slow_finished.set()
            else:
                if value == 2 and not slow_finished.is_set():
                    third_started_before_slow_finished.set()
                time.sleep(0.01)
            return value

        with patch.object(main, "MpVmClient", SlowClient):
            executor = main.AssetCardRequestExecutor(
                auth=SimpleNamespace(api_url="https://fixture"),
                token="token",
                workers=2,
            )
            try:
                values = executor.map([
                    (lambda client, value=value: operation(client, value))
                    for value in range(8)
                ])
            finally:
                executor.close()

        self.assertEqual(values, list(range(8)))
        self.assertTrue(third_started_before_slow_finished.is_set())

    def test_adaptive_controller_grows_and_halves_on_throttle(self):
        controller = main.AdaptiveConcurrencyController(minimum=4, initial=8, maximum=16)
        for _window in range(4):
            for _request in range(controller.sample_size):
                controller.observe(100, None)
        self.assertEqual(controller.window(), 16)

        controller.observe(100, main.MpVmApiError("MP VM API failed: HTTP 429"))
        self.assertEqual(controller.window(), 8)
        telemetry = controller.telemetry()
        self.assertEqual(telemetry["throttle_events"], 1)
        self.assertEqual(telemetry["concurrency_changes"][-1]["reason"], "http_429")
        self.assertEqual(main.adaptive_failure_reason(main.MpVmApiError("HTTP 503")), "http_503")
        self.assertEqual(main.adaptive_failure_reason(main.requests.Timeout("slow")), "timeout")

        fixed = main.FixedConcurrencyController(64)
        fixed.observe(5000, main.MpVmApiError("HTTP 429"))
        fixed.observe(5000, main.MpVmApiError("HTTP 503"))
        self.assertEqual(fixed.window(), 64)

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

        self.assertEqual(semantic_card(parallel), semantic_card(sequential))

    def test_parallel_tree_pipeline_matches_sequential_and_uses_eight_workers(self):
        auth = SimpleNamespace(api_url="https://parallel-fixture")
        main.ASSET_METADATA_CACHE.clear()
        ParallelTreeAssetClient.reset_metrics()
        sequential_started = time.perf_counter()
        sequential = main.build_asset_card(
            client=ParallelTreeAssetClient(auth),
            token="token",
            asset_id="asset-1",
            timeline_timestamp=1,
            limit_per_collection=2,
            max_items_per_collection=4,
            max_depth=8,
        )
        sequential_elapsed = time.perf_counter() - sequential_started

        main.ASSET_METADATA_CACHE.clear()
        ParallelTreeAssetClient.reset_metrics()
        with patch.object(main, "MpVmClient", ParallelTreeAssetClient):
            executor = main.AssetCardRequestExecutor(auth=auth, token="token", workers=8)
            parallel_started = time.perf_counter()
            try:
                parallel = main.build_asset_card(
                    client=None,
                    token="token",
                    asset_id="asset-1",
                    timeline_timestamp=1,
                    limit_per_collection=2,
                    max_items_per_collection=4,
                    max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()
            parallel_elapsed = time.perf_counter() - parallel_started

        self.assertEqual(semantic_card(parallel), semantic_card(sequential))
        self.assertEqual(parallel["stats"]["collection_requests"], 16)
        self.assertEqual(parallel["stats"]["node_requests"], 25)
        self.assertLessEqual(ParallelTreeAssetClient.max_active, 8)
        self.assertGreaterEqual(ParallelTreeAssetClient.max_active, 6)
        self.assertLess(parallel_elapsed, sequential_elapsed / 2)

    def test_fast_nested_branch_does_not_wait_for_slow_sibling_collection(self):
        auth = SimpleNamespace(api_url="https://streaming-fixture")
        main.ASSET_METADATA_CACHE.clear()
        StreamingTreeAssetClient.reset_metrics()
        with patch.object(main, "MpVmClient", StreamingTreeAssetClient):
            executor = main.AssetCardRequestExecutor(auth=auth, token="token", workers=4)
            try:
                card = main.build_asset_card(
                    client=None, token="token", asset_id="asset-1", timeline_timestamp=1,
                    limit_per_collection=100, max_items_per_collection=100, max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()

        self.assertTrue(StreamingTreeAssetClient.nested_started_early.is_set())
        self.assertEqual(card["stats"]["collections"], 3)

    def test_vulnerability_pages_share_the_request_pool(self):
        auth = SimpleNamespace(api_url="https://vulnerability-pages")
        main.ASSET_METADATA_CACHE.clear()
        VulnerabilityPagingClient.reset_metrics()
        with patch.object(main, "MpVmClient", VulnerabilityPagingClient):
            executor = main.AssetCardRequestExecutor(auth=auth, token="token", workers=8)
            try:
                card = main.build_asset_card(
                    client=None, token="token", asset_id="asset-1", timeline_timestamp=1,
                    limit_per_collection=2, max_items_per_collection=8, max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()

        self.assertEqual(card["vulnerabilities"]["stats"]["findings"], 16)
        self.assertEqual(card["stats"]["vulnerability_collection_requests"], 8)
        self.assertGreaterEqual(VulnerabilityPagingClient.max_active, 4)

    def test_metadata_for_new_types_is_loaded_in_parallel(self):
        auth = SimpleNamespace(api_url="https://metadata-parallel")
        main.ASSET_METADATA_CACHE.clear()
        MetadataParallelClient.reset_metrics()
        with patch.object(main, "MpVmClient", MetadataParallelClient):
            executor = main.AssetCardRequestExecutor(
                auth=auth,
                token="token",
                workers=32,
                concurrency_mode="fixed",
            )
            try:
                card = main.build_asset_card(
                    client=None, token="token", asset_id="asset-1", timeline_timestamp=1,
                    limit_per_collection=4, max_items_per_collection=4, max_depth=8,
                    request_executor=executor,
                )
            finally:
                executor.close()

        self.assertEqual(card["stats"]["metadata_requests"], 33)
        self.assertGreaterEqual(MetadataParallelClient.metadata_max_active, 16)

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
    def test_create_job_is_submitted_to_common_runner(self):
        client = SimpleNamespace(auth=SimpleNamespace(api_url="https://fixture"))
        job = {"job_id": "job-1", "asset_id": "asset-1", "status": "queued", "stage": "queued"}
        background_tasks = BackgroundTasks()
        with (
            patch.object(main, "require_mpvm", return_value=(client, "token")),
            patch.object(main.db, "get_active_asset_card_build_job", return_value=None),
            patch.object(main.db, "asset_card_exists", return_value=False),
            patch.object(main.db, "create_asset_card_build_job", return_value=job),
            patch.object(main.WORKER_RUNNER, "submit", return_value=True) as submit,
        ):
            response = main.create_asset_card_build_job(
                main.AssetCardBuildJobRequest(asset_id="asset-1"),
                background_tasks,
            )
        main.unregister_asset_card_build_job("job-1")

        self.assertEqual(response["job"]["status"], "queued")
        self.assertEqual(len(background_tasks.tasks), 0)
        submit.assert_called_once()
        self.assertEqual(submit.call_args.args[0], "asset-card")

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
    def test_copy_rows_streams_every_row_in_one_copy_operation(self):
        writer = MagicMock()
        cursor = MagicMock()
        cursor.copy.return_value.__enter__.return_value = writer
        rows = [(1, "one"), (2, "two"), (3, "three")]

        db.copy_rows(cursor, "asset_card_nodes", ("id", "title"), rows)

        cursor.copy.assert_called_once_with("COPY asset_card_nodes (id, title) FROM STDIN")
        self.assertEqual([call.args[0] for call in writer.write_row.call_args_list], rows)

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
