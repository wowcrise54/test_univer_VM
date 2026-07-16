from __future__ import annotations

import threading
import time
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import psycopg
from fastapi import BackgroundTasks
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app import db
from app import main


class FakeSession:
    def close(self) -> None:
        pass


DOCKER_HOST_ID = "1e41d929-8f00-0001-0000-000000000017"
DOCKER_IMAGE_ID = "sha256:add1c50cd8fced216ecbb1305669b1e8e24593ffd66e1b97bf7d48891891320c"
DOCKER_VULNERABILITY_INTERNAL_ID = "1de1a79b-4181-4001-0000-0000000007fd"


def docker_group_record(
    *, container: str = "agent-server.EDR-Application.EDR", group_key: str = "group-1",
) -> dict:
    return {
        "@Host": {
            "name": "srv-ptedr01.utmn.ru (10.252.206.115)",
            "id": DOCKER_HOST_ID,
            "deviceType": "Server",
        },
        "Docker": "Docker Engine 28.5.2",
        "Container": container,
        "$assetGridGroupKey": group_key,
    }


def docker_detail_record(
    *,
    source_id: str = "source-vulnerability-1",
    container: str = "agent-server.EDR-Application.EDR",
    container_id: str = "3747c21b8ffdde0004bc8d8d8f2f28a75ab0c6f8b91a88de139d220ffa90dd7d",
    image_id: str = DOCKER_IMAGE_ID,
    package: str = "apt (3.0.3)",
    cve: str = "CVE-2011-3374",
    severity: str = "low",
    internal_id: str = DOCKER_VULNERABILITY_INTERNAL_ID,
) -> dict:
    return {
        "@Host": {
            "name": "srv-ptedr01.utmn.ru (10.252.206.115)",
            "id": DOCKER_HOST_ID,
            "deviceType": "Server",
        },
        "Docker": "Docker Engine 28.5.2",
        "Container": container,
        "ContainerId": container_id,
        "ImageId": image_id,
        "Q.Package": package,
        "Q.Vulner": {
            "name": f"Уязвимость {cve}",
            "id": source_id,
            "kb": f"Debian_Project.Debian.{cve}",
            "severityRating": severity,
            "internalId": internal_id,
        },
        "Q.VulnerStatus": {"value": "new", "id": "1"},
        "Q.HowToFix": f"Исправление для {package}: https://security-tracker.debian.org/tracker/{cve}",
    }


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

    def _delay(self):
        with self.lock:
            type(self).active += 1
            type(self).max_active = max(type(self).max_active, type(self).active)
        try:
            time.sleep(self.delay)
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
        self._delay()
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
        "save_duration_ms",
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
            patch.object(main, "capture_vulnerability_snapshot") as capture_snapshot,
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
        capture_snapshot.assert_called_once_with("asset_card_build", "job-progress")


class AssetCardDatabaseTests(unittest.TestCase):
    def test_build_job_rejects_invalid_docker_pdql_with_api_error_code(self):
        with patch.object(
            main.app_auth, "get_session_user", return_value={"id": 1, "role": "operator"}
        ):
            response = TestClient(main.app).post(
                "/api/asset-cards/build-jobs",
                json={
                    "asset_id": "asset-1",
                    "docker_vulnerability_pdql": "select(@ImageSet as ImageName)",
                },
            )

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.json()["detail"]["code"], "INVALID_DOCKER_PDQL")

    def test_docker_pdql_contract_requires_grouped_container_fields(self):
        valid = main.validate_docker_vulnerability_pdql(main.DOCKER_VULNERABILITY_PDQL)
        self.assertIn("Host.Softs<DockerEngine>.Containers", valid)
        self.assertIn("| group(@Host, Docker, Container)", valid)

        with self.assertRaises(HTTPException) as caught:
            main.validate_docker_vulnerability_pdql("select(@ImageSet as ImageName)")

        self.assertEqual(caught.exception.status_code, 422)
        self.assertEqual(caught.exception.detail["code"], "INVALID_DOCKER_PDQL")
        self.assertIn("ContainerId", caught.exception.detail["required_fields"])
        self.assertIn("Q.HowToFix", caught.exception.detail["required_fields"])

        lookalikes_only = (
            "select(@Host, Value as Docker, ContainerId, ImageId, Q.Package, "
            "Q.VulnerStatus, Q.HowToFix) | group(@Host, Docker, ContainerId)"
        )
        with self.assertRaises(HTTPException) as lookalike_error:
            main.validate_docker_vulnerability_pdql(lookalikes_only)
        self.assertIn("Container", lookalike_error.exception.detail["message"])
        self.assertIn("Q.Vulner", lookalike_error.exception.detail["message"])

        missing_from_final_select = (
            "select(@Host, Docker, Container, ContainerId, ImageId, Q.Package, "
            "Q.Vulner, Q.VulnerStatus, Q.HowToFix) | "
            "select(@Host, Docker, Container, ImageId, Q.Package, Q.Vulner, "
            "Q.VulnerStatus, Q.HowToFix) | group(@Host, Docker, Container)"
        )
        with self.assertRaises(HTTPException) as final_select_error:
            main.validate_docker_vulnerability_pdql(missing_from_final_select)
        self.assertIn("ContainerId", final_select_error.exception.detail["message"])

    def test_docker_pdql_uses_asset_filter_and_still_supports_legacy_placeholder(self):
        asset_id = "1e5fa774-8780-0001-0000-000000000146"

        unchanged = main.render_docker_vulnerability_pdql(
            main.DOCKER_VULNERABILITY_PDQL, asset_id, "Host"
        )
        host_query = main.render_docker_vulnerability_pdql("filter(${ASSET_SELECTOR})", asset_id, "Host")

        self.assertEqual(unchanged, main.DOCKER_VULNERABILITY_PDQL)
        self.assertIn(f"Host.@Id = {asset_id}", host_query)
        self.assertNotIn(f'"{asset_id}"', host_query)
        with self.assertRaises(ValueError):
            main.render_docker_vulnerability_pdql(
                "filter(${ASSET_SELECTOR})", f"{asset_id}) | limit(0)", "Host"
            )

    def test_docker_container_records_win_over_structured_software_fallback(self):
        detail = docker_detail_record()
        expected = main.normalize_docker_vulnerability_record(detail)
        fallback = main.normalize_asset_vulnerability_item({
            "id": "fallback-finding-1",
            "vulnerabilityId": expected["vulnerability_id"],
            "cveName": expected["cve_name"],
            "imageId": expected["image_id"],
            "packageName": expected["package_name"],
            "packageVersion": expected["package_version"],
        })
        sources = [{
            "source": "software",
            "groups": [{
                "collection_id": "software",
                "items": [fallback],
            }],
        }]
        records = [detail]

        def remote_call(_operation, label):
            if label == "docker_pdql_token":
                return "pdql-token"
            if label == "docker_pdql_groups":
                return {"records": [docker_group_record()]}
            return {"records": records}

        source, warning = main.build_docker_vulnerability_source(
            token="token",
            asset_id="1e5fa774-8780-0001-0000-000000000146",
            asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL,
            max_items=100,
            sources=sources,
            remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(source["status"], "containers")
        self.assertEqual(source["reported_container_groups"], 1)
        self.assertEqual(source["vulnerabilities_count"], 1)
        self.assertEqual(source["groups"][0]["items"][0]["package_name"], "apt")
        self.assertEqual(source["groups"][0]["collection_id"], expected["container_id"])
        self.assertNotEqual(source["groups"][0]["collection_id"], expected["image_id"])
        self.assertEqual(sources[0]["groups"], [])

    def test_docker_dedupe_ignores_unstable_source_vulnerability_ids(self):
        sources = []
        records = [
            docker_detail_record(source_id="source-vulnerability-1"),
            docker_detail_record(source_id="source-vulnerability-2"),
            docker_detail_record(source_id="source-vulnerability-3"),
        ]

        def remote_call(_operation, label):
            if label == "docker_pdql_token":
                return "pdql-token"
            if label == "docker_pdql_groups":
                return {"records": [docker_group_record()]}
            return {"records": records}

        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id="1e5fa774-8780-0001-0000-000000000146", asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=100,
            sources=sources, remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(source["vulnerabilities_count"], 1)
        finding = source["groups"][0]["items"][0]
        self.assertTrue(finding["vulnerability_instance_id"].startswith("docker:"))
        self.assertEqual(finding["vulnerability_id"], DOCKER_VULNERABILITY_INTERNAL_ID)
        self.assertEqual(finding["source_vulnerability_instance_id"], "source-vulnerability-1")

    def test_docker_dedupe_keeps_two_versions_of_the_same_package(self):
        records = [
            docker_detail_record(source_id="source-vulnerability-1", package="apt (3.0.3)"),
            docker_detail_record(source_id="source-vulnerability-2", package="apt (3.0.4)"),
        ]

        def remote_call(_operation, label):
            if label == "docker_pdql_token":
                return "pdql-token"
            if label == "docker_pdql_groups":
                return {"records": [docker_group_record()]}
            return {"records": records}

        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id=DOCKER_HOST_ID, asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=100,
            sources=[], remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(source["vulnerabilities_count"], 2)
        self.assertEqual(
            {item["package_version"] for item in source["groups"][0]["items"]},
            {"3.0.3", "3.0.4"},
        )

    def test_docker_group_detail_record_is_normalized_for_storage(self):
        record = docker_detail_record()

        finding = main.normalize_docker_vulnerability_record(record)

        self.assertEqual(finding["asset_id"], DOCKER_HOST_ID)
        self.assertEqual(finding["container_name"], "agent-server.EDR-Application.EDR")
        self.assertEqual(finding["docker_engine"], "Docker Engine 28.5.2")
        self.assertEqual(finding["image_id"], DOCKER_IMAGE_ID)
        self.assertEqual(finding["package_name"], "apt")
        self.assertEqual(finding["package_version"], "3.0.3")
        self.assertEqual(finding["cve_name"], "CVE-2011-3374")
        self.assertEqual(finding["level"], "low")
        self.assertEqual(finding["status"], "new")
        self.assertEqual(finding["status_id"], "1")
        self.assertIn("security-tracker.debian.org", finding["how_to_fix"])
        self.assertEqual(finding["vulnerability_id"], DOCKER_VULNERABILITY_INTERNAL_ID)

    def test_same_image_in_two_containers_creates_two_findings_and_groups(self):
        first = main.normalize_docker_vulnerability_record(docker_detail_record())
        second = main.normalize_docker_vulnerability_record(docker_detail_record(
            container="storage-minio.EDR-Application.EDR",
            container_id="second-container-id",
            source_id="source-vulnerability-2",
        ))

        groups = main._docker_groups([first, second])

        self.assertEqual(len(groups), 2)
        self.assertEqual({group["collection_id"] for group in groups}, {
            first["container_id"], second["container_id"],
        })
        self.assertNotEqual(first["vulnerability_instance_id"], second["vulnerability_instance_id"])

    def test_docker_loader_reads_group_headers_then_group_details(self):
        labels: list[str] = []

        class Remote:
            def __init__(self) -> None:
                self.asset_ids = None

            def create_pdql_token(self, _token, pdql, *, asset_ids):
                self.asset_ids = asset_ids
                self.pdql = pdql
                return "pdql-token"

            def fetch_asset_grid_data(self, _token, _pdql_token, *, limit):
                self.group_limit = limit
                return {"records": [docker_group_record()]}

            def fetch_asset_grid_group_data(self, _token, _pdql_token, *, limit, offset):
                self.detail_request = {"limit": limit, "offset": offset}
                return {"records": [docker_detail_record()]}

        remote = Remote()

        def remote_call(operation, label):
            labels.append(label)
            return operation(remote)

        source, warning = main.build_docker_vulnerability_source(
            token="token",
            asset_id=DOCKER_HOST_ID,
            asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL,
            max_items=100,
            sources=[],
            remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(remote.asset_ids, [DOCKER_HOST_ID])
        self.assertEqual(remote.pdql, main.DOCKER_VULNERABILITY_PDQL)
        self.assertEqual(remote.group_limit, 1001)
        self.assertEqual(remote.detail_request, {"limit": 100, "offset": None})
        self.assertEqual(labels, [
            "docker_pdql_token", "docker_pdql_groups", "docker_pdql_group_page",
        ])
        self.assertEqual(source["status"], "containers")
        self.assertEqual(source["groups"][0]["name"], "agent-server.EDR-Application.EDR")

    def test_docker_loader_continues_short_pages_when_total_has_more_rows(self):
        first = docker_detail_record()
        second = docker_detail_record(
            source_id="source-vulnerability-2",
            package="coreutils (9.7-3)",
            cve="CVE-2017-18018",
            internal_id="1de1a7a3-e8c1-4001-0000-0000000008cc",
        )

        class Remote:
            def __init__(self) -> None:
                self.offsets = []

            def create_pdql_token(self, *_args, **_kwargs):
                return "pdql-token"

            def fetch_asset_grid_data(self, *_args, **_kwargs):
                return {"records": [docker_group_record()]}

            def fetch_asset_grid_group_data(self, *_args, limit, offset):
                self.offsets.append((limit, offset))
                rows = [first] if offset is None else [second]
                return {"records": rows, "totalCount": 2}

        remote = Remote()
        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id=DOCKER_HOST_ID, asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=10, sources=[],
            remote_call=lambda operation, _label: operation(remote),
        )

        self.assertIsNone(warning)
        self.assertEqual(remote.offsets, [(10, None), (9, 1)])
        self.assertEqual(source["vulnerabilities_count"], 2)
        self.assertFalse(source["groups"][0]["truncated"])

    def test_docker_loader_exact_total_at_limit_is_not_truncated(self):
        records = [
            docker_detail_record(),
            docker_detail_record(
                source_id="source-vulnerability-2",
                package="coreutils (9.7-3)",
                cve="CVE-2017-18018",
                internal_id="1de1a7a3-e8c1-4001-0000-0000000008cc",
            ),
        ]

        def remote_call(_operation, label):
            if label == "docker_pdql_token":
                return "pdql-token"
            if label == "docker_pdql_groups":
                return {"records": [docker_group_record()]}
            return {"records": records, "totalCount": 2}

        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id=DOCKER_HOST_ID, asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=2, sources=[],
            remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(source["vulnerabilities_count"], 2)
        self.assertFalse(source["groups"][0]["truncated"])

    def test_docker_loader_rejects_package_only_detail_rows(self):
        package_only = docker_detail_record()
        package_only["Q.Vulner"] = {}

        def remote_call(_operation, label):
            if label == "docker_pdql_token":
                return "pdql-token"
            if label == "docker_pdql_groups":
                return {"records": [docker_group_record()]}
            return {"records": [package_only]}

        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id=DOCKER_HOST_ID, asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=10, sources=[],
            remote_call=remote_call,
        )

        self.assertIsNone(warning)
        self.assertEqual(source["status"], "empty")
        self.assertEqual(source["vulnerabilities_count"], 0)

    def test_docker_fallback_is_used_without_breaking_the_card(self):
        normalized = main.normalize_asset_vulnerability_item({
            "id": "finding-2",
            "cveName": "CVE-2026-2",
            "image": {"id": "image-2", "repository": "team/worker", "tag": "latest"},
            "package": {"name": "openssl", "version": "3.0"},
        })
        sources = [{"source": "software", "groups": [{"collection_id": "soft", "items": [normalized]}]}]

        def unavailable(_operation, _label):
            raise RuntimeError("not supported")

        source, warning = main.build_docker_vulnerability_source(
            token="token", asset_id="1e5fa774-8780-0001-0000-000000000146", asset_type="Host",
            pdql_template=main.DOCKER_VULNERABILITY_PDQL, max_items=100,
            sources=sources, remote_call=unavailable,
        )

        self.assertEqual(source["status"], "fallback")
        self.assertTrue(source["fallback_used"])
        self.assertEqual(source["groups"][0]["name"], "team/worker:latest")
        self.assertIn("not supported", warning)

    def test_duplicate_vulnerability_instance_ids_are_removed_before_copy(self):
        first_group = {
            "source": "os",
            "collection_type": "HostOSVulnerabilities",
            "collection_id": "group-1",
            "items": [
                {"vulnerability_instance_id": "instance-1", "name": "first"},
                {"vulnerability_instance_id": None, "name": "without-id-1"},
            ],
        }
        second_group = {
            "source": "software",
            "collection_type": "HostSoftVulnerabilities",
            "collection_id": "group-2",
            "items": [
                {"vulnerability_instance_id": "instance-1", "name": "duplicate"},
                {"vulnerability_instance_id": None, "name": "without-id-2"},
            ],
        }

        findings, duplicate_count = db.deduplicate_asset_card_vulnerability_findings(
            [first_group, second_group]
        )

        self.assertEqual(duplicate_count, 1)
        self.assertEqual([finding["name"] for _, finding in findings], [
            "first",
            "without-id-1",
            "without-id-2",
        ])

    def asset_card_row(self):
        return {
            "id": 1,
            "asset_id": "asset-1",
            "display_name": "Fixture host",
            "asset_type": "Host",
            "fqdn": "fixture.local",
            "hostname": "fixture",
            "ip_address": "10.0.0.1",
            "os_name": "Linux",
            "os_version": "1",
            "vulnerability_level": "medium",
            "token_timestamp": 123,
            "root_json": '{"displayName":"Fixture host","type":"Host","data":{"hostname":"fixture"}}',
            "metadata_json": '{"Host":{"properties":[]}}',
            "stats_json": '{"nodes":2,"collections":1}',
            "first_seen": "2026-01-01T00:00:00+00:00",
            "last_seen": "2026-01-01T00:00:00+00:00",
        }

    def test_asset_card_summary_section_omits_heavy_arrays(self):
        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = self.asset_card_row()
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            card = db.get_asset_card_section("asset-1", "summary")

        self.assertEqual(card["loaded_sections"], ["summary"])
        self.assertEqual(card["display_name"], "Fixture host")
        self.assertNotIn("nodes", card)
        self.assertNotIn("collections", card)
        self.assertNotIn("table_rows", card)
        self.assertNotIn("vulnerabilities", card)

    def test_asset_card_configuration_section_does_not_load_vulnerabilities(self):
        connection = MagicMock()
        connection.execute.return_value.fetchone.return_value = self.asset_card_row()
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with (
            patch.object(db, "init_db"),
            patch.object(db, "connect", connect),
            patch.object(db, "load_asset_card_structure", return_value={
                "nodes": [{"path": "asset.node"}],
                "collections": [],
                "table_rows": [],
            }) as structure,
            patch.object(db, "load_asset_card_vulnerabilities") as vulnerabilities,
        ):
            card = db.get_asset_card_section("asset-1", "configuration")

        structure.assert_called_once()
        vulnerabilities.assert_not_called()
        self.assertEqual(card["loaded_sections"], ["summary", "configuration"])
        self.assertEqual(card["nodes"], [{"path": "asset.node"}])
        self.assertNotIn("vulnerabilities", card)

    def db_result(self, *, one=None, many=None):
        result = MagicMock()
        result.fetchone.return_value = one
        result.fetchall.return_value = many or []
        return result

    def test_asset_card_configuration_tree_returns_only_direct_children(self):
        connection = MagicMock()
        connection.execute.side_effect = [
            self.db_result(one=self.asset_card_row()),
            self.db_result(one={"count": 2}),
            self.db_result(many=[
                {
                    "path": "asset.software",
                    "title": "Software",
                    "display_name": None,
                    "name": "software",
                    "object_type": None,
                    "value_type": "Software",
                    "reported_count": 300,
                    "fetched_count": 200,
                    "kind": "collection",
                },
                {
                    "path": "asset.os",
                    "title": "OS",
                    "display_name": "Linux",
                    "name": None,
                    "object_type": "Host",
                    "value_type": None,
                    "reported_count": None,
                    "fetched_count": None,
                    "kind": "node",
                },
            ]),
            self.db_result(many=[{"path": "asset.os"}]),
        ]
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            tree = db.list_asset_card_configuration_tree("asset-1", limit=200)

        self.assertEqual([row["path"] for row in tree["rows"]], ["asset", "asset.software", "asset.os"])
        self.assertEqual(tree["rows"][1]["parent_path"], "asset")
        self.assertEqual(tree["rows"][1]["meta"], "200 / 300")
        self.assertTrue(tree["rows"][2]["has_children"])
        self.assertEqual(connection.execute.call_count, 4)

    def test_asset_card_configuration_detail_is_paginated(self):
        connection = MagicMock()
        connection.execute.side_effect = [
            self.db_result(one={"exists": 1}),
            self.db_result(one={"count": 2}),
            self.db_result(many=[
                {
                    "item_path": "asset.software[0]",
                    "display_name": "nginx",
                    "object_id": "soft-1",
                    "object_type": "Software",
                    "data_json": '{"name":"nginx","version":"1.25"}',
                    "item_json": '{"path":"asset.software[0]","display_name":"nginx","object_id":"soft-1","type":"Software","data":{"name":"nginx","version":"1.25"}}',
                },
            ]),
        ]
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            detail = db.get_asset_card_configuration_detail(
                "asset-1",
                path="asset.software",
                kind="collection",
                limit=1,
                offset=0,
            )

        self.assertEqual(detail["total"], 2)
        self.assertEqual(detail["limit"], 1)
        self.assertTrue(detail["has_more"])
        self.assertEqual(detail["rows"][0]["name"], "nginx")

    def test_legacy_asset_card_cache_is_hydrated_before_paged_reads(self):
        row = {
            **self.asset_card_row(),
            "nodes_json": '[{"path":"asset.os","title":"OS"}]',
            "collections_json": "[]",
            "table_rows_json": "[]",
            "vulnerabilities_json": "{}",
        }
        connection = MagicMock()
        connection.execute.return_value = self.db_result(
            one={"has_structure": False, "has_vulnerabilities": False},
        )

        with patch.object(db, "replace_asset_card_cache") as replace_cache:
            hydrated = db._hydrate_legacy_asset_card_cache(connection, "asset-1", row)

        self.assertTrue(hydrated)
        replace_cache.assert_called_once()
        self.assertEqual(replace_cache.call_args.args[1], "asset-1")
        self.assertEqual(replace_cache.call_args.args[2]["nodes"][0]["path"], "asset.os")

    def test_direct_child_filter_includes_collection_items(self):
        sql, params = db._direct_child_filter_sql("asset.software")

        self.assertIn("path ~ %s", sql)
        self.assertEqual(params[-1], r"^asset\.software\[\d+\]$")

    def test_asset_card_vulnerability_groups_do_not_return_findings(self):
        connection = MagicMock()
        connection.execute.side_effect = [
            self.db_result(one={"vulnerabilities_json": '{"header":{"os_soft_vulnerabilities_count":2},"sources":[{"source":"os","collection_type":"HostOSVulnerabilities","groups":[{"items":[{"name":"old"}]}]}]}'}),
            self.db_result(many=[{
                "id": 7,
                "source_type": "os",
                "collection_type": "HostOSVulnerabilities",
                "collection_id": "group-1",
                "name": "OS",
                "severity": "high",
                "vulnerability_count": 2,
                "cvss_score": 8.1,
                "group_order": 0,
                "truncated": False,
                "group_json": '{"items":[{"name":"old"}]}',
            }]),
        ]
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            result = db.list_asset_card_vulnerability_groups("asset-1")

        group = result["vulnerabilities"]["sources"][0]["groups"][0]
        self.assertEqual(group["collection_id"], "group-1")
        self.assertNotIn("items", group)

    def test_asset_card_vulnerability_findings_returns_selected_page(self):
        group_row = {
            "id": 7,
            "source_type": "os",
            "collection_type": "HostOSVulnerabilities",
            "collection_id": "group-1",
            "name": "OS",
            "severity": "high",
            "vulnerability_count": 2,
            "cvss_score": 8.1,
            "group_order": 0,
            "truncated": False,
            "group_json": "{}",
        }
        connection = MagicMock()
        connection.execute.side_effect = [
            self.db_result(one={"exists": 1}),
            self.db_result(one=group_row),
            self.db_result(one={"count": 2}),
            self.db_result(many=[{
                "vulnerability_json": "{}",
                "severity": "high",
                "name": "Finding",
                "cve_name": "CVE-2026-0001",
                "description_key": None,
                "cvss_score": 8.1,
                "object_id": "object-1",
                "vulnerability_id": "vulnerability-1",
                "vulnerability_instance_id": "instance-1",
                "passport_ids": ["passport-1"],
                "passports": [{"internal_id": "passport-1", "name": "Passport"}],
            }]),
        ]
        connect = MagicMock()
        connect.return_value.__enter__.return_value = connection

        with patch.object(db, "init_db"), patch.object(db, "connect", connect):
            result = db.list_asset_card_vulnerability_findings(
                "asset-1",
                source="os",
                collection_id="group-1",
                limit=1,
                offset=0,
            )

        self.assertEqual(result["total"], 2)
        self.assertTrue(result["has_more"])
        self.assertEqual(result["rows"][0]["cve_name"], "CVE-2026-0001")
        self.assertEqual(result["rows"][0]["passport_ids"], ["passport-1"])

    def test_database_circuit_breaker_skips_repeated_connect_attempts(self):
        db._close_database_circuit()
        try:
            with patch.object(
                db.DiagnosticConnection,
                "connect",
                side_effect=psycopg.OperationalError("connect failed"),
            ) as diagnostic_connect:
                with self.assertRaises(psycopg.OperationalError):
                    db.connect()
                started = time.perf_counter()
                with self.assertRaises(psycopg.OperationalError):
                    db.connect()
                elapsed = time.perf_counter() - started

            self.assertEqual(diagnostic_connect.call_count, 1)
            self.assertLess(elapsed, 0.05)
        finally:
            db._close_database_circuit()

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

    def test_passport_link_reconciliation_ranks_one_os_aware_match(self):
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

        self.assertEqual(created, 2)
        self.assertEqual(connection.execute.call_count, 2)
        delete_sql = connection.execute.call_args_list[0].args[0]
        ranking_sql = connection.execute.call_args_list[1].args[0]
        self.assertIn("DELETE FROM asset_card_vulnerability_passports", delete_sql)
        self.assertIn("ROW_NUMBER() OVER", ranking_sql)
        self.assertIn("PARTITION BY finding_id", ranking_sql)
        self.assertIn("passport.os_family = finding.os_family", ranking_sql)
        self.assertIn("cve_os_version", ranking_sql)
        self.assertIn("image_os_name", ranking_sql)
        self.assertIn("image_os_version", ranking_sql)

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
