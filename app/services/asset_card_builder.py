from __future__ import annotations

import logging
import re
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from contextvars import copy_context
from datetime import UTC, datetime
from typing import Any

import requests

from ..diagnostics import log_event
from ..mpvm.asset_metadata import (
    asset_value_to_text,
    filter_windows_asset_metadata,
    is_excluded_windows_asset_card_branch,
    is_hidden_asset_technical_field,
    is_object_ref,
    is_windows_asset_card_root,
    labelize_asset_key,
    metadata_collection_name,
    metadata_collection_properties,
    metadata_data_has_property,
    metadata_properties_by_name,
    metadata_property_for_name,
    normalize_asset_vulnerabilities_header,
    normalize_asset_vulnerability_item,
    should_fetch_collection,
    vulnerability_collection_id,
)
from ..mpvm.common import (
    as_dict,
    clean_text,
    extract_collection_count,
    extract_collection_items,
    first_present,
    number_or_none,
    number_or_zero,
)
from ..mpvm.docker_vulnerabilities import build_docker_vulnerability_source
from ..mpvm_client import DOCKER_VULNERABILITY_PDQL, AuthConfig, MpVmApiError, MpVmClient

# Process-wide resources owned by the application container. They are bound by
# configure() when app.main builds the container; the placeholders keep the
# module importable on its own.
BACKGROUND_REQUEST_SEMAPHORE: Any = threading.BoundedSemaphore(1)
ASSET_METADATA_CACHE: Any = {}
ASSET_METADATA_INFLIGHT: Any = {}
ASSET_METADATA_CACHE_LOCK: Any = threading.Lock()
ASSET_METADATA_TTL_SECONDS = 3600


def configure(
    *,
    background_semaphore: Any,
    metadata_cache: Any,
    metadata_inflight: Any,
    metadata_cache_lock: Any,
    metadata_ttl_seconds: int,
) -> None:
    global BACKGROUND_REQUEST_SEMAPHORE, ASSET_METADATA_CACHE, ASSET_METADATA_INFLIGHT
    global ASSET_METADATA_CACHE_LOCK, ASSET_METADATA_TTL_SECONDS
    BACKGROUND_REQUEST_SEMAPHORE = background_semaphore
    ASSET_METADATA_CACHE = metadata_cache
    ASSET_METADATA_INFLIGHT = metadata_inflight
    ASSET_METADATA_CACHE_LOCK = metadata_cache_lock
    ASSET_METADATA_TTL_SECONDS = metadata_ttl_seconds


class AssetCardBuildCancelled(Exception):
    pass


class AssetCardRequestExecutor:
    def __init__(
        self,
        *,
        auth: AuthConfig,
        token: str,
        workers: int,
        cancel_event: threading.Event | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> None:
        self.auth = auth
        self.token = token
        self.cancel_event = cancel_event or threading.Event()
        self.on_progress = on_progress
        self.worker_count = max(1, workers)
        self._executor = ThreadPoolExecutor(max_workers=self.worker_count, thread_name_prefix="asset-card-request")
        self._worker_state = threading.local()
        self._clients: list[MpVmClient] = []
        self._clients_lock = threading.Lock()
        self._progress_lock = threading.Lock()
        self._telemetry_lock = threading.Lock()
        self.discovered = 0
        self.completed = 0
        self.active = 0
        self.peak_active = 0
        self.queue_wait_ms = 0.0
        self.request_duration_ms: dict[str, float] = {}
        self.request_counts: dict[str, int] = {}

    def _client(self) -> MpVmClient:
        client = getattr(self._worker_state, "client", None)
        if client is None:
            client = MpVmClient(self.auth)
            self._worker_state.client = client
            with self._clients_lock:
                self._clients.append(client)
        return client

    def _run(self, operation: Callable[..., Any], queued_at: float, label: str) -> Any:
        if self.cancel_event.is_set():
            raise AssetCardBuildCancelled("Asset card build was cancelled.")
        with BACKGROUND_REQUEST_SEMAPHORE:
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            with self._progress_lock:
                self.active += 1
                active = self.active
                self.peak_active = max(self.peak_active, active)
            started = time.perf_counter()
            queue_wait_ms = (started - queued_at) * 1000
            with self._telemetry_lock:
                self.queue_wait_ms += queue_wait_ms
            log_event(
                "asset-card-build",
                "request.worker.started",
                level=logging.DEBUG,
                worker=threading.current_thread().name,
                active_workers=active,
                worker_limit=self.worker_count,
            )
            try:
                return operation(self._client())
            finally:
                duration_ms = (time.perf_counter() - started) * 1000
                with self._telemetry_lock:
                    self.request_counts[label] = self.request_counts.get(label, 0) + 1
                    self.request_duration_ms[label] = self.request_duration_ms.get(label, 0.0) + duration_ms
                with self._progress_lock:
                    self.active = max(0, self.active - 1)
                    active = self.active
                log_event(
                    "asset-card-build",
                    "request.worker.completed",
                    level=logging.DEBUG,
                    worker=threading.current_thread().name,
                    active_workers=active,
                    worker_limit=self.worker_count,
                )

    def record_request_started(self) -> None:
        with self._progress_lock:
            self.discovered += 1
            discovered = self.discovered
            completed = self.completed
        if self.on_progress:
            self.on_progress(discovered, completed)

    def record_request_completed(self) -> None:
        with self._progress_lock:
            self.completed += 1
            discovered = self.discovered
            completed = self.completed
        if self.on_progress:
            self.on_progress(discovered, completed)

    def submit(
        self,
        operation: Callable[..., Any],
        *,
        count_progress: bool = True,
        label: str = "request",
    ) -> Future[Any]:
        if count_progress:
            self.record_request_started()
        context = copy_context()
        log_event(
            "asset-card-build",
            "request.scheduled",
            level=logging.DEBUG,
            discovered_requests=self.discovered,
            completed_requests=self.completed,
            queued_requests=max(0, self.discovered - self.completed - self.active),
            active_workers=self.active,
            worker_limit=self.worker_count,
        )
        future = self._executor.submit(context.run, self._run, operation, time.perf_counter(), label)

        def mark_completed(_future: Future[Any]) -> None:
            if count_progress:
                self.record_request_completed()

        future.add_done_callback(mark_completed)
        return future

    def call(self, operation: Callable[..., Any], *, label: str = "request") -> Any:
        return self.submit(operation, label=label).result()

    def map(self, operations: list[Callable[..., Any]]) -> list[Any]:
        settled = self.map_settled(operations)
        values: list[Any] = []
        for value, error in settled:
            if error is not None:
                raise error
            values.append(value)
        return values

    def map_settled(
        self,
        operations: list[Callable[..., Any]],
        *,
        count_progress: bool = True,
        label: str = "request",
    ) -> list[tuple[Any | None, Exception | None]]:
        results: list[tuple[Any | None, Exception | None]] = []
        for start in range(0, len(operations), self.worker_count):
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            # Keep the executor queue bounded. This also means cancellation stops
            # the coordinator before it schedules another batch of requests.
            futures = [
                self.submit(operation, count_progress=count_progress, label=label)
                for operation in operations[start : start + self.worker_count]
            ]
            for future in futures:
                try:
                    results.append((future.result(), None))
                except AssetCardBuildCancelled:
                    raise
                except Exception as exc:
                    results.append((None, exc))
        return results

    def map_labeled_settled(
        self,
        operations: list[tuple[str, Callable[..., Any]]],
        *,
        count_progress: bool = True,
    ) -> list[tuple[Any | None, Exception | None]]:
        results: list[tuple[Any | None, Exception | None]] = []
        for start in range(0, len(operations), self.worker_count):
            if self.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            futures = [
                self.submit(operation, count_progress=count_progress, label=label)
                for label, operation in operations[start : start + self.worker_count]
            ]
            for future in futures:
                try:
                    results.append((future.result(), None))
                except AssetCardBuildCancelled:
                    raise
                except Exception as exc:
                    results.append((None, exc))
        return results

    def telemetry(self) -> dict[str, Any]:
        with self._progress_lock, self._telemetry_lock:
            http = {"requests": 0, "retries": 0, "errors": 0, "rate_limited": 0}
            for client in self._clients:
                telemetry = getattr(client.session, "telemetry", None)
                snapshot = telemetry() if callable(telemetry) else {}
                for key in http:
                    http[key] += int(snapshot.get(key) or 0)
            return {
                "peak_active_requests": self.peak_active,
                "queue_wait_ms": round(self.queue_wait_ms, 2),
                "request_counts": dict(sorted(self.request_counts.items())),
                "request_duration_ms": {
                    key: round(value, 2) for key, value in sorted(self.request_duration_ms.items())
                },
                "http": http,
            }

    def close(self) -> None:
        self._executor.shutdown(wait=True, cancel_futures=False)
        for client in self._clients:
            client.session.close()


def build_asset_card(
    *,
    client: MpVmClient | None,
    token: str,
    asset_id: str,
    timeline_timestamp: int | None,
    limit_per_collection: int,
    max_items_per_collection: int,
    max_depth: int,
    docker_vulnerability_pdql: str = DOCKER_VULNERABILITY_PDQL,
    request_executor: AssetCardRequestExecutor | None = None,
    stage_callback: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    build_started = time.perf_counter()
    timestamp = timeline_timestamp or int(datetime.now(UTC).timestamp())
    log_event(
        "asset-card-build",
        "build.snapshot.started",
        asset_id=asset_id,
        timeline_timestamp=timestamp,
        limit_per_collection=limit_per_collection,
        max_items_per_collection=max_items_per_collection,
        max_depth=max_depth,
    )

    def remote_call(operation: Callable[..., Any], *, label: str = "request") -> Any:
        if request_executor:
            return request_executor.call(operation, label=label)
        if client is None:
            raise RuntimeError("A direct MP VM client is required for synchronous asset card builds.")
        return operation(client)

    api_url = request_executor.auth.api_url if request_executor else client.auth.api_url if client else ""

    if stage_callback:
        stage_callback("timeline")
    timeline_token = remote_call(
        lambda remote: remote.create_asset_timeline_token(token, asset_id, timestamp),
        label="timeline",
    )
    if stage_callback:
        stage_callback("root")
    root = remote_call(lambda remote: remote.get_asset_tree_root(token, timeline_token), label="tree_root")
    root_asset_id = str(first_present(root.get("objectId"), asset_id))
    windows_asset = is_windows_asset_card_root(root)

    metadata_cache: dict[str, dict[str, Any]] = {}
    nodes: list[dict[str, Any]] = []
    collections: list[dict[str, Any]] = []
    table_rows: list[dict[str, Any]] = []
    seen_nodes: set[str] = set()
    seen_collections: set[str] = set()
    node_cache: dict[str, dict[str, Any]] = {}
    stats: dict[str, Any] = {
        "metadata_requests": 0,
        "node_requests": 0,
        "collection_requests": 0,
        "vulnerability_header_requests": 0,
        "vulnerability_group_requests": 0,
        "vulnerability_collection_requests": 0,
        "nodes": 0,
        "collections": 0,
        "table_rows": 0,
        "warnings": [],
    }

    def warn(message: str) -> None:
        stats["warnings"].append(message)
        lowered = message.casefold()
        if "connection pool" in lowered:
            warning_code = "mpvm_connection_pool_exhausted"
        elif "timed out" in lowered or "timeout" in lowered:
            warning_code = "mpvm_request_timeout"
        elif "http 4" in lowered or "http 5" in lowered:
            warning_code = "mpvm_http_error"
        elif "certificate_verify_failed" in lowered or "ssl" in lowered:
            warning_code = "mpvm_tls_error"
        else:
            warning_code = "asset_card_collection_warning"
        endpoint_match = re.search(r"(?:GET|POST|PUT|DELETE|PATCH)\s+(\/api\/[^\s:]+)", message)
        log_event(
            "asset-card-build",
            "build.warning",
            level=logging.WARNING,
            warning=message,
            warning_code=warning_code,
            endpoint=endpoint_match.group(1) if endpoint_match else None,
        )

    def metadata_for_types(asset_types: list[str]) -> None:
        ordered_types = list(dict.fromkeys(item for item in asset_types if item and item not in metadata_cache))
        owned: list[tuple[str, tuple[str, str], threading.Event]] = []
        waiting: list[tuple[str, tuple[str, str], threading.Event]] = []
        now = time.monotonic()
        with ASSET_METADATA_CACHE_LOCK:
            for asset_type in ordered_types:
                cache_key = (api_url, asset_type)
                cached = ASSET_METADATA_CACHE.get(cache_key)
                if ASSET_METADATA_TTL_SECONDS and cached and now - cached[0] <= ASSET_METADATA_TTL_SECONDS:
                    metadata_cache[asset_type] = cached[1]
                    continue
                event = ASSET_METADATA_INFLIGHT.get(cache_key)
                if event is None:
                    event = threading.Event()
                    ASSET_METADATA_INFLIGHT[cache_key] = event
                    owned.append((asset_type, cache_key, event))
                else:
                    waiting.append((asset_type, cache_key, event))

        operations = [
            (
                "metadata",
                lambda remote, asset_type=asset_type: remote.get_asset_metadata(token, asset_type),
            )
            for asset_type, _cache_key, _event in owned
        ]
        try:
            if request_executor and operations:
                settled = request_executor.map_labeled_settled(operations)
            else:
                settled = []
                for _label, operation in operations:
                    try:
                        if client is None:
                            raise RuntimeError("A direct MP VM client is required for metadata loading.")
                        settled.append((operation(client), None))
                    except Exception as exc:
                        settled.append((None, exc))
        except BaseException:
            with ASSET_METADATA_CACHE_LOCK:
                for _asset_type, cache_key, event in owned:
                    ASSET_METADATA_INFLIGHT.pop(cache_key, None)
                    event.set()
            raise

        for (asset_type, cache_key, event), (value, error) in zip(owned, settled, strict=False):
            metadata = value if isinstance(value, dict) else {}
            if windows_asset:
                metadata = filter_windows_asset_metadata(metadata)
            if error is not None:
                warn(f"metadata {asset_type}: {error}")
            else:
                stats["metadata_requests"] += 1
            metadata_cache[asset_type] = metadata
            with ASSET_METADATA_CACHE_LOCK:
                if metadata and ASSET_METADATA_TTL_SECONDS:
                    ASSET_METADATA_CACHE[cache_key] = (time.monotonic(), metadata)
                    if len(ASSET_METADATA_CACHE) > 128:
                        oldest_key = min(ASSET_METADATA_CACHE, key=lambda key: ASSET_METADATA_CACHE[key][0])
                        ASSET_METADATA_CACHE.pop(oldest_key, None)
                ASSET_METADATA_INFLIGHT.pop(cache_key, None)
                event.set()

        for asset_type, cache_key, event in waiting:
            event.wait()
            with ASSET_METADATA_CACHE_LOCK:
                cached = ASSET_METADATA_CACHE.get(cache_key)
            metadata_cache[asset_type] = cached[1] if cached else {}

    def add_table_row(
        *,
        path: str,
        name: str,
        title: str | None,
        value: Any,
        value_type: str | None = None,
        kind: str | None = None,
        parent_type: str | None = None,
        parent_object_id: str | None = None,
    ) -> None:
        table_rows.append(
            {
                "path": path,
                "name": name,
                "title": title or name,
                "type": value_type,
                "kind": kind,
                "value": asset_value_to_text(value),
                "parent_type": parent_type,
                "parent_object_id": parent_object_id,
            }
        )

    def add_value_rows(
        *,
        path: str,
        name: str,
        title: str | None,
        value: Any,
        value_type: str | None = None,
        kind: str | None = None,
        parent_type: str | None = None,
        parent_object_id: str | None = None,
    ) -> None:
        add_table_row(
            path=path,
            name=name,
            title=title,
            value=value,
            value_type=value_type,
            kind=kind,
            parent_type=parent_type,
            parent_object_id=parent_object_id,
        )
        add_embedded_value_rows(
            value=value,
            path=path,
            name=name,
            title=title or name,
            parent_type=parent_type,
            parent_object_id=parent_object_id,
        )

    def add_embedded_value_rows(
        *,
        value: Any,
        path: str,
        name: str,
        title: str,
        parent_type: str | None,
        parent_object_id: str | None,
        depth: int = 1,
    ) -> None:
        if depth > 4 or value is None:
            return
        if isinstance(value, list):
            for index, item in enumerate(value):
                child_path = f"{path}[{index}]"
                child_name = f"{name}[{index}]"
                child_title = f"{title} {index + 1}"
                add_table_row(
                    path=child_path,
                    name=child_name,
                    title=child_title,
                    value=item,
                    kind="item",
                    parent_type=parent_type,
                    parent_object_id=parent_object_id,
                )
                add_embedded_value_rows(
                    value=item,
                    path=child_path,
                    name=child_name,
                    title=child_title,
                    parent_type=parent_type,
                    parent_object_id=parent_object_id,
                    depth=depth + 1,
                )
            return
        if not isinstance(value, dict) or "hasItems" in value:
            return

        nested_data = value.get("data")
        nested: dict[str, Any] = nested_data if isinstance(nested_data, dict) else value
        for key, item in nested.items():
            if is_hidden_asset_technical_field(key):
                continue
            child_path = f"{path}.{key}"
            child_name = f"{name}.{key}"
            child_title = labelize_asset_key(key)
            add_table_row(
                path=child_path,
                name=child_name,
                title=child_title,
                value=item,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
            )
            add_embedded_value_rows(
                value=item,
                path=child_path,
                name=child_name,
                title=child_title,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
                depth=depth + 1,
            )

    def add_embedded_data_rows(item: dict[str, Any], path: str, parent_type: str, parent_object_id: str) -> None:
        data = as_dict(item.get("data"))
        for key, embedded_value in data.items():
            if is_hidden_asset_technical_field(key):
                continue
            add_value_rows(
                path=f"{path}.{key}",
                name=key,
                title=labelize_asset_key(key),
                value=embedded_value,
                value_type=None,
                kind=None,
                parent_type=parent_type,
                parent_object_id=parent_object_id,
            )

    def run_operations(
        operations: list[tuple[str, Callable[..., Any]]],
    ) -> list[tuple[Any | None, Exception | None]]:
        if request_executor:
            return request_executor.map_labeled_settled(operations)
        settled: list[tuple[Any | None, Exception | None]] = []
        for _label, operation in operations:
            try:
                if client is None:
                    raise RuntimeError("A direct MP VM client is required for asset tree loading.")
                settled.append((operation(client), None))
            except Exception as exc:
                settled.append((None, exc))
        return settled

    def fetch_node_specs(specs: list[dict[str, Any]]) -> None:
        unique: list[dict[str, Any]] = []
        scheduled: set[str] = set()
        for spec in specs:
            key = f"{spec['type']}|{spec['id']}"
            if key in node_cache or key in scheduled:
                continue
            scheduled.add(key)
            unique.append(spec)
        operations = [
            (
                "tree_node",
                lambda remote, spec=spec: remote.get_asset_tree_node(
                    token, spec["type"], spec["id"], timeline_token
                ),
            )
            for spec in unique
        ]
        for spec, (value, error) in zip(unique, run_operations(operations), strict=False):
            key = f"{spec['type']}|{spec['id']}"
            if error is not None:
                warn(f"node {spec['path']} ({spec['type']}/{spec['id']}): {error}")
                continue
            if isinstance(value, dict):
                node_cache[key] = value
                stats["node_requests"] += 1

    def fetch_collection_specs(specs: list[dict[str, Any]]) -> None:
        if not specs:
            return
        page_size = max(1, min(limit_per_collection, max_items_per_collection))
        first_operations = [
            (
                "tree_collection",
                lambda remote, spec=spec: remote.get_asset_tree_collection(
                    token,
                    spec["parent_type"],
                    spec["object_id"],
                    spec["name"],
                    timeline_token,
                    full=True,
                    limit=page_size,
                    offset=0,
                ),
            )
            for spec in specs
        ]
        for spec, (response, error) in zip(specs, run_operations(first_operations), strict=False):
            spec["pages"] = {}
            spec["reported_count"] = None
            spec["next_offset"] = 0
            spec["done"] = True
            if error is not None:
                warn(
                    f"collection {spec['path']} ({spec['parent_type']}/{spec['object_id']}/{spec['name']}): {error}"
                )
                continue
            stats["collection_requests"] += 1
            batch = extract_collection_items(response)
            spec["pages"][0] = batch
            spec["reported_count"] = extract_collection_count(response)
            spec["next_offset"] = len(batch)
            spec["done"] = not batch or len(batch) < page_size

        while True:
            page_specs: list[tuple[dict[str, Any], int, int]] = []
            for spec in specs:
                if spec.get("done"):
                    continue
                offset = int(spec["next_offset"])
                reported_count = spec.get("reported_count")
                target = min(max_items_per_collection, reported_count) if reported_count is not None else max_items_per_collection
                if offset >= target:
                    spec["done"] = True
                    continue
                if reported_count is not None:
                    while offset < target:
                        current_limit = min(limit_per_collection, target - offset)
                        page_specs.append((spec, offset, current_limit))
                        offset += current_limit
                    spec["done"] = True
                else:
                    current_limit = min(limit_per_collection, target - offset)
                    page_specs.append((spec, offset, current_limit))
            if not page_specs:
                break
            operations = [
                (
                    "tree_collection",
                    lambda remote, spec=spec, offset=offset, current_limit=current_limit:
                        remote.get_asset_tree_collection(
                            token,
                            spec["parent_type"],
                            spec["object_id"],
                            spec["name"],
                            timeline_token,
                            full=True,
                            limit=current_limit,
                            offset=offset,
                        ),
                )
                for spec, offset, current_limit in page_specs
            ]
            for (spec, offset, current_limit), (response, error) in zip(page_specs, run_operations(operations), strict=False):
                if error is not None:
                    warn(f"collection {spec['path']} offset {offset}: {error}")
                    spec["done"] = True
                    continue
                stats["collection_requests"] += 1
                batch = extract_collection_items(response)
                spec["pages"][offset] = batch
                count = extract_collection_count(response)
                if count is not None:
                    spec["reported_count"] = count
                spec["next_offset"] = offset + len(batch)
                if not batch or len(batch) < current_limit:
                    spec["done"] = True

        for spec in specs:
            spec["items"] = [
                item
                for offset in sorted(spec.get("pages", {}))
                for item in spec["pages"][offset]
            ][:max_items_per_collection]
            reported_count = spec.get("reported_count")
            spec["truncated"] = (
                len(spec["items"]) < reported_count
                if reported_count is not None
                else len(spec["items"]) >= max_items_per_collection
            )
            if spec["truncated"]:
                warn(
                    f"collection {spec['path']}: fetched {len(spec['items'])} item(s), "
                    f"reported count {reported_count or 'unknown'}"
                )

    def traverse_tree() -> None:
        pending_nodes: list[dict[str, Any]] = [
            {"node": root, "path": "asset", "depth": 0, "title": root.get("displayName")}
        ]
        while pending_nodes:
            current_nodes: list[dict[str, Any]] = []
            for entry in sorted(pending_nodes, key=lambda item: item["path"]):
                node = entry["node"]
                node_type = clean_text(first_present(node.get("type"), ""))
                object_id = clean_text(first_present(node.get("objectId"), ""))
                key = f"{node_type}|{object_id}"
                if object_id and key in seen_nodes:
                    continue
                if object_id:
                    seen_nodes.add(key)
                    node_cache[key] = node
                entry["type"] = node_type
                entry["id"] = object_id
                current_nodes.append(entry)
                if entry["path"] != "asset":
                    nodes.append(
                        {
                            "path": entry["path"],
                            "title": entry.get("title") or node.get("displayName") or entry["path"],
                            "display_name": node.get("displayName"),
                            "object_id": object_id,
                            "type": node_type,
                            "vulnerability_level": node.get("vulnerabilityLevel"),
                            "data": node.get("data") if isinstance(node.get("data"), dict) else {},
                        }
                    )
                    stats["nodes"] += 1
            if not current_nodes:
                break

            metadata_for_types([entry["type"] for entry in current_nodes])
            collection_specs: list[dict[str, Any]] = []
            direct_refs: list[dict[str, Any]] = []
            for entry in current_nodes:
                node = entry["node"]
                node_type = entry["type"]
                object_id = entry["id"]
                depth = int(entry["depth"])
                path = entry["path"]
                metadata = metadata_cache.get(node_type) or {}
                properties = metadata_properties_by_name(metadata)
                data = node.get("data") if isinstance(node.get("data"), dict) else {}
                for name, value in data.items():
                    prop = metadata_property_for_name(properties, name)
                    title = clean_text(first_present(prop.get("title"), name))
                    value_type = clean_text(
                        first_present(prop.get("type"), value.get("type") if isinstance(value, dict) else None)
                    )
                    kind = clean_text(prop.get("kind"))
                    current_path = f"{path}.{name}"
                    if windows_asset and is_excluded_windows_asset_card_branch(
                        name, prop.get("collectionName"), prop.get("collection_name"), title,
                    ):
                        continue
                    if should_fetch_collection(prop, value):
                        add_table_row(
                            path=current_path, name=name, title=title, value=value,
                            value_type=value_type, kind=kind or "collection",
                            parent_type=node_type, parent_object_id=object_id,
                        )
                        if depth >= max_depth:
                            warn(f"max depth reached before collection {current_path}")
                        else:
                            collection_specs.append(
                                {
                                    "parent_type": node_type,
                                    "object_id": object_id or root_asset_id,
                                    "name": metadata_collection_name(prop, name),
                                    "prop": prop,
                                    "path": current_path,
                                    "depth": depth + 1,
                                }
                            )
                        continue
                    if is_object_ref(value):
                        add_table_row(
                            path=current_path, name=name, title=title, value=value,
                            value_type=value_type, kind=kind or "node",
                            parent_type=node_type, parent_object_id=object_id,
                        )
                        if depth >= max_depth:
                            warn(f"max depth reached before node {current_path}")
                        else:
                            child_type = clean_text(value.get("type"))
                            child_id = clean_text(value.get("objectId"))
                            if child_type and child_id:
                                direct_refs.append(
                                    {"type": child_type, "id": child_id, "path": current_path,
                                     "depth": depth + 1, "title": title}
                                )
                        continue
                    add_value_rows(
                        path=current_path, name=name, title=title, value=value,
                        value_type=value_type, kind=kind,
                        parent_type=node_type, parent_object_id=object_id,
                    )

                for prop in metadata_collection_properties(metadata):
                    name = metadata_collection_name(prop)
                    if not name or metadata_data_has_property(data, name):
                        continue
                    current_path = f"{path}.{name}"
                    if windows_asset and is_excluded_windows_asset_card_branch(
                        name, prop.get("collectionName"), prop.get("collection_name"), prop.get("title"),
                    ):
                        continue
                    if depth >= max_depth:
                        warn(f"max depth reached before collection {current_path}")
                    else:
                        collection_specs.append(
                            {"parent_type": node_type, "object_id": object_id or root_asset_id,
                             "name": name, "prop": prop, "path": current_path, "depth": depth + 1}
                        )

            unique_collections: list[dict[str, Any]] = []
            for spec in sorted(collection_specs, key=lambda item: item["path"]):
                key = f"{spec['parent_type']}|{spec['object_id']}|{spec['name']}"
                if not spec["parent_type"] or not spec["object_id"]:
                    warn(f"collection {spec['path']}: parent type or object id is empty")
                elif key not in seen_collections:
                    seen_collections.add(key)
                    unique_collections.append(spec)

            # Узлы по прямым ссылкам не зависят от коллекций уровня — грузим одновременно.
            if request_executor and direct_refs and unique_collections:
                with ThreadPoolExecutor(max_workers=1, thread_name_prefix="asset-card-direct-nodes") as side:
                    direct_future = side.submit(copy_context().run, fetch_node_specs, list(direct_refs))
                    try:
                        fetch_collection_specs(unique_collections)
                    finally:
                        direct_future.result()
            else:
                fetch_collection_specs(unique_collections)
                fetch_node_specs(direct_refs)
            child_refs = list(direct_refs)
            for spec in unique_collections:
                items = spec.get("items") or []
                prop = spec["prop"]
                collection_doc: dict[str, Any] = {
                    "path": spec["path"], "name": spec["name"],
                    "title": clean_text(first_present(prop.get("title"), spec["name"])),
                    "type": prop.get("type"), "kind": prop.get("kind"),
                    "parent_type": spec["parent_type"], "parent_object_id": spec["object_id"],
                    "count": spec.get("reported_count") if spec.get("reported_count") is not None else len(items),
                    "fetched_count": len(items), "truncated": bool(spec.get("truncated")), "items": [],
                }
                collections.append(collection_doc)
                stats["collections"] += 1
                for index, item in enumerate(items):
                    item_path = f"{spec['path']}[{index}]"
                    if not isinstance(item, dict):
                        collection_doc["items"].append({"path": item_path, "value": item})
                        add_table_row(
                            path=item_path, name=spec["name"], title=collection_doc["title"], value=item,
                            value_type=prop.get("type"), kind=prop.get("kind"),
                            parent_type=spec["parent_type"], parent_object_id=spec["object_id"],
                        )
                        continue
                    item_doc = {
                        "path": item_path, "display_name": item.get("displayName"),
                        "object_id": item.get("objectId"), "type": item.get("type"),
                        "vulnerability_level": item.get("vulnerabilityLevel"),
                        "data": item.get("data") if isinstance(item.get("data"), dict) else {},
                    }
                    collection_doc["items"].append(item_doc)
                    add_table_row(
                        path=item_path, name=spec["name"], title=collection_doc["title"], value=item,
                        value_type=item.get("type") or prop.get("type"), kind=prop.get("kind"),
                        parent_type=spec["parent_type"], parent_object_id=spec["object_id"],
                    )
                    if int(spec["depth"]) <= max_depth and is_object_ref(item):
                        child_type = clean_text(item.get("type"))
                        child_id = clean_text(item.get("objectId"))
                        if child_type and child_id:
                            child_refs.append(
                                {"type": child_type, "id": child_id, "path": item_path,
                                 "depth": spec["depth"], "title": item_doc.get("display_name"),
                                 "item": item, "item_doc": item_doc,
                                 "parent_type": spec["parent_type"], "parent_object_id": spec["object_id"]}
                            )
                            continue
                    if int(spec["depth"]) > max_depth:
                        warn(f"max depth reached inside collection {item_path}")
                    add_embedded_data_rows(item, item_path, spec["parent_type"], spec["object_id"])

            fetch_node_specs(child_refs)
            pending_nodes = []
            for ref in sorted(child_refs, key=lambda item: item["path"]):
                child = node_cache.get(f"{ref['type']}|{ref['id']}")
                if child:
                    if ref.get("item_doc") is not None:
                        ref["item_doc"]["node"] = child
                    pending_nodes.append(
                        {"node": child, "path": ref["path"], "depth": ref["depth"], "title": ref.get("title")}
                    )
                elif ref.get("item") is not None:
                    add_embedded_data_rows(
                        ref["item"], ref["path"], ref["parent_type"], ref["parent_object_id"]
                    )

        nodes.sort(key=lambda item: item.get("path") or "")
        collections.sort(key=lambda item: item.get("path") or "")
        table_rows.sort(key=lambda item: item.get("path") or "")

    vulnerability_args = {
        "client": client,
        "token": token,
        "timeline_token": timeline_token,
        "limit_per_collection": min(limit_per_collection, 1000),
        "max_items_per_collection": max_items_per_collection,
        "stats": stats,
        "request_executor": request_executor,
        "asset_id": root_asset_id,
        "asset_type": clean_text(root.get("type")),
        "docker_vulnerability_pdql": docker_vulnerability_pdql,
    }
    phase_duration_ms: dict[str, float] = {}

    def timed_tree() -> None:
        started = time.perf_counter()
        try:
            traverse_tree()
        finally:
            phase_duration_ms["tree"] = round((time.perf_counter() - started) * 1000, 2)

    def timed_vulnerabilities() -> dict[str, Any]:
        started = time.perf_counter()
        try:
            return build_asset_vulnerability_snapshot(**vulnerability_args)
        finally:
            phase_duration_ms["vulnerabilities"] = round((time.perf_counter() - started) * 1000, 2)

    if stage_callback:
        stage_callback("tree_and_vulnerabilities")
    if request_executor:
        with ThreadPoolExecutor(max_workers=2, thread_name_prefix="asset-card-coordinator") as coordinators:
            tree_future: Future[Any] = coordinators.submit(timed_tree)
            vulnerability_future: Future[Any] = coordinators.submit(timed_vulnerabilities)
            first_done, _ = wait((tree_future, vulnerability_future), return_when=FIRST_COMPLETED)
            if vulnerability_future in first_done and tree_future not in first_done:
                vulnerabilities = vulnerability_future.result()
                if stage_callback:
                    stage_callback("vulnerabilities_ready")
                tree_future.result()
            else:
                tree_future.result()
                if stage_callback:
                    stage_callback("tree_ready")
                vulnerabilities = vulnerability_future.result()
    else:
        timed_tree()
        vulnerabilities = timed_vulnerabilities()
    stats["table_rows"] = len(table_rows)
    stats["elapsed_ms"] = round((time.perf_counter() - build_started) * 1000)
    stats["network_requests"] = sum(
        int(stats.get(key) or 0)
        for key in (
            "metadata_requests",
            "node_requests",
            "collection_requests",
            "vulnerability_header_requests",
            "vulnerability_group_requests",
            "vulnerability_collection_requests",
        )
    ) + 2
    stats["stage_duration_ms"] = dict(sorted(phase_duration_ms.items()))
    if request_executor:
        stats.update(request_executor.telemetry())
    stats["warnings"].sort()
    if stage_callback:
        stage_callback("assembling")

    result = {
        "asset_id": root_asset_id,
        "requested_asset_id": asset_id,
        "display_name": root.get("displayName"),
        "asset_type": root.get("type"),
        "vulnerability_level": root.get("vulnerabilityLevel"),
        "timeline_timestamp": timestamp,
        "timeline_token": timeline_token,
        "root": root,
        "metadata": metadata_cache,
        "nodes": nodes,
        "collections": collections,
        "table_rows": table_rows,
        "vulnerabilities": vulnerabilities,
        "stats": stats,
    }
    log_event(
        "asset-card-build",
        "build.snapshot.completed",
        duration_ms=stats["elapsed_ms"],
        stats=stats,
    )
    return result


def build_asset_vulnerability_snapshot(
    *,
    client: MpVmClient,
    token: str,
    timeline_token: str,
    limit_per_collection: int,
    max_items_per_collection: int,
    stats: dict[str, Any],
    request_executor: AssetCardRequestExecutor | None = None,
    asset_id: str,
    asset_type: str | None,
    docker_vulnerability_pdql: str,
) -> dict[str, Any]:
    """Load the two widget trees and expand every software/OS vulnerability collection.

    The widgets are intentionally handled apart from the generic asset-tree API: their
    collection identifiers and payloads are a different contract and are what lets the
    UI show the compact hierarchy from the MP VM asset card.
    """

    snapshot: dict[str, Any] = {
        "header": {},
        "sources": [],
        "stats": {"groups": 0, "findings": 0, "truncated_groups": 0, "warnings": []},
    }

    def warn(message: str) -> None:
        snapshot["stats"]["warnings"].append(message)
        stats["warnings"].append(message)

    widget_sources = (
        ("os", "HostOSVulnerabilities", "Уязвимости ОС"),
        ("software", "HostSoftVulnerabilities", "Уязвимости программного обеспечения"),
    )
    page_size = max(1, min(limit_per_collection, 1000))
    max_items = max(1, max_items_per_collection)

    initial_operations: list[Callable[..., Any]] = [
        lambda remote: remote.get_asset_vulnerabilities_header(token, timeline_token),
        *[
            (
                lambda remote, collection_type=collection_type:
                    remote.get_asset_vulnerability_groups(token, collection_type, timeline_token)
            )
            for _source, collection_type, _title in widget_sources
        ],
    ]
    if request_executor:
        initial_results = request_executor.map_labeled_settled(
            [
                ("vulnerability_header" if index == 0 else "vulnerability_groups", operation)
                for index, operation in enumerate(initial_operations)
            ]
        )
    else:
        initial_results = []
        for operation in initial_operations:
            try:
                initial_results.append((operation(client), None))
            except Exception as exc:
                initial_results.append((None, exc))

    header, header_error = initial_results[0]
    if header_error is not None:
        warn(f"vulnerabilities header: {header_error}")
    elif isinstance(header, dict):
        stats["vulnerability_header_requests"] += 1
        snapshot["header"] = normalize_asset_vulnerabilities_header(header)

    group_loads: list[dict[str, Any]] = []
    for source_index, (source, collection_type, title) in enumerate(widget_sources):
        source_doc: dict[str, Any] = {
            "source": source,
            "collection_type": collection_type,
            "title": title,
            "level": None,
            "vulnerabilities_count": 0,
            "cvss_score": None,
            "groups": [],
        }
        snapshot["sources"].append(source_doc)
        response, response_error = initial_results[source_index + 1]
        if response_error is not None:
            warn(f"{collection_type}: {response_error}")
            continue
        if not isinstance(response, dict):
            warn(f"{collection_type}: unexpected group response")
            continue
        stats["vulnerability_group_requests"] += 1
        source_doc["level"] = response.get("level")
        source_doc["vulnerabilities_count"] = number_or_zero(response.get("vulnerabilitiesCount"))
        source_doc["cvss_score"] = number_or_none(response.get("cvssScore"))
        for group_index, item in enumerate(extract_collection_items(response)):
            if not isinstance(item, dict):
                continue
            collection_id = vulnerability_collection_id(item)
            group: dict[str, Any] = {
                "source": source,
                "collection_type": collection_type,
                "collection_id": collection_id,
                "name": clean_text(item.get("name")),
                "level": item.get("level"),
                "vulnerabilities_count": number_or_zero(item.get("vulnerabilitiesCount")),
                "cvss_score": number_or_none(item.get("cvssScore")),
                "order": group_index,
                "items": [],
                "truncated": False,
            }
            source_doc["groups"].append(group)
            if not collection_id:
                warn(f"{collection_type} group '{group['name'] or group_index}' does not contain collection id")
                continue
            group_loads.append({"group": group, "collection_type": collection_type, "collection_id": collection_id})

    def load_group(remote: MpVmClient, spec: dict[str, Any]) -> dict[str, Any]:
        items: list[dict[str, Any]] = []
        offset = 0
        request_count = 0
        error: Exception | None = None
        while len(items) < max_items:
            if request_executor and request_executor.cancel_event.is_set():
                raise AssetCardBuildCancelled("Asset card build was cancelled.")
            current_limit = min(page_size, max_items - len(items))
            if request_executor:
                request_executor.record_request_started()
            page_started = time.perf_counter()
            try:
                batch = remote.get_asset_vulnerability_collection(
                    token,
                    spec["collection_type"],
                    timeline_token,
                    spec["collection_id"],
                    limit=current_limit,
                    offset=offset,
                )
                request_count += 1
            except (MpVmApiError, requests.RequestException) as exc:
                error = exc
                break
            finally:
                if request_executor:
                    request_executor.record_request_completed()
            items.extend(normalize_asset_vulnerability_item(entry) for entry in batch)
            log_event(
                "asset-card-build",
                "vulnerability.page.loaded",
                level=logging.DEBUG,
                collection_type=spec["collection_type"],
                collection_id=spec["collection_id"],
                offset=offset,
                limit=current_limit,
                item_count=len(batch),
                duration_ms=round((time.perf_counter() - page_started) * 1000, 2),
            )
            if not batch or len(batch) < current_limit:
                break
            offset += len(batch)
        return {"items": items, "request_count": request_count, "error": error}

    group_operations = [
        (lambda remote, spec=spec: load_group(remote, spec))
        for spec in group_loads
    ]
    if request_executor:
        group_results = request_executor.map_settled(
            group_operations,
            count_progress=False,
            label="vulnerability_collection",
        )
    else:
        group_results = []
        for operation in group_operations:
            try:
                group_results.append((operation(client), None))
            except Exception as exc:
                group_results.append((None, exc))

    for spec, (result, operation_error) in zip(group_loads, group_results, strict=False):
        group = spec["group"]
        if operation_error is not None:
            warn(f"{spec['collection_type']} collection {spec['collection_id']}: {operation_error}")
            continue
        if not isinstance(result, dict):
            continue
        group["items"] = result.get("items") or []
        stats["vulnerability_collection_requests"] += int(result.get("request_count") or 0)
        if result.get("error") is not None:
            warn(f"{spec['collection_type']} collection {spec['collection_id']}: {result['error']}")
        reported_count = group["vulnerabilities_count"]
        group["truncated"] = (
            len(group["items"]) < reported_count
            if reported_count
            else len(group["items"]) >= max_items
        )
        if group["truncated"]:
            snapshot["stats"]["truncated_groups"] += 1
            warn(
                f"{spec['collection_type']} collection {spec['collection_id']}: loaded {len(group['items'])} of "
                f"{reported_count or 'unknown'} vulnerability item(s)"
            )

    def docker_remote_call(operation: Callable[..., Any], label: str) -> Any:
        if request_executor:
            return request_executor.call(operation, label=label)
        if client is None:
            raise RuntimeError("A direct MP VM client is required for Docker vulnerability queries.")
        return operation(client)

    docker_source, docker_warning = build_docker_vulnerability_source(
        token=token,
        asset_id=asset_id,
        asset_type=asset_type,
        pdql_template=docker_vulnerability_pdql,
        max_items=max_items,
        sources=snapshot["sources"],
        remote_call=docker_remote_call,
    )
    snapshot["sources"].append(docker_source)
    snapshot["header"]["docker_vulnerabilities_count"] = docker_source["vulnerabilities_count"]
    if docker_warning:
        warn(docker_warning)

    snapshot["stats"]["groups"] = sum(len(source["groups"]) for source in snapshot["sources"])
    snapshot["stats"]["findings"] = sum(
        len(group["items"])
        for source in snapshot["sources"]
        for group in source["groups"]
    )
    return snapshot
