from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter

from .mpvm import build_retry_adapter, build_session, resolve_access_token


ASSET_GRID_PATH = "/api/assets_temporal_readmodel/v1/assets_grid"
ASSET_GRID_DATA_PATH = "/api/assets_temporal_readmodel/v1/assets_grid/data"
ASSET_GRID_EXPORT_PATH = "/api/assets_temporal_readmodel/v1/assets_grid/export"
VULNERABILITY_DETAIL_PATH = "/api/assets_temporal_readmodel/v1/vulnerabilities/{passport_id}"
ASSET_TIMELINE_TOKEN_PATH = "/api/v1/asset/timeline/{asset_id}/token"
ASSET_TREE_ROOT_PATH = "/api/assets/tree/root"
ASSET_TREE_COLLECTION_PATH = "/api/assets/tree/collection/{asset_type}/{object_id}/{collection_name}"
ASSET_TREE_NODE_PATH = "/api/assets/tree/node/{asset_type}/{object_id}"
ASSET_METADATA_PATH = "/api/assets/metadata/{asset_type}"
ASSET_VULNERABILITIES_HEADER_PATH = "/api/widgets/assets/HostVulnerabilitiesHeader/{timeline_token}"
ASSET_OS_VULNERABILITIES_PATH = "/api/widgets/assets/HostOSVulnerabilities/{timeline_token}"
ASSET_SOFTWARE_VULNERABILITIES_PATH = "/api/widgets/assets/HostSoftVulnerabilities/{timeline_token}"
ASSET_VULNERABILITY_COLLECTION_PATH = "/api/widgets/assets/{collection_type}/{timeline_token}/collections/{collection_id}"
SCOPES_PATH = "/api/scopes/v2/scopes"
CREDENTIALS_PATH = "/api/v3/credentials"
ASSET_REMOVE_OPERATION_PATH = "/api/assets_processing/v1/asset_operations/removeAssets"
SCANNER_PROFILES_PATH = "/api/scanning/v3/scanner_profiles"
SCANNER_TASKS_CREATE_PATH = "/api/scanning/v4/scanner_tasks/create"
SCANNER_TASKS_UPDATE_PATH = "/api/scanning/v4/scanner_tasks/{task_id}"
SCANNER_TASKS_DELETE_V3_PATH = "/api/scanning/v3/scanner_tasks/{task_id}"
SCANNER_TASK_VALIDATION_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/validation"
SCANNER_TASK_START_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/start"
SCANNER_TASK_STOP_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/stop"
SCANNER_TASK_CONNECTION_CHECK_START_PATH = "/api/scanning/v4/scanner_tasks/{task_id}/start_connection_check"
SCANNER_TASKS_LIST_V4_PATH = "/api/scanning/v4/scanner_tasks"
SCANNER_TASK_RUNS_PATH = "/api/scanning/v2/scanner_tasks/{task_id}/runs"
SCANNER_RUN_JOBS_PATH = "/api/scanning/v2/runs/{run_id}/jobs"
SCANNER_JOB_ERRORS_PATH = "/api/scanning/v2/jobs/{job_id}/job_errors"
CONNECTION_CHECK_PAYLOAD = {"mode": "connectionAndAccounts", "agentSelectionMode": "all"}

DEFAULT_SCOPE = "authorization offline_access mpx.api ptkb.api"

SOFTWARE_VULN_PDQL = """select(Host.IpAddress, Host.Fqdn, Host.Softs.Name as SoftName, Host.Softs.Version as SoftVersion,
  Host.Softs.@Vulners as SoftVulner, Host.Softs.@Vulners.CVEs as CVE, Host.Softs.@Vulners.SeverityRating as SeverityRating)
| sort(Host.IpAddress ASC, SoftName ASC, SoftVersion ASC, SoftVulner ASC, CVE ASC)"""

VULNER_PASSPORT_PDQL = """select(@VulnerPassport, compact(VulnerPassport.CVEs),
VulnerPassport.SeverityRating, VulnerPassport.Score,
VulnerPassport.IssueTime, VulnerPassport.PackageId,
VulnerPassport.PackageVersion, VulnerPassport.Metrics)
| limit(0)"""

ASSET_CARD_PDQL = "select(@Host, Host.OsName, Host.@CreationTime, Host.@UpdateTime) | sort(@Host ASC)"

ASSET_ID_PDQL = "select(Host.@Id as AssetId, @Host as HostName, Host.IpAddress as IpAddress)"
ASSET_RESOLUTION_PDQL = (
    "select(Host.@Id as AssetId, @Host as HostName, Host.IpAddress as IpAddress, "
    "Host.Fqdn as Fqdn, Host.@CreationTime as CreationTime, "
    "Host.@UpdateTime as UpdateTime)"
)


class MpVmApiError(RuntimeError):
    """Raised when MP VM returns an unexpected API response."""


@dataclass(frozen=True)
class AuthConfig:
    api_url: str
    token_url: str
    username: str | None = None
    password: str | None = None
    client_id: str = "mpx"
    client_secret: str | None = None
    scope: str = DEFAULT_SCOPE
    access_token: str | None = None
    verify_tls: bool = True
    timeout: float = 120


class MpVmClient:
    def __init__(self, auth: AuthConfig) -> None:
        self.auth = auth
        self.session = build_session(verify_tls=auth.verify_tls)

    @staticmethod
    def _build_retry_adapter() -> HTTPAdapter:
        return build_retry_adapter()

    def ensure_access_token(self) -> str:
        return resolve_access_token(self.auth, self.session, self._json_response, MpVmApiError)

    def create_pdql_token(
        self,
        access_token: str,
        pdql: str,
        utc_offset: str | None = None,
        selected_group_ids: list[str] | None = None,
        include_nested_groups: bool = True,
        asset_ids: list[str] | None = None,
    ) -> str:
        data = self.query_assets_grid(
            access_token,
            pdql,
            utc_offset=utc_offset,
            selected_group_ids=selected_group_ids,
            include_nested_groups=include_nested_groups,
            asset_ids=asset_ids,
        )
        token = data.get("token")
        if not token:
            raise MpVmApiError(f"PDQL token response does not contain token: {compact_json_summary(data)}")
        return str(token)

    def query_assets_grid(
        self,
        access_token: str,
        pdql: str,
        utc_offset: str | None = None,
        selected_group_ids: list[str] | None = None,
        include_nested_groups: bool = True,
        asset_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        body = self._asset_grid_body(
            pdql=pdql,
            utc_offset=utc_offset,
            selected_group_ids=selected_group_ids,
            include_nested_groups=include_nested_groups,
            asset_ids=asset_ids,
        )
        response = self.session.post(
            self._api_url(ASSET_GRID_PATH),
            headers=self._bearer_headers(access_token),
            json=body,
            timeout=self.auth.timeout,
        )
        return self._json_response(response, "query asset grid")

    @staticmethod
    def _asset_grid_body(
        *,
        pdql: str,
        utc_offset: str | None = None,
        selected_group_ids: list[str] | None = None,
        include_nested_groups: bool = True,
        asset_ids: list[str] | None = None,
    ) -> dict[str, Any]:
        selected_group_ids = selected_group_ids or []
        asset_ids = asset_ids or []
        body: dict[str, Any] = {
            "pdql": pdql,
            "selectedGroupIds": selected_group_ids,
            "includeNestedGroups": include_nested_groups,
        }
        if utc_offset:
            body["utcOffset"] = utc_offset

        additional_filter: dict[str, list[str]] = {}
        if selected_group_ids:
            additional_filter["groupIds"] = selected_group_ids
        if asset_ids:
            additional_filter["assetIds"] = asset_ids
        if additional_filter:
            body["additionalFilterParameters"] = additional_filter

        return body

    def fetch_csv(self, access_token: str, pdql_token: str) -> str:
        response = self.session.get(
            self._api_url(ASSET_GRID_EXPORT_PATH),
            headers={**self._bearer_headers(access_token), "Accept": "text/csv"},
            params={"pdqlToken": pdql_token},
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, "fetch CSV")
        if not response.encoding:
            response.encoding = "utf-8-sig"
        return response.text

    def fetch_asset_grid_data(
        self,
        access_token: str,
        pdql_token: str,
        limit: int = 1001,
        offset: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"limit": limit, "pdqlToken": pdql_token}
        if offset is not None:
            params["offset"] = offset
        response = self.session.get(
            self._api_url(ASSET_GRID_DATA_PATH),
            headers=self._bearer_headers(access_token),
            params=params,
            timeout=self.auth.timeout,
        )
        return self._json_response(response, "fetch asset grid data")

    def export_csv_file(self, access_token: str, pdql_token: str, output_path: Path) -> None:
        response = self.session.get(
            self._api_url(ASSET_GRID_EXPORT_PATH),
            headers={**self._bearer_headers(access_token), "Accept": "text/csv"},
            params={"pdqlToken": pdql_token},
            timeout=self.auth.timeout,
            stream=True,
        )
        self._raise_for_status(response, "export CSV")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as output_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output_file.write(chunk)

    def list_credentials(self, access_token: str) -> list[dict[str, Any]]:
        return ensure_list(self.get_json(access_token, CREDENTIALS_PATH), "credentials")

    def list_scopes(self, access_token: str) -> list[dict[str, Any]]:
        return ensure_list(self.get_json(access_token, SCOPES_PATH), "scopes")

    def list_scanner_profiles(self, access_token: str) -> list[dict[str, Any]]:
        return ensure_list(self.get_json(access_token, SCANNER_PROFILES_PATH), "scanner profiles")

    def get_vulnerability_passport(self, access_token: str, passport_id: str) -> dict[str, Any]:
        safe_id = quote(passport_id, safe="")
        data = self.get_json(access_token, VULNERABILITY_DETAIL_PATH.format(passport_id=safe_id))
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected vulnerability passport response: {compact_json_summary(data)}")
        return data

    def create_asset_timeline_token(self, access_token: str, asset_id: str, timestamp: int) -> str:
        safe_id = quote(asset_id, safe="")
        data = self.get_json(
            access_token,
            ASSET_TIMELINE_TOKEN_PATH.format(asset_id=safe_id),
            params={"datetime": timestamp},
        )
        if not isinstance(data, dict) or not data.get("token"):
            raise MpVmApiError(f"Asset timeline token response does not contain token: {compact_json_summary(data)}")
        return str(data["token"])

    def get_asset_tree_root(self, access_token: str, timeline_token: str) -> dict[str, Any]:
        data = self.get_json(access_token, ASSET_TREE_ROOT_PATH, params={"token": timeline_token})
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset tree root response: {compact_json_summary(data)}")
        return data

    def get_asset_metadata(self, access_token: str, asset_type: str) -> dict[str, Any]:
        safe_type = quote(asset_type, safe="")
        data = self.get_json(access_token, ASSET_METADATA_PATH.format(asset_type=safe_type))
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset metadata response: {compact_json_summary(data)}")
        return data

    def get_asset_tree_node(self, access_token: str, asset_type: str, object_id: str, timeline_token: str) -> dict[str, Any]:
        safe_type = quote(asset_type, safe="")
        safe_id = quote(object_id, safe="")
        data = self.get_json(
            access_token,
            ASSET_TREE_NODE_PATH.format(asset_type=safe_type, object_id=safe_id),
            params={"token": timeline_token},
        )
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset tree node response: {compact_json_summary(data)}")
        return data

    def get_asset_tree_collection(
        self,
        access_token: str,
        asset_type: str,
        object_id: str,
        collection_name: str,
        timeline_token: str,
        *,
        full: bool = True,
        limit: int = 500,
        offset: int = 0,
    ) -> dict[str, Any]:
        safe_type = quote(asset_type, safe="")
        safe_id = quote(object_id, safe="")
        safe_collection_name = quote(collection_name, safe="")
        data = self.get_json(
            access_token,
            ASSET_TREE_COLLECTION_PATH.format(
                asset_type=safe_type,
                object_id=safe_id,
                collection_name=safe_collection_name,
            ),
            params={
                "full": "true" if full else "false",
                "limit": limit,
                "offset": offset,
                "token": timeline_token,
            },
        )
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset tree collection response: {compact_json_summary(data)}")
        return data

    def get_asset_vulnerabilities_header(self, access_token: str, timeline_token: str) -> dict[str, Any]:
        safe_token = quote(timeline_token, safe="")
        data = self.get_json(
            access_token,
            ASSET_VULNERABILITIES_HEADER_PATH.format(timeline_token=safe_token),
        )
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset vulnerabilities header response: {compact_json_summary(data)}")
        return data

    def get_asset_vulnerability_groups(
        self,
        access_token: str,
        collection_type: str,
        timeline_token: str,
    ) -> dict[str, Any]:
        paths = {
            "HostOSVulnerabilities": ASSET_OS_VULNERABILITIES_PATH,
            "HostSoftVulnerabilities": ASSET_SOFTWARE_VULNERABILITIES_PATH,
        }
        path = paths.get(collection_type)
        if not path:
            raise ValueError(f"Unsupported asset vulnerability collection type: {collection_type}")
        safe_token = quote(timeline_token, safe="")
        data = self.get_json(access_token, path.format(timeline_token=safe_token))
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected {collection_type} response: {compact_json_summary(data)}")
        return data

    def get_asset_vulnerability_collection(
        self,
        access_token: str,
        collection_type: str,
        timeline_token: str,
        collection_id: str,
        *,
        limit: int = 1000,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        if collection_type not in {"HostOSVulnerabilities", "HostSoftVulnerabilities"}:
            raise ValueError(f"Unsupported asset vulnerability collection type: {collection_type}")
        safe_collection_type = quote(collection_type, safe="")
        safe_token = quote(timeline_token, safe="")
        safe_collection_id = quote(collection_id, safe="")
        data = self.get_json(
            access_token,
            ASSET_VULNERABILITY_COLLECTION_PATH.format(
                collection_type=safe_collection_type,
                timeline_token=safe_token,
                collection_id=safe_collection_id,
            ),
            params={"offset": offset, "limit": limit},
        )
        if isinstance(data, list):
            return [item for item in data if isinstance(item, dict)]
        if isinstance(data, dict):
            items = data.get("items") or data.get("data")
            if isinstance(items, list):
                return [item for item in items if isinstance(item, dict)]
        raise MpVmApiError(f"Unexpected {collection_type} collection response: {compact_json_summary(data)}")

    def list_remote_scanner_tasks(
        self,
        access_token: str,
        offset: int = 0,
        limit: int = 50,
        main_filter: str | None = None,
    ) -> Any:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if main_filter:
            params["mainFilter"] = main_filter
        response = self.session.post(
            self._api_url(SCANNER_TASKS_LIST_V4_PATH),
            headers=self._bearer_headers(access_token),
            json={},
            params=params,
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, "list remote scanner tasks")
        if not response.content:
            return {}
        return response.json()

    def create_scanner_task(self, access_token: str, payload: dict[str, Any]) -> str:
        response = self.session.post(
            self._api_url(SCANNER_TASKS_CREATE_PATH),
            headers=self._bearer_headers(access_token),
            json=payload,
            timeout=self.auth.timeout,
        )
        data = self._json_response(response, "create scanner task")
        task_id = data.get("id")
        if not task_id:
            raise MpVmApiError(f"Scanner task create response does not contain id: {compact_json_summary(data)}")
        return str(task_id)

    def update_scanner_task(self, access_token: str, task_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.put(
            self._api_url(SCANNER_TASKS_UPDATE_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            json=payload,
            timeout=self.auth.timeout,
        )
        if not response.content:
            self._raise_for_status(response, "update scanner task")
            return {"id": task_id}
        return self._json_response(response, "update scanner task")

    def delete_scanner_task(
        self,
        access_token: str,
        task_id: str,
        mode: str = "delete_v3",
        put_payload: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if mode == "put_v4":
            response = self.session.put(
                self._api_url(SCANNER_TASKS_UPDATE_PATH.format(task_id=task_id)),
                headers=self._bearer_headers(access_token),
                json=put_payload or {"isDeleted": True},
                timeout=self.auth.timeout,
            )
            self._raise_for_status(response, "delete scanner task via PUT v4")
            return response.json() if response.content else {"id": task_id, "mode": mode}

        response = self.session.delete(
            self._api_url(SCANNER_TASKS_DELETE_V3_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.auth.timeout,
        )
        if response.status_code == 404:
            return {"id": task_id, "mode": mode, "alreadyDeleted": True}
        self._raise_for_status(response, "delete scanner task")
        return response.json() if response.content else {"id": task_id, "mode": mode}

    def validate_scanner_task(self, access_token: str, task_id: str) -> tuple[bool, str | None]:
        response = self.session.get(
            self._api_url(SCANNER_TASK_VALIDATION_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.auth.timeout,
        )
        if response.ok:
            return True, None
        if response.status_code == 400:
            return False, self._response_summary(response)
        self._raise_for_status(response, "validate scanner task")
        return True, None

    def start_scanner_task(self, access_token: str, task_id: str) -> dict[str, Any]:
        response = self.session.post(
            self._api_url(SCANNER_TASK_START_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.auth.timeout,
        )
        return self._json_response(response, "start scanner task")

    def stop_scanner_task(self, access_token: str, task_id: str) -> dict[str, Any]:
        response = self.session.post(
            self._api_url(SCANNER_TASK_STOP_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, "stop scanner task")
        return response.json() if response.content else {"id": task_id, "status": "stop_requested"}

    def start_scanner_task_connection_check(self, access_token: str, task_id: str) -> dict[str, Any]:
        response = self.session.post(
            self._api_url(SCANNER_TASK_CONNECTION_CHECK_START_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            json=CONNECTION_CHECK_PAYLOAD,
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, "start scanner task connection check")
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}

    def get_task_runs(self, access_token: str, task_id: str, time_from: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"offset": 0, "limit": 1}
        if time_from:
            params["timeFrom"] = time_from
        data = self.get_json(access_token, SCANNER_TASK_RUNS_PATH.format(task_id=task_id), params=params)
        return ensure_items(data, "task runs")

    def get_run_jobs(
        self,
        access_token: str,
        run_id: str,
        *,
        target_pattern: str | None = None,
        orderby: str | None = None,
        offset: int = 0,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"offset": offset, "limit": limit}
        if target_pattern is not None:
            params["targetPattern"] = target_pattern
        if orderby:
            params["orderby"] = orderby
        data = self.get_json(access_token, SCANNER_RUN_JOBS_PATH.format(run_id=run_id), params=params)
        return ensure_items(data, "run jobs")

    def get_all_run_jobs(
        self,
        access_token: str,
        run_id: str,
        *,
        target_pattern: str | None = None,
        orderby: str | None = None,
        batch_size: int = 1000,
    ) -> list[dict[str, Any]]:
        jobs: list[dict[str, Any]] = []
        offset = 0
        while True:
            batch = self.get_run_jobs(
                access_token,
                run_id,
                target_pattern=target_pattern,
                orderby=orderby,
                offset=offset,
                limit=batch_size,
            )
            jobs.extend(batch)
            if len(batch) < batch_size:
                return jobs
            offset += len(batch)

    def split_successful_run_jobs(
        self,
        access_token: str,
        run_id: str,
        *,
        require_clean_jobs: bool = False,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        jobs = self.get_all_run_jobs(
            access_token,
            run_id,
            target_pattern="",
            orderby="startedAt desc",
            batch_size=100,
        )
        tracked_jobs = [
            job
            for job in jobs
            if not is_host_discovery_profile(job.get("profile"))
        ]
        successful: list[dict[str, Any]] = []
        for job in tracked_jobs:
            if "connectioncheck" in status_strings(job.get("runMode")):
                continue
            if not has_success_status(job.get("errorStatus")):
                continue
            if require_clean_jobs:
                job_id = str(job.get("id") or "")
                if job_id and self.get_job_errors_count(access_token, job_id) > 0:
                    continue
            successful.append(job)
        return tracked_jobs, successful

    def get_job_errors_count(self, access_token: str, job_id: str) -> int:
        data = self.get_json(access_token, SCANNER_JOB_ERRORS_PATH.format(job_id=job_id), params={"offset": 0, "limit": 1})
        if isinstance(data, dict):
            value = data.get("totalItems", data.get("totalCount", 0))
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0
        return 0

    def validate_scanner_task_with_retry(
        self,
        access_token: str,
        task_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> tuple[bool, str | None]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            valid, error = self.validate_scanner_task(access_token, task_id)
            if valid:
                return True, None
            if not is_scanner_task_not_found(error) or time.monotonic() >= deadline:
                return False, error
            time.sleep(poll_seconds)

    def start_scanner_task_with_retry(
        self,
        access_token: str,
        task_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                return self.start_scanner_task(access_token, task_id)
            except MpVmApiError as exc:
                if not is_scanner_task_not_found(str(exc)) or time.monotonic() >= deadline:
                    raise
                time.sleep(poll_seconds)

    def start_connection_check_with_retry(
        self,
        access_token: str,
        task_id: str,
        timeout_seconds: float,
        poll_seconds: float,
    ) -> dict[str, Any]:
        deadline = time.monotonic() + timeout_seconds
        while True:
            try:
                return self.start_scanner_task_connection_check(access_token, task_id)
            except MpVmApiError as exc:
                if not is_scanner_task_not_found(str(exc)) or time.monotonic() >= deadline:
                    raise
                time.sleep(poll_seconds)

    def wait_for_connection_check_targets(
        self,
        access_token: str,
        task_id: str,
        time_from: str,
        timeout_seconds: float,
        stop_after_seconds: float,
        poll_seconds: float,
        jobs_limit: int,
    ) -> tuple[list[str], str]:
        started_at = time.monotonic()
        deadline = started_at + timeout_seconds
        stop_deadline = started_at + stop_after_seconds if stop_after_seconds > 0 else None
        last_message = "no run yet"
        successful_targets: list[str] = []
        while time.monotonic() < deadline:
            now = time.monotonic()
            runs = self.get_task_runs(access_token, task_id, time_from=time_from)
            if not runs:
                if stop_deadline and now >= stop_deadline:
                    stop_message = self.stop_scanner_task_best_effort(access_token, task_id)
                    return [], f"stopped after {stop_after_seconds / 60:.1f} minute(s); no run found; {stop_message}"
                time.sleep(poll_seconds)
                continue

            run = runs[0]
            run_id = str(run.get("id", ""))
            if not run_id:
                return [], f"run does not contain id: {compact_json_summary(run)}"

            jobs = self.get_run_jobs(access_token, run_id, target_pattern="", orderby="startedAt desc", limit=jobs_limit)
            if jobs:
                successful_targets = dedupe_keep_order(successful_targets + extract_successful_connection_targets(jobs))
                last_message = f"run {run_id} has {len(successful_targets)} successful target(s)"
            else:
                last_message = f"run {run_id} has no jobs yet"

            if is_finished(run):
                if successful_targets:
                    return successful_targets, f"run {run_id}"
                if has_error_status(run.get("errorStatus")):
                    return [], f"run {run_id} has errorStatus={run.get('errorStatus')!r}"
                return [], f"run {run_id} has no jobs with full connection success"

            now = time.monotonic()
            if stop_deadline and now >= stop_deadline:
                stop_message = self.stop_scanner_task_best_effort(access_token, task_id)
                if successful_targets:
                    return successful_targets, (
                        f"stopped run {run_id} after {stop_after_seconds / 60:.1f} minute(s); "
                        f"using {len(successful_targets)} successful target(s); {stop_message}"
                    )
                return [], (
                    f"stopped run {run_id} after {stop_after_seconds / 60:.1f} minute(s); "
                    f"no successful targets; {stop_message}"
                )
            time.sleep(poll_seconds)
        return [], f"timeout after {timeout_seconds / 60:.1f} minute(s); last status: {last_message}"

    def wait_for_task_success(
        self,
        access_token: str,
        task_id: str,
        time_from: str,
        timeout_seconds: float,
        poll_seconds: float,
        require_clean_jobs: bool = False,
        stop_on_timeout: bool = True,
    ) -> tuple[bool, str]:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            runs = self.get_task_runs(access_token, task_id, time_from=time_from)
            if not runs:
                time.sleep(poll_seconds)
                continue

            run = runs[0]
            if not is_finished(run):
                time.sleep(poll_seconds)
                continue

            run_id = str(run.get("id", ""))
            run_error_status = run.get("errorStatus")
            if has_blocking_error_status(run_error_status) or (require_clean_jobs and has_error_status(run_error_status)):
                return False, f"run {run_id} has errorStatus={run_error_status!r}"
            if not run_id:
                return False, f"finished run does not contain id: {compact_json_summary(run)}"

            jobs = self.get_run_jobs(access_token, run_id)
            failed_jobs: list[str] = []
            jobs_with_errors: list[str] = []
            for job in jobs:
                job_id = str(job.get("id", ""))
                job_error_status = job.get("errorStatus")
                if has_blocking_error_status(job_error_status) or has_failed_status(job.get("status")):
                    failed_jobs.append(job_id or compact_json_summary(job))
                    continue
                if require_clean_jobs:
                    if has_error_status(job_error_status):
                        jobs_with_errors.append(job_id or compact_json_summary(job))
                        continue
                    if job_id and self.get_job_errors_count(access_token, job_id) > 0:
                        jobs_with_errors.append(job_id)

            if failed_jobs:
                return False, f"failed job(s): {format_limited_list(failed_jobs)}"
            if jobs_with_errors:
                return False, f"job(s) have non-green error status or job_errors: {format_limited_list(jobs_with_errors)}"
            return True, "ok"

        message = f"timeout after {timeout_seconds / 60:.1f} minute(s)"
        if stop_on_timeout:
            message += f"; {self.stop_scanner_task_best_effort(access_token, task_id)}"
        return False, message

    def stop_scanner_task_best_effort(self, access_token: str, task_id: str) -> str:
        try:
            self.stop_scanner_task(access_token, task_id)
            return "stop requested"
        except (MpVmApiError, requests.RequestException) as exc:
            return f"stop request failed: {exc}"

    def remove_assets(self, access_token: str, asset_ids: list[str]) -> str:
        response = self.session.post(
            self._api_url(ASSET_REMOVE_OPERATION_PATH),
            headers=self._bearer_headers(access_token),
            json={"assetsIds": asset_ids},
            timeout=self.auth.timeout,
        )
        data = self._json_response(response, "start asset removal")
        operation_id = data.get("operationId")
        if not operation_id:
            raise MpVmApiError(f"Asset removal response does not contain operationId: {compact_json_summary(data)}")
        return str(operation_id)

    def get_asset_removal_operation(self, access_token: str, operation_id: str) -> dict[str, Any]:
        response = self.session.get(
            self._api_url(ASSET_REMOVE_OPERATION_PATH),
            headers=self._bearer_headers(access_token),
            params={"operationId": operation_id},
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, "get asset removal operation")
        if response.status_code == 202 and not response.content.strip():
            return {"status": "processing", "httpStatus": 202}
        try:
            data = response.json()
        except ValueError as exc:
            raise MpVmApiError("Cannot parse JSON while trying to get asset removal operation.") from exc
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected asset removal operation response: {compact_json_summary(data)}")
        return data

    def wait_for_asset_removal(
        self,
        access_token: str,
        operation_id: str,
        timeout_seconds: float = 1800,
        poll_seconds: float = 10,
    ) -> tuple[bool, str, dict[str, Any] | None]:
        deadline = time.monotonic() + timeout_seconds
        last_data: dict[str, Any] | None = None
        last_message = f"operation {operation_id} is not finished"
        while time.monotonic() < deadline:
            last_data = self.get_asset_removal_operation(access_token, operation_id)
            done, ok, message = parse_asset_removal_operation(last_data)
            last_message = message
            if done:
                return ok, message, last_data
            time.sleep(poll_seconds)
        return False, f"timeout after {timeout_seconds / 60:.1f} minute(s); last status: {last_message}", last_data

    def get_json(self, access_token: str, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.session.get(
            self._api_url(path),
            headers=self._bearer_headers(access_token),
            params=params,
            timeout=self.auth.timeout,
        )
        self._raise_for_status(response, f"GET {path}")
        try:
            return response.json()
        except ValueError as exc:
            raise MpVmApiError(f"Cannot parse JSON from GET {path}.") from exc

    def _api_url(self, path: str) -> str:
        return f"{self.auth.api_url.rstrip('/')}{path}"

    @staticmethod
    def _bearer_headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def _json_response(self, response: requests.Response, action: str) -> dict[str, Any]:
        self._raise_for_status(response, action)
        try:
            data = response.json()
        except ValueError as exc:
            raise MpVmApiError(f"Cannot parse JSON while trying to {action}.") from exc
        if not isinstance(data, dict):
            raise MpVmApiError(f"Unexpected JSON payload while trying to {action}.")
        return data

    @staticmethod
    def _raise_for_status(response: requests.Response, action: str) -> None:
        if response.ok:
            return
        body = MpVmClient._response_summary(response)
        message = f"MP VM API failed to {action}: HTTP {response.status_code}"
        if body:
            message += f"; response: {body[:1000]}"
        raise MpVmApiError(message)

    @staticmethod
    def _response_summary(response: requests.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            return response.text[:1000].replace("\n", " ").strip()
        return compact_json_summary(data)


def build_scanner_task_payload(
    *,
    name: str,
    description: str | None,
    scope_id: str,
    profile_id: str,
    include_targets: list[str],
    exclude_targets: list[str] | None = None,
    agent_ids: list[str] | None = None,
    credential_id: str | None = None,
    host_discovery_enabled: bool = False,
    host_discovery_profile_id: str | None = None,
    time_zone: str = "+00:00",
    is_fqdn_priority: bool = True,
) -> dict[str, Any]:
    host_discovery: dict[str, Any] = {"enabled": host_discovery_enabled}
    if host_discovery_profile_id:
        host_discovery["profile"] = host_discovery_profile_id

    task: dict[str, Any] = {
        "name": name,
        "description": description or "",
        "scope": scope_id,
        "profile": profile_id,
        "overrides": build_windows_credential_overrides(credential_id),
        "include": {
            "assets": [],
            "targets": include_targets,
            "assetsGroups": [],
        },
        "exclude": {
            "assets": [],
            "targets": exclude_targets or [],
            "assetsGroups": [],
        },
        "hostDiscovery": host_discovery,
        "triggerParameters": build_disabled_daily_trigger(time_zone),
        "deniedScanSettings": {
            "isEnabled": False,
            "periods": [],
        },
        "isFqdnPriority": is_fqdn_priority,
        "groups": [],
    }
    if agent_ids:
        task["agents"] = {"agentIds": agent_ids}
    return task


def build_windows_credential_overrides(credential_id: str | None) -> dict[str, Any]:
    if not credential_id:
        return {}
    return {
        "transports": {
            "windows": {
                "wmi_and_rpc_and_re": {
                    "connection": {
                        "auth": {
                            "ref_value": credential_id,
                            "ref_type": "credential",
                        }
                    }
                }
            }
        }
    }


def build_disabled_daily_trigger(time_zone: str) -> dict[str, Any]:
    return {
        "isEnabled": False,
        "fromDate": utc_now_iso_millis(),
        "timeZone": time_zone,
        "type": "Daily",
        "atTime": "09:00:00",
        "daysOfWeek": ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"],
    }


def build_asset_id_pdql_for_ips(ips: list[str]) -> str:
    normalized: list[str] = []
    for ip in ips:
        try:
            normalized.append(str(ipaddress.ip_address(ip.strip())))
        except ValueError:
            continue
    if not normalized:
        return ASSET_ID_PDQL
    return f"filter(Host.@IpAddresses intersect [{', '.join(normalized)}]) | {ASSET_ID_PDQL}"


def build_asset_resolution_pdql(target: str) -> str:
    value = target.strip()
    if not value:
        raise MpVmApiError("Cannot build an asset resolution query for an empty target.")
    try:
        if "/" in value:
            network = str(ipaddress.ip_network(value, strict=False))
            predicate = f"Host.@IpAddresses.Item in {network}"
        else:
            address = str(ipaddress.ip_address(value))
            predicate = f"Host.@IpAddresses contains {address}"
    except ValueError:
        quoted = pdql_quote(value)
        predicate = f"Host.Fqdn = {quoted}"
    return f"filter({predicate}) | {ASSET_RESOLUTION_PDQL}"


def pdql_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def extract_asset_ids_from_csv(csv_text: str) -> list[str]:
    reader = csv_dict_reader(csv_text)
    asset_ids: list[str] = []
    for row in reader:
        asset_id = asset_id_from_csv_row(row)
        if asset_id:
            asset_ids.append(asset_id)
    return dedupe_keep_order(asset_ids)


def extract_ips_from_csv(csv_text: str) -> list[str]:
    reader = csv_dict_reader(csv_text)
    ips: list[str] = []
    for row in reader:
        for key, value in row.items():
            normalized_key = normalize_csv_key(key)
            if normalized_key in {"hostipaddress", "ipaddress", "ip"} and value:
                try:
                    ips.append(str(ipaddress.ip_address(value.strip())))
                except ValueError:
                    pass
    return dedupe_keep_order(ips)


def csv_dict_reader(csv_text: str) -> csv.DictReader:
    if not csv_text.strip():
        return csv.DictReader(io.StringIO(""))
    try:
        dialect = csv.Sniffer().sniff(csv_text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    return csv.DictReader(io.StringIO(csv_text), dialect=dialect)


def asset_id_from_csv_row(row: dict[str, str | None]) -> str | None:
    preferred_keys = {"assetid", "@host", "hostid", "id"}
    for key, value in row.items():
        if normalize_csv_key(key) in preferred_keys:
            asset_id = extract_uuid(value)
            if asset_id:
                return asset_id
    for value in row.values():
        asset_id = extract_uuid(value)
        if asset_id:
            return asset_id
    return None


def extract_uuid(value: Any) -> str | None:
    if value is None:
        return None
    match = re.search(
        r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b",
        str(value),
    )
    return match.group(0) if match else None


def normalize_csv_key(value: str | None) -> str:
    return re.sub(r"[^a-z0-9@]+", "", (value or "").strip("\ufeff").casefold())


def parse_asset_removal_operation(data: dict[str, Any]) -> tuple[bool, bool, str]:
    total = optional_int(data.get("totalCount", data.get("total")))
    succeed = optional_int(data.get("succeedCount", data.get("succeededCount", data.get("successCount"))))
    failed = optional_int(data.get("failedCount", data.get("failureCount", data.get("errorCount"))))
    message = compact_json_summary(data)
    if total is not None and succeed is not None and failed is not None and succeed + failed >= total:
        return True, failed == 0, f"total={total}, succeed={succeed}, failed={failed}"

    statuses = status_strings(data.get("status")) | status_strings(data.get("state")) | status_strings(data.get("type"))
    if statuses & {"finished", "completed", "success", "succeeded"}:
        return True, failed in (None, 0), message
    if statuses & {"failed", "error", "errored"}:
        return True, False, message
    return False, True, message


def ensure_list(data: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return as_dict_list(data, label)
    if isinstance(data, dict):
        for key in ("items", "scopes", "profiles", "credentials", "data", "values"):
            value = data.get(key)
            if isinstance(value, list):
                return as_dict_list(value, label)
    raise MpVmApiError(f"Unexpected {label} response: {compact_json_summary(data)}")


def ensure_items(data: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return as_dict_list(data, label)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return as_dict_list(data["items"], label)
    raise MpVmApiError(f"Unexpected {label} response: {compact_json_summary(data)}")


def as_dict_list(items: list[Any], label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise MpVmApiError(f"Unexpected item in {label} response: {item!r}")
        result.append(item)
    return result


def extract_successful_connection_targets(jobs: list[dict[str, Any]]) -> list[str]:
    targets: list[str] = []
    for job in jobs:
        if not is_successful_connection_check_job(job):
            continue
        raw_targets = job.get("targets")
        if not isinstance(raw_targets, list):
            continue
        for target in raw_targets:
            if isinstance(target, str) and target:
                targets.append(target)
    return dedupe_keep_order(targets)


def is_successful_connection_check_job(job: dict[str, Any]) -> bool:
    if "connectioncheck" not in status_strings(job.get("runMode")):
        return False
    if not is_finished(job) or has_failed_status(job.get("status")) or has_error_status(job.get("errorStatus")):
        return False
    results = job.get("connectionCheckResults")
    if not isinstance(results, list) or not results:
        return False
    return all(is_successful_connection_check_result(result) for result in results)


def is_successful_connection_check_result(result: Any) -> bool:
    if not isinstance(result, dict):
        return False
    if "success" not in status_strings(result.get("status")):
        return False
    return not result.get("errors")


def is_finished(data: dict[str, Any]) -> bool:
    if data.get("finishedAt"):
        return True
    statuses = status_strings(data.get("status"))
    return any(status in {"finished", "completed", "failed", "stopped", "suspended"} for status in statuses)


def has_failed_status(value: Any) -> bool:
    return any(status in {"failed", "error", "errored"} for status in status_strings(value))


def has_error_status(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, str):
        normalized = re.sub(r"[^a-z0-9]+", "", value.casefold())
        return normalized not in {"", "none", "noerror", "noerrors", "withouterrors", "ok", "success", "green"}
    if isinstance(value, list):
        return any(has_error_status(item) for item in value)
    if isinstance(value, dict):
        return any(has_error_status(item) for item in value.values())
    return bool(value)


def has_success_status(value: Any) -> bool:
    return any(status in {"success", "succeeded", "successful", "green", "ok"} for status in status_strings(value))


def is_host_discovery_profile(value: Any) -> bool:
    if isinstance(value, dict):
        value = value.get("name")
    normalized = re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())
    return "hostdiscovery" in normalized


def has_blocking_error_status(value: Any) -> bool:
    if value is None or value == "":
        return False
    if isinstance(value, str):
        normalized = re.sub(r"[^a-z0-9]+", "", value.casefold())
        if normalized in {"yellow", "warning", "warnings", "withwarnings"}:
            return False
        return has_error_status(value)
    if isinstance(value, list):
        return any(has_blocking_error_status(item) for item in value)
    if isinstance(value, dict):
        return any(has_blocking_error_status(item) for item in value.values())
    return bool(value)


def is_scanner_task_not_found(message: str | None) -> bool:
    if not message:
        return False
    normalized = message.casefold()
    return (
        "scanner task not found" in normalized
        or "task not found" in normalized
        or ("задач" in normalized and "не найден" in normalized)
    )


def normalize_url(url: str | None) -> str:
    if not url:
        raise MpVmApiError("URL is empty.")
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise MpVmApiError(f"Invalid URL: {url!r}. Use full URL with scheme, for example https://srv-siem.local")
    return url.rstrip("/")


def build_default_token_url(api_url: str) -> str:
    parsed = urlparse(api_url)
    netloc = parsed.hostname or parsed.netloc
    if parsed.username or parsed.password:
        raise MpVmApiError("Credentials in API URL are not supported.")
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    return urlunparse((parsed.scheme, f"{netloc}:3334", "/connect/token", "", "", ""))


def utc_now_iso_millis() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def status_strings(value: Any) -> set[str]:
    result: set[str] = set()
    if value is None:
        return result
    if isinstance(value, str):
        result.add(re.sub(r"[^a-z0-9]+", "", value.casefold()))
        return result
    if isinstance(value, list):
        for item in value:
            result.update(status_strings(item))
        return result
    if isinstance(value, dict):
        for item in value.values():
            result.update(status_strings(item))
        return result
    return result


def compact_json_summary(data: Any) -> str:
    try:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":"))[:1000]
    except TypeError:
        return str(data)[:1000]


def dedupe_keep_order(items: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def format_limited_list(items: list[str], limit: int = 20) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    shown = ", ".join(items[:limit])
    return f"{shown}, ... (+{len(items) - limit} more)"
