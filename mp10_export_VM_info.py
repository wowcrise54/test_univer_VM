#!/usr/bin/env python3
"""Export MaxPatrol 10 asset tables to CSV with predefined PDQL queries."""

from __future__ import annotations

import argparse
import csv
import getpass
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, urlunparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry


ASSET_GRID_PATH = "/api/assets_temporal_readmodel/v1/assets_grid"
ASSET_GRID_EXPORT_PATH = "/api/assets_temporal_readmodel/v1/assets_grid/export"
SCOPES_PATH = "/api/scopes/v2/scopes"
CREDENTIALS_PATH = "/api/v3/credentials"
ASSET_REMOVE_OPERATION_PATH = "/api/assets_processing/v1/asset_operations/removeAssets"
SCANNER_PROFILES_PATH = "/api/scanning/v3/scanner_profiles"
SCANNER_TASKS_CREATE_PATH = "/api/scanning/v4/scanner_tasks/create"
SCANNER_TASK_VALIDATION_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/validation"
SCANNER_TASK_START_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/start"
SCANNER_TASK_STOP_PATH = "/api/scanning/v3/scanner_tasks/{task_id}/stop"
SCANNER_TASK_CONNECTION_CHECK_START_PATH = "/api/scanning/v4/scanner_tasks/{task_id}/start_connection_check"
SCANNER_TASK_RUNS_PATH = "/api/scanning/v2/scanner_tasks/{task_id}/runs"
SCANNER_RUN_JOBS_PATH = "/api/scanning/v2/runs/{run_id}/jobs"
SCANNER_JOB_ERRORS_PATH = "/api/scanning/v2/jobs/{job_id}/job_errors"
DEFAULT_AUDIT_PROFILE_NAME = "Windows Audit Vulnerabilities Discovery"
CONNECTION_CHECK_PAYLOAD = {"mode": "connectionAndAccounts", "agentSelectionMode": "all"}

PDQL_QUERIES = {
    "os": """select(Host.IpAddress, Host.Fqdn, Host.OsName, Host.OsVersion, Host.@NodeVulners as OsVulner, Host.@NodeVulners.CVEs as CVE, Host.@NodeVulners.SeverityRating as SeverityRating) | sort(CVE DESC)""",
    "softs": """select(Host.IpAddress, Host.Fqdn, Host.Softs.Name as SoftName, Host.Softs.Version as SoftVersion,
  Host.Softs.@Vulners as SoftVulner, Host.Softs.@Vulners.CVEs as CVE, Host.Softs.@Vulners.SeverityRating as SeverityRating)
| sort(Host.IpAddress ASC, SoftName ASC, SoftVersion ASC, SoftVulner ASC, CVE ASC)""",
}

OUTPUT_FILES = {
    "os": "host_os_vulnerabilities.csv",
    "softs": "host_software_vulnerabilities.csv",
}


class Mp10ApiError(RuntimeError):
    """Raised when MP10 API returns an unexpected response."""


@dataclass(frozen=True)
class AuthConfig:
    api_url: str
    token_url: str
    username: str | None
    password: str | None
    client_id: str
    client_secret: str | None
    scope: str
    access_token: str | None


class Mp10Client:
    def __init__(self, auth: AuthConfig, verify_tls: bool, timeout: float) -> None:
        self.auth = auth
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.session.headers.update({"User-Agent": "mp10-assets-csv-export/1.0"})
        self.session.mount("https://", self._build_retry_adapter())
        self.session.mount("http://", self._build_retry_adapter())

    @staticmethod
    def _build_retry_adapter() -> HTTPAdapter:
        retry = Retry(
            total=3,
            connect=3,
            read=3,
            status=3,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
        )
        return HTTPAdapter(max_retries=retry)

    def ensure_access_token(self) -> str:
        if self.auth.access_token:
            return self.auth.access_token

        required = {
            "username": self.auth.username,
            "password": self.auth.password,
            "client_secret": self.auth.client_secret,
        }
        missing = [name for name, value in required.items() if not value]
        if missing:
            raise Mp10ApiError(
                "Missing authentication fields: "
                + ", ".join(missing)
                + ". Pass them as arguments or environment variables, or set MP10_ACCESS_TOKEN."
            )

        form = {
            "username": self.auth.username,
            "password": self.auth.password,
            "client_id": self.auth.client_id,
            "client_secret": self.auth.client_secret,
            "grant_type": "password",
            "response_type": "code id_token",
            "scope": self.auth.scope,
        }
        response = self.session.post(self.auth.token_url, data=form, timeout=self.timeout)
        data = self._json_response(response, "get OAuth access token")
        token = data.get("access_token")
        if not token:
            raise Mp10ApiError("OAuth response does not contain access_token.")
        return str(token)

    def create_pdql_token(
        self,
        access_token: str,
        pdql: str,
        utc_offset: str | None,
        selected_group_ids: list[str],
        include_nested_groups: bool,
        asset_ids: list[str],
    ) -> str:
        body: dict[str, object] = {
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

        response = self.session.post(
            self._api_url(ASSET_GRID_PATH),
            headers=self._bearer_headers(access_token),
            json=body,
            timeout=self.timeout,
        )
        data = self._json_response(response, "create PDQL token")
        token = data.get("token")
        if not token:
            raise Mp10ApiError("PDQL token response does not contain token.")
        return str(token)

    def export_csv(self, access_token: str, pdql_token: str, output_path: Path) -> None:
        response = self.session.get(
            self._api_url(ASSET_GRID_EXPORT_PATH),
            headers={**self._bearer_headers(access_token), "Accept": "text/csv"},
            params={"pdqlToken": pdql_token},
            timeout=self.timeout,
            stream=True,
        )
        self._raise_for_status(response, "export CSV")

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("wb") as output_file:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output_file.write(chunk)

    def fetch_csv(self, access_token: str, pdql_token: str) -> str:
        response = self.session.get(
            self._api_url(ASSET_GRID_EXPORT_PATH),
            headers={**self._bearer_headers(access_token), "Accept": "text/csv"},
            params={"pdqlToken": pdql_token},
            timeout=self.timeout,
        )
        self._raise_for_status(response, "fetch CSV")
        if not response.encoding:
            response.encoding = "utf-8-sig"
        return response.text

    def list_scopes(self, access_token: str) -> list[dict[str, Any]]:
        data = self.get_json(access_token, SCOPES_PATH)
        return ensure_list(data, "scopes")

    def list_credentials(self, access_token: str) -> list[dict[str, Any]]:
        data = self.get_json(access_token, CREDENTIALS_PATH)
        return ensure_list(data, "credentials")

    def list_scanner_profiles(self, access_token: str) -> list[dict[str, Any]]:
        data = self.get_json(access_token, SCANNER_PROFILES_PATH)
        return ensure_list(data, "scanner profiles")

    def remove_assets(self, access_token: str, asset_ids: list[str]) -> str:
        response = self.session.post(
            self._api_url(ASSET_REMOVE_OPERATION_PATH),
            headers=self._bearer_headers(access_token),
            json={"assetsIds": asset_ids},
            timeout=self.timeout,
        )
        data = self._json_response(response, "start asset removal")
        operation_id = data.get("operationId")
        if not operation_id:
            raise Mp10ApiError(f"Asset removal response does not contain operationId: {data}")
        return str(operation_id)

    def get_asset_removal_operation(self, access_token: str, operation_id: str) -> dict[str, Any]:
        data = self.get_json(
            access_token,
            ASSET_REMOVE_OPERATION_PATH,
            params={"operationId": operation_id},
        )
        if not isinstance(data, dict):
            raise Mp10ApiError(f"Unexpected asset removal operation response: {compact_json_summary(data)}")
        return data

    def create_scanner_task(self, access_token: str, task: dict[str, Any]) -> str:
        response = self.session.post(
            self._api_url(SCANNER_TASKS_CREATE_PATH),
            headers=self._bearer_headers(access_token),
            json=task,
            timeout=self.timeout,
        )
        data = self._json_response(response, "create scanner task")
        task_id = data.get("id")
        if not task_id:
            raise Mp10ApiError(f"Scanner task create response does not contain id: {data}")
        return str(task_id)

    def validate_scanner_task(self, access_token: str, task_id: str) -> tuple[bool, str | None]:
        response = self.session.get(
            self._api_url(SCANNER_TASK_VALIDATION_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.timeout,
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
            timeout=self.timeout,
        )
        return self._json_response(response, "start scanner task")

    def stop_scanner_task(self, access_token: str, task_id: str) -> None:
        response = self.session.post(
            self._api_url(SCANNER_TASK_STOP_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            timeout=self.timeout,
        )
        self._raise_for_status(response, "stop scanner task")

    def start_scanner_task_connection_check(self, access_token: str, task_id: str) -> dict[str, Any]:
        response = self.session.post(
            self._api_url(SCANNER_TASK_CONNECTION_CHECK_START_PATH.format(task_id=task_id)),
            headers=self._bearer_headers(access_token),
            json=CONNECTION_CHECK_PAYLOAD,
            timeout=self.timeout,
        )
        self._raise_for_status(response, "start scanner task connection check")
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError:
            return {}
        if not isinstance(data, dict):
            return {}
        return data

    def get_task_runs(self, access_token: str, task_id: str, time_from: str | None = None) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"offset": 0, "limit": 1}
        if time_from:
            params["timeFrom"] = time_from
        data = self.get_json(
            access_token,
            SCANNER_TASK_RUNS_PATH.format(task_id=task_id),
            params=params,
        )
        return ensure_items(data, "task runs")

    def get_run_jobs(
        self,
        access_token: str,
        run_id: str,
        *,
        target_pattern: str | None = None,
        orderby: str | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"offset": 0, "limit": limit}
        if target_pattern is not None:
            params["targetPattern"] = target_pattern
        if orderby:
            params["orderby"] = orderby
        data = self.get_json(
            access_token,
            SCANNER_RUN_JOBS_PATH.format(run_id=run_id),
            params=params,
        )
        return ensure_items(data, "run jobs")

    def get_job_errors_count(self, access_token: str, job_id: str) -> int:
        data = self.get_json(
            access_token,
            SCANNER_JOB_ERRORS_PATH.format(job_id=job_id),
            params={"offset": 0, "limit": 1},
        )
        if isinstance(data, dict):
            value = data.get("totalItems", data.get("totalCount", 0))
            try:
                return int(value)
            except (TypeError, ValueError):
                return 0
        return 0

    def get_json(self, access_token: str, path: str, params: dict[str, Any] | None = None) -> Any:
        response = self.session.get(
            self._api_url(path),
            headers=self._bearer_headers(access_token),
            params=params,
            timeout=self.timeout,
        )
        self._raise_for_status(response, f"GET {path}")
        try:
            return response.json()
        except ValueError as exc:
            raise Mp10ApiError(f"Cannot parse JSON from GET {path}.") from exc

    def _api_url(self, path: str) -> str:
        return f"{self.auth.api_url.rstrip('/')}{path}"

    @staticmethod
    def _bearer_headers(access_token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {access_token}"}

    def _json_response(self, response: requests.Response, action: str) -> dict[str, object]:
        self._raise_for_status(response, action)
        try:
            data = response.json()
        except ValueError as exc:
            raise Mp10ApiError(f"Cannot parse JSON while trying to {action}.") from exc
        if not isinstance(data, dict):
            raise Mp10ApiError(f"Unexpected JSON payload while trying to {action}.")
        return data

    @staticmethod
    def _raise_for_status(response: requests.Response, action: str) -> None:
        if response.ok:
            return
        body = Mp10Client._response_summary(response)
        message = f"MP10 API failed to {action}: HTTP {response.status_code}"
        if body:
            message += f"; response: {body[:1000]}"
        raise Mp10ApiError(message)

    @staticmethod
    def _response_summary(response: requests.Response) -> str:
        try:
            data = response.json()
        except ValueError:
            return response.text[:1000].replace("\n", " ").strip()
        return compact_json_summary(data)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        api_url = normalize_url(args.api_url)
        token_url = normalize_url(args.token_url) if args.token_url else build_default_token_url(api_url)
        password = args.password or os.getenv("MP10_PASSWORD")

        if not args.access_token and not password and args.username:
            password = getpass.getpass("MP10 password: ")

        auth = AuthConfig(
            api_url=api_url,
            token_url=token_url,
            username=args.username,
            password=password,
            client_id=args.client_id,
            client_secret=args.client_secret,
            scope=args.scope,
            access_token=args.access_token,
        )
        client = Mp10Client(auth=auth, verify_tls=not args.insecure, timeout=args.timeout)
        access_token = client.ensure_access_token()
        if args.create_scan_tasks:
            run_scan_tasks(client, access_token, args)
        if not args.create_scan_tasks or args.export_assets:
            run_asset_exports(client, access_token, args)
    except Mp10ApiError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except requests.RequestException as exc:
        print(f"ERROR: HTTP request failed: {exc}", file=sys.stderr)
        return 1

    return 0


def parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export MaxPatrol 10 asset vulnerabilities to CSV by PDQL queries.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("MP10_API_URL"),
        required=not os.getenv("MP10_API_URL"),
        help="MP10 root API URL, for example https://mp10.example.local",
    )
    parser.add_argument(
        "--token-url",
        default=os.getenv("MP10_TOKEN_URL"),
        help="OAuth token URL. If omitted, :3334/connect/token is derived from --api-url.",
    )
    parser.add_argument("--username", default=os.getenv("MP10_USERNAME"), help="PT MC username")
    parser.add_argument(
        "--password",
        default=None,
        help="PT MC password. Prefer MP10_PASSWORD or interactive prompt.",
    )
    parser.add_argument("--client-id", default=os.getenv("MP10_CLIENT_ID", "mpx"), help="OAuth client_id")
    parser.add_argument(
        "--client-secret",
        default=os.getenv("MP10_CLIENT_SECRET"),
        help="OAuth client_secret for MP10 application",
    )
    parser.add_argument(
        "--scope",
        default=os.getenv("MP10_SCOPE", "authorization offline_access mpx.api ptkb.api"),
        help="OAuth scope",
    )
    parser.add_argument(
        "--access-token",
        default=os.getenv("MP10_ACCESS_TOKEN"),
        help="Existing Bearer token. If set, username/password/client_secret are not used.",
    )
    parser.add_argument(
        "--query",
        choices=sorted(PDQL_QUERIES),
        nargs="+",
        default=sorted(PDQL_QUERIES),
        help="Which predefined PDQL export to run",
    )
    parser.add_argument(
        "--export-assets",
        action="store_true",
        help="Export asset CSV files even when --create-scan-tasks is used.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path(os.getenv("MP10_OUTPUT_DIR", "exports")),
        help="Directory for exported CSV files",
    )
    parser.add_argument(
        "--utc-offset",
        default=os.getenv("MP10_UTC_OFFSET"),
        help="Optional PDQL utcOffset, for example +05:00",
    )
    parser.add_argument(
        "--group-id",
        action="append",
        default=env_list("MP10_GROUP_IDS"),
        help="Asset group UUID. Can be passed multiple times.",
    )
    parser.add_argument(
        "--asset-id",
        action="append",
        default=env_list("MP10_ASSET_IDS"),
        help="Asset UUID. Can be passed multiple times.",
    )
    parser.add_argument(
        "--include-nested-groups",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_INCLUDE_NESTED_GROUPS", True),
        help="Include nested asset groups when group filters are used",
    )
    parser.add_argument(
        "--create-scan-tasks",
        action="store_true",
        help="Create, validate, and start scanner tasks for /24 subnets from --subnets-file.",
    )
    parser.add_argument(
        "--subnets-file",
        type=Path,
        default=env_path("MP10_SUBNETS_FILE"),
        help="Text or CSV file with IPv4 /24 subnets. Lines may contain comments after #.",
    )
    parser.add_argument(
        "--scan-profile-id",
        default=os.getenv("MP10_SCAN_PROFILE_ID"),
        help="Scanner profile UUID for vulnerability collection.",
    )
    parser.add_argument(
        "--scan-profile-name",
        default=os.getenv("MP10_SCAN_PROFILE_NAME", DEFAULT_AUDIT_PROFILE_NAME),
        help="Scanner profile name for vulnerability collection.",
    )
    parser.add_argument(
        "--precheck-profile-id",
        default=os.getenv("MP10_PRECHECK_PROFILE_ID"),
        help="Optional scanner profile UUID used to create the connection-check task before the audit task.",
    )
    parser.add_argument(
        "--precheck-profile-name",
        default=os.getenv("MP10_PRECHECK_PROFILE_NAME"),
        help="Optional scanner profile name used to create the connection-check task before the audit task.",
    )
    parser.add_argument(
        "--scan-scope-id",
        default=os.getenv("MP10_SCAN_SCOPE_ID"),
        help="Infrastructure UUID. If omitted and only one scope exists, it is used automatically.",
    )
    parser.add_argument(
        "--scan-scope-name",
        default=os.getenv("MP10_SCAN_SCOPE_NAME"),
        help="Infrastructure name used when --scan-scope-id is omitted.",
    )
    parser.add_argument(
        "--scan-credential-id",
        action="append",
        default=env_list("MP10_SCAN_CREDENTIAL_IDS"),
        help="Scanner credential UUID for Windows transport auth override.",
    )
    parser.add_argument(
        "--scan-credential-name",
        action="append",
        default=env_list("MP10_SCAN_CREDENTIAL_NAMES"),
        help="Scanner credential name for Windows transport auth override.",
    )
    parser.add_argument(
        "--scan-agent-id",
        action="append",
        default=env_list("MP10_SCAN_AGENT_IDS"),
        help="Scanner collector/agent UUID. Can be passed multiple times.",
    )
    parser.add_argument(
        "--host-discovery-profile-id",
        default=os.getenv("MP10_HOST_DISCOVERY_PROFILE_ID"),
        help="Optional HostDiscovery profile UUID.",
    )
    parser.add_argument(
        "--host-discovery-profile-name",
        default=os.getenv("MP10_HOST_DISCOVERY_PROFILE_NAME"),
        help="Optional HostDiscovery profile name.",
    )
    parser.add_argument(
        "--host-discovery-enabled",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_HOST_DISCOVERY_ENABLED", False),
        help="Enable HostDiscovery before data collection.",
    )
    parser.add_argument(
        "--scan-task-prefix",
        default=os.getenv("MP10_SCAN_TASK_PREFIX", "MP10 Windows Audit"),
        help="Prefix for created vulnerability collection task names.",
    )
    parser.add_argument(
        "--precheck-task-prefix",
        default=os.getenv("MP10_PRECHECK_TASK_PREFIX", "MP10 credential precheck"),
        help="Prefix for created precheck task names.",
    )
    parser.add_argument(
        "--scan-time-zone",
        default=os.getenv("MP10_SCAN_TIME_ZONE", os.getenv("MP10_UTC_OFFSET", local_utc_offset())),
        help="Time zone for disabled task schedule, for example +05:00.",
    )
    parser.add_argument(
        "--scan-fqdn-priority",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_SCAN_FQDN_PRIORITY", True),
        help="Set isFqdnPriority in created scanner tasks.",
    )
    parser.add_argument(
        "--scan-start",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_SCAN_START", True),
        help="Start successfully validated scanner tasks.",
    )
    parser.add_argument(
        "--scan-skip-validation",
        action="store_true",
        default=env_bool("MP10_SCAN_SKIP_VALIDATION", False),
        help="Skip GET /validation after task creation and start the task directly.",
    )
    parser.add_argument(
        "--scan-create-settle-seconds",
        type=float,
        default=float(os.getenv("MP10_SCAN_CREATE_SETTLE_SECONDS", "30")),
        help="How long to retry validation/start when MP10 has not indexed the created task yet.",
    )
    parser.add_argument(
        "--precheck-timeout-minutes",
        type=float,
        default=float(os.getenv("MP10_PRECHECK_TIMEOUT_MINUTES", "30")),
        help="How long to wait for each precheck task to finish.",
    )
    parser.add_argument(
        "--precheck-max-runtime-minutes",
        type=float,
        default=float(os.getenv("MP10_PRECHECK_MAX_RUNTIME_MINUTES", "5")),
        help="Stop a running connection-check precheck after this many minutes and use already successful targets.",
    )
    parser.add_argument(
        "--precheck-poll-seconds",
        type=float,
        default=float(os.getenv("MP10_PRECHECK_POLL_SECONDS", "15")),
        help="How often to poll precheck task run status.",
    )
    parser.add_argument(
        "--precheck-jobs-limit",
        type=int,
        default=int(os.getenv("MP10_PRECHECK_JOBS_LIMIT", "250")),
        help="How many run jobs to read while parsing connection check results.",
    )
    parser.add_argument(
        "--scan-export-after-finish",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_SCAN_EXPORT_AFTER_FINISH", True),
        help="Wait for each audit task to finish and export vulnerability CSV files for its targets.",
    )
    parser.add_argument(
        "--scan-finish-timeout-minutes",
        type=float,
        default=float(os.getenv("MP10_SCAN_FINISH_TIMEOUT_MINUTES", "240")),
        help="How long to wait for each audit task to finish before export/delete.",
    )
    parser.add_argument(
        "--scan-finish-poll-seconds",
        type=float,
        default=float(os.getenv("MP10_SCAN_FINISH_POLL_SECONDS", "60")),
        help="How often to poll audit task run status.",
    )
    parser.add_argument(
        "--scan-export-settle-seconds",
        type=float,
        default=float(os.getenv("MP10_SCAN_EXPORT_SETTLE_SECONDS", "30")),
        help="How long to wait after an audit task finishes before exporting asset data.",
    )
    parser.add_argument(
        "--scan-require-clean-jobs",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_SCAN_REQUIRE_CLEAN_JOBS", False),
        help=(
            "Treat yellow audit errorStatus values and job_errors entries as task failure. "
            "By default only red/failed/error run or job statuses block export."
        ),
    )
    parser.add_argument(
        "--delete-assets-after-export",
        action=argparse.BooleanOptionalAction,
        default=env_bool("MP10_DELETE_ASSETS_AFTER_EXPORT", True),
        help="Delete scanned assets from MP10 after vulnerability export succeeds.",
    )
    parser.add_argument(
        "--delete-assets-timeout-minutes",
        type=float,
        default=float(os.getenv("MP10_DELETE_ASSETS_TIMEOUT_MINUTES", "30")),
        help="How long to wait for the asset removal operation to finish.",
    )
    parser.add_argument(
        "--delete-assets-poll-seconds",
        type=float,
        default=float(os.getenv("MP10_DELETE_ASSETS_POLL_SECONDS", "10")),
        help="How often to poll asset removal operation status.",
    )
    parser.add_argument(
        "--scan-dry-run",
        action="store_true",
        help="Print scanner task payloads without creating or starting tasks.",
    )
    parser.add_argument("--timeout", type=float, default=float(os.getenv("MP10_TIMEOUT", "120")), help="HTTP timeout")
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    return parser.parse_args(argv)


def run_asset_exports(client: Mp10Client, access_token: str, args: argparse.Namespace) -> list[Path]:
    return export_asset_vulnerability_csvs(
        client=client,
        access_token=access_token,
        args=args,
        targets=None,
        output_suffix=None,
    )


def export_asset_vulnerability_csvs(
    client: Mp10Client,
    access_token: str,
    args: argparse.Namespace,
    targets: list[str] | None,
    output_suffix: str | None,
) -> list[Path]:
    output_paths: list[Path] = []
    for query_name in args.query:
        pdql = build_filtered_pdql(PDQL_QUERIES[query_name], targets)
        target_text = f" for {', '.join(targets)}" if targets else ""
        print(f"[{query_name}] creating PDQL token{target_text}...")
        pdql_token = client.create_pdql_token(
            access_token=access_token,
            pdql=pdql,
            utc_offset=args.utc_offset,
            selected_group_ids=args.group_id,
            include_nested_groups=args.include_nested_groups,
            asset_ids=args.asset_id,
        )
        output_path = build_export_output_path(args.output_dir, query_name, output_suffix)
        print(f"[{query_name}] exporting CSV to {output_path}...")
        client.export_csv(access_token, pdql_token, output_path)
        print(f"[{query_name}] done")
        output_paths.append(output_path)
    return output_paths


def build_export_output_path(output_dir: Path, query_name: str, output_suffix: str | None) -> Path:
    output_name = OUTPUT_FILES[query_name]
    if not output_suffix:
        return output_dir / output_name
    path = Path(output_name)
    return output_dir / f"{path.stem}_{safe_file_part(output_suffix)}{path.suffix}"


def remove_assets_for_targets(
    client: Mp10Client,
    access_token: str,
    args: argparse.Namespace,
    targets: list[str],
    label: str,
) -> None:
    asset_ids = resolve_asset_ids_for_targets(client, access_token, args, targets)
    if not asset_ids:
        print(f"[{label}] no asset ids found for deletion")
        return

    print(f"[{label}] deleting {len(asset_ids)} asset(s)...")
    operation_id = client.remove_assets(access_token, asset_ids)
    ok, message = wait_for_asset_removal(
        client=client,
        access_token=access_token,
        operation_id=operation_id,
        timeout_seconds=args.delete_assets_timeout_minutes * 60,
        poll_seconds=args.delete_assets_poll_seconds,
    )
    if not ok:
        raise Mp10ApiError(f"Asset deletion failed for {label}: {message}")
    print(f"[{label}] assets deleted: {message}")


def resolve_asset_ids_for_targets(
    client: Mp10Client,
    access_token: str,
    args: argparse.Namespace,
    targets: list[str],
) -> list[str]:
    pdql = build_filtered_pdql("select(Host.@Id as AssetId, @Host as HostName, Host.IpAddress as IpAddress)", targets)
    print(f"[cleanup] resolving asset ids for {', '.join(targets)}...")
    pdql_token = client.create_pdql_token(
        access_token=access_token,
        pdql=pdql,
        utc_offset=args.utc_offset,
        selected_group_ids=args.group_id,
        include_nested_groups=args.include_nested_groups,
        asset_ids=args.asset_id,
    )
    return extract_asset_ids_from_csv(client.fetch_csv(access_token, pdql_token))


def wait_for_asset_removal(
    client: Mp10Client,
    access_token: str,
    operation_id: str,
    timeout_seconds: float,
    poll_seconds: float,
) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    last_message = f"operation {operation_id} is not finished"
    while time.monotonic() < deadline:
        data = client.get_asset_removal_operation(access_token, operation_id)
        done, ok, message = parse_asset_removal_operation(data)
        last_message = message
        if done:
            return ok, message
        time.sleep(poll_seconds)
    return False, f"timeout after {timeout_seconds / 60:.1f} minute(s); last status: {last_message}"


def parse_asset_removal_operation(data: dict[str, Any]) -> tuple[bool, bool, str]:
    total = optional_int(data.get("totalCount", data.get("total")))
    succeed = optional_int(data.get("succeedCount", data.get("succeededCount", data.get("successCount"))))
    failed = optional_int(data.get("failedCount", data.get("failureCount", data.get("errorCount"))))
    counts = [value for value in (total, succeed, failed) if value is not None]
    message = compact_json_summary(data)
    if total is not None and succeed is not None and failed is not None and succeed + failed >= total:
        return True, failed == 0, f"total={total}, succeed={succeed}, failed={failed}"

    statuses = status_strings(data.get("status")) | status_strings(data.get("state")) | status_strings(data.get("type"))
    if statuses & {"finished", "completed", "success", "succeeded"}:
        return True, failed in (None, 0), message
    if statuses & {"failed", "error", "errored"}:
        return True, False, message
    if counts:
        return False, True, ", ".join(str(value) for value in counts)
    return False, True, message


def extract_asset_ids_from_csv(csv_text: str) -> list[str]:
    if not csv_text.strip():
        return []
    try:
        dialect = csv.Sniffer().sniff(csv_text[:4096], delimiters=",;\t")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(csv_text.splitlines(), dialect=dialect)
    asset_ids: list[str] = []
    for row in reader:
        asset_id = asset_id_from_csv_row(row)
        if asset_id:
            asset_ids.append(asset_id)
    return dedupe_keep_order(asset_ids)


def asset_id_from_csv_row(row: dict[str, str | None]) -> str | None:
    preferred_keys = {"assetid", "@host", "hostid", "id"}
    for key, value in row.items():
        if key is None:
            continue
        normalized_key = re.sub(r"[^a-z0-9@]+", "", key.strip("\ufeff").casefold())
        if normalized_key in preferred_keys:
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
    if not match:
        return None
    return match.group(0)


def build_filtered_pdql(base_pdql: str, targets: list[str] | None) -> str:
    if not targets:
        return base_pdql
    return f"filter({build_target_pdql_predicate(targets)}) | {base_pdql}"


def build_target_pdql_predicate(targets: list[str]) -> str:
    ip_targets: list[str] = []
    network_targets: list[str] = []
    for target in targets:
        target = target.strip()
        if not target:
            continue
        try:
            if "/" in target:
                network_targets.append(str(ipaddress.ip_network(target, strict=False)))
            else:
                ip_targets.append(str(ipaddress.ip_address(target)))
        except ValueError as exc:
            raise Mp10ApiError(f"Unsupported target for PDQL filtering: {target!r}") from exc

    predicates: list[str] = []
    if ip_targets:
        predicates.append(f"Host.@IpAddresses intersect [{', '.join(ip_targets)}]")
    predicates.extend(f"Host.@IpAddresses.Item in {network}" for network in network_targets)
    if not predicates:
        raise Mp10ApiError("Cannot build PDQL target filter for empty target list.")
    if len(predicates) == 1:
        return predicates[0]
    return " or ".join(f"({predicate})" for predicate in predicates)


def safe_file_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("._") or "targets"


def optional_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def run_scan_tasks(client: Mp10Client, access_token: str, args: argparse.Namespace) -> None:
    if not args.subnets_file:
        raise Mp10ApiError("--subnets-file is required when --create-scan-tasks is used.")

    subnets = read_subnets_file(args.subnets_file)
    profiles: list[dict[str, Any]] | None = None

    def get_profiles() -> list[dict[str, Any]]:
        nonlocal profiles
        if profiles is None:
            profiles = client.list_scanner_profiles(access_token)
        return profiles

    audit_profile_id = args.scan_profile_id
    if not audit_profile_id:
        audit_profile_id = resolve_object_id(
            get_profiles(),
            args.scan_profile_name,
            "scanner profile",
        )
    precheck_profile_id = args.precheck_profile_id
    if not precheck_profile_id and args.precheck_profile_name:
        precheck_profile_id = resolve_object_id(get_profiles(), args.precheck_profile_name, "precheck scanner profile")

    host_discovery_profile_id = args.host_discovery_profile_id
    if not host_discovery_profile_id and args.host_discovery_profile_name:
        host_discovery_profile_id = resolve_object_id(
            get_profiles(),
            args.host_discovery_profile_name,
            "HostDiscovery profile",
        )
    if args.host_discovery_enabled and not host_discovery_profile_id:
        raise Mp10ApiError("--host-discovery-enabled requires --host-discovery-profile-id or --host-discovery-profile-name.")
    host_discovery_enabled = args.host_discovery_enabled or bool(host_discovery_profile_id)

    scope_id = args.scan_scope_id
    if not scope_id:
        scopes = client.list_scopes(access_token)
        scope_id = resolve_scope_id(scopes, args.scan_scope_name)

    credential_ids = list(args.scan_credential_id)
    if args.scan_credential_name:
        credentials = client.list_credentials(access_token)
        credential_ids.extend(
            resolve_object_id(credentials, credential_name, "scanner credential")
            for credential_name in args.scan_credential_name
        )
    credential_ids = dedupe_keep_order(credential_ids)
    credential_id = resolve_single_credential_id(credential_ids)
    agent_ids = dedupe_keep_order(list(args.scan_agent_id))

    print(f"[scan] loaded {len(subnets)} /24 subnet(s) from {args.subnets_file}")
    print(f"[scan] scope: {scope_id}")
    print(f"[scan] audit profile: {audit_profile_id} ({args.scan_profile_name})")
    if agent_ids:
        print(f"[scan] agents: {', '.join(agent_ids)}")
    if precheck_profile_id:
        print(f"[scan] precheck profile: {precheck_profile_id}")
    if credential_id:
        print(f"[scan] Windows transport credential: {credential_id}")

    failed_subnets: list[str] = []
    for subnet_index, subnet in enumerate(subnets, 1):
        target = str(subnet)
        print(f"[scan] processing subnet {subnet_index}/{len(subnets)}: {target}")
        try:
            process_scan_subnet(
                client=client,
                access_token=access_token,
                args=args,
                target=target,
                scope_id=scope_id,
                audit_profile_id=audit_profile_id,
                precheck_profile_id=precheck_profile_id,
                host_discovery_enabled=host_discovery_enabled,
                host_discovery_profile_id=host_discovery_profile_id,
                credential_id=credential_id,
                agent_ids=agent_ids,
            )
        except (Mp10ApiError, requests.RequestException) as exc:
            failed_subnets.append(f"{target}: {exc}")
            print(f"[scan] failed processing {target}: {exc}")
            continue
        print(f"[scan] finished subnet {subnet_index}/{len(subnets)}: {target}")

    if failed_subnets:
        print(f"[scan] completed with {len(failed_subnets)} failed subnet(s)")
        for failure in failed_subnets:
            print(f"[scan] failed subnet: {failure}")
        raise Mp10ApiError(f"{len(failed_subnets)} subnet(s) failed during scan workflow")


def process_scan_subnet(
    client: Mp10Client,
    access_token: str,
    args: argparse.Namespace,
    target: str,
    scope_id: str,
    audit_profile_id: str,
    precheck_profile_id: str | None,
    host_discovery_enabled: bool,
    host_discovery_profile_id: str | None,
    credential_id: str | None,
    agent_ids: list[str],
) -> None:
    audit_targets = [target]
    if precheck_profile_id:
        precheck_task = build_scanner_task(
            name=build_task_name(args.precheck_task_prefix, target),
            description=f"Connection check for {target}.",
            scope_id=scope_id,
            profile_id=precheck_profile_id,
            target=target,
            agent_ids=agent_ids,
            credential_id=credential_id,
            host_discovery_enabled=host_discovery_enabled,
            host_discovery_profile_id=host_discovery_profile_id,
            time_zone=args.scan_time_zone,
            is_fqdn_priority=args.scan_fqdn_priority,
        )
        audit_targets = create_run_parse_connection_precheck(
            client=client,
            access_token=access_token,
            task=precheck_task,
            label=f"precheck {target}",
            start_task=args.scan_start,
            dry_run=args.scan_dry_run,
            timeout_seconds=args.precheck_timeout_minutes * 60,
            stop_after_seconds=args.precheck_max_runtime_minutes * 60,
            poll_seconds=args.precheck_poll_seconds,
            jobs_limit=args.precheck_jobs_limit,
            skip_validation=args.scan_skip_validation,
            create_settle_seconds=args.scan_create_settle_seconds,
        )
        if not audit_targets:
            print(f"[scan] skipping audit task for {target}: precheck found no successful targets")
            return

    audit_task = build_scanner_task(
        name=build_task_name(args.scan_task_prefix, target),
        description=f"Windows audit vulnerability collection for {target}.",
        scope_id=scope_id,
        profile_id=audit_profile_id,
        target=audit_targets,
        agent_ids=agent_ids,
        credential_id=credential_id,
        host_discovery_enabled=host_discovery_enabled,
        host_discovery_profile_id=host_discovery_profile_id,
        time_zone=args.scan_time_zone,
        is_fqdn_priority=args.scan_fqdn_priority,
    )
    wait_for_audit_finish = args.scan_export_after_finish or args.delete_assets_after_export
    audit_ok = create_validate_start_task(
        client=client,
        access_token=access_token,
        task=audit_task,
        label=f"audit {target}",
        start_task=args.scan_start,
        dry_run=args.scan_dry_run,
        wait_for_finish=wait_for_audit_finish,
        timeout_seconds=args.scan_finish_timeout_minutes * 60,
        poll_seconds=args.scan_finish_poll_seconds,
        skip_validation=args.scan_skip_validation,
        create_settle_seconds=args.scan_create_settle_seconds,
        require_clean_jobs=args.scan_require_clean_jobs,
    )
    if not audit_ok:
        print(f"[scan] skipping export/delete for {target}: audit task failed")
        return
    if args.scan_dry_run or not args.scan_start:
        return
    if not args.scan_export_after_finish:
        if args.delete_assets_after_export:
            print(f"[scan] skipping asset deletion for {target}: vulnerability export is disabled")
        return

    if args.scan_export_settle_seconds > 0:
        print(f"[scan] waiting {args.scan_export_settle_seconds:.0f}s before exporting results for {target}...")
        time.sleep(args.scan_export_settle_seconds)
    export_asset_vulnerability_csvs(
        client=client,
        access_token=access_token,
        args=args,
        targets=audit_targets,
        output_suffix=target,
    )
    if args.delete_assets_after_export:
        remove_assets_for_targets(
            client=client,
            access_token=access_token,
            args=args,
            targets=audit_targets,
            label=f"cleanup {target}",
        )


def create_run_parse_connection_precheck(
    client: Mp10Client,
    access_token: str,
    task: dict[str, Any],
    label: str,
    start_task: bool,
    dry_run: bool,
    timeout_seconds: float,
    stop_after_seconds: float,
    poll_seconds: float,
    jobs_limit: int,
    skip_validation: bool,
    create_settle_seconds: float,
) -> list[str]:
    if dry_run:
        print(f"[{label}] dry-run payload:")
        print(json.dumps(task, ensure_ascii=False, indent=2))
        print(f"[{label}] dry-run connection-check payload:")
        print(json.dumps(CONNECTION_CHECK_PAYLOAD, ensure_ascii=False, indent=2))
        print(f"[{label}] dry-run uses original target in audit preview; successful IPs are known only after run.")
        return list(task.get("include", {}).get("targets", []))

    print(f"[{label}] creating scanner task...")
    task_id = client.create_scanner_task(access_token, task)
    if skip_validation:
        print(f"[{label}] created task {task_id}; validation skipped")
    else:
        print(f"[{label}] created task {task_id}; validating...")
        valid, validation_error = validate_scanner_task_with_retry(
            client=client,
            access_token=access_token,
            task_id=task_id,
            timeout_seconds=create_settle_seconds,
            poll_seconds=min(poll_seconds, 5),
        )
        if not valid:
            print(f"[{label}] validation failed: {validation_error}")
            return []
    if not start_task:
        print(f"[{label}] task is ready; connection check start disabled")
        return []

    started_from = datetime.now(timezone.utc).isoformat()
    print(f"[{label}] starting connection check...")
    start_scanner_task_connection_check_with_retry(
        client=client,
        access_token=access_token,
        task_id=task_id,
        timeout_seconds=create_settle_seconds,
        poll_seconds=min(poll_seconds, 5),
    )
    print(f"[{label}] waiting for connection check result...")
    targets, message = wait_for_connection_check_targets(
        client=client,
        access_token=access_token,
        task_id=task_id,
        time_from=started_from,
        timeout_seconds=timeout_seconds,
        stop_after_seconds=stop_after_seconds,
        poll_seconds=poll_seconds,
        jobs_limit=jobs_limit,
    )
    if targets:
        print(f"[{label}] successful target(s): {', '.join(targets)}")
    else:
        print(f"[{label}] no successful targets: {message}")
    return targets


def create_validate_start_task(
    client: Mp10Client,
    access_token: str,
    task: dict[str, Any],
    label: str,
    start_task: bool,
    dry_run: bool,
    wait_for_finish: bool,
    timeout_seconds: float,
    poll_seconds: float,
    skip_validation: bool,
    create_settle_seconds: float,
    require_clean_jobs: bool,
) -> bool:
    if dry_run:
        print(f"[{label}] dry-run payload:")
        print(json.dumps(task, ensure_ascii=False, indent=2))
        return True

    print(f"[{label}] creating scanner task...")
    task_id = client.create_scanner_task(access_token, task)
    if skip_validation:
        print(f"[{label}] created task {task_id}; validation skipped")
    else:
        print(f"[{label}] created task {task_id}; validating...")
        valid, validation_error = validate_scanner_task_with_retry(
            client=client,
            access_token=access_token,
            task_id=task_id,
            timeout_seconds=create_settle_seconds,
            poll_seconds=min(poll_seconds, 5),
        )
        if not valid:
            print(f"[{label}] validation failed: {validation_error}")
            return False
    if not start_task:
        print(f"[{label}] task is ready; start disabled")
        return True

    started_from = datetime.now(timezone.utc).isoformat()
    print(f"[{label}] starting task...")
    start_scanner_task_with_retry(
        client=client,
        access_token=access_token,
        task_id=task_id,
        timeout_seconds=create_settle_seconds,
        poll_seconds=min(poll_seconds, 5),
    )
    if not wait_for_finish:
        print(f"[{label}] started")
        return True

    print(f"[{label}] waiting for task result...")
    ok, message = wait_for_task_success(
        client=client,
        access_token=access_token,
        task_id=task_id,
        time_from=started_from,
        timeout_seconds=timeout_seconds,
        poll_seconds=poll_seconds,
        require_clean_jobs=require_clean_jobs,
    )
    if ok:
        if message == "ok":
            print(f"[{label}] task completed successfully")
        else:
            print(f"[{label}] task completed successfully: {message}")
    else:
        print(f"[{label}] task failed: {message}")
    return ok


def validate_scanner_task_with_retry(
    client: Mp10Client,
    access_token: str,
    task_id: str,
    timeout_seconds: float,
    poll_seconds: float,
) -> tuple[bool, str | None]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        valid, error = client.validate_scanner_task(access_token, task_id)
        if valid:
            return True, None
        if not is_scanner_task_not_found(error) or time.monotonic() >= deadline:
            return False, error
        time.sleep(poll_seconds)


def start_scanner_task_with_retry(
    client: Mp10Client,
    access_token: str,
    task_id: str,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return client.start_scanner_task(access_token, task_id)
        except Mp10ApiError as exc:
            if not is_scanner_task_not_found(str(exc)) or time.monotonic() >= deadline:
                raise
            time.sleep(poll_seconds)


def start_scanner_task_connection_check_with_retry(
    client: Mp10Client,
    access_token: str,
    task_id: str,
    timeout_seconds: float,
    poll_seconds: float,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            return client.start_scanner_task_connection_check(access_token, task_id)
        except Mp10ApiError as exc:
            if not is_scanner_task_not_found(str(exc)) or time.monotonic() >= deadline:
                raise
            time.sleep(poll_seconds)


def stop_scanner_task_best_effort(client: Mp10Client, access_token: str, task_id: str) -> str:
    try:
        client.stop_scanner_task(access_token, task_id)
        return "stop requested"
    except Mp10ApiError as exc:
        return f"stop request failed: {exc}"


def wait_for_task_success(
    client: Mp10Client,
    access_token: str,
    task_id: str,
    time_from: str,
    timeout_seconds: float,
    poll_seconds: float,
    require_clean_jobs: bool,
) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        runs = client.get_task_runs(access_token, task_id, time_from=time_from)
        if not runs:
            time.sleep(poll_seconds)
            continue

        run = runs[0]
        if not is_finished(run):
            time.sleep(poll_seconds)
            continue

        run_id = str(run.get("id", ""))
        run_error_status = run.get("errorStatus")
        if has_blocking_error_status(run_error_status) or (
            require_clean_jobs and has_error_status(run_error_status)
        ):
            return False, f"run {run_id} has errorStatus={run.get('errorStatus')!r}"
        if not run_id:
            return False, f"finished run does not contain id: {run}"

        jobs = client.get_run_jobs(access_token, run_id)
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
                if job_id and client.get_job_errors_count(access_token, job_id) > 0:
                    jobs_with_errors.append(job_id)

        if failed_jobs:
            return False, f"failed job(s): {format_limited_list(failed_jobs)}"
        if jobs_with_errors:
            return False, f"job(s) have non-green error status or job_errors: {format_limited_list(jobs_with_errors)}"
        return True, "ok"

    return False, f"timeout after {timeout_seconds / 60:.1f} minute(s)"


def wait_for_connection_check_targets(
    client: Mp10Client,
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
        runs = client.get_task_runs(access_token, task_id, time_from=time_from)
        if not runs:
            if stop_deadline and now >= stop_deadline:
                stop_message = stop_scanner_task_best_effort(client, access_token, task_id)
                return [], f"stopped after {stop_after_seconds / 60:.1f} minute(s); no run found; {stop_message}"
            time.sleep(poll_seconds)
            continue

        run = runs[0]
        run_id = str(run.get("id", ""))
        if not run_id:
            return [], f"finished run does not contain id: {run}"

        jobs = client.get_run_jobs(
            access_token,
            run_id,
            target_pattern="",
            orderby="startedAt desc",
            limit=jobs_limit,
        )
        if jobs:
            successful_targets = dedupe_keep_order(
                successful_targets + extract_successful_connection_targets(jobs)
            )
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
            stop_message = stop_scanner_task_best_effort(client, access_token, task_id)
            if successful_targets:
                return successful_targets, (
                    f"stopped run {run_id} after {stop_after_seconds / 60:.1f} minute(s); "
                    f"using {len(successful_targets)} successful target(s); {stop_message}"
                )
            return [], (
                f"stopped run {run_id} after {stop_after_seconds / 60:.1f} minute(s); "
                f"no successful targets; {stop_message}"
            )

        if not jobs:
            time.sleep(poll_seconds)
            continue
        time.sleep(poll_seconds)

    return [], f"timeout after {timeout_seconds / 60:.1f} minute(s); last status: {last_message}"


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
    errors = result.get("errors")
    return not errors


def build_scanner_task(
    name: str,
    description: str,
    scope_id: str,
    profile_id: str,
    target: str | list[str],
    agent_ids: list[str],
    credential_id: str | None,
    host_discovery_enabled: bool,
    host_discovery_profile_id: str | None,
    time_zone: str,
    is_fqdn_priority: bool,
) -> dict[str, Any]:
    targets = [target] if isinstance(target, str) else target
    host_discovery: dict[str, Any] = {"enabled": host_discovery_enabled}
    if host_discovery_profile_id:
        host_discovery["profile"] = host_discovery_profile_id

    task: dict[str, Any] = {
        "name": name,
        "description": description,
        "scope": scope_id,
        "profile": profile_id,
    }
    if agent_ids:
        task["agents"] = {"agentIds": agent_ids}
    task.update({
        "overrides": build_windows_credential_overrides(credential_id),
        "include": {
            "assets": [],
            "targets": targets,
            "assetsGroups": [],
        },
        "exclude": {
            "assets": [],
            "targets": [],
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
    })
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
        "daysOfWeek": [
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ],
    }


def utc_now_iso_millis() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def build_task_name(prefix: str, target: str) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    safe_target = target.replace("/", "_")
    return f"{prefix} {safe_target} {stamp}"


def read_subnets_file(path: Path) -> list[ipaddress.IPv4Network]:
    if not path.exists():
        raise Mp10ApiError(f"Subnets file does not exist: {path}")

    subnets: list[ipaddress.IPv4Network] = []
    for line_no, raw_line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        for token in re.split(r"[,;\s]+", line):
            token = token.strip()
            if not token or token.lower() in {"subnet", "network", "target", "targets"}:
                continue
            subnets.append(parse_ipv4_24_network(token, path, line_no))

    if not subnets:
        raise Mp10ApiError(f"Subnets file is empty: {path}")
    return dedupe_keep_order(subnets)


def parse_ipv4_24_network(token: str, path: Path, line_no: int) -> ipaddress.IPv4Network:
    value = token if "/" in token else f"{token}/24"
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise Mp10ApiError(f"Invalid subnet {token!r} in {path}:{line_no}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise Mp10ApiError(f"Only IPv4 /24 subnets are supported, got {token!r} in {path}:{line_no}")
    if network.prefixlen != 24:
        raise Mp10ApiError(f"Expected /24 subnet, got {network} in {path}:{line_no}")
    return network


def resolve_scope_id(scopes: list[dict[str, Any]], scope_name: str | None) -> str:
    if scope_name:
        return resolve_object_id(scopes, scope_name, "scope")
    if len(scopes) == 1 and scopes[0].get("id"):
        return str(scopes[0]["id"])
    names = ", ".join(str(scope.get("name", scope.get("id", "<unnamed>"))) for scope in scopes[:10])
    raise Mp10ApiError(
        "Cannot choose infrastructure automatically. "
        f"Pass --scan-scope-id or --scan-scope-name. Available scopes: {names}"
    )


def resolve_single_credential_id(credential_ids: list[str]) -> str | None:
    if not credential_ids:
        return None
    if len(credential_ids) == 1:
        return credential_ids[0]
    raise Mp10ApiError(
        "Windows transport credential override supports exactly one credential. "
        f"Got: {', '.join(credential_ids)}"
    )


def resolve_object_id(objects: list[dict[str, Any]], name: str | None, label: str) -> str:
    if not name:
        raise Mp10ApiError(f"Pass {label} id or name.")
    matches = [item for item in objects if str(item.get("name", "")).casefold() == name.casefold()]
    if len(matches) == 1 and matches[0].get("id"):
        return str(matches[0]["id"])
    if len(matches) > 1:
        ids = ", ".join(str(item.get("id")) for item in matches)
        raise Mp10ApiError(f"Found multiple {label}s named {name!r}: {ids}")

    hints = [
        str(item.get("name"))
        for item in objects
        if name.casefold() in str(item.get("name", "")).casefold()
    ][:10]
    hint_text = f" Similar names: {', '.join(hints)}" if hints else ""
    raise Mp10ApiError(f"Cannot find {label} named {name!r}.{hint_text}")


def ensure_list(data: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return as_dict_list(data, label)
    if isinstance(data, dict):
        for key in ("items", "scopes", "profiles", "credentials", "data", "values"):
            value = data.get(key)
            if isinstance(value, list):
                return as_dict_list(value, label)
    raise Mp10ApiError(f"Unexpected {label} response: {compact_json_summary(data)}")


def ensure_items(data: Any, label: str) -> list[dict[str, Any]]:
    if isinstance(data, list):
        return as_dict_list(data, label)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return as_dict_list(data["items"], label)
    raise Mp10ApiError(f"Unexpected {label} response: {compact_json_summary(data)}")


def as_dict_list(items: list[Any], label: str) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            raise Mp10ApiError(f"Unexpected item in {label} response: {item!r}")
        result.append(item)
    return result


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


def format_limited_list(items: list[str], limit: int = 20) -> str:
    if len(items) <= limit:
        return ", ".join(items)
    shown = ", ".join(items[:limit])
    return f"{shown}, ... and {len(items) - limit} more"


def dedupe_keep_order(items: list[Any]) -> list[Any]:
    seen: set[Any] = set()
    result: list[Any] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    return result


def normalize_url(url: str | None) -> str:
    if not url:
        raise Mp10ApiError("URL is empty.")
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise Mp10ApiError(f"Invalid URL: {url!r}. Use full URL with scheme, for example https://mp10.local")
    return url.rstrip("/")


def build_default_token_url(api_url: str) -> str:
    parsed = urlparse(api_url)
    netloc = parsed.hostname or parsed.netloc
    if parsed.username or parsed.password:
        raise Mp10ApiError("Credentials in --api-url are not supported.")
    if ":" in netloc and not netloc.startswith("["):
        netloc = f"[{netloc}]"
    return urlunparse((parsed.scheme, f"{netloc}:3334", "/connect/token", "", "", ""))


def env_list(name: str) -> list[str]:
    raw = os.getenv(name)
    if not raw:
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_path(name: str) -> Path | None:
    raw = os.getenv(name)
    if not raw:
        return None
    return Path(raw)


def local_utc_offset() -> str:
    offset = datetime.now().astimezone().utcoffset()
    if offset is None:
        return "+00:00"
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours, minutes = divmod(total_minutes, 60)
    return f"{sign}{hours:02d}:{minutes:02d}"


def env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


if __name__ == "__main__":
    raise SystemExit(main())
