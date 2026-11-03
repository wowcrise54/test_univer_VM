from __future__ import annotations

from typing import Annotated, Any, Literal
from urllib.parse import quote

from mcp.server.mcpserver import MCPServer
from mcp_types import ToolAnnotations
from pydantic import Field

from . import __version__
from . import vulnerabilities as vuln
from .client import AppClient
from .config import McpSettings
from .shaping import fit_response

INSTRUCTIONS = (
    "Read-only access to vulnerability data of MP VM Client. "
    "To answer 'which hosts have vulnerability X' call find_hosts_by_vulnerability with the CVE, vulnerability id "
    "or name; the answer lists hosts and says whether MP VM describes a fix. "
    "Data is read from locally saved asset cards, so check last_seen / stale before trusting "
    "that a host is still affected (include_coverage adds the global completeness, but is slow). Nothing here can change data or start a fix or a scan."
)

READ_ONLY = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)

Severity = Literal["critical", "high", "medium", "low", "unknown"]
Source = Literal["os", "software", "docker"]
Limit = Annotated[int, Field(ge=1, le=200, description="Maximum number of rows to return.")]
Offset = Annotated[int, Field(ge=0, description="Rows to skip, for paging.")]


def build_server(settings: McpSettings, client: AppClient | Any) -> MCPServer:
    server = MCPServer("mpvm-vulnerabilities", instructions=INSTRUCTIONS, version=__version__)
    coverage = vuln.CoverageProbe(client)
    cap = settings.max_response_chars

    def read_only_tool(fn: Any) -> Any:
        return server.tool(annotations=READ_ONLY)(fn)

    @read_only_tool
    async def find_hosts_by_vulnerability(
        query: Annotated[str, Field(min_length=2, max_length=500, description="CVE id (CVE-2024-3094), vulnerability id or name.")],
        severity: Annotated[Severity | None, Field(description="Only findings of this severity.")] = None,
        source: Annotated[Source | None, Field(description="Only OS, software or docker findings.")] = None,
        host_q: Annotated[str | None, Field(max_length=500, description="Only hosts whose name, FQDN or IP contains this text.")] = None,
        limit: Limit = 50,
        offset: Offset = 0,
        include_coverage: Annotated[
            bool,
            Field(description="Also add the global completeness of the local data. Slow on large databases; off by default."),
        ] = False,
    ) -> dict[str, Any]:
        """List the hosts that currently have a vulnerability, with fix availability from the MP VM passport."""
        result = await vuln.find_hosts_by_vulnerability(
            client,
            coverage,
            query=query,
            stale_days=settings.stale_days,
            severity=severity,
            source=source,
            host_q=host_q,
            limit=limit,
            offset=offset,
            include_coverage=include_coverage,
        )
        return fit_response(result, cap)

    @read_only_tool
    async def get_vulnerability_fix_info(
        query: Annotated[str, Field(min_length=2, max_length=500, description="CVE id, vulnerability id or name.")],
        severity: Annotated[Severity | None, Field(description="Only findings of this severity.")] = None,
        source: Annotated[Source | None, Field(description="Only OS, software or docker findings.")] = None,
    ) -> dict[str, Any]:
        """Tell whether a vulnerability can be fixed according to its MP VM passport (information only, nothing is applied)."""
        return fit_response(await vuln.get_fix_info(client, query=query, severity=severity, source=source), cap)

    @read_only_tool
    async def search_vulnerabilities(
        q: Annotated[str | None, Field(max_length=500, description="Substring of CVE, id, name or affected object.")] = None,
        severity: Annotated[Severity | None, Field(description="Severity filter.")] = None,
        source: Annotated[Source | None, Field(description="OS, software or docker.")] = None,
        has_fix: Annotated[Literal["yes", "no", "any"] | None, Field(description="Filter by fix described in the passport.")] = None,
        fix_q: Annotated[str | None, Field(max_length=500, description="Text to find inside the fix description.")] = None,
        host_q: Annotated[str | None, Field(max_length=500, description="Limit to hosts matching this text.")] = None,
        os: Annotated[str | None, Field(max_length=500, description="Limit to hosts of this OS.")] = None,
        asset_type: Annotated[str | None, Field(max_length=200, description="Limit to this asset type.")] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Search vulnerabilities across all saved hosts; each row has the number of affected hosts and fix info."""
        result = await client.get(
            "/api/vulnerabilities",
            q=q,
            severity=severity,
            source=source,
            has_fix=has_fix,
            fix_q=fix_q,
            host_q=host_q,
            os=os,
            asset_type=asset_type,
            limit=limit,
            offset=offset,
        )
        return fit_response(
            {
                "total": result.get("total"),
                "offset": offset,
                "limit": limit,
                "rows": [vuln.slim_vulnerability(row) for row in result.get("rows", [])],
            },
            cap,
        )

    @read_only_tool
    async def list_host_vulnerabilities(
        asset_id: Annotated[str, Field(min_length=1, max_length=500, description="MP VM asset id of the host.")],
        severity: Annotated[Severity | None, Field(description="Severity filter.")] = None,
        source: Annotated[Source | None, Field(description="OS, software or docker.")] = None,
        limit: Limit = 50,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List the vulnerabilities of one host, with fix info."""
        result = await client.get(
            "/api/vulnerabilities", asset_id=asset_id, severity=severity, source=source, limit=limit, offset=offset
        )
        return fit_response(
            {
                "asset_id": asset_id,
                "total": result.get("total"),
                "offset": offset,
                "limit": limit,
                "rows": [vuln.slim_vulnerability(row) for row in result.get("rows", [])],
            },
            cap,
        )

    @read_only_tool
    async def find_hosts(
        q: Annotated[str | None, Field(max_length=500, description="Name, FQDN, IP or asset id fragment.")] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Find hosts among the saved asset cards."""
        return fit_response(await client.get("/api/asset-cards/local", q=q, limit=limit, offset=offset), cap)

    @read_only_tool
    async def get_host(
        asset_id: Annotated[str, Field(min_length=1, max_length=500, description="MP VM asset id of the host.")],
        section: Annotated[
            Literal["summary", "configuration", "vulnerabilities"], Field(description="Which part of the card.")
        ] = "summary",
    ) -> dict[str, Any]:
        """Get a saved host card (summary by default)."""
        return fit_response(await client.get(f"/api/asset-cards/{quote(asset_id, safe='')}", section=section), cap)

    @read_only_tool
    async def vulnerability_summary() -> dict[str, Any]:
        """Totals by severity, top vulnerabilities and hosts, and how complete and fresh the local data is. Can take minutes on a large database."""
        result = await client.get("/api/vulnerabilities/summary")
        return fit_response(
            {
                "source": result.get("source"),
                "totals": result.get("totals"),
                "by_severity": result.get("by_severity"),
                "coverage": result.get("coverage"),
                "top_vulnerabilities": [vuln.slim_vulnerability(row) for row in (result.get("top_vulnerabilities") or [])[:10]],
                "top_hosts": [
                    vuln.slim_host(row, stale_days=settings.stale_days) for row in (result.get("top_hosts") or [])[:10]
                ],
            },
            cap,
        )

    @read_only_tool
    async def trending_vulnerabilities(
        limit: Annotated[int, Field(ge=1, le=100, description="Maximum number of rows.")] = 20,
        context: Annotated[Literal["all", "docker", "host"], Field(description="Scope of the ranking.")] = "all",
    ) -> dict[str, Any]:
        """Trending vulnerabilities known to MP VM, ranked by affected hosts."""
        return fit_response(await client.get("/api/vulnerabilities/trending", limit=limit, context=context), cap)

    @read_only_tool
    async def list_remediation_cases(
        q: Annotated[str | None, Field(max_length=500, description="Text filter.")] = None,
        status: Annotated[
            Literal["open", "in_progress", "risk_accepted", "false_positive", "resolved"] | None,
            Field(description="Case status."),
        ] = None,
        severity: Annotated[Severity | None, Field(description="Severity filter.")] = None,
        assignee: Annotated[str | None, Field(max_length=200, description="Assignee user name.")] = None,
        overdue: Annotated[bool, Field(description="Only cases past their SLA due date.")] = False,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """List remediation cases (tracking of fixes: status, assignee, SLA). Read-only."""
        return fit_response(
            await client.get(
                "/api/remediation/cases",
                q=q,
                status=status,
                severity=severity,
                assignee=assignee,
                overdue=overdue,
                limit=limit,
                offset=offset,
            ),
            cap,
        )

    @read_only_tool
    async def remediation_summary() -> dict[str, Any]:
        """Counts of remediation cases by status, overdue cases and SLA policy."""
        return fit_response(
            {
                "summary": await client.get("/api/remediation/summary"),
                "resolution_stats": await client.get("/api/remediation/resolution-stats"),
            },
            cap,
        )

    @read_only_tool
    async def data_freshness(
        issue: Annotated[
            Literal["missing", "stale", "truncated", "failed"] | None,
            Field(description="List hosts with this coverage problem."),
        ] = None,
        q: Annotated[str | None, Field(max_length=500, description="Host text filter.")] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Coverage of the local data: how many hosts are missing, stale, truncated or failed to scan."""
        return fit_response(
            {
                "summary": await client.get("/api/coverage/summary"),
                "assets": await client.get("/api/coverage/assets", issue=issue, q=q, limit=limit, offset=offset),
            },
            cap,
        )

    @read_only_tool
    async def list_scan_tasks() -> dict[str, Any]:
        """Saved scanner tasks."""
        return fit_response(await client.get("/api/scanner-tasks"), cap)

    @read_only_tool
    async def list_operations(
        status: Annotated[str | None, Field(max_length=100, description="Operation status, e.g. running or failed.")] = None,
        kind: Annotated[str | None, Field(max_length=100, description="Operation kind.")] = None,
        q: Annotated[str | None, Field(max_length=500, description="Text filter.")] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Background operations (scans, refreshes) and their progress, plus a summary."""
        return fit_response(
            {
                "summary": await client.get("/api/operations/summary"),
                "operations": await client.get(
                    "/api/operations", status=status, kind=kind, q=q, limit=limit, offset=offset
                ),
            },
            cap,
        )

    @read_only_tool
    async def risk_queue(
        level: Annotated[Literal["urgent", "high", "medium", "low"] | None, Field(description="Risk level.")] = None,
        owner: Annotated[str | None, Field(max_length=200, description="Owner.")] = None,
        environment: Annotated[Literal["production", "test", "development"] | None, Field(description="Environment.")] = None,
        criticality: Annotated[Literal["critical", "high", "medium", "low"] | None, Field(description="Asset criticality.")] = None,
        exposure: Annotated[Literal["external", "internal", "isolated"] | None, Field(description="Exposure.")] = None,
        tag: Annotated[str | None, Field(max_length=100, description="Tag.")] = None,
        limit: Limit = 25,
        offset: Offset = 0,
    ) -> dict[str, Any]:
        """Hosts ranked by remediation risk."""
        return fit_response(
            await client.get(
                "/api/risk/queue",
                level=level,
                owner=owner,
                environment=environment,
                criticality=criticality,
                exposure=exposure,
                tag=tag,
                limit=limit,
                offset=offset,
            ),
            cap,
        )

    return server
