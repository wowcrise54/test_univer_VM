import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client.js";

export const VULNERABILITY_PAGE_SIZE = 50;

function compactParams(values) {
  const params = new URLSearchParams();
  Object.entries(values).forEach(([key, value]) => {
    if (value === undefined || value === null || value === "") return;
    params.set(key, String(value));
  });
  return params;
}

export function vulnerabilityApiUrl(path, values = {}) {
  const query = compactParams(values).toString();
  return query ? `${path}?${query}` : path;
}

function normalizedFilters(filters = {}) {
  return {
    q: String(filters.q || "").trim(),
    host_q: String(filters.host_q || "").trim(),
    os: String(filters.os || "").trim(),
    asset_type: String(filters.asset_type || "").trim(),
    asset_id: String(filters.asset_id || "").trim(),
    severity: String(filters.severity || ""),
    source: String(filters.source || ""),
    has_fix: String(filters.has_fix || ""),
    fix_q: String(filters.fix_q || "").trim(),
  };
}

export function useVulnerabilityDashboard({
  filters,
  mode = "vulnerabilities",
  applied = false,
  selectionRevision = 0,
  trendDays = 30,
  trendingContext = "all",
  vulnerabilityOffset,
  vulnerabilitySort,
  selectedSelector,
  hostOffset,
  hostSort,
  resolutionDays = 30,
  resolutionEnabled = false,
  pageSize = VULNERABILITY_PAGE_SIZE,
}) {
  const appliedFilters = normalizedFilters(filters);
  const trendRange = useMemo(() => {
    const to = new Date();
    const from = new Date(
      to.getTime() - Math.max(1, trendDays) * 24 * 60 * 60 * 1000,
    );
    return {
      from: from.toISOString(),
      to: to.toISOString(),
      bucket: trendDays >= 90 ? "week" : "day",
    };
  }, [trendDays]);
  const trendsQuery = useQuery({
    queryKey: ["vulnerability-trends", trendDays],
    queryFn: ({ signal }) =>
      api(vulnerabilityApiUrl("/api/vulnerabilities/trends", trendRange), {
        signal,
      }),
    staleTime: 60_000,
    enabled: mode === "dashboards",
  });
  const trendingPassportsQuery = useQuery({
    queryKey: ["trending-vulnerability-passports", trendingContext],
    queryFn: ({ signal }) =>
      api(
        vulnerabilityApiUrl("/api/vulnerabilities/trending", {
          limit: 20,
          context: trendingContext,
        }),
        { signal },
      ),
    staleTime: 60_000,
    enabled: mode === "dashboards",
  });
  const summaryQuery = useQuery({
    enabled: mode === "dashboards" || applied,
    queryKey: ["vulnerability-dashboard", appliedFilters, selectionRevision],
    queryFn: ({ signal }) =>
      api(vulnerabilityApiUrl("/api/vulnerabilities/summary", appliedFilters), {
        signal,
      }),
  });
  const assetFilterOptionsQuery = useQuery({
    enabled: mode === "vulnerabilities",
    queryKey: ["vulnerability-asset-filter-options"],
    queryFn: ({ signal }) =>
      api(
        vulnerabilityApiUrl("/api/asset-cards/local", {
          limit: 1000,
          sort_by: "display_name",
          sort_dir: "asc",
        }),
        { signal },
      ),
    staleTime: 5 * 60_000,
  });
  const vulnerabilitiesQuery = useQuery({
    enabled: mode === "vulnerabilities" && applied,
    queryKey: [
      "vulnerabilities",
      appliedFilters,
      selectionRevision,
      vulnerabilityOffset,
      vulnerabilitySort,
      pageSize,
    ],
    queryFn: ({ signal }) =>
      api(
        vulnerabilityApiUrl("/api/vulnerabilities", {
          ...appliedFilters,
          limit: pageSize,
          offset: vulnerabilityOffset,
          sort_by: vulnerabilitySort.key,
          sort_dir: vulnerabilitySort.direction,
        }),
        { signal },
      ),
  });
  const hostsQuery = useQuery({
    queryKey: [
      "vulnerability-hosts",
      selectedSelector,
      appliedFilters.source,
      appliedFilters.severity,
      appliedFilters.host_q,
      appliedFilters.os,
      appliedFilters.asset_type,
      appliedFilters.asset_id,
      selectionRevision,
      hostOffset,
      hostSort,
      pageSize,
    ],
    queryFn: ({ signal }) =>
      api(
        vulnerabilityApiUrl("/api/vulnerabilities/hosts", {
          selector: selectedSelector,
          source: appliedFilters.source,
          severity: appliedFilters.severity,
          host_q: appliedFilters.host_q,
          os: appliedFilters.os,
          asset_type: appliedFilters.asset_type,
          asset_id: appliedFilters.asset_id,
          limit: pageSize,
          offset: hostOffset,
          sort_by: hostSort.key,
          sort_dir: hostSort.direction,
        }),
        { signal },
      ),
    enabled: mode === "vulnerabilities" && applied && Boolean(selectedSelector),
  });
  const resolutionQuery = useQuery({
    queryKey: ["remediation-resolution-stats", resolutionDays],
    queryFn: ({ signal }) =>
      api(
        vulnerabilityApiUrl("/api/remediation/resolution-stats", {
          days: resolutionDays,
          recent_limit: 20,
        }),
        { signal },
      ),
    enabled: mode === "dashboards" && resolutionEnabled,
  });

  return {
    trendsQuery,
    trendingPassportsQuery,
    summaryQuery,
    assetFilterOptionsQuery,
    vulnerabilitiesQuery,
    hostsQuery,
    resolutionQuery,
  };
}
