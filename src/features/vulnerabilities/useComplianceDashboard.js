import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client.js";
import { vulnerabilityApiUrl } from "./useVulnerabilityDashboard.js";

export function useComplianceDashboard({ scope, assessmentDate, enabled }) {
  const params = { assessment_date: assessmentDate };
  const base = `/api/vulnerabilities/compliance/${scope}`;
  const options = { enabled, staleTime: 30_000 };
  const summaryQuery = useQuery({
    queryKey: ["compliance-summary", scope, assessmentDate],
    queryFn: () => api(vulnerabilityApiUrl(`${base}/summary`, params)),
    ...options,
  });
  const findingsQuery = useQuery({
    queryKey: ["compliance-findings", scope, assessmentDate],
    queryFn: () => api(vulnerabilityApiUrl(`${base}/findings`, { ...params, limit: 500 })),
    ...options,
  });
  const staleQuery = useQuery({
    queryKey: ["compliance-stale", scope, assessmentDate],
    queryFn: () => api(vulnerabilityApiUrl(`${base}/stale-assets`, { ...params, limit: 500 })),
    ...options,
  });
  return { summaryQuery, findingsQuery, staleQuery };
}
