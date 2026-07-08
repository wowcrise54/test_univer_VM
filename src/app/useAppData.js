import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";

const EMPTY_LOOKUPS = {
  credentials: [],
  scopes: [],
  scanner_profiles: [],
};

const EMPTY_CONNECTION_DRAFT = {
  api_url: "",
  token_url: "",
  username: "",
  password: "",
  client_id: "mpx",
  client_secret: "",
  scope: "",
  access_token: "",
  verify_tls: true,
};

const ACTIVE_OPERATION_STATUSES = new Set([
  "queued",
  "running",
  "cancelling",
  "recovering",
]);

function unavailableSystemStatus(error) {
  return {
    state: "down",
    checked_at: new Date().toISOString(),
    error,
    components: {
      application: {
        state: "down",
        message:
          error?.operatorMessage || error?.message || "Backend недоступен.",
        retryable: true,
        trace_id: error?.traceId || null,
      },
      database: {
        state: "down",
        message:
          "Состояние PostgreSQL неизвестно, потому что backend недоступен.",
        retryable: true,
      },
      mpvm: {
        state: "degraded",
        message: "Состояние сессии MP VM неизвестно.",
        retryable: true,
      },
      background_workers: {
        state: "down",
        message: "Состояние фоновых исполнителей неизвестно.",
        retryable: true,
      },
    },
  };
}

function assetsQuery(filters) {
  const params = new URLSearchParams({ limit: "300" });
  if (filters.q) params.set("q", filters.q);
  if (filters.severity) params.set("severity", filters.severity);
  if (filters.sort_by) params.set("sort_by", filters.sort_by);
  if (filters.sort_dir) params.set("sort_dir", filters.sort_dir);
  return Promise.all([
    api("/api/assets/summary"),
    api("/api/assets?" + params.toString()),
  ]).then(([summary, assets]) => ({
    summary,
    rows: assets.rows || [],
    total: assets.total || 0,
  }));
}

function operationsQuery(sorting) {
  const params = new URLSearchParams({ limit: "100" });
  if (sorting.sort_by) params.set("sort_by", sorting.sort_by);
  if (sorting.sort_dir) params.set("sort_dir", sorting.sort_dir);
  return api(`/api/operations?${params}`);
}

export function useAppData(routeId) {
  const queryClient = useQueryClient();
  const [session, setSessionState] = useState({ connected: false });
  const [connectionDraft, setConnectionDraft] = useState(
    EMPTY_CONNECTION_DRAFT,
  );
  const [lookups, setLookups] = useState(EMPTY_LOOKUPS);
  const [selectedTaskId, setSelectedTaskId] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState({});
  const [assetFilters, setAssetFilters] = useState({});
  const [operationSorting, setOperationSorting] = useState({});

  const defaultsQuery = useQuery({
    queryKey: ["defaults"],
    queryFn: () => api("/api/defaults"),
    staleTime: Infinity,
  });
  const sessionQuery = useQuery({
    queryKey: ["session"],
    queryFn: () => api("/api/session"),
    staleTime: Infinity,
  });
  const systemQuery = useQuery({
    queryKey: ["system-status"],
    queryFn: async () => {
      try {
        return await api("/api/system/status");
      } catch (error) {
        return unavailableSystemStatus(error);
      }
    },
    refetchInterval: 10000,
  });
  const systemStatus = systemQuery.data || null;
  const databaseAvailable =
    systemStatus?.components?.database?.state !== "down";

  const operationsQueryResult = useQuery({
    queryKey: ["operations", operationSorting],
    queryFn: () => operationsQuery(operationSorting),
    enabled: databaseAvailable,
    refetchInterval: (query) => {
      const rows = query.state.data?.rows || [];
      return rows.some((item) => ACTIVE_OPERATION_STATUSES.has(item.status))
        ? 2000
        : 15000;
    },
  });
  const tasksQueryResult = useQuery({
    queryKey: ["scanner-tasks"],
    queryFn: () => api("/api/scanner-tasks"),
    enabled: routeId === "tasks" && Boolean(systemStatus) && databaseAvailable,
    staleTime: Infinity,
  });
  const assetsQueryResult = useQuery({
    queryKey: ["assets", assetFilters],
    queryFn: () => assetsQuery(assetFilters),
    enabled: routeId === "assets" && Boolean(systemStatus) && databaseAvailable,
    staleTime: Infinity,
  });

  useEffect(() => {
    const value = defaultsQuery.data;
    if (!value) return;
    setConnectionDraft((current) => ({
      ...current,
      api_url: current.api_url || value.api_url || "",
      client_id: current.client_id || value.client_id || "mpx",
      scope: current.scope || value.scope || "",
    }));
  }, [defaultsQuery.data]);

  useEffect(() => {
    const value = sessionQuery.data;
    if (!value) return;
    setSessionState(value);
    setConnectionDraft((current) => ({
      ...current,
      api_url: value.api_url || current.api_url,
      token_url: value.token_url || current.token_url,
      username: value.username ?? current.username,
      verify_tls: value.verify_tls ?? current.verify_tls,
    }));
  }, [sessionQuery.data]);

  const showAlert = useCallback((message, type = "info") => {
    const id = Date.now() + "-" + Math.random();
    setAlerts((items) => {
      if (items.some((item) => item.message === message && item.type === type))
        return items;
      return [{ id, message, type }, ...items].slice(0, 4);
    });
    window.setTimeout(
      () => setAlerts((items) => items.filter((item) => item.id !== id)),
      9000,
    );
  }, []);

  const runBusy = useCallback(
    async (key, fn) => {
      setBusy((value) => ({ ...value, [key]: true }));
      try {
        return await fn();
      } catch (error) {
        showAlert(error.message || String(error), "error");
        return null;
      } finally {
        setBusy((value) => ({ ...value, [key]: false }));
      }
    },
    [showAlert],
  );

  const setSession = useCallback(
    (value) => {
      setSessionState(value);
      queryClient.setQueryData(["session"], value);
    },
    [queryClient],
  );

  const refreshTasks = useCallback(async () => {
    const result = await queryClient.fetchQuery({
      queryKey: ["scanner-tasks"],
      queryFn: () => api("/api/scanner-tasks"),
      staleTime: 0,
    });
    return result;
  }, [queryClient]);

  const refreshAssets = useCallback(
    async (filters = {}) => {
      setAssetFilters(filters);
      return queryClient.fetchQuery({
        queryKey: ["assets", filters],
        queryFn: () => assetsQuery(filters),
        staleTime: 0,
      });
    },
    [queryClient],
  );

  const refreshOperations = useCallback(
    async (sorting = {}) => {
      setOperationSorting(sorting);
      try {
        return await queryClient.fetchQuery({
          queryKey: ["operations", sorting],
          queryFn: () => operationsQuery(sorting),
          staleTime: 0,
        });
      } catch (_error) {
        return null;
      }
    },
    [queryClient],
  );

  const refreshSystemStatus = useCallback(
    () => systemQuery.refetch().then((result) => result.data),
    [systemQuery],
  );
  const tasks = useMemo(
    () => tasksQueryResult.data || [],
    [tasksQueryResult.data],
  );
  const selectedTask = useMemo(
    () => tasks.find((task) => task.mp_task_id === selectedTaskId) || null,
    [tasks, selectedTaskId],
  );
  const operations = operationsQueryResult.data?.rows || [];
  const assetsData = assetsQueryResult.data || {};

  return {
    alerts,
    assetRows: assetsData.rows || [],
    assetTotal: assetsData.total || 0,
    busy,
    connectionDraft,
    defaults: defaultsQuery.data || null,
    lookups,
    operations,
    operationsStale: !databaseAvailable || operationsQueryResult.isError,
    operationsTotal: operationsQueryResult.data?.total || 0,
    operationsUpdatedAt: operationsQueryResult.dataUpdatedAt
      ? new Date(operationsQueryResult.dataUpdatedAt).toISOString()
      : null,
    refreshAssets,
    refreshOperations,
    refreshSystemStatus,
    refreshTasks,
    runBusy,
    selectedTask,
    selectedTaskId,
    session,
    setConnectionDraft,
    setLookups,
    setSelectedTaskId,
    setSession,
    showAlert,
    summary: assetsData.summary || null,
    systemStatus,
    tasks,
  };
}
