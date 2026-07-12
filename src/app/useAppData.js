import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

const DEFAULT_OPERATION_QUERY = {
  limit: 50,
  offset: 0,
  q: "",
  status: "",
  kind: "",
  sort_by: "created_at",
  sort_dir: "desc",
};

function operationsQuery(query) {
  const params = new URLSearchParams({
    limit: String(query.limit || DEFAULT_OPERATION_QUERY.limit),
    offset: String(query.offset || 0),
  });
  if (query.q) params.set("q", query.q);
  if (query.status) params.set("status", query.status);
  if (query.kind) params.set("kind", query.kind);
  if (query.sort_by) params.set("sort_by", query.sort_by);
  if (query.sort_dir) params.set("sort_dir", query.sort_dir);
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
  const [operationQuery, setOperationQuery] = useState(DEFAULT_OPERATION_QUERY);
  const operationQueryRef = useRef(operationQuery);
  const busyCountsRef = useRef(new Map());
  const busyPromisesRef = useRef(new Map());

  useEffect(() => {
    operationQueryRef.current = operationQuery;
  }, [operationQuery]);

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
    queryKey: ["operations", operationQuery],
    queryFn: () => operationsQuery(operationQuery),
    enabled: routeId === "operations" && databaseAvailable,
    refetchInterval: (query) => {
      const rows = query.state.data?.rows || [];
      return rows.some((item) => ACTIVE_OPERATION_STATUSES.has(item.status))
        ? 2000
        : 15000;
    },
  });
  const operationSummaryQueryResult = useQuery({
    queryKey: ["operations-summary"],
    queryFn: () => api("/api/operations/summary"),
    enabled: databaseAvailable,
    refetchInterval: (query) =>
      Number(query.state.data?.active || 0) > 0 ? 2000 : 15000,
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
    (key, fn, options = {}) => {
      const count = busyCountsRef.current.get(key) || 0;
      if (count && !options.allowConcurrent) {
        return busyPromisesRef.current.get(key) || Promise.resolve(null);
      }
      busyCountsRef.current.set(key, count + 1);
      setBusy((value) => ({ ...value, [key]: true }));
      const pending = Promise.resolve()
        .then(fn)
        .catch((error) => {
          showAlert(error.message || String(error), "error");
          return null;
        })
        .finally(() => {
          const remaining = (busyCountsRef.current.get(key) || 1) - 1;
          if (remaining > 0) busyCountsRef.current.set(key, remaining);
          else {
            busyCountsRef.current.delete(key);
            busyPromisesRef.current.delete(key);
            setBusy((value) => ({ ...value, [key]: false }));
          }
        });
      busyPromisesRef.current.set(key, pending);
      return pending;
    },
    [showAlert],
  );

  const setSession = useCallback(
    (value) => {
      setSessionState(value);
      if (!value?.connected) setLookups(EMPTY_LOOKUPS);
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
    async (nextQuery) => {
      const query = nextQuery
        ? { ...DEFAULT_OPERATION_QUERY, ...nextQuery }
        : operationQueryRef.current;
      operationQueryRef.current = query;
      setOperationQuery(query);
      return queryClient.fetchQuery({
        queryKey: ["operations", query],
        queryFn: () => operationsQuery(query),
        staleTime: 0,
      });
    },
    [queryClient],
  );

  const refreshOperationSummary = useCallback(
    () =>
      queryClient.fetchQuery({
        queryKey: ["operations-summary"],
        queryFn: () => api("/api/operations/summary"),
        staleTime: 0,
      }),
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
    operationSummary: operationSummaryQueryResult.data || null,
    operationSummaryError: operationSummaryQueryResult.error || null,
    operationsStale:
      !databaseAvailable ||
      operationsQueryResult.isError ||
      operationSummaryQueryResult.isError,
    operationsError: operationsQueryResult.error || null,
    operationsLoading:
      operationsQueryResult.isPending ||
      (operationsQueryResult.isFetching && !operationsQueryResult.data),
    operationsTotal: operationsQueryResult.data?.total || 0,
    operationsUpdatedAt: operationsQueryResult.dataUpdatedAt
      ? new Date(operationsQueryResult.dataUpdatedAt).toISOString()
      : null,
    refreshAssets,
    refreshOperations,
    refreshOperationSummary,
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
    assetsError: assetsQueryResult.error || null,
    assetsLoading:
      assetsQueryResult.isPending ||
      (assetsQueryResult.isFetching && !assetsQueryResult.data),
    systemStatus,
    tasks,
    tasksError: tasksQueryResult.error || null,
    tasksLoading:
      tasksQueryResult.isPending ||
      (tasksQueryResult.isFetching && !tasksQueryResult.data),
  };
}
