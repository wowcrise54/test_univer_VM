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

const ACTIVE_OPERATION_STATUSES = new Set(["queued", "running", "cancelling", "recovering"]);

function unavailableSystemStatus(error) {
  return {
    state: "down",
    checked_at: new Date().toISOString(),
    error,
    components: {
      application: {
        state: "down",
        message: error?.operatorMessage || error?.message || "Backend недоступен.",
        retryable: true,
        trace_id: error?.traceId || null,
      },
      database: { state: "down", message: "Состояние PostgreSQL неизвестно, потому что backend недоступен.", retryable: true },
      mpvm: { state: "degraded", message: "Состояние сессии MP VM неизвестно.", retryable: true },
      background_workers: { state: "down", message: "Состояние фоновых исполнителей неизвестно.", retryable: true },
    },
  };
}

export function useAppData(routeId) {
  const [defaults, setDefaults] = useState(null);
  const [session, setSession] = useState({ connected: false });
  const [connectionDraft, setConnectionDraft] = useState(EMPTY_CONNECTION_DRAFT);
  const [lookups, setLookups] = useState(EMPTY_LOOKUPS);
  const [tasks, setTasks] = useState([]);
  const [tasksLoaded, setTasksLoaded] = useState(false);
  const [selectedTaskId, setSelectedTaskId] = useState(null);
  const [summary, setSummary] = useState(null);
  const [assetRows, setAssetRows] = useState([]);
  const [assetTotal, setAssetTotal] = useState(0);
  const [alerts, setAlerts] = useState([]);
  const [busy, setBusy] = useState({});
  const [systemStatus, setSystemStatus] = useState(null);
  const [operations, setOperations] = useState([]);
  const [operationsTotal, setOperationsTotal] = useState(0);
  const [operationsUpdatedAt, setOperationsUpdatedAt] = useState(null);
  const [operationsStale, setOperationsStale] = useState(false);

  const showAlert = useCallback((message, type = "info") => {
    const id = Date.now() + "-" + Math.random();
    setAlerts((items) => {
      if (items.some((item) => item.message === message && item.type === type)) return items;
      return [{ id, message, type }, ...items].slice(0, 4);
    });
    window.setTimeout(() => setAlerts((items) => items.filter((item) => item.id !== id)), 9000);
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

  const refreshTasks = useCallback(async () => {
    const items = await api("/api/scanner-tasks");
    setTasks(items);
    setTasksLoaded(true);
  }, []);

  const refreshAssets = useCallback(async (filters = {}) => {
    const params = new URLSearchParams({ limit: "300" });
    if (filters.q) params.set("q", filters.q);
    if (filters.severity) params.set("severity", filters.severity);
    if (filters.sort_by) params.set("sort_by", filters.sort_by);
    if (filters.sort_dir) params.set("sort_dir", filters.sort_dir);

    const [summaryResult, assetsResult] = await Promise.all([
      api("/api/assets/summary"),
      api("/api/assets?" + params.toString()),
    ]);
    setSummary(summaryResult);
    setAssetRows(assetsResult.rows || []);
    setAssetTotal(assetsResult.total || 0);
  }, []);

  const refreshSystemStatus = useCallback(async () => {
    try {
      const value = await api("/api/system/status");
      setSystemStatus(value);
      return value;
    } catch (error) {
      const fallback = unavailableSystemStatus(error);
      setSystemStatus(fallback);
      return fallback;
    }
  }, []);

  const refreshOperations = useCallback(async (sorting = {}) => {
    try {
      const params = new URLSearchParams({ limit: "100" });
      if (sorting.sort_by) params.set("sort_by", sorting.sort_by);
      if (sorting.sort_dir) params.set("sort_dir", sorting.sort_dir);
      const result = await api(`/api/operations?${params}`);
      setOperations(result.rows || []);
      setOperationsTotal(result.total || 0);
      setOperationsUpdatedAt(new Date().toISOString());
      setOperationsStale(false);
      return result;
    } catch (_error) {
      setOperationsStale(true);
      return null;
    }
  }, []);

  useEffect(() => {
    let alive = true;
    api("/api/defaults")
      .then((value) => {
        if (!alive) return;
        setDefaults(value);
        setConnectionDraft((current) => ({
          ...current,
          api_url: current.api_url || value.api_url || "",
          client_id: current.client_id || value.client_id || "mpx",
          scope: current.scope || value.scope || "",
        }));
      })
      .catch(() => null);
    api("/api/session")
      .then((value) => {
        if (!alive) return;
        setSession(value);
        setConnectionDraft((current) => ({
          ...current,
          api_url: value.api_url || current.api_url,
          token_url: value.token_url || current.token_url,
          username: value.username ?? current.username,
          verify_tls: value.verify_tls ?? current.verify_tls,
        }));
      })
      .catch(() => null);
    return () => {
      alive = false;
    };
  }, [showAlert]);

  useEffect(() => {
    let alive = true;
    const poll = async () => {
      await refreshSystemStatus();
      if (alive) window.setTimeout(poll, 10000);
    };
    poll();
    return () => {
      alive = false;
    };
  }, [refreshSystemStatus]);

  const hasActiveOperations = operations.some((item) => ACTIVE_OPERATION_STATUSES.has(item.status));

  useEffect(() => {
    if (systemStatus?.components?.database?.state === "down") {
      setOperationsStale(true);
      return undefined;
    }
    let alive = true;
    let timerId;
    const poll = async () => {
      await refreshOperations();
      if (alive) timerId = window.setTimeout(poll, hasActiveOperations ? 2000 : 15000);
    };
    poll();
    return () => {
      alive = false;
      window.clearTimeout(timerId);
    };
  }, [hasActiveOperations, refreshOperations, systemStatus?.components?.database?.state]);

  useEffect(() => {
    if (routeId !== "tasks" || tasksLoaded || !systemStatus || systemStatus?.components?.database?.state === "down") return;
    runBusy("tasks", () => refreshTasks());
  }, [refreshTasks, routeId, runBusy, systemStatus, tasksLoaded]);

  useEffect(() => {
    if (routeId !== "assets" || summary !== null || !systemStatus || systemStatus?.components?.database?.state === "down") return;
    runBusy("assets", () => refreshAssets());
  }, [refreshAssets, routeId, runBusy, summary, systemStatus]);

  const selectedTask = useMemo(
    () => tasks.find((task) => task.mp_task_id === selectedTaskId) || null,
    [tasks, selectedTaskId],
  );

  return {
    alerts,
    assetRows,
    assetTotal,
    busy,
    connectionDraft,
    defaults,
    lookups,
    operations,
    operationsStale,
    operationsTotal,
    operationsUpdatedAt,
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
    summary,
    systemStatus,
    tasks,
  };
}
