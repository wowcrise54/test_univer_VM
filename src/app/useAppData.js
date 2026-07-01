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

  const showAlert = useCallback((message, type = "info") => {
    const id = Date.now() + "-" + Math.random();
    setAlerts((items) => [{ id, message, type }, ...items].slice(0, 4));
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

    const [summaryResult, assetsResult] = await Promise.all([
      api("/api/assets/summary"),
      api("/api/assets?" + params.toString()),
    ]);
    setSummary(summaryResult);
    setAssetRows(assetsResult.rows || []);
    setAssetTotal(assetsResult.total || 0);
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
      .catch((error) => alive && showAlert(error.message || String(error), "error"));
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
      .catch((error) => alive && showAlert(error.message || String(error), "error"));
    return () => {
      alive = false;
    };
  }, [showAlert]);

  useEffect(() => {
    if (routeId !== "tasks" || tasksLoaded) return;
    runBusy("tasks", () => refreshTasks());
  }, [refreshTasks, routeId, runBusy, tasksLoaded]);

  useEffect(() => {
    if (routeId !== "assets" || summary !== null) return;
    runBusy("assets", () => refreshAssets());
  }, [refreshAssets, routeId, runBusy, summary]);

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
    refreshAssets,
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
    tasks,
  };
}
