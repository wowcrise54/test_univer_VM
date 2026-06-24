import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api/client.js";

const EMPTY_LOOKUPS = {
  credentials: [],
  scopes: [],
  scanner_profiles: [],
};

export function useAppData(routeId) {
  const [defaults, setDefaults] = useState(null);
  const [session, setSession] = useState({ connected: false });
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
      .then((value) => alive && setDefaults(value))
      .catch((error) => alive && showAlert(error.message || String(error), "error"));
    api("/api/session")
      .then((value) => alive && setSession(value))
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
    defaults,
    lookups,
    refreshAssets,
    refreshTasks,
    runBusy,
    selectedTask,
    selectedTaskId,
    session,
    setLookups,
    setSelectedTaskId,
    setSession,
    showAlert,
    summary,
    tasks,
  };
}
