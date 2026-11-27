import { useCallback, useEffect, useRef, useState } from "react";

const ALERT_DURATION = 6000;

export function useAlerts() {
  const [alerts, setAlerts] = useState([]);
  const entries = useRef(new Map());
  const nextId = useRef(0);

  const dismissAlert = useCallback((id) => {
    const entry = entries.current.get(id);
    if (!entry) return;
    window.clearTimeout(entry.timer);
    entries.current.delete(id);
    setAlerts((current) => current.filter((alert) => alert.id !== id));
  }, []);

  const showAlert = useCallback(
    (message, tone = "info") => {
      if (!message) return;
      const text = String(message);
      const duplicate = [...entries.current.values()].find(
        (entry) => entry.message === text && entry.tone === tone,
      );
      if (duplicate) return duplicate.id;
      const id = ++nextId.current;
      const alert = { id, message: text, tone, type: tone };
      const timer = window.setTimeout(() => dismissAlert(id), ALERT_DURATION);
      if (entries.current.size >= 4)
        dismissAlert(entries.current.keys().next().value);
      entries.current.set(id, { ...alert, timer });
      setAlerts((current) => [...current, alert]);
      return id;
    },
    [dismissAlert],
  );

  useEffect(() => {
    const timers = entries.current;
    return () => {
      for (const entry of timers.values()) window.clearTimeout(entry.timer);
      timers.clear();
    };
  }, []);

  return { alerts, showAlert, dismissAlert };
}
