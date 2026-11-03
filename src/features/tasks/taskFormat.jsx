export function objectRecords(value) {
  return Array.isArray(value)
    ? value.filter(
        (item) => item && typeof item === "object" && !Array.isArray(item),
      )
    : [];
}

export function displayText(value) {
  if (typeof value === "string") return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  for (const field of [
    "name",
    "displayName",
    "userName",
    "login",
    "value",
    "id",
  ]) {
    const label = value[field];
    if (typeof label === "string" && label) return label;
    if (typeof label === "number" && Number.isFinite(label))
      return String(label);
  }
  return "";
}

export function displayTargets(value) {
  return Array.isArray(value)
    ? value.map(displayText).filter(Boolean).join(", ")
    : displayText(value);
}

export function connectionChecks(job) {
  return objectRecords(job?.connectionCheckResults);
}

export function formatCheckErrors(errors) {
  if (Array.isArray(errors)) {
    const messages = errors.filter((item) => typeof item === "string");
    return messages.length ? ` · ${messages.join(", ")}` : "";
  }
  return typeof errors === "string" && errors ? ` · ${errors}` : "";
}

export function taskStatusLabel(value) {
  return (
    {
      unknown: "Неизвестно",
      running: "Выполняется",
      in_progress: "Выполняется",
      started: "Выполняется",
      queued: "В очереди",
      stopped: "Остановлена",
      stopping: "Останавливается",
      cancelled: "Остановлена",
      failed: "Ошибка",
      error: "Ошибка",
      invalid: "Ошибка проверки",
      created: "Не запускалась",
      new: "Не запускалась",
      idle: "Не запускалась",
    }[value.toLowerCase()] || value
  );
}

export function StatusBadge({ status, result }) {
  const value = String(status || "unknown");
  const success =
    ["finished", "completed", "valid", "success"].includes(
      value.toLowerCase(),
    ) ||
    ["success", "ok", "succeeded"].includes(String(result || "").toLowerCase());
  const running = ["running", "in_progress", "started", "queued"].includes(
    value.toLowerCase(),
  );
  return (
    <span
      className={`task-status ${success ? "is-success" : running ? "is-running" : ""}`}
    >
      <i aria-hidden="true" />
      {success ? "Завершена" : taskStatusLabel(value)}
    </span>
  );
}

export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : new Intl.DateTimeFormat("ru-RU", {
        dateStyle: "medium",
        timeStyle: "short",
      }).format(date);
}

export function formatDuration(start, finish) {
  if (!start || !finish) return "—";
  const seconds = Math.max(
    0,
    Math.round((new Date(finish).getTime() - new Date(start).getTime()) / 1000),
  );
  return seconds >= 60
    ? `${Math.floor(seconds / 60)} мин ${seconds % 60} с`
    : `${seconds} с`;
}
