import { severityLabel } from "./labels.js";
import { formatDateTime } from "./values.js";

export function Severity({ value }) {
  const normalized = (value || "empty").toLowerCase();
  return (
    <span className={`severity severity--${normalized}`}>
      {severityLabel(value)}
    </span>
  );
}

export function FreshnessBadge({
  value,
  freshForHours = 24,
  staleAfterHours = 7 * 24,
}) {
  const timestamp = value ? new Date(value).getTime() : Number.NaN;
  const ageHours = Number.isFinite(timestamp)
    ? // eslint-disable-next-line react-hooks/purity -- the relative age is meant to be computed at render time
      Math.max(0, (Date.now() - timestamp) / 3600000)
    : null;
  const state =
    ageHours == null
      ? "unknown"
      : ageHours <= freshForHours
        ? "fresh"
        : ageHours <= staleAfterHours
          ? "aging"
          : "stale";
  const label =
    state === "fresh"
      ? "свежие"
      : state === "aging"
        ? "требуют обновления"
        : state === "stale"
          ? "устарели"
          : "время неизвестно";
  return (
    <span
      className={`freshness freshness--${state}`}
      title={value ? formatDateTime(value) : "Время обновления отсутствует"}
    >
      <strong>{label}</strong>
      {value ? <small>{formatDateTime(value)}</small> : null}
    </span>
  );
}
