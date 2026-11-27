export function splitTokens(value) {
  return (value || "")
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function formatCount(value) {
  return new Intl.NumberFormat("ru-RU").format(Number(value || 0));
}

/** Shows the name; the ID is appended only when another item has the same name. */
export function optionLabel(item, items = []) {
  if (!item) return "";
  if (!item.name) return item.id || "";
  const duplicate = items.some((other) => other !== item && other?.name === item.name);
  return duplicate && item.id ? `${item.name} · ${item.id}` : item.name;
}

export function filterOptions(items, query) {
  const normalizedQuery = String(query || "").trim().toLocaleLowerCase("ru-RU");
  if (!normalizedQuery) return items || [];
  return (items || []).filter((item) =>
    `${item?.name || ""} ${item?.id || ""}`.toLocaleLowerCase("ru-RU").includes(normalizedQuery),
  );
}

const dateFormatter = new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "short" });

/** Formats an ISO timestamp for display; empty or invalid values become "—". */
export function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : dateFormatter.format(date);
}
