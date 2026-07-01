export function splitTokens(value) {
  return (value || "")
    .split(/[\n,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

export function formatCount(value) {
  return new Intl.NumberFormat("ru-RU").format(Number(value || 0));
}

export function optionLabel(item) {
  if (!item) return "";
  return item.name ? `${item.name}${item.id ? ` · ${item.id}` : ""}` : item.id || "";
}

export function filterOptions(items, query) {
  const normalizedQuery = String(query || "").trim().toLocaleLowerCase("ru-RU");
  if (!normalizedQuery) return items || [];
  return (items || []).filter((item) => optionLabel(item).toLocaleLowerCase("ru-RU").includes(normalizedQuery));
}
