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
