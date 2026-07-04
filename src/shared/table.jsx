import { useMemo, useState } from "react";

export function useTableSort(defaultKey = "", defaultDirection = "asc") {
  const [sort, setSort] = useState({ key: defaultKey, direction: defaultDirection });
  const toggleSort = (key, initialDirection = "asc") => {
    setSort((current) => current.key === key
      ? { key, direction: current.direction === "asc" ? "desc" : "asc" }
      : { key, direction: initialDirection });
  };
  return [sort, toggleSort, setSort];
}

export function SortableHeader({ column, sort, onSort, children, initialDirection = "asc", ...props }) {
  const active = sort?.key === column;
  const ariaSort = active ? (sort.direction === "asc" ? "ascending" : "descending") : "none";
  return (
    <th aria-sort={ariaSort} {...props}>
      <button className="sortable-header" type="button" onClick={() => onSort(column, initialDirection)}>
        <span>{children}</span>
        <span className="sortable-header__icon" aria-hidden="true">{active ? (sort.direction === "asc" ? "↑" : "↓") : "↕"}</span>
      </button>
    </th>
  );
}

export function useSortedRows(rows, sort, accessors = {}) {
  return useMemo(() => sortRows(rows, sort, accessors), [rows, sort, accessors]);
}

export function sortRows(rows, sort, accessors = {}) {
  if (!sort?.key) return rows;
  const accessor = accessors[sort.key] || ((row) => readPath(row, sort.key));
  const direction = sort.direction === "desc" ? -1 : 1;
  return rows.map((row, index) => ({ row, index })).sort((left, right) => {
    const a = accessor(left.row);
    const b = accessor(right.row);
    const aEmpty = a === null || a === undefined || a === "";
    const bEmpty = b === null || b === undefined || b === "";
    if (aEmpty !== bEmpty) return aEmpty ? 1 : -1;
    if (aEmpty) return left.index - right.index;
    const result = compareTyped(a, b);
    return result === 0 ? left.index - right.index : result * direction;
  }).map(({ row }) => row);
}

function readPath(value, path) {
  return String(path).split(".").reduce((current, key) => current?.[key], value);
}

function compareTyped(a, b) {
  if (typeof a === "boolean" || typeof b === "boolean") return Number(Boolean(a)) - Number(Boolean(b));
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (a instanceof Date || b instanceof Date) return new Date(a).getTime() - new Date(b).getTime();
  return String(a).localeCompare(String(b), "ru", { numeric: true, sensitivity: "base" });
}
